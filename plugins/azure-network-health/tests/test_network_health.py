from __future__ import annotations

import copy
import hashlib
import json
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import ValidationError


SKILL = Path(__file__).resolve().parents[1] / "skills" / "azure-network-health-assessment"
sys.path.insert(0, str(SKILL))
import network_health as nh
from runtime import validate_document


FIXTURE = nh.load(Path(__file__).with_name("fixtures.json"))
SUB = nh.text(FIXTURE["subscriptionId"])
RUN = nh.text(FIXTURE["runId"])
TIME = nh.text(FIXTURE["timestamp"])


class FixtureReader:
    def __init__(self, page_size: int = 1000) -> None:
        self.page_size = page_size
        self.calls: list[list[str]] = []
        self.resources = copy.deepcopy(nh.obj(FIXTURE["resources"]))
        self.fail: str | None = None
        self.transform = lambda payload, operation, page: payload
        self.operations = nh.records(nh.catalog()["operations"])

    def __call__(self, command: list[str]) -> nh.ReadResponse:
        self.calls.append(command)
        if command[1:3] == ["account", "show"]:
            return nh.ReadResponse({"subscriptionId": SUB})
        query = command[command.index("-q") + 1]
        operation = next(op for op in self.operations if op.get("query") == query)
        op_id = nh.text(operation["operationId"])
        if self.fail == op_id:
            raise nh.ReadFailure("Forbidden", "permissionDenied")
        token = command[command.index("--skip-token") + 1] if "--skip-token" in command else "0"
        offset = int(token)
        source = nh.records(self.resources[op_id])
        rows = []
        for item in source[offset:offset + self.page_size]:
            rows.append({
                **item, "type": operation["entityType"], "subscriptionId": SUB,
                "resourceGroup": "fixture", "location": "eastus",
                "parentId": item.get("parentId", ""),
            })
        next_offset = offset + len(rows)
        payload = {
            "data": rows, "count": len(rows), "total_records": len(source),
            "skip_token": str(next_offset) if next_offset < len(source) else None,
        }
        return nh.ReadResponse(self.transform(payload, op_id, offset))


class PrivateFixtureReader(FixtureReader):
    def __init__(self, page_size=1000):
        super().__init__(page_size)
        self.operations = nh.records(nh.catalog("1.1.0")["operations"])
        base = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Network"
        endpoint = base + "/privateEndpoints/storage"
        zone = base + "/privateDnsZones/privatelink.blob.core.windows.net"
        vnet = base + "/virtualNetworks/alpha"
        self.resources.update({
            "private-endpoints": [{"id": endpoint, "name": "storage", "properties": {
                "subnetId": vnet + "/subnets/app", "provisioningState": "Succeeded",
                "automaticConnectionCount": 1, "manualConnectionCount": 0,
            }}],
            "private-endpoint-connections": [{
                "id": endpoint + "/privateLinkServiceConnections/blob", "name": "blob", "parentId": endpoint,
                "properties": {"connectionKind": "automatic", "privateLinkServiceId": f"/subscriptions/{SUB}/resourceGroups/workload/providers/Microsoft.Storage/storageAccounts/storage",
                               "groupIds": ["blob"], "connectionStatus": "Approved", "provisioningState": "Succeeded"},
            }],
            "private-dns-zones": [{"id": zone, "name": "privatelink.blob.core.windows.net", "properties": {
                "provisioningState": "Succeeded", "virtualNetworkLinkCount": 1,
            }}],
            "private-dns-links": [{"id": zone + "/virtualNetworkLinks/alpha", "name": "alpha", "parentId": zone,
                                   "properties": {"virtualNetworkId": vnet, "registrationEnabled": False,
                                                  "virtualNetworkLinkState": "Completed", "provisioningState": "Succeeded"}}],
            "private-dns-groups": [{"id": endpoint + "/privateDnsZoneGroups/default", "name": "default",
                                   "properties": {"privateDnsZoneIds": [zone], "provisioningState": "Succeeded"}}],
        })

    def __call__(self, command):
        if command[:5] != ["az", "network", "private-endpoint", "dns-zone-group", "list"]:
            return super().__call__(command)
        self.calls.append(command)
        if self.fail == "private-dns-groups":
            raise nh.ReadFailure("Forbidden", "permissionDenied")
        name = command[command.index("--endpoint-name") + 1]
        rows = [item for item in self.resources["private-dns-groups"] if "/privateEndpoints/" + name + "/" in item["id"]]
        return nh.ReadResponse({"count": len(rows), "data": copy.deepcopy(rows)})


class NetworkHealthTests(unittest.TestCase):
    def make(self, reader: FixtureReader | None = None, page_size: int = 1000):
        reader = reader or FixtureReader(page_size)
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", page_size, lambda: TIME)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def private_make(self, reader=None, progress=None, save_progress=None):
        reader = reader or PrivateFixtureReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME,
                              progress, save_progress, include_private=True)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_private_enrichment_is_explicit_and_preserves_default_nine_operations(self) -> None:
        legacy, legacy_model, legacy_assessment, _ = self.make()
        enriched, model, assessment, _ = self.private_make()
        self.assertEqual(len(legacy["collections"]), 9)
        self.assertEqual(legacy["inputVersion"], "0.1.0")
        self.assertEqual(legacy_model["schemaVersion"], "0.1.0")
        self.assertEqual(len(legacy_assessment["checksExecuted"]), 6)
        self.assertEqual(len(enriched["collections"]), 14)
        self.assertEqual(enriched["inputVersion"], "0.2.0")
        self.assertEqual(model["schemaVersion"], "0.2.0")
        self.assertEqual(enriched["queryCatalogVersion"], "1.1.0")
        self.assertEqual(len(assessment["checksExecuted"]), 8)
        self.assertEqual(assessment["checkCatalogVersion"], "1.3.0")

    def test_private_relationships_are_configured_references_not_dns_or_traffic_proof(self) -> None:
        _, model, assessment, _ = self.private_make()
        kinds = {rel["relationshipType"] for rel in model["relationships"]}
        self.assertTrue({"targetsPrivateLinkResource", "referencesPrivateDnsZone", "dnsLinkedToVNet", "attachedToSubnet"} <= kinds)
        self.assertNotIn("observedTrafficVia", kinds)
        self.assertNotIn("dnsResolvesTo", kinds)
        private = [item for item in assessment["findings"] if item["checkId"].startswith("NET-PRIVATE")]
        self.assertTrue(any(item["recordType"] == "architectureObservation" and item["checkId"] == "NET-PRIVATE-DNS-001" for item in private))
        self.assertTrue(any("public-access behavior" in item["title"] and item["recordType"] == "evidenceGap" for item in private))
        self.assertFalse(any(item["recordType"] in ("verifiedProblem", "positiveObservation") for item in private))

    def test_private_approval_pending_rejected_and_missing_state_are_contextual(self) -> None:
        for state in ("Pending", "Rejected", "Disconnected", None, "FutureState"):
            with self.subTest(state=state):
                reader = PrivateFixtureReader()
                reader.resources["private-endpoint-connections"][0]["properties"]["connectionStatus"] = state
                _, _, assessment, _ = self.private_make(reader)
                item = next(item for item in assessment["findings"] if item["checkId"] == "NET-PRIVATE-001")
                self.assertEqual(item["recordType"], "evidenceGap" if state in (None, "FutureState") else "contextValidation")
                self.assertIsNone(item["severity"])
                self.assertFalse(any(item["recordType"] == "verifiedProblem" for item in assessment["findings"]))

    def test_private_group_failed_parent_list_is_unknown_not_absence(self) -> None:
        reader = PrivateFixtureReader()
        reader.fail = "private-dns-groups"
        _, model, assessment, _ = self.private_make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "private-dns-groups")
        self.assertEqual(collection["status"], "permissionDenied")
        self.assertEqual(collection["pages"], [])
        self.assertTrue(any(item["title"] == "Private endpoint DNS zone-group evidence was not collected" for item in assessment["findings"]))
        self.assertFalse(any(item["title"] == "Private endpoint has no collected zone-group association" for item in assessment["findings"]))

    def test_private_group_zero_rows_has_parent_evidence_and_is_context_not_dns_failure(self) -> None:
        reader = PrivateFixtureReader()
        reader.resources["private-dns-groups"] = []
        _, model, assessment, _ = self.private_make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "private-dns-groups")
        self.assertEqual(collection["status"], "succeeded")
        self.assertEqual(collection["pages"][0]["itemCount"], 0)
        self.assertIn("/privateEndpoints/storage", collection["pages"][0]["parentResourceId"])
        item = next(item for item in assessment["findings"] if item["title"] == "Private endpoint has no collected zone-group association")
        self.assertEqual(item["recordType"], "contextValidation")
        self.assertIn("manual/custom/shared DNS", item["reasoning"])

    def test_rejected_group_rows_never_turn_into_association_absence(self) -> None:
        reader = PrivateFixtureReader()
        reader.resources["private-dns-groups"][0]["properties"]["privateDnsZoneIds"] = [{"invalid": "not-retained"}]
        _, model, assessment, _ = self.private_make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "private-dns-groups")
        self.assertEqual(collection["status"], "partial")
        self.assertEqual(collection["pages"][0]["itemCount"], 1)
        self.assertEqual(collection["retainedRowCount"], 0)
        self.assertTrue(any(item["title"] == "Private endpoint DNS zone-group evidence was not collected" for item in assessment["findings"]))
        self.assertFalse(any(item["title"] == "Private endpoint has no collected zone-group association" for item in assessment["findings"]))

    def test_private_external_zone_and_missing_link_never_expand_scope_or_claim_resolution_failure(self) -> None:
        for scenario in ("external", "no-link", "unknown-link"):
            with self.subTest(scenario=scenario):
                reader = PrivateFixtureReader()
                if scenario == "external":
                    reader.resources["private-dns-groups"][0]["properties"]["privateDnsZoneIds"] = [
                        "/subscriptions/00000000-0000-4000-8000-000000000004/resourceGroups/shared/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net",
                    ]
                elif scenario == "no-link":
                    reader.resources["private-dns-links"] = []
                    reader.resources["private-dns-zones"][0]["properties"]["virtualNetworkLinkCount"] = 0
                else:
                    reader.resources["private-dns-links"][0]["properties"]["virtualNetworkId"] = None
                _, model, assessment, _ = self.private_make(reader)
                item = next(item for item in assessment["findings"] if item["title"] == "Private DNS configuration linkage needs architecture evidence")
                self.assertEqual(item["recordType"], "evidenceGap")
                self.assertIn("do not prove resolution failure", item["reasoning"])
                self.assertEqual(model["scope"]["requestedSubscriptionIds"], [SUB])
                for command in reader.calls:
                    self.assertTrue(SUB in command)

    def test_private_checkpoint_preserves_empty_parent_lists_and_resumes_next_parent(self) -> None:
        reader = PrivateFixtureReader()
        first = reader.resources["private-endpoints"][0]
        second = copy.deepcopy(first)
        second["id"] = second["id"].replace("/storage", "/storage2")
        second["name"] = "storage2"
        second["properties"]["automaticConnectionCount"] = 0
        reader.resources["private-endpoints"].append(second)
        reader.resources["private-dns-groups"] = []
        saved = {}
        stopped = False

        def checkpoint(progress):
            nonlocal saved, stopped
            saved = copy.deepcopy(progress)
            current = progress["current"]
            if current and current["collection"]["operationId"] == "private-dns-groups" and current["nextPage"] == 1 and not stopped:
                stopped = True
                raise RuntimeError("Interrupted")

        with self.assertRaises(RuntimeError):
            nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, {}, checkpoint, True)
        resumed = nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, saved, checkpoint, True)
        groups = next(c for c in resumed["collections"] if c["operationId"] == "private-dns-groups")
        self.assertEqual(len(groups["pages"]), 2)
        self.assertEqual(groups["status"], "succeeded")
        calls = [cmd for cmd in reader.calls if cmd[:5] == ["az", "network", "private-endpoint", "dns-zone-group", "list"]]
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0], calls[1])

    def test_private_sensitive_connection_and_record_payloads_are_omitted(self) -> None:
        reader = PrivateFixtureReader()
        reader.resources["private-endpoint-connections"][0]["properties"].update({"description": "must-not-persist", "requestMessage": "must-not-persist"})
        reader.resources["private-dns-groups"][0]["properties"]["recordSets"] = [{"credentials": "must-not-persist"}]
        envelope, model, assessment, _ = self.private_make(reader)
        self.assertNotIn("must-not-persist", json.dumps([envelope, model, assessment]))

    def test_four_artifacts_are_valid_and_reproducible(self) -> None:
        _, model, assessment, _ = self.make()
        validate_document(model, SKILL / "observed-network.schema.json")
        validate_document(assessment, SKILL / "assessment.schema.json")
        self.assertNotIn("findings", model)
        self.assertEqual(nh.assess(model), assessment)
        self.assertEqual(nh.render(assessment), nh.render(assessment))
        with tempfile.TemporaryDirectory() as directory:
            result = nh.bundle(model, assessment, Path(directory))
            artifacts = nh.obj(result["artifacts"])
            self.assertEqual(set(artifacts), {
                "observed-network.json", "assessment.json", "network-assessment.md", "network-evidence.md",
            })
            for item in artifacts.values():
                description = nh.obj(item)
                content = Path(nh.text(description["path"])).read_bytes()
                self.assertEqual(hashlib.sha256(content).hexdigest(), description["sha256"])
            with self.assertRaises(FileExistsError):
                nh.bundle(model, assessment, Path(directory))

    def publication(self, root: Path):
        _, model, assessment, _ = self.make()
        result = nh.bundle(model, assessment, root)
        manifest = root / "original-result.json"
        manifest.write_bytes(nh.encoded(result))
        return result, manifest

    def test_publication_plan_uses_verified_run_hash_aliases_without_rebuilding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, manifest = self.publication(root)
            before = {name: Path(item["path"]).read_bytes() for name, item in result["artifacts"].items()}
            with patch.object(nh, "collect") as collect, patch.object(nh, "assess") as assess, patch.object(nh, "render") as render:
                plan = nh.report_save(root, RUN, SUB, "plan", manifest)
                collect.assert_not_called()
                assess.assert_not_called()
                render.assert_not_called()
            self.assertEqual(plan["status"], "partial-report-save")
            self.assertEqual(set(plan["remaining"]), set(nh.REPORT_FILES))
            for name, item in plan["files"].items():
                self.assertIn(RUN, item["publicationName"])
                self.assertIn(item["sha256"], item["publicationName"])
                self.assertEqual(Path(plan["publicationPaths"][name]).read_bytes(), before[name])
            self.assertEqual(len(list((root / "runs" / RUN).iterdir())), 4)

    def test_partial_save_resume_skips_receipted_files_and_preserves_original_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, manifest = self.publication(root)
            plan = nh.report_save(root, RUN, SUB, "plan", manifest)
            before = {name: Path(item["path"]).read_bytes() for name, item in result["artifacts"].items()}
            for name in nh.REPORT_FILES[:2]:
                started = nh.report_save(root, RUN, SUB, "begin", artifact=name)
                key = "tmp/ThreadFiles/" + SUB + "/" + started["files"][name]["publicationName"]
                nh.report_save(root, RUN, SUB, "record", artifact=name, blob_key=key)
            resumed = nh.report_save(root, RUN, SUB, "plan")
            self.assertEqual(set(resumed["remaining"]), set(nh.REPORT_FILES[2:]))
            self.assertEqual(before, {name: Path(item["path"]).read_bytes() for name, item in result["artifacts"].items()})
            for name in nh.REPORT_FILES[2:]:
                started = nh.report_save(root, RUN, SUB, "begin", artifact=name)
                key = "tmp/ThreadFiles/" + SUB + "/" + started["files"][name]["publicationName"]
                nh.report_save(root, RUN, SUB, "record", artifact=name, blob_key=key)
            self.assertEqual(nh.report_save(root, RUN, SUB, "plan")["status"], "saved-not-download-verified")

    def test_interrupted_save_can_retry_only_the_same_verified_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest = self.publication(root)
            nh.report_save(root, RUN, SUB, "plan", manifest)
            first = nh.report_save(root, RUN, SUB, "begin", artifact=nh.REPORT_FILES[0])
            retried = nh.report_save(root, RUN, SUB, "begin", artifact=nh.REPORT_FILES[0])
            self.assertEqual(first["publicationPaths"], retried["publicationPaths"])
            name = nh.REPORT_FILES[0]
            key = "tmp/ThreadFiles/" + SUB + "/" + retried["files"][name]["publicationName"]
            nh.report_save(root, RUN, SUB, "record", artifact=name, blob_key=key)
            nh.report_save(root, RUN, SUB, "record", artifact=name, blob_key=key)
            with self.assertRaisesRegex(ValueError, "already has a receipt"):
                nh.report_save(root, RUN, SUB, "begin", artifact=name)
            with self.assertRaisesRegex(ValueError, "differs from the durable"):
                nh.report_save(root, RUN, SUB, "record", artifact=name, blob_key="tmp/ThreadFiles/" + SUB + "/other/" + retried["files"][name]["publicationName"])

    def test_missing_manifest_original_or_corrupted_alias_never_regenerates(self) -> None:
        for failure in ("manifest", "original", "alias"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result, manifest = self.publication(root)
                if failure == "manifest":
                    with self.assertRaises(ValueError):
                        nh.report_save(root, RUN, SUB, "plan")
                    continue
                plan = nh.report_save(root, RUN, SUB, "plan", manifest)
                name = nh.REPORT_FILES[0]
                target = Path(result["artifacts"][name]["path"]) if failure == "original" else Path(plan["publicationPaths"][name])
                target.write_bytes(b"corrupt")
                with patch.object(nh, "bundle") as bundle:
                    with self.assertRaisesRegex(ValueError, "hash mismatch|copy differs"):
                        nh.report_save(root, RUN, SUB, "plan")
                    bundle.assert_not_called()
                self.assertEqual(target.read_bytes(), b"corrupt")

    def test_publication_thread_manifest_and_saved_key_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest = self.publication(root)
            plan = nh.report_save(root, RUN, SUB, "plan", manifest)
            with self.assertRaisesRegex(ValueError, "run/thread mismatch"):
                nh.report_save(root, RUN, "00000000-0000-4000-8000-000000000004", "plan")
            name = nh.REPORT_FILES[0]
            nh.report_save(root, RUN, SUB, "begin", artifact=name)
            for key in (
                "tmp/ThreadFiles/" + RUN + "/" + plan["files"][name]["publicationName"],
                "tmp/ThreadFiles/" + SUB + "/../" + plan["files"][name]["publicationName"],
                "tmp/ThreadFiles/" + SUB + "/" + plan["files"][name]["publicationName"] + "?token=x",
                "tmp/ThreadFiles/" + SUB + "/different.json",
            ):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    nh.report_save(root, RUN, SUB, "record", artifact=name, blob_key=key)

    def test_publication_lock_and_record_without_begin_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest = self.publication(root)
            plan = nh.report_save(root, RUN, SUB, "plan", manifest)
            name = nh.REPORT_FILES[0]
            key = "tmp/ThreadFiles/" + SUB + "/" + plan["files"][name]["publicationName"]
            with self.assertRaisesRegex(ValueError, "begun save"):
                nh.report_save(root, RUN, SUB, "record", artifact=name, blob_key=key)
            lock = Path(plan["statePath"]).parent / ".publication.lock"
            lock.mkdir()
            with self.assertRaises(FileExistsError):
                nh.report_save(root, RUN, SUB, "plan")
            self.assertTrue(lock.exists())

    def test_original_result_manifest_and_publication_cli_do_not_recollect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope, _, _, _ = self.make()
            input_path = root / "input.json"
            input_path.write_bytes(nh.encoded(envelope))
            manifest = root / "helper-result.json"
            args = ["helper", "--input", str(input_path), "--output-root", str(root), "--bundle-result", str(manifest)]
            with patch.object(sys, "argv", args), patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(nh.main(), 0)
            self.assertEqual(nh.load(manifest), json.loads(output.getvalue()))
            with patch.object(sys, "argv", args), patch.object(nh, "collect") as collect:
                with self.assertRaises(FileExistsError):
                    nh.main()
                collect.assert_not_called()
            args = [
                "helper", "--output-root", str(root), "--run-id", RUN, "--report-thread-id", SUB,
                "--report-save-action", "plan", "--bundle-manifest", str(manifest),
            ]
            with patch.object(sys, "argv", args), patch.object(nh, "collect") as collect:
                with patch.object(nh, "assess") as assess, patch("sys.stdout", new_callable=io.StringIO) as output:
                    self.assertEqual(nh.main(), 0)
                collect.assert_not_called()
                assess.assert_not_called()
            plan = json.loads(output.getvalue())
            self.assertEqual(nh.load(Path(plan["ledgerExportPath"]))["threadId"], SUB)

    def test_real_pagination_interface_is_exercised(self) -> None:
        _, model, _, reader = self.make(page_size=1)
        self.assertGreater(len(reader.calls), len(nh.catalog()["operations"]))
        self.assertTrue(any("--skip-token" in command for command in reader.calls))
        self.assertEqual(nh.obj(model["coverage"])["status"], "accessible-pages-collected")

    def test_page_progress_resumes_without_repeating_selected_pages(self) -> None:
        reader = FixtureReader(1)
        saved = {}
        interrupted = False

        def checkpoint(progress):
            nonlocal saved, interrupted
            saved = copy.deepcopy(progress)
            current = progress["current"]
            if current and current["collection"]["operationId"] == "vnets" and current["nextPage"] == 1 and not interrupted:
                interrupted = True
                raise RuntimeError("Interrupted after selected page")

        with self.assertRaisesRegex(RuntimeError, "Interrupted after selected page"):
            nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, {}, checkpoint)
        prior_calls = len(reader.calls)
        resumed = nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, saved, checkpoint)
        expected_reader = FixtureReader(1)
        expected = nh.collect(SUB, RUN, expected_reader, "synthetic-fixture", 1, lambda: TIME)
        self.assertGreater(prior_calls, 0)
        self.assertEqual(resumed, expected)
        self.assertEqual(reader.calls, expected_reader.calls)
        self.assertIsNone(saved["current"])

    def test_resume_preserves_original_started_times_without_extra_clock_calls(self) -> None:
        reader = FixtureReader(1)
        saved = {}
        ticks = iter(f"2026-10-07T21:00:{value:02d}Z" for value in range(60))
        stopped = False

        def checkpoint(progress):
            nonlocal saved, stopped
            saved = copy.deepcopy(progress)
            current = progress["current"]
            if current and current["collection"]["operationId"] == "vnets" and current["nextPage"] == 1 and not stopped:
                stopped = True
                raise RuntimeError("Interrupted")

        with self.assertRaises(RuntimeError):
            nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: next(ticks), {}, checkpoint)
        resumed = nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: next(ticks), saved, checkpoint)
        baseline_ticks = iter(f"2026-10-07T21:00:{value:02d}Z" for value in range(60))
        baseline = nh.collect(SUB, RUN, FixtureReader(1), "synthetic-fixture", 1, lambda: next(baseline_ticks))
        self.assertEqual(resumed, baseline)

    def test_checkpoint_keeps_rejected_row_issues_without_raw_sensitive_values(self) -> None:
        reader = FixtureReader(1)
        reader.resources["vnets"][0]["properties"]["credentials"] = "must-not-persist"
        reader.resources["vnets"][1]["resourceGroup"] = {"token": "must-not-persist"}
        reader.transform = lambda payload, op, page: {
            **payload, "data": [
                {**row, "tags": {"private": "must-not-persist"},
                 "resourceGroup": {"token": "must-not-persist"} if op == "vnets" and page == 1 else "fixture"}
                for row in payload.get("data", [])
            ],
        }
        snapshots = []
        result = nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, {}, lambda p: snapshots.append(copy.deepcopy(p)))
        self.assertNotIn("must-not-persist", json.dumps(snapshots))
        vnets = next(c for c in result["collections"] if c["operationId"] == "vnets")
        self.assertIn("RejectedRow:ValueError", vnets["issues"])
        self.assertEqual(vnets["status"], "partial")

    def test_checkpoint_identity_changes_are_rejected_before_reader(self) -> None:
        progress = {}
        nh.collect(SUB, RUN, FixtureReader(), "synthetic-fixture", clock=lambda: TIME, progress=progress)
        for key, value in (
            ("runId", "00000000-0000-4000-8000-000000000004"),
            ("subscriptionId", "00000000-0000-4000-8000-000000000004"),
            ("pageSize", 1), ("capabilityVersion", "99.0.0"), ("catalogSha256", "0" * 64),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(progress)
                changed[key] = value
                with patch.object(nh, "cli_reader") as reader:
                    with self.assertRaisesRegex(ValueError, "identity"):
                        nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, progress=changed)
                    reader.assert_not_called()

    def test_completed_checkpoint_requires_no_reads_or_new_timestamps(self) -> None:
        progress = {}
        original = nh.collect(SUB, RUN, FixtureReader(), "synthetic-fixture", clock=lambda: TIME, progress=progress)
        with patch.object(nh, "cli_reader") as reader, patch.object(nh, "utc_now") as clock:
            resumed = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=clock, progress=progress)
        self.assertEqual(original, resumed)
        reader.assert_not_called()
        clock.assert_not_called()

    def test_resumed_page_count_drift_and_unknown_associations_remain_explicit(self) -> None:
        def reader():
            fixture = FixtureReader(1)
            fixture.transform = lambda data, op, page: {
                **data, "total_records": data["total_records"] + 1,
            } if op == "vnets" and page > 0 else data
            return fixture

        saved = {}
        stopped = False

        def checkpoint(progress):
            nonlocal saved, stopped
            saved = copy.deepcopy(progress)
            current = progress["current"]
            if current and current["collection"]["operationId"] == "vnets" and current["nextPage"] == 1 and not stopped:
                stopped = True
                raise RuntimeError("Interrupted")

        fixture = reader()
        with self.assertRaises(RuntimeError):
            nh.collect(SUB, RUN, fixture, "synthetic-fixture", 1, lambda: TIME, {}, checkpoint)
        resumed = nh.collect(SUB, RUN, fixture, "synthetic-fixture", 1, lambda: TIME, saved, checkpoint)
        baseline = nh.collect(SUB, RUN, reader(), "synthetic-fixture", 1, lambda: TIME)
        self.assertEqual(resumed, baseline)
        vnets = next(c for c in resumed["collections"] if c["operationId"] == "vnets")
        self.assertIn("InventoryChangedDuringPaging", vnets["issues"])
        model = nh.normalize(resumed)
        beta = next(e for e in model["entities"] if e["entityId"].endswith("/beta/subnets/app"))
        association = next(a for a in model["assertions"] if a["entityId"] == beta["entityId"] and a["property"] == "networkSecurityGroupId")
        self.assertEqual(association["classification"], "UNKNOWN")

    def test_bundle_is_published_only_after_all_files_are_verified(self) -> None:
        _, model, assessment, _ = self.make()
        real_open = Path.open
        writes = []
        with tempfile.TemporaryDirectory() as directory:
            final = Path(directory) / "runs" / RUN

            def opened(path, mode="r", *args, **kwargs):
                if mode == "xb":
                    self.assertFalse(final.exists())
                    self.assertEqual(path.parent.name, "." + RUN + ".pending")
                    writes.append(path.name)
                return real_open(path, mode, *args, **kwargs)

            with patch.object(Path, "open", opened):
                result = nh.bundle(model, assessment, Path(directory))
            self.assertEqual(set(writes), set(nh.obj(result["artifacts"])))
            self.assertEqual(set(p.name for p in final.iterdir()), set(writes))
            self.assertEqual(list(final.parent.iterdir()), [final])

    def test_failed_bundle_writes_are_cleaned_up_and_retryable(self) -> None:
        _, model, assessment, _ = self.make()
        real_open = Path.open
        for failure_at in range(1, 5):
            with self.subTest(failure_at=failure_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                writes = 0

                def opened(path, mode="r", *args, **kwargs):
                    nonlocal writes
                    if mode == "xb":
                        writes += 1
                        if writes == failure_at:
                            raise OSError("Injected write failure")
                    return real_open(path, mode, *args, **kwargs)

                with patch.object(Path, "open", opened):
                    with self.assertRaisesRegex(OSError, "Injected write failure"):
                        nh.bundle(model, assessment, root)
                self.assertEqual(list((root / "runs").iterdir()), [])
                result = nh.bundle(model, assessment, root)
                self.assertEqual(set(nh.obj(result["artifacts"])), {
                    "observed-network.json", "assessment.json",
                    "network-assessment.md", "network-evidence.md",
                })

    def test_failed_bundle_flush_is_explicit_and_retryable(self) -> None:
        _, model, assessment, _ = self.make()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(nh.os, "fsync", side_effect=OSError("Injected sync failure")):
                with self.assertRaisesRegex(OSError, "Injected sync failure"):
                    nh.bundle(model, assessment, root)
            self.assertEqual(list((root / "runs").iterdir()), [])
            nh.bundle(model, assessment, root)

    def test_staged_bundle_corruption_is_rejected_before_publication(self) -> None:
        _, model, assessment, _ = self.make()
        real_read_bytes = Path.read_bytes

        def corrupted(path):
            content = real_read_bytes(path)
            return content + b"corruption" if path.parent.name == "." + RUN + ".pending" else content

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(Path, "read_bytes", corrupted):
                with self.assertRaisesRegex(OSError, "Staged artifact integrity mismatch"):
                    nh.bundle(model, assessment, root)
            self.assertEqual(list((root / "runs").iterdir()), [])
            nh.bundle(model, assessment, root)

    def test_failed_bundle_publication_is_cleaned_up_and_retryable(self) -> None:
        _, model, assessment, _ = self.make()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(Path, "rename", side_effect=OSError("Injected publication failure")):
                with self.assertRaisesRegex(OSError, "Injected publication failure"):
                    nh.bundle(model, assessment, root)
            self.assertEqual(list((root / "runs").iterdir()), [])
            nh.bundle(model, assessment, root)

    def test_existing_pending_bundle_is_preserved_and_blocks_retry(self) -> None:
        _, model, assessment, _ = self.make()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending = root / "runs" / ("." + RUN + ".pending")
            pending.mkdir(parents=True)
            marker = pending / "observed-network.json"
            marker.write_bytes(b"interrupted-private-evidence")
            with self.assertRaises(FileExistsError):
                nh.bundle(model, assessment, root)
            self.assertEqual(marker.read_bytes(), b"interrupted-private-evidence")
            self.assertFalse((root / "runs" / RUN).exists())

    def test_concurrent_same_run_writer_cannot_remove_active_staging(self) -> None:
        _, model, assessment, _ = self.make()
        real_open = Path.open
        attempted = False
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def opened(path, mode="r", *args, **kwargs):
                nonlocal attempted
                if mode == "xb" and not attempted:
                    attempted = True
                    with self.assertRaises(FileExistsError):
                        nh.bundle(model, assessment, root)
                    self.assertTrue(path.parent.exists())
                return real_open(path, mode, *args, **kwargs)

            with patch.object(Path, "open", opened):
                nh.bundle(model, assessment, root)
            self.assertTrue(attempted)
            self.assertEqual(len(list((root / "runs" / RUN).iterdir())), 4)

    def test_final_directory_appearing_during_staging_is_not_overwritten(self) -> None:
        _, model, assessment, _ = self.make()
        real_open = Path.open
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final = root / "runs" / RUN

            def opened(path, mode="r", *args, **kwargs):
                if mode == "xb" and not final.exists():
                    final.mkdir()
                return real_open(path, mode, *args, **kwargs)

            with patch.object(Path, "open", opened):
                with self.assertRaises(FileExistsError):
                    nh.bundle(model, assessment, root)
            self.assertEqual(list(final.iterdir()), [])
            self.assertEqual(list(final.parent.iterdir()), [final])

    def test_contract_version_stays_stable_when_capability_version_changes(self) -> None:
        envelope, model, assessment, _ = self.make()
        self.assertEqual(envelope["inputVersion"], "0.1.0")
        self.assertEqual(model["schemaVersion"], "0.1.0")
        self.assertEqual(assessment["schemaVersion"], "0.1.0")
        self.assertEqual(nh.obj(model["run"])["capabilityVersion"], nh.VERSION)
        self.assertEqual(assessment["capabilityVersion"], nh.VERSION)

    def test_historical_capability_bundles_remain_valid(self) -> None:
        _, model, assessment, _ = self.make()
        nh.obj(model["run"])["capabilityVersion"] = "0.1.0"
        assessment["capabilityVersion"] = "0.1.0"
        nh.obj(assessment["observationArtifact"])["sha256"] = hashlib.sha256(nh.encoded(model)).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            nh.bundle(model, assessment, Path(directory))

    def test_partial_permission_is_not_absence(self) -> None:
        reader = FixtureReader()
        reader.fail = "nsgs"
        _, model, assessment, _ = self.make(reader)
        collection = next(c for c in nh.records(model["collections"]) if c["operationId"] == "nsgs")
        self.assertEqual(collection["status"], "permissionDenied")
        self.assertEqual(assessment["status"], "incomplete-configuration-triage")
        self.assertTrue(any(e["collectionState"] == "referenceOnly"
                            for e in nh.records(model["entities"]) if "networksecuritygroups/app" == nh.text(e["entityId"]).split("/providers/microsoft.network/")[-1]))

    def test_truncation_without_token_stays_partial(self) -> None:
        reader = FixtureReader(1)
        reader.transform = lambda data, op, page: {**data, "skip_token": None} if op == "vnets" else data
        _, model, _, _ = self.make(reader, 1)
        collection = next(c for c in nh.records(model["collections"]) if c["operationId"] == "vnets")
        self.assertIn("TruncatedWithoutContinuation", nh.array(collection["issues"]))
        self.assertEqual(collection["status"], "partial")

    def test_repeated_token_is_bounded(self) -> None:
        reader = FixtureReader(1)
        reader.transform = lambda data, op, page: {**data, "skip_token": "0"} if op == "vnets" else data
        _, model, _, _ = self.make(reader, 1)
        collection = next(c for c in nh.records(model["collections"]) if c["operationId"] == "vnets")
        self.assertIn("RepeatedOrEmptyContinuation", nh.array(collection["issues"]))

    def test_page_budget_is_explicit(self) -> None:
        config = copy.deepcopy(nh.catalog())
        config["maxPagesPerOperation"] = 1
        with patch.object(nh, "catalog", return_value=config):
            _, model, _, _ = self.make(page_size=1)
        collection = next(c for c in nh.records(model["collections"]) if c["operationId"] == "vnets")
        self.assertIn("PageBudgetExceeded", nh.array(collection["issues"]))

    def test_missing_association_is_unknown_not_no_nsg(self) -> None:
        _, model, assessment, _ = self.make()
        beta = next(e for e in nh.records(model["entities"]) if nh.text(e["entityId"]).endswith("/beta/subnets/app"))
        assertions = [a for a in nh.records(model["assertions"])
                      if a["entityId"] == beta["entityId"] and a["property"] == "networkSecurityGroupId"]
        self.assertEqual(assertions[0]["classification"], "UNKNOWN")
        nsg_findings = [f for f in nh.records(assessment["findings"]) if f["checkId"] == "NET-NSG-001"]
        self.assertFalse(any(beta["entityId"] in nh.array(f["affectedResources"]) for f in nsg_findings))

    def test_explicit_no_nsg_is_only_context_observation(self) -> None:
        _, _, assessment, _ = self.make()
        finding = next(f for f in nh.records(assessment["findings"]) if f["checkId"] == "NET-NSG-001")
        self.assertEqual(finding["recordType"], "architectureObservation")
        self.assertIsNone(finding["severity"])

    def test_route_table_presence_does_not_claim_health(self) -> None:
        _, _, assessment, _ = self.make()
        finding = next(f for f in nh.records(assessment["findings"]) if f["checkId"] == "NET-ROUTE-001")
        self.assertIsNone(finding["severity"])
        self.assertIn("not an effective-route", nh.text(finding["reasoning"]))

    def test_no_public_reachability_from_wide_nsg_rule(self) -> None:
        _, _, assessment, _ = self.make()
        self.assertFalse(any(f["recordType"] == "verifiedProblem" for f in nh.records(assessment["findings"])))
        self.assertNotIn("publicly reachable", nh.encoded(assessment).decode())

    def test_overlap_is_risk_not_connectivity_failure(self) -> None:
        _, _, assessment, _ = self.make()
        finding = next(f for f in nh.records(assessment["findings"]) if f["checkId"] == "NET-ADDR-001")
        self.assertEqual(finding["recordType"], "potentialRisk")
        self.assertIn("disconnected networks", nh.text(finding["risk"]))

    def test_peering_state_is_contextual_not_outage(self) -> None:
        _, _, assessment, _ = self.make()
        finding = next(f for f in nh.records(assessment["findings"])
                       if f["checkId"] == "NET-PEER-001" and f["recordType"] == "contextValidation")
        self.assertEqual(finding["recordType"], "contextValidation")
        self.assertIn("no outage", nh.text(finding["risk"]))

    def test_next_hop_bad_ip_and_missing_ip_are_distinct(self) -> None:
        reader = FixtureReader()
        routes = nh.records(reader.resources["routes"])
        nh.obj(routes[0]["properties"])["nextHopIpAddress"] = None
        _, model, assessment, _ = self.make(reader)
        findings = [f for f in nh.records(assessment["findings"]) if f["checkId"] == "NET-ROUTE-002"]
        self.assertEqual({f["recordType"] for f in findings}, {"potentialRisk", "evidenceGap"})
        self.assertTrue(any(r["relationshipType"] == "hasConfiguredNextHop" for r in nh.records(model["relationships"])))
        self.assertFalse(any(r["relationshipType"] == "routesVia" for r in nh.records(model["relationships"])))

    def test_sensitive_extra_properties_are_not_retained(self) -> None:
        reader = FixtureReader()
        vnet = nh.records(reader.resources["vnets"])[0]
        vnet["tags"] = {"credential": "TOP-SECRET"}
        nh.obj(vnet["properties"])["description"] = "TOP-SECRET"
        envelope, model, assessment, _ = self.make(reader)
        self.assertNotIn("TOP-SECRET", nh.encoded(envelope).decode())
        self.assertNotIn("TOP-SECRET", nh.encoded(model).decode())
        self.assertNotIn("TOP-SECRET", nh.encoded(assessment).decode())

    def test_requested_and_returned_scope_are_separate(self) -> None:
        _, model, _, _ = self.make()
        scope = nh.obj(model["scope"])
        self.assertEqual(scope["requestedSubscriptionIds"], [SUB])
        self.assertEqual(scope["returnedSubscriptionIds"], [SUB])
        external = [e for e in nh.records(model["entities"])
                    if e["subscriptionId"] != SUB]
        self.assertTrue(external)
        self.assertTrue(all(e["collectionState"] == "referenceOnly" for e in external))

    def test_unexpected_returned_scope_is_rejected_and_recorded(self) -> None:
        reader = FixtureReader()
        nh.records(reader.resources["vnets"])[0]["id"] = "/subscriptions/00000000-0000-4000-8000-000000000003/foreign"
        _, model, _, _ = self.make(reader)
        collection = next(c for c in nh.records(model["collections"]) if c["operationId"] == "vnets")
        self.assertEqual(collection["status"], "partial")
        self.assertIn("RejectedRow:ValueError", nh.array(collection["issues"]))

    def test_zero_resources_is_not_healthy_or_complete_subscription_claim(self) -> None:
        reader = FixtureReader()
        reader.resources = {key: [] for key in nh.obj(FIXTURE["resources"])}
        _, model, assessment, _ = self.make(reader)
        self.assertEqual(nh.obj(model["coverage"])["permissionCompleteness"], "UNKNOWN")
        self.assertEqual(assessment["status"], "limited-configuration-triage")
        self.assertTrue(nh.records(assessment["findings"]))

    def address_fixture(self, beta_prefix="10.1.0.0/16", linked=False):
        reader = FixtureReader()
        reader.resources["vnets"][1]["properties"]["addressPrefixes"] = [beta_prefix]
        if linked:
            reader.resources["peerings"][0]["properties"]["remoteVNetId"] = reader.resources["vnets"][1]["id"]
        return reader

    def test_disjoint_address_positive_is_aggregated_scoped_and_inferred(self) -> None:
        _, model, assessment, _ = self.make(self.address_fixture())
        positives = [f for f in assessment["findings"] if f["recordType"] == "positiveObservation"]
        self.assertEqual(len(positives), 1)
        positive = positives[0]
        vnets = [entity for entity in model["entities"] if entity["resourceType"] == "microsoft.network/virtualnetworks"]
        self.assertEqual(positive["affectedResources"], sorted(entity["entityId"] for entity in vnets))
        self.assertEqual(positive["interpretationClassification"], "INFERRED")
        self.assertIsNone(positive["severity"])
        self.assertEqual(positive["priority"]["band"], "INFO")
        self.assertEqual(positive["priority"]["actionType"], "none")
        self.assertEqual(positive["checkVersion"], "1.1.0")
        self.assertIn("not permission-wide", positive["reasoning"])
        self.assertTrue(positive["evidenceRefs"])
        self.assertTrue(positive["collectionRefs"])

    def test_overlap_with_configured_peering_prioritizes_evidence_not_proven_outage(self) -> None:
        _, model, assessment, _ = self.make(self.address_fixture("10.0.1.0/24", linked=True))
        overlap = next(f for f in assessment["findings"] if f["checkId"] == "NET-ADDR-001" and f["recordType"] == "potentialRisk")
        peering = next(entity for entity in model["entities"] if entity["resourceType"].endswith("/virtualnetworkpeerings"))
        self.assertEqual(overlap["priority"]["band"], "P1")
        self.assertEqual(overlap["priority"]["actionType"], "evidenceCollection")
        self.assertEqual(overlap["severity"], "medium")
        self.assertEqual(overlap["interpretationClassification"], "INFERRED")
        self.assertIn("Peering mode/subnet selection/IPv6-only settings", overlap["evidenceGaps"])
        self.assertIn("not remediation or an outage claim", overlap["priority"]["reason"])
        self.assertTrue(set(peering["evidenceRefs"]) <= set(overlap["evidenceRefs"]))
        self.assertEqual(overlap["priority"]["rank"], 1)

    def test_overlap_without_retained_peering_link_stays_contextual_p2(self) -> None:
        _, _, assessment, _ = self.make()
        overlap = next(f for f in assessment["findings"] if f["checkId"] == "NET-ADDR-001" and f["recordType"] == "potentialRisk")
        self.assertEqual(overlap["priority"]["band"], "P2")
        self.assertEqual(overlap["priority"]["actionType"], "contextValidation")
        self.assertFalse(any(f["recordType"] == "positiveObservation" for f in assessment["findings"]))

    def test_disjoint_positive_includes_all_comparison_evidence_not_only_subset(self) -> None:
        reader = self.address_fixture("10.0.1.0/24")
        third = copy.deepcopy(reader.resources["vnets"][0])
        third["id"] = third["id"].replace("/alpha", "/gamma")
        third["name"] = "gamma"
        third["properties"] = {"addressPrefixes": ["10.2.0.0/16"], "subnetCount": 0, "peeringCount": 0}
        reader.resources["vnets"].append(third)
        _, model, assessment, _ = self.make(reader)
        positive = next(f for f in assessment["findings"] if f["recordType"] == "positiveObservation")
        self.assertEqual(len(positive["affectedResources"]), 1)
        self.assertTrue(positive["affectedResources"][0].endswith("/gamma"))
        refs = {ref for entity in model["entities"] if entity["resourceType"] == "microsoft.network/virtualnetworks" for ref in entity["evidenceRefs"]}
        self.assertEqual(set(positive["evidenceRefs"]), refs)
        self.assertIn("1 of 3", positive["observedState"])

    def test_address_positive_suppressed_for_empty_invalid_or_partial_vnet_evidence(self) -> None:
        for scenario in ("empty", "invalid", "partial", "single"):
            with self.subTest(scenario=scenario):
                reader = self.address_fixture()
                if scenario == "empty":
                    reader.resources["vnets"][0]["properties"]["addressPrefixes"] = []
                elif scenario == "invalid":
                    reader.resources["vnets"][0]["properties"]["addressPrefixes"] = ["invalid-prefix"]
                elif scenario == "partial":
                    reader.resources["vnets"].append(copy.deepcopy(reader.resources["vnets"][0]))
                else:
                    reader.resources["vnets"] = reader.resources["vnets"][:1]
                _, _, assessment, _ = self.make(reader)
                self.assertFalse(any(f["recordType"] == "positiveObservation" for f in assessment["findings"]))
                if scenario in ("empty", "invalid"):
                    self.assertTrue(any(f["checkId"] == "NET-ADDR-001" and f["recordType"] == "evidenceGap" for f in assessment["findings"]))

    def test_address_comparison_handles_ipv6_and_distinct_address_families(self) -> None:
        for first, second, overlap in (
            ("2001:db8::/32", "2001:db8:1::/48", True),
            ("2001:db8::/48", "2001:db8:1::/48", False),
            ("10.0.0.0/16", "2001:db8::/32", False),
        ):
            with self.subTest(first=first, second=second):
                reader = self.address_fixture(second)
                reader.resources["vnets"][0]["properties"]["addressPrefixes"] = [first]
                _, _, assessment, _ = self.make(reader)
                risks = [f for f in assessment["findings"] if f["checkId"] == "NET-ADDR-001" and f["recordType"] == "potentialRisk"]
                positives = [f for f in assessment["findings"] if f["recordType"] == "positiveObservation"]
                self.assertEqual(bool(risks), overlap)
                self.assertEqual(bool(positives), not overlap)

    def test_historical_check_catalog_and_policy_remain_verified_without_reassessment(self) -> None:
        _, model, assessment, _ = self.make()
        assessment["capabilityVersion"] = "0.1.4"
        assessment["checkCatalogVersion"] = "1.0.0"
        assessment["priorityPolicyVersion"] = "1.0.0"
        for check in assessment["checksExecuted"]:
            check["checkVersion"] = "1.0.0"
        for finding in assessment["findings"]:
            finding["checkVersion"] = "1.0.0"
        nh.verify_assessment(model, assessment)
        assessment["priorityPolicyVersion"] = "1.1.0"
        with self.assertRaisesRegex(ValueError, "Priority policy"):
            nh.verify_assessment(model, assessment)

    def reciprocal_fixture(self, reverse=True):
        reader = self.address_fixture()
        alpha, beta = reader.resources["vnets"]
        forward = reader.resources["peerings"][0]
        forward["properties"].update({
            "remoteVNetId": beta["id"], "peeringState": "Connected", "provisioningState": "Succeeded",
        })
        if reverse:
            backwards = copy.deepcopy(forward)
            backwards.update({
                "id": beta["id"] + "/virtualNetworkPeerings/to-alpha",
                "name": "to-alpha", "parentId": beta["id"],
            })
            backwards["properties"]["remoteVNetId"] = alpha["id"]
            reader.resources["peerings"].append(backwards)
            beta["properties"]["peeringCount"] = 1
        return reader

    def test_reciprocal_connected_configuration_is_one_observed_informational_record(self) -> None:
        reader = self.reciprocal_fixture()
        reader.resources["peerings"][0]["properties"]["allowVirtualNetworkAccess"] = False
        _, model, assessment, _ = self.make(reader)
        records = [f for f in assessment["findings"] if f["checkId"] == "NET-PEER-001"]
        self.assertEqual(len(records), 1)
        item = records[0]
        self.assertEqual(item["recordType"], "architectureObservation")
        self.assertEqual(item["interpretationClassification"], "OBSERVED")
        self.assertEqual(item["priority"]["actionType"], "none")
        self.assertEqual(item["priority"]["band"], "INFO")
        self.assertEqual(len(item["affectedResources"]), 2)
        refs = {ref for entity in model["entities"] if entity["resourceType"].endswith("/virtualnetworkpeerings") for ref in entity["evidenceRefs"]}
        self.assertEqual(set(item["evidenceRefs"]), refs)
        self.assertIn("configuration state only", item["reasoning"])
        self.assertIn("Access/NSG/route applicability", item["evidenceGaps"])
        self.assertFalse(any(f["recordType"] == "positiveObservation" and f["checkId"] == "NET-PEER-001" for f in records))

    def test_one_direction_is_an_unobserved_reciprocal_gap_not_missing_peering_defect(self) -> None:
        _, _, assessment, _ = self.make(self.reciprocal_fixture(False))
        items = [f for f in assessment["findings"] if f["checkId"] == "NET-PEER-001"]
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["title"], "Reciprocal peering was not observed in collected configuration")
        self.assertEqual(item["recordType"], "evidenceGap")
        self.assertIsNone(item["severity"])
        self.assertEqual(item["priority"]["actionType"], "evidenceCollection")
        self.assertIn("not proof that the reverse is absent", item["reasoning"])

    def test_initiated_and_transitional_states_are_context_not_failed_connectivity(self) -> None:
        for state, provisioning in (("Initiated", "Succeeded"), ("Connected", "Updating"), ("Updating", "Creating"), ("Connected", "Deleting")):
            with self.subTest(state=state, provisioning=provisioning):
                reader = self.reciprocal_fixture()
                reader.resources["peerings"][0]["properties"].update({"peeringState": state, "provisioningState": provisioning})
                _, _, assessment, _ = self.make(reader)
                items = [f for f in assessment["findings"] if f["checkId"] == "NET-PEER-001"]
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]["recordType"], "contextValidation")
                self.assertIsNone(items[0]["severity"])
                self.assertIn("no persistent failure", items[0]["risk"])
                self.assertIn("Expected timing/connectivity intent", items[0]["evidenceGaps"])

    def test_failed_reciprocal_pair_is_deduplicated_contextual_medium(self) -> None:
        reader = self.reciprocal_fixture()
        for peering in reader.resources["peerings"]:
            peering["properties"]["peeringState"] = "Disconnected"
        _, _, assessment, _ = self.make(reader)
        items = [f for f in assessment["findings"] if f["checkId"] == "NET-PEER-001"]
        self.assertEqual(len(items), 1)
        self.assertEqual(len(items[0]["affectedResources"]), 2)
        self.assertEqual(items[0]["severity"], "medium")
        self.assertEqual(items[0]["recordType"], "contextValidation")
        self.assertIn("no outage", items[0]["risk"])

    def test_unavailable_or_future_directional_states_are_unknown_evidence(self) -> None:
        for property_name, value in (("peeringState", None), ("peeringState", "FutureState"), ("provisioningState", None), ("provisioningState", "FutureProvisioning")):
            with self.subTest(property_name=property_name, value=value):
                reader = self.reciprocal_fixture()
                reader.resources["peerings"][0]["properties"][property_name] = value
                _, _, assessment, _ = self.make(reader)
                item = next(f for f in assessment["findings"] if f["checkId"] == "NET-PEER-001")
                self.assertEqual(item["recordType"], "evidenceGap")
                self.assertEqual(item["interpretationClassification"], "UNKNOWN")
                self.assertIsNone(item["severity"])

    def test_external_unknown_or_self_target_stays_scoped_without_new_reads(self) -> None:
        for scenario in ("external", "unknown", "self"):
            with self.subTest(scenario=scenario):
                reader = FixtureReader()
                if scenario == "unknown":
                    reader.resources["peerings"][0]["properties"]["remoteVNetId"] = None
                elif scenario == "self":
                    reader.resources["peerings"][0]["properties"]["remoteVNetId"] = reader.resources["vnets"][0]["id"]
                _, model, assessment, _ = self.make(reader)
                gap = next(f for f in assessment["findings"] if f["title"] == "Reciprocal peering evidence is outside collected VNet context")
                self.assertEqual(gap["recordType"], "evidenceGap")
                self.assertIn("do not expand scope", gap["recommendation"])
                self.assertEqual(len(reader.calls), 9)
                if scenario == "external":
                    self.assertTrue(any(e["collectionState"] == "referenceOnly" and e["subscriptionId"] != SUB for e in model["entities"]))

    def test_ambiguous_pair_does_not_select_an_arbitrary_reciprocal(self) -> None:
        reader = self.reciprocal_fixture()
        duplicate_direction = copy.deepcopy(reader.resources["peerings"][0])
        duplicate_direction["id"] += "-alternative"
        duplicate_direction["name"] = "alternative"
        reader.resources["peerings"].append(duplicate_direction)
        reader.resources["vnets"][0]["properties"]["peeringCount"] = 2
        _, _, assessment, _ = self.make(reader)
        items = [f for f in assessment["findings"] if f["checkId"] == "NET-PEER-001"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Reciprocal peering configuration is ambiguous")
        self.assertEqual(len(items[0]["affectedResources"]), 3)
        self.assertEqual(items[0]["recordType"], "evidenceGap")

    def test_partial_peering_collection_suppresses_connected_pair_information(self) -> None:
        reader = self.reciprocal_fixture()
        reader.resources["peerings"].append(copy.deepcopy(reader.resources["peerings"][0]))
        _, _, assessment, _ = self.make(reader)
        items = [f for f in assessment["findings"] if f["checkId"] == "NET-PEER-001"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Reciprocal peering collection evidence is incomplete")
        self.assertEqual(items[0]["recordType"], "evidenceGap")

    def test_previous_address_catalog_remains_valid_with_peering_version_preserved(self) -> None:
        _, model, assessment, _ = self.make(self.address_fixture())
        assessment["capabilityVersion"] = "0.1.5"
        assessment["checkCatalogVersion"] = "1.1.0"
        for check in assessment["checksExecuted"]:
            if check["checkId"] == "NET-PEER-001":
                check["checkVersion"] = "1.0.0"
        for item in assessment["findings"]:
            if item["checkId"] == "NET-PEER-001":
                item["checkVersion"] = "1.0.0"
        nh.verify_assessment(model, assessment)
        peer = next(c for c in assessment["checksExecuted"] if c["checkId"] == "NET-PEER-001")
        peer["checkVersion"] = "1.1.0"
        with self.assertRaisesRegex(ValueError, "executed check versions"):
            nh.verify_assessment(model, assessment)

    def test_duplicate_and_case_variant_ids_are_stable(self) -> None:
        reader = FixtureReader()
        rows = nh.records(reader.resources["vnets"])
        duplicate = copy.deepcopy(rows[0])
        duplicate["id"] = nh.text(duplicate["id"]).upper()
        rows.append(duplicate)
        reader.resources["vnets"] = rows
        _, model, _, _ = self.make(reader)
        collected = [e for e in nh.records(model["entities"])
                     if e["resourceType"] == "microsoft.network/virtualnetworks"]
        self.assertEqual(len(collected), 2)
        self.assertEqual(nh.obj(model["coverage"])["status"], "partial")

    def test_child_count_gap_is_explicit(self) -> None:
        reader = FixtureReader()
        nh.obj(nh.records(reader.resources["vnets"])[0]["properties"])["subnetCount"] = 2001
        _, model, _, _ = self.make(reader)
        self.assertTrue(any(nh.text(i).startswith("ChildExpansionLimit") for i in nh.array(nh.obj(model["coverage"])["issues"])))

    def test_evidence_corruption_and_inference_fail_verification(self) -> None:
        _, original, _, _ = self.make()
        model = copy.deepcopy(original)
        nh.records(model["evidence"])[0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "integrity"):
            nh.verify_observation(model)
        model = copy.deepcopy(original)
        nh.records(model["assertions"])[0]["classification"] = "INFERRED"
        with self.assertRaisesRegex(ValueError, "inferred"):
            nh.verify_observation(model)

    def test_run_id_check_versions_and_evidence_links_are_verified(self) -> None:
        _, model, original, _ = self.make()
        for kind in ("runId", "checkVersion", "evidenceRefs"):
            with self.subTest(kind=kind):
                assessment = copy.deepcopy(original)
                if kind == "runId":
                    assessment["runId"] = "00000000-0000-4000-8000-000000000004"
                elif kind == "checkVersion":
                    nh.records(assessment["findings"])[0]["checkVersion"] = "99.0.0"
                else:
                    nh.records(assessment["findings"])[0]["evidenceRefs"] = ["missing"]
                with self.assertRaises(ValueError):
                    nh.verify_assessment(model, assessment)

    def test_observation_schema_forbids_findings_and_ambiguous_routes(self) -> None:
        _, original, _, _ = self.make()
        model = copy.deepcopy(original)
        model["findings"] = []
        with self.assertRaises(ValidationError):
            validate_document(model, SKILL / "observed-network.schema.json")
        model = copy.deepcopy(original)
        nh.records(model["relationships"])[0]["relationshipType"] = "routesVia"
        with self.assertRaises(ValidationError):
            validate_document(model, SKILL / "observed-network.schema.json")

    def test_reports_need_only_assessment_and_escape_table_text(self) -> None:
        _, _, assessment, _ = self.make()
        nh.records(assessment["findings"])[0]["title"] = "Example | <script>"
        summary, engineering = nh.render(assessment)
        self.assertIn("Example \\| &lt;script&gt;", summary)
        self.assertNotIn("<script>", engineering)
        self.assertIn(nh.text(assessment["runId"]), summary)
        self.assertIn(nh.text(assessment["runId"]), engineering)

    def test_report_dynamic_markdown_is_literal_and_does_not_change_json(self) -> None:
        _, _, assessment, _ = self.make()
        title = "Literal ](#not-a-link) [label](https://example.invalid) `code` *bold* _name_ \\path | <tag>\nnext"
        assessment["findings"][0]["title"] = title
        before = nh.encoded(assessment)
        summary, engineering = nh.render(assessment)
        escaped = nh.markdown(title)
        self.assertIn(escaped, summary)
        self.assertIn(escaped, engineering)
        self.assertIn(r"\]\(#not-a-link\)", summary)
        self.assertIn(r"\`code\` \*bold\* \_name\_ \\path \| &lt;tag&gt; next", summary)
        self.assertEqual(before, nh.encoded(assessment))
        nh.verify_reports(assessment, summary, engineering)

    def test_selected_json_link_syntax_and_html_stay_literal_not_report_links(self) -> None:
        _, _, assessment, _ = self.make()
        evidence = assessment["evidenceCatalog"][0]
        literal = 'Literal [text](#not-a-link) <a id="not-an-anchor"></a> ```'
        evidence["excerpt"]["name"] = literal
        evidence["sha256"] = nh.digest(evidence["excerpt"])
        before = nh.encoded(assessment)
        summary, engineering = nh.render(assessment)
        blocks = re.findall(r"```json\n(.*?)\n```", engineering, re.S)
        excerpts = [json.loads(block) for block in blocks]
        self.assertTrue(any(excerpt.get("name") == literal for excerpt in excerpts))
        self.assertEqual(before, nh.encoded(assessment))
        nh.verify_reports(assessment, summary, engineering)

    def test_report_escaping_does_not_accept_unapproved_source_metadata(self) -> None:
        _, _, assessment, _ = self.make()
        source = "connected [source](#not-a-link) *literal*"
        assessment["evidenceCatalog"][0]["source"] = source
        with self.assertRaises(ValidationError):
            nh.render(assessment)

    def test_missing_duplicate_and_wrong_document_links_are_rejected(self) -> None:
        _, _, assessment, _ = self.make()
        summary, engineering = nh.render(assessment)
        first = assessment["findings"][0]
        target = "(network-evidence.md#" + first["findingId"].lower() + ")"
        for changed in (
            summary.replace(target, "", 1),
            summary + "\n[duplicate]" + target + "\n",
            summary.replace(target, "(#" + first["findingId"].lower() + ")", 1),
        ):
            with self.subTest(summary=changed[-100:]):
                with self.assertRaisesRegex(ValueError, "generated links"):
                    nh.verify_reports(assessment, changed, engineering)
        linked = next(finding for finding in assessment["findings"] if finding["evidenceRefs"])
        ref = linked["evidenceRefs"][0]
        changed = engineering.replace(f"[{ref}](#{ref})", ref, 1)
        with self.assertRaisesRegex(ValueError, "generated links"):
            nh.verify_reports(assessment, summary, changed)

    def test_report_version_provenance_and_all_executed_checks_are_verified(self) -> None:
        _, _, assessment, _ = self.make()
        summary, engineering = nh.render(assessment)
        for marker in nh.report_provenance(assessment):
            self.assertEqual(summary.splitlines().count(marker), 1)
            self.assertEqual(engineering.splitlines().count(marker), 1)
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(ValueError, "version provenance"):
                    nh.verify_reports(assessment, summary.replace(marker, marker + "-changed", 1), engineering)
                with self.assertRaisesRegex(ValueError, "version provenance"):
                    nh.verify_reports(assessment, summary, engineering.replace(marker, "", 1))
        check = assessment["checksExecuted"][0]
        marker = f"| {check['checkId']} | {check['checkVersion']} |"
        with self.assertRaisesRegex(ValueError, "executed check versions"):
            nh.verify_reports(assessment, summary, engineering.replace(marker, "", 1))

    def test_unsafe_report_identifiers_are_explicitly_rejected(self) -> None:
        _, _, assessment, _ = self.make()
        assessment["findings"][0]["findingId"] = 'unsafe"><tag>'
        with self.assertRaisesRegex(ValueError, "Unsafe Markdown"):
            nh.render(assessment)

    def test_legacy_report_provenance_remains_accepted_without_relabeling(self) -> None:
        _, _, assessment, _ = self.make()
        assessment["capabilityVersion"] = "0.1.2"
        summary, engineering = nh.render(assessment)
        for marker in nh.report_provenance(assessment):
            if not marker.startswith("**Capability:"):
                summary = summary.replace(marker + "\n", "", 1)
            engineering = engineering.replace(marker + "\n", "", 1)
        start = engineering.index("## Executed checks\n")
        end = engineering.index("## Collection coverage\n")
        engineering = engineering[:start] + engineering[end:]
        nh.verify_reports(assessment, summary, engineering)
        self.assertIn("**Capability:** 0.1.2", summary)
        self.assertNotIn("**Capability:**", engineering)

    def test_markdown_links_and_interpretation_are_verified(self) -> None:
        _, _, assessment, _ = self.make()
        summary, engineering = nh.render(assessment)
        with self.assertRaisesRegex(ValueError, "Markdown evidence link"):
            nh.verify_reports(assessment, summary + "\n[broken](#missing)\n", engineering)
        for finding in nh.records(assessment["findings"]):
            if finding["recordType"] in ("potentialRisk", "contextValidation"):
                self.assertEqual(finding["interpretationClassification"], "INFERRED")
            elif finding["recordType"] == "evidenceGap":
                self.assertEqual(finding["interpretationClassification"], "UNKNOWN")

    def test_unknown_relationship_target_is_retained_as_unknown(self) -> None:
        reader = FixtureReader()
        nh.obj(nh.records(reader.resources["peerings"])[0]["properties"])["remoteVNetId"] = "unavailable-target"
        _, model, _, _ = self.make(reader)
        relationship = next(r for r in nh.records(model["relationships"]) if r["relationshipType"] == "peeringTo")
        self.assertIsNone(relationship["targetId"])
        self.assertEqual(relationship["classification"], "UNKNOWN")
        self.assertIn("InvalidRelationshipTarget", nh.array(nh.obj(model["coverage"])["issues"]))

    def test_guidance_format_is_explicitly_checked(self) -> None:
        _, _, assessment, _ = self.make()
        nh.records(assessment["findings"])[0]["guidanceReferences"] = ["https://unverified.example"]
        with self.assertRaises(ValidationError):
            validate_document(assessment, SKILL / "assessment.schema.json")

    def test_acquisition_version_and_scope_cannot_be_forged(self) -> None:
        original, _, _, _ = self.make()
        for key, value in (
            ("operationVersion", "99.0.0"),
            ("querySha256", "0" * 64),
            ("returnedSubscriptionIds", ["00000000-0000-4000-8000-000000000003"]),
        ):
            with self.subTest(key=key):
                envelope = copy.deepcopy(original)
                graph = next(c for c in nh.records(envelope["collections"]) if c["operationId"] == "vnets")
                graph[key] = value
                with self.assertRaises(ValueError):
                    nh.normalize(envelope)

    def test_changed_check_version_is_recorded_without_changing_observations(self) -> None:
        _, model, original, _ = self.make()
        catalog = copy.deepcopy(nh.load(SKILL / "checks.json"))
        nh.records(catalog["checks"])[0]["checkVersion"] = "1.0.1"
        real_load = nh.load

        def loaded(path):
            return catalog if path.name == "checks.json" else real_load(path)

        before = nh.encoded(model)
        with patch.object(nh, "load", side_effect=loaded):
            updated = nh.assess(model)
        self.assertEqual(before, nh.encoded(model))
        overlaps = [f for f in nh.records(updated["findings"]) if f["checkId"] == "NET-ADDR-001"]
        self.assertTrue(all(f["checkVersion"] == "1.0.1" for f in overlaps))
        self.assertNotEqual(updated["checksExecuted"], original["checksExecuted"])


if __name__ == "__main__":
    unittest.main()
