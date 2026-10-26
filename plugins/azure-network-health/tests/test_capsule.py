from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import network_health_capsule as capsule


SUB = "00000000-0000-4000-8000-000000000002"
CAPSULE = "00000000-0000-4000-8000-000000000003"
TIME = "2026-10-12T20:00:00Z"


def fixture(root: Path) -> Path:
    source = root / "source"
    source.mkdir()
    types = {
        "storage": ("Microsoft.Storage/storageAccounts", "2023-05-01"),
        "keyvault": ("Microsoft.KeyVault/vaults", "2023-07-01"),
        "acr": ("Microsoft.ContainerRegistry/registries", "2023-07-01"),
        "loganalytics": ("Microsoft.OperationalInsights/workspaces", "2023-09-01"),
    }
    records = {}
    indexed = []
    for family, (resource_type, api) in types.items():
        identifier = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/{resource_type}/{family}"
        indexed.append({"id": identifier, "subscriptionId": SUB, "type": resource_type.lower(),
                        "name": family, "resourceGroup": "fixture", "location": "eastus"})
        row = {"id": identifier, "type": resource_type}
        if family == "loganalytics":
            row.update({"publicNetworkAccessForIngestion": "Enabled", "publicNetworkAccessForQuery": "Disabled",
                        "privateLinkScopedResources": None})
        elif family == "acr":
            row.update({"publicNetworkAccess": "Enabled", "networkRuleBypassOptions": "None", "networkRuleSet": None})
        else:
            row.update({"publicNetworkAccess": "Disabled", "networkAcls": {
                "bypass": "None", "defaultAction": "Deny", "ipRules": [],
                "virtualNetworkRules": [],
            }})
            if family == "storage":
                row["networkAcls"]["ipv6Rules"] = [{"value": "2001:db8::/32", "action": "Allow"}]
                row["networkAcls"]["resourceAccessRules"] = []
        url = f"https://management.azure.com/subscriptions/{SUB}/providers/{resource_type}?api-version={api}"
        records[family + "-arm.json"] = {
            "source": "synthetic operator ARM GET", "subscriptionId": SUB, "requestUrl": url,
            "projection": "selected configuration", "startedAtUtc": TIME, "completedAtUtc": TIME,
            "status": "succeeded", "retention": "selected configuration, private",
            "selected": {"items": [row], "nextLink": None},
        }
    next_link = records["keyvault-arm.json"]["requestUrl"] + "&%24skiptoken=fixture"
    records["keyvault-arm.json"]["status"] = "partial"
    records["keyvault-arm.json"]["selected"]["nextLink"] = next_link
    records["keyvault-arm-page2.json"] = {
        **copy.deepcopy(records["keyvault-arm.json"]), "requestUrl": next_link,
        "status": "succeeded", "page": 2, "selected": {"items": [], "nextLink": None},
    }
    for family, resource_type, api in (
        ("nsp", "Microsoft.Network/networkSecurityPerimeters", "2024-07-01"),
        ("ampls", "Microsoft.Insights/privateLinkScopes", "2021-07-01-preview"),
    ):
        records[family + "-root-arm.json"] = {
            "source": "synthetic operator ARM GET", "subscriptionId": SUB, "tenantId": SUB,
            "requestUrl": f"https://management.azure.com/subscriptions/{SUB}/providers/{resource_type}?api-version={api}",
            "startedAtUtc": TIME, "completedAtUtc": TIME, "status": "succeeded",
            "retention": "selected root metadata", "selected": {"items": [], "nextLink": None},
        }
    records["arg-inventory.json"] = {
        "source": "synthetic operator ARG", "recordedAtUtc": TIME, "scopeSubscriptionId": SUB,
        "retention": "selected metadata", "coverage": "visible selected scope",
        "response": {"isSuccessful": True, "results": {"$id": "1", "data": indexed, "facets": []},
                     "rowCount": 4, "totalRecords": 4, "resultTruncated": False, "executedQuery": "fixture"},
    }
    records["keyvault-continuation-failed-attempt.json"] = {
        "source": "synthetic operator", "recordedAtUtc": TIME, "requestUrl": next_link,
        "status": "clientInvocationFailed", "code": "WindowsCmdContinuationArgumentFailure",
        "observedError": "synthetic argument failure", "azureReadCompletion": "unknown",
        "resourceMutationAttempted": False,
    }
    records["inventory-summary.json"] = {
        "recordedAtUtc": TIME, "source": "synthetic summary", "subscriptionId": SUB, "families": [],
        "indexedAndDirectIdSetsMatch": True, "indexedAndDirectVisibleResourceCount": 4,
        "coverage": "visible selected scope", "classificationPerformed": False,
        "sreAgentCollectorExecuted": False, "failedAttemptRetained": "keyvault-continuation-failed-attempt.json",
    }
    for name, record in records.items():
        (source / name).write_bytes(capsule.nh.encoded(record))
    index(source)
    return source


def index(source: Path) -> None:
    members = []
    for path in sorted(source.glob("*.json")):
        if path.name != "evidence-index.json":
            content = path.read_bytes()
            members.append({"name": path.name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    value = {
        "recordedAtUtc": TIME, "sensitivity": "private selected configuration",
        "retention": "retain until owner cleanup", "identifierHandling": "selected resource IDs",
        "assessmentClassification": "not performed", "scopeSubscriptionId": SUB,
        "controlReadCoverage": "selected scoped roots only", "artifacts": members,
    }
    (source / "evidence-index.json").write_bytes(capsule.nh.encoded(value))


class CapsuleTests(unittest.TestCase):
    def build(self, root: Path):
        source = fixture(root)
        output = root / "private"
        output.mkdir()
        return source, output, capsule.seal(source, output, CAPSULE)

    def test_duplicate_json_fields_are_rejected_even_when_the_last_value_is_valid(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, directory = self.build(Path(temporary))
            path = directory / capsule.MANIFEST
            text = path.read_text()
            path.write_text(text.replace('"capsuleVersion": "0.1.0"',
                                         '"capsuleVersion": "unsupported", "capsuleVersion": "0.1.0"'))
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                capsule.verify(directory)

    def test_selected_metadata_cannot_hide_unreviewed_payload_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            path = source / "storage-arm.json"
            record = json.loads(path.read_bytes())
            record["source"] = {"unreviewedPayload": {"password": "synthetic-do-not-retain"}}
            path.write_bytes(capsule.nh.encoded(record))
            index(source)
            output = root / "private"
            output.mkdir()
            with self.assertRaises(ValueError):
                capsule.seal(source, output, CAPSULE)
            self.assertEqual(list(output.iterdir()), [])

    def test_duplicate_indexed_resources_cannot_discard_source_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            path = source / "arg-inventory.json"
            record = json.loads(path.read_bytes())
            record["response"]["results"]["data"][1] = copy.deepcopy(record["response"]["results"]["data"][0])
            path.write_bytes(capsule.nh.encoded(record))
            index(source)
            output = root / "private"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "Duplicate indexed"):
                capsule.seal(source, output, CAPSULE)

    def test_unsigned_capsule_cannot_claim_verified_source_authentication(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, directory = self.build(Path(temporary))
            path = directory / capsule.MANIFEST
            manifest = json.loads(path.read_bytes())
            manifest["assurance"]["sourceAuthentication"] = "verified"
            path.write_bytes(capsule.nh.encoded(manifest))
            with self.assertRaisesRegex(ValueError, "assurance"):
                capsule.verify(directory)

    def test_missing_source_index_fields_fail_explicitly_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            (source / capsule.INDEX).write_bytes(b"{}\n")
            output = root / "private"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "fields"):
                capsule.seal(source, output, CAPSULE)
            self.assertEqual(list(output.iterdir()), [])

    def test_continuation_evidence_must_match_the_saved_next_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            path = source / "keyvault-arm-page2.json"
            record = json.loads(path.read_bytes())
            record["requestUrl"] = record["requestUrl"].replace("skiptoken=fixture", "skiptoken=unrelated")
            path.write_bytes(capsule.nh.encoded(record))
            index(source)
            output = root / "private"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "continuation"):
                capsule.seal(source, output, CAPSULE)

    def test_resource_identity_must_match_its_recorded_type(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            path = source / "storage-arm.json"
            record = json.loads(path.read_bytes())
            record["selected"]["items"][0]["id"] = record["selected"]["items"][0]["id"].replace(
                "Microsoft.Storage/storageAccounts", "Microsoft.Compute/virtualMachines",
            )
            path.write_bytes(capsule.nh.encoded(record))
            index(source)
            output = root / "private"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "type"):
                capsule.seal(source, output, CAPSULE)

    def test_member_tampering_missing_and_extra_files_are_rejected(self):
        for change in ("tampered", "missing", "extra"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                _, _, directory = self.build(Path(temporary))
                path = directory / "storage-arm.json"
                if change == "tampered":
                    path.write_bytes(path.read_bytes().replace(b"Disabled", b"Enabled "))
                elif change == "missing":
                    path.unlink()
                else:
                    (directory / "unexpected.json").write_bytes(b"{}\n")
                with self.assertRaises(ValueError):
                    capsule.verify(directory)

    def test_manifest_versions_scope_and_member_paths_are_bound(self):
        for field, value in (
            ("capsuleVersion", "99.0.0"), ("profileId", "unreviewed"),
            ("profileVersion", "99.0.0"), ("scopeSubscriptionId", CAPSULE),
            ("memberName", "../outside.json"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                _, _, directory = self.build(Path(temporary))
                path = directory / capsule.MANIFEST
                manifest = json.loads(path.read_bytes())
                if field == "memberName":
                    manifest["members"][0]["name"] = value
                else:
                    manifest[field] = value
                path.write_bytes(capsule.nh.encoded(manifest))
                with self.assertRaises(ValueError):
                    capsule.verify(directory)

    def test_unreviewed_resource_fields_and_foreign_scopes_are_not_retained(self):
        for change in ("credentials", "foreignScope", "extraSource"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = fixture(root)
                if change == "extraSource":
                    (source / "unreviewed.json").write_bytes(b"{}\n")
                else:
                    path = source / "storage-arm.json"
                    record = json.loads(path.read_bytes())
                    if change == "credentials":
                        record["selected"]["items"][0]["keys"] = ["synthetic-do-not-retain"]
                    else:
                        record["subscriptionId"] = CAPSULE
                    path.write_bytes(capsule.nh.encoded(record))
                    index(source)
                output = root / "private"
                output.mkdir()
                with self.assertRaises(ValueError):
                    capsule.seal(source, output, CAPSULE)
                self.assertEqual(list(output.iterdir()), [])

    def test_replay_preserves_denied_and_partial_evidence_without_empty_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            path = source / "storage-arm.json"
            record = json.loads(path.read_bytes())
            record.update({"status": "permissionDenied", "errorCode": "Forbidden", "selected": None})
            path.write_bytes(capsule.nh.encoded(record))
            index(source)
            output = root / "private"
            output.mkdir()
            replay = capsule.replay(capsule.seal(source, output, CAPSULE))
            denied = next(row for row in replay["coverage"]["collections"] if row["member"] == "storage-arm.json")
            self.assertEqual(denied["status"], "permissionDenied")
            self.assertIsNone(denied["returnedRows"])
            partial = next(row for row in replay["coverage"]["collections"] if row["member"] == "keyvault-arm.json")
            self.assertEqual(partial["status"], "partial")
            self.assertIsNotNone(partial["nextLink"])
            storage = next(row for row in replay["resources"] if row["type"] == "microsoft.storage/storageaccounts")
            self.assertEqual([row["member"] for row in storage["observations"]], ["arg-inventory.json"])

    def test_published_capsule_is_not_overwritten_and_replay_is_source_independent(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output, directory = self.build(Path(temporary))
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            expected = capsule.replay(directory)
            with self.assertRaises(FileExistsError):
                capsule.seal(source, output, CAPSULE)
            self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)
            (source / "storage-arm.json").unlink()
            self.assertEqual(capsule.replay(directory), expected)
            self.assertEqual([path.name for path in output.iterdir()], [CAPSULE])

    def test_member_byte_limit_accepts_exactly_five_mib_and_rejects_one_more(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            path = source / "arg-inventory.json"
            content = path.read_bytes()
            path.write_bytes(content + b" " * (5 * 1024 * 1024 - len(content)))
            index(source)
            output = root / "private"
            output.mkdir()
            directory = capsule.seal(source, output, CAPSULE)
            self.assertEqual((directory / path.name).stat().st_size, 5 * 1024 * 1024)
            capsule.verify(directory)
            with path.open("ab") as stream:
                stream.write(b" ")
            index(source)
            with self.assertRaisesRegex(ValueError, "byte budget"):
                capsule.seal(source, output, SUB)
            self.assertFalse((output / SUB).exists())

    def test_total_byte_limit_accepts_twenty_mib_and_rejects_one_more(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            for name in ("arg-inventory.json", "storage-arm.json", "keyvault-arm.json", "loganalytics-arm.json"):
                path = source / name
                content = path.read_bytes()
                target = 5 * 1024 * 1024 - (64 * 1024 if name == "loganalytics-arm.json" else 0)
                path.write_bytes(content + b" " * (target - len(content)))
            index(source)
            output = root / "private"
            output.mkdir()
            directory = capsule.seal(source, output, CAPSULE)
            remaining = 20 * 1024 * 1024 - sum(path.stat().st_size for path in directory.iterdir())
            manifest = directory / capsule.MANIFEST
            self.assertGreater(remaining, 0)
            self.assertLessEqual(manifest.stat().st_size + remaining, 64 * 1024)
            with manifest.open("ab") as stream:
                stream.write(b" " * remaining)
            self.assertEqual(sum(path.stat().st_size for path in directory.iterdir()), 20 * 1024 * 1024)
            capsule.verify(directory)
            with manifest.open("ab") as stream:
                stream.write(b" ")
            with self.assertRaisesRegex(ValueError, "total byte budget"):
                capsule.verify(directory)

    def test_manifest_byte_limit_accepts_sixty_four_kib_and_rejects_one_more(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, directory = self.build(Path(temporary))
            path = directory / capsule.MANIFEST
            content = path.read_bytes()
            path.write_bytes(content + b" " * (64 * 1024 - len(content)))
            capsule.verify(directory)
            with path.open("ab") as stream:
                stream.write(b" ")
            with self.assertRaisesRegex(ValueError, "byte budget"):
                capsule.verify(directory)

    def test_response_row_limit_accepts_one_thousand_and_rejects_one_more(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            path = source / "storage-arm.json"
            record = json.loads(path.read_bytes())
            original = record["selected"]["items"][0]
            rows = []
            for number in range(1000):
                row = copy.deepcopy(original)
                row["id"] += "-" + str(number)
                rows.append(row)
            record["selected"]["items"] = rows
            path.write_bytes(capsule.nh.encoded(record))
            index(source)
            output = root / "private"
            output.mkdir()
            directory = capsule.seal(source, output, CAPSULE)
            collection = next(row for row in capsule.verify(directory)["coverage"]["collections"]
                              if row["member"] == "storage-arm.json")
            self.assertEqual(collection["returnedRows"], 1000)
            extra = copy.deepcopy(original)
            extra["id"] += "-1000"
            rows.append(extra)
            path.write_bytes(capsule.nh.encoded(record))
            index(source)
            with self.assertRaisesRegex(ValueError, "rows exceed"):
                capsule.seal(source, output, SUB)

    def test_capsule_output_inside_repository_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = fixture(Path(temporary))
            with self.assertRaisesRegex(ValueError, "outside the repository"):
                capsule.seal(source, ROOT, CAPSULE)

    def test_manifest_write_failure_does_not_publish_or_leave_partial_capsule(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            output = root / "private"
            output.mkdir()
            original_open = Path.open

            def fail_manifest(path, *args, **kwargs):
                if path.name == capsule.MANIFEST and args and args[0] == "xb":
                    raise OSError("Synthetic manifest write failure")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", autospec=True, side_effect=fail_manifest):
                with self.assertRaisesRegex(OSError, "manifest write failure"):
                    capsule.seal(source, output, CAPSULE)
            self.assertEqual(list(output.iterdir()), [])

    def test_cli_replay_writes_a_new_external_output_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, output, directory = self.build(Path(temporary))
            destination = output / "replay.json"
            arguments = ["capsule", "replay", "--capsule", str(directory), "--output", str(destination)]
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, "argv", arguments), redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(capsule.main(), 0)
            self.assertEqual(json.loads(destination.read_bytes()), capsule.replay(directory))
            self.assertFalse(json.loads(stdout.getvalue())["assessmentPerformed"])
            before = destination.read_bytes()
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, "argv", arguments), redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as failure:
                    capsule.main()
            self.assertEqual(failure.exception.code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Capsule operation failed", stderr.getvalue())
            self.assertEqual(destination.read_bytes(), before)

    def test_linked_member_is_rejected_instead_of_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, directory = self.build(root)
            member = directory / "storage-arm.json"
            target = root / "external.json"
            member.rename(target)
            try:
                member.symlink_to(target)
            except OSError as error:
                self.skipTest("Symlink creation unavailable on this host: " + str(error))
            with self.assertRaisesRegex(ValueError, "links"):
                capsule.verify(directory)

    def test_seal_verify_and_replay_preserve_evidence_without_live_operations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fixture(root)
            output = root / "private"
            output.mkdir()
            original = {path.name: path.read_bytes() for path in source.iterdir()}
            with patch("urllib.request.urlopen", side_effect=AssertionError("Network access is forbidden")):
                with patch("subprocess.run", side_effect=AssertionError("Subprocess activity is forbidden")):
                    directory = capsule.seal(source, output, CAPSULE)
                    manifest = capsule.verify(directory)
                    replay = capsule.replay(directory)
                    self.assertEqual(replay, capsule.replay(directory))
            self.assertEqual(manifest["capsuleVersion"], "0.1.0")
            self.assertEqual(len(replay["resources"]), 4)
            storage = next(row for row in replay["resources"] if row["type"] == "microsoft.storage/storageaccounts")
            direct = next(row for row in storage["observations"] if row["member"] == "storage-arm.json")
            self.assertEqual(direct["configuration"]["networkAcls"]["ipv6Rules"],
                             [{"value": "2001:db8::/32", "action": "Allow"}])
            self.assertEqual(direct["startedAtUtc"], TIME)
            acr = next(row for row in replay["resources"] if row["type"] == "microsoft.containerregistry/registries")
            self.assertIsNone(next(row for row in acr["observations"] if row["member"] == "acr-arm.json")["configuration"]["networkRuleSet"])
            self.assertTrue(all(row["status"] == "notCollected" and row["events"] is None for row in replay["eventSources"]))
            self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, original)
            self.assertEqual({path.name: (directory / path.name).read_bytes() for path in source.iterdir()}, original)


if __name__ == "__main__":
    unittest.main()
