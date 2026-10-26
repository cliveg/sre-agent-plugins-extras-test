from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_dns_intent as intent_tests
import test_service_access as access_tests
import test_sre_transport as transport_tests


nh = access_tests.nh
SUB, RUN, TIME = access_tests.SUB, access_tests.RUN, access_tests.TIME


class ServiceArmReader(access_tests.ServiceAccessReader):
    def __init__(self, page_size=1000):
        super().__init__(page_size)
        self.operations = nh.records(nh.catalog("1.7.0")["operations"])
        self.direct = {row["id"].lower(): copy.deepcopy(row) for row in self.resources["private-link-services"]
                       if row["type"] in nh.SERVICE_ACCESS_TYPES}
        self.fail_parent = None
        self.invalid_parent = None
        self.transform_direct = lambda payload: payload

    def __call__(self, command):
        if nh.child_kind(command) != nh.SERVICE_ARM_KIND:
            return super().__call__(command)
        self.calls.append(command)
        target = nh.command_target(command, SUB)
        parent_id = target["id"].lower()
        if self.fail_parent == parent_id:
            raise nh.ReadFailure("PermissionDenied", "permissionDenied")
        op = next(op for op in self.operations if op["kind"] == nh.SERVICE_ARM_KIND
                  and op["query"] == command[command.index("--query") + 1])
        row = copy.deepcopy(self.direct[parent_id])
        props = row["properties"]
        for field in ("ipRuleCount", "virtualNetworkRuleCount", "resourceAccessRuleCount"):
            applicable = field != "resourceAccessRuleCount" or row["type"] == nh.SERVICE_ACCESS_TYPES[0]
            known = props.get(field) is not None and applicable
            props[field + "Known"] = known
            if not known:
                props[field] = 0 if applicable else None
        row["location"] = "eastus"
        if self.invalid_parent == parent_id:
            row["id"] += "-wrong"
        self.assert_api = op["apiVersion"] in command[command.index("--url") + 1]
        return nh.ReadResponse(self.transform_direct({"count": 1, "data": [row]}))


class ServiceReconciliationTests(unittest.TestCase):
    def make(self, reader=None, progress=None, save_progress=None, clock=None):
        reader = reader or ServiceArmReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", reader.page_size, clock or (lambda: TIME),
                              progress, save_progress, include_service_arm=True, dns_subscriptions=[SUB])
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_new_mode_preserves_existing_operations_and_has_fifteen_checks(self):
        envelope, model, assessment, reader = self.make()
        self.assertEqual((envelope["inputVersion"], model["schemaVersion"]), ("0.8.0", "0.8.0"))
        self.assertEqual(model["run"]["queryCatalogVersion"], "1.7.0")
        self.assertEqual(len(model["collections"]), 26)
        self.assertEqual(len(assessment["checksExecuted"]), 15)
        self.assertEqual(assessment["checkCatalogVersion"], "1.11.0")
        self.assertEqual(nh.catalog("1.7.0")["operations"][:23], nh.catalog("1.6.0")["operations"])
        self.assertEqual(len([command for command in reader.calls if nh.child_kind(command) == nh.SERVICE_ARM_KIND]), 3)
        self.assertTrue(reader.assert_api)

    def test_indexed_values_are_not_overwritten_and_missing_is_not_matching_zero(self):
        reader = ServiceArmReader()
        storage_id = next(key for key, row in reader.direct.items() if row["type"] == nh.SERVICE_ACCESS_TYPES[0])
        reader.direct[storage_id]["properties"]["publicNetworkAccess"] = "Disabled"
        reader.direct[storage_id]["properties"]["virtualNetworkRuleCount"] = None
        _, model, assessment, _ = self.make(reader)
        entity = next(e for e in model["entities"] if e["entityId"] == storage_id)
        self.assertEqual(entity["properties"]["publicNetworkAccess"], "Enabled")
        direct = next(e for e in model["entities"] if e["entityId"] == storage_id + "/observedarmserviceaccess/summary")
        self.assertEqual(direct["collectionState"], "configurationObject")
        self.assertEqual(direct["properties"]["publicNetworkAccess"], "Disabled")
        self.assertIsNone(direct["properties"]["virtualNetworkRuleCount"])
        row = next(row for row in assessment["serviceControlReconciliation"]["rows"] if row["serviceId"] == storage_id)
        fields = {field["field"]: field for field in row["fields"]}
        self.assertEqual(fields["publicNetworkAccess"]["result"], "different-observed-values")
        self.assertEqual(fields["virtualNetworkRuleCount"]["result"], "direct-unavailable")
        self.assertEqual(fields["virtualNetworkRuleCount"]["indexedValue"], 0)
        self.assertIsNone(fields["virtualNetworkRuleCount"]["directValue"])
        findings = [f for f in assessment["findings"] if f["checkId"] == "NET-SERVICE-SOURCE-001"]
        self.assertTrue(any(f["recordType"] == "contextValidation" for f in findings))
        self.assertTrue(all(f["severity"] is None and f["recordType"] != "verifiedProblem" for f in findings))

    def test_nulls_and_not_applicable_fields_are_not_observed_matches(self):
        reader = ServiceArmReader()
        for row in reader.resources["private-link-services"]:
            if row["type"] in nh.SERVICE_ACCESS_TYPES:
                row["properties"]["trustedServiceBypass"] = None
                reader.direct[row["id"].lower()]["properties"]["trustedServiceBypass"] = None
        _, _, assessment, _ = self.make(reader)
        for row in assessment["serviceControlReconciliation"]["rows"]:
            fields = {field["field"]: field for field in row["fields"]}
            self.assertEqual(fields["trustedServiceBypass"]["result"], "both-unavailable")
            if row["resourceType"] != nh.SERVICE_ACCESS_TYPES[0]:
                self.assertEqual(fields["resourceAccessRuleCount"]["result"], "not-applicable")

    def test_one_failed_parent_keeps_failure_provenance_and_continues_other_parents(self):
        reader = ServiceArmReader()
        extra = copy.deepcopy(reader.resources["private-link-services"][0])
        extra["id"] += "second"
        extra["name"] += "second"
        reader.resources["private-link-services"].append(extra)
        reader.direct[extra["id"].lower()] = copy.deepcopy(extra)
        reader.fail_parent = reader.resources["private-link-services"][0]["id"].lower()
        _, _, assessment, reader = self.make(reader)
        rows = {row["serviceId"]: row for row in assessment["serviceControlReconciliation"]["rows"]}
        failed = rows[reader.fail_parent]
        self.assertEqual(failed["directSource"]["readStatus"], "permissionDenied")
        self.assertEqual(failed["directSource"]["readError"], "PermissionDenied")
        self.assertIsNone(failed["directSource"]["entityId"])
        self.assertEqual(rows[extra["id"].lower()]["directSource"]["readStatus"], "succeeded")
        self.assertTrue(all(field["result"] == "direct-not-collected" for field in failed["fields"]))
        self.assertEqual(assessment["status"], "incomplete-configuration-triage")

    def test_parent_discovery_failure_makes_no_direct_reads_and_keeps_explicit_outcomes(self):
        reader = ServiceArmReader()
        reader.fail = "private-link-services"
        _, model, assessment, reader = self.make(reader)
        self.assertFalse(any(nh.child_kind(command) == nh.SERVICE_ARM_KIND for command in reader.calls))
        direct = [c for c in model["collections"] if c["operationId"] in nh.SERVICE_ARM_PROFILES]
        self.assertEqual(len(direct), 3)
        self.assertTrue(all(c["status"] == "notAttempted" and "ServiceParentDiscoveryIncomplete" in c["issues"] for c in direct))
        self.assertEqual(assessment["serviceControlReconciliation"]["rows"], [])

    def test_parent_budget_is_measured_and_unread_services_stay_explicit(self):
        reader = ServiceArmReader()
        base = reader.resources["private-link-services"][0]
        reader.resources["private-link-services"] = []
        reader.direct = {}
        for index in range(101):
            row = copy.deepcopy(base)
            row["id"] += f"{index:03d}"
            row["name"] += f"{index:03d}"
            reader.resources["private-link-services"].append(row)
            reader.direct[row["id"].lower()] = copy.deepcopy(row)
        _, model, assessment, reader = self.make(reader)
        calls = [command for command in reader.calls if nh.child_kind(command) == nh.SERVICE_ARM_KIND]
        self.assertEqual(len(calls), 100)
        collection = next(c for c in model["collections"] if c["operationId"] == "storage-service-arm")
        self.assertEqual(len(collection["pages"]), 100)
        self.assertEqual(collection["status"], "partial")
        self.assertIn("PageBudgetExceeded", collection["issues"])
        rows = assessment["serviceControlReconciliation"]["rows"]
        self.assertEqual(len(rows), 101)
        self.assertEqual(sum(row["directSource"]["readStatus"] == "notAttempted" for row in rows), 1)
        self.assertEqual(rows[-1]["fields"][0]["result"], "direct-not-collected")

    def test_corrupted_completed_parent_or_api_checkpoint_is_rejected_before_reads(self):
        progress = {}
        _, _, _, reader = self.make(progress=progress)
        self.assertTrue(progress["collections"])
        for key, value in (("apiVersion", "2024-11-01"), ("pages", [])):
            changed = copy.deepcopy(progress)
            direct = next(c for c in changed["collections"] if c["operationId"] == "storage-service-arm")
            direct[key] = value
            replay = ServiceArmReader()
            with self.assertRaises(ValueError):
                self.make(replay, progress=changed)
            self.assertEqual(replay.calls, [])

    def test_mismatched_response_or_bad_availability_is_rejected_without_retaining_raw_fields(self):
        for transform in (
            lambda payload: {**payload, "count": True},
            lambda payload: {**payload, "data": "invalid"},
            lambda payload: {**payload, "data": [{**payload["data"][0], "id": "/subscriptions/" + SUB + "/wrong"}]},
            lambda payload: {**payload, "data": [{**payload["data"][0], "properties": {
                **payload["data"][0]["properties"], "ipRuleCountKnown": "false"}}]},
        ):
            reader = ServiceArmReader()
            reader.transform_direct = transform
            _, model, assessment, _ = self.make(reader)
            self.assertFalse(any(e["resourceType"] == "service-arm-access-settings" for e in model["entities"]))
            self.assertTrue(all(row["directSource"]["readStatus"] == "failed"
                                for row in assessment["serviceControlReconciliation"]["rows"]))
            self.assertNotIn("omit-credential", json.dumps([model, assessment]))
            self.assertNotIn("omit-ip-rule-value", json.dumps([model, assessment]))

    def test_scope_api_query_and_collected_parent_guards(self):
        reader = ServiceArmReader()
        op = next(op for op in reader.operations if op["operationId"] == "storage-service-arm")
        target = {**reader.resources["private-link-services"][0], "subscriptionId": SUB}
        command = nh.command_for(op, SUB, 1000, None, target)
        self.assertTrue(nh.matches_command(command, SUB, 1000))
        for replacement in (
            command[5].replace("2023-05-01", "2024-01-01"), command[5] + "&$expand=secrets",
            command[5].replace("management.azure.com", "unapproved.example"),
        ):
            changed = command.copy()
            changed[5] = replacement
            self.assertFalse(nh.matches_command(changed, SUB, 1000))
        bridge = transport_tests.bridge
        transport = bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-not-a-secret")
        transport.approved_operations = {SUB: [op]}
        transport.approved_service_parents = set()
        with self.assertRaisesRegex(ValueError, "actually collected"):
            transport._validate_acquisition_command(command)
        transport.approved_service_parents.add(target["id"].lower())
        transport._validate_acquisition_command(command)

    def test_per_parent_read_times_survive_age_review_and_resume(self):
        from datetime import datetime, timedelta, timezone
        tick = 0
        def clock():
            nonlocal tick
            tick += 1
            return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=tick)).isoformat().replace("+00:00", "Z")
        envelope, model, _, _ = self.make(clock=clock)
        review = nh.provenance_time_review(model, "2026-01-02T00:00:00Z")
        self.assertFalse(any("timestamps differ" in issue for row in review["collections"] for issue in row["issues"]))
        for evidence in model["evidence"]:
            collection = next(c for c in model["collections"] if c["collectionId"] == evidence["collectionId"])
            if collection["operationId"] in nh.SERVICE_ARM_PROFILES:
                self.assertEqual(evidence["collectedAt"], nh.evidence_time(collection, evidence["excerpt"]["parentId"]))
        changed = copy.deepcopy(envelope)
        direct = next(c for c in changed["collections"] if c["operationId"] in nh.SERVICE_ARM_PROFILES)
        direct["apiVersion"] = "2024-11-01"
        with self.assertRaisesRegex(ValueError, "parents/API"):
            nh.normalize(changed)

    def test_reports_tampering_and_seventeen_check_composition(self):
        _, model, assessment, reader = self.make()
        source = assessment["serviceControlReconciliation"]
        self.assertEqual(len(source["rows"]), 3)
        self.assertEqual(len(source["unsupportedServiceIds"]), 1)
        before = nh.encoded(model)
        combined = nh.assess(model, intent_tests.DNSIntentTests().intent(reader), TIME)
        self.assertEqual(len(combined["checksExecuted"]), 17)
        self.assertEqual(nh.encoded(model), before)
        summary, evidence = nh.render(combined)
        with self.assertRaisesRegex(ValueError, "source reconciliation"):
            nh.verify_reports(combined, summary.replace("observed-match", "private-only"), evidence)
        changed = copy.deepcopy(assessment)
        changed["serviceControlReconciliation"]["rows"][0]["fields"][0]["directValue"] = "invented"
        with self.assertRaisesRegex(ValueError, "selected source"):
            nh.verify_assessment(model, changed)
        with tempfile.TemporaryDirectory() as directory:
            nh.bundle(model, assessment, Path(directory))

    def test_existing_indexed_only_mode_does_not_add_reads_or_reconciliation(self):
        reader = access_tests.ServiceAccessReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_service_access=True)
        assessment = nh.assess(nh.normalize(envelope))
        self.assertEqual(envelope["queryCatalogVersion"], "1.6.0")
        self.assertEqual(len(assessment["checksExecuted"]), 14)
        self.assertNotIn("serviceControlReconciliation", assessment)
        self.assertFalse(any(nh.child_kind(command) == nh.SERVICE_ARM_KIND for command in reader.calls))

    def test_accepted_direct_read_resume_is_mode_bound_and_adds_no_duplicate_reads(self):
        bridge = transport_tests.bridge
        reader = ServiceArmReader(1)
        nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, include_service_arm=True)
        loss = next(i + 1 for i, command in enumerate(reader.calls) if nh.child_kind(command) == nh.SERVICE_ARM_KIND)
        service = transport_tests.NativeService(lose_after=loss, reader=ServiceArmReader(1))
        def transport():
            return bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-not-a-secret")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = transport()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1, include_service_arm=True)
            rejected = transport()
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "Service ARM acquisition differs"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, include_service_arm=False)
                request.assert_not_called()
            resumed = transport()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["inputVersion"], "0.8.0")
            self.assertEqual(len(service.posts), len(reader.calls))
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))
            final = transport()
            before = len(service.posts)
            with patch.object(final, "request", side_effect=service.request):
                self.assertEqual(bridge.acquire(final, SUB, RUN, root, resume=True), envelope)
            self.assertEqual(len(service.posts), before)
