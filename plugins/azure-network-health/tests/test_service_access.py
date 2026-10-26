from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import ValidationError

import test_dns_intent as intent_tests
import test_dns_paths as paths
import test_sre_transport as transport_tests


nh = paths.nh
SUB, RUN, TIME = paths.SUB, paths.RUN, paths.TIME


class ServiceAccessReader(paths.DNSPathFixtureReader):
    def __init__(self, page_size=1000):
        super().__init__(page_size)
        self.operations = nh.records(nh.catalog("1.6.0")["operations"])
        for service in self.resources["private-link-services"]:
            service["properties"] = {
                "publicNetworkAccess": "Enabled", "firewallDefaultAction": "Allow",
                "trustedServiceBypass": "AzureServices", "ipRuleCount": 1,
                "virtualNetworkRuleCount": 0, "resourceAccessRuleCount": 0,
                "ipRules": [{"value": "omit-ip-rule-value"}], "secret": "omit-credential",
            }
        for resource_type, name in (
            ("microsoft.containerregistry/registries", "registry"),
            ("microsoft.monitor/accounts", "monitor"),
        ):
            self.resources["private-link-services"].append({
                "id": f"/subscriptions/{SUB}/resourceGroups/fixture/providers/{resource_type}/{name}",
                "name": name, "type": resource_type,
                "properties": {"publicNetworkAccess": "Disabled", "firewallDefaultAction": "Deny",
                               "trustedServiceBypass": "AzureServices", "ipRuleCount": 0,
                               "virtualNetworkRuleCount": 0, "resourceAccessRuleCount": None},
            })


class ServiceAccessTests(unittest.TestCase):
    def make(self, reader=None):
        reader = reader or ServiceAccessReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", reader.page_size,
                              lambda: TIME, include_service_access=True, dns_subscriptions=[SUB])
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_opt_in_changes_only_service_projection_and_adds_one_check(self):
        _, model, assessment, _ = self.make()
        self.assertEqual(model["schemaVersion"], "0.7.0")
        self.assertEqual(model["run"]["queryCatalogVersion"], "1.6.0")
        self.assertEqual(len(model["collections"]), 23)
        self.assertEqual(len(assessment["checksExecuted"]), 14)
        self.assertEqual(assessment["checkCatalogVersion"], "1.10.0")
        old = {op["operationId"]: op for op in nh.catalog("1.5.0")["operations"]}
        new = {op["operationId"]: op for op in nh.catalog("1.6.0")["operations"]}
        self.assertEqual(set(old), set(new))
        self.assertEqual([key for key in old if old[key] != new[key]], ["private-link-services"])
        self.assertEqual(new["private-link-services"]["operationVersion"], "1.1.0")

    def test_observed_properties_and_scoped_approved_groups_are_not_reachability(self):
        _, model, assessment, _ = self.make()
        review = assessment["serviceAccessReview"]
        storage = next(row for row in review["rows"] if row["resourceType"] == nh.SERVICE_ACCESS_TYPES[0])
        self.assertEqual(storage["configurationState"], "enabled-firewall-allow")
        self.assertEqual(storage["approvedGroupIds"], ["blob"])
        self.assertEqual(len(storage["approvedConnectionIds"]), 1)
        self.assertEqual(storage["actualReachability"], "UNKNOWN")
        self.assertEqual(storage["exceptionApproval"], "not-assessed")
        self.assertNotIn("serviceAccessReview", model)
        for finding in assessment["findings"]:
            if finding["checkId"] == "NET-SERVICE-ACCESS-001":
                self.assertIsNone(finding["severity"])
                self.assertNotIn(finding["recordType"], ("verifiedProblem", "positiveObservation"))
                self.assertTrue(finding["evidenceRefs"])
        serialized = json.dumps([model, assessment])
        self.assertNotIn("omit-ip-rule-value", serialized)
        self.assertNotIn("omit-credential", serialized)
        self.assertNotIn('"ipRules"', serialized)

    def test_missing_and_future_values_never_inherit_enabled_or_disabled_defaults(self):
        for pna in (None, "", "FutureMode"):
            with self.subTest(pna=pna):
                reader = ServiceAccessReader()
                reader.resources["private-link-services"][0]["properties"]["publicNetworkAccess"] = pna
                _, _, assessment, _ = self.make(reader)
                row = next(row for row in assessment["serviceAccessReview"]["rows"] if row["resourceType"] == nh.SERVICE_ACCESS_TYPES[0])
                self.assertEqual(row["configurationState"], "unknown-setting")
                self.assertIn("PublicNetworkAccessUnavailableOrUnrecognized", row["evidenceGaps"])

    def test_selected_networks_are_not_private_only_and_unknown_action_is_not_allow(self):
        for default, expected in (("Deny", "enabled-firewall-deny"), (None, "enabled-firewall-unknown"),
                                  ("FutureAction", "enabled-firewall-unknown")):
            reader = ServiceAccessReader()
            reader.resources["private-link-services"][0]["properties"]["firewallDefaultAction"] = default
            _, _, assessment, _ = self.make(reader)
            row = next(row for row in assessment["serviceAccessReview"]["rows"] if row["resourceType"] == nh.SERVICE_ACCESS_TYPES[0])
            self.assertEqual(row["configurationState"], expected)
            finding = next(f for f in assessment["findings"] if f["title"] == "Service access configuration: " + expected)
            self.assertEqual(finding["recordType"], "contextValidation")
            self.assertEqual(finding["priority"]["band"], "P2")

    def test_disabled_retains_trusted_bypass_and_does_not_certify_private_only(self):
        _, _, assessment, _ = self.make()
        row = next(row for row in assessment["serviceAccessReview"]["rows"] if row["resourceType"] == nh.SERVICE_ACCESS_TYPES[2])
        self.assertEqual(row["configurationState"], "disabled-configured")
        self.assertEqual(row["properties"]["trustedServiceBypass"], "AzureServices")
        finding = next(f for f in assessment["findings"] if f["title"].endswith("disabled-configured"))
        self.assertEqual(finding["recordType"], "architectureObservation")
        self.assertEqual(finding["priority"]["band"], "INFO")
        self.assertIn("does not certify private-only", finding["recommendation"])

    def test_unrecognized_bypass_and_missing_counts_remain_explicit_gaps(self):
        reader = ServiceAccessReader()
        reader.resources["private-link-services"][0]["properties"].update(
            {"trustedServiceBypass": "FutureBypass", "ipRuleCount": None})
        _, _, assessment, _ = self.make(reader)
        row = next(row for row in assessment["serviceAccessReview"]["rows"] if row["resourceType"] == nh.SERVICE_ACCESS_TYPES[0])
        self.assertEqual(row["configurationState"], "enabled-firewall-allow")
        self.assertIn("TrustedServiceBypassUnavailableOrUnrecognized", row["evidenceGaps"])
        self.assertIn("ipRuleCountUnavailable", row["evidenceGaps"])
        self.assertTrue(any(f["title"] == "Selected service access-control evidence is incomplete"
                            and f["recordType"] == "evidenceGap" for f in assessment["findings"]))

    def test_perimeter_mode_is_unverified_and_acr_does_not_inherit_support(self):
        reader = ServiceAccessReader()
        for service in reader.resources["private-link-services"]:
            service["properties"]["publicNetworkAccess"] = "SecuredByPerimeter"
        _, _, assessment, _ = self.make(reader)
        rows = {row["resourceType"]: row for row in assessment["serviceAccessReview"]["rows"]}
        for resource_type in nh.SERVICE_ACCESS_TYPES[:2]:
            self.assertEqual(rows[resource_type]["configurationState"], "perimeter-mode-unverified")
            self.assertIn("PerimeterAssociationProfileRulesAndEnforcementNotCollected", rows[resource_type]["evidenceGaps"])
        self.assertEqual(rows[nh.SERVICE_ACCESS_TYPES[2]]["configurationState"], "unknown-setting")
        self.assertEqual(assessment["accessPreference"]["exceptions"], [])

    def test_unsupported_monitor_is_explicit_and_retains_no_access_properties(self):
        _, model, assessment, _ = self.make()
        row = next(row for row in assessment["serviceAccessReview"]["rows"] if row["resourceType"] == "microsoft.monitor/accounts")
        self.assertFalse(row["supported"])
        self.assertEqual(row["configurationState"], "unsupported-family")
        self.assertEqual(row["properties"], {})
        self.assertEqual(next(e for e in model["entities"] if e["entityId"] == row["serviceId"])["properties"], {})

    def test_failed_collections_and_no_approved_connections_never_prove_absence(self):
        for failed in ("private-link-services", "private-endpoint-connections"):
            reader = ServiceAccessReader()
            reader.fail = failed
            _, _, assessment, _ = self.make(reader)
            review = assessment["serviceAccessReview"]
            key = "serviceInventoryStatus" if failed == "private-link-services" else "connectionInventoryStatus"
            self.assertEqual(review[key], "permissionDenied")
            self.assertEqual(assessment["status"], "incomplete-configuration-triage")
            if failed == "private-endpoint-connections":
                self.assertTrue(all(not row["approvedConnectionIds"] for row in review["rows"]))
                self.assertTrue(all("PrivateEndpointConnectionInventoryPartial" in row["evidenceGaps"] for row in review["rows"]))

    def test_invalid_count_types_are_rejected_and_raw_values_are_not_retained(self):
        op = next(op for op in nh.catalog("1.6.0")["operations"] if op["operationId"] == "private-link-services")
        row = {"id": f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Storage/storageAccounts/test",
               "name": "test", "type": nh.SERVICE_ACCESS_TYPES[0], "subscriptionId": SUB, "properties": {}}
        for bad in (True, -1, "0", []):
            row["properties"]["ipRuleCount"] = bad
            with self.subTest(bad=bad), self.assertRaises((ValueError, ValidationError)):
                nh.select_row(row, op, SUB)

    def test_report_and_assessment_tampering_are_rejected(self):
        _, model, assessment, _ = self.make()
        summary, evidence = nh.render(assessment)
        for text in (summary, evidence):
            self.assertIn("Service access-control configuration review", text)
            self.assertIn("trusted-service bypass", text.lower())
        with self.assertRaisesRegex(ValueError, "Markdown service access"):
            nh.verify_reports(assessment, summary.replace("enabled-firewall-allow", "disabled-configured"), evidence)
        changed = copy.deepcopy(assessment)
        changed["serviceAccessReview"]["rows"][0]["actualReachability"] = "OBSERVED"
        with self.assertRaises(ValueError):
            nh.verify_assessment(model, changed)
        with tempfile.TemporaryDirectory() as directory:
            result = nh.bundle(model, assessment, Path(directory))
            self.assertEqual(result["status"], assessment["status"])
            self.assertEqual(set(result["artifacts"]), set(nh.REPORT_FILES))

    def test_intent_and_time_are_composable_without_changing_observations(self):
        _, model, _, reader = self.make()
        original = nh.encoded(model)
        intent = intent_tests.DNSIntentTests().intent(reader)
        assessment = nh.assess(model, intent, TIME)
        self.assertEqual(len(assessment["checksExecuted"]), 16)
        self.assertEqual(assessment["checkCatalogVersion"], "1.10.0")
        self.assertIn("provenanceTimeReview", assessment)
        self.assertIn("dnsIntentComparison", assessment)
        self.assertEqual(nh.encoded(model), original)
        nh.render(assessment)

    def test_historical_modes_do_not_acquire_or_invent_access_settings(self):
        reader = ServiceAccessReader()
        reader.operations = nh.records(nh.catalog("1.5.0")["operations"])
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True)
        model = nh.normalize(envelope)
        assessment = nh.assess(model)
        self.assertNotIn("serviceAccessReview", assessment)
        self.assertEqual(len(assessment["checksExecuted"]), 13)
        self.assertTrue(all(not entity["properties"] for entity in model["entities"]
                            if entity["resourceType"] in nh.SERVICE_ACCESS_TYPES))

    def test_accepted_service_page_resume_is_mode_bound_and_never_reposts(self):
        bridge = transport_tests.bridge
        reader = ServiceAccessReader(1)
        nh.collect(SUB, RUN, reader, "synthetic-fixture", 1, lambda: TIME, include_service_access=True)
        op = next(op for op in nh.catalog("1.6.0")["operations"] if op["operationId"] == "private-link-services")
        loss = next(i + 1 for i, command in enumerate(reader.calls) if op["query"] in command)
        service = transport_tests.NativeService(lose_after=loss, reader=ServiceAccessReader(1))
        def transport():
            return bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-not-a-secret")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = transport()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, 1, include_service_access=True)
            rejected = transport()
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "Service access acquisition differs"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, include_service_access=False)
                request.assert_not_called()
            resumed = transport()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["inputVersion"], "0.7.0")
            self.assertEqual(len(service.posts), len(reader.calls))
            self.assertEqual(len(service.posts), len({tuple(command) for command in service.posts}))
            final = transport()
            before = len(service.posts)
            with patch.object(final, "request", side_effect=service.request):
                self.assertEqual(bridge.acquire(final, SUB, RUN, root, resume=True), envelope)
            self.assertEqual(len(service.posts), before)
