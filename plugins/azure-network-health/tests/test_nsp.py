from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_dns_intent as intent_tests
import test_service_reconciliation as service_tests
import test_sre_transport as transport_tests


nh = service_tests.nh
SUB, RUN, TIME = service_tests.SUB, service_tests.RUN, service_tests.TIME


class NspReader(service_tests.ServiceArmReader):
    def __init__(self, page_size=1000):
        super().__init__(page_size)
        self.operations = nh.records(nh.catalog("1.8.0")["operations"])
        base = f"/subscriptions/{SUB}/resourceGroups/fixture/providers/Microsoft.Network/networkSecurityPerimeters/perimeter"
        profile = base + "/profiles/profile"
        target = self.resources["private-link-services"][0]["id"]
        self.nsp = {
            "nsp-perimeters": [{"id": base, "name": "perimeter", "properties": {"provisioningState": "Succeeded"}}],
            "nsp-profiles": [{"id": profile, "name": "profile", "properties": {"provisioningState": "Succeeded"}}],
            "nsp-associations": [{"id": base + "/resourceAssociations/association", "name": "association",
                                  "properties": {"provisioningState": "Succeeded", "privateLinkResourceId": target,
                                                 "profileId": profile, "accessMode": "Enforced", "hasProvisioningIssues": "no"}}],
            "nsp-rules": [{"id": profile + "/accessRules/rule", "name": "rule", "properties": {
                "provisioningState": "Succeeded", "direction": "Inbound",
                **{field: 0 for field in nh.NSP_SELECTOR_FIELDS},
                **{field + "Known": True for field in nh.NSP_SELECTOR_FIELDS},
                "addressPrefixes": ["do-not-retain-prefix"], "fullyQualifiedDomainNames": ["do-not-retain-fqdn"],
                "emailAddresses": ["do-not-retain-email"], "phoneNumbers": ["do-not-retain-phone"],
                "subscriptions": [{"id": "do-not-retain-selector"}],
            }}],
        }
        self.nsp_failure = None
        self.root_continuation = False
        self.rules_continuation = False
        self.hostile_continuation = False

    def __call__(self, command):
        kind = nh.child_kind(command)
        if kind not in nh.NSP_KINDS:
            return super().__call__(command)
        self.calls.append(command)
        op = next(op for op in self.operations if op["kind"] == kind and op["query"] == command[command.index("--query") + 1])
        if self.nsp_failure == op["operationId"]:
            raise nh.ReadFailure("PermissionDenied", "permissionDenied")
        rows = copy.deepcopy(self.nsp[op["operationId"]])
        for row in rows:
            row.update({"type": op["entityType"], "location": None})
        url = command[5]
        next_link = None
        if self.root_continuation and kind == "nsp-arm-root" and "$skipToken" not in url:
            next_link = url + "&$skipToken=next&$top=20"
        elif self.root_continuation and kind == "nsp-arm-root":
            rows = []
        if self.rules_continuation and kind == "nsp-rules":
            if "$skipToken" not in url:
                next_link = url + "&$skipToken=next&$top=20"
            else:
                rows[0]["id"] += "-second"
                rows[0]["name"] += "-second"
        if self.hostile_continuation and kind == "nsp-arm-root":
            next_link = url.replace("management.azure.com", "unapproved.example") + "&$skipToken=next"
        return nh.ReadResponse({"count": len(rows), "data": rows, "nextLink": next_link})


class NspTests(unittest.TestCase):
    def make(self, reader=None, hosts=None):
        reader = reader or NspReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", reader.page_size, lambda: TIME,
                              include_nsp=True, dns_subscriptions=hosts)
        model = nh.normalize(envelope)
        return envelope, model, nh.assess(model), reader

    def test_opt_in_preserves_prior_operations_and_executes_sixteen_checks(self):
        envelope, model, assessment, _ = self.make()
        self.assertEqual(envelope["inputVersion"], "0.9.0")
        self.assertEqual(model["schemaVersion"], "0.9.0")
        self.assertEqual(len(model["collections"]), 30)
        self.assertEqual(len(assessment["checksExecuted"]), 16)
        self.assertEqual(assessment["checkCatalogVersion"], "1.12.0")
        self.assertEqual(nh.catalog("1.8.0")["operations"][:26], nh.catalog("1.7.0")["operations"])

    def test_enforced_is_only_configuration_and_no_exception_is_accepted(self):
        _, model, assessment, _ = self.make()
        row = assessment["nspConfigurationReview"]["associationRows"][0]
        self.assertEqual(row["configurationState"], "enforced-configured-unverified")
        self.assertEqual(row["effectiveEnforcement"], "UNKNOWN")
        self.assertEqual(row["exceptionApproval"], "not-assessed")
        self.assertEqual(row["ruleMetadataCoverage"], "selected-metadata-collected")
        self.assertEqual(row["evidenceGaps"], [])
        self.assertEqual(assessment["accessPreference"]["exceptions"], [])
        kinds = {r["relationshipType"] for r in model["relationships"]}
        self.assertTrue({"associatesPerimeterResource", "associatedWithPerimeterProfile"} <= kinds)
        self.assertNotIn("observedTrafficVia", kinds)
        findings = [f for f in assessment["findings"] if f["checkId"] == "NET-NSP-001"]
        self.assertTrue(all(f["severity"] is None and f["recordType"] == "architectureObservation" for f in findings))

    def test_learning_transition_audit_and_unknown_modes_remain_distinct(self):
        for raw, expected in (
            ("Learning", "transition-configured-unverified"), ("Transition", "transition-configured-unverified"),
            ("Audit", "audit-configured-unverified"), ("FutureMode", "unknown-configured-mode"), (None, "unknown-configured-mode"),
        ):
            reader = NspReader()
            reader.nsp["nsp-associations"][0]["properties"]["accessMode"] = raw
            _, _, assessment, _ = self.make(reader)
            row = assessment["nspConfigurationReview"]["associationRows"][0]
            self.assertEqual(row["configuredAccessMode"], raw)
            self.assertEqual(row["configurationState"], expected)
            self.assertEqual(row["effectiveEnforcement"], "UNKNOWN")

    def test_only_counts_are_retained_and_missing_arrays_are_not_zero(self):
        reader = NspReader()
        props = reader.nsp["nsp-rules"][0]["properties"]
        props["addressPrefixCount"] = 2
        props["fqdnCountKnown"] = False
        _, model, assessment, _ = self.make(reader)
        serialized = json.dumps([model, assessment])
        for value in ("do-not-retain-prefix", "do-not-retain-fqdn", "do-not-retain-email",
                      "do-not-retain-phone", "do-not-retain-selector"):
            self.assertNotIn(value, serialized)
        rule = assessment["nspConfigurationReview"]["ruleMetadata"][0]
        self.assertEqual(rule["properties"]["addressPrefixCount"], 2)
        self.assertIsNone(rule["properties"]["fqdnCount"])
        self.assertIn("RuleSelectorCountsUnavailable", assessment["nspConfigurationReview"]["associationRows"][0]["evidenceGaps"])

    def test_invalid_selector_flags_are_explicit_partial_not_successful_empty_rules(self):
        reader = NspReader()
        reader.nsp["nsp-rules"][0]["properties"]["fqdnCountKnown"] = "false"
        _, model, assessment, _ = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "nsp-rules")
        self.assertEqual(collection["status"], "partial")
        self.assertIn("NspSelectorMetadataRejected", collection["issues"])
        self.assertEqual(assessment["nspConfigurationReview"]["associationRows"][0]["ruleMetadataCoverage"], "unknown-or-partial")

    def test_scoped_zero_and_failed_roots_never_establish_perimeter_absence(self):
        for failed in (False, True):
            reader = NspReader()
            reader.nsp["nsp-perimeters"] = []
            reader.nsp_failure = "nsp-perimeters" if failed else None
            _, model, assessment, reader = self.make(reader)
            nsp_calls = [c for c in reader.calls if nh.child_kind(c) in nh.NSP_KINDS]
            self.assertEqual(len(nsp_calls), 1)
            self.assertEqual(assessment["nspConfigurationReview"]["associationRows"], [])
            self.assertTrue(any(f["checkId"] == "NET-NSP-001" and f["recordType"] == "evidenceGap" for f in assessment["findings"]))
            if failed:
                self.assertTrue(any(c["status"] == "notAttempted" for c in model["collections"] if c["operationId"] in nh.NSP_FIELDS))

    def test_profile_rule_and_provisioning_gaps_do_not_certify_enforcement(self):
        for failed in ("nsp-profiles", "nsp-rules"):
            reader = NspReader()
            reader.nsp_failure = failed
            _, _, assessment, _ = self.make(reader)
            row = assessment["nspConfigurationReview"]["associationRows"][0]
            self.assertTrue(row["evidenceGaps"])
            self.assertEqual(row["effectiveEnforcement"], "UNKNOWN")
        reader = NspReader()
        reader.nsp["nsp-associations"][0]["properties"].update({"provisioningState": "Updating", "hasProvisioningIssues": "yes"})
        _, _, assessment, _ = self.make(reader)
        row = assessment["nspConfigurationReview"]["associationRows"][0]
        self.assertIn("AssociationReportsProvisioningIssues", row["evidenceGaps"])
        self.assertIn("AssociationProvisioningNotConfirmedSucceeded", row["evidenceGaps"])

    def test_external_target_and_profile_references_are_not_followed(self):
        reader = NspReader()
        external = "00000000-0000-4000-8000-000000000099"
        props = reader.nsp["nsp-associations"][0]["properties"]
        props["privateLinkResourceId"] = props["privateLinkResourceId"].replace(SUB, external)
        props["profileId"] = props["profileId"].replace(SUB, external)
        _, _, assessment, reader = self.make(reader)
        row = assessment["nspConfigurationReview"]["associationRows"][0]
        self.assertEqual(row["targetScope"], "external-or-unknown-reference")
        self.assertIn("AssociationProfileNotCollectedWithinItsPerimeter", row["evidenceGaps"])
        self.assertFalse(any(external in c[5] for c in reader.calls if nh.child_kind(c) in nh.NSP_KINDS))

    def test_perimeter_mode_without_scoped_association_is_a_gap_not_a_defect(self):
        reader = NspReader()
        reader.nsp["nsp-associations"] = []
        service = reader.resources["private-link-services"][0]
        service["properties"]["publicNetworkAccess"] = "SecuredByPerimeter"
        reader.direct[service["id"].lower()]["properties"]["publicNetworkAccess"] = "SecuredByPerimeter"
        _, _, assessment, _ = self.make(reader)
        candidates = assessment["nspConfigurationReview"]["perimeterModeWithoutObservedAssociation"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["status"], "association-not-observed-in-collected-perimeter-scope")
        self.assertFalse(any(f["recordType"] == "verifiedProblem" and f["checkId"] == "NET-NSP-001" for f in assessment["findings"]))

    def test_pagination_top_budget_origin_path_and_api_guards(self):
        reader = NspReader()
        reader.root_continuation = True
        _, model, _, reader = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "nsp-perimeters")
        self.assertEqual(collection["status"], "succeeded")
        self.assertEqual(len(collection["pages"]), 2)
        path = "/subscriptions/" + SUB + "/providers/microsoft.network/networksecurityperimeters"
        good = "https://management.azure.com" + path + "?api-version=2024-07-01&$skipToken=next&$top=20"
        self.assertEqual(nh.validated_arm_url(good, path, "2024-07-01"), good)
        for bad in (good.replace("$top=20", "$top=21"), good.replace("2024-07-01", "2023-08-01-preview"),
                    good.replace("management.azure.com", "unapproved.example"), good + "&sig=secret"):
            with self.assertRaises(ValueError):
                nh.validated_arm_url(bad, path, "2024-07-01")
        op = next(op for op in reader.operations if op["operationId"] == "nsp-profiles")
        target = {**reader.nsp["nsp-perimeters"][0], "subscriptionId": SUB}
        command = nh.command_for(op, SUB, 1000, None, target)
        bridge = transport_tests.bridge
        t = bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-not-a-secret")
        t.approved_operations = {SUB: [op]}
        t.approved_nsp_parents = {kind: set() for kind in nh.NSP_CHILD_KINDS}
        with self.assertRaisesRegex(ValueError, "actually collected"):
            t._validate_acquisition_command(command)

    def test_child_rule_pagination_is_complete_only_after_terminal_page(self):
        reader = NspReader()
        reader.rules_continuation = True
        _, model, assessment, _ = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "nsp-rules")
        self.assertEqual(len(collection["pages"]), 2)
        self.assertEqual([p["armHasContinuation"] for p in collection["pages"]], [True, False])
        row = assessment["nspConfigurationReview"]["associationRows"][0]
        self.assertEqual(row["ruleMetadataCoverage"], "selected-metadata-collected")
        self.assertEqual(row["retainedInboundRuleCount"], 2)
        self.assertEqual(len(row["ruleIds"]), 2)

    def test_hostile_continuation_stays_partial_and_never_leaves_management_origin(self):
        reader = NspReader()
        reader.hostile_continuation = True
        _, model, assessment, reader = self.make(reader)
        collection = next(c for c in model["collections"] if c["operationId"] == "nsp-perimeters")
        self.assertEqual(collection["status"], "partial")
        self.assertIn("NspArmContinuationRejected", collection["issues"])
        self.assertFalse(any("unapproved.example" in c[5] for c in reader.calls if nh.child_kind(c) in nh.NSP_KINDS))
        self.assertEqual(assessment["status"], "incomplete-configuration-triage")

    def test_reports_integrity_and_eighteen_check_composition(self):
        _, model, assessment, reader = self.make()
        before = nh.encoded(model)
        combined = nh.assess(model, intent_tests.DNSIntentTests().intent(reader), TIME)
        self.assertEqual(len(combined["checksExecuted"]), 18)
        self.assertEqual(nh.encoded(model), before)
        summary, engineering = nh.render(combined)
        with self.assertRaisesRegex(ValueError, "Markdown NSP"):
            nh.verify_reports(combined, summary.replace("enforced-configured-unverified", "verified-enforcement"), engineering)
        changed = copy.deepcopy(assessment)
        changed["nspConfigurationReview"]["associationRows"][0]["effectiveEnforcement"] = "OBSERVED"
        with self.assertRaisesRegex(ValueError, "selected configuration"):
            nh.verify_assessment(model, changed)
        with tempfile.TemporaryDirectory() as directory:
            nh.bundle(model, assessment, Path(directory))

    def test_existing_modes_do_not_collect_or_invent_nsp_evidence(self):
        reader = service_tests.ServiceArmReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_service_arm=True)
        assessment = nh.assess(nh.normalize(envelope))
        self.assertEqual(len(assessment["checksExecuted"]), 15)
        self.assertNotIn("nspConfigurationReview", assessment)
        self.assertFalse(any(nh.child_kind(c) in nh.NSP_KINDS for c in reader.calls))

    def test_accepted_continuation_resume_is_bound_and_never_reposts(self):
        bridge = transport_tests.bridge
        reader = NspReader()
        reader.root_continuation = True
        nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_nsp=True)
        loss = next(i + 1 for i, command in enumerate(reader.calls)
                    if nh.child_kind(command) == "nsp-arm-root" and "$skipToken" in command[5])
        service_reader = NspReader()
        service_reader.root_continuation = True
        service = transport_tests.NativeService(lose_after=loss, reader=service_reader)
        def transport():
            return bridge.SRETransport(transport_tests.ENDPOINT, transport_tests.THREAD, "synthetic-not-a-secret")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = transport()
            with patch.object(first, "request", side_effect=service.request):
                with self.assertRaisesRegex(RuntimeError, "response loss"):
                    bridge.acquire(first, SUB, RUN, root, include_nsp=True)
            rejected = transport()
            with patch.object(rejected, "request") as request:
                with self.assertRaisesRegex(ValueError, "NSP acquisition differs"):
                    bridge.acquire(rejected, SUB, RUN, root, resume=True, include_nsp=False)
                request.assert_not_called()
            resumed = transport()
            with patch.object(resumed, "request", side_effect=service.request):
                envelope = bridge.acquire(resumed, SUB, RUN, root, resume=True)
            self.assertEqual(envelope["inputVersion"], "0.9.0")
            self.assertEqual(len(service.posts), len(reader.calls))
            self.assertEqual(len(service.posts), len({tuple(c) for c in service.posts}))
            final = transport()
            before = len(service.posts)
            with patch.object(final, "request", side_effect=service.request):
                self.assertEqual(bridge.acquire(final, SUB, RUN, root, resume=True), envelope)
            self.assertEqual(len(service.posts), before)
