from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import ValidationError

import test_dns_paths as paths
import test_network_health as fixtures


nh = paths.nh
SUB, RUN, TIME = paths.SUB, paths.RUN, paths.TIME


class DNSIntentTests(unittest.TestCase):
    def setup_model(self):
        reader = paths.DNSPathFixtureReader()
        envelope = nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True)
        return envelope, nh.normalize(envelope), reader

    def intent(self, reader, stage="required-now"):
        vnet = reader.resources["vnets"][0]["id"]
        return {
            "intentVersion": "1.0.0", "runId": RUN, "subscriptionId": SUB,
            "source": {"documentId": "synthetic-dns-standard", "revision": "revision-1", "owner": "synthetic-platform-team",
                       "declaredAt": TIME, "reviewedAt": TIME},
            "cohorts": [{"cohortId": "wave-one", "stage": stage, "vnetIds": [vnet],
                         "dnsMode": "custom-configured",
                         "requiredRulesetIds": [reader.path_resources["dns-rulesets"][0]["id"]],
                         "requiredInboundEndpointIds": [reader.path_resources["dns-inbound-endpoints"][0]["id"]]}],
        }

    def test_declared_intent_persists_separately_and_does_not_change_observation(self):
        _, model, reader = self.setup_model()
        before = nh.encoded(model)
        intent = self.intent(reader)
        a = nh.assess(model, intent)
        comparison = a["dnsIntentComparison"]
        self.assertEqual(comparison["intent"], intent)
        self.assertEqual(comparison["intentSha256"], nh.digest(intent))
        self.assertEqual(comparison["classification"], "DECLARED")
        self.assertEqual(comparison["actualClientUse"], "UNKNOWN")
        self.assertEqual(comparison["rows"][0]["result"], "configured-match")
        self.assertEqual(len(a["checksExecuted"]), 14)
        self.assertEqual(a["checkCatalogVersion"], "1.8.0")
        self.assertEqual(before, nh.encoded(model))
        self.assertNotIn("dnsIntentComparison", model)
        self.assertFalse(any(f["recordType"] == "verifiedProblem" and f["checkId"] == "NET-DNS-INTENT-001" for f in a["findings"]))

    def test_no_intent_keeps_previous_check_set_and_does_not_invent_requirements(self):
        _, model, _ = self.setup_model()
        a = nh.assess(model)
        self.assertNotIn("dnsIntentComparison", a)
        self.assertEqual(a["checkCatalogVersion"], "1.7.0")
        self.assertEqual(len(a["checksExecuted"]), 13)

    def test_required_now_difference_is_context_and_planned_difference_is_not_defect(self):
        _, model, reader = self.setup_model()
        for stage, band in (("required-now", "P2"), ("planned", "P3"), ("in-progress", "P3")):
            intent = self.intent(reader, stage)
            intent["cohorts"][0]["dnsMode"] = "azure-provided-configured"
            intent["cohorts"][0]["requiredInboundEndpointIds"] = []
            a = nh.assess(model, intent)
            row = a["dnsIntentComparison"]["rows"][0]
            finding = next(f for f in a["findings"] if f["checkId"] == "NET-DNS-INTENT-001")
            self.assertEqual(row["result"], "configured-difference")
            self.assertEqual(finding["recordType"], "contextValidation")
            self.assertIsNone(finding["severity"])
            self.assertEqual(finding["priority"]["band"], band)

    def test_excluded_cohort_has_no_implicit_requirements_or_finding(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader, "excluded")
        intent["cohorts"][0].update({"dnsMode": "unspecified", "requiredRulesetIds": [], "requiredInboundEndpointIds": []})
        a = nh.assess(model, intent)
        self.assertEqual(a["dnsIntentComparison"]["rows"][0]["result"], "excluded")
        self.assertFalse(any(f["checkId"] == "NET-DNS-INTENT-001" for f in a["findings"]))

    def test_planned_cohort_without_target_is_not_configuration_match(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader, "planned")
        intent["cohorts"][0].update({"dnsMode": "unspecified", "requiredRulesetIds": [], "requiredInboundEndpointIds": []})
        self.assertEqual(nh.assess(model, intent)["dnsIntentComparison"]["rows"][0]["result"], "no-declared-target")
        intent["cohorts"][0]["stage"] = "required-now"
        with self.assertRaisesRegex(ValueError, "declare a configuration expectation"):
            nh.assess(model, intent)

    def test_undeclared_vnets_do_not_inherit_cohort_requirements(self):
        _, model, reader = self.setup_model()
        a = nh.assess(model, self.intent(reader))
        self.assertEqual(len(a["dnsIntentComparison"]["rows"]), 1)
        self.assertTrue(all(not row["vnetId"].endswith("/beta") for row in a["dnsIntentComparison"]["rows"]))

    def test_failed_or_partial_links_are_unknown_not_missing_required_links(self):
        for fail, continuation in (("dns-ruleset-links", False), (None, True)):
            reader = paths.DNSPathFixtureReader()
            intent = self.intent(reader)
            reader.fail, reader.continuation = fail, continuation
            model = nh.normalize(nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True))
            a = nh.assess(model, intent)
            self.assertEqual(a["dnsIntentComparison"]["rows"][0]["result"], "unknown-evidence")
            self.assertTrue(any(f["checkId"] == "NET-DNS-INTENT-001" and f["recordType"] == "evidenceGap" for f in a["findings"]))

    def test_successful_unready_link_is_declared_configuration_difference_not_outage(self):
        reader = paths.DNSPathFixtureReader()
        reader.path_resources["dns-ruleset-links"][0]["properties"]["provisioningState"] = "Updating"
        model = nh.normalize(nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True))
        a = nh.assess(model, self.intent(reader))
        self.assertEqual(a["dnsIntentComparison"]["rows"][0]["result"], "configured-difference")
        self.assertTrue(all(f["severity"] is None for f in a["findings"] if f["checkId"] == "NET-DNS-INTENT-001"))

    def test_uncollected_and_external_targets_remain_unknown_without_new_reads(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader)
        calls = len(reader.calls)
        external = intent["cohorts"][0]["requiredRulesetIds"][0].replace(SUB, paths.HOST)
        intent["cohorts"][0]["requiredRulesetIds"] = [external]
        a = nh.assess(model, intent)
        self.assertEqual(a["dnsIntentComparison"]["rows"][0]["result"], "unknown-evidence")
        self.assertNotIn(external.lower(), [entity["entityId"] for entity in model["entities"]])
        self.assertEqual(len(reader.calls), calls)

    def test_unobserved_consumer_is_unknown_not_missing_dns(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader)
        intent["cohorts"][0]["vnetIds"] = [reader.resources["vnets"][0]["id"].replace("/alpha", "/not-collected")]
        self.assertEqual(nh.assess(model, intent)["dnsIntentComparison"]["rows"][0]["result"], "unknown-evidence")

    def test_newer_intent_requires_observation_time_alignment(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader)
        intent["source"]["declaredAt"] = intent["source"]["reviewedAt"] = "2026-10-10T12:00:00Z"
        a = nh.assess(model, intent)
        self.assertEqual(a["dnsIntentComparison"]["timeAlignment"], "intent-declared-after-observation")
        self.assertEqual(a["dnsIntentComparison"]["rows"][0]["result"], "unknown-evidence")

    def test_time_comparison_uses_timestamps_not_lexical_fraction_order(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader)
        intent["source"]["declaredAt"] = TIME.replace("Z", ".100000Z")
        intent["source"]["reviewedAt"] = TIME.replace("Z", ".200000Z")
        a = nh.assess(model, intent)
        self.assertEqual(a["dnsIntentComparison"]["timeAlignment"], "intent-declared-after-observation")
        intent["source"]["reviewedAt"] = TIME
        with self.assertRaisesRegex(ValueError, "review time"):
            nh.assess(model, intent)

    def test_required_inbound_target_match_does_not_certify_endpoint_health_or_client_use(self):
        reader = paths.DNSPathFixtureReader()
        intent = self.intent(reader)
        reader.path_resources["dns-inbound-endpoints"][0]["properties"]["provisioningState"] = "Updating"
        model = nh.normalize(nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True))
        a = nh.assess(model, intent)
        self.assertEqual(a["dnsIntentComparison"]["rows"][0]["result"], "unknown-evidence")
        self.assertEqual(a["dnsIntentComparison"]["actualClientUse"], "UNKNOWN")

    def test_scope_run_conflicts_duplicate_case_and_bad_types_are_rejected(self):
        _, model, reader = self.setup_model()
        for change in ("run", "scope", "cohort", "consumer", "case", "type", "excluded"):
            intent = self.intent(reader)
            cohort = intent["cohorts"][0]
            if change == "run":
                intent["runId"] = SUB
            elif change == "scope":
                intent["subscriptionId"] = paths.HOST
            elif change == "cohort":
                intent["cohorts"].append(copy.deepcopy(cohort))
            elif change == "consumer":
                other = copy.deepcopy(cohort)
                other["cohortId"] = "wave-two"
                intent["cohorts"].append(other)
            elif change == "case":
                cohort["vnetIds"].append(cohort["vnetIds"][0].upper())
            elif change == "type":
                cohort["requiredRulesetIds"] = cohort["vnetIds"]
            else:
                cohort["stage"] = "excluded"
            with self.subTest(change=change), self.assertRaises((ValueError, ValidationError)):
                nh.assess(model, intent)

    def test_intent_requires_path_evidence_and_explicit_provenance(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader)
        del intent["source"]["owner"]
        with self.assertRaises(ValidationError):
            nh.assess(model, intent)
        legacy = nh.normalize(nh.collect(SUB, RUN, fixtures.FixtureReader(), "synthetic-fixture", clock=lambda: TIME))
        with self.assertRaisesRegex(ValueError, "requires DNS-path"):
            nh.assess(legacy, self.intent(reader))

    def test_comparison_and_rendering_tampering_are_rejected(self):
        _, model, reader = self.setup_model()
        a = nh.assess(model, self.intent(reader))
        altered = copy.deepcopy(a)
        altered["dnsIntentComparison"]["rows"][0]["result"] = "configured-difference"
        with self.assertRaisesRegex(ValueError, "DNS intent comparison"):
            nh.verify_assessment(model, altered)
        summary, engineering = nh.render(a)
        self.assertIn("synthetic-dns-standard", engineering)
        self.assertNotIn("synthetic-platform-team", summary)
        with self.assertRaisesRegex(ValueError, "DNS intent comparison"):
            nh.verify_reports(a, summary, engineering.replace("revision=revision-1", "revision=changed"))

    def test_cli_processing_and_verified_bundle_preserve_supplied_intent_without_fifth_report(self):
        envelope, _, reader = self.setup_model()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.json").write_bytes(nh.encoded(envelope))
            (root / "intent.json").write_bytes(nh.encoded(self.intent(reader)))
            command = [sys.executable, str(nh.HERE / "network_health.py"), "--input", str(root / "input.json"),
                       "--dns-intent", str(root / "intent.json"), "--output-root", str(root / "output")]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            bundle = json.loads(result.stdout)
            self.assertEqual(set(bundle["artifacts"]), set(nh.REPORT_FILES))
            run_root = root / "output" / "runs" / RUN
            self.assertEqual({path.name for path in run_root.iterdir()}, set(nh.REPORT_FILES))
            a = nh.load(run_root / "assessment.json")
            self.assertEqual(a["dnsIntentComparison"]["intentSha256"], nh.digest(self.intent(reader)))
            self.assertEqual(nh.load(run_root / "observed-network.json").get("dnsIntentComparison"), None)
            repeated = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(hashlib.sha256((root / "intent.json").read_bytes()).hexdigest(),
                             hashlib.sha256(nh.encoded(self.intent(reader))).hexdigest())

    def test_conflicting_configuration_expectations_and_blank_source_are_rejected(self):
        _, model, reader = self.setup_model()
        intent = self.intent(reader)
        intent["cohorts"][0]["dnsMode"] = "azure-provided-configured"
        with self.assertRaisesRegex(ValueError, "cannot require direct inbound"):
            nh.assess(model, intent)
        intent = self.intent(reader)
        intent["source"]["owner"] = "   "
        with self.assertRaisesRegex(ValueError, "cannot be blank"):
            nh.assess(model, intent)

    def test_unready_declared_ruleset_is_unknown_not_configuration_match(self):
        reader = paths.DNSPathFixtureReader()
        reader.path_resources["dns-rulesets"][0]["properties"]["provisioningState"] = "Updating"
        model = nh.normalize(nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, include_dns_paths=True))
        a = nh.assess(model, self.intent(reader))
        self.assertEqual(a["dnsIntentComparison"]["rows"][0]["result"], "unknown-evidence")

    def test_intent_findings_cite_selected_dns_setting_and_link_evidence(self):
        _, model, reader = self.setup_model()
        a = nh.assess(model, self.intent(reader))
        comparison = a["dnsIntentComparison"]["rows"][0]
        finding = next(f for f in a["findings"] if f["checkId"] == "NET-DNS-INTENT-001")
        self.assertTrue(set(comparison["evidenceRefs"]) <= set(finding["evidenceRefs"]))

    def test_missing_parent_page_does_not_certify_declared_inbound_or_ruleset_match(self):
        for operation in ("dns-inbound-endpoints", "dns-rulesets"):
            _, model, reader = self.setup_model()
            next(c for c in model["collections"] if c["operationId"] == operation)["pages"] = []
            comparison = nh.compare_dns_intent(model, self.intent(reader))
            self.assertEqual(comparison["rows"][0]["result"], "unknown-evidence")
