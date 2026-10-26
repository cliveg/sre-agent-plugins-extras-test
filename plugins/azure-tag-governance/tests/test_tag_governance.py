from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "azure-tag-governance" / "scripts" / "tag_governance.py"
PUBLISH_SCRIPT = ROOT / "skills" / "azure-tag-governance" / "scripts" / "publish_run.py"
FIXTURES = ROOT / "tests" / "fixtures"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


governance = load_module("tag_governance", SCRIPT)
publish = load_module("publish_run", PUBLISH_SCRIPT)


class TagGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name)
        self.scope_id = (
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-demo"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def args(self, **overrides):
        values = {
            "resources": FIXTURES / "resources.json",
            "policy_evidence": FIXTURES / "policy.json",
            "ai_decisions": None,
            "previous_run": None,
            "output_root": self.output,
            "subscription_label": "demo-subscription",
            "scope_folder": "rg-demo",
            "scope_id": self.scope_id,
            "plugin_build": "0.1.0",
            "run_id": None,
            "now": "2026-10-13T16:00:00Z",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def build(self, **overrides) -> Path:
        return governance.build(self.args(**overrides))

    def test_first_run_is_candidate_only_and_deterministic(self) -> None:
        run = self.build(run_id="baseline")
        profile = governance.load_json(run / "governance-profile.json")
        assessment = governance.load_json(run / "assessment.json")
        self.assertEqual("1.0.0", profile["profileVersion"])
        self.assertFalse(profile["rules"])
        self.assertTrue(profile["candidates"])
        self.assertFalse(assessment["findings"])
        self.assertEqual("baseline", governance.verify_run(run)["runId"])

    def test_engineering_report_explains_required_tag_candidates(self) -> None:
        run = self.build(run_id="tag-candidate-report")
        profile = governance.load_json(run / "governance-profile.json")
        report = (run / "engineering-report.md").read_text(encoding="utf-8")
        candidate = next(item for item in profile["candidates"] if item.get("tagKey") == "Environment")

        self.assertIn("### Required tag: `Environment`", report)
        self.assertIn(f"- Candidate ID: `{candidate['id']}`", report)
        self.assertIn(f"- Scope: `{self.scope_id}`", report)
        self.assertIn("- Resource type: `microsoft.compute/virtualmachines`", report)
        self.assertIn("Tag present on 2/3 resources (66.7%)", report)
        self.assertIn("1/3 resources without this tag", report)
        self.assertIn("1 distinct observed value", report)
        self.assertIn("not authoritative requirements or compliance findings", report)
        self.assertIn("INFERRED (candidate only; not enforced)", report)

    def test_engineering_report_explains_naming_candidates(self) -> None:
        run = self.build(run_id="naming-candidate-report")
        profile = governance.load_json(run / "governance-profile.json")
        report = (run / "engineering-report.md").read_text(encoding="utf-8")
        candidate = next(item for item in profile["candidates"] if item["kind"] == "namingPattern")

        self.assertIn("### Naming format: `microsoft.compute/virtualmachines`", report)
        self.assertIn(f"- Candidate ID: `{candidate['id']}`", report)
        self.assertIn(f"- Pattern: `{candidate['pattern']}`", report)
        self.assertIn("Lowercase letters and digits, with optional single hyphen separators", report)
        self.assertIn("3/3 names match (100.0%)", report)
        self.assertIn("does not prove naming intent or semantic correctness", report)

    def test_engineering_report_is_order_independent_and_does_not_change_inputs(self) -> None:
        run = self.build(run_id="stable-candidate-report")
        profile = governance.load_json(run / "governance-profile.json")
        assessment = governance.load_json(run / "assessment.json")
        original_profile = governance.canonical_bytes(profile)
        original_assessment = governance.canonical_bytes(assessment)
        report = governance.engineering_report("stable-candidate-report", assessment, profile)

        reordered_profile = json.loads(original_profile)
        reordered_profile["candidates"].reverse()
        self.assertEqual(
            report,
            governance.engineering_report("stable-candidate-report", assessment, reordered_profile),
        )
        self.assertEqual(original_profile, governance.canonical_bytes(profile))
        self.assertEqual(original_assessment, governance.canonical_bytes(assessment))
        self.assertEqual(
            report,
            (run / "engineering-report.md").read_text(encoding="utf-8"),
        )

    def test_engineering_report_explains_each_inferred_naming_format(self) -> None:
        run = self.build(run_id="naming-format-report")
        profile = governance.load_json(run / "governance-profile.json")
        assessment = governance.load_json(run / "assessment.json")
        candidate = next(item for item in profile["candidates"] if item["kind"] == "namingPattern")
        examples = [
            ("vm-app-01", r"^[a-z0-9]+(?:-[a-z0-9]+)*$", "single hyphen separators"),
            ("vm_app_01", r"^[a-z0-9]+(?:_[a-z0-9]+)*$", "single underscore separators"),
            ("Vm-App-01", r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$", "Letters and digits (either case)"),
            ("vm.app_01", r"^[A-Za-z0-9._-]+$", "Letters, digits, dots, underscores, and hyphens"),
            ("vm-app", r"^vm-[a-z]+$", "Full name must match the regular expression below"),
        ]
        for name, pattern, description in examples:
            with self.subTest(pattern=pattern):
                if pattern in governance.NAMING_PATTERNS:
                    self.assertEqual(pattern, governance.infer_name_pattern([name]))
                candidate["pattern"] = pattern
                report = governance.engineering_report("naming-format-report", assessment, profile)
                self.assertIn(description, report)
                self.assertIn(f"- Pattern: `{pattern}`", report)

    def test_engineering_report_preserves_unknown_and_zero_sample_support(self) -> None:
        run = self.build(run_id="unknown-support-report")
        profile = governance.load_json(run / "governance-profile.json")
        assessment = governance.load_json(run / "assessment.json")
        candidate = next(item for item in profile["candidates"] if item.get("tagKey") == "Environment")
        candidate["evidence"] = {}
        report = governance.engineering_report("unknown-support-report", assessment, profile)
        self.assertIn("UNKNOWN (supporting resource counts were not collected)", report)
        candidate["evidence"] = {"eligibleResourceCount": 0, "observedResourceCount": 0}
        report = governance.engineering_report("unknown-support-report", assessment, profile)
        self.assertIn("no eligible sample; percentage UNKNOWN", report)
        candidate["evidence"] = {"eligibleResourceCount": 1, "observedResourceCount": 2}
        with self.assertRaisesRegex(ValueError, "Candidate support counts"):
            governance.engineering_report("unknown-support-report", assessment, profile)

    def test_engineering_report_keeps_tag_keys_with_backticks_readable(self) -> None:
        run = self.build(run_id="quoted-tag-report")
        profile = governance.load_json(run / "governance-profile.json")
        assessment = governance.load_json(run / "assessment.json")
        candidate = next(item for item in profile["candidates"] if item.get("tagKey") == "Environment")
        candidate["tagKey"] = "Team`Name"
        report = governance.engineering_report("quoted-tag-report", assessment, profile)
        self.assertIn("### Required tag: ``Team`Name``", report)
        self.assertNotIn("valueDigests", report)
        self.assertNotIn("nameDigests", report)

    def test_generated_profile_matches_contract(self) -> None:
        run = self.build(run_id="schema")
        schema = governance.load_json(
            ROOT / "skills" / "azure-tag-governance" / "governance-profile.schema.json"
        )
        profile = governance.load_json(run / "governance-profile.json")
        Draft202012Validator(
            schema, format_checker=Draft202012Validator.FORMAT_CHECKER
        ).validate(profile)

    def test_second_comparable_run_can_promote_and_find_missing_tag(self) -> None:
        first = self.build(run_id="first")
        profile = governance.load_json(first / "governance-profile.json")
        candidate = next(
            item for item in profile["candidates"]
            if item["kind"] == "requiredTag" and item.get("tagKey") == "Environment"
        )
        decision = [{
            "candidateId": candidate["id"],
            "action": "promote",
            "authorityEligible": True,
            "supportingEvidence": ["Observed on two of three eligible resources in two comparable runs."],
            "contraryEvidence": ["One eligible resource lacks the tag."],
            "coverage": {"complete": True, "sources": ["AzureResourceGraph"]},
            "modelVersion": "test-model",
            "promptVersion": "test-prompt",
            "confidence": "high",
            "rationale": "The repeated pattern is suitable for deterministic evaluation.",
            "expiresAt": "2027-01-01T00:00:00Z",
            "rollbackProfileVersion": profile["profileVersion"],
            "ruleSpec": {
                "kind": candidate["kind"],
                "scope": candidate["scope"],
                "tagKey": candidate["tagKey"]
            }
        }]
        decisions = self.output / "decisions.json"
        governance.write_json(decisions, decision)
        second = self.build(
            run_id="second",
            previous_run=first,
            ai_decisions=decisions,
            now="2026-10-20T16:00:00Z",
        )
        second_profile = governance.load_json(second / "governance-profile.json")
        assessment = governance.load_json(second / "assessment.json")
        self.assertEqual("1.0.1", second_profile["profileVersion"])
        self.assertEqual(1, len(second_profile["rules"]))
        self.assertEqual(1, len(assessment["findings"]))
        self.assertIn("Environment", assessment["findings"][0]["message"])
        observations = governance.load_json(second / "observations.json")
        self.assertEqual(1, len(observations["retainedFindingResources"]))
        self.assertNotIn("CostCenter", observations["retainedFindingResources"][0]["tags"])

    def promotion_fixture(self, run_id):
        first = self.build(run_id=run_id)
        profile = governance.load_json(first / "governance-profile.json")
        candidate = next(item for item in profile["candidates"] if item.get("tagKey") == "Environment")
        decision = {
            "candidateId": candidate["id"],
            "action": "promote",
            "authorityEligible": True,
            "supportingEvidence": ["Synthetic repeated candidate evidence."],
            "contraryEvidence": ["One fixture resource lacks the tag."],
            "coverage": {"complete": True},
            "modelVersion": "test-model",
            "promptVersion": "test-prompt",
            "confidence": "high",
            "rationale": "Synthetic approval for promotion-gate testing only.",
            "expiresAt": "2027-01-01T00:00:00Z",
            "rollbackProfileVersion": profile["profileVersion"],
            "ruleSpec": {
                "kind": candidate["kind"],
                "scope": candidate["scope"],
                "tagKey": candidate["tagKey"],
            },
        }
        return first, profile, decision

    def test_low_confidence_cannot_be_auto_promoted(self) -> None:
        first, _, decision = self.promotion_fixture("low-confidence-first")
        decision["confidence"] = "low"
        path = self.output / "low-confidence-decision.json"
        governance.write_json(path, [decision])
        second = self.build(
            run_id="low-confidence-second", previous_run=first,
            ai_decisions=path, now="2026-10-20T00:00:00Z",
        )
        profile = governance.load_json(second / "governance-profile.json")
        assessment = governance.load_json(second / "assessment.json")
        self.assertFalse(profile["rules"])
        self.assertTrue(assessment["evidenceGaps"])

    def test_repeated_promotion_does_not_duplicate_an_authoritative_rule(self) -> None:
        first, _, decision = self.promotion_fixture("duplicate-first")
        path = self.output / "duplicate-decision.json"
        governance.write_json(path, [decision])
        second = self.build(
            run_id="duplicate-second", previous_run=first,
            ai_decisions=path, now="2026-10-20T00:00:00Z",
        )
        third = self.build(
            run_id="duplicate-third", previous_run=second,
            now="2026-10-21T00:00:00Z",
        )
        prior = governance.load_json(third / "governance-profile.json")
        decision["rollbackProfileVersion"] = prior["profileVersion"]
        governance.write_json(path, [decision])
        fourth = self.build(
            run_id="duplicate-fourth", previous_run=third,
            ai_decisions=path, now="2026-10-22T00:00:00Z",
        )
        profile = governance.load_json(fourth / "governance-profile.json")
        self.assertEqual(1, len(profile["rules"]))
        self.assertEqual(1, len({rule["id"] for rule in profile["rules"]}))

    def test_auto_promotion_cannot_weaken_an_inherited_rule(self) -> None:
        first, prior, decision = self.promotion_fixture("inherited-first")
        prior["rules"] = [{
            "id": "rule-declared-broad",
            "kind": "requiredTag",
            "status": "authoritative",
            "scope": {"scopeId": self.scope_id},
            "tagKey": "Environment",
            "normalization": {
                "keyCaseSensitive": True, "valueCaseSensitive": True,
                "trimWhitespace": False, "unicodeNormalization": "none",
                "emptyIsMissing": True,
            },
            "multiValue": None,
            "evidenceClass": "DECLARED",
            "createdAt": "2026-10-01T00:00:00Z",
            "expiresAt": "2027-01-01T00:00:00Z",
            "sourceCandidateId": "declared-environment",
        }]
        document = governance.load_json(FIXTURES / "resources.json")
        resources = [governance.normalize_resource(item) for item in document["resources"]]
        profile, errors = governance.build_profile(
            resources, self.scope_id,
            governance.parse_time("2026-10-20T00:00:00Z", "now"),
            prior, governance.load_json(first / "run.json"),
            "0.1.0", document["coverage"], [decision],
        )
        self.assertEqual(1, len(profile["rules"]))
        self.assertTrue(profile["rules"][0]["normalization"]["emptyIsMissing"])
        self.assertTrue(errors)

    def test_retention_review_is_auditable_in_profile_and_report(self) -> None:
        first, _, decision = self.promotion_fixture("review-first")
        decision["action"] = "retainCandidate"
        decision["authorityEligible"] = False
        decision["confidence"] = "low"
        decision["rationale"] = "Fixture patterns do not establish an authoritative requirement."
        path = self.output / "retention-review.json"
        governance.write_json(path, [decision])
        second = self.build(
            run_id="review-second", previous_run=first,
            ai_decisions=path, now="2026-10-20T00:00:00Z",
        )
        profile = governance.load_json(second / "governance-profile.json")
        candidate = next(item for item in profile["candidates"] if item["id"] == decision["candidateId"])
        self.assertEqual(decision, candidate["decision"])
        self.assertEqual("retainedCandidate", candidate["reviewOutcome"])
        self.assertFalse(profile["rules"])
        report = (second / "engineering-report.md").read_text(encoding="utf-8")
        self.assertIn(decision["rationale"], report)
        self.assertIn("- Review confidence: `low`", report)
        self.assertIn("- Review model: `test-model`", report)

    def test_promotion_requires_support_and_complete_decision_coverage(self) -> None:
        first, _, decision = self.promotion_fixture("support-first")
        for key, value in (("supportingEvidence", []), ("coverage", {"complete": False})):
            with self.subTest(key=key):
                invalid = json.loads(json.dumps(decision))
                invalid[key] = value
                path = self.output / f"{key}-decision.json"
                governance.write_json(path, [invalid])
                second = self.build(
                    run_id=f"support-{key}", previous_run=first,
                    ai_decisions=path, now="2026-10-20T00:00:00Z",
                )
                self.assertFalse(governance.load_json(second / "governance-profile.json")["rules"])
                self.assertTrue(governance.load_json(second / "assessment.json")["evidenceGaps"])

    def test_scope_overlap_distinguishes_disjoint_resource_scopes(self) -> None:
        self.assertTrue(governance.scopes_overlap(
            {"scopeId": self.scope_id},
            {"scopeId": self.scope_id, "resourceType": "contoso/widgets"},
        ))
        self.assertFalse(governance.scopes_overlap(
            {"scopeId": self.scope_id},
            {"scopeId": self.scope_id.replace("rg-demo", "rg-different")},
        ))
        self.assertFalse(governance.scopes_overlap(
            {"scopeId": self.scope_id, "resourceType": "contoso/widgets"},
            {"scopeId": self.scope_id, "resourceType": "contoso/gadgets"},
        ))

    def test_rule_spec_cannot_replace_reserved_rule_metadata(self) -> None:
        _, _, decision = self.promotion_fixture("reserved-first")
        decision["ruleSpec"]["id"] = "forged-rule"
        with self.assertRaisesRegex(ValueError, "reserved"):
            governance.validate_decision(
                decision, governance.parse_time("2026-10-20T00:00:00Z", "now"),
            )

    def test_promotion_rollback_reference_must_match_baseline(self) -> None:
        first, _, decision = self.promotion_fixture("rollback-first")
        decision["rollbackProfileVersion"] = "99.0.0"
        path = self.output / "wrong-rollback-decision.json"
        governance.write_json(path, [decision])
        second = self.build(
            run_id="rollback-second", previous_run=first,
            ai_decisions=path, now="2026-10-20T00:00:00Z",
        )
        self.assertFalse(governance.load_json(second / "governance-profile.json")["rules"])
        gaps = governance.load_json(second / "assessment.json")["evidenceGaps"]
        self.assertTrue(any("rollback" in item["message"] for item in gaps))

    def test_stale_rule_revalidation_preserves_identity_without_duplicates(self) -> None:
        first, _, decision = self.promotion_fixture("revalidate-first")
        decision["expiresAt"] = "2026-10-21T00:00:00Z"
        path = self.output / "revalidate-decision.json"
        governance.write_json(path, [decision])
        second = self.build(
            run_id="revalidate-second", previous_run=first,
            ai_decisions=path, now="2026-10-20T00:00:00Z",
        )
        original_rule = governance.load_json(second / "governance-profile.json")["rules"][0]
        third = self.build(
            run_id="revalidate-third", previous_run=second,
            now="2026-10-22T00:00:00Z",
        )
        prior = governance.load_json(third / "governance-profile.json")
        self.assertEqual("stale", prior["rules"][0]["status"])
        decision["rollbackProfileVersion"] = prior["profileVersion"]
        decision["expiresAt"] = "2027-01-01T00:00:00Z"
        governance.write_json(path, [decision])
        fourth = self.build(
            run_id="revalidate-fourth", previous_run=third,
            ai_decisions=path, now="2026-10-23T00:00:00Z",
        )
        rules = governance.load_json(fourth / "governance-profile.json")["rules"]
        self.assertEqual(1, len(rules))
        self.assertEqual("authoritative", rules[0]["status"])
        self.assertEqual(original_rule["id"], rules[0]["id"])
        self.assertEqual(original_rule["createdAt"], rules[0]["createdAt"])

    def test_expired_rule_becomes_stale_and_stops_findings(self) -> None:
        first = self.build(run_id="first-expiry")
        profile = governance.load_json(first / "governance-profile.json")
        candidate = next(item for item in profile["candidates"] if item.get("tagKey") == "Environment")
        decision = [{
            "candidateId": candidate["id"],
            "action": "promote",
            "authorityEligible": True,
            "supportingEvidence": ["Repeated evidence"],
            "contraryEvidence": [],
            "coverage": {"complete": True},
            "modelVersion": "test-model",
            "promptVersion": "test-prompt",
            "confidence": "high",
            "rationale": "Test promotion",
            "expiresAt": "2026-10-21T00:00:00Z",
            "rollbackProfileVersion": "1.0.0",
            "ruleSpec": {
                "kind": "requiredTag",
                "scope": candidate["scope"],
                "tagKey": "Environment"
            }
        }]
        decisions = self.output / "expiry-decisions.json"
        governance.write_json(decisions, decision)
        second = self.build(
            run_id="second-expiry", previous_run=first, ai_decisions=decisions,
            now="2026-10-20T00:00:00Z",
        )
        third = self.build(
            run_id="third-expiry", previous_run=second, now="2026-10-22T00:00:00Z",
        )
        third_profile = governance.load_json(third / "governance-profile.json")
        assessment = governance.load_json(third / "assessment.json")
        self.assertEqual("stale", third_profile["rules"][0]["status"])
        self.assertFalse(assessment["findings"])

    def test_partial_coverage_is_an_unknown_gap(self) -> None:
        document = governance.load_json(FIXTURES / "resources.json")
        document["coverage"]["complete"] = False
        resources = self.output / "partial.json"
        governance.write_json(resources, document)
        run = self.build(resources=resources, run_id="partial")
        assessment = governance.load_json(run / "assessment.json")
        self.assertTrue(any(item["classification"] == "UNKNOWN" for item in assessment["evidenceGaps"]))
        self.assertEqual("SucceededWithWarnings", governance.load_json(run / "run.json")["status"])

    def test_malformed_ai_decision_is_recorded_without_promotion(self) -> None:
        first = self.build(run_id="malformed-first")
        decisions = self.output / "malformed-decisions.json"
        governance.write_json(decisions, [{"candidateId": "candidate-incomplete", "action": "promote"}])
        second = self.build(
            run_id="malformed-second",
            previous_run=first,
            ai_decisions=decisions,
            now="2026-10-20T00:00:00Z",
        )
        profile = governance.load_json(second / "governance-profile.json")
        assessment = governance.load_json(second / "assessment.json")
        self.assertFalse(profile["rules"])
        self.assertTrue(any("AI decision is missing" in item["message"] for item in assessment["evidenceGaps"]))

    def test_unmarked_narrower_rule_conflict_blocks_evaluation(self) -> None:
        resource = governance.normalize_resource({
            "id": self.scope_id + "/providers/Contoso/widgets/example",
            "name": "example",
            "type": "Contoso/widgets",
            "resourceGroup": "rg-demo",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "tags": {},
        })
        base = {
            "kind": "requiredTag",
            "status": "authoritative",
            "tagKey": "Environment",
            "normalization": {"keyCaseSensitive": True},
            "multiValue": None,
            "evidenceClass": "DECLARED",
            "createdAt": "2026-10-01T00:00:00Z",
            "expiresAt": "2027-10-01T00:00:00Z",
            "sourceCandidateId": "candidate-environment",
        }
        profile = {
            "profileId": "profile",
            "profileVersion": "1.0.0",
            "generatedAt": "2026-10-01T00:00:00Z",
            "scopeId": self.scope_id,
            "rules": [
                {"id": "rule-broad", "scope": {"scopeId": self.scope_id}, **base},
                {
                    "id": "rule-narrow",
                    "scope": {"scopeId": self.scope_id, "resourceType": "contoso/widgets"},
                    **base,
                },
            ],
            "candidates": [],
            "exceptions": [],
            "applicability": [{
                "resourceType": "contoso/widgets",
                "taggable": True,
                "namingAssessable": True,
                "reason": "test",
            }],
        }
        assessment = governance.evaluate(
            profile, [resource], governance.parse_time("2026-10-13T00:00:00Z", "now"),
            {"complete": True}, [],
        )
        self.assertEqual(1, len(assessment["profileConflicts"]))
        self.assertFalse(assessment["findings"])

    def test_active_exception_suppresses_and_expired_exception_is_reported(self) -> None:
        resource = governance.normalize_resource({
            "id": self.scope_id + "/providers/Contoso/widgets/example",
            "name": "example",
            "type": "Contoso/widgets",
            "resourceGroup": "rg-demo",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "tags": {},
        })
        rule = {
            "id": "rule-required",
            "kind": "requiredTag",
            "status": "authoritative",
            "scope": {"scopeId": self.scope_id, "resourceType": "contoso/widgets"},
            "tagKey": "Environment",
            "normalization": {"keyCaseSensitive": True, "emptyIsMissing": True},
            "multiValue": None,
            "evidenceClass": "DECLARED",
            "createdAt": "2026-10-01T00:00:00Z",
            "expiresAt": "2027-10-01T00:00:00Z",
            "sourceCandidateId": "candidate-required",
        }
        exception = {
            "id": "exception-one",
            "owner": "platform",
            "rationale": "Temporary migration",
            "approvalEvidence": "change-1",
            "scope": {"scopeId": self.scope_id},
            "ruleIds": [rule["id"]],
            "resourceIds": [resource["id"]],
            "createdAt": "2026-10-01T00:00:00Z",
            "expiresAt": "2026-10-20T00:00:00Z",
            "status": "active",
        }
        profile = {
            "profileId": "profile",
            "profileVersion": "1.0.0",
            "generatedAt": "2026-10-01T00:00:00Z",
            "scopeId": self.scope_id,
            "rules": [rule],
            "candidates": [],
            "exceptions": [exception],
            "applicability": [{
                "resourceType": "contoso/widgets",
                "taggable": True,
                "namingAssessable": True,
                "reason": "test",
            }],
        }
        active = governance.evaluate(
            profile, [resource], governance.parse_time("2026-10-13T00:00:00Z", "now"),
            {"complete": True}, [],
        )
        self.assertFalse(active["findings"])
        expired = governance.evaluate(
            profile, [resource], governance.parse_time("2026-10-21T00:00:00Z", "now"),
            {"complete": True}, [],
        )
        self.assertEqual(2, len(expired["findings"]))
        self.assertTrue(any(item["status"] == "UNKNOWN" for item in expired["findings"]))

    def test_multi_value_rules_use_explicit_delimiter_and_duplicate_policy(self) -> None:
        resource = governance.normalize_resource({
            "id": self.scope_id + "/providers/Contoso/widgets/example",
            "name": "example",
            "type": "Contoso/widgets",
            "resourceGroup": "rg-demo",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "tags": {"Teams": "ops;ops"},
        })
        rule = {
            "id": "rule-teams",
            "kind": "allowedValues",
            "status": "authoritative",
            "scope": {"scopeId": self.scope_id, "resourceType": "contoso/widgets"},
            "tagKey": "Teams",
            "allowedValues": ["ops", "platform"],
            "normalization": {
                "keyCaseSensitive": True,
                "valueCaseSensitive": True,
                "trimWhitespace": False,
                "emptyIsMissing": False,
            },
            "multiValue": {"delimiter": ";", "duplicatesAllowed": False},
            "evidenceClass": "DECLARED",
            "createdAt": "2026-10-01T00:00:00Z",
            "expiresAt": "2027-10-01T00:00:00Z",
            "sourceCandidateId": "candidate-teams",
        }
        profile = {
            "profileId": "profile",
            "profileVersion": "1.0.0",
            "generatedAt": "2026-10-01T00:00:00Z",
            "scopeId": self.scope_id,
            "rules": [rule],
            "candidates": [],
            "exceptions": [],
            "applicability": [{
                "resourceType": "contoso/widgets",
                "taggable": True,
                "namingAssessable": True,
                "reason": "test",
            }],
        }
        assessment = governance.evaluate(
            profile, [resource], governance.parse_time("2026-10-13T00:00:00Z", "now"),
            {"complete": True}, [],
        )
        self.assertEqual(1, len(assessment["findings"]))
        self.assertIn("duplicate", assessment["findings"][0]["message"])

    def test_verify_detects_tampering(self) -> None:
        run = self.build(run_id="tamper")
        (run / "executive-report.md").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "verification failed"):
            governance.verify_run(run)

    def test_publication_guards_repository_and_destination(self) -> None:
        self.assertTrue(publish.repository_matches(
            "https://github.com/example/output.git", "example/output"
        ))
        self.assertTrue(publish.repository_matches(
            "git@github.com:example/output.git", "example/output"
        ))
        self.assertFalse(publish.repository_matches(
            "https://example.com/example/output.git", "example/output"
        ))
        with self.assertRaisesRegex(ValueError, "Destination"):
            publish.validate_destination("../output")


if __name__ == "__main__":
    unittest.main()
