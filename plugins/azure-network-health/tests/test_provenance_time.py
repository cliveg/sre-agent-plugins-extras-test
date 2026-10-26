from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_dns_intent as intent_tests
import test_network_health as fixtures


nh = fixtures.nh
SUB, RUN, TIME = fixtures.SUB, fixtures.RUN, fixtures.TIME
REVIEW = "2026-10-08T21:00:00.123456Z"


class ProvenanceTimeTests(unittest.TestCase):
    def model(self):
        return nh.normalize(nh.collect(SUB, RUN, fixtures.FixtureReader(), "synthetic-fixture", clock=lambda: TIME))

    def test_age_only_view_has_exact_microseconds_no_threshold_or_observation_changes(self):
        model = self.model()
        before = nh.encoded(model)
        a = nh.assess(model, review_at=REVIEW)
        view = a["provenanceTimeReview"]
        self.assertEqual(view["observationCompletionAgeMicroseconds"], 86400123456)
        self.assertEqual(view["referenceAt"], REVIEW)
        self.assertEqual(view["policy"], "age-and-provenance-only-no-expiry-thresholds")
        self.assertEqual(view["validity"], "UNKNOWN")
        self.assertEqual(len(view["collections"]), 9)
        self.assertEqual(len(a["checksExecuted"]), 7)
        self.assertEqual(a["checkCatalogVersion"], "1.9.0")
        self.assertIsNone(view["intent"])
        self.assertEqual(before, nh.encoded(model))
        self.assertNotIn("provenanceTimeReview", model)
        self.assertTrue(all(f["severity"] is None for f in a["findings"] if f["checkId"] == "NET-EVID-TIME-001"))

    def test_no_reference_time_keeps_existing_catalog_and_no_implicit_clock(self):
        a = nh.assess(self.model())
        self.assertNotIn("provenanceTimeReview", a)
        self.assertEqual(a["checkCatalogVersion"], "1.2.0")
        self.assertEqual(len(a["checksExecuted"]), 6)

    def test_review_check_is_wired_for_each_existing_input_mode(self):
        import test_dns_planning as planning
        import test_dns_record_metadata as metadata
        cases = (
            (fixtures.FixtureReader(), {}, 7),
            (fixtures.PrivateFixtureReader(), {"include_private": True}, 9),
            (planning.PlanningFixtureReader(), {"include_dns_planning": True}, 11),
            (metadata.MetadataFixtureReader(), {"include_record_metadata": True}, 12),
            (intent_tests.paths.DNSPathFixtureReader(), {"include_dns_paths": True}, 14),
        )
        for reader, options, expected in cases:
            with self.subTest(expected=expected):
                model = nh.normalize(nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME, **options))
                a = nh.assess(model, review_at=REVIEW)
                self.assertEqual(len(a["checksExecuted"]), expected)
                self.assertEqual(a["checkCatalogVersion"], "1.9.0")
                self.assertNotIn("dnsIntentComparison", a)

    def test_reopening_or_different_wall_clock_does_not_change_report(self):
        model = self.model()
        first = nh.assess(model, review_at=REVIEW)
        with patch.object(nh, "utc_now", return_value="2099-01-01T00:00:00Z"):
            second = nh.assess(model, review_at=REVIEW)
        self.assertEqual(first, second)
        self.assertEqual(nh.render(first), nh.render(second))

    def test_old_age_does_not_mean_stale_or_expired(self):
        a = nh.assess(self.model(), review_at="2099-01-01T00:00:00Z")
        self.assertEqual(a["provenanceTimeReview"]["validity"], "UNKNOWN")
        self.assertFalse(any(f["severity"] for f in a["findings"] if f["checkId"] == "NET-EVID-TIME-001"))
        self.assertFalse(any("expired" in f["title"].lower() or "stale" in f["title"].lower()
                             for f in a["findings"] if f["checkId"] == "NET-EVID-TIME-001"))

    def test_future_collection_times_are_unknown_not_clamped_to_zero(self):
        a = nh.assess(self.model(), review_at="2026-10-01T00:00:00Z")
        view = a["provenanceTimeReview"]
        self.assertIsNone(view["observationCompletionAgeMicroseconds"])
        self.assertTrue(view["observationIssues"])
        self.assertTrue(all(row["completionAgeMicroseconds"] is None and row["issues"] for row in view["collections"]))
        self.assertTrue(any(f["recordType"] == "evidenceGap" for f in a["findings"] if f["checkId"] == "NET-EVID-TIME-001"))

    def test_collection_failure_is_not_fresh_success_evidence(self):
        reader = fixtures.FixtureReader()
        reader.fail = "nsgs"
        model = nh.normalize(nh.collect(SUB, RUN, reader, "synthetic-fixture", clock=lambda: TIME))
        a = nh.assess(model, review_at=REVIEW)
        row = next(row for row in a["provenanceTimeReview"]["collections"] if row["operationId"] == "nsgs")
        self.assertEqual(row["collectionStatus"], "permissionDenied")
        self.assertTrue(any("not evidence of successful collection" in issue for issue in row["issues"]))
        self.assertTrue(any("No collection pages" in issue for issue in row["issues"]))

    def test_inconsistent_collection_interval_and_run_boundary_are_reported_not_rewritten(self):
        model = self.model()
        model["collections"][0]["startedAt"] = "2026-10-08T00:00:00Z"
        model["run"]["startedAt"] = "2026-10-06T21:00:00Z"
        original = nh.encoded(model)
        a = nh.assess(model, review_at=REVIEW)
        self.assertTrue(any("does not match" in issue for issue in a["provenanceTimeReview"]["observationIssues"]))
        self.assertTrue(any("precedes its start" in issue for row in a["provenanceTimeReview"]["collections"] for issue in row["issues"]))
        self.assertEqual(original, nh.encoded(model))

    def test_evidence_timestamp_disagreement_is_an_explicit_provenance_gap(self):
        model = self.model()
        model["evidence"][0]["collectedAt"] = "2026-10-08T00:00:00Z"
        a = nh.assess(model, review_at=REVIEW)
        self.assertTrue(any("Evidence timestamps differ" in issue for row in a["provenanceTimeReview"]["collections"] for issue in row["issues"]))

    def test_intent_ages_do_not_authenticate_document_or_owner(self):
        helper = intent_tests.DNSIntentTests()
        _, model, reader = helper.setup_model()
        intent = helper.intent(reader)
        a = nh.assess(model, intent, REVIEW)
        view = a["provenanceTimeReview"]
        self.assertEqual(len(a["checksExecuted"]), 15)
        self.assertEqual(view["intent"]["classification"], "DECLARED")
        self.assertEqual(view["intent"]["intentSha256"], nh.digest(intent))
        self.assertEqual(view["intent"]["declarationAgeMicroseconds"], 86400123456)
        self.assertEqual(view["intent"]["validity"], "UNKNOWN")
        self.assertIn("not independently authenticated", view["intent"]["issues"][0])
        self.assertEqual(a["dnsIntentComparison"]["classification"], "DECLARED")

    def test_intent_future_to_review_and_newer_than_observation_are_explicit(self):
        helper = intent_tests.DNSIntentTests()
        _, model, reader = helper.setup_model()
        intent = helper.intent(reader)
        intent["source"]["declaredAt"] = intent["source"]["reviewedAt"] = "2026-10-10T00:00:00Z"
        a = nh.assess(model, intent, REVIEW)
        self.assertIsNone(a["provenanceTimeReview"]["intent"]["declarationAgeMicroseconds"])
        self.assertTrue(any("after the supplied review time" in issue for issue in a["provenanceTimeReview"]["intent"]["issues"]))
        self.assertTrue(any("after the observation interval" in issue for issue in a["provenanceTimeReview"]["intent"]["issues"]))

    def test_reference_input_rejects_missing_timezone_offsets_invalid_dates_and_empty_values(self):
        for value in ("", "today", "2026-10-10", "2026-10-10T00:00:00", "2026-10-10T00:00:00+00:00",
                      "2026-02-30T00:00:00Z", "2026-10-10T00:00:00.1234567Z"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                nh.assess(self.model(), review_at=value)

    def test_tampered_reference_age_and_markdown_are_rejected(self):
        model = self.model()
        a = nh.assess(model, review_at=REVIEW)
        altered = copy.deepcopy(a)
        altered["provenanceTimeReview"]["observationCompletionAgeMicroseconds"] = 0
        with self.assertRaisesRegex(ValueError, "Temporal review"):
            nh.verify_assessment(model, altered)
        summary, engineering = nh.render(a)
        self.assertIn("86400.123456", engineering)
        with self.assertRaisesRegex(ValueError, "temporal review"):
            nh.verify_reports(a, summary, engineering.replace("86400.123456", "0.000000"))

    def test_cli_review_is_processing_only_and_produces_four_files(self):
        envelope = nh.collect(SUB, RUN, fixtures.FixtureReader(), "synthetic-fixture", clock=lambda: TIME)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input.json").write_bytes(nh.encoded(envelope))
            command = [sys.executable, str(nh.HERE / "network_health.py"), "--input", str(root / "input.json"),
                       "--review-at", REVIEW, "--output-root", str(root / "output")]
            completed = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertTrue(completed.stdout)
            self.assertEqual({p.name for p in (root / "output" / "runs" / RUN).iterdir()}, set(nh.REPORT_FILES))
            invalid = subprocess.run([sys.executable, str(nh.HERE / "network_health.py"), "--review-at", REVIEW,
                                      "--output-root", str(root / "other")], capture_output=True, text=True, check=False)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("requires existing --input", invalid.stderr)
