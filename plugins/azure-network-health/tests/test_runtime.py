from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import ValidationError


SKILL = Path(__file__).resolve().parents[1] / "skills" / "azure-network-health-assessment"
SPEC = importlib.util.spec_from_file_location("network_health_runtime", SKILL / "runtime.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load runtime helper")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)

RUN = "00000000-0000-4000-8000-000000000001"
SUBSCRIPTION = "00000000-0000-4000-8000-000000000002"
OTHER = "00000000-0000-4000-8000-000000000003"
TIMESTAMP = "2026-10-07T21:00:00Z"


class RuntimeTests(unittest.TestCase):
    def build(self, **changes: object) -> dict[str, object]:
        args = {
            "run_id": RUN,
            "subscription_id": SUBSCRIPTION,
            "collection_timestamp": TIMESTAMP,
            "outcome": {"status": "succeeded", "subscriptionId": SUBSCRIPTION},
        }
        args.update(changes)
        return runtime.build_artifact(**args)

    def test_success_is_valid_and_does_not_contain_subscription(self) -> None:
        artifact = self.build()
        runtime.validate_artifact(artifact)
        self.assertNotIn(SUBSCRIPTION, json.dumps(artifact))
        self.assertEqual(artifact["readOutcome"]["returnedScopeMatches"], True)

    def test_same_inputs_produce_identical_artifact(self) -> None:
        self.assertEqual(self.build(), self.build())

    def test_scope_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.build(outcome={"status": "succeeded", "subscriptionId": OTHER})

    def test_failure_is_preserved_without_success_fields(self) -> None:
        for status in ("permissionDenied", "unavailable", "failed"):
            with self.subTest(status=status):
                artifact = self.build(outcome={"status": status, "errorCode": "Forbidden"})
                self.assertEqual(artifact["readOutcome"]["status"], status)
                self.assertNotIn("returnedScopeMatches", artifact["readOutcome"])

    def test_unredacted_extra_input_is_rejected(self) -> None:
        for extra in ("subscriptionName", "tenantId", "tags", "errorMessage"):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    self.build(outcome={
                        "status": "succeeded", "subscriptionId": SUBSCRIPTION, extra: "private",
                    })

    def test_invalid_status_and_error_code_are_rejected(self) -> None:
        for outcome in (
            {"status": "unknown", "errorCode": "Unavailable"},
            {"status": "failed", "errorCode": "sensitive message with spaces"},
        ):
            with self.subTest(outcome=outcome):
                with self.assertRaises(ValidationError):
                    self.build(outcome=outcome)

    def test_naive_timestamp_and_invalid_ids_are_rejected(self) -> None:
        for changes in (
            {"collection_timestamp": "2026-10-07T21:00:00"},
            {"run_id": "../escape"},
            {"subscription_id": "not-a-subscription"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.build(**changes)

    def test_timestamp_is_normalized_to_utc(self) -> None:
        artifact = self.build(collection_timestamp="2026-10-07T15:00:00-06:00")
        self.assertEqual(artifact["collectionTimestamp"], TIMESTAMP)

    def test_json_schema_format_and_unknown_fields_are_checked(self) -> None:
        for field, value in (
            ("runId", "not-a-uuid"),
            ("collectionTimestamp", "not-a-date"),
            ("unexpected", "payload"),
        ):
            with self.subTest(field=field):
                artifact = copy.deepcopy(self.build())
                artifact[field] = value
                with self.assertRaises(ValidationError):
                    runtime.validate_artifact(artifact)

    def test_missing_supporting_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "reference.md"
            reference.write_text("incorrect reference", encoding="utf-8")
            with patch.object(runtime, "HERE", Path(directory)):
                with self.assertRaisesRegex(ValueError, "reference marker"):
                    self.build()

    def test_file_is_retrievable_with_integrity_and_cannot_be_overwritten(self) -> None:
        artifact = self.build()
        with tempfile.TemporaryDirectory() as directory:
            path, digest = runtime.write_artifact(artifact, Path(directory))
            self.assertEqual(json.loads(path.read_bytes()), artifact)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.parent.name, RUN)
            with self.assertRaises(FileExistsError):
                runtime.write_artifact(artifact, Path(directory))

    def test_schema_prevents_failure_masquerading_as_success(self) -> None:
        artifact = self.build()
        artifact["readOutcome"]["status"] = "permissionDenied"
        with self.assertRaises(ValidationError):
            runtime.validate_artifact(artifact)

    def test_timestamp_validation_does_not_need_optional_date_time_package(self) -> None:
        checker = runtime.FormatChecker()
        checker.checkers.pop("date-time", None)
        artifact = self.build()
        with patch.object(runtime, "FormatChecker", return_value=checker):
            runtime.validate_artifact(artifact)
            for invalid in ("2026-02-30T00:00:00Z", "not-a-date", "2026-01-01T00:00:00"):
                artifact["collectionTimestamp"] = invalid
                with self.assertRaises(ValidationError):
                    runtime.validate_artifact(artifact)


if __name__ == "__main__":
    unittest.main()
