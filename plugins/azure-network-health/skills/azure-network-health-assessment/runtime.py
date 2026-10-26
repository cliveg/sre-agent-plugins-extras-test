"""Build the Increment 0 proof from a supplied, explicitly scoped read outcome."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


CAPABILITY_VERSION = "0.0.1"
REFERENCE_MARKER = "AZURE-NETWORK-HEALTH-INCREMENT-0-REFERENCE-V1"
HERE = Path(__file__).resolve().parent


def canonical_uuid(value: str) -> str:
    return str(UUID(value))


def validate_document(document: dict[str, object], schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    registry = Registry()
    common_path = schema_path.parent / "common.schema.json"
    if common_path.exists():
        common = json.loads(common_path.read_text(encoding="utf-8"))
        registry = registry.with_resource(common["$id"], Resource.from_contents(common))
    checker = FormatChecker()

    @checker.checks("utc-date-time", raises=ValueError)
    def utc_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return True
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
            return False
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True

    @checker.checks("microsoft-learn-url", raises=ValueError)
    def microsoft_learn_url(value: object) -> bool:
        if not isinstance(value, str):
            return True
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https" and parsed.hostname == "learn.microsoft.com"
            and not parsed.username and not parsed.password
            and not re.search(r"\s", value)
        )

    def require_formats(node: object) -> None:
        if isinstance(node, dict):
            if "format" in node and node["format"] not in checker.checkers:
                raise RuntimeError("Schema format checker unavailable: " + str(node["format"]))
            for child in node.values():
                require_formats(child)
        elif isinstance(node, list):
            for child in node:
                require_formats(child)

    require_formats(schema)
    if common_path.exists():
        require_formats(common)

    Draft202012Validator(schema, format_checker=checker, registry=registry).validate(document)


def validate_artifact(artifact: dict[str, object]) -> None:
    validate_document(artifact, HERE / "feasibility.schema.json")


def build_artifact(
    run_id: str,
    subscription_id: str,
    collection_timestamp: str,
    outcome: dict[str, object],
) -> dict[str, object]:
    run_id = canonical_uuid(run_id)
    subscription_id = canonical_uuid(subscription_id)
    timestamp = datetime.fromisoformat(collection_timestamp.replace("Z", "+00:00"))
    if timestamp.utcoffset() is None:
        raise ValueError("Collection timestamp must include a timezone")
    timestamp_text = timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    read_outcome: dict[str, object] = {
        "operationId": "subscription-context",
        "status": outcome.get("status"),
    }
    if outcome.get("status") == "succeeded":
        if set(outcome) != {"status", "subscriptionId"}:
            raise ValueError("Success input must contain only status and subscriptionId")
        returned_id = outcome["subscriptionId"]
        if not isinstance(returned_id, str) or canonical_uuid(returned_id) != subscription_id:
            raise ValueError("Returned subscription does not match requested scope")
        read_outcome["returnedScopeMatches"] = True
    else:
        if set(outcome) != {"status", "errorCode"}:
            raise ValueError("Failure input must contain only status and errorCode")
        read_outcome["errorCode"] = outcome["errorCode"]

    reference = (HERE / "reference.md").read_text(encoding="utf-8")
    if f"Reference marker: `{REFERENCE_MARKER}`" not in reference:
        raise ValueError("Installed supporting reference marker is missing")

    artifact: dict[str, object] = {
        "schemaVersion": CAPABILITY_VERSION,
        "runId": run_id,
        "selectedSubscription": {
            "identifier": "sha256:" + hashlib.sha256(subscription_id.encode("ascii")).hexdigest(),
            "handling": "sha256-pseudonymized",
        },
        "collectionTimestamp": timestamp_text,
        "capabilityVersion": CAPABILITY_VERSION,
        "readOutcome": read_outcome,
        "dataHandling": {
            "sourceSensitivity": "internal",
            "redactionState": "pseudonymized",
            "rawResponsesPersisted": False,
            "retentionDecision": "prototype-run-only-no-external-publication",
            "omittedSensitiveProperties": [
                "subscriptionName", "tenantId", "tags", "resourcePayloads", "credentials",
            ],
        },
        "supportingAssets": {
            "referenceMarker": REFERENCE_MARKER,
            "schemaSha256": hashlib.sha256((HERE / "feasibility.schema.json").read_bytes()).hexdigest(),
            "runtimeSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
    }
    validate_artifact(artifact)
    return artifact


def write_artifact(artifact: dict[str, object], output_root: Path) -> tuple[Path, str]:
    validate_artifact(artifact)
    run_id = artifact["runId"]
    if not isinstance(run_id, str):
        raise ValueError("Run ID must be a UUID string")
    run_dir = output_root.resolve() / "runs" / canonical_uuid(run_id)
    run_dir.mkdir(parents=True, exist_ok=False)
    path = run_dir / "runtime-feasibility.json"
    data = (json.dumps(artifact, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(data)
    return path, hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--collection-timestamp", required=True)
    parser.add_argument("--outcome-json", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    outcome = json.loads(args.outcome_json)
    if not isinstance(outcome, dict):
        raise ValueError("Outcome input must be an object")
    artifact = build_artifact(
        args.run_id, args.subscription_id, args.collection_timestamp, outcome,
    )
    path, digest = write_artifact(artifact, args.output_root)
    print(json.dumps({"artifactPath": str(path), "sha256": digest, "status": outcome["status"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
