"""Compare retained configuration observations offline without desired-state claims."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from collections import Counter
from pathlib import Path

import configuration_profile as profile
import evidence_bundle as bundle
import evidence_files as ef
import network_capture as capture
from workspace_activity import time_key


VERSION = "1.0.0"
CHECK = "configuration-retained-value-difference"
MAX_RECORDS = 20000
COMMON_ARRAYS = (
    "/properties/privateEndpointConnections",
    "/properties/privateEndpointConnections/*/properties/groupIds",
)
UNORDERED = {
    "storage": (*COMMON_ARRAYS, *("/properties/networkAcls/" + key for key in (
        "ipRules", "ipv6Rules", "virtualNetworkRules", "resourceAccessRules",
    ))),
    "keyvault": (*COMMON_ARRAYS, "/properties/accessPolicies",
                 *("/properties/accessPolicies/*/permissions/" + key for key in ("keys", "secrets", "certificates", "storage")),
                 "/properties/networkAcls/ipRules", "/properties/networkAcls/virtualNetworkRules"),
    "acr": (*COMMON_ARRAYS, "/properties/dataEndpointHostNames",
            "/properties/networkRuleSet/ipRules", "/properties/networkRuleSet/virtualNetworkRules"),
    "ampls": (*COMMON_ARRAYS, "/properties/accessModeSettings/exclusions"),
    "loganalytics": ("/properties/privateLinkScopedResources",),
    "nsp-rules": tuple("/properties/" + key for key in (
        "addressPrefixes", "fullyQualifiedDomainNames", "networkSecurityPerimeters", "subscriptions",
    )),
}
METADATA_NAMES = {
    "provisioningState", "creationTime", "lastEnabledTime", "lastUpdatedTime",
    "quotaNextResetTime", "dataIngestionStatus", "statusOfPrimary", "statusOfSecondary",
    "hasProvisioningIssues", "perimeterGuid", "actionsRequired", "state",
}
POLICY = {
    "checkId": CHECK, "checkVersion": VERSION, "unorderedMembershipArrays": UNORDERED,
    "metadataNames": sorted(METADATA_NAMES), "baseMetadata": ["id", "name", "type", "systemData"],
    "identifierCasing": "absolute-ARM-identifiers-only", "duplicates": "preserved",
    "missingField": "UNKNOWN-not-default-or-removal", "configurationAuthority": "successful-direct-GET",
}


def _canonical(value: object, family: str, path: str = "") -> object:
    if isinstance(value, dict):
        return {key: _canonical(entry, family, path + "/" + key) for key, entry in ef.obj(value).items()}
    if isinstance(value, list):
        values = [_canonical(entry, family, path + "/*") for entry in value]
        return sorted(values, key=lambda entry: json.dumps(entry, sort_keys=True, separators=(",", ":"))) if path in UNORDERED.get(family, ()) else values
    if isinstance(value, str) and re.fullmatch(r"/subscriptions/[0-9a-fA-F-]{36}(?:/[^\\?#%\s]+)*", value, re.IGNORECASE):
        return value.rstrip("/").lower()
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _category(path: str) -> str:
    parts = path.split("/")[1:]
    return "metadata" if parts and (parts[0] in ("id", "name", "type", "systemData")
                                    or any(part in METADATA_NAMES for part in parts)) else "settings"


def _settings_value(value: object, path: str) -> object:
    if isinstance(value, dict):
        return {key: _settings_value(entry, path + "/" + key) for key, entry in ef.obj(value).items()
                if _category(path + "/" + key) != "metadata"}
    if isinstance(value, list):
        return [_settings_value(entry, path + "/*") for entry in value]
    return value


def _snapshot(root: Path, identifier: str) -> ef.Record:
    directory = root / "sources" / identifier
    manifest, documents, manifest_bytes = capture.verified(directory)
    if manifest["profileId"] != capture.PROFILE or manifest["capsuleVersion"] != capture.CAPSULE_VERSION:
        raise ValueError("Comparison requires compatible configuration 0.3.0 capsules")
    if manifest["capsuleId"] != identifier:
        raise ValueError("Comparison source directory/identity mismatch")
    resources: dict[str, ef.Record] = {}
    descriptors = {ef.text(value["name"]): value for value in ef.records(manifest["members"])}
    rows = 0
    for name, page in sorted(documents.items()):
        if name == capture.CONTEXT or name.startswith("attempt-"):
            continue
        operation = ef.text(page["operationId"])
        kind, family, _ = profile.OPS[operation]
        if page["targetId"] is not None and kind == "get":
            target = ef.text(page["targetId"]).lower()
            resource = resources.setdefault(target, {"id": target, "family": family, "direct": [], "observations": [], "getOutcomes": []})
            ef.array(resource["getOutcomes"]).append({"status": page["status"], "httpStatus": page["httpStatus"],
                                                     "errorCode": page["errorCode"], "member": "sources/" + identifier + "/" + name})
        for position, row in enumerate(ef.records(page["rows"]) if page["rows"] is not None else []):
            rows += 1
            configuration = ef.obj(row["configuration"])
            target = ef.text(configuration["id"]).lower()
            resource = resources.setdefault(target, {"id": target, "family": family, "direct": [], "observations": [], "getOutcomes": []})
            reference = {
                "capsuleId": identifier, "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "member": "sources/" + identifier + "/" + name, "memberSha256": descriptors[name]["sha256"],
                "pointer": "/rows/" + str(position) + "/configuration", "operationId": operation,
                "collectionStartedAt": page["startedAtUtc"], "collectionCompletedAt": page["completedAtUtc"],
                "omittedPaths": row["omittedPaths"],
            }
            ef.array(resource["observations"]).append(reference)
            if kind == "get":
                ef.array(resource["direct"]).append({"configuration": configuration, "evidence": reference})
    return {"capsuleId": identifier, "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "manifest": manifest, "resources": resources, "inputRows": rows}


def _selection(resource: ef.Record | None) -> ef.Record:
    if resource is None:
        return {"state": "notObserved", "reason": "notInProvidedSnapshotResults", "evidence": None, "observations": []}
    direct = ef.records(resource["direct"])
    if not direct:
        return {"state": "UNKNOWN", "reason": "noSuccessfulDirectGet", "evidence": None,
                "observations": resource["observations"], "getOutcomes": resource["getOutcomes"]}
    if len({ef.digest(entry["configuration"]) for entry in direct}) != 1:
        return {"state": "UNKNOWN", "reason": "directGetObservationsDisagree", "evidence": None,
                "observations": resource["observations"], "getOutcomes": resource["getOutcomes"]}
    return {"state": "observed", "evidence": direct[-1]["evidence"],
            "observations": resource["observations"], "getOutcomes": resource["getOutcomes"],
            "configuration": direct[-1]["configuration"]}


def _differences(before: object, after: object, family: str, before_omitted: list[str],
                 after_omitted: list[str], path: str = "") -> tuple[list[ef.Record], list[ef.Record], int]:
    for label, omissions in (("before", before_omitted), ("after", after_omitted)):
        if path and any(path == omitted or path.startswith(omitted + "/") for omitted in omissions):
            return [], [{"path": path, "reason": "omittedIn" + label.title()}], 0
    if isinstance(before, dict) and isinstance(after, dict):
        changes: list[ef.Record] = []
        gaps: list[ef.Record] = []
        compared = 0
        left, right = ef.obj(before), ef.obj(after)
        for key in sorted(left.keys() | right.keys()):
            pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in left or key not in right:
                gaps.append({"path": pointer, "reason": "notReturnedBefore" if key not in left else "notReturnedAfter"})
                continue
            selected, missing, count = _differences(left[key], right[key], family, before_omitted, after_omitted, pointer)
            changes.extend(selected)
            gaps.extend(missing)
            compared += count
        return changes, gaps, compared
    gaps = []
    if isinstance(before, list) or isinstance(after, list):
        if any(value.startswith(path + "/") for value in [*before_omitted, *after_omitted]):
            gaps.append({"path": path, "reason": "arrayContainsOmittedFields"})
    if ef.digest(_canonical(before, family, path)) == ef.digest(_canonical(after, family, path)):
        return [], gaps, 1
    category = _category(path)
    if category == "settings" and (
        ef.digest(_canonical(_settings_value(before, path), family, path))
        == ef.digest(_canonical(_settings_value(after, path), family, path))
    ):
        category = "metadata"
    return [{
        "path": path, "category": category, "checkId": CHECK, "checkVersion": VERSION,
        "before": {"state": "observed", "value": before}, "after": {"state": "observed", "value": after},
        "interpretation": "retained-observation-difference-not-defect-or-cause",
    }], gaps, 1


def _document(root: Path, identifier: str, inputs: ef.Record) -> ef.Record:
    inputs = ef.fields(inputs, {"before", "after"})
    ids = {key: ef.text(inputs[key]) for key in ("before", "after")}
    if any(ef.canonical_uuid(value) != value for value in ids.values()) or ids["before"] == ids["after"]:
        raise ValueError("Comparison requires two distinct canonical capsule identities")
    if set(path.name for path in (root / "sources").iterdir()) != set(ids.values()):
        raise ValueError("Comparison source membership differs from before/after selection")
    left, right = (_snapshot(root, ids[key]) for key in ("before", "after"))
    before_manifest, after_manifest = ef.obj(left["manifest"]), ef.obj(right["manifest"])
    scope = {key: ef.obj(before_manifest["scope"])[key] for key in ("tenantId", "subscriptionId")}
    if scope != {key: ef.obj(after_manifest["scope"])[key] for key in scope}:
        raise ValueError("Comparison source tenant/subscription scope differs")
    if time_key(ef.obj(before_manifest["collectionWindow"])["completedAtUtc"]) > time_key(
        ef.obj(after_manifest["collectionWindow"])["startedAtUtc"]
    ):
        raise ValueError("Comparison windows must be chronological and nonoverlapping")
    if ef.integer(left["inputRows"]) + ef.integer(right["inputRows"]) > MAX_RECORDS:
        raise ValueError("Comparison input observation row budget exceeded")
    before_resources, after_resources = ef.obj(left["resources"]), ef.obj(right["resources"])
    resources: list[ef.Record] = []
    total = 0
    for target in sorted(before_resources.keys() | after_resources.keys()):
        earlier = ef.obj(before_resources[target]) if target in before_resources else None
        later = ef.obj(after_resources[target]) if target in after_resources else None
        first, second = _selection(earlier), _selection(later)
        changes: list[ef.Record] = []
        gaps: list[ef.Record] = []
        compared = 0
        status = "UNKNOWN"
        if first["state"] == second["state"] == "observed":
            if earlier is None or later is None or earlier["family"] != later["family"]:
                raise ValueError("Comparable resource families differ")
            first_reference, second_reference = ef.obj(first["evidence"]), ef.obj(second["evidence"])
            if time_key(first_reference["collectionCompletedAt"]) > time_key(second_reference["collectionStartedAt"]):
                raise ValueError("Comparable resource GET windows are not chronological")
            changes, gaps, compared = _differences(
                first["configuration"], second["configuration"], ef.text(earlier["family"]),
                [ef.text(value) for value in ef.array(first_reference["omittedPaths"])],
                [ef.text(value) for value in ef.array(second_reference["omittedPaths"])],
            )
            status = "compared"
        else:
            gaps.append({"path": "", "reason": "successfulComparableGetNotAvailable"})
        total += len(changes) + len(gaps) + compared
        if total > MAX_RECORDS:
            raise ValueError("Comparison derived entry budget exceeded")
        resources.append({
            "resourceId": target, "status": status,
            "visibility": "newlyObserved" if earlier is None else "notObservedLater" if later is None else "observedBoth",
            "before": {key: value for key, value in first.items() if key != "configuration"},
            "after": {key: value for key, value in second.items() if key != "configuration"},
            "differences": changes, "evidenceGaps": gaps, "comparedValuePaths": compared,
        })
    all_differences = [value for resource in resources for value in ef.records(resource["differences"])]
    sources = {label: {key: source[key] for key in ("capsuleId", "manifestSha256", "manifest")}
               for label, source in (("before", left), ("after", right))}
    outcomes = [{
        "side": label, "outcomes": dict(sorted(Counter(
            ef.text(entry["status"]) for entry in ef.records(ef.obj(ef.obj(source["manifest"])["coverage"])["collections"])
        ).items())),
        "unperformedOperations": ef.obj(ef.obj(source["manifest"])["coverage"])["unperformedOperations"],
        "unconfirmedAttempts": ef.obj(ef.obj(source["manifest"])["coverage"])["unconfirmedAttempts"],
    } for label, source in (("before", left), ("after", right))]
    return {
        "comparisonVersion": VERSION, "comparisonId": identifier, "scope": scope, "sources": sources,
        "policy": {**POLICY, "policySha256": ef.digest(POLICY)}, "resources": resources,
        "statistics": {
            "inputCapsules": 2, "inputObservationRows": ef.integer(left["inputRows"]) + ef.integer(right["inputRows"]),
            "resources": len(resources), "comparedResources": sum(resource["status"] == "compared" for resource in resources),
            "unknownResources": sum(resource["status"] == "UNKNOWN" for resource in resources),
            "settingsDifferences": sum(value["category"] == "settings" for value in all_differences),
            "metadataDifferences": sum(value["category"] == "metadata" for value in all_differences),
            "evidenceGaps": sum(len(ef.array(resource["evidenceGaps"])) for resource in resources),
            "newlyObserved": sum(resource["visibility"] == "newlyObserved" for resource in resources),
            "notObservedLater": sum(resource["visibility"] == "notObservedLater" for resource in resources),
        },
        "coverage": {"assurance": "reviewed-direct-observations-not-whole-resource-equality",
                     "missingValues": "UNKNOWN-not-default-or-removal", "omissions": "retained-with-original-evidence",
                     "inventory": "visibility-not-authoritative-creation-or-deletion", "sourceOutcomes": outcomes},
        "assessmentPerformed": False, "desiredStateComparison": "notPerformed", "causalConclusions": "notGenerated",
    }


def _cell(value: object) -> str:
    return html.escape(str(value), quote=True).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _markdown(document: ef.Record) -> bytes:
    lines = [
        "# Configuration comparison", "",
        "An observed difference is not a defect, desired-state violation, successful change or cause.", "",
        "Only compatible retained direct GET observations are compared. Missing/denied/omitted evidence is UNKNOWN.",
        "Resource visibility changes are not proof of creation or deletion. Array membership comparison preserves duplicates.", "",
        "## Summary", "", "| Measure | Count |", "|---|---|",
    ]
    for key, value in ef.obj(document["statistics"]).items():
        lines.append("| " + _cell(key) + " | " + str(value) + " |")
    lines.extend(("", "## Source evidence", "", "| Side | Collection window | Source capsule |", "|---|---|---|"))
    for label, source in ef.obj(document["sources"]).items():
        value = ef.obj(source)
        window = ef.obj(ef.obj(value["manifest"])["collectionWindow"])
        capsule = ef.text(value["capsuleId"])
        lines.append("| " + label + " | " + _cell(ef.text(window["startedAtUtc"]) + " to " + ef.text(window["completedAtUtc"]))
                     + " | [manifest](sources/" + capsule + "/manifest.json) |")
    lines.extend(("", "| Side | Collection outcomes | Unperformed operations | Unconfirmed attempts |",
                  "|---|---|---|---|"))
    for coverage in ef.records(ef.obj(document["coverage"])["sourceOutcomes"]):
        lines.append("| " + " | ".join((
            _cell(coverage["side"]), _cell(", ".join(key + ": " + str(value)
                                                     for key, value in ef.obj(coverage["outcomes"]).items())),
            str(len(ef.array(coverage["unperformedOperations"]))), str(len(ef.array(coverage["unconfirmedAttempts"]))),
        )) + " |")
    lines.extend(("", "## Resource comparison", "", "| Resource | Status | Visibility | Settings | Metadata | Evidence gaps | Evidence |",
                  "|---|---|---|---|---|---|---|"))
    for resource in ef.records(document["resources"]):
        changes = ef.records(resource["differences"])
        links = []
        for side in ("before", "after"):
            selected = ef.obj(resource[side])
            if selected["evidence"] is not None:
                links.append("[" + side + "](" + ef.text(ef.obj(selected["evidence"])["member"]) + ")")
        lines.append("| " + " | ".join((
            _cell(resource["resourceId"]), _cell(resource["status"]), _cell(resource["visibility"]),
            str(sum(value["category"] == "settings" for value in changes)),
            str(sum(value["category"] == "metadata" for value in changes)),
            str(len(ef.array(resource["evidenceGaps"]))), ", ".join(links),
        )) + " |")
    lines.extend(("", "## Observed differences", "", "Exact values remain in private JSON and original source evidence.", "",
                  "| Resource | Retained path | Category | Rule/version |", "|---|---|---|---|"))
    for resource in ef.records(document["resources"]):
        for difference in ef.records(resource["differences"]):
            lines.append("| " + " | ".join(_cell(value) for value in (
                resource["resourceId"], difference["path"], difference["category"],
                ef.text(difference["checkId"]) + "/" + ef.text(difference["checkVersion"]),
            )) + " |")
    lines.extend(("", "## Evidence gaps", "", "| Resource | Path | Reason |", "|---|---|---|"))
    for resource in ef.records(document["resources"]):
        for gap in ef.records(resource["evidenceGaps"]):
            lines.append("| " + " | ".join(_cell(value) for value in (resource["resourceId"], gap["path"], gap["reason"])) + " |")
    lines.extend(("", "Raw omissions, failures and collection coverage remain in the unchanged source manifests/members.", ""))
    return "\n".join(lines).encode()


def _views(root: Path, identifier: str, inputs: ef.Record) -> dict[str, bytes]:
    document = _document(root, identifier, inputs)
    return {"comparison.json": ef.encoded(document), "comparison.md": _markdown(document)}


def build(before: Path, after: Path, comparison_id: str, output_root: Path) -> Path:
    selected = {}
    for label, directory in (("before", before), ("after", after)):
        manifest = capture.verify(directory)
        selected[label] = manifest["capsuleId"]
    return bundle.build([before, after], comparison_id, output_root, "comparison", _views, selected)


def verify(directory: Path) -> ef.Record:
    return bundle.verify(directory, "comparison", _views)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("build")
    for name in ("before", "after", "output-root"):
        create.add_argument("--" + name, required=True, type=Path)
    create.add_argument("--comparison-id", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--comparison", type=Path, required=True)
    args = parser.parse_args()
    try:
        directory = build(args.before, args.after, args.comparison_id, args.output_root) if args.command == "build" else args.comparison
        manifest = verify(directory)
        print(ef.encoded({"status": "verified-offline-comparison", "comparison": str(directory),
                          "comparisonId": manifest["comparisonId"], "azureReads": 0, "assessmentPerformed": False}).decode().strip())
        return 0
    except (ValueError, OSError) as error:
        parser.exit(2, "Comparison operation failed: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
