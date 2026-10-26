"""Development-only sealing and offline replay of reviewed selected inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.parse
from datetime import datetime
from pathlib import Path

import network_health_sre as bridge


nh = bridge.nh
VERSION = "0.1.0"
PROFILE = "selected-inventory"
PROFILE_VERSION = "1.0.0"
REPLAY_VERSION = "1.0.0"
MAX_MEMBER_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ROWS = 1000
MANIFEST = "manifest.json"
INDEX = "evidence-index.json"
INDEX_FIELDS = {
    "recordedAtUtc", "sensitivity", "retention", "identifierHandling",
    "assessmentClassification", "scopeSubscriptionId", "controlReadCoverage", "artifacts",
}
OPERATIONS = {
    "storage-arm.json": ("Microsoft.Storage/storageAccounts", "2023-05-01"),
    "keyvault-arm.json": ("Microsoft.KeyVault/vaults", "2023-07-01"),
    "keyvault-arm-page2.json": ("Microsoft.KeyVault/vaults", "2023-07-01"),
    "acr-arm.json": ("Microsoft.ContainerRegistry/registries", "2023-07-01"),
    "loganalytics-arm.json": ("Microsoft.OperationalInsights/workspaces", "2023-09-01"),
    "nsp-root-arm.json": ("Microsoft.Network/networkSecurityPerimeters", "2024-07-01"),
    "ampls-root-arm.json": ("Microsoft.Insights/privateLinkScopes", "2021-07-01-preview"),
}
SOURCE_NAMES = {
    *OPERATIONS, "arg-inventory.json", "keyvault-continuation-failed-attempt.json",
    "inventory-summary.json",
}
MEMBER_NAMES = SOURCE_NAMES | {INDEX}
EVENT_SOURCES = ("administrativeActivityLog", "resourceChanges", "resourceHealth", "serviceHealth", "historicalExports")
ASSURANCE = {"sourceAuthentication": "notVerified", "storageAccessControls": "operatorManaged", "encryption": "notVerified"}


def fields(value: object, required: set[str], optional: set[str] | None = None) -> nh.Record:
    record = nh.obj(value)
    if not required <= set(record) or set(record) - required - (optional or set()):
        raise ValueError("Unsupported or missing selected-evidence fields")
    return record


def timestamp(value: object) -> str:
    text = nh.text(value)
    if not text.endswith("Z"):
        raise ValueError("Evidence timestamp must be UTC Z")
    datetime.fromisoformat(text.replace("Z", "+00:00"))
    return text


def text_fields(record: nh.Record, names: set[str], nullable: bool = False) -> None:
    for name in names & set(record):
        if record[name] is not None or not nullable:
            nh.text(record[name])


def normal_path(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or (
        os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError("Evidence links and reparse points are not permitted")


def private_root(path: Path) -> Path:
    normal_path(path)
    resolved = path.resolve(strict=True)
    if not resolved.is_dir() or resolved.is_relative_to(bridge.ROOT.resolve()):
        raise ValueError("Evidence output must be an existing directory outside the repository")
    return resolved


def read_member(path: Path, limit: int = MAX_MEMBER_BYTES) -> bytes:
    normal_path(path)
    if not path.is_file():
        raise ValueError("Evidence member must be a regular file")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if not content or len(content) > limit:
        raise ValueError("Evidence member exceeds its byte budget or is empty")
    return content


def unique_fields(pairs: list[tuple[str, object]]) -> nh.Record:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field in capsule evidence")
        result[key] = value
    return result


def invalid_constant(value: str) -> object:
    raise ValueError("Nonfinite JSON number in capsule evidence")


def decode(content: bytes) -> nh.Record:
    return nh.obj(json.loads(content.decode("utf-8"), object_pairs_hook=unique_fields, parse_constant=invalid_constant))


def descriptor(name: str, content: bytes) -> nh.Record:
    return {"name": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def descriptors(value: object, names: set[str]) -> dict[str, nh.Record]:
    result = {}
    for item in nh.records(value):
        item = fields(item, {"name", "bytes", "sha256"})
        name = nh.text(item["name"])
        if name not in names or name in result:
            raise ValueError("Unsafe, duplicate or unsupported evidence member")
        if not 0 < nh.integer(item["bytes"]) <= MAX_MEMBER_BYTES:
            raise ValueError("Evidence member byte budget exceeded")
        if re.fullmatch(r"[0-9a-f]{64}", nh.text(item["sha256"])) is None:
            raise ValueError("Invalid evidence member hash")
        result[name] = item
    if set(result) != names:
        raise ValueError("Missing evidence members for supported profile")
    return result


def read_verified_members(directory: Path, expected: dict[str, nh.Record], base_bytes: int) -> dict[str, bytes]:
    if base_bytes + sum(nh.integer(item["bytes"]) for item in expected.values()) > MAX_TOTAL_BYTES:
        raise ValueError("Capsule total byte budget exceeded")
    payloads = {}
    for name, item in expected.items():
        content = read_member(directory / name)
        if descriptor(name, content) != item:
            raise ValueError("Evidence member integrity mismatch")
        payloads[name] = content
    return payloads


def scoped_id(value: object, subscription: str, resource_type: str) -> str:
    identifier = nh.text(value)
    if not identifier.lower().startswith("/subscriptions/" + subscription + "/") or any(
        character in identifier for character in ("\\", "?", "#")
    ) or any(part in ("", ".", "..") for part in identifier.split("/")[1:]):
        raise ValueError("Resource identifier exceeds capsule scope")
    parts = identifier.lower().split("/")
    if (
        len(parts) != 9 or parts[3] != "resourcegroups" or parts[5] != "providers"
        or "/".join(parts[6:8]) != resource_type.lower()
    ):
        raise ValueError("Resource identifier/type mismatch")
    return identifier.lower()


def request_url(value: object, subscription: str, operation: tuple[str, str]) -> str:
    url = nh.text(value)
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    resource_type, version = operation
    if (
        parsed.scheme != "https" or parsed.hostname != "management.azure.com"
        or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment
        or parsed.path.rstrip("/").lower() != f"/subscriptions/{subscription}/providers/{resource_type}".lower()
        or any(key not in ("api-version", "$skiptoken") for key, _ in query)
        or len({key for key, _ in query}) != len(query)
        or dict(query).get("api-version") != version
    ):
        raise ValueError("Evidence request exceeds approved ARM scope/API")
    return url


def same_request(left: object, right: object) -> bool:
    first, second = (urllib.parse.urlsplit(nh.text(value)) for value in (left, right))
    return (
        first.scheme == second.scheme and first.netloc.lower() == second.netloc.lower()
        and first.path.lower() == second.path.lower()
        and sorted(urllib.parse.parse_qsl(first.query)) == sorted(urllib.parse.parse_qsl(second.query))
    )


def rule_set(value: object, storage: bool, registry: bool = False) -> None:
    if value is None:
        return
    allowed = {"defaultAction", "ipRules"}
    if not registry:
        allowed |= {"bypass", "virtualNetworkRules"}
    if storage:
        allowed |= {"ipv6Rules", "resourceAccessRules"}
    record = fields(value, set(), allowed)
    for key, entry in record.items():
        if key in ("bypass", "defaultAction"):
            if entry is not None:
                nh.text(entry)
        elif entry is not None:
            rows = nh.records(entry)
            if len(rows) > MAX_ROWS:
                raise ValueError("Rule rows exceed profile budget")
            allowed_row = (
                {"resourceId", "tenantId"} if key == "resourceAccessRules"
                else {"id", "action", "state", "ignoreMissingVnetServiceEndpoint"} if key == "virtualNetworkRules"
                else {"value", "action", "iPAddressOrRange"}
            )
            for row in rows:
                fields(row, set(), allowed_row)
                for field, value in row.items():
                    if field == "ignoreMissingVnetServiceEndpoint":
                        if value is not None and not isinstance(value, bool):
                            raise ValueError("Invalid selected rule boolean")
                    elif value is not None:
                        nh.text(value)


def validate_profile(documents: dict[str, nh.Record], subscription: str) -> None:
    index = fields(documents[INDEX], INDEX_FIELDS)
    timestamp(index["recordedAtUtc"])
    text_fields(index, {"sensitivity", "retention", "identifierHandling", "assessmentClassification", "controlReadCoverage"})
    if nh.canonical_uuid(nh.text(index["scopeSubscriptionId"])) != subscription:
        raise ValueError("Evidence index scope mismatch")
    for name, operation in OPERATIONS.items():
        record = fields(documents[name], {
            "source", "subscriptionId", "requestUrl", "startedAtUtc", "completedAtUtc",
            "status", "retention", "selected",
        }, {"tenantId", "projection", "page", "errorCode"})
        text_fields(record, {"source", "retention", "projection", "errorCode"})
        if "tenantId" in record:
            nh.canonical_uuid(nh.text(record["tenantId"]))
        if "page" in record and nh.integer(record["page"]) != 2:
            raise ValueError("Unsupported selected continuation page")
        if nh.canonical_uuid(nh.text(record["subscriptionId"])) != subscription:
            raise ValueError("Selected ARM evidence scope mismatch")
        request_url(record["requestUrl"], subscription, operation)
        start, end = timestamp(record["startedAtUtc"]), timestamp(record["completedAtUtc"])
        if datetime.fromisoformat(start.replace("Z", "+00:00")) > datetime.fromisoformat(end.replace("Z", "+00:00")):
            raise ValueError("Evidence completion precedes collection")
        status = nh.text(record["status"])
        if status not in ("succeeded", "partial", "permissionDenied", "failed", "unavailable", "notCollected", "unsupported"):
            raise ValueError("Unsupported selected collection status")
        if status not in ("succeeded", "partial"):
            if record["selected"] is not None:
                raise ValueError("Failed collection cannot claim selected results")
            continue
        selected = fields(record["selected"], {"items", "nextLink"})
        if bool(selected["nextLink"]) != (status == "partial"):
            raise ValueError("Collection status and continuation disagree")
        if selected["nextLink"] is not None:
            request_url(selected["nextLink"], subscription, operation)
        rows = nh.records(selected["items"])
        if len(rows) > MAX_ROWS:
            raise ValueError("Selected resource rows exceed profile budget")
        seen = set()
        for row in rows:
            if name in ("nsp-root-arm.json", "ampls-root-arm.json"):
                fields(row, {"id", "name", "location"})
                text_fields(row, {"name", "location"}, True)
            else:
                configuration = (
                    {"publicNetworkAccessForIngestion", "publicNetworkAccessForQuery", "privateLinkScopedResources"}
                    if name == "loganalytics-arm.json" else
                    {"publicNetworkAccess", "networkRuleSet", "networkRuleBypassOptions"}
                    if name == "acr-arm.json" else {"publicNetworkAccess", "networkAcls"}
                )
                fields(row, {"id", "type", *configuration})
                text_fields(row, configuration - {"networkAcls", "networkRuleSet", "privateLinkScopedResources"}, True)
                if nh.text(row["type"]).lower() != operation[0].lower():
                    raise ValueError("Selected resource type mismatch")
                if "networkAcls" in row:
                    rule_set(row["networkAcls"], name == "storage-arm.json")
                if "networkRuleSet" in row:
                    rule_set(row["networkRuleSet"], False, True)
                if name == "loganalytics-arm.json" and row["privateLinkScopedResources"] is not None:
                    for linked in nh.records(row["privateLinkScopedResources"]):
                        fields(linked, set(), {"resourceId", "scopeId"})
                        text_fields(linked, {"resourceId", "scopeId"}, True)
            identifier = scoped_id(row["id"], subscription, operation[0])
            if identifier in seen:
                raise ValueError("Duplicate selected resource within page")
            seen.add(identifier)
    first_page, second_page = documents["keyvault-arm.json"], documents["keyvault-arm-page2.json"]
    if second_page.get("page") != 2:
        raise ValueError("Missing selected continuation page number")
    if first_page["selected"] is not None:
        next_link = nh.obj(first_page["selected"])["nextLink"]
        if next_link is None or not same_request(next_link, second_page["requestUrl"]):
            raise ValueError("Selected continuation does not match saved next link")
    elif second_page["selected"] is not None:
        raise ValueError("Selected continuation has no observed parent page")
    arg = fields(documents["arg-inventory.json"], {
        "source", "recordedAtUtc", "scopeSubscriptionId", "retention", "coverage", "response",
    })
    timestamp(arg["recordedAtUtc"])
    text_fields(arg, {"source", "retention", "coverage"})
    if nh.canonical_uuid(nh.text(arg["scopeSubscriptionId"])) != subscription:
        raise ValueError("Indexed evidence scope mismatch")
    response = fields(arg["response"], {"isSuccessful", "results", "rowCount", "totalRecords", "resultTruncated", "executedQuery"},
                      {"skipToken"})
    if response["isSuccessful"] is not True:
        raise ValueError("Supported inventory profile requires a successful indexed read")
    text_fields(response, {"executedQuery", "skipToken"}, True)
    if not isinstance(response["resultTruncated"], bool):
        raise ValueError("Invalid indexed truncation flag")
    results = fields(response["results"], {"data", "facets"}, {"$id"})
    if nh.array(results["facets"]):
        raise ValueError("Unreviewed indexed facets are not retained")
    rows = nh.records(results["data"])
    if len(rows) > MAX_ROWS or nh.integer(response["rowCount"]) != len(rows) or nh.integer(response["totalRecords"]) < len(rows):
        raise ValueError("Indexed row coverage mismatch")
    indexed_ids = set()
    for row in rows:
        fields(row, {"id", "subscriptionId", "type", "name", "resourceGroup", "location"})
        text_fields(row, {"type", "name", "resourceGroup", "location"}, True)
        identifier = scoped_id(row["id"], subscription, nh.text(row["type"]))
        if identifier in indexed_ids:
            raise ValueError("Duplicate indexed resource identity")
        indexed_ids.add(identifier)
        if nh.canonical_uuid(nh.text(row["subscriptionId"])) != subscription:
            raise ValueError("Indexed resource scope mismatch")
    failure = fields(documents["keyvault-continuation-failed-attempt.json"], {
        "source", "recordedAtUtc", "requestUrl", "status", "code", "observedError",
        "azureReadCompletion", "resourceMutationAttempted",
    })
    timestamp(failure["recordedAtUtc"])
    text_fields(failure, {"source", "status", "code", "observedError", "azureReadCompletion"})
    request_url(failure["requestUrl"], subscription, OPERATIONS["keyvault-arm.json"])
    if not same_request(failure["requestUrl"], second_page["requestUrl"]):
        raise ValueError("Failed continuation attempt differs from selected retry")
    if failure["status"] != "clientInvocationFailed" or failure["resourceMutationAttempted"] is not False:
        raise ValueError("Unsupported failed-attempt evidence")
    summary = fields(documents["inventory-summary.json"], {
        "recordedAtUtc", "source", "subscriptionId", "families", "indexedAndDirectIdSetsMatch",
        "indexedAndDirectVisibleResourceCount", "coverage", "classificationPerformed",
        "sreAgentCollectorExecuted", "failedAttemptRetained",
    })
    timestamp(summary["recordedAtUtc"])
    text_fields(summary, {"source", "coverage", "failedAttemptRetained"})
    if nh.canonical_uuid(nh.text(summary["subscriptionId"])) != subscription or summary["classificationPerformed"] is not False:
        raise ValueError("Inventory summary scope/classification mismatch")
    if not isinstance(summary["indexedAndDirectIdSetsMatch"], bool) or not isinstance(summary["sreAgentCollectorExecuted"], bool):
        raise ValueError("Invalid inventory summary flag")
    if nh.integer(summary["indexedAndDirectVisibleResourceCount"]) < 0:
        raise ValueError("Invalid inventory summary count")
    for family in nh.records(summary["families"]):
        fields(family, {"family", "visibleResourceCount", "retainedPages", "terminal", "observedModes"})
        label = nh.text(family["family"])
        if label not in ("storage", "keyvault", "acr", "loganalytics"):
            raise ValueError("Unsupported inventory summary family")
        if nh.integer(family["visibleResourceCount"]) < 0 or nh.integer(family["retainedPages"]) < 1 or not isinstance(family["terminal"], bool):
            raise ValueError("Invalid inventory family coverage")
        for mode in nh.records(family["observedModes"]):
            names = {"ingestion", "query"} if label == "loganalytics" else {"publicNetworkAccess"}
            fields(mode, names | {"count"})
            text_fields(mode, names, True)
            if nh.integer(mode["count"]) < 0:
                raise ValueError("Invalid inventory mode count")


def coverage(documents: dict[str, nh.Record]) -> nh.Record:
    collections = []
    for name, _ in sorted(OPERATIONS.items()):
        record = documents[name]
        selected = record["selected"]
        collections.append({
            "member": name, "source": record["source"], "status": record["status"],
            "startedAtUtc": record["startedAtUtc"], "completedAtUtc": record["completedAtUtc"],
            "requestUrl": record["requestUrl"],
            "returnedRows": None if selected is None else len(nh.array(nh.obj(selected)["items"])),
            "nextLink": None if selected is None else nh.obj(selected)["nextLink"],
        })
    return {
        "collections": collections,
        "indexedEvidence": {"member": "arg-inventory.json", "recordedAtUtc": documents["arg-inventory.json"]["recordedAtUtc"],
                            "responseCoverage": {key: documents["arg-inventory.json"]["response"][key]
                                                 for key in ("rowCount", "totalRecords", "resultTruncated")}},
        "failedAttempts": ["keyvault-continuation-failed-attempt.json"],
        "eventSources": [{"source": source, "status": "notCollected", "events": None} for source in EVENT_SOURCES],
        "boundary": "selected-visible-scope-not-global-or-permission-wide-completeness",
    }


def source_members(source: Path) -> tuple[dict[str, bytes], dict[str, nh.Record], str]:
    normal_path(source)
    if set(path.name for path in source.iterdir()) != MEMBER_NAMES:
        raise ValueError("Missing or extra source profile members")
    payloads = {INDEX: read_member(source / INDEX)}
    index = fields(decode(payloads[INDEX]), INDEX_FIELDS)
    expected = descriptors(index["artifacts"], SOURCE_NAMES)
    payloads.update(read_verified_members(source, expected, len(payloads[INDEX])))
    documents = {name: decode(content) for name, content in payloads.items()}
    subscription = nh.canonical_uuid(nh.text(index["scopeSubscriptionId"]))
    validate_profile(documents, subscription)
    return payloads, documents, subscription


def verified(directory: Path) -> tuple[nh.Record, dict[str, nh.Record], bytes]:
    directory = private_root(directory)
    manifest_bytes = read_member(directory / MANIFEST, MAX_MANIFEST_BYTES)
    manifest = fields(decode(manifest_bytes), {
        "capsuleVersion", "capsuleId", "profileId", "profileVersion", "scopeSubscriptionId",
        "sealedAtUtc", "members", "coverage", "assurance",
    })
    native = manifest["profileId"] == "native-configuration-snapshot"
    if native:
        import network_health_snapshot as snapshot
        if (manifest["capsuleVersion"], manifest["profileId"], manifest["profileVersion"]) != (
            snapshot.CAPSULE_VERSION, snapshot.PROFILE, snapshot.PROFILE_VERSION,
        ):
            raise ValueError("Unsupported native capsule format/profile version")
        expected_names = snapshot.names({"artifacts": manifest["members"]})
    elif manifest["capsuleVersion"] != VERSION or manifest["profileId"] != PROFILE or manifest["profileVersion"] != PROFILE_VERSION:
        raise ValueError("Unsupported capsule format/profile version")
    else:
        expected_names = MEMBER_NAMES
    nh.canonical_uuid(nh.text(manifest["capsuleId"]))
    subscription = nh.canonical_uuid(nh.text(manifest["scopeSubscriptionId"]))
    timestamp(manifest["sealedAtUtc"])
    if manifest["assurance"] != ASSURANCE:
        raise ValueError("Unsupported capsule assurance claim")
    expected = descriptors(manifest["members"], expected_names)
    if set(path.name for path in directory.iterdir()) != expected_names | {MANIFEST}:
        raise ValueError("Missing or extra capsule members")
    payloads = read_verified_members(directory, expected, len(manifest_bytes))
    documents = {name: decode(content) for name, content in payloads.items()}
    if native:
        snapshot.validate_documents(documents, subscription)
        source_names = expected_names - {snapshot.INDEX}
        source_index = descriptors(documents[snapshot.INDEX]["artifacts"], source_names)
        selected_coverage = snapshot.coverage(documents)
    else:
        source_names = SOURCE_NAMES
        source_index = descriptors(fields(documents[INDEX], INDEX_FIELDS)["artifacts"], source_names)
        validate_profile(documents, subscription)
        selected_coverage = coverage(documents)
    if any(source_index[name] != expected[name] for name in source_names):
        raise ValueError("Capsule/source-index binding mismatch")
    if manifest["coverage"] != selected_coverage:
        raise ValueError("Capsule coverage bindings differ from retained evidence")
    return manifest, documents, manifest_bytes


def verify(directory: Path) -> nh.Record:
    return verified(directory)[0]


def seal(source: Path, output_root: Path, capsule_id: str) -> Path:
    capsule_id = nh.canonical_uuid(capsule_id)
    output_root = private_root(output_root)
    source = source.absolute()
    if output_root == source.resolve() or output_root.is_relative_to(source.resolve()):
        raise ValueError("Capsule output cannot modify source evidence")
    if (source / "capture-index.json").exists():
        import network_health_snapshot as snapshot
        payloads, documents, subscription = snapshot.source_members(source)
        version, profile, profile_version = snapshot.CAPSULE_VERSION, snapshot.PROFILE, snapshot.PROFILE_VERSION
        selected_coverage = snapshot.coverage(documents)
    else:
        payloads, documents, subscription = source_members(source)
        version, profile, profile_version = VERSION, PROFILE, PROFILE_VERSION
        selected_coverage = coverage(documents)
    manifest = {
        "capsuleVersion": version, "capsuleId": capsule_id, "profileId": profile,
        "profileVersion": profile_version, "scopeSubscriptionId": subscription,
        "sealedAtUtc": nh.utc_now(), "members": [descriptor(name, payloads[name]) for name in sorted(payloads)],
        "coverage": selected_coverage,
        "assurance": dict(ASSURANCE),
    }
    manifest_bytes = nh.encoded(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES or len(manifest_bytes) + sum(map(len, payloads.values())) > MAX_TOTAL_BYTES:
        raise ValueError("Capsule manifest/total byte budget exceeded")
    directory = output_root / capsule_id
    if os.path.lexists(directory):
        raise FileExistsError("Capsule destination already exists")
    staging = Path(tempfile.mkdtemp(prefix="." + capsule_id + ".", dir=output_root))
    published = False
    try:
        for name, content in {**payloads, MANIFEST: manifest_bytes}.items():
            nh.immutable_file(staging / name, content)
        verify(staging)
        if os.path.lexists(directory):
            raise FileExistsError("Capsule destination already exists")
        staging.rename(directory)
        published = True
    finally:
        if not published:
            for name in set(payloads) | {MANIFEST}:
                (staging / name).unlink(missing_ok=True)
            staging.rmdir()
    return directory


def replay(directory: Path) -> nh.Record:
    manifest, documents, manifest_bytes = verified(directory)
    if manifest["profileId"] == "native-configuration-snapshot":
        import network_health_snapshot as snapshot
        return {
            "replayVersion": REPLAY_VERSION, "capsuleId": manifest["capsuleId"],
            "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "profileId": manifest["profileId"], "profileVersion": manifest["profileVersion"],
            "scopeSubscriptionId": manifest["scopeSubscriptionId"],
            "resources": snapshot.replay_resources(documents), "coverage": manifest["coverage"],
            "eventSources": nh.obj(manifest["coverage"])["eventSources"], "assessmentPerformed": False,
        }
    resources: dict[str, nh.Record] = {}
    for position, row in enumerate(nh.records(documents["arg-inventory.json"]["response"]["results"]["data"])):
        identifier = nh.text(row["id"]).lower()
        resources[identifier] = {
            "id": identifier, "type": nh.text(row["type"]).lower(),
            "observations": [{
                "member": "arg-inventory.json", "pointer": f"/response/results/data/{position}",
                "recordedAtUtc": documents["arg-inventory.json"]["recordedAtUtc"], "configuration": row,
            }],
        }
    for name, operation in sorted(OPERATIONS.items()):
        record = documents[name]
        if record["selected"] is None:
            continue
        for position, row in enumerate(nh.records(nh.obj(record["selected"])["items"])):
            identifier = nh.text(row["id"]).lower()
            resource = resources.setdefault(identifier, {"id": identifier, "type": operation[0].lower(), "observations": []})
            nh.array(resource["observations"]).append({
                "member": name, "pointer": f"/selected/items/{position}",
                "source": record["source"], "requestUrl": record["requestUrl"],
                "startedAtUtc": record["startedAtUtc"], "completedAtUtc": record["completedAtUtc"],
                "configuration": {key: value for key, value in row.items() if key not in ("id", "type")},
            })
    return {
        "replayVersion": REPLAY_VERSION, "capsuleId": manifest["capsuleId"],
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "profileId": manifest["profileId"], "profileVersion": manifest["profileVersion"],
        "scopeSubscriptionId": manifest["scopeSubscriptionId"],
        "resources": [resources[key] for key in sorted(resources)],
        "coverage": manifest["coverage"], "eventSources": manifest["coverage"]["eventSources"],
        "assessmentPerformed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("seal")
    create.add_argument("--source", required=True, type=Path)
    create.add_argument("--output-root", required=True, type=Path)
    create.add_argument("--capsule-id", required=True)
    for command in ("verify", "replay"):
        child = commands.add_parser(command)
        child.add_argument("--capsule", required=True, type=Path)
        if command == "replay":
            child.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "seal":
            directory = seal(args.source, args.output_root, args.capsule_id)
            result = {"capsule": str(directory), "status": "sealed", "capsuleVersion": verify(directory)["capsuleVersion"]}
        elif args.command == "verify":
            manifest = verify(args.capsule)
            result = {"capsuleId": manifest["capsuleId"], "status": "verified",
                      "members": len(nh.array(manifest["members"])), "sourceAuthentication": "notVerified"}
        else:
            parent = private_root(args.output.parent)
            output = parent / args.output.name
            if output.is_relative_to(args.capsule.resolve()) or os.path.lexists(output):
                raise ValueError("Replay output must be new and outside the immutable capsule")
            content = nh.encoded(replay(args.capsule))
            nh.immutable_file(output, content)
            result = {"output": str(output), "sha256": hashlib.sha256(content).hexdigest(),
                      "processedAtUtc": nh.utc_now(), "assessmentPerformed": False}
    except (ValueError, OSError) as error:
        parser.exit(2, "Capsule operation failed: " + str(error) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
