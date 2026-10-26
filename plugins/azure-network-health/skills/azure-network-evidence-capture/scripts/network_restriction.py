"""Offline technical source-restriction assessment; no Azure or credential calls."""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
from collections import Counter
from pathlib import Path

import configuration_profile as profile
import evidence_bundle as bundle
import evidence_files as ef
import network_capture as capture


VERSION = "1.0.0"
ADDRESS_CHECK = "NET-SOURCE-ADDRESS-001"
RESTRICTION_CHECK = "NET-SOURCE-RESTRICTION-001"
ALTERNATIVE_CHECK = "NET-SOURCE-ALTERNATIVE-001"
FAMILIES = ("storage", "keyvault", "acr", "loganalytics")
# IANA IPv4 Special-Purpose registry facts, inspected 2026-10-19; multicast is RFC 1112.
NON_PUBLIC_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.2/32",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
)
GLOBAL_EXCEPTIONS_V4 = ("192.0.0.9/32", "192.0.0.10/32")
INDETERMINATE_V4 = ("192.88.99.0/24",)
Interval = tuple[int, int]
MAX_OBSERVATIONS = 20000
GUIDANCE = {
    "storageFirewall": "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security",
    "storageLimitations": "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security-limitations",
    "storageIpRules": "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security-ip-address-range",
    "storagePerimeter": "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security-perimeter",
    "keyVault": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    "acrFirewall": "https://learn.microsoft.com/en-us/azure/container-registry/container-registry-access-selected-networks",
    "acrTrustedServices": "https://learn.microsoft.com/en-us/azure/container-registry/allow-access-trusted-services",
    "monitorPerimeter": "https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/network-security-perimeter",
    "monitorPrivateLink": "https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/private-link-design",
    "perimeterConcepts": "https://learn.microsoft.com/en-us/azure/private-link/network-security-perimeter-concepts",
    "perimeterTransition": "https://learn.microsoft.com/en-us/azure/private-link/network-security-perimeter-transition",
    "ianaIpv4": "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv",
    "ipv4Multicast": "https://www.rfc-editor.org/rfc/rfc1112.html",
}
POLICY = {
    "policyId": "technical-public-source-restriction", "policyVersion": VERSION,
    "serviceFamilies": list(FAMILIES), "sourceAuthority": "successful-consistent-direct-GET-only",
    "defaultValuesAssumed": False, "arbitraryRangeSizeThreshold": None, "ownerAllowlistCompliance": "not-assessed",
    "positiveNspAmplsQualification": "gated-not-live-validated",
    "nspServiceSupport": {"storage": "requires-qualification", "keyvault": "requires-qualification",
                         "loganalytics": "requires-qualification", "acr": "not-in-inspected-supported-resource-list"},
    "contradictoryAcrPerimeterAssociation": "UNKNOWN-not-supported-enforcement",
    "ipv4NonPublic": list(NON_PUBLIC_V4), "ipv4GlobalExceptions": list(GLOBAL_EXCEPTIONS_V4),
    "ipv4Indeterminate": list(INDETERMINATE_V4), "addressFactsInspectedAt": "2026-10-19",
    "ipv6": "whole-family-mathematics-only; no positive service selector qualification",
    "checks": [{"checkId": value, "checkVersion": VERSION} for value in (
        RESTRICTION_CHECK, ADDRESS_CHECK, ALTERNATIVE_CHECK,
    )],
    "severity": "unassigned-without-contextual-impact-evidence",
    "priority": "recommended-next-action; UNKNOWN-evidenceCollection; NOT_RESTRICTED-contextValidation",
}


def _merge(values: list[Interval]) -> list[Interval]:
    result: list[Interval] = []
    for first, last in sorted(values):
        if result and first <= result[-1][1] + 1:
            result[-1] = result[-1][0], max(last, result[-1][1])
        else:
            result.append((first, last))
    return result


def _subtract(values: list[Interval], removed: list[Interval]) -> list[Interval]:
    result = []
    exclusions = _merge(removed)
    for first, last in values:
        for lower, upper in exclusions:
            if upper < first:
                continue
            if lower > last:
                break
            if first < lower:
                result.append((first, lower - 1))
            first = max(first, upper + 1)
            if first > last:
                break
        if first <= last:
            result.append((first, last))
    return result


def _interval(value: str) -> Interval:
    network = ipaddress.ip_network(value)
    return int(network.network_address), int(network.broadcast_address)


def address_coverage(values: list[object]) -> ef.Record:
    """Assess allow-selector union, retaining malformed and indeterminate evidence."""
    ef.array(values)
    if len(values) > ef.MAX_ROWS:
        raise ValueError("Address-selector count exceeds the reviewed row budget")
    intervals: dict[int, list[Interval]] = {4: [], 6: []}
    errors: list[ef.Record] = []
    for position, value in enumerate(values):
        if not isinstance(value, str) or value != value.strip() or "%" in value:
            errors.append({"index": position, "reason": "AddressSelectorNotPlainText"})
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            errors.append({"index": position, "reason": "UnsupportedOrMalformedAddressSelector"})
            continue
        intervals[network.version].append((int(network.network_address), int(network.broadcast_address)))
    upper = _merge(
        _subtract([(0, 2**32 - 1)], [_interval(value) for value in NON_PUBLIC_V4])
        + [_interval(value) for value in GLOBAL_EXCEPTIONS_V4]
    )
    lower = _subtract(upper, [_interval(value) for value in INDETERMINATE_V4])
    families = {}
    for version in (4, 6):
        allowed = _merge(intervals[version])
        full = allowed == [(0, 2**(32 if version == 4 else 128) - 1)]
        state = "UNKNOWN"
        reason = "MalformedSelector" if errors else "IPv6InternetUniverseNotQualified"
        if not errors:
            if full:
                state, reason = "ALL", "EntireAddressFamilyCovered"
            elif version == 4 and not _subtract(upper, allowed):
                state, reason = "ALL", "AllPotentialPublicUnicastCovered"
            elif version == 4 and _subtract(lower, allowed):
                state, reason = "SUBSET", "KnownPublicUnicastNotAllowed"
            elif version == 4:
                reason = "OnlyIndeterminateRegistrySpaceNotAllowed"
        families["ipv" + str(version)] = {
            "coversEntireFamily": full, "internetCoverage": state, "reason": reason,
            "selectorCount": len(intervals[version]),
        }
    return {
        "checkId": ADDRESS_CHECK, "checkVersion": VERSION,
        "status": "UNKNOWN" if errors else "evaluated", "errors": errors, **families,
        "addressUniverse": {
            "ipv4": "IANA-special-purpose-exclusions-with-global-overrides-and-indeterminate-deprecated-block",
            "ipv6": "whole-family-proof-only; service applicability remains separately gated",
            "runtimeIsGlobalHeuristicUsed": False, "actualRoutingOrAuthorizationTested": False,
        },
    }


def _omitted(path: str, omissions: list[str]) -> bool:
    return any(path == value or path.startswith(value + "/") for value in omissions)


def _unavailable(record: ef.Record, field: str, label: str) -> str:
    return label + ("NotReturned" if field not in record else "Null" if record[field] is None else "UnexpectedType")


def _uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ef.canonical_uuid(value) == value.lower()
    except ValueError:
        return False


def _resource_reference(value: object, resource_type: str | None = None) -> bool:
    if not isinstance(value, str) or "*" in value:
        return False
    parts = value.split("/")
    if len(parts) < 9 or not _uuid(parts[2]):
        return False
    try:
        profile.resource_id(value, parts[2].lower(), resource_type or "/".join([parts[6], *parts[7::2]]))
    except ValueError:
        return False
    return True


def _selected_networks(family: str, properties: ef.Record, rules: ef.Record,
                       pointer: str, omissions: list[str]) -> tuple[str, list[str], ef.Record | None]:
    gaps: list[str] = []
    if any(value == pointer or value.startswith(pointer + "/") for value in omissions):
        gaps.append("NetworkRuleSelectorsOmitted")
    rule_values = rules.get("ipRules")
    selectors: list[object] = []
    if not isinstance(rule_values, list):
        gaps.append(_unavailable(rules, "ipRules", "IpRuleInventory"))
    else:
        if len(rule_values) > ef.MAX_ROWS:
            raise ValueError("IP rule inventory exceeds the reviewed row budget")
        for value in rule_values:
            if not isinstance(value, dict):
                gaps.append("IpRuleShapeNotQualified")
                continue
            action = value.get("action")
            if (family != "keyvault" or "action" in value) and (
                not isinstance(action, str) or action.casefold() != "allow"
            ):
                gaps.append("IpRuleActionNotQualified")
            fields = ("iPAddressOrRange", "value") if family == "acr" else ("value",)
            available = [value[key] for key in fields if key in value]
            if not available or any(entry != available[0] for entry in available):
                gaps.append("IpRuleValueMissingOrConflicting")
            else:
                selectors.append(available[0])
    analysis = address_coverage(selectors) if isinstance(rule_values, list) else None
    if analysis is not None and analysis["status"] == "UNKNOWN":
        gaps.append("MalformedAddressSelector")
    if analysis is not None and ef.integer(ef.obj(analysis["ipv6"])["selectorCount"]):
        gaps.append("ServiceIPv6SelectorNotQualified")
    if "ipv6Rules" in rules and rules["ipv6Rules"] != []:
        gaps.append("ServiceIPv6SelectorNotQualified")
    bypass_pointer = "/properties/networkRuleBypassOptions" if family == "acr" else pointer + "/bypass"
    bypass = properties.get("networkRuleBypassOptions") if family == "acr" else rules.get("bypass")
    allowed = {"none", "azureservices", "logging", "metrics"} if family == "storage" else {"none", "azureservices"}
    parts = {part.strip().casefold() for part in bypass.split(",")} if isinstance(bypass, str) else set()
    if _omitted(bypass_pointer, omissions) or not parts or not parts <= allowed or ("none" in parts and len(parts) != 1):
        gaps.append("TrustedServiceBypassNotQualified")
    virtual = rules.get("virtualNetworkRules")
    if isinstance(virtual, list) and len(virtual) > ef.MAX_ROWS:
        raise ValueError("Virtual network rule inventory exceeds the reviewed row budget")
    if not isinstance(virtual, list):
        gaps.append(_unavailable(rules, "virtualNetworkRules", "VirtualNetworkRuleInventory"))
    elif family == "acr" and virtual:
        gaps.append("LegacyAcrVirtualNetworkRulesNotQualified")
    elif any(not isinstance(value, dict)
             or not _resource_reference(value.get("id"), "Microsoft.Network/virtualNetworks/subnets")
             or (family == "storage" or "action" in value) and (
                 not isinstance(value.get("action"), str) or value["action"].casefold() != "allow"
             ) for value in virtual):
        gaps.append("VirtualNetworkRuleShapeNotQualified")
    if family == "storage":
        instances = rules.get("resourceAccessRules")
        if isinstance(instances, list) and len(instances) > ef.MAX_ROWS:
            raise ValueError("Resource-instance rule inventory exceeds the reviewed row budget")
        if not isinstance(instances, list):
            gaps.append(_unavailable(rules, "resourceAccessRules", "ResourceInstanceRuleInventory"))
        elif any(not isinstance(value, dict) or not _resource_reference(value.get("resourceId"))
                 or not _uuid(value.get("tenantId")) for value in instances):
            gaps.append("ResourceInstanceRuleShapeNotQualified")
    if gaps:
        return "UNKNOWN", sorted(set(gaps)), analysis
    if analysis is None:
        raise ValueError("Qualified rules require address evidence")
    ipv4 = ef.obj(analysis["ipv4"])["internetCoverage"]
    if ipv4 == "ALL":
        return "UNRESTRICTED", [], analysis
    if ipv4 == "SUBSET":
        return "SELECTED_NETWORKS", [], analysis
    return "UNKNOWN", ["AddressUniverseNotQualified"], analysis


def _local_setting(family: str, properties: ef.Record, path: str,
                   omissions: list[str]) -> tuple[str, list[str], ef.Record | None, list[str]]:
    field = "publicNetworkAccessFor" + path.title() if family == "loganalytics" else "publicNetworkAccess"
    pointer = "/properties/" + field
    references = [pointer]
    if _omitted(pointer, omissions):
        return "UNKNOWN", ["PublicNetworkAccessOmitted"], None, references
    mode = properties.get(field)
    if not isinstance(mode, str):
        return "UNKNOWN", [_unavailable(properties, field, "PublicNetworkAccess")], None, references
    if mode.casefold() == "disabled":
        return "PUBLIC_DISABLED", [], None, references
    if mode.casefold() != "enabled":
        reason = "PerimeterModeRequiresQualifiedEvidence" if mode.casefold() == "securedbyperimeter" else "PublicNetworkAccessUnrecognized"
        return "UNKNOWN", [reason], None, references
    if family == "loganalytics":
        return "UNRESTRICTED", [], None, references
    rule_field = "networkRuleSet" if family == "acr" else "networkAcls"
    rule_pointer = "/properties/" + rule_field
    references.append(rule_pointer)
    if _omitted(rule_pointer, omissions):
        return "UNKNOWN", ["NetworkRulesOmitted"], None, references
    rules = properties.get(rule_field)
    if not isinstance(rules, dict):
        return "UNKNOWN", [_unavailable(properties, rule_field, "NetworkRules")], None, references
    default_pointer = rule_pointer + "/defaultAction"
    if _omitted(default_pointer, omissions):
        return "UNKNOWN", ["DefaultActionOmitted"], None, references
    default = rules.get("defaultAction")
    if not isinstance(default, str):
        return "UNKNOWN", [_unavailable(rules, "defaultAction", "DefaultAction")], None, references
    if default.casefold() == "allow":
        return "UNRESTRICTED", [], None, references
    if default.casefold() != "deny":
        return "UNKNOWN", ["DefaultActionUnrecognized"], None, references
    local, gaps, analysis = _selected_networks(family, properties, rules, rule_pointer, omissions)
    return local, gaps, analysis, references


def evaluate_configuration(family: str, properties: ef.Record, *,
                           omitted_paths: list[str] | None = None, source_eligible: bool = True) -> list[ef.Record]:
    """Keep the local service gate distinct from the qualified overall criterion."""
    if family not in FAMILIES:
        raise ValueError("Unsupported source-restriction service family")
    properties = ef.obj(properties)
    omissions = [ef.text(value) for value in ef.array(omitted_paths)] if omitted_paths is not None else []
    if not isinstance(source_eligible, bool) or any(not value.startswith("/") for value in omissions):
        raise ValueError("Restriction source eligibility and omission paths require explicit valid values")
    result = []
    for path in ("ingestion", "query") if family == "loganalytics" else ("data-plane",):
        if source_eligible:
            local, reasons, selectors, references = _local_setting(family, properties, path, omissions)
        else:
            local, reasons, selectors, references = "UNKNOWN", ["SuccessfulConsistentDirectGetUnavailable"], None, []
        gaps = list(reasons)
        if family != "acr":
            gaps.append("PerimeterPrecedenceAndApplicabilityNotQualified")
        if family == "loganalytics":
            gaps.append("AMPLSAssociationIsNotPathEnforcementProof")
        verdict = "UNKNOWN"
        if family == "acr":
            verdict = {"PUBLIC_DISABLED": "RESTRICTED", "SELECTED_NETWORKS": "RESTRICTED",
                       "UNRESTRICTED": "NOT_RESTRICTED"}.get(local, "UNKNOWN")
        result.append({
            "checkId": RESTRICTION_CHECK, "checkVersion": VERSION, "path": path,
            "serviceConfiguration": local, "criterionVerdict": verdict,
            "interpretationClassification": "UNKNOWN" if verdict == "UNKNOWN" else "INFERRED",
            "localInterpretationClassification": "UNKNOWN" if local == "UNKNOWN" else "INFERRED",
            "propertyReferences": references, "addressAnalysis": selectors, "evidenceGaps": sorted(set(gaps)),
            "alternativeControlCheck": {
                "checkId": ALTERNATIVE_CHECK, "checkVersion": VERSION,
                "perimeterQualification": "unsupported-in-pinned-service-policy" if family == "acr" else "UNKNOWN",
                "amplsQualification": "UNKNOWN" if family == "loganalytics" else "not-applicable",
                "positiveAlternativeVerdictEnabled": False,
            },
            "severity": None,
            "priority": {
                "band": "P2" if verdict != "RESTRICTED" else "INFO",
                "actionType": "evidenceCollection" if verdict == "UNKNOWN" else
                              "contextValidation" if verdict == "NOT_RESTRICTED" else "none",
            },
            "actualReachability": "UNKNOWN", "authorizationAssessed": False,
            "privateConnectivityVerified": False, "ownerAllowlistCompliance": "not-assessed",
        })
    return result


def _observed(root: Path, run_id: str) -> ef.Record:
    sources = list((root / "sources").iterdir())
    if len(sources) != 1 or ef.canonical_uuid(sources[0].name) != sources[0].name:
        raise ValueError("Restriction assessment requires exactly one canonical configuration source")
    source = sources[0]
    manifest, documents, manifest_bytes = capture.verified(source)
    if (manifest["profileId"], manifest["capsuleVersion"], manifest["capsuleId"]) != (
        capture.PROFILE, capture.CAPSULE_VERSION, source.name,
    ):
        raise ValueError("Restriction assessment requires the compatible configuration 0.3.0 profile")
    source_hash = hashlib.sha256(manifest_bytes).hexdigest()
    descriptors = {ef.text(value["name"]): value for value in ef.records(manifest["members"])}
    entities: dict[str, ef.Record] = {}
    alternatives: list[ef.Record] = []
    catalog: dict[str, ef.Record] = {}
    count = 0
    for name, page in sorted(documents.items()):
        if name == capture.CONTEXT or name.startswith("attempt-"):
            continue
        operation = ef.text(page["operationId"])
        kind, family, _ = profile.OPS[operation]
        member = "sources/" + source.name + "/" + name
        reference = {
            "capsuleId": source.name, "manifestSha256": source_hash, "member": member,
            "memberSha256": descriptors[name]["sha256"], "operationId": operation,
            "collectionStartedAt": page["startedAtUtc"], "collectionCompletedAt": page["completedAtUtc"],
            "requestId": page["requestId"], "classification": "OBSERVED",
        }
        if family in FAMILIES and kind == "get":
            target = ef.text(page["targetId"]).lower()
            entity = entities.setdefault(target, {
                "resourceId": target, "family": family, "observations": [], "getOutcomes": [],
            })
            evidence_id = "ev-" + ef.digest([member, "/status"])
            catalog[evidence_id] = {**reference, "pointer": "/status"}
            ef.array(entity["getOutcomes"]).append({
                "status": page["status"], "httpStatus": page["httpStatus"],
                "errorCode": page["errorCode"], "evidenceId": evidence_id,
            })
        for position, row in enumerate(ef.records(page["rows"]) if page["rows"] is not None else []):
            count += 1
            if count > MAX_OBSERVATIONS:
                raise ValueError("Restriction input observation budget exceeded")
            configuration = ef.obj(row["configuration"])
            pointer = "/rows/" + str(position) + "/configuration"
            evidence_id = "ev-" + ef.digest([member, pointer])
            catalog[evidence_id] = {**reference, "pointer": pointer}
            observation = {
                "configuration": configuration, "evidenceId": evidence_id, "direct": kind == "get",
                "omittedPaths": row["omittedPaths"],
            }
            if family not in FAMILIES:
                alternatives.append({"family": family, **observation})
                continue
            target = ef.text(configuration["id"]).lower()
            entity = entities.setdefault(target, {
                "resourceId": target, "family": family, "observations": [], "getOutcomes": [],
            })
            if entity["family"] != family:
                raise ValueError("Restriction source resource families disagree")
            ef.array(entity["observations"]).append(observation)
    return {
        "profileId": "retained-source-restriction-observations", "profileVersion": VERSION,
        "runId": run_id, "legacyObservedNetworkModelCompatible": False,
        "source": {
            "capsuleId": source.name, "manifestSha256": source_hash, "profileId": manifest["profileId"],
            "profileVersion": manifest["profileVersion"], "capsuleVersion": manifest["capsuleVersion"],
            "scope": manifest["scope"], "collectionWindow": manifest["collectionWindow"],
            "assurance": manifest["assurance"],
        },
        "coverage": manifest["coverage"], "entities": [entities[key] for key in sorted(entities)],
        "alternativeControlObservations": alternatives, "evidenceCatalog": catalog,
        "interpretationsIncluded": False,
        "retention": {
            "sensitivity": "private-network-configuration", "sourceCapsuleCopiedUnchanged": True,
            "newRawResponsesCollected": False, "sourceOmissionsPreserved": True,
        },
    }


def _associated(alternatives: list[ef.Record]) -> dict[str, list[ef.Record]]:
    matches: dict[str, list[ef.Record]] = {}
    for entry in alternatives:
        configuration = ef.obj(entry["configuration"])
        properties = configuration.get("properties")
        if not isinstance(properties, dict):
            continue
        if entry["family"] == "nsp-associations":
            linked = properties.get("privateLinkResource")
            identifier = linked.get("id") if isinstance(linked, dict) else None
        elif entry["family"] == "ampls-scoped":
            identifier = properties.get("linkedResourceId")
        else:
            continue
        if isinstance(identifier, str):
            matches.setdefault(identifier.rstrip("/").lower(), []).append(entry)
    return matches


def _assessment(observed: ef.Record) -> ef.Record:
    results: list[ef.Record] = []
    associations = _associated(ef.records(observed["alternativeControlObservations"]))
    for entity in ef.records(observed["entities"]):
        observations = ef.records(entity["observations"])
        direct = [value for value in observations if value["direct"]]
        eligible = bool(direct) and len({ef.digest(value["configuration"]) for value in direct}) == 1
        selected = direct[-1] if eligible else None
        configuration = ef.obj(selected["configuration"]) if selected else {}
        properties = ef.obj(configuration["properties"]) if isinstance(configuration.get("properties"), dict) else {}
        omissions = [ef.text(value) for value in ef.array(selected["omittedPaths"])] if selected else []
        refs = [ef.text(selected["evidenceId"])] if selected else sorted({
            ef.text(value["evidenceId"]) for value in observations + ef.records(entity["getOutcomes"])
        })
        associated = associations.get(ef.text(entity["resourceId"]), [])
        rows = evaluate_configuration(ef.text(entity["family"]), properties,
                                      omitted_paths=omissions, source_eligible=eligible)
        for row in rows:
            gaps = ef.array(row["evidenceGaps"])
            if not eligible:
                gaps.append("ConflictingDirectGetObservations" if direct else "SuccessfulDirectGetNotCollected")
            elif not isinstance(configuration.get("properties"), dict):
                gaps.append(_unavailable(configuration, "properties", "Properties"))
            if entity["family"] == "acr" and any(value["family"] == "nsp-associations" for value in associated):
                row.update({
                    "criterionVerdict": "UNKNOWN", "interpretationClassification": "UNKNOWN",
                    "priority": {"band": "P2", "actionType": "evidenceCollection"},
                })
                ef.obj(row["alternativeControlCheck"])["perimeterQualification"] = "UNKNOWN-contradicts-pinned-service-support"
                gaps.append("UnsupportedAcrPerimeterAssociationObserved")
            for outcome in ef.records(entity["getOutcomes"]):
                if outcome["status"] != "succeeded":
                    gaps.append("DirectGetUnavailable:" + str(outcome["httpStatus"]) + ":" + str(outcome["errorCode"]))
            results.append({
                "resourceId": entity["resourceId"], "family": entity["family"],
                "evidenceRefs": refs, "directGetOutcomes": entity["getOutcomes"],
                "alternativeControlEvidenceRefs": sorted({ef.text(value["evidenceId"]) for value in associated}),
                **row, "evidenceGaps": sorted(set(ef.text(value) for value in gaps)),
            })
    return {
        "profileId": "retained-source-restriction-assessment", "profileVersion": VERSION,
        "runId": observed["runId"], "legacyAssessmentSchemaCompatible": False,
        "policy": POLICY, "policySha256": ef.digest(POLICY), "guidance": GUIDANCE,
        "requirement": {
            "classification": "DECLARED", "origin": "owner-approved-technical-criterion",
            "statement": "Distinguish unrestricted Internet sources from a configured technical source restriction.",
            "ownerApprovedAllowlistProvided": False,
        },
        "source": observed["source"], "coverage": observed["coverage"],
        "observationArtifact": {
            "filename": "observed-network.json", "sha256": hashlib.sha256(ef.encoded(observed)).hexdigest(),
            "profileId": observed["profileId"], "profileVersion": observed["profileVersion"],
        },
        "assessmentState": "service-paths-reviewed" if results else "UNKNOWN-no-service-paths-observed",
        "scopeCoverageConclusion": "UNKNOWN-not-global-completeness",
        "statistics": {
            "resources": len(ef.records(observed["entities"])), "servicePaths": len(results),
            "families": dict(sorted(Counter(ef.text(value["family"]) for value in ef.records(observed["entities"])).items())),
            "serviceConfiguration": dict(sorted(Counter(ef.text(value["serviceConfiguration"]) for value in results).items())),
            "criterionVerdicts": dict(sorted(Counter(ef.text(value["criterionVerdict"]) for value in results).items())),
        },
        "evidenceCatalog": observed["evidenceCatalog"], "results": results,
        "limitations": [
            "Historical retained configuration only; not a current-state or atomic-environment certification.",
            "Technical source restriction, not anonymous access, authorization, reachability or customer-policy compliance.",
            "Disabled public access is not proof of private connectivity or that trusted-service exceptions are absent.",
            "Private endpoint presence and NSP/AMPLS association or Enforced mode alone are not qualified enforcement proof.",
            "NSP/AMPLS precedence, cross-scope associations and service/path applicability remain unqualified.",
            "Empty visible NSP/AMPLS collection results are not proof of global or cross-subscription absence.",
            "Azure Monitor diagnostic-setting ingestion can use a separate secure Microsoft channel.",
            "Missing, null, omitted, denied, malformed and unsupported evidence is not a documented service default.",
            "IPv6 whole-family mathematics does not establish service support or a qualified IPv6 restriction.",
            "Selected source bytes are integrity checked; transport authenticity, effective enforcement and impact are not certified.",
        ],
        "causalConclusions": "notGenerated", "azureReads": 0, "activeConnectivityTests": 0,
        "memoryWrites": 0, "deploymentPerformed": False,
    }


def _cell(value: object) -> str:
    return html.escape(str(value)).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def render(assessment: ef.Record) -> tuple[bytes, bytes]:
    """Both deterministic Markdown views consume assessment JSON only."""
    if (assessment["profileId"], assessment["profileVersion"]) != (
        "retained-source-restriction-assessment", VERSION,
    ):
        raise ValueError("Unsupported restriction assessment report profile")
    statistics = ef.obj(assessment["statistics"])
    source = ef.obj(assessment["source"])
    window = ef.obj(source["collectionWindow"])
    header = [
        "# Offline public-source restriction assessment", "",
        "PRIVATE: retained network configuration; unreleased companion contract.", "",
        "**Run:** " + _cell(assessment["runId"]),
        "**Collected:** " + _cell(window["startedAtUtc"]) + " through " + _cell(window["completedAtUtc"]),
        "**Source manifest SHA256:** `" + ef.text(source["manifestSha256"]) + "`", "",
        "This is technical configuration analysis, not anonymous access or verified reachability.",
        "Local service settings and the overall qualified criterion are deliberately separate.", "",
    ]
    summary = [
        "## Summary", "",
        f"Resources: {statistics['resources']}; independently assessed service paths: {statistics['servicePaths']}.", "",
        "| Overall criterion | Paths |", "|---|---:|",
        *("| " + _cell(key) + " | " + str(value) + " |" for key, value in sorted(ef.obj(statistics["criterionVerdicts"]).items())), "",
        "| Local service configuration | Paths |", "|---|---:|",
        *("| " + _cell(key) + " | " + str(value) + " |" for key, value in sorted(ef.obj(statistics["serviceConfiguration"]).items())), "",
        "UNKNOWN is an evidence gap, not a pass or a proven unrestricted endpoint.",
        "RESTRICTED is a configured technical source restriction, not owner-allowlist compliance or private-only certification.",
        "No impact-based severity is assigned; priority identifies the next action, including evidence collection.", "",
        "## Resource paths", "",
        "| Resource | Path | Local service setting | Overall criterion | Next action |",
        "|---|---|---|---|---|",
    ]
    rows = ef.records(assessment["results"])
    for row in rows:
        summary.append("| " + " | ".join(_cell(value) for value in (
            row["resourceId"], row["path"], row["serviceConfiguration"], row["criterionVerdict"],
            ef.obj(row["priority"])["actionType"],
        )) + " |")
    limitations = ["", "## Limitations", "", *("- " + _cell(value) for value in ef.array(assessment["limitations"])), ""]
    engineering = [*header, "## Evidence and check results", "",
                   "[Assessment JSON](assessment.json) is authoritative for these deterministic views.",
                   "[Observations](observed-network.json) contain retained facts, not findings.", ""]
    catalog = ef.obj(assessment["evidenceCatalog"])
    for row in rows:
        engineering.extend([
            "### " + _cell(row["resourceId"]) + " / " + _cell(row["path"]), "",
            "Check: `" + ef.text(row["checkId"]) + "` / `" + ef.text(row["checkVersion"]) + "`.",
            "Local: **" + _cell(row["serviceConfiguration"]) + "**. Overall: **" + _cell(row["criterionVerdict"]) + "**.",
            "Next action: " + _cell(ef.obj(row["priority"])["actionType"]) + ".",
            "Gaps: " + (", ".join(_cell(value) for value in ef.array(row["evidenceGaps"])) or "none in this pinned technical criterion"),
            "Address analysis: " + ("not evaluated: local mode is decisive or selector evidence is unavailable" if row["addressAnalysis"] is None
                                   else _cell(json.dumps(row["addressAnalysis"], sort_keys=True))), "",
        ])
        if row["alternativeControlEvidenceRefs"]:
            engineering.append("Matching alternative-control references below are unqualified; association is not enforcement.")
        for evidence_id in ef.array(row["evidenceRefs"]) + ef.array(row["alternativeControlEvidenceRefs"]):
            reference = ef.obj(catalog[ef.text(evidence_id)])
            member = ef.text(reference["member"])
            engineering.append(
                "- [Retained source](" + member + ") `" + ef.text(reference["pointer"]) + "`; "
                + _cell(reference["collectionStartedAt"]) + " to " + _cell(reference["collectionCompletedAt"])
                + "; member SHA256 `" + ef.text(reference["memberSha256"]) + "`."
            )
        engineering.append("")
    engineering.extend([
        "## Collection coverage", "",
        "Collection status is original source coverage, not current or global completeness.", "",
        "| Operation | HTTP | Status | Rows | Source |", "|---|---:|---|---:|---|",
    ])
    for entry in ef.records(ef.obj(assessment["coverage"])["collections"]):
        member = "sources/" + ef.text(source["capsuleId"]) + "/" + ef.text(entry["member"])
        engineering.append("| " + " | ".join(_cell(entry[key]) for key in (
            "operationId", "httpStatus", "status", "returnedRows",
        )) + " | [Evidence](" + member + ") |")
    engineering.extend(["", "Unperformed operations: " + _cell(json.dumps(
        ef.obj(assessment["coverage"])["unperformedOperations"], sort_keys=True,
    )), "", "## Pinned primary guidance", "",
        *("- [" + _cell(key) + "](" + ef.text(value) + ")" for key, value in sorted(ef.obj(assessment["guidance"]).items()))])
    return ("\n".join([*header, *summary, *limitations]).encode(),
            "\n".join([*engineering, *limitations]).encode())


def _views(root: Path, run_id: str, inputs: ef.Record) -> dict[str, bytes]:
    if inputs:
        raise ValueError("Restriction companion has no optional source-selection defaults")
    observed = _observed(root, run_id)
    assessment = _assessment(observed)
    executive, engineering = render(assessment)
    return {
        "observed-network.json": ef.encoded(observed), "assessment.json": ef.encoded(assessment),
        "network-assessment.md": executive, "network-evidence.md": engineering,
    }


def build(capsule: Path, run_id: str, output_root: Path) -> Path:
    return bundle.build([capsule], run_id, output_root, "restriction", _views)


def verify(directory: Path) -> ef.Record:
    return bundle.verify(directory, "restriction", _views)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("build")
    create.add_argument("--capsule", required=True, type=Path)
    create.add_argument("--run-id", required=True)
    create.add_argument("--output-root", required=True, type=Path)
    check = commands.add_parser("verify")
    check.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    directory = build(args.capsule, args.run_id, args.output_root) if args.command == "build" else args.run
    manifest = verify(directory)
    print(json.dumps({
        "restriction": str(directory), "restrictionId": manifest["restrictionId"],
        "members": len(ef.array(manifest["members"])), "azureReads": 0, "memoryWrites": 0,
        "installedAcceptance": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
