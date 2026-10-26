#!/usr/bin/env python3
"""Build and verify deterministic Azure Tag Governance run bundles."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import re
import secrets
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ARTIFACTS = (
    "governance-profile.json",
    "observations.json",
    "assessment.json",
    "delta.json",
    "executive-report.md",
    "engineering-report.md",
)
CLASSIFICATIONS = {"OBSERVED", "DECLARED", "INFERRED", "UNKNOWN"}
RULE_KINDS = {"requiredTag", "allowedValues", "valuePattern", "namingPattern"}
NAMING_PATTERNS = {
    r"^[a-z0-9]+(?:-[a-z0-9]+)*$": "Lowercase letters and digits, with optional single hyphen separators",
    r"^[a-z0-9]+(?:_[a-z0-9]+)*$": "Lowercase letters and digits, with optional single underscore separators",
    r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$": "Letters and digits (either case), with optional single hyphen separators",
    r"^[A-Za-z0-9._-]+$": "Letters, digits, dots, underscores, and hyphens",
}


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_bytes(value))


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read JSON {path}: {exc}") from exc


def object_value(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def list_value(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: Any, label: str) -> dt.datetime:
    raw = text(value, label)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def stable_id(prefix: str, value: object) -> str:
    return f"{prefix}-{digest(value)[:16]}"


def safe_label(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value) or value in {".", ".."}:
        raise ValueError(f"{label} must contain only letters, numbers, dot, underscore, and hyphen")
    return value


def normalize_resource_id(value: Any) -> str:
    identifier = text(value, "resource.id").strip().rstrip("/").lower()
    if not identifier.startswith("/subscriptions/"):
        raise ValueError("resource.id must be an Azure subscription resource ID")
    return identifier


def normalize_resource(value: Any) -> dict[str, Any]:
    source = object_value(value, "resource")
    raw_tags = source.get("tags") or {}
    if not isinstance(raw_tags, dict):
        raise ValueError("resource.tags must be an object or null")
    tags: dict[str, str] = {}
    for key, item in raw_tags.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError("resource tag keys and values must be strings")
        tags[key] = item
    return {
        "id": normalize_resource_id(source.get("id")),
        "name": text(source.get("name"), "resource.name"),
        "type": text(source.get("type"), "resource.type").lower(),
        "subscriptionId": str(source.get("subscriptionId") or ""),
        "resourceGroup": str(source.get("resourceGroup") or ""),
        "location": str(source.get("location") or ""),
        "tags": tags,
    }


def infer_name_pattern(names: list[str]) -> str | None:
    if not names:
        return None
    for pattern in NAMING_PATTERNS:
        if all(re.fullmatch(pattern, name) for name in names):
            return pattern
    return None


def discover_candidates(resources: list[dict[str, Any]], scope_id: str) -> list[dict[str, Any]]:
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for resource in resources:
        by_type[resource["type"]].append(resource)
    candidates: list[dict[str, Any]] = []
    for resource_type, members in sorted(by_type.items()):
        counts: Counter[str] = Counter()
        values: dict[str, Counter[str]] = defaultdict(Counter)
        for resource in members:
            for key, value in resource["tags"].items():
                counts[key] += 1
                values[key][value] += 1
        for key, count in sorted(counts.items()):
            identity = {
                "kind": "requiredTag",
                "scope": {"scopeId": scope_id, "resourceType": resource_type},
                "tagKey": key,
            }
            candidates.append({
                "id": stable_id("candidate", identity),
                **identity,
                "evidenceClass": "INFERRED",
                "evidence": {
                    "eligibleResourceCount": len(members),
                    "observedResourceCount": count,
                    "prevalence": round(count / len(members), 6),
                    "distinctValueCount": len(values[key]),
                    "valueDigests": sorted(hashlib.sha256(item.encode("utf-8")).hexdigest() for item in values[key]),
                },
            })
        names = [member["name"] for member in members]
        pattern = infer_name_pattern(names)
        if pattern:
            identity = {
                "kind": "namingPattern",
                "scope": {"scopeId": scope_id, "resourceType": resource_type},
                "pattern": pattern,
            }
            candidates.append({
                "id": stable_id("candidate", identity),
                **identity,
                "evidenceClass": "INFERRED",
                "evidence": {
                    "eligibleResourceCount": len(names),
                    "matchingResourceCount": len(names),
                    "nameDigests": sorted(hashlib.sha256(item.encode("utf-8")).hexdigest() for item in names),
                },
            })
    return candidates


def validate_decision(value: Any, now: dt.datetime) -> dict[str, Any]:
    decision = object_value(value, "AI decision")
    required = (
        "candidateId",
        "action",
        "authorityEligible",
        "supportingEvidence",
        "contraryEvidence",
        "coverage",
        "modelVersion",
        "promptVersion",
        "confidence",
        "rationale",
        "expiresAt",
        "rollbackProfileVersion",
        "ruleSpec",
    )
    missing = [key for key in required if key not in decision]
    if missing:
        raise ValueError("AI decision is missing: " + ", ".join(missing))
    if decision["action"] not in {"promote", "retainCandidate"}:
        raise ValueError("AI decision action is invalid")
    if not isinstance(decision["authorityEligible"], bool):
        raise ValueError("AI decision authorityEligible must be boolean")
    for key in ("supportingEvidence", "contraryEvidence"):
        list_value(decision[key], f"AI decision {key}")
    object_value(decision["coverage"], "AI decision coverage")
    for key in ("modelVersion", "promptVersion", "confidence", "rationale", "rollbackProfileVersion"):
        text(decision[key], f"AI decision {key}")
    if decision["action"] == "promote" and decision["authorityEligible"]:
        if decision["confidence"].casefold() != "high":
            raise ValueError("Automatic promotion requires explicitly high confidence")
        if not decision["supportingEvidence"]:
            raise ValueError("Automatic promotion requires supporting evidence")
        if decision["coverage"].get("complete") is not True:
            raise ValueError("Automatic promotion requires complete decision coverage")
    expires = parse_time(decision["expiresAt"], "AI decision expiresAt")
    if expires <= now:
        raise ValueError("AI decision is already expired")
    spec = object_value(decision["ruleSpec"], "AI decision ruleSpec")
    if spec.get("kind") not in RULE_KINDS:
        raise ValueError("AI decision ruleSpec.kind is invalid")
    allowed_spec_keys = {"kind", "scope", "tagKey", "pattern", "allowedValues", "normalization", "multiValue"}
    if set(spec) - allowed_spec_keys:
        raise ValueError("AI decision ruleSpec contains unsupported or reserved fields")
    object_value(spec.get("scope"), "AI decision ruleSpec.scope")
    return copy.deepcopy(decision)


def profile_version(previous: str | None, changed: bool) -> str:
    if previous is None:
        return "1.0.0"
    if not re.fullmatch(r"\d+\.\d+\.\d+", previous):
        raise ValueError("Previous profileVersion is invalid")
    if not changed:
        return previous
    major, minor, patch = (int(part) for part in previous.split("."))
    return f"{major}.{minor}.{patch + 1}"


def rule_subject(rule: dict[str, Any]) -> tuple[str, str]:
    return str(rule.get("kind")), str(rule.get("tagKey") or "")


def scopes_overlap(first: dict[str, Any], second: dict[str, Any]) -> bool:
    for key in ("tenantId", "subscriptionId", "resourceGroup", "resourceType", "resourceId"):
        if key in first and key in second and str(first[key]).casefold() != str(second[key]).casefold():
            return False
    first_id = str(first.get("scopeId", "")).rstrip("/").casefold()
    second_id = str(second.get("scopeId", "")).rstrip("/").casefold()
    if first_id.startswith("/subscriptions/") and second_id.startswith("/subscriptions/"):
        return (
            first_id == second_id
            or first_id.startswith(second_id + "/")
            or second_id.startswith(first_id + "/")
        )
    return True


def conflicts_with_existing(spec: dict[str, Any], rules: list[dict[str, Any]]) -> bool:
    subject = rule_subject(spec)
    for rule in rules:
        existing_subject = rule_subject(rule)
        same_subject = existing_subject == subject
        if (
            existing_subject[0] == subject[0]
            and (
                rule.get("normalization", {}).get("keyCaseSensitive") is False
                or spec.get("normalization", {}).get("keyCaseSensitive") is False
            )
        ):
            same_subject = existing_subject[1].casefold() == subject[1].casefold()
        if rule.get("status") == "authoritative" and same_subject:
            if scopes_overlap(rule.get("scope", {}), spec.get("scope", {})):
                return True
    return False


def comparable(previous_run: dict[str, Any] | None, plugin_build: str, scope_id: str,
               coverage: dict[str, Any]) -> bool:
    if previous_run is None:
        return False
    return (
        previous_run.get("pluginBuild") == plugin_build
        and previous_run.get("scopeId") == scope_id
        and previous_run.get("coverage", {}).get("complete") is True
        and coverage.get("complete") is True
        and coverage.get("materialReduction") is not True
    )


def build_profile(resources: list[dict[str, Any]], scope_id: str, now: dt.datetime,
                  previous_profile: dict[str, Any] | None, previous_run: dict[str, Any] | None,
                  plugin_build: str, coverage: dict[str, Any],
                  decisions: list[Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    candidates = discover_candidates(resources, scope_id)
    prior_candidates = {
        item["id"]: item for item in (previous_profile or {}).get("candidates", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    rules = copy.deepcopy((previous_profile or {}).get("rules", []))
    exceptions = copy.deepcopy((previous_profile or {}).get("exceptions", []))
    applicability = copy.deepcopy((previous_profile or {}).get("applicability", []))
    errors: list[dict[str, Any]] = []
    changed = previous_profile is None

    for rule in rules:
        if rule.get("status") == "authoritative" and parse_time(rule["expiresAt"], "rule.expiresAt") <= now:
            rule["status"] = "stale"
            changed = True

    parsed_decisions: dict[str, dict[str, Any]] = {}
    for raw in decisions:
        try:
            decision = validate_decision(raw, now)
            parsed_decisions[text(decision["candidateId"], "AI decision candidateId")] = decision
        except ValueError as exc:
            errors.append({"classification": "UNKNOWN", "message": str(exc)})

    is_comparable = comparable(previous_run, plugin_build, scope_id, coverage)
    retained: list[dict[str, Any]] = []
    for candidate in candidates:
        decision = parsed_decisions.get(candidate["id"])
        if decision is not None:
            candidate["decision"] = copy.deepcopy(decision)
            candidate["decisionAt"] = timestamp(now)
            candidate["reviewOutcome"] = "retainedCandidate"
        eligible = (
            is_comparable
            and candidate["id"] in prior_candidates
            and decision is not None
            and decision["action"] == "promote"
            and decision["authorityEligible"] is True
        )
        if eligible:
            if decision["rollbackProfileVersion"] != (previous_profile or {}).get("profileVersion"):
                errors.append({
                    "classification": "UNKNOWN",
                    "candidateId": candidate["id"],
                    "message": "AI rollback profile version does not match the verified baseline",
                })
                retained.append(candidate)
                continue
            spec = copy.deepcopy(decision["ruleSpec"])
            if (
                spec.get("kind") != candidate["kind"]
                or spec.get("scope") != candidate["scope"]
                or spec.get("tagKey") != candidate.get("tagKey")
                or spec.get("pattern") != candidate.get("pattern")
            ):
                errors.append({
                    "classification": "UNKNOWN",
                    "candidateId": candidate["id"],
                    "message": "AI ruleSpec does not match the referenced candidate",
                })
                retained.append(candidate)
                continue
            spec.setdefault("normalization", {
                "keyCaseSensitive": True,
                "valueCaseSensitive": True,
                "trimWhitespace": False,
                "unicodeNormalization": "none",
                "emptyIsMissing": False,
            })
            spec.setdefault("multiValue", None)
            identity = {"candidateId": candidate["id"], "spec": spec}
            identifier = stable_id("rule", identity)
            existing = next((rule for rule in rules if rule["id"] == identifier), None)
            if existing is not None and existing["status"] == "authoritative":
                continue
            if conflicts_with_existing(spec, rules):
                errors.append({
                    "classification": "UNKNOWN",
                    "candidateId": candidate["id"],
                    "message": "Promotion would conflict with or override an authoritative rule",
                })
                retained.append(candidate)
                continue
            promoted = {
                "id": identifier,
                **spec,
                "status": "authoritative",
                "evidenceClass": "INFERRED",
                "createdAt": timestamp(now),
                "expiresAt": decision["expiresAt"],
                "sourceCandidateId": candidate["id"],
                "decision": decision,
            }
            if existing is not None:
                promoted["createdAt"] = existing["createdAt"]
                existing.update(promoted)
            else:
                rules.append(promoted)
            changed = True
        else:
            already_authoritative = any(
                rule.get("status") == "authoritative"
                and rule.get("sourceCandidateId") == candidate["id"]
                for rule in rules
            )
            if not already_authoritative:
                retained.append(candidate)

    resource_types = sorted({resource["type"] for resource in resources})
    known = {str(item.get("resourceType")) for item in applicability if isinstance(item, dict)}
    for resource_type in resource_types:
        if resource_type not in known:
            applicability.append({
                "resourceType": resource_type,
                "taggable": True,
                "namingAssessable": True,
                "reason": "Observed in scoped Resource Graph evidence; review resource-type exceptions before enforcement.",
            })
            changed = True

    previous_version = (previous_profile or {}).get("profileVersion")
    version = profile_version(previous_version, changed)
    profile = {
        "profileId": stable_id("profile", {"scopeId": scope_id}),
        "profileVersion": version,
        "generatedAt": timestamp(now),
        "scopeId": scope_id,
        "rules": sorted(rules, key=lambda item: item["id"]),
        "candidates": sorted(retained, key=lambda item: item["id"]),
        "exceptions": sorted(exceptions, key=lambda item: item["id"]),
        "applicability": sorted(applicability, key=lambda item: item["resourceType"]),
    }
    return profile, errors


def scope_specificity(scope: dict[str, Any]) -> int:
    return sum(key in scope for key in ("subscriptionId", "resourceGroup", "resourceType", "resourceId"))


def scope_matches(scope: dict[str, Any], resource: dict[str, Any]) -> bool:
    checks = {
        "subscriptionId": resource["subscriptionId"].lower(),
        "resourceGroup": resource["resourceGroup"].lower(),
        "resourceType": resource["type"].lower(),
        "resourceId": resource["id"].lower(),
    }
    return all(str(value).lower() == checks[key] for key, value in scope.items() if key in checks)


def find_tag(tags: dict[str, str], key: str, case_sensitive: bool) -> tuple[str | None, str | None]:
    if case_sensitive:
        return (key, tags[key]) if key in tags else (None, None)
    matches = [(item_key, value) for item_key, value in tags.items() if item_key.casefold() == key.casefold()]
    if len(matches) == 1:
        return matches[0]
    return None, None


def normalize_value(value: str, normalization: dict[str, Any]) -> str:
    result = value.strip() if normalization.get("trimWhitespace") else value
    if not normalization.get("valueCaseSensitive", True):
        result = result.casefold()
    return result


def exception_status(profile: dict[str, Any], rule_id: str, resource_id: str,
                     now: dt.datetime) -> tuple[bool, list[dict[str, Any]]]:
    expired: list[dict[str, Any]] = []
    for item in profile["exceptions"]:
        if rule_id not in item.get("ruleIds", []):
            continue
        resources = [str(value).lower() for value in item.get("resourceIds", [])]
        if resources and resource_id.lower() not in resources:
            continue
        if item.get("status") == "active" and parse_time(item["expiresAt"], "exception.expiresAt") > now:
            return True, expired
        expired.append(item)
    return False, expired


def resolve_rules(profile: dict[str, Any], resource: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    applicable = [
        rule for rule in profile["rules"]
        if rule.get("status") == "authoritative" and scope_matches(rule.get("scope", {}), resource)
    ]
    resolved: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for rule in applicable:
        grouped[rule_subject(rule)].append(rule)
    for subject, rules in grouped.items():
        ordered = sorted(rules, key=lambda item: scope_specificity(item.get("scope", {})))
        chosen = ordered[0]
        for rule in ordered[1:]:
            if scope_specificity(rule.get("scope", {})) > scope_specificity(chosen.get("scope", {})):
                if rule.get("explicitOverride") is True:
                    chosen = rule
                else:
                    conflicts.append({"subject": list(subject), "ruleIds": [chosen["id"], rule["id"]]})
            elif digest(rule) != digest(chosen):
                conflicts.append({"subject": list(subject), "ruleIds": [chosen["id"], rule["id"]]})
        if not any(chosen["id"] in item["ruleIds"] for item in conflicts):
            resolved.append(chosen)
    return resolved, conflicts


def finding(rule: dict[str, Any], resource: dict[str, Any], message: str,
            observed: dict[str, Any], status: str = "NONCOMPLIANT") -> dict[str, Any]:
    identity = {"ruleId": rule["id"], "resourceId": resource["id"], "message": message}
    return {
        "id": stable_id("finding", identity),
        "ruleId": rule["id"],
        "resourceId": resource["id"],
        "resourceName": resource["name"],
        "resourceType": resource["type"],
        "status": status,
        "confidence": "HIGH",
        "severity": "MEDIUM",
        "priority": "P2",
        "evidenceClass": "OBSERVED",
        "message": message,
        "observed": observed,
    }


def evaluate(profile: dict[str, Any], resources: list[dict[str, Any]], now: dt.datetime,
             coverage: dict[str, Any], profile_errors: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    gaps = copy.deepcopy(profile_errors)
    if coverage.get("complete") is not True:
        gaps.append({"classification": "UNKNOWN", "message": "Collection coverage is partial or unknown"})

    applicability = {item["resourceType"]: item for item in profile["applicability"]}
    for resource in resources:
        capability = applicability.get(resource["type"])
        if capability is None:
            gaps.append({
                "classification": "UNKNOWN",
                "resourceId": resource["id"],
                "message": "Resource type is absent from the applicability matrix",
            })
            continue
        rules, resource_conflicts = resolve_rules(profile, resource)
        for item in resource_conflicts:
            conflict = {**item, "resourceId": resource["id"], "classification": "UNKNOWN"}
            conflicts.append(conflict)
        for rule in rules:
            suppressed, expired = exception_status(profile, rule["id"], resource["id"], now)
            for item in expired:
                findings.append(finding(
                    rule, resource, f"Exception {item['id']} is expired or inactive",
                    {"exceptionId": item["id"]}, "UNKNOWN",
                ))
            if suppressed:
                continue
            normalization = object_value(rule.get("normalization", {}), "rule.normalization")
            kind = rule["kind"]
            if kind == "namingPattern":
                if capability.get("namingAssessable") and not re.fullmatch(text(rule.get("pattern"), "rule.pattern"), resource["name"]):
                    findings.append(finding(
                        rule, resource, "Resource name does not match the configured format",
                        {"name": resource["name"], "pattern": rule["pattern"]},
                    ))
                continue
            if not capability.get("taggable"):
                continue
            tag_key = text(rule.get("tagKey"), "rule.tagKey")
            actual_key, raw = find_tag(resource["tags"], tag_key, normalization.get("keyCaseSensitive", True))
            missing = raw is None or (normalization.get("emptyIsMissing") and raw == "")
            if kind == "requiredTag" and missing:
                findings.append(finding(
                    rule, resource, f"Required tag '{tag_key}' is missing",
                    {"tagKey": tag_key, "actualKey": actual_key},
                ))
            elif not missing and kind in {"allowedValues", "valuePattern"}:
                value = normalize_value(raw, normalization)
                multi = rule.get("multiValue")
                values = [value]
                if multi is not None:
                    delimiter = text(object_value(multi, "rule.multiValue").get("delimiter"), "rule.multiValue.delimiter")
                    values = [normalize_value(item, normalization) for item in value.split(delimiter)]
                    if multi.get("duplicatesAllowed") is False and len(values) != len(set(values)):
                        findings.append(finding(
                            rule, resource, f"Tag '{tag_key}' contains duplicate values",
                            {"tagKey": tag_key, "rawValue": raw},
                        ))
                if kind == "allowedValues":
                    allowed = [normalize_value(str(item), normalization) for item in rule.get("allowedValues", [])]
                    if any(item not in allowed for item in values):
                        findings.append(finding(
                            rule, resource, f"Tag '{tag_key}' has a value outside the allowed set",
                            {"tagKey": tag_key, "rawValue": raw},
                        ))
                elif any(re.fullmatch(text(rule.get("pattern"), "rule.pattern"), item) is None for item in values):
                    findings.append(finding(
                        rule, resource, f"Tag '{tag_key}' does not match the configured pattern",
                        {"tagKey": tag_key, "rawValue": raw, "pattern": rule["pattern"]},
                    ))

    findings.sort(key=lambda item: item["id"])
    conflicts.sort(key=lambda item: (item["resourceId"], item["ruleIds"]))
    counts = Counter(item["status"] for item in findings)
    return {
        "profileVersion": profile["profileVersion"],
        "profileDigest": digest(profile),
        "summary": {
            "resourceCount": len(resources),
            "findingCount": len(findings),
            "statusCounts": dict(sorted(counts.items())),
            "conflictCount": len(conflicts),
            "evidenceGapCount": len(gaps),
        },
        "findings": findings,
        "profileConflicts": conflicts,
        "evidenceGaps": gaps,
        "limitations": [
            "Resource Graph is eventually consistent and findings were not re-read through ARM.",
            "Finding accuracy has not been quantitatively or qualitatively human-benchmarked.",
        ],
    }


def build_delta(previous: dict[str, Any] | None, current: dict[str, Any],
                compatible: bool) -> dict[str, Any]:
    if previous is None:
        return {"compatible": False, "reason": "No prior assessment", "new": [], "resolved": [], "unchanged": []}
    if not compatible:
        return {"compatible": False, "reason": "Plugin build or profile version differs", "new": [], "resolved": [], "unchanged": []}
    prior_ids = {item["id"] for item in previous.get("findings", [])}
    current_ids = {item["id"] for item in current.get("findings", [])}
    return {
        "compatible": True,
        "reason": None,
        "new": sorted(current_ids - prior_ids),
        "resolved": sorted(prior_ids - current_ids),
        "unchanged": sorted(current_ids & prior_ids),
    }


def executive_report(run_id: str, assessment: dict[str, Any], profile: dict[str, Any],
                     coverage: dict[str, Any]) -> str:
    summary = assessment["summary"]
    return "\n".join([
        "# Azure Tag Governance Executive Report",
        "",
        f"- Run: `{run_id}`",
        f"- Profile: `{profile['profileVersion']}`",
        f"- Resources assessed: {summary['resourceCount']}",
        f"- Findings: {summary['findingCount']}",
        f"- Evidence gaps: {summary['evidenceGapCount']}",
        f"- Profile conflicts: {summary['conflictCount']}",
        f"- Coverage complete: {str(coverage.get('complete') is True).lower()}",
        "",
        "## Limitations",
        "",
        *[f"- {item}" for item in assessment["limitations"]],
        "",
        "No Azure resources were changed.",
        "",
    ])


def markdown_code(value: str) -> str:
    value = " ".join(value.splitlines())
    width = max((len(item) for item in re.findall(r"`+", value)), default=0) + 1
    fence = "`" * width
    padding = " " if value.startswith(("`", " ")) or value.endswith(("`", " ")) else ""
    return f"{fence}{padding}{value}{padding}{fence}"


def candidate_support(evidence: dict[str, Any], kind: str) -> str:
    eligible = evidence.get("eligibleResourceCount")
    observed_key = "observedResourceCount" if kind == "requiredTag" else "matchingResourceCount"
    observed = evidence.get(observed_key)
    if eligible is None or observed is None:
        return "UNKNOWN (supporting resource counts were not collected)."
    if (
        type(eligible) is not int or type(observed) is not int
        or eligible < 0 or observed < 0 or observed > eligible
    ):
        raise ValueError("Candidate support counts must be non-negative integers with observed <= eligible")
    percentage = f"{observed / eligible:.1%}" if eligible else "no eligible sample; percentage UNKNOWN"
    if kind == "requiredTag":
        return (
            f"Tag present on {observed}/{eligible} resources ({percentage}); "
            f"{eligible - observed}/{eligible} resources without this tag."
        )
    return f"{observed}/{eligible} names match ({percentage})."


def engineering_report(run_id: str, assessment: dict[str, Any], profile: dict[str, Any]) -> str:
    lines = [
        "# Azure Tag Governance Engineering Report",
        "",
        f"- Run: `{run_id}`",
        f"- Profile digest: `{assessment['profileDigest']}`",
        "",
        "## Findings",
        "",
    ]
    if not assessment["findings"]:
        lines.append("- No deterministic findings.")
    for item in assessment["findings"]:
        lines.extend([
            f"### {item['id']}",
            "",
            f"- Status: {item['status']}",
            f"- Severity: {item['severity']}",
            f"- Priority: {item['priority']}",
            f"- Rule: `{item['ruleId']}`",
            f"- Resource: `{item['resourceId']}`",
            f"- Evidence: {item['evidenceClass']}",
            f"- Detail: {item['message']}",
            "",
        ])
    lines.extend(["", "## Candidate rules", ""])
    if not profile["candidates"]:
        lines.append("- None.")
    else:
        lines.extend([
            "These are inferred proposals, not authoritative requirements or compliance findings. "
            "Candidate IDs are stable tracking references, not confidence scores.",
            "",
            "Observed prevalence is supporting evidence, not proof of customer intent. "
            "Small samples and missing tags do not by themselves establish a requirement or violation.",
            "",
        ])
    for candidate in sorted(
        profile["candidates"],
        key=lambda item: (
            item["scope"].get("resourceType", ""),
            item["kind"],
            item.get("tagKey", ""),
            item["id"],
        ),
    ):
        scope = object_value(candidate["scope"], "candidate.scope")
        evidence = object_value(candidate["evidence"], "candidate.evidence")
        kind = candidate["kind"]
        if kind == "requiredTag":
            tag_key = markdown_code(text(candidate.get("tagKey"), "candidate.tagKey"))
            lines.extend([
                f"### Required tag: {tag_key}",
                "",
                f"- Proposed rule: Require the tag {tag_key} on resources in the scope below.",
            ])
        elif kind == "namingPattern":
            pattern = text(candidate.get("pattern"), "candidate.pattern")
            resource_type = markdown_code(text(scope.get("resourceType"), "candidate.scope.resourceType"))
            description = NAMING_PATTERNS.get(pattern, "Full name must match the regular expression below")
            lines.extend([
                f"### Naming format: {resource_type}",
                "",
                f"- Proposed rule: {description}.",
                f"- Pattern: {markdown_code(pattern)}",
            ])
        else:
            raise ValueError(f"Unsupported candidate rule kind for engineering report: {kind}")
        lines.extend([
            f"- Candidate ID: {markdown_code(candidate['id'])}",
            f"- Classification: {candidate['evidenceClass']} (candidate only; not enforced)",
        ])
        if "scopeId" in scope:
            lines.append(f"- Scope: {markdown_code(text(scope['scopeId'], 'candidate.scope.scopeId'))}")
        if "resourceType" in scope:
            lines.append(f"- Resource type: {markdown_code(text(scope['resourceType'], 'candidate.scope.resourceType'))}")
        for key, value in sorted(scope.items()):
            if key not in {"scopeId", "resourceType"}:
                lines.append(f"- Scope filter {markdown_code(key)}: {markdown_code(text(value, 'candidate.scope.' + key))}")
        if kind in {"requiredTag", "namingPattern"}:
            lines.append(f"- Observed support: {candidate_support(evidence, kind)}")
        if kind == "requiredTag" and "distinctValueCount" in evidence:
            count = evidence["distinctValueCount"]
            if type(count) is not int or count < 0:
                raise ValueError("Candidate distinctValueCount must be a non-negative integer")
            suffix = "" if count == 1 else "s"
            lines.append(f"- Values: {count} distinct observed value{suffix} (raw values omitted).")
        if kind == "namingPattern":
            lines.append("- Limitation: Matching this format does not prove naming intent or semantic correctness.")
        if "decision" in candidate:
            decision = object_value(candidate["decision"], "candidate.decision")
            lines.extend([
                "- Promotion review: Retained as a candidate; no authoritative rule was created.",
                f"- Review confidence: {markdown_code(text(decision.get('confidence'), 'candidate.decision.confidence'))}",
                f"- Review rationale: {text(decision.get('rationale'), 'candidate.decision.rationale')}",
                f"- Review model: {markdown_code(text(decision.get('modelVersion'), 'candidate.decision.modelVersion'))}",
                f"- Review prompt: {markdown_code(text(decision.get('promptVersion'), 'candidate.decision.promptVersion'))}",
                f"- Revalidation due: {markdown_code(text(decision.get('expiresAt'), 'candidate.decision.expiresAt'))}",
            ])
        lines.append("")
    lines.extend(["", "## Evidence gaps and conflicts", ""])
    for item in assessment["evidenceGaps"]:
        lines.append(f"- {item.get('classification', 'UNKNOWN')}: {item.get('message', 'Unspecified evidence gap')}")
    for item in assessment["profileConflicts"]:
        lines.append(f"- UNKNOWN: conflicting rules {', '.join(item['ruleIds'])} for `{item['resourceId']}`")
    if not assessment["evidenceGaps"] and not assessment["profileConflicts"]:
        lines.append("- None.")
    lines.extend(["", "No Azure resources were changed.", ""])
    return "\n".join(lines)


def artifact_descriptor(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {"name": path.name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def verify_run(run_dir: Path) -> dict[str, Any]:
    run = object_value(load_json(run_dir / "run.json"), "run.json")
    declared = {
        text(item.get("name"), "artifact.name"): item
        for item in (object_value(item, "artifact") for item in list_value(run.get("artifacts"), "run.artifacts"))
    }
    if set(declared) != set(ARTIFACTS):
        raise ValueError("run.json artifact set is incomplete or unexpected")
    for name in ARTIFACTS:
        actual = artifact_descriptor(run_dir / name)
        if actual != declared[name]:
            raise ValueError(f"Artifact verification failed for {name}")
    profile = object_value(load_json(run_dir / "governance-profile.json"), "governance profile")
    assessment = object_value(load_json(run_dir / "assessment.json"), "assessment")
    if digest(profile) != assessment.get("profileDigest"):
        raise ValueError("Assessment profile digest does not match the profile artifact")
    return run


def build(args: argparse.Namespace) -> Path:
    now = parse_time(args.now, "--now") if args.now else utc_now()
    resource_document = object_value(load_json(args.resources), "resources input")
    resources = [normalize_resource(item) for item in list_value(resource_document.get("resources"), "resources")]
    coverage = object_value(resource_document.get("coverage"), "resources.coverage")
    collected_at = text(resource_document.get("collectedAt"), "resources.collectedAt")
    policy = object_value(load_json(args.policy_evidence), "policy evidence") if args.policy_evidence else {}
    decisions = list_value(load_json(args.ai_decisions), "AI decisions") if args.ai_decisions else []

    previous_run = previous_profile = previous_assessment = None
    if args.previous_run:
        previous_run = verify_run(args.previous_run)
        previous_profile = object_value(load_json(args.previous_run / "governance-profile.json"), "previous profile")
        previous_assessment = object_value(load_json(args.previous_run / "assessment.json"), "previous assessment")

    profile, profile_errors = build_profile(
        resources, args.scope_id, now, previous_profile, previous_run,
        args.plugin_build, coverage, decisions,
    )
    assessment = evaluate(profile, resources, now, coverage, profile_errors)
    is_compatible = bool(
        previous_run
        and previous_run.get("pluginBuild") == args.plugin_build
        and previous_profile.get("profileVersion") == profile["profileVersion"]
    )
    delta = build_delta(previous_assessment, assessment, is_compatible)
    run_id = args.run_id or now.strftime("%Y-%m-%dT%H%M%S000Z-") + secrets.token_hex(4)
    subscription_label = safe_label(args.subscription_label, "--subscription-label")
    scope_folder = safe_label(args.scope_folder, "--scope-folder")
    run_dir = args.output_root / "tag-governance" / subscription_label / scope_folder / run_id
    if run_dir.exists():
        raise FileExistsError(f"Run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)

    finding_ids = {item["resourceId"] for item in assessment["findings"]}
    retained_resources = [
        {
            "id": resource["id"],
            "name": resource["name"],
            "type": resource["type"],
            "tags": {
                key: value for key, value in resource["tags"].items()
                if any(
                    rule.get("tagKey") == key and rule.get("status") == "authoritative"
                    for rule in profile["rules"]
                )
            },
        }
        for resource in resources if resource["id"] in finding_ids
    ]
    observations = {
        "scopeId": args.scope_id,
        "collectedAt": collected_at,
        "classifications": sorted(CLASSIFICATIONS),
        "coverage": coverage,
        "collections": resource_document.get("collections", []),
        "candidateEvidence": [
            {"candidateId": item["id"], "evidence": item["evidence"]}
            for item in profile["candidates"]
        ],
        "declaredPolicyEvidence": {
            "classification": "DECLARED",
            "itemCount": len(policy.get("items", [])) if isinstance(policy.get("items", []), list) else 0,
            "digest": digest(policy),
            "limitations": policy.get("limitations", []),
        },
        "retainedFindingResources": retained_resources,
    }
    write_json(run_dir / "governance-profile.json", profile)
    write_json(run_dir / "observations.json", observations)
    write_json(run_dir / "assessment.json", assessment)
    write_json(run_dir / "delta.json", delta)
    (run_dir / "executive-report.md").write_text(
        executive_report(run_id, assessment, profile, coverage), encoding="utf-8", newline="\n",
    )
    (run_dir / "engineering-report.md").write_text(
        engineering_report(run_id, assessment, profile), encoding="utf-8", newline="\n",
    )
    artifacts = [artifact_descriptor(run_dir / name) for name in ARTIFACTS]
    run = {
        "runId": run_id,
        "status": "Succeeded" if coverage.get("complete") is True and not profile_errors else "SucceededWithWarnings",
        "createdAt": timestamp(now),
        "pluginBuild": args.plugin_build,
        "scopeId": args.scope_id,
        "profileVersion": profile["profileVersion"],
        "previousRunId": previous_run.get("runId") if previous_run else None,
        "coverage": coverage,
        "azureReads": int(resource_document.get("azureReads", 0)),
        "azureMutations": 0,
        "sourceLimitations": resource_document.get("limitations", []),
        "artifacts": artifacts,
    }
    write_json(run_dir / "run.json", run)
    verify_run(run_dir)
    write_json(run_dir.parent / "latest.json", {
        "runId": run_id,
        "profileVersion": profile["profileVersion"],
        "pluginBuild": args.plugin_build,
        "status": run["status"],
        "runPath": run_dir.name,
    })
    return run_dir


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser("build")
    build_command.add_argument("--resources", required=True, type=Path)
    build_command.add_argument("--policy-evidence", type=Path)
    build_command.add_argument("--ai-decisions", type=Path)
    build_command.add_argument("--previous-run", type=Path)
    build_command.add_argument("--output-root", required=True, type=Path)
    build_command.add_argument("--subscription-label", required=True)
    build_command.add_argument("--scope-folder", required=True)
    build_command.add_argument("--scope-id", required=True)
    build_command.add_argument("--plugin-build", required=True)
    build_command.add_argument("--run-id")
    build_command.add_argument("--now")
    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--run-dir", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "build":
            print(build(args))
        else:
            run = verify_run(args.run_dir)
            print(f"PASS: verified {run['runId']}")
        return 0
    except (FileExistsError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
