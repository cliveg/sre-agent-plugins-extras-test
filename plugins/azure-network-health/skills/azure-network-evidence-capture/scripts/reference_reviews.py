"""Read-only specialist procedures adapted with the attribution in the source map."""

from __future__ import annotations

import re

import evidence_files as ef
import network_restriction as restriction


VERSION = "1.0.0"
NSG_CHECK = "NET-NSG-002"
PORTS = (22, 3389, 5985, 5986, 1433, 3306, 5432, 6379, 27017)
CONFIG_CHECKS = ("NET-FW-CONFIG-001", "NET-HYBRID-CONFIG-001", "NET-TELEMETRY-001")


def configured_reviews(envelope: ef.Record) -> dict[str, ef.Record]:
    collections = {ef.text(row["operationId"]): row for row in ef.records(envelope["collections"])}
    firewalls = []
    for row in ef.records(collections["reference-firewalls"]["rows"]):
        properties = ef.obj(row["properties"])
        firewalls.append({
            "resourceId": row["id"], "resourceType": row["type"], "configuration": properties,
            "policyReference": properties.get("firewallPolicyId"),
            "completeRuleReview": "not-collected", "effectiveEnforcement": "UNKNOWN",
            "nextEvidence": [
                "Confirm the authoritative firewall/policy configuration and applicable classic versus policy rules.",
                "Read-only export of applicable rule-collection groups and validated existing diagnostic/log coverage.",
                "Owner rule intent; never infer unused rules from unverified zero hits or assign severity from CIDR width.",
            ],
        })
    hybrid = []
    for row in ef.records(collections["reference-hybrid"]["rows"]):
        properties = ef.obj(row["properties"])
        hybrid.append({
            "resourceId": row["id"], "resourceType": row["type"], "configuration": properties,
            "reportedConnectionStatus": properties.get("connectionStatus"),
            "effectiveRouting": "UNKNOWN", "bgpAndLearnedRoutes": "not-collected",
            "statusInterpretation": "coarse-indexed-state-not-traffic-or-outage-proof",
            "nextEvidence": [
                "Confirm applicable authoritative connection/gateway/circuit and counterpart configuration.",
                "Separately scoped read-only BGP peer, learned-route and effective-route evidence where supported.",
                "Never request shared keys/circuit authorization keys or infer traffic from a Connected label.",
            ],
        })
    monitoring = []
    for row in ef.records(collections["reference-monitoring"]["rows"]):
        properties = ef.obj(row["properties"])
        monitoring.append({
            "resourceId": row["id"], "resourceType": row["type"], "configuration": properties,
            "configuredEnabled": properties.get("enabled"), "dataCoverageVerified": "UNKNOWN",
            "usageOrHealthAssessed": False,
            "nextEvidence": [
                "Verify existing destination, table/schema, retention and query-window coverage before interpreting usage.",
                "Inventory/configuration is not evidence of emitted flows, successful tests, latency or anomaly baselines.",
                "No log/monitor enablement, new tests, dashboards or alerts are part of assessment.",
            ],
        })
    return {
        "firewall-hybrid": {
            "firewallResources": firewalls, "hybridResources": hybrid,
            "indexOnly": True, "keysOrCredentialsCollected": False,
            "scopedEmptyInterpretation": "no-returned-config-in-this-indexed-scope; not global absence or health",
        },
        "telemetry-history": {
            "existingMonitoring": monitoring, "configuredTelemetryRows": len(monitoring),
            "networkLogCoverage": "UNKNOWN", "ruleUsageAndUnusedRules": "not-assessed",
        },
    }


def _values(properties: ef.Record, singular: str, plural: str) -> tuple[list[str], str | None]:
    one, many = properties.get(singular), properties.get(plural)
    if one not in (None, "") and many not in (None, []):
        return [], "ConflictingSingularPluralSelectors"
    if one not in (None, ""):
        return ([one], None) if isinstance(one, str) else ([], "UnsupportedSelectorShape")
    if isinstance(many, list) and many:
        if len(many) > ef.MAX_ROWS or any(not isinstance(value, str) for value in many):
            return [], "UnsupportedSelectorShape"
        return [ef.text(value) for value in many], None
    return [], "SelectorNotReturned"


def _ports(values: list[str]) -> tuple[list[int], str | None]:
    matches = set()
    for value in values:
        if value == "*":
            matches.update(PORTS)
            continue
        if re.fullmatch(r"[0-9]+(?:-[0-9]+)?", value) is None:
            return [], "MalformedPortSelector"
        parts = value.split("-")
        first, last = int(parts[0]), int(parts[-1])
        if not 0 <= first <= last <= 65535:
            return [], "MalformedPortSelector"
        matches.update(port for port in PORTS if first <= port <= last)
    return sorted(matches), None


def _broad(values: list[str]) -> tuple[bool, str | None]:
    if any(value.casefold() in ("*", "internet") for value in values):
        return True, None
    result = restriction.address_coverage(list[object](values))
    if result["status"] == "UNKNOWN":
        return False, "SourceSelectorNotQualified"
    if ef.obj(result["ipv4"])["internetCoverage"] == "ALL" or ef.obj(result["ipv6"])["coversEntireFamily"] is True:
        return True, None
    if ef.integer(ef.obj(result["ipv6"])["selectorCount"]):
        return False, "IPv6PublicUniverseNotQualified"
    return False, None


def nsg_review(envelope: ef.Record, catalog: ef.Record) -> tuple[list[ef.Record], ef.Record]:
    collections = {ef.text(row["operationId"]): row for row in ef.records(envelope["collections"])}
    rules = ef.records(collections["nsg-rules"]["rows"])
    subnets = ef.records(collections["subnets"]["rows"])
    attachments = ef.records(collections["ip-attachments"]["rows"])
    public_ips = ef.records(collections["reference-public-ips"]["rows"])
    evidence_by_subject: dict[str, list[str]] = {}
    for evidence_id, value in catalog.items():
        reference = ef.obj(value)
        evidence_by_subject.setdefault(ef.text(reference["subjectId"]).lower(), []).append(evidence_id)
    findings: list[ef.Record] = []
    gaps: list[ef.Record] = []
    reviewed = 0
    for rule in rules:
        properties = ef.obj(rule["properties"])
        if properties.get("isDefault") is True:
            continue
        direction, access = properties.get("direction"), properties.get("access")
        if not isinstance(direction, str) or direction.casefold() not in ("inbound", "outbound"):
            gaps.append({"resourceId": rule["id"], "reason": "DirectionUnavailable"})
            continue
        if not isinstance(access, str) or access.casefold() not in ("allow", "deny"):
            gaps.append({"resourceId": rule["id"], "reason": "AccessUnavailable"})
            continue
        if direction.casefold() != "inbound" or access.casefold() != "allow":
            continue
        if properties.get("isDefault") is not False:
            gaps.append({"resourceId": rule["id"], "reason": "CustomRuleKindUnavailable"})
            continue
        reviewed += 1
        protocol = properties.get("protocol")
        if not isinstance(protocol, str):
            gaps.append({"resourceId": rule["id"], "reason": "ProtocolUnavailable"})
            continue
        if protocol.casefold() not in ("tcp", "*"):
            continue
        sources, error = _values(properties, "sourceAddressPrefix", "sourceAddressPrefixes")
        if error is not None:
            gaps.append({"resourceId": rule["id"], "reason": error})
            continue
        broad, error = _broad(sources)
        if error is not None:
            gaps.append({"resourceId": rule["id"], "reason": error})
        if not broad:
            continue
        ports, error = _values(properties, "destinationPortRange", "destinationPortRanges")
        matching, port_error = _ports(ports) if error is None else ([], error)
        if port_error is not None:
            gaps.append({"resourceId": rule["id"], "reason": port_error})
            continue
        if not matching:
            continue
        parent = ef.text(rule["parentId"]).lower()
        related = {ef.text(rule["id"]).lower(), parent}
        ingress = "not-established-from-collected-configuration"
        for subnet in subnets:
            nsg = ef.obj(subnet["properties"]).get("networkSecurityGroupId")
            if not isinstance(nsg, str) or nsg.lower() != parent:
                continue
            related.add(ef.text(subnet["id"]).lower())
            for attachment in attachments:
                attached_subnet = ef.obj(attachment["properties"]).get("subnetId")
                if not isinstance(attached_subnet, str) or attached_subnet.lower() != ef.text(subnet["id"]).lower():
                    continue
                attachment_id = ef.text(attachment["id"])
                if re.search(r"/providers/microsoft\.network/networkinterfaces/[^/]+/ipconfigurations/[^/]+$",
                             attachment_id, re.IGNORECASE) is None:
                    continue
                for public_ip in public_ips:
                    props = ef.obj(public_ip["properties"])
                    target = props.get("ipConfigurationId")
                    if (isinstance(target, str) and target.lower() == attachment_id.lower()
                            and props.get("ipAddressKnown") is True and props.get("ipAddressPresent") is True):
                        ingress = "configured-public-ip-nic-subnet-reference"
                        related.update((attachment_id.lower(), ef.text(public_ip["id"]).lower()))
        refs = sorted({value for subject in related for value in evidence_by_subject.get(subject, [])})
        identifier = "NET-" + ef.digest([NSG_CHECK, rule["id"]])[:24]
        findings.append({
            "findingId": identifier, "checkId": NSG_CHECK, "checkVersion": VERSION,
            "title": "Broad-source inbound management/database rule requires contextual validation",
            "category": "Network security", "recordType": "potentialRisk", "severity": None,
            "interpretationClassification": "INFERRED", "confidence": "medium",
            "affectedResources": sorted(related), "evidenceRefs": refs,
            "collectionRefs": [collections["nsg-rules"]["collectionId"], collections["reference-public-ips"]["collectionId"]],
            "observedState": "Returned custom inbound Allow configuration matches a broad source and review port(s) "
                             + ", ".join(str(port) for port in matching) + "; ingress evidence: " + ingress + ".",
            "expectedState": "Validate the owner-approved source scope and management-access design; no customer policy is assumed.",
            "risk": "The configuration could permit broad-source access if other path and enforcement conditions allow. "
                    "Neither this rule nor the collected attachment references establish actual reachability.",
            "recommendation": "Validate intended sources, effective NIC/subnet/admin rules, routing and listeners before assigning impact or planning changes.",
            "dependencies": [
                "Owner source/port applicability and documented exceptions", "Earlier-priority and effective NIC/subnet rules",
                "Security-admin overrides", "Effective routes and actual listeners", "No automatic remediation",
            ],
            "reasoning": "Adapted configured-rule review; Network Desk's unconditional severity is intentionally not imported.",
            "evidenceGaps": ["Effective rule evaluation", "Actual reachability", "Validated rule-usage coverage"],
            "actualReachability": "UNKNOWN", "ingressEvidence": ingress,
            "priority": {"rank": 0, "band": "P2", "actionType": "evidenceCollection",
                         "reason": "Collect the missing path/enforcement/context evidence; impact and urgency are not established."},
            "guidanceReferences": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works"],
            "recommendedDeepDive": {
                "domain": "Network security", "question": "Is the broad rule applicable to an intended ingress path after all controls?",
                "requiredEvidence": ["Effective rules/routes", "Owner intent and listeners"], "execution": "recommendationOnly",
            },
        })
    return findings, {
        "returnedRules": len(rules), "customInboundAllowRulesReviewed": reviewed,
        "broadSourceRuleCandidates": len(findings), "ruleReviewGaps": gaps,
        "effectiveRuleEvaluation": "not-collected", "unusedRuleClassification": "not-assessed",
        "portPolicy": {"ports": list(PORTS), "meaning": "review examples, not Azure-assigned management ports or severity"},
    }
