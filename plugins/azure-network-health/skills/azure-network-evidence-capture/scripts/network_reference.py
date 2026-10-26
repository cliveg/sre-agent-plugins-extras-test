"""Reference-led Azure configuration assessment; observations and findings stay separate."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from collections import Counter
from functools import partial
from pathlib import Path

import evidence_bundle as bundle
import evidence_files as ef
import reference_capture
import reference_profile as profile
import reference_reviews
import network_capture
import network_restriction
import network_timeline


VERSION = "1.0.0"
REPORT_VERSION = "1.0.1"
AREAS = {
    "topology-peering": {
        "title": "Topology, addressing and peering", "operations": ["vnets", "subnets", "peerings"],
        "evaluated": ["Returned address-space relationships", "Directional configured peering and transit context"],
        "unassessed": ["Owner connectivity intent", "Uncollected external networks", "Effective transit and reachability"],
    },
    "routing-egress": {
        "title": "Configured routing and egress", "operations": ["route-tables", "routes", "subnets"],
        "evaluated": ["Configured route-table associations", "Configured next-hop references"],
        "unassessed": ["NIC effective routes", "Learned routes and actual egress/return paths"],
    },
    "network-security": {
        "title": "NSG rules and ingress context", "operations": ["nsgs", "nsg-rules", "ip-attachments", "reference-public-ips"],
        "evaluated": ["Returned subnet NSG associations"],
        "unassessed": ["Effective NIC/subnet/admin rules", "Listeners, source paths and actual reachability", "Rule hit-count coverage"],
    },
    "private-dns": {
        "title": "Private Endpoints and DNS", "operations": [
            "private-endpoints", "private-endpoint-connections", "private-dns-zones", "private-dns-links",
            "private-dns-groups", "vnet-dns-settings", "dns-resolvers", "dns-rulesets",
        ],
        "evaluated": ["Configured endpoint approvals and DNS linkage", "Collected central/custom DNS alternatives"],
        "unassessed": ["Actual client resolution and traffic", "External DNS dependencies", "Owner-approved public exceptions"],
    },
    "telemetry-history": {
        "title": "Existing telemetry and recorded context", "operations": ["reference-monitoring"],
        "evaluated": ["Returned existing flow-log/Connection Monitor configuration"],
        "unassessed": ["Validated log-table/window coverage", "Traffic, latency and rule-usage evidence", "Recorded context not supplied"],
    },
    "firewall-hybrid": {
        "title": "Firewall and hybrid connectivity", "operations": ["reference-firewalls", "reference-hybrid"],
        "evaluated": ["Returned firewall/policy/gateway/circuit/connection configuration"],
        "unassessed": ["Complete firewall rule and hit-count evidence", "BGP/learned/effective routes", "Tunnel/traffic behavior"],
    },
}
FRAMEWORK = {
    "frameworkVersion": VERSION,
    "upstream": [
        {
            "author": "Usman Mahmood", "project": "Azure Networking Assessment Agent",
            "repository": "https://github.com/lavoizer-develop/azure-networking-agent-test-repo",
            "revision": "624bd5c3bf5bd5b8df625cc111c94531dff19148",
            "assets": [".github/agents/azure-networking.agent.md", ".github/skills/assessment-reporting/SKILL.md",
                       ".github/skills/azure-networking/SKILL.md"],
            "classification": "ADAPT",
            "adapted": "scope/evidence/requirements workflow; dashboard and contextual findings, positives, assumptions and artifact verification",
            "permission": "project-owner-reported-2026-10-07; not MIT or independently verified written grant",
        },
        {
            "author": "Daniel Mauser", "project": "Network Desk",
            "repository": "https://github.com/dmauser/network-desk",
            "revision": "4104279fa4707c24e6038b35b2779fecfdd11eea",
            "assets": [
                "extensions/network-desk/specialists/vnet-architect/skills/peering-advisor/SKILL.md",
                "extensions/network-desk/specialists/vnet-architect/skills/network-diagram/SKILL.md",
                "extensions/network-desk/specialists/network-troubleshooter/skills/routing-debug/SKILL.md",
                "extensions/network-desk/specialists/network-security/skills/nsg-audit/SKILL.md",
                "extensions/network-desk/specialists/private-link/skills/dns-integration/SKILL.md",
                "extensions/network-desk/specialists/firewall-engineer/skills/rule-audit/SKILL.md",
                "extensions/network-desk/specialists/hybrid-connectivity/skills/troubleshoot/SKILL.md",
                "extensions/network-desk/specialists/network-monitor/agents/network-monitor.md",
            ],
            "classification": "ADAPT-procedures/COMPOSE-primary-checks",
            "adapted": "Azure-only evidence questions and specialist review sequence; no mutation, active tests or blanket severity heuristics",
            "permission": "MIT; copyright 2025 dmauser; package Network Desk notice retained",
        },
    ],
    "deviations": [
        "Connected Azure evidence replaces assumed repository/IaC implementation evidence.",
        "Both Markdown artifacts are deterministic views of assessment JSON.",
        "No global Healthy status or automatic severity from source heuristics.",
        "Configured relationships and recorded context do not demonstrate traffic or causation.",
    ],
}


def _diagram(model: ef.Record) -> ef.Record:
    labels = {
        "microsoft.network/virtualnetworks": "Azure Virtual Network",
        "microsoft.network/virtualnetworks/subnets": "Subnet",
        "microsoft.network/networksecuritygroups": "Network Security Group",
        "microsoft.network/routetables": "Route table",
    }
    eligible = sorted(
        [row for row in ef.records(model["entities"]) if row["collectionState"] == "collected"
         and row["resourceType"] in labels],
        key=lambda row: (list(labels).index(ef.text(row["resourceType"])), ef.text(row["entityId"])),
    )
    nodes = [{
        "id": "n" + ef.digest(row["entityId"])[:16], "resourceId": row["entityId"],
        "label": labels[ef.text(row["resourceType"])] + ": " + ef.text(row["name"]),
        "evidenceRefs": row["evidenceRefs"],
    } for row in eligible[:80]]
    identifiers = {ef.text(row["resourceId"]): ef.text(row["id"]) for row in nodes}
    candidates = [
        row for row in ef.records(model["relationships"])
        if row["sourceId"] in identifiers and isinstance(row["targetId"], str) and row["targetId"] in identifiers
        and row["relationshipType"] in ("contains", "associatedWithNSG", "associatedWithRouteTable", "peeringTo")
        and row["classification"] == "OBSERVED"
    ]
    edges = [{
        "sourceId": row["sourceId"], "targetId": row["targetId"], "relationshipType": row["relationshipType"],
        "evidenceRefs": row["evidenceRefs"],
    } for row in sorted(candidates, key=lambda row: ef.text(row["relationshipId"]))[:120]]
    lines = ["flowchart LR"]
    for row in nodes:
        label = html.escape(ef.text(row["label"]), quote=True).replace("\n", " ").replace("\r", " ")
        label = label.replace("[", "&#91;").replace("]", "&#93;")
        lines.append("  " + ef.text(row["id"]) + '["' + label + '"]')
    for row in edges:
        lines.append("  " + identifiers[ef.text(row["sourceId"])] + " -->|" + ef.text(row["relationshipType"])
                     + "| " + identifiers[ef.text(row["targetId"])])
    return {
        "status": "bounded-collected-configuration-view" if nodes else "not-generated-insufficient-configuration",
        "relationshipMeaning": "configured-associations-not-traffic", "classification": "INFERRED",
        "viewScope": "collected-VNet/subnet/NSG/route-table-configuration-only",
        "nodes": nodes, "edges": edges, "omittedEligibleNodes": max(0, len(eligible) - len(nodes)),
        "omittedEligibleEdges": max(0, len(candidates) - len(edges)),
        "uncollectedReferencesIncluded": False, "mermaid": "\n".join(lines) if nodes else None,
    }


def _load_source(directory: Path) -> tuple[str, dict[str, bytes]]:
    root = network_capture.checked_root(directory)
    content = ef.read_member(root / "manifest.json", ef.MAX_MANIFEST_BYTES)
    header = ef.decode(content)
    if header.get("profileId") == "reference-network-source":
        manifest = reference_capture.verify(root)
        identifier = ef.text(manifest["sourceId"])
    elif header.get("processorId") == "offline-source-restriction-assessment":
        manifest = network_restriction.verify(root)
        identifier = ef.text(manifest["restrictionId"])
    elif header.get("processorId") == "offline-evidence-timeline":
        manifest = network_timeline.verify(root)
        identifier = ef.text(manifest["timelineId"])
    else:
        raise ValueError("Unsupported comprehensive-review input type")
    return identifier, {
        "manifest.json": content, **{
            ef.text(entry["name"]): ef.read_member(
                root / ef.text(entry["name"]), ef.MAX_MANIFEST_BYTES if ef.text(entry["name"]).endswith("manifest.json") else ef.MAX_MEMBER_BYTES,
            )
            for entry in ef.records(manifest["members"])
        },
    }


def _document(root: Path, run_id: str, inputs: ef.Record, version: str) -> tuple[ef.Record, ef.Record]:
    ef.fields(inputs, {"network"}, {"restriction", "timeline"})
    source_id = ef.text(inputs["network"])
    identifiers = {ef.text(value) for value in inputs.values()}
    if (any(ef.canonical_uuid(value) != value for value in identifiers)
            or {path.name for path in (root / "sources").iterdir()} != identifiers):
        raise ValueError("Reference assessment input role/membership differs")
    source = root / "sources" / source_id
    manifest, documents, manifest_bytes = reference_capture.verified(source)
    timeline_document = None
    if "timeline" in inputs:
        timeline_document = network_timeline.read(root / "sources" / ef.text(inputs["timeline"]))
        timeline_scope = ef.obj(timeline_document["scope"])
        network_scope = ef.obj(manifest["scope"])
        if any(timeline_scope[key] != network_scope[key] for key in ("tenantId", "subscriptionId")):
            raise ValueError("Timeline tenant/subscription differs from network source")
    public_review = None
    if "restriction" in inputs:
        public_id = ef.text(inputs["restriction"])
        folder = root / "sources" / public_id
        network_restriction.verify(folder)
        public = ef.decode(ef.read_member(folder / "assessment.json"))
        public_source = ef.obj(public["source"])
        scope = ef.obj(public_source["scope"])
        expected_scope = ef.obj(manifest["scope"])
        if any(scope[key] != expected_scope[key] for key in ("tenantId", "subscriptionId")):
            raise ValueError("Public-source review tenant/subscription differs from network source")
        public_review = {
            "sourceRunId": public_id, "statistics": public["statistics"], "results": public["results"],
            "collectionWindow": public_source["collectionWindow"],
            "relationship": "separate-source-window-not-merged-current-state",
            "member": "sources/" + public_id + "/assessment.json",
            "memberSha256": hashlib.sha256(ef.read_member(folder / "assessment.json")).hexdigest(),
            "evidenceCatalog": {
                key: {**ef.obj(value), "member": "sources/" + public_id + "/" + ef.text(ef.obj(value)["member"])}
                for key, value in ef.obj(public["evidenceCatalog"]).items()
            },
        }
    envelope = documents["selected-input.json"]
    core = profile.nh.normalize(profile.core_input(envelope))
    base = profile.nh.assess(core)
    collections = ef.records(envelope["collections"])
    recorded_context = None
    if timeline_document is not None:
        targets = {ef.text(row["id"]).lower() for collection in collections for row in ef.records(collection["rows"])}
        contexts: dict[str, ef.Record] = {}
        events = ef.records(timeline_document["events"])
        for event in events:
            target = event["resourceId"]
            if not isinstance(target, str) or target.lower() not in targets:
                continue
            target = target.lower()
            context = contexts.setdefault(target, {"resourceId": target, "eventRevisions": []})
            ef.array(context["eventRevisions"]).append({
                key: event[key] for key in ("id", "revisionId", "sourceId", "times")
            })
        windows = []
        for entry in ef.records(timeline_document["sourceCapsules"]):
            original = ef.obj(entry["manifest"])
            windows.append({
                "capsuleId": entry["capsuleId"], "sourceId": entry["sourceId"],
                "queryWindow": original.get("queryWindow"), "collectionWindow": original["collectionWindow"],
                "manifestSha256": entry["manifestSha256"],
            })
        recorded_context = {
            "timelineId": timeline_document["timelineId"], "eventRevisions": len(events),
            "matchedResourceCount": len(contexts),
            "matchedEventRevisions": sum(len(ef.array(value["eventRevisions"])) for value in contexts.values()),
            "resources": [contexts[key] for key in sorted(contexts)], "sourceWindows": windows,
            "coverage": timeline_document["coverage"],
            "member": "sources/" + ef.text(inputs["timeline"]) + "/timeline.md",
            "causalConclusions": "notGenerated", "currentConfigurationInferredFromEvents": False,
            "relationship": "recorded-resource-context-not-cause-or-atomic-current-state",
        }
    descriptor = next(entry for entry in ef.records(manifest["members"]) if entry["name"] == "selected-input.json")
    evidence: dict[str, ef.Record] = {}
    collection_positions = {ef.text(value["collectionId"]): index for index, value in enumerate(collections)}
    for entry in ef.records(core["evidence"]):
        index = collection_positions[ef.text(entry["collectionId"])]
        rows = ef.records(collections[index]["rows"])
        matches = [position for position, row in enumerate(rows) if ef.text(row["id"]).lower() == entry["subjectId"]]
        if len(matches) != 1:
            raise ValueError("Core evidence does not bind to exactly one original selected row")
        evidence[ef.text(entry["evidenceId"])] = {
            **entry, "member": "sources/" + source_id + "/selected-input.json",
            "memberSha256": descriptor["sha256"], "pointer": "/collections/" + str(index) + "/rows/" + str(matches[0]),
        }
    for index, collection in enumerate(collections):
        if collection["operationId"] not in profile.FIELDS:
            continue
        for position, row in enumerate(ef.records(collection["rows"])):
            identifier = "reference-evidence-" + ef.digest([collection["collectionId"], row["id"]])[:24]
            evidence[identifier] = {
                "evidenceId": identifier, "collectionId": collection["collectionId"],
                "subjectId": ef.text(row["id"]).lower(), "source": collection["source"],
                "collectedAt": collection["completedAt"], "classification": "OBSERVED",
                "member": "sources/" + source_id + "/selected-input.json", "memberSha256": descriptor["sha256"],
                "pointer": "/collections/" + str(index) + "/rows/" + str(position),
                "sourceAssurance": "indexed-configuration-not-effective-state",
            }
    metadata = [{
        key: value for key, value in collection.items() if key != "rows"
    } for collection in collections]
    retention = {
        "sourceSensitivity": "private-customer-network-configuration", "rawResponsesPersisted": False,
        "retentionDecision": "owner-approved-private-output-until-explicit-cleanup",
        "identifiers": "retained-privately-for-evidence-links", "unneededValuesOmitted": True,
    }
    observed = {
        "profileId": "reference-network-observations", "profileVersion": VERSION, "runId": run_id,
        "legacyObservedNetworkModelCompatible": False, "scope": manifest["scope"],
        "sources": [{
            "sourceId": source_id, "sourceVersion": manifest["sourceVersion"],
            "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(), "collectionWindow": manifest["collectionWindow"],
            "authority": "selected-indexed-and-direct-ARM-config; effective-state-not-collected",
        }],
        "normalization": {
            "engineVersion": profile.nh.VERSION, "sourceCatalogVersion": "1.9.0",
            "coreProjectionCatalogVersion": "1.8.0", "projectionDoesNotRewriteSource": True,
        },
        "dataHandling": retention, "collections": metadata,
        **{key: core[key] for key in ("entities", "assertions", "relationships")},
        "specialistObservations": [
            {"operationId": collection["operationId"], "collectionId": collection["collectionId"], "rows": collection["rows"]}
            for collection in collections if collection["operationId"] in profile.FIELDS
        ],
        "evidenceCatalog": evidence, "interpretationsIncluded": False,
    }
    if public_review is not None:
        ef.array(observed["sources"]).append({
            "sourceId": public_review["sourceRunId"], "role": "public-source-review",
            "collectionWindow": public_review["collectionWindow"], "member": public_review["member"],
            "memberSha256": public_review["memberSha256"], "authority": "versioned-derived-assessment-not-new-observation",
        })
    if recorded_context is not None:
        ef.array(observed["sources"]).append({
            "sourceId": recorded_context["timelineId"], "role": "recorded-history-context",
            "member": recorded_context["member"], "sourceWindows": recorded_context["sourceWindows"],
            "authority": "recorded-events-with-original-time-meanings-not-current-config-or-causation",
        })
    findings = ef.records(base["findings"])
    nsg_findings, nsg_details = reference_reviews.nsg_review(envelope, evidence)
    findings.extend(nsg_findings)
    profile.nh.prioritize_findings(findings)
    configuration_reviews = reference_reviews.configured_reviews(envelope)
    scorecard = []
    reviews = []
    for area_id, area in AREAS.items():
        selected = [collection for collection in collections if collection["operationId"] in area["operations"]]
        rows = sum(ef.integer(collection["retainedRowCount"]) for collection in selected)
        complete = all(collection["status"] == "succeeded" for collection in selected)
        state = "configuration-reviewed-with-gaps" if rows and complete else "partial-or-unavailable" if not complete else "no-resources-returned-in-scoped-index"
        review = {
            "areaId": area_id, "area": area["title"], "status": state, "returnedRows": rows,
            "collectionRefs": [collection["collectionId"] for collection in selected],
            "evaluatedQuestions": area["evaluated"], "unassessedQuestions": area["unassessed"],
            "interpretation": "assessment-coverage-not-an-operational-health-grade",
        }
        if area_id in configuration_reviews:
            review["details"] = configuration_reviews[area_id]
        if area_id == "network-security":
            review["details"] = nsg_details
            review["evaluatedQuestions"] = [
                *area["evaluated"], "Broad-source custom inbound management/database selector candidates",
                "Collected public-IP/NIC/subnet configuration references",
            ]
        if area_id == "telemetry-history" and recorded_context is not None:
            ef.obj(review["details"]).update({key: recorded_context[key] for key in (
                "eventRevisions", "matchedResourceCount", "matchedEventRevisions", "sourceWindows", "causalConclusions",
            )})
            review["evaluatedQuestions"] = [*area["evaluated"], "Recorded resource-ID context in the supplied verified timeline"]
            review["unassessedQuestions"] = [
                value for value in area["unassessed"] if value != "Recorded context not supplied"
            ] + ["Event arrival/coverage gaps and causation remain unverified"]
        reviews.append(review)
        scorecard.append({key: review[key] for key in ("areaId", "area", "status", "returnedRows")})
    assessment = {
        "profileId": "reference-network-assessment", "profileVersion": version, "runId": run_id,
        "status": "PARTIAL_CONFIGURATION_ASSESSMENT", "legacyAssessmentSchemaCompatible": False,
        "framework": FRAMEWORK, "scope": manifest["scope"], "sources": observed["sources"],
        "observationArtifact": {"filename": "observed-network.json", "sha256": hashlib.sha256(ef.encoded(observed, compact=True)).hexdigest()},
        "dataHandling": retention, "checksExecuted": [
            *ef.records(base["checksExecuted"]), {"checkId": reference_reviews.NSG_CHECK, "checkVersion": VERSION},
            *({"checkId": check_id, "checkVersion": VERSION} for check_id in reference_reviews.CONFIG_CHECKS),
        ],
        "baseEngine": {"version": profile.nh.VERSION, "catalogVersion": base["checkCatalogVersion"]},
        "accessPreference": base.get("accessPreference"), "requirementsCompliance": "not-assessed-without-supplied-owner-requirements",
        "scorecard": scorecard, "domainReviews": reviews, "findings": findings, "evidenceCatalog": evidence,
        "topologyDiagram": _diagram(core),
        "collectionCatalog": metadata,
        "statistics": {
            "collectedEntities": len(ef.records(core["entities"])), "collectionOutcomes": len(collections),
            "findings": len(findings), "recordTypes": dict(sorted(Counter(ef.text(row["recordType"]) for row in findings).items())),
            "impactSeverities": dict(sorted(Counter(ef.text(row["severity"]) for row in findings if row["severity"] is not None).items())),
            "areas": len(scorecard),
        },
        "limitations": [
            "Fresh configuration is not an atomic environment snapshot or actual packet flow.",
            "Indexed data can lag; absence is limited to returned accessible results, not global completeness.",
            "Effective rules/routes, listeners, BGP/learned routes and validated rule usage are not collected by this pass.",
            "Private Endpoint approval/DNS configuration is not client resolution or private-only access.",
            "No customer architecture, IaC authority, business criticality or public-access exceptions were invented.",
            "No resource, logging, monitor, role or identity changes; no active tests or automatic remediation.",
            "No memory maintenance or schedule is part of this workflow.",
        ],
    }
    # Published 1.0.0 statistics remain byte-for-byte reproducible.
    if version == REPORT_VERSION:
        statistics = ef.obj(assessment["statistics"])
        statistics["normalizedEntities"] = statistics["collectedEntities"]
        statistics["collectedEntities"] = sum(
            row["collectionState"] == "collected" for row in ef.records(core["entities"])
        )
    if public_review is not None:
        assessment["publicSourceReview"] = public_review
    if recorded_context is not None:
        assessment["recordedContext"] = recorded_context
    return observed, assessment


def _text(value: object) -> str:
    return html.escape(str(value)).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def render(assessment: ef.Record) -> tuple[bytes, bytes]:
    if assessment["profileId"] != "reference-network-assessment" or assessment["profileVersion"] not in (VERSION, REPORT_VERSION):
        raise ValueError("Unsupported reference assessment renderer profile")
    sources = ef.records(assessment["sources"])
    window = ef.obj(sources[0]["collectionWindow"])
    header = [
        "# Azure Network Assessment Dashboard", "",
        "**Run:** " + _text(assessment["runId"]), "**Assessment status:** " + _text(assessment["status"]),
        "**Configuration window:** " + _text(window["startedAtUtc"]) + " through " + _text(window["completedAtUtc"]), "",
        "Prototype, read-only configuration assessment; not effective connectivity, customer compliance or operational-health certification.", "",
    ]
    summary = [*header, "## Executive summary", "",
        "The review composes existing network checks and attributed specialist procedures. "
        "Reported coverage describes evidence actually evaluated, not a global health score. "
        "Missing/effective/operational evidence is explicitly identified; zero findings does not mean Healthy.", "",
        "## Assessment scorecard", "", "| Area | Assessment coverage | Returned rows |", "|---|---|---:|",
    ]
    for row in ef.records(assessment["scorecard"]):
        summary.append("| " + " | ".join(_text(row[key]) for key in ("area", "status", "returnedRows")) + " |")
    diagram = ef.obj(assessment["topologyDiagram"])
    summary.extend([
        "", "## Configuration architecture", "",
        "Arrows show collected resource containment/configuration associations, not packet flow, transit or reachability. "
        "Uncollected references are excluded; this is a bounded view, not the entire environment.", "",
    ])
    if diagram["mermaid"] is not None:
        summary.extend(["```mermaid", ef.text(diagram["mermaid"]), "```", "",
                        "Omitted eligible nodes/edges: " + _text(diagram["omittedEligibleNodes"]) + " / "
                        + _text(diagram["omittedEligibleEdges"]) + ".", ""])
    else:
        summary.extend(["No diagram is asserted without suitable collected configuration.", ""])
    if "publicSourceReview" in assessment:
        public = ef.obj(assessment["publicSourceReview"])
        window = ef.obj(public["collectionWindow"])
        statistics = ef.obj(public["statistics"])
        summary.extend([
            "", "## Public-source restriction context", "",
            "Independent source window: " + _text(window["startedAtUtc"]) + " through " + _text(window["completedAtUtc"]) + ".",
            "Service paths: " + _text(statistics["servicePaths"]) + "; overall criterion counts: "
            + _text(statistics["criterionVerdicts"]) + ". This source window is not silently merged into current network state.",
            "[Original verified assessment](" + ef.text(public["member"]) + ")", "",
        ])
    if "recordedContext" in assessment:
        context = ef.obj(assessment["recordedContext"])
        summary.extend([
            "", "## Recorded change and health context", "",
            "Source event revisions: " + _text(context["eventRevisions"]) + "; matched network resources: "
            + _text(context["matchedResourceCount"]) + "; matched revisions: " + _text(context["matchedEventRevisions"]) + ".",
            "Resource-ID context is not causation or proof of current configuration. Original windows and source-specific gaps remain distinct.",
            "[Verified recorded timeline](" + ef.text(context["member"]) + ")", "",
        ])
    summary.extend(["", "## Prioritized next actions", "", "| Priority | Type | Finding | Next action |", "|---|---|---|---|"])
    findings = ef.records(assessment["findings"])
    for finding in findings:
        priority = ef.obj(finding["priority"])
        summary.append("| " + " | ".join(_text(value) for value in (
            str(priority["rank"]) + " / " + str(priority["band"]), finding["recordType"],
            finding["title"], finding["recommendation"],
        )) + " |")
    summary.extend(["", "## Positive observations", ""])
    positives = [finding for finding in findings if finding["recordType"] == "positiveObservation"]
    summary.extend("- " + _text(finding["title"]) for finding in positives)
    if not positives:
        summary.append("No positive observation is asserted from missing or unsuitable evidence.")
    summary.extend(["", "## Assumptions and validation required", ""])
    for review in ef.records(assessment["domainReviews"]):
        summary.append("- **" + _text(review["area"]) + ":** " + "; ".join(
            _text(value) for value in ef.array(review["unassessedQuestions"])
        ))
    engineering = [*header, "## Evidence and source coverage", "",
        "[Assessment JSON](assessment.json) is authoritative; [observations](observed-network.json) contain no interpreted findings.", "",
        "| Operation | Status | Retained rows | Issues |", "|---|---|---:|---|",
    ]
    for collection in ef.records(assessment["collectionCatalog"]):
        engineering.append("| " + " | ".join(_text(value) for value in (
            collection["operationId"], collection["status"], collection["retainedRowCount"],
            "; ".join(ef.text(value) for value in ef.array(collection["issues"])),
        )) + " |")
    engineering.extend(["", "## Specialist review coverage", ""])
    for review in ef.records(assessment["domainReviews"]):
        engineering.extend([
            "### " + _text(review["area"]), "",
            "**Observed state:** " + _text(review["status"]) + "; returned rows: " + _text(review["returnedRows"]),
            "**Expected state:** Applicable declared requirements and supported platform behavior; owner-specific intent is not assumed.",
            "**Risk:** Uncollected effective/operational evidence limits conclusions; configured references are not actual traffic.",
            "**Dependencies / considerations:** " + "; ".join(_text(value) for value in ef.array(review["unassessedQuestions"])), "",
        ])
        if review["areaId"] == "firewall-hybrid":
            details = ef.obj(review["details"])
            engineering.extend([
                "| Firewall/policy | Rule review | Effective enforcement |", "|---|---|---|",
                *("| " + " | ".join(_text(row[key]) for key in (
                    "resourceId", "completeRuleReview", "effectiveEnforcement",
                )) + " |" for row in ef.records(details["firewallResources"])), "",
                "| Hybrid resource | Reported coarse connection state | Effective routing |", "|---|---|---|",
                *("| " + " | ".join(_text(row[key]) for key in (
                    "resourceId", "reportedConnectionStatus", "effectiveRouting",
                )) + " |" for row in ef.records(details["hybridResources"])), "",
                "These indexed states do not establish traffic, BGP exchange or an outage.", "",
            ])
        if review["areaId"] == "telemetry-history":
            engineering.extend([
                "| Existing monitoring resource | Configured enabled | Data coverage verified |", "|---|---|---|",
                *("| " + " | ".join(_text(row[key]) for key in (
                    "resourceId", "configuredEnabled", "dataCoverageVerified",
                )) + " |" for row in ef.records(ef.obj(review["details"])["existingMonitoring"])), "",
            ])
    engineering.extend(["## Findings", ""])
    if "recordedContext" in assessment:
        context = ef.obj(assessment["recordedContext"])
        engineering.extend([
            "## Recorded resource context", "",
            "Recorded events, not configuration outcomes or causes. Full original sources and time meanings remain embedded.", "",
            "| Resource | Recorded revisions |", "|---|---:|",
            *("| " + _text(row["resourceId"]) + " | " + str(len(ef.array(row["eventRevisions"]))) + " |"
              for row in ef.records(context["resources"])), "",
            "[Original verified timeline](" + ef.text(context["member"]) + ")", "",
        ])
    if "publicSourceReview" in assessment:
        public = ef.obj(assessment["publicSourceReview"])
        engineering.extend([
            "## Public-source path results", "",
            "These retain their separate source window and versioned criteria; no private-connectivity or effective-enforcement certification.", "",
            "| Resource | Path | Local setting | Overall criterion |", "|---|---|---|---|",
            *("| " + " | ".join(_text(row[key]) for key in (
                "resourceId", "path", "serviceConfiguration", "criterionVerdict",
            )) + " |" for row in ef.records(public["results"])), "",
            "[Original verified source review](" + ef.text(public["member"]) + ")", "",
        ])
    catalog = ef.obj(assessment["evidenceCatalog"])
    for finding in findings:
        engineering.extend([
            "### " + _text(finding["findingId"]) + " - " + _text(finding["title"]), "",
            "**Check:** " + _text(finding["checkId"]) + " / " + _text(finding["checkVersion"]),
            "**Record / impact severity:** " + _text(finding["recordType"]) + " / " + _text(finding["severity"]),
            "**Confidence:** " + _text(finding["confidence"]),
            "**Observed state:** " + _text(finding["observedState"]),
            "**Expected state:** " + _text(finding["expectedState"] if finding["expectedState"] is not None else "No owner-specific requirement supplied."),
            "**Risk:** " + _text(finding["risk"]),
            "**Recommendation:** " + _text(finding["recommendation"]),
            "**Dependencies / considerations:** " + "; ".join(_text(value) for value in ef.array(finding["dependencies"])), "",
        ])
        if "actualReachability" in finding:
            engineering.extend([
                "**Configured ingress evidence:** " + _text(finding["ingressEvidence"]),
                "**Actual reachability:** " + _text(finding["actualReachability"]), "",
            ])
        for evidence_id in ef.array(finding["evidenceRefs"]):
            reference = ef.obj(catalog[ef.text(evidence_id)])
            engineering.append("- [Retained source](" + ef.text(reference["member"]) + ") `" + ef.text(reference["pointer"]) + "`")
        engineering.append("")
    attribution = ["", "## Framework and technical lineage", ""]
    for upstream in ef.records(ef.obj(assessment["framework"])["upstream"]):
        attribution.append("- " + _text(upstream["author"]) + " / " + _text(upstream["project"]) + ": "
                           + _text(upstream["adapted"]) + "; revision `" + ef.text(upstream["revision"]) + "`.")
    limitations = ["", "## Limitations", "", *("- " + _text(value) for value in ef.array(assessment["limitations"])), ""]
    return ("\n".join([*summary, *attribution, *limitations]).encode(),
            "\n".join([*engineering, *attribution, *limitations]).encode())


def _views(root: Path, run_id: str, inputs: ef.Record, *, version: str = REPORT_VERSION) -> dict[str, bytes]:
    observed, assessment = _document(root, run_id, inputs, version)
    summary, engineering = render(assessment)
    return {"observed-network.json": ef.encoded(observed, compact=True), "assessment.json": ef.encoded(assessment),
            "network-assessment.md": summary, "network-evidence.md": engineering}


def build(network_source: Path, run_id: str, output_root: Path, *, restriction: Path | None = None,
          timeline: Path | None = None) -> Path:
    manifest = reference_capture.verify(network_source)
    sources = [network_source]
    inputs = {"network": manifest["sourceId"]}
    if restriction is not None:
        sources.append(restriction)
        inputs["restriction"] = network_restriction.verify(restriction)["restrictionId"]
    if timeline is not None:
        sources.append(timeline)
        inputs["timeline"] = network_timeline.verify(timeline)["timelineId"]
    return bundle.build(
        sources, run_id, output_root, "review", _views,
        inputs=inputs, source_loader=_load_source, version=REPORT_VERSION,
    )


def verify(directory: Path) -> ef.Record:
    root = network_capture.checked_root(directory)
    version = ef.text(ef.decode(ef.read_member(root / bundle.MANIFEST, ef.MAX_MANIFEST_BYTES))["processorVersion"])
    return bundle.verify(root, "review", partial(_views, version=version), version=version)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    create = actions.add_parser("build")
    create.add_argument("--network-source", required=True, type=Path)
    create.add_argument("--run-id", required=True)
    create.add_argument("--output-root", required=True, type=Path)
    create.add_argument("--restriction", type=Path)
    create.add_argument("--timeline", type=Path)
    check = actions.add_parser("verify")
    check.add_argument("--review", required=True, type=Path)
    args = parser.parse_args()
    directory = build(
        args.network_source, args.run_id, args.output_root, restriction=args.restriction, timeline=args.timeline,
    ) if args.command == "build" else args.review
    manifest = verify(directory)
    assessment = ef.decode(ef.read_member(directory / "assessment.json"))
    statistics = ef.obj(assessment["statistics"])
    print(json.dumps({
        "review": str(directory), "reviewId": manifest["reviewId"],
        "status": "verified-reference-network-review", **statistics,
        "azureReads": 0, "memoryWrites": 0,
        "assuranceScope": "processor-only; installation-and-surrounding-agent-actions-require-separate-audit",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
