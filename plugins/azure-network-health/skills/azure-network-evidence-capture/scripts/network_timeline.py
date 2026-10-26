"""Build and verify an offline, self-contained view of retained evidence."""

from __future__ import annotations

import argparse
import hashlib
import html
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

import evidence_files as ef
import evidence_bundle as bundle
import network_capture as capture
from workspace_activity import time_key


VERSION = "1.0.0"
COMPACT_VERSION = "1.1.0"
PROCESSOR = "offline-evidence-timeline"
MANIFEST = "manifest.json"
JSON = "timeline.json"
MARKDOWN = "timeline.md"
MAX_CAPSULES = 20
MAX_RECORDS = 20000
SOURCE_IDS = ("configuration", "activity-log", "workspace-activity", "resource-changes", "service-health")
SECTIONS = {
    "events": "events", "configurationObservations": "configuration-observations",
    "resources": "resources", "correlationGroups": "correlation-groups",
    "unboundEventRevisions": "unbound-events",
}
PAGE_ROWS = 500
MAX_SECTION_PAGES = 100


def _event_order(event: ef.Record) -> tuple[bool, tuple[datetime, int] | None, str, str]:
    times = ef.obj(event["times"])
    anchor = times["eventTime"] if times["eventTime"] is not None else times["sourceUpdatedTime"]
    return anchor is None, time_key(anchor) if anchor is not None else None, ef.text(event["id"]), ef.text(event["revisionId"])


def _reference(reference: ef.Record, capsule_id: str, manifest_hash: str,
               descriptors: dict[str, ef.Record]) -> ef.Record:
    member = ef.text(reference["member"])
    return {
        **reference, "capsuleId": capsule_id, "manifestSha256": manifest_hash,
        "member": "sources/" + capsule_id + "/" + member, "memberSha256": descriptors[member]["sha256"],
    }


def _resource(value: object, subscription: str) -> str | None:
    if value is None or value == "":
        return None
    identifier = ef.text(value).rstrip("/").lower()
    prefix = "/subscriptions/" + subscription
    if identifier != prefix and not identifier.startswith(prefix + "/"):
        raise ValueError("Recorded resource target exceeds timeline subscription scope")
    return identifier


def _context(source: str, record: ef.Record, subscription: str) -> tuple[str | None, str | None]:
    if source == "workspace-activity":
        target, correlation = record.get("ResourceId"), record.get("CorrelationId")
    elif source == "activity-log":
        target, correlation = record.get("resourceId"), record.get("correlationId")
    elif source == "resource-changes":
        target = record.get("targetResourceId")
        attributes = record.get("changeAttributes")
        correlation = ef.obj(attributes).get("correlationId") if attributes is not None else None
    else:
        target, correlation = None, None
    return _resource(target, subscription), ef.text(correlation) if correlation not in (None, "") else None


def _source_outcomes(sources: list[ef.Record]) -> list[ef.Record]:
    result = []
    for source in sources:
        manifest = ef.obj(source["manifest"])
        coverage = ef.obj(manifest["coverage"])
        configuration = source["sourceId"] == "configuration"
        collections = ef.records(coverage["collections" if configuration else "pages"])
        result.append({
            "capsuleId": source["capsuleId"], "sourceId": source["sourceId"],
            "outcomes": dict(sorted(Counter(ef.text(entry["status"]) for entry in collections).items())),
            "retainedRecords": None if configuration else coverage["retainedRecords"],
            "unperformedOperations": coverage["unperformedOperations"] if configuration else [],
            "unconfirmedAttempts": len(ef.array(coverage["unconfirmedAttempts"])),
            "requestedWindow": None if configuration else manifest["requestedWindow"],
            "queryWindow": None if configuration else manifest["queryWindow"],
            "readiness": coverage["readiness"] if source["sourceId"] == "workspace-activity" else None,
        })
    return result


def _parents(sources: list[ef.Record]) -> list[ef.Record]:
    by_id = {ef.text(source["capsuleId"]): source for source in sources}
    result = []
    for source in sources:
        manifest = ef.obj(source["manifest"])
        if source["sourceId"] == "configuration" or manifest["parentCapsule"] is None:
            continue
        parent = ef.obj(manifest["parentCapsule"])
        provided = by_id.get(ef.text(parent["capsuleId"]))
        if provided is not None and (
            provided["manifestSha256"] != parent["manifestSha256"] or provided["sourceKey"] != source["sourceKey"]
            or ef.obj(provided["manifest"])["scope"] != manifest["scope"]
        ):
            raise ValueError("Timeline parent source/manifest binding mismatch")
        result.append({
            "capsuleId": source["capsuleId"], "parentCapsuleId": parent["capsuleId"],
            "expectedManifestSha256": parent["manifestSha256"],
            "state": "verified" if provided is not None else "notProvided",
        })
    return result


def _document(root: Path, identifier: str) -> ef.Record:
    sources: list[ef.Record] = []
    events: dict[tuple[str, str], ef.Record] = {}
    observations: list[ef.Record] = []
    scope = None
    input_rows = 0
    source_root = root / "sources"
    ef.normal_path(source_root)
    for directory in sorted(source_root.iterdir()):
        manifest = capture.verify(directory)
        approved = ef.obj(manifest["scope"])
        current_scope = {key: approved[key] for key in ("tenantId", "subscriptionId")}
        if scope is not None and scope != current_scope:
            raise ValueError("Timeline source tenant/subscription scope differs")
        scope = current_scope
        capsule_id = ef.text(manifest["capsuleId"])
        if directory.name != capsule_id:
            raise ValueError("Timeline source directory and capsule identity differ")
        replay = capture.replay(directory)
        configuration = manifest["profileId"] == capture.PROFILE
        source_id = "configuration" if configuration else ef.text(manifest["sourceId"])
        manifest_hash = hashlib.sha256(ef.read_member(directory / MANIFEST, ef.MAX_MANIFEST_BYTES)).hexdigest()
        source_key = ef.digest([
            current_scope, source_id, manifest["profileId"], manifest["profileVersion"], manifest["profileSha256"],
            ef.obj(manifest["workspace"])["workspaceId"] if "workspace" in manifest else None,
        ])
        sources.append({"capsuleId": capsule_id, "directory": "sources/" + capsule_id,
                        "manifestSha256": manifest_hash, "sourceKey": source_key, "sourceId": source_id,
                        "manifest": manifest})
        descriptors = {ef.text(entry["name"]): entry for entry in ef.records(manifest["members"])}
        if configuration:
            for resource in ef.records(replay["resources"]):
                for observation in ef.records(resource["observations"]):
                    reference = _reference({
                        "member": observation["member"], "pointer": observation["pointer"],
                        "collectionStartedAt": observation["startedAtUtc"],
                        "collectionCompletedAt": observation["completedAtUtc"],
                        "requestId": observation["requestId"], "omittedPaths": observation["omittedPaths"],
                    }, capsule_id, manifest_hash, descriptors)
                    observations.append({
                        "id": "observation-" + ef.digest([capsule_id, observation["member"], observation["pointer"]]),
                        "resourceId": resource["id"], "resourceType": resource["type"],
                        "retainedPayloadSha256": ef.digest(observation["configuration"]), "evidence": reference,
                    })
            continue
        input_rows += ef.integer(ef.obj(manifest["coverage"])["retainedRecords"])
        for event in ef.records(replay["events"]):
            record = ef.obj(event["record"])
            evidence = [_reference(reference, capsule_id, manifest_hash, descriptors)
                        for reference in ef.records(event["evidence"])]
            target, correlation = _context(source_id, record, ef.text(approved["subscriptionId"]))
            identity = ef.digest([source_key, event["sourceEventId"]]) if event["sourceEventId"] is not None else ef.digest(
                [source_key, capsule_id, event["id"]]
            )
            value = events.setdefault((identity, ef.text(event["revisionId"])), {
                "id": "event-" + identity, "sourceKey": source_key,
                "sourceId": source_id, "revisionId": event["revisionId"],
                "sourceEventId": event["sourceEventId"], "identityAssurance": event["identityAssurance"],
                "resourceId": target, "correlationId": correlation,
                "times": {key: event[key] for key in ("eventTime", "sourceUpdatedTime", "submissionTime")}
                         | {"ingestionTime": record.get("IngestedTime")},
                "record": record, "evidence": [],
            })
            ef.array(value["evidence"]).extend(evidence)
    if not sources or len(sources) > MAX_CAPSULES or input_rows + len(observations) > MAX_RECORDS:
        raise ValueError("Timeline source/record budget exceeded or no sources supplied")
    ordered_events = sorted(events.values(), key=_event_order)
    resources: dict[str, ef.Record] = {}
    correlations: dict[str, ef.Record] = {}
    unbound: list[ef.Record] = []
    for observation in observations:
        target = ef.text(observation["resourceId"])
        resource = resources.setdefault(target, {"id": target, "configurationObservations": [], "eventRevisions": []})
        ef.array(resource["configurationObservations"]).append(observation["id"])
    for event in ordered_events:
        reference = {"id": event["id"], "revisionId": event["revisionId"]}
        if event["resourceId"] is not None:
            target = ef.text(event["resourceId"])
            resource = resources.setdefault(target, {"id": target, "configurationObservations": [], "eventRevisions": []})
            ef.array(resource["eventRevisions"]).append(reference)
        else:
            unbound.append(reference)
        if event["correlationId"] is not None:
            correlation = ef.text(event["correlationId"])
            group = correlations.setdefault(correlation, {
                "correlationId": correlation, "meaning": "shared-recorded-id-not-causation", "eventRevisions": [],
            })
            ef.array(group["eventRevisions"]).append(reference)
    configuration_provided = any(source["sourceId"] == "configuration" for source in sources)
    for resource in resources.values():
        resource["configurationEvidence"] = (
            "observedInProvidedSnapshots" if resource["configurationObservations"] else
            "notObservedInProvidedSnapshots" if configuration_provided else "notProvided"
        )
    return {
        "timelineVersion": VERSION, "timelineId": identifier, "scope": scope,
        "sourceCapsules": sources, "events": ordered_events, "configurationObservations": observations,
        "resources": [resources[key] for key in sorted(resources)],
        "correlationGroups": [correlations[key] for key in sorted(correlations)], "unboundEventRevisions": unbound,
        "coverage": {
            "assurance": "provided-evidence-not-continuous-history",
            "notProvidedSources": [source for source in SOURCE_IDS if source not in {entry["sourceId"] for entry in sources}],
            "sourceOutcomes": _source_outcomes(sources), "parentReferences": _parents(sources),
        },
        "statistics": {"inputCapsules": len(sources), "inputEventRows": input_rows, "eventRevisions": len(events),
                       "eventIdentities": len({event["id"] for event in events.values()}),
                       "configurationObservations": len(observations), "resources": len(resources)},
        "assessmentPerformed": False, "causalConclusions": "notGenerated", "configurationComparison": "notPerformed",
    }


def _cell(value: object) -> str:
    return html.escape(str(value), quote=True).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _markdown(document: ef.Record) -> bytes:
    statistics = ef.obj(document["statistics"])
    lines = [
        "# Evidence timeline", "",
        "This is retained evidence, not an assessment, desired state or causal conclusion.", "",
        "Input capsules: " + str(statistics["inputCapsules"]),
        "Retained event revisions: " + str(statistics["eventRevisions"]),
        "Configuration observations: " + str(statistics["configurationObservations"]), "",
        "## Evidence coverage", "",
        "Successful or empty queries do not prove complete history or absence. UNKNOWN evidence stays UNKNOWN.",
        "Sources not provided: " + ", ".join(ef.text(value) for value in ef.array(ef.obj(document["coverage"])["notProvidedSources"])),
        "", "| Source capsule | Outcomes | Source readiness | Retained events | Source window | Retention gap |",
        "|---|---|---|---|---|---|",
    ]
    for source in ef.records(ef.obj(document["coverage"])["sourceOutcomes"]):
        window = ef.obj(source["queryWindow"]) if source["queryWindow"] is not None else None
        gap = ef.obj(window["retentionGap"]) if window is not None and window["retentionGap"] is not None else None
        readiness = ef.obj(source["readiness"]) if source["readiness"] is not None else None
        capsule_id = ef.text(source["capsuleId"])
        label = _cell(source["sourceId"]) + " [" + capsule_id + "](sources/" + capsule_id + "/" + MANIFEST + ")"
        lines.append("| " + " | ".join((
            label, _cell(", ".join(key + ": " + str(value) for key, value in ef.obj(source["outcomes"]).items())),
            _cell(ef.text(readiness["status"]) + " / " + ef.text(readiness["reason"])) if readiness is not None else "not assessed",
            str(source["retainedRecords"]) if source["retainedRecords"] is not None else "not applicable",
            _cell(ef.text(window["start"]) + " to " + ef.text(window["end"])) if window is not None else "collection evidence",
            _cell(ef.text(gap["start"]) + " to " + ef.text(gap["end"])) if gap is not None else "not established/applicable",
        )) + " |")
    lines.extend(("", "### Incremental parent evidence", "", "| Child capsule | Parent capsule | Evidence state |",
                  "|---|---|---|"))
    for parent in ef.records(ef.obj(document["coverage"])["parentReferences"]):
        lines.append("| " + " | ".join(_cell(parent[key]) for key in ("capsuleId", "parentCapsuleId", "state")) + " |")
    lines.extend((
        "",
        "## Resource context", "",
        "Exact recorded resource IDs join observations and events; an unmatched resource is not proof of deletion.", "",
        "| Resource | Configuration evidence | Observations | Event revisions |",
        "|---|---|---|---|",
    ))
    for resource in ef.records(document["resources"]):
        lines.append("| " + " | ".join((
            _cell(resource["id"]), _cell(resource["configurationEvidence"]),
            str(len(ef.array(resource["configurationObservations"]))), str(len(ef.array(resource["eventRevisions"]))),
        )) + " |")
    lines.extend((
        "", "## Configuration observations", "",
        "These are collection windows, not configuration-change timestamps.", "",
        "| Resource | Collection started | Collection completed | Evidence |",
        "|---|---|---|---|",
    ))
    for observation in ef.records(document["configurationObservations"]):
        reference = ef.obj(observation["evidence"])
        lines.append("| " + " | ".join((
            _cell(observation["resourceId"]), _cell(reference["collectionStartedAt"]),
            _cell(reference["collectionCompletedAt"]), "[evidence](" + ef.text(reference["member"]) + ")",
        )) + " |")
    lines.extend((
        "", "## Recorded correlation context", "",
        "Shared recorded IDs are context, not a proven operation, common incident or causal relationship.", "",
        "Correlation groups: " + str(len(ef.array(document["correlationGroups"]))),
        "Events without a recorded resource target: " + str(len(ef.array(document["unboundEventRevisions"]))), "",
        "## Recorded events", "",
        "| Source | Event time | Revision | Evidence |",
        "|---|---|---|---|",
    ))
    for event in ef.records(document["events"]):
        references = ef.records(event["evidence"])
        links = ", ".join("[evidence](" + ef.text(reference["member"]) + ")" for reference in references)
        lines.append("| " + " | ".join((
            _cell(event["sourceId"]), _cell(ef.obj(event["times"])["eventTime"] or "UNKNOWN"),
            _cell(event["revisionId"]), links,
        )) + " |")
    lines.extend(("", "Actor identifiers and retained payload details remain in the private JSON/source evidence.", ""))
    return "\n".join(lines).encode("utf-8")


def _views(root: Path, identifier: str, inputs: ef.Record) -> dict[str, bytes]:
    document = _document(root, identifier)
    return {JSON: ef.encoded(document), MARKDOWN: _markdown(document)}


def _page_markdown(section: str, number: int, items: list[ef.Record], json_name: str) -> bytes:
    lines = [
        "# Evidence timeline: " + section + " page " + str(number), "",
        "[Timeline index](timeline.md) | [Page JSON](" + json_name + ")", "",
        "Retained context only, not a defect, impact, deletion or causal assessment.", "",
    ]
    if section == "events":
        lines.extend(("| Source | Event time | Source update | Revision | Evidence |", "|---|---|---|---|---|"))
    elif section == "configurationObservations":
        lines.extend(("Collection windows are not configuration-change timestamps.", "",
                      "| Resource | Collection started | Collection completed | Evidence |", "|---|---|---|---|"))
    elif section == "resources":
        lines.extend(("| Resource | Configuration evidence | Observations | Event revisions |", "|---|---|---|---|"))
    elif section == "correlationGroups":
        lines.extend(("Shared recorded identifiers do not prove a common operation or cause.", "",
                      "| Recorded correlation ID | Event revisions |", "|---|---|"))
    else:
        lines.extend(("Events without a recorded resource target remain unbound.", "",
                      "| Event identity | Revision |", "|---|---|"))
    for item in items:
        if section == "events":
            links = ", ".join("[evidence](" + ef.text(ref["member"]) + ")" for ref in ef.records(item["evidence"]))
            times = ef.obj(item["times"])
            row = (_cell(item["sourceId"]), _cell(times["eventTime"] or "UNKNOWN"),
                   _cell(times["sourceUpdatedTime"] or "UNKNOWN"), _cell(item["revisionId"]), links)
        elif section == "configurationObservations":
            ref = ef.obj(item["evidence"])
            row = (_cell(item["resourceId"]), _cell(ref["collectionStartedAt"]), _cell(ref["collectionCompletedAt"]),
                   "[evidence](" + ef.text(ref["member"]) + ")")
        elif section == "resources":
            row = (_cell(item["id"]), _cell(item["configurationEvidence"]),
                   str(len(ef.array(item["configurationObservations"]))), str(len(ef.array(item["eventRevisions"]))))
        elif section == "correlationGroups":
            row = (_cell(item["correlationId"]), str(len(ef.array(item["eventRevisions"]))))
        else:
            row = (_cell(item["id"]), _cell(item["revisionId"]))
        lines.append("| " + " | ".join(row) + " |")
    lines.extend(("", "Payloads, omissions and original collection metadata remain in embedded source evidence.", ""))
    return "\n".join(lines).encode("utf-8")


def _compact_views(root: Path, identifier: str, inputs: ef.Record) -> dict[str, bytes]:
    document = _document(root, identifier)
    registry: list[ef.Record] = []
    for source in ef.records(document["sourceCapsules"]):
        for entry in sorted(ef.records(ef.obj(source["manifest"])["members"]), key=lambda value: ef.text(value["name"])):
            registry.append({
                "capsuleId": source["capsuleId"], "manifestSha256": source["manifestSha256"],
                "member": "sources/" + ef.text(source["capsuleId"]) + "/" + ef.text(entry["name"]),
                "memberSha256": entry["sha256"],
            })
    by_member = {ef.text(entry["member"]): position for position, entry in enumerate(registry)}

    def witness(reference: ef.Record) -> ef.Record:
        return {"memberIndex": by_member[ef.text(reference["member"])], "pointer": reference["pointer"]}

    def compact(section: str, item: ef.Record) -> ef.Record:
        if section == "events":
            references = ef.records(item["evidence"])
            if not references:
                raise ValueError("Compact event payload requires an original source witness")
            return {key: value for key, value in item.items() if key not in ("record", "evidence")} | {
                "recordStorage": "first-witness", "witnesses": [witness(ref) for ref in references],
            }
        if section == "configurationObservations":
            return {key: value for key, value in item.items() if key != "evidence"} | {
                "witness": witness(ef.obj(item["evidence"])),
            }
        return item

    views: dict[str, bytes] = {}
    sections: ef.Record = {}
    for section, slug in SECTIONS.items():
        records = ef.records(document[section])
        pending = deque(records[position:position + PAGE_ROWS] for position in range(0, len(records), PAGE_ROWS))
        pages: list[ef.Record] = []
        while pending:
            items = pending.popleft()
            number = len(pages) + 1
            if number > MAX_SECTION_PAGES:
                raise ValueError("Compact timeline section page budget exceeded")
            stem = "timeline-" + slug + "-p" + str(number).zfill(4)
            content = ef.encoded({
                "timelineVersion": COMPACT_VERSION, "timelineId": identifier,
                "section": section, "page": number, "items": [compact(section, item) for item in items],
            })
            markdown = _page_markdown(section, number, items, stem + ".json")
            if max(len(content), len(markdown)) > ef.MAX_MEMBER_BYTES:
                if len(items) == 1:
                    raise ValueError("Single compact timeline entry exceeds member byte budget")
                middle = len(items) // 2
                pending.appendleft(items[middle:])
                pending.appendleft(items[:middle])
                continue
            views[stem + ".json"], views[stem + ".md"] = content, markdown
            pages.append({
                "json": stem + ".json", "markdown": stem + ".md", "count": len(items),
                "sha256": hashlib.sha256(content).hexdigest(),
            })
        sections[section] = pages
    header = {key: value for key, value in document.items() if key not in SECTIONS}
    header.update({
        "timelineVersion": COMPACT_VERSION,
        "storage": {"mode": "compact-paged", "payloads": "unchanged-embedded-source",
                    "witnessMetadata": "unchanged-source-page-and-row", "maxPageRows": PAGE_ROWS,
                    "maxSectionPages": MAX_SECTION_PAGES},
        "evidenceMembers": registry, "sections": sections,
    })
    views[JSON] = ef.encoded(header)
    lines = [
        "# Evidence timeline", "", "Storage 1.1.0: compact, paged and self-contained.", "",
        "This is retained evidence, not desired state, a defect, impact or causal assessment.", "",
        "Payloads, omissions and collection times remain in unchanged embedded source pages.",
        "Use the full normalized reader for analysis; one index/page is not the whole timeline.", "",
        "## Summary", "", "| Measure | Count |", "|---|---|",
    ]
    lines.extend("| " + _cell(key) + " | " + str(value) + " |" for key, value in ef.obj(document["statistics"]).items())
    lines.extend(("", "## Evidence coverage", "",
                  "Query enumeration is not continuous history or a guarantee that all late events arrived.",
                  "Not provided: " + ", ".join(ef.text(value) for value in ef.array(ef.obj(document["coverage"])["notProvidedSources"])),
                  "", "| Source capsule | Outcomes | Readiness | Query window | Retention gap |", "|---|---|---|---|---|"))
    for source in ef.records(ef.obj(document["coverage"])["sourceOutcomes"]):
        window = ef.obj(source["queryWindow"]) if source["queryWindow"] is not None else None
        gap = ef.obj(window["retentionGap"]) if window is not None and window["retentionGap"] is not None else None
        readiness = ef.obj(source["readiness"]) if source["readiness"] is not None else None
        capsule = ef.text(source["capsuleId"])
        lines.append("| " + " | ".join((
            _cell(source["sourceId"]) + " [" + capsule + "](sources/" + capsule + "/manifest.json)",
            _cell(", ".join(key + ": " + str(value) for key, value in ef.obj(source["outcomes"]).items())),
            _cell(ef.text(readiness["status"]) + " / " + ef.text(readiness["reason"])) if readiness is not None else "not assessed",
            _cell(ef.text(window["start"]) + " to " + ef.text(window["end"])) if window is not None else "configuration collection",
            _cell(ef.text(gap["start"]) + " to " + ef.text(gap["end"])) if gap is not None else "not established/applicable",
        )) + " |")
    lines.extend(("", "## Incremental parent evidence", "", "| Child | Parent | State |", "|---|---|---|"))
    for parent in ef.records(ef.obj(document["coverage"])["parentReferences"]):
        lines.append("| " + " | ".join(_cell(parent[key]) for key in ("capsuleId", "parentCapsuleId", "state")) + " |")
    lines.extend(("", "## Data pages", "", "| Section | Entries | Pages |", "|---|---|---|"))
    for section, values in sections.items():
        pages = ef.records(values)
        links = ", ".join(
            "[page " + str(number) + "](" + ef.text(page["markdown"]) + ")"
            " ([JSON](" + ef.text(page["json"]) + "))"
            for number, page in enumerate(pages, 1)
        )
        lines.append("| " + _cell(section) + " | " + str(sum(ef.integer(page["count"]) for page in pages)) + " | " + links + " |")
    lines.extend(("", "Resource and recorded correlation indexes provide context only.",
                  "Unavailable configuration, missing actors and unbound health events remain UNKNOWN, not absence.", ""))
    views[MARKDOWN] = "\n".join(lines).encode("utf-8")
    return views


def verify(directory: Path) -> ef.Record:
    directory = capture.checked_root(directory)
    version = ef.text(ef.decode(ef.read_member(directory / MANIFEST, ef.MAX_MANIFEST_BYTES)).get("bundleVersion"))
    render = _compact_views if version == COMPACT_VERSION else _views
    return bundle.verify(directory, "timeline", render, version=version)


def read(directory: Path) -> ef.Record:
    """Return the complete normalized logical view of either verified storage format."""
    manifest = verify(directory)
    return _document(directory, ef.text(manifest["timelineId"]))


def build(capsules: list[Path], timeline_id: str, output_root: Path, *, compact: bool = False) -> Path:
    return bundle.build(capsules, timeline_id, output_root, "timeline", _compact_views if compact else _views,
                        version=COMPACT_VERSION if compact else VERSION)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("build")
    create.add_argument("--capsule", type=Path, action="append", required=True)
    create.add_argument("--timeline-id", required=True)
    create.add_argument("--output-root", type=Path, required=True)
    create.add_argument("--compact", action="store_true")
    check = commands.add_parser("verify")
    check.add_argument("--timeline", type=Path, required=True)
    args = parser.parse_args()
    try:
        directory = build(args.capsule, args.timeline_id, args.output_root, compact=args.compact) if args.command == "build" else args.timeline
        manifest = verify(directory)
        print(ef.encoded({"status": "verified-offline-timeline", "timeline": str(directory),
                          "timelineId": manifest["timelineId"], "azureReads": 0, "assessmentPerformed": False}).decode().strip())
        return 0
    except (ValueError, OSError) as error:
        parser.exit(2, "Timeline operation failed: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
