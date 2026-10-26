"""Bounded existing event history, source-specific capsules and offline revisions."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Protocol
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent))
import configuration_profile as configuration
import event_profile as policy
import evidence_files as ef
import network_capture as snapshot


PROFILE = "hostless-event-history"
PROFILE_VERSION = "1.0.0"
CAPSULE_VERSION = "0.4.0"
MAX_PAGES = 100
MAX_RECORDS = 20000
MAX_REQUESTS = 100


class Reader(Protocol):
    def context(self) -> ef.Record: ...
    def events(self, source: str, window: ef.Record, cursor: object) -> ef.Record: ...


def source_contract(source: str) -> tuple[str, str, str, str]:
    if source == "workspace-activity":
        import workspace_activity
        return (workspace_activity.PROFILE, workspace_activity.PROFILE_VERSION,
                workspace_activity.CAPSULE_VERSION, workspace_activity.CONTRACT_SHA)
    if source not in policy.SOURCES:
        raise ValueError("Unsupported history source")
    return PROFILE, PROFILE_VERSION, CAPSULE_VERSION, policy.PROFILE_SHA


def source_window(source: str, start: str, end: str, planning_time: str) -> ef.Record:
    if source == "workspace-activity":
        import workspace_activity
        return workspace_activity.query_window(start, end, planning_time)
    return policy.query_window(source, start, end, planning_time)


def source_times(source: str, record: ef.Record) -> tuple[object, object, object]:
    if source == "workspace-activity":
        return record.get("TimeGenerated"), None, record.get("SubmittedTime") or None
    return policy.record_times(source, record)


def source_in_window(source: str, record: ef.Record, window: ef.Record) -> bool:
    if source == "workspace-activity":
        import workspace_activity
        return workspace_activity.time_key(window["start"]) <= workspace_activity.time_key(
            record["TimeGenerated"]
        ) <= workspace_activity.time_key(window["end"])
    return policy.in_window(source, record, window)


def event_shape(source: str, record: object, subscription: str) -> None:
    if source == "workspace-activity":
        import workspace_activity
        workspace_activity.event_valid(record, subscription)
        return
    value = ef.obj(record)
    policy.scoped(value, subscription, "targetResourceId" if source == "resource-changes" else "resourceId")
    if source == "activity-log":
        base = {key: entry for key, entry in value.items() if key not in ("actorClaims", "actorClaimsSourceState", "healthProperties")}
        configuration.validate_retained(base, policy.ACTIVITY_FIELDS)
        claims = ef.fields(value.get("actorClaims"), set(), set(policy.ACTOR_CLAIMS))
        for entry in claims.values():
            if entry is not None:
                ef.text(entry)
        if value.get("actorClaimsSourceState") not in ("notProvided", "explicitNull", "selected"):
            raise ValueError("Invalid recorded actor-claims presence")
        if "healthProperties" in value:
            configuration.validate_retained(value["healthProperties"], policy.ACTIVITY_HEALTH_PROPERTIES)
    elif source == "service-health":
        configuration.validate_retained(value, policy.HEALTH_FIELDS)
        properties = ef.obj(value["properties"]) if value.get("properties") is not None else {}
        if properties.get("isEventSensitive") is True:
            if "summary" in properties:
                raise ValueError("Sensitive health summary must not be retained")
            for impact in ef.records(properties.get("impact", [])):
                for region in ef.records(impact.get("impactedRegions", [])):
                    if any("summary" in update for update in ef.records(region.get("updates", []))):
                        raise ValueError("Sensitive health update summary must not be retained")
    else:
        configuration.validate_retained({key: entry for key, entry in value.items() if key != "changedProperties"}, policy.CHANGE_FIELDS)
        changes = ef.records(value.get("changedProperties"))
        if len(changes) > ef.MAX_ROWS:
            raise ValueError("Changed-property budget exceeded")
        resource_type = ef.text(value["targetResourceType"]) if value.get("targetResourceType") is not None else ""
        for change in changes:
            ef.fields(change, {"path", "sourceTruncation", "reviewedPath", "previous", "new"})
            path = ef.text(change["path"])
            shape = policy.config_node(resource_type, path)
            if change["reviewedPath"] != (shape is not None):
                raise ValueError("Retained delta path policy mismatch")
            for key in ("previous", "new"):
                selected = ef.obj(change[key])
                status = selected.get("status")
                if status == "selected":
                    ef.fields(selected, {"status", "value", "representation", "omittedPaths"})
                    if shape is None:
                        raise ValueError("Unreviewed property-change value retained")
                    value_frame = policy.change_value({"value": selected["value"]}, "value", shape)
                    if value_frame["status"] != "selected" or value_frame["value"] != selected["value"]:
                        raise ValueError("Delta value does not match reviewed shape")
                    for omission in ef.array(selected["omittedPaths"]):
                        ef.text(omission)
                elif status in ("notProvided", "unreviewedPathOmitted", "unsupportedSourceValueShape"):
                    ef.fields(selected, {"status"})
                else:
                    raise ValueError("Unknown property-value selection outcome")
    for value in policy.record_times(source, ef.obj(record)):
        if value is not None:
            policy.time(value)


def cursor_valid(source: str, subscription: str, window: ef.Record, cursor: object) -> None:
    if source == "workspace-activity":
        import workspace_activity
        workspace_activity.cursor_valid(subscription, window, cursor)
    elif source == "resource-changes":
        policy.graph_body(subscription, window, cursor)
    else:
        policy.request_url(source, subscription, window, cursor)


def select_page(source: str, body: object, subscription: str, window: ef.Record,
                cursor: object = None) -> tuple[list[ef.Record], object, int, int]:
    if source == "workspace-activity":
        import workspace_activity
        return workspace_activity.select_page(body, subscription, window, cursor)
    value = ef.obj(body)
    if source == "resource-changes":
        rows = ef.records(value.get("data"))
        if ef.integer(value.get("count")) != len(rows) or ef.integer(value.get("totalRecords")) < len(rows):
            raise ValueError("Resource Graph history row coverage mismatch")
        truncated = value.get("resultTruncated")
        if truncated not in (True, False, "true", "false"):
            raise ValueError("Resource Graph history truncation flag unavailable")
        token = value.get("$skipToken")
        cursor = {"skipToken": ef.text(token)} if token is not None else None
        if truncated in (True, "true") and cursor is None:
            raise ValueError("Resource Graph history is truncated without continuation")
    else:
        rows = ef.records(value.get("value"))
        cursor = {"nextLink": ef.text(value["nextLink"])} if value.get("nextLink") is not None else None
    if len(rows) > ef.MAX_ROWS:
        raise ValueError("History response row budget exceeded")
    cursor_valid(source, subscription, window, cursor)
    events = []
    dropped = 0
    for position, row in enumerate(rows):
        retained, omissions = policy.select_event(source, row, subscription)
        if retained is None or not policy.in_window(source, retained, window):
            dropped += 1
            continue
        event_shape(source, retained, subscription)
        events.append({"record": retained, "omittedPaths": omissions, "sourceRow": position})
    return events, cursor, len(rows), dropped


def page_name(number: int) -> str:
    return "events-p" + str(number).zfill(4) + ".json"


def history_name(name: str) -> None:
    if name == snapshot.CONTEXT or re.fullmatch(r"events-p\d{4}\.json", name):
        return
    if name.startswith("attempt-") and name.endswith(".json"):
        identifier = name.removeprefix("attempt-").removesuffix(".json")
        if ef.canonical_uuid(identifier) == identifier:
            return
    raise ValueError("Unsupported history member name")


def page_valid(value: object, source: str, scope: ef.Record, window: ef.Record) -> ef.Record:
    record = ef.fields(value, {"sourceId", "page", "attemptId", "cursorIn", "cursorOut", "startedAtUtc", "completedAtUtc",
                               "status", "errorCode", "httpStatus", "requestId", "returnedRows", "discardedRows", "events"})
    if record["sourceId"] != source or not 1 <= ef.integer(record["page"]) <= MAX_PAGES:
        raise ValueError("History page/source binding mismatch")
    ef.canonical_uuid(ef.text(record["attemptId"]))
    if policy.time(record["startedAtUtc"]) > policy.time(record["completedAtUtc"]):
        raise ValueError("History read completion precedes attempt")
    subscription = ef.text(scope["subscriptionId"])
    cursor_valid(source, subscription, window, record["cursorIn"])
    cursor_valid(source, subscription, window, record["cursorOut"])
    ef.integer(record["httpStatus"])
    if record["requestId"] is not None:
        ef.text(record["requestId"])
    if record["status"] != "succeeded":
        if record["status"] not in ("permissionDenied", "unavailable", "failed") or (
            record["events"] is not None or record["cursorOut"] is not None
            or record["returnedRows"] is not None or record["discardedRows"] is not None
        ):
            raise ValueError("Failed history source claims successful events")
        ef.text(record["errorCode"])
        return record
    if record["httpStatus"] != 200 or record["errorCode"] is not None:
        raise ValueError("History HTTP result and outcome differ")
    returned, dropped = ef.integer(record["returnedRows"]), ef.integer(record["discardedRows"])
    events = ef.records(record["events"])
    if not 0 <= returned <= ef.MAX_ROWS or dropped < 0 or returned != len(events) + dropped:
        raise ValueError("History retained/discarded row counts disagree")
    positions = set()
    for event in events:
        ef.fields(event, {"record", "omittedPaths", "sourceRow"})
        position = ef.integer(event["sourceRow"])
        if not 0 <= position < returned or position in positions:
            raise ValueError("Invalid history source row binding")
        positions.add(position)
        event_shape(source, event["record"], subscription)
        if not source_in_window(source, ef.obj(event["record"]), window):
            raise ValueError("Retained event exceeds requested selection window")
        for omission in ef.array(event["omittedPaths"]):
            ef.text(omission)
    return record


def progress_valid(progress: ef.Record, documents: dict[str, ef.Record], pending: object,
                   source: str, scope: ef.Record, window: ef.Record) -> None:
    if not isinstance(progress["terminal"], bool) or not isinstance(progress["complete"], bool):
        raise ValueError("Invalid history checkpoint completion flags")
    number = ef.integer(progress["page"])
    if not 1 <= number <= MAX_PAGES + 1 or not 0 <= ef.integer(progress["returnedRecords"]) <= MAX_RECORDS:
        raise ValueError("History checkpoint count/page exceeds profile")
    pages = []
    for name, record in documents.items():
        history_name(name)
        if name == snapshot.CONTEXT:
            snapshot.validate_context(record, scope)
        elif name.startswith("events-"):
            page_valid(record, source, scope, window)
            if name != page_name(ef.integer(record["page"])):
                raise ValueError("History checkpoint member page identity differs")
            pages.append(record)
    pages.sort(key=lambda record: ef.integer(record["page"]))
    if [page["page"] for page in pages] != list(range(1, number)):
        raise ValueError("History checkpoint has missing or skipped pages")
    expected_cursor = pages[-1]["cursorOut"] if pages else None
    if progress["cursor"] != expected_cursor:
        raise ValueError("History checkpoint cursor differs from retained outcome")
    if sum(ef.integer(page["returnedRows"]) for page in pages if page["returnedRows"] is not None) != progress["returnedRecords"]:
        raise ValueError("History checkpoint row count differs from retained pages")
    if progress["terminal"] != bool(pages and pages[-1]["cursorOut"] is None):
        raise ValueError("History checkpoint terminal state differs from source pages")
    if progress["complete"] and not progress["terminal"]:
        raise ValueError("History checkpoint claims completion with outstanding reads")
    if pending is not None:
        attempt = ef.fields(pending, {"attemptId", "sourceId", "page", "cursor", "startedAtUtc"})
        if attempt["sourceId"] != source or attempt["page"] != number or attempt["cursor"] != expected_cursor or progress["terminal"]:
            raise ValueError("History checkpoint pending read differs from current source page")
        ef.canonical_uuid(ef.text(attempt["attemptId"]))
        policy.time(attempt["startedAtUtc"])


def coverage(documents: dict[str, ef.Record], source: str) -> ef.Record:
    pages = [documents[name] for name in sorted(documents) if name.startswith("events-")]
    returned = sum(ef.integer(page["returnedRows"]) for page in pages if page["returnedRows"] is not None)
    retained = sum(len(ef.array(page["events"])) for page in pages if page["events"] is not None)
    result = {
        "sourceId": source, "pages": [{
            key: page[key] for key in ("page", "startedAtUtc", "completedAtUtc", "status", "errorCode", "httpStatus",
                                       "requestId", "cursorIn", "cursorOut", "returnedRows", "discardedRows")
        } for page in pages], "returnedRecords": returned, "retainedRecords": retained,
        "unconfirmedAttempts": [documents[name] for name in sorted(documents) if name.startswith("attempt-")],
        "notCollected": [] if source == "workspace-activity" else ["existing-exported-Log-Analytics-history"],
        "boundary": "requested existing source window in visible subscription; no completeness or causation guarantee",
    }
    if source == "workspace-activity":
        available = retained > 0 and all(page["status"] == "succeeded" for page in pages)
        result["readiness"] = {"status": "AVAILABLE" if available else "UNKNOWN",
                               "reason": "ReviewedWorkspaceRowsRetained" if available else
                                   "WorkspaceSourceFailed" if any(page["status"] != "succeeded" for page in pages)
                                   else "NoWorkspaceRowsRetainedAfterPreflight"}
    return result


def verified(directory: Path) -> tuple[ef.Record, dict[str, ef.Record], bytes]:
    root = snapshot.checked_root(directory)
    manifest_bytes = ef.read_member(root / snapshot.MANIFEST, ef.MAX_MANIFEST_BYTES)
    raw_manifest = ef.decode(manifest_bytes)
    source = ef.text(raw_manifest.get("sourceId"))
    profile_id, profile_version, capsule_version, profile_sha = source_contract(source)
    manifest = ef.fields(raw_manifest, {
        "capsuleVersion", "capsuleId", "profileId", "profileVersion", "profileSha256", "sourceId", "scope",
        "requestedWindow", "queryWindow", "planningTime", "parentCapsule", "collectionWindow",
        "members", "coverage", "watermark", "assurance",
    } | ({"workspace"} if source == "workspace-activity" else set()))
    if (manifest["capsuleVersion"], manifest["profileId"], manifest["profileVersion"], manifest["profileSha256"]) != (
        capsule_version, profile_id, profile_version, profile_sha,
    ) or manifest["assurance"] != snapshot.ASSURANCE:
        raise ValueError("Unsupported history capsule/profile/assurance")
    ef.canonical_uuid(ef.text(manifest["capsuleId"]))
    scope = ef.fields(manifest["scope"], {"tenantId", "subscriptionId", "managedIdentityClientId"})
    if scope != snapshot.scope(ef.text(scope["tenantId"]), ef.text(scope["subscriptionId"]), ef.text(scope["managedIdentityClientId"])):
        raise ValueError("History scope is not canonical")
    requested = ef.fields(manifest["requestedWindow"], {"start", "end"})
    expected_window = source_window(source, ef.text(requested["start"]), ef.text(requested["end"]), ef.text(manifest["planningTime"]))
    if manifest["queryWindow"] != expected_window or expected_window["expired"]:
        raise ValueError("History source/window availability bindings differ")
    if source == "workspace-activity":
        import workspace_activity
        workspace_activity.validate_preflight(manifest["workspace"], scope, expected_window)
    names = {ef.member_name(entry["name"]) for entry in ef.records(manifest["members"])}
    if snapshot.CONTEXT not in names or snapshot.MANIFEST in names or len(names) > MAX_PAGES + 1001:
        raise ValueError("History capsule member set exceeds profile")
    expected = ef.descriptors(manifest["members"], names)
    for name in names:
        history_name(name)
    if set(path.name for path in root.iterdir()) != names | {snapshot.MANIFEST}:
        raise ValueError("Missing or extra history capsule members")
    payloads = ef.read_verified_members(root, expected, len(manifest_bytes))
    documents = {name: ef.decode(content) for name, content in payloads.items()}
    snapshot.validate_context(documents[snapshot.CONTEXT], scope)
    pages = sorted((record for name, record in documents.items() if name.startswith("events-")),
                   key=lambda record: ef.integer(record["page"]))
    if not pages or [page["page"] for page in pages] != list(range(1, len(pages) + 1)):
        raise ValueError("History source page coverage has gaps or duplicates")
    cursor = None
    seen_cursors = set()
    for record in pages:
        if cursor is None and record is not pages[0]:
            raise ValueError("History contains pages after terminal source outcome")
        page_valid(record, source, scope, expected_window)
        if record["cursorIn"] != cursor:
            raise ValueError("History page continuation binding differs")
        cursor = record["cursorOut"]
        if cursor is not None:
            fingerprint = ef.digest(cursor)
            if fingerprint in seen_cursors:
                raise ValueError("History continuation is repeated")
            seen_cursors.add(fingerprint)
    for name, record in documents.items():
        if name.startswith("events-") and name != page_name(ef.integer(record["page"])):
            raise ValueError("History member page identity differs")
    for name, record in documents.items():
        if name.startswith("attempt-"):
            ef.fields(record, {"attemptId", "sourceId", "page", "cursor", "startedAtUtc", "status"})
            if (
                record["sourceId"] != source or record["status"] != "unconfirmed"
                or name != "attempt-" + ef.canonical_uuid(ef.text(record["attemptId"])) + ".json"
                or not 1 <= ef.integer(record["page"]) <= MAX_PAGES
            ):
                raise ValueError("Invalid unconfirmed history attempt")
            cursor_valid(source, ef.text(scope["subscriptionId"]), expected_window, record["cursor"])
            policy.time(record["startedAtUtc"])
    if cursor is not None:
        raise ValueError("Finalized history source still has an outstanding cursor")
    if coverage(documents, source) != manifest["coverage"]:
        raise ValueError("History coverage differs from retained bytes")
    if ef.integer(ef.obj(manifest["coverage"])["returnedRecords"]) > MAX_RECORDS:
        raise ValueError("History capsule exceeds declared record budget")
    complete = pages[-1]["status"] == "succeeded" and all(page["status"] == "succeeded" for page in pages)
    if source == "workspace-activity" and ef.obj(ef.obj(manifest["coverage"])["readiness"])["status"] != "AVAILABLE":
        complete = False
    watermark = ef.fields(manifest["watermark"], {"enumeratedThrough", "basis", "overlapHours"})
    if watermark != {"enumeratedThrough": requested["end"] if complete else None,
                      "basis": "terminal-request-enumeration-not-all-events-arrived", "overlapHours": 24}:
        raise ValueError("History watermark falsely advances incomplete source")
    return manifest, documents, manifest_bytes


def verify(directory: Path) -> ef.Record:
    return verified(directory)[0]


def replay(directory: Path) -> ef.Record:
    manifest, documents, manifest_bytes = verified(directory)
    source = ef.text(manifest["sourceId"])
    subscription = ef.text(ef.obj(manifest["scope"])["subscriptionId"])
    events: dict[tuple[str, str], ef.Record] = {}
    for name in sorted(documents):
        if not name.startswith("events-") or documents[name]["events"] is None:
            continue
        page = documents[name]
        for position, value in enumerate(ef.records(page["events"])):
            record = ef.obj(value["record"])
            source_identifier = (ef.text(record["EventId"]) or None) if source == "workspace-activity" else policy.event_id(source, record)
            identity_scope = [source, subscription]
            if source == "workspace-activity":
                identity_scope.append(ef.obj(manifest["workspace"])["workspaceId"])
            identity = ef.digest([*identity_scope, source_identifier]) if source_identifier is not None else ef.digest(
                [source, subscription, manifest["capsuleId"], name, position]
            )
            revision = ef.digest(record)
            event_time, updated_time, submitted_time = source_times(source, record)
            key = identity, revision
            event = events.setdefault(key, {
                "id": source + "-" + identity[:24], "revisionId": revision, "revisionBasis": "retained-reviewed-payload",
                "sourceEventId": source_identifier, "identityAssurance": "source-provided" if source_identifier else "capture-occurrence-not-cross-capture-deduplicable",
                "eventTime": event_time, "sourceUpdatedTime": updated_time, "submissionTime": submitted_time,
                "timeAvailability": {"eventTime": "provided" if event_time is not None else "UNKNOWN",
                                     "sourceUpdatedTime": "provided" if updated_time is not None else "UNKNOWN"},
                "record": record, "evidence": [],
            })
            ef.array(event["evidence"]).append({
                "member": name, "pointer": "/events/" + str(position) + "/record",
                "collectionStartedAt": page["startedAtUtc"], "collectionCompletedAt": page["completedAtUtc"],
                "omittedPaths": value["omittedPaths"],
            })
    def order(value: ef.Record) -> tuple[str, str, str]:
        anchor = value["eventTime"] if value["eventTime"] is not None else value["sourceUpdatedTime"]
        return (policy.time(anchor).isoformat() if anchor is not None else "unknown", ef.text(value["id"]), ef.text(value["revisionId"]))
    result = {"replayVersion": "1.0.0", "capsuleId": manifest["capsuleId"], "profileId": manifest["profileId"],
            "sourceId": source, "scope": manifest["scope"], "queryWindow": manifest["queryWindow"],
            "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "events": sorted(events.values(), key=order), "coverage": manifest["coverage"], "watermark": manifest["watermark"],
            "assessmentPerformed": False, "causalConclusions": "notGenerated"}
    if source == "workspace-activity":
        result["workspace"] = manifest["workspace"]
    return result


def capture(reader: Reader, source: str, tenant: str, subscription: str, client: str, capture_id: str, output_root: Path,
            start: str, end: str, *, planning_time: str | None = None, previous_capsule: Path | None = None,
            resume: bool = False, retry_unconfirmed: bool = False, workspace: ef.Record | None = None) -> Path:
    approved = snapshot.scope(tenant, subscription, client)
    subscription = ef.text(approved["subscriptionId"])
    capture_id = ef.canonical_uuid(capture_id)
    profile_id, profile_version, capsule_version, profile_sha = source_contract(source)
    root = snapshot.checked_root(output_root)
    acquisition = root / "history-acquisition" / capture_id
    destination = root / "capsules" / capture_id
    parent = None
    if previous_capsule is not None:
        previous, _, previous_bytes = verified(previous_capsule)
        if previous["sourceId"] != source or previous["scope"] != approved or previous["watermark"]["enumeratedThrough"] is None:
            raise ValueError("Previous history source is incomplete or has different scope; resume its checkpoint or supply an explicit new range")
        if source == "workspace-activity" and (workspace is None or (
            ef.obj(previous["workspace"])["workspaceId"] != workspace["workspaceId"]
        )):
            raise ValueError("Previous workspace history identity differs")
        start = (policy.time(previous["watermark"]["enumeratedThrough"]) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
        parent = {"capsuleId": previous["capsuleId"], "manifestSha256": hashlib.sha256(previous_bytes).hexdigest()}
    requested = {"start": policy.utc(start), "end": policy.utc(end)}
    identity = {"stateVersion": "1.0.0", "profileId": profile_id, "profileVersion": profile_version,
                "profileSha256": profile_sha, "sourceId": source, "scope": approved,
                "captureId": capture_id, "requestedWindow": requested, "parentCapsule": parent}
    if source == "workspace-activity":
        if workspace is None:
            raise ValueError("Workspace history requires verified preflight evidence")
        identity["workspace"] = workspace
    elif workspace is not None:
        raise ValueError("Workspace evidence cannot relabel a native history source")
    if not resume:
        acquisition.mkdir(parents=True, exist_ok=False)
        (acquisition / "evidence").mkdir()
    ef.normal_path(acquisition)
    lock = acquisition / ".history.lock"
    lock.mkdir(exist_ok=False)
    evidence = acquisition / "evidence"
    try:
        if resume:
            state = ef.fields(ef.decode(ef.read_member(acquisition / "state.json")),
                              {*identity, "planningTime", "queryWindow", "progress", "progressSha256", "pending"})
            if any(state[key] != value for key, value in identity.items()) or state["progressSha256"] != ef.digest(state["progress"]):
                raise ValueError("History checkpoint scope/source/window/integrity mismatch")
        else:
            planned = planning_time or ef.utc_now()
            window = source_window(source, start, end, planned)
            if window["expired"]:
                raise ValueError("Requested history is outside the source's native retention; no query sent")
            state = {**identity, "planningTime": planned, "queryWindow": window,
                     "progress": {"page": 1, "cursor": None, "members": [], "returnedRecords": 0,
                                  "startedAtUtc": ef.utc_now(), "terminal": False, "complete": False},
                     "progressSha256": "", "pending": None}
        window = ef.obj(state["queryWindow"])
        if window != source_window(source, start, end, ef.text(state["planningTime"])):
            raise ValueError("History saved query window differs")
        if source == "workspace-activity":
            import workspace_activity
            workspace_activity.validate_preflight(state["workspace"], approved, window)
        progress = ef.fields(state["progress"], {"page", "cursor", "members", "returnedRecords", "startedAtUtc", "terminal", "complete"})
        def save() -> None:
            state["progressSha256"] = ef.digest(progress)
            ef.atomic_json(acquisition / "state.json", state)
        names = {ef.member_name(entry["name"]) for entry in ef.records(progress["members"])}
        expected = ef.descriptors(progress["members"], names)
        payloads = ef.read_verified_members(evidence, expected)
        documents = {name: ef.decode(content) for name, content in payloads.items()}
        progress_valid(progress, documents, state["pending"], source, approved, window)
        if progress["complete"] is True or os.path.lexists(destination):
            manifest = verify(destination)
            if manifest["capsuleId"] != capture_id or manifest["sourceId"] != source or manifest["scope"] != approved:
                raise ValueError("Completed history capsule differs from checkpoint")
            if manifest["members"] != sorted(ef.records(progress["members"]), key=lambda entry: ef.text(entry["name"])):
                raise ValueError("Completed history member bindings differ")
            if progress["complete"] is not True:
                progress["complete"] = True
                save()
            return destination
        if not resume:
            save()
        for name, page in documents.items():
            if name.startswith("events-"):
                page_valid(page, source, approved, window)
        seen_cursors = {ef.digest(page["cursorOut"]) for name, page in documents.items()
                        if name.startswith("events-") and page["cursorOut"] is not None}
        cursor_valid(source, subscription, window, progress["cursor"])
        if state["pending"] is not None and not (evidence / page_name(ef.integer(progress["page"]))).exists() and not retry_unconfirmed:
            raise snapshot.UnconfirmedRead("Unconfirmed history read requires explicit --retry-unconfirmed; no query sent")
        context = snapshot.validate_context(reader.context(), approved)
        if snapshot.CONTEXT not in documents:
            data = ef.encoded(context)
            ef.immutable_file(evidence / snapshot.CONTEXT, data)
            ef.array(progress["members"]).append(ef.descriptor(snapshot.CONTEXT, data))
            payloads[snapshot.CONTEXT], documents[snapshot.CONTEXT] = data, context
            save()
        if state["pending"] is not None and not (evidence / page_name(ef.integer(progress["page"]))).exists():
            attempt = {**ef.obj(state["pending"]), "status": "unconfirmed"}
            name = "attempt-" + ef.text(attempt["attemptId"]) + ".json"
            data = ef.encoded(attempt)
            ef.immutable_file(evidence / name, data)
            if ef.descriptor(name, data) not in ef.array(progress["members"]):
                ef.array(progress["members"]).append(ef.descriptor(name, data))
            payloads[name], documents[name] = data, attempt
            state["pending"] = None
            save()
        requests = 0
        while progress["terminal"] is not True:
            number = ef.integer(progress["page"])
            name = page_name(number)
            if number > MAX_PAGES or requests >= MAX_REQUESTS:
                raise ValueError("History page/request budget exhausted; partial checkpoint retained without watermark")
            if state["pending"] is not None and (evidence / name).exists():
                page = page_valid(ef.decode(ef.read_member(evidence / name)), source, approved, window)
                if page["attemptId"] != ef.obj(state["pending"])["attemptId"] or page["cursorIn"] != progress["cursor"]:
                    raise ValueError("Recovered history page differs from pending attempt")
            else:
                pending = {"attemptId": str(uuid4()), "sourceId": source, "page": number,
                           "cursor": progress["cursor"], "startedAtUtc": ef.utc_now()}
                state["pending"] = pending
                save()
                response = reader.events(source, window, progress["cursor"])
                requests += 1
                status, error, http = snapshot.outcome(response)
                if status == "succeeded":
                    events, next_cursor, returned, dropped = select_page(source, response["body"], subscription, window, progress["cursor"])
                else:
                    events, next_cursor, returned, dropped = None, None, None, None
                page = {"sourceId": source, "page": number, "attemptId": pending["attemptId"], "cursorIn": progress["cursor"],
                        "cursorOut": next_cursor, "startedAtUtc": pending["startedAtUtc"], "completedAtUtc": ef.utc_now(),
                        "status": status, "errorCode": error, "httpStatus": http, "requestId": response["requestId"],
                        "returnedRows": returned, "discardedRows": dropped, "events": events}
                page_valid(page, source, approved, window)
            data = ef.encoded(page)
            if page["cursorOut"] is not None:
                fingerprint = ef.digest(page["cursorOut"])
                if fingerprint in seen_cursors:
                    raise ValueError("History continuation is repeated; no additional request sent")
                seen_cursors.add(fingerprint)
            if (
                len(data) > ef.MAX_MEMBER_BYTES or sum(map(len, payloads.values())) + len(data) > ef.MAX_TOTAL_BYTES
                or ef.integer(progress["returnedRecords"]) + (ef.integer(page["returnedRows"]) if page["returnedRows"] is not None else 0) > MAX_RECORDS
            ):
                raise ValueError("History record/byte budget exhausted; partial checkpoint retained without watermark")
            ef.immutable_file(evidence / name, data)
            reference = ef.descriptor(name, data)
            if reference not in ef.array(progress["members"]):
                ef.array(progress["members"]).append(reference)
            payloads[name], documents[name] = data, page
            progress["returnedRecords"] = ef.integer(progress["returnedRecords"]) + (ef.integer(page["returnedRows"]) if page["returnedRows"] is not None else 0)
            progress["cursor"] = page["cursorOut"]
            progress["terminal"] = page["cursorOut"] is None
            progress["page"] = number + 1
            state["pending"] = None
            save()
        pages = [record for name, record in documents.items() if name.startswith("events-")]
        complete = all(page["status"] == "succeeded" for page in pages)
        if source == "workspace-activity" and not any(page["events"] for page in pages):
            complete = False
        manifest = {
            "capsuleVersion": capsule_version, "capsuleId": capture_id, "profileId": profile_id, "profileVersion": profile_version,
            "profileSha256": profile_sha, "sourceId": source, "scope": approved,
            "requestedWindow": requested, "queryWindow": window, "planningTime": state["planningTime"], "parentCapsule": parent,
            "collectionWindow": {"startedAtUtc": progress["startedAtUtc"], "completedAtUtc": ef.utc_now()},
            "members": sorted(ef.records(progress["members"]), key=lambda entry: ef.text(entry["name"])),
            "coverage": coverage(documents, source), "assurance": dict(snapshot.ASSURANCE),
            "watermark": {"enumeratedThrough": end if complete else None,
                          "basis": "terminal-request-enumeration-not-all-events-arrived", "overlapHours": 24},
        }
        if source == "workspace-activity":
            manifest["workspace"] = workspace
        manifest_bytes = ef.encoded(manifest)
        if len(manifest_bytes) > ef.MAX_MANIFEST_BYTES or len(manifest_bytes) + sum(map(len, payloads.values())) > ef.MAX_TOTAL_BYTES:
            raise ValueError("History manifest/total budget exhausted; no watermark published")
        destination.parent.mkdir(exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix="." + capture_id + ".", dir=destination.parent))
        published = False
        try:
            for name, content in {**payloads, snapshot.MANIFEST: manifest_bytes}.items():
                ef.immutable_file(staging / name, content)
            verify(staging)
            if os.path.lexists(destination):
                raise FileExistsError("History capsule destination already exists")
            staging.rename(destination)
            published = True
        finally:
            if not published:
                for name in set(payloads) | {snapshot.MANIFEST}:
                    (staging / name).unlink(missing_ok=True)
                staging.rmdir()
        progress["complete"] = True
        save()
        return destination
    finally:
        lock.rmdir()


class HistoryBridge(snapshot.ArmBridge):
    SCRIPT = "history_reader.ps1"

    def events(self, source: str, window: ef.Record, cursor: object) -> ef.Record:
        if source not in policy.SOURCES:
            raise ValueError("Unreviewed history source")
        cursor_valid(source, ef.text(self.approved["subscriptionId"]), window, cursor)
        return self.exchange({"source": source, "start": policy.utc(window["start"]), "end": policy.utc(window["end"]), "cursor": cursor})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, choices=policy.SOURCES)
    for name in ("tenant-id", "subscription-id", "managed-identity-client-id", "capture-id", "start-time", "end-time"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--previous-capsule", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-unconfirmed", action="store_true")
    args = parser.parse_args()
    reader = HistoryBridge(snapshot.scope(args.tenant_id, args.subscription_id, args.managed_identity_client_id))
    try:
        directory = capture(reader, args.source, args.tenant_id, args.subscription_id, args.managed_identity_client_id,
                            args.capture_id, args.output_root, args.start_time, args.end_time,
                            previous_capsule=args.previous_capsule, resume=args.resume, retry_unconfirmed=args.retry_unconfirmed)
        manifest = verify(directory)
        print(ef.encoded({"capsule": str(directory), "sourceId": args.source, "status": "captured-existing-history",
                          "retainedEvents": ef.obj(manifest["coverage"])["retainedRecords"],
                          "watermark": manifest["watermark"], "assessmentPerformed": False}).decode().strip())
    except (ValueError, OSError, snapshot.UnconfirmedRead) as error:
        parser.exit(2, "History capture failed: " + str(error) + "\n")
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
