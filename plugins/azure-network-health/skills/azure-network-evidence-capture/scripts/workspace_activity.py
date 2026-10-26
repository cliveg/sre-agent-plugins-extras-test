"""Explicit Log Analytics Activity Log readiness and reviewed query contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse
from datetime import timedelta
from datetime import datetime
from pathlib import Path
from typing import Protocol

sys.path.insert(0, str(Path(__file__).resolve().parent))
import event_profile as events
import evidence_files as ef
import network_capture as snapshot


SOURCE = "workspace-activity"
PROFILE = "hostless-workspace-activity"
PROFILE_VERSION = "1.0.0"
CAPSULE_VERSION = "0.5.0"
CATEGORIES = ("Administrative", "ResourceHealth", "ServiceHealth")
SUMMARY_COLUMNS = ("Category", "Records", "Earliest", "Latest", "WithCaller")
EVENT_COLUMNS = (
    "TimeGenerated", "EventId", "SubmittedTime", "IngestedTime", "AssessedSubscription", "Category",
    "Caller", "CorrelationId", "OperationId", "Operation", "Status", "ResourceId", "ResourceGroup",
    "AppId", "PrincipalId", "HealthCause", "CurrentHealthStatus", "PreviousHealthStatus", "HealthType", "Copies", "RowKey",
)
QUERIES = {name: Path(__file__).with_name("workspace-" + name + ".kql").read_text(encoding="utf-8").strip()
           for name in ("base", "summary", "page")}
CONTRACT_SHA = ef.digest({"queries": QUERIES, "columns": EVENT_COLUMNS, "categories": CATEGORIES,
                         "capsuleVersion": CAPSULE_VERSION, "profileVersion": PROFILE_VERSION,
                         "paging": "TimeGenerated-and-reviewed-row-hash; grouped-copy-counts", "pageSize": 500})


def time_key(value: object) -> tuple[datetime, int]:
    stamp = events.time(value)
    fraction = re.search(r"\.(\d{1,7})(?:Z|[+-]\d{2}:\d{2})$", ef.text(value))
    seventh = int(fraction.group(1).ljust(7, "0")[6]) if fraction else 0
    return stamp, seventh


def cursor_time(value: object) -> str:
    stamp, seventh = time_key(value)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + str(stamp.microsecond).zfill(6) + str(seventh) + "Z"


def cursor_valid(subscription: str, window: ef.Record, cursor: object) -> None:
    ef.canonical_uuid(subscription)
    if cursor is None:
        return
    record = ef.fields(cursor, {"afterTime", "afterKey"})
    stamp = time_key(events.utc(record["afterTime"]))
    if not time_key(window["start"]) <= stamp <= time_key(window["end"]) or re.fullmatch(
        r"[0-9a-f]{64}", ef.text(record["afterKey"])
    ) is None:
        raise ValueError("Workspace cursor exceeds reviewed scope/window")


def kql(operation: str, subscription: str, window: ef.Record, cursor: object = None) -> str:
    if operation not in ("summary", "page"):
        raise ValueError("Unreviewed workspace query operation")
    subscription = ef.canonical_uuid(subscription)
    cursor_valid(subscription, window, cursor)
    base = QUERIES["base"].replace("__SUBSCRIPTION__", subscription).replace(
        "__START__", events.utc(window["start"])
    ).replace("__END__", events.utc(window["end"]))
    suffix = QUERIES[operation]
    if operation == "page":
        after = "true"
        if cursor is not None:
            record = ef.obj(cursor)
            after = (
                "TimeGenerated > datetime('" + ef.text(record["afterTime"]) + "') or "
                "(TimeGenerated == datetime('" + ef.text(record["afterTime"]) + "') and strcmp(RowKey, '"
                + ef.text(record["afterKey"]) + "') > 0)"
            )
        suffix = suffix.replace("__AFTER__", after)
    return base + "\n" + suffix


def event_valid(value: object, subscription: str) -> ef.Record:
    record = ef.fields(value, set(EVENT_COLUMNS))
    if ef.canonical_uuid(ef.text(record["AssessedSubscription"])) != subscription or record["Category"] not in CATEGORIES:
        raise ValueError("Workspace activity row exceeds approved subscription/category")
    for key in EVENT_COLUMNS:
        if key == "Copies":
            if ef.integer(record[key]) < 1:
                raise ValueError("Invalid workspace duplicate count")
        elif record[key] is not None:
            ef.text(record[key])
    for key in ("TimeGenerated", "SubmittedTime", "IngestedTime"):
        if record[key] not in (None, ""):
            events.time(record[key])
    if record["TimeGenerated"] in (None, "") or re.fullmatch(r"[0-9a-f]{64}", ef.text(record["RowKey"])) is None:
        raise ValueError("Workspace event has no stable paging time/key")
    events.scoped({"resourceId": record["ResourceId"]}, subscription, "resourceId")
    return record


def select_page(body: object, subscription: str, window: ef.Record,
                cursor: object) -> tuple[list[ef.Record], object, int, int]:
    rows = query_rows(body, EVENT_COLUMNS)
    if len(rows) > 501:
        raise ValueError("Workspace result exceeds bounded lookahead page")
    cursor_valid(subscription, window, cursor)
    previous = None if cursor is None else (time_key(ef.obj(cursor)["afterTime"]), ef.text(ef.obj(cursor)["afterKey"]))
    selected = []
    for row in rows:
        event_valid(row, subscription)
        stamp = time_key(row["TimeGenerated"])
        if not time_key(window["start"]) <= stamp <= time_key(window["end"]):
            raise ValueError("Workspace row exceeds requested history window")
        key = stamp, ef.text(row["RowKey"])
        if previous is not None and key <= previous:
            raise ValueError("Workspace result order/cursor is not strictly increasing")
        previous = key
        selected.append({"record": row, "omittedPaths": [
            "Unprojected AzureActivity columns", "CallerIpAddress", "Unreviewed claims/properties",
        ], "sourceRow": len(selected)})
    next_cursor = None
    if len(selected) == 501:
        selected = selected[:500]
        last = ef.obj(selected[-1]["record"])
        next_cursor = {"afterTime": cursor_time(last["TimeGenerated"]),
                       "afterKey": last["RowKey"]}
    return selected, next_cursor, len(selected), 0


class Reader(Protocol):
    def context(self) -> ef.Record: ...
    def workspace(self, operation: str, resource_id: str, workspace_id: str | None = None,
                  window: ef.Record | None = None, cursor: object = None) -> ef.Record: ...


def workspace_resource(value: object) -> str:
    identifier = ef.text(value)
    pattern = r"/subscriptions/([0-9a-f-]{36})/resourcegroups/[^/?#\\%]+/providers/microsoft\.operationalinsights/workspaces/[^/?#\\%]+"
    match = re.fullmatch(pattern, identifier, re.IGNORECASE)
    if match is None or any(part in (".", "..") for part in identifier.split("/")):
        raise ValueError("Expected an explicit Log Analytics workspace resource ID")
    ef.canonical_uuid(match.group(1))
    return identifier


def query_window(start: str, end: str, planning_time: str) -> ef.Record:
    first, last, planned = (events.time(events.utc(value)) for value in (start, end, planning_time))
    if first >= last or last > planned or last - first > timedelta(days=365):
        raise ValueError("Workspace history window must be positive, at most 365 days and not in the future")
    return {"start": start, "end": end, "expired": False, "selectionBasis": "AzureActivity.TimeGenerated",
            "nativeLimitDays": None, "availabilityAssurance": "workspace-queryable-history-not-completeness",
            "retentionGap": None, "boundary": "fixed-inclusive-UTC-range; late-ingested rows may arrive later"}


def query_rows(response: object, columns: tuple[str, ...]) -> list[ef.Record]:
    response = ef.obj(response)
    if response.get("error") is not None:
        raise ValueError("Logs query returned partial/error results; rows are not complete evidence")
    tables = ef.records(response.get("tables"))
    if len(tables) != 1 or tables[0].get("name") != "PrimaryResult":
        raise ValueError("Logs query returned an unexpected table set")
    table = tables[0]
    names = [ef.text(column["name"]) for column in ef.records(table.get("columns"))]
    if len(names) != len(set(names)) or set(names) != set(columns):
        raise ValueError("Logs result columns differ from the reviewed projection")
    rows = ef.array(table.get("rows"))
    if len(rows) > ef.MAX_ROWS:
        raise ValueError("Logs result row budget exceeded")
    result = []
    for value in rows:
        values = ef.array(value)
        if len(values) != len(names):
            raise ValueError("Logs row does not match its column schema")
        result.append(dict(zip(names, values)))
    return result


def read_outcome(response: object) -> tuple[ef.Record, str | None]:
    record = ef.fields(response, {"statusCode", "body", "requestId"}, {"errorCode", "transportOutcome"})
    status = ef.integer(record["statusCode"])
    if status == 200 and record.get("transportOutcome") is None:
        return record, None
    if status in (401, 403):
        return record, "AuthorizationUnavailable"
    if status == 404:
        return record, "WorkspaceOrTableNotFound"
    if status == 429:
        return record, "QueryThrottled"
    return record, "SourceUnavailable"


def preflight(reader: Reader, tenant: str, subscription: str, client: str, resource_id: str,
              start: str, end: str, *, planning_time: str | None = None) -> ef.Record:
    approved = snapshot.scope(tenant, subscription, client)
    resource_id = workspace_resource(resource_id)
    planned = planning_time or ef.utc_now()
    window = query_window(start, end, planned)
    snapshot.validate_context(reader.context(), approved)
    result: ef.Record = {
        "preflightVersion": "1.0.0", "sourceId": SOURCE, "scope": approved,
        "workspaceResourceId": resource_id, "workspaceId": None, "queryWindow": window,
        "checkedAtUtc": ef.utc_now(), "planningTime": planned,
        "readiness": "UNKNOWN", "reason": None, "outcomes": [],
        "workspaceMetadata": None, "tableMetadata": None, "observedCoverage": None,
        "fullWindowCompletenessProven": False, "sourceSelection": "Log-Analytics-preferred-no-direct-fallback",
    }
    response, error = read_outcome(reader.workspace("describe", resource_id))
    ef.array(result["outcomes"]).append({"operation": "describe", "httpStatus": response["statusCode"], "error": error})
    if error:
        result["reason"] = "WorkspaceMetadata" + error
        return result
    metadata = ef.obj(response["body"])
    if ef.text(metadata.get("id")).lower() != resource_id.lower():
        raise ValueError("Workspace metadata resource differs from explicitly approved destination")
    properties = ef.obj(metadata.get("properties"))
    workspace_id = ef.canonical_uuid(ef.text(properties.get("customerId")))
    result["workspaceId"] = workspace_id
    result["workspaceMetadata"] = {key: properties[key] for key in ("retentionInDays", "publicNetworkAccessForQuery")
                                  if key in properties}
    response, error = read_outcome(reader.workspace("table", resource_id, workspace_id))
    ef.array(result["outcomes"]).append({"operation": "table", "httpStatus": response["statusCode"], "error": error})
    if error:
        result["reason"] = "TableMetadata" + error
        return result
    table = ef.obj(response["body"])
    if table.get("name") != "AzureActivity":
        raise ValueError("Workspace table metadata is not AzureActivity")
    table_properties = ef.obj(table.get("properties"))
    selected = {key: table_properties[key] for key in ("plan", "retentionInDays", "totalRetentionInDays", "archiveRetentionInDays")
                if key in table_properties}
    schema = ef.obj(table_properties.get("schema", {}))
    inventories = {
        key: None if schema[key] is None else [ef.text(column["name"]) for column in ef.records(schema[key])]
        for key in ("columns", "standardColumns") if key in schema
    }
    columns = sorted({name for values in inventories.values() if values is not None for name in values})
    if len(columns) > 1000 or any(values is not None and len(values) > 1000 for values in inventories.values()):
        raise ValueError("Workspace schema column budget exceeded")
    selected["columns"], selected["schemaSources"] = columns, inventories
    result["tableMetadata"] = selected
    if selected.get("plan") != "Analytics":
        result["reason"] = "TablePlanUnavailableOrUnsupported"
        return result
    if not {"TimeGenerated", "SubscriptionId", "EventDataId", "CategoryValue"} <= set(columns):
        result["reason"] = "RequiredAzureActivityColumnsUnavailable"
        return result
    response, error = read_outcome(reader.workspace("summary", resource_id, workspace_id, window))
    ef.array(result["outcomes"]).append({"operation": "summary", "httpStatus": response["statusCode"], "error": error})
    if error:
        result["reason"] = "LogsQuery" + error
        return result
    if ef.obj(response["body"]).get("error") is not None:
        result["reason"] = "LogsQueryPartialError"
        ef.obj(ef.array(result["outcomes"])[-1])["error"] = "PartialError"
        return result
    rows = query_rows(response["body"], SUMMARY_COLUMNS)
    summary = []
    categories = set()
    for row in rows:
        category = ef.text(row["Category"])
        count = ef.integer(row["Records"])
        callers = ef.integer(row["WithCaller"])
        if category not in CATEGORIES or category in categories or not 0 <= callers <= count:
            raise ValueError("Invalid workspace category coverage")
        categories.add(category)
        if count:
            if not events.time(start) <= events.time(row["Earliest"]) <= events.time(row["Latest"]) <= events.time(end):
                raise ValueError("Workspace summary exceeds assessed query window")
        elif row["Earliest"] is not None or row["Latest"] is not None:
            raise ValueError("Empty workspace summary claims event times")
        summary.append(dict(row))
    relevant = sum(ef.integer(row["Records"]) for row in summary if row["Category"] in CATEGORIES)
    available = {ef.text(row["Category"]) for row in summary if ef.integer(row["Records"]) > 0}
    result["observedCoverage"] = {"categories": sorted(summary, key=lambda row: ef.text(row["Category"])),
                                  "relevantRecords": relevant,
                                  "missingCategories": [category for category in CATEGORIES if category not in available],
                                  "notes": ["Observed dates and current retention do not prove continuous historical coverage.",
                                            "Archived data and categories with no rows are not restored or enabled."]}
    result["readiness"] = "AVAILABLE" if relevant else "UNKNOWN"
    result["reason"] = "RelevantAzureActivityRowsObserved" if relevant else "NoRelevantAzureActivityRows"
    return result


def destination_cursor(subscription: str, value: object) -> None:
    if value is None:
        return
    link = ef.text(ef.fields(value, {"nextLink"})["nextLink"])
    uri = urllib.parse.urlsplit(link)
    parts = urllib.parse.parse_qsl(uri.query, keep_blank_values=True)
    query = dict(parts)
    if (
        uri.scheme != "https" or uri.hostname != "management.azure.com" or uri.port not in (None, 443)
        or uri.username or uri.password or uri.fragment
        or uri.path.lower() != "/subscriptions/" + subscription + "/providers/microsoft.insights/diagnosticsettings"
        or len(parts) != len(query) or query.get("api-version") != "2021-05-01-preview"
        or any(key not in ("api-version", "$skiptoken", "$skipToken") for key in query)
        or not (query.get("$skiptoken") or query.get("$skipToken"))
    ):
        raise ValueError("Diagnostic-settings continuation exceeds approved subscription")


def discover(reader: Reader, tenant: str, subscription: str, client: str, start: str, end: str, *,
             approved_workspaces: list[str] | None = None) -> ef.Record:
    approved = snapshot.scope(tenant, subscription, client)
    subscription = ef.text(approved["subscriptionId"])
    window = query_window(start, end, ef.utc_now())
    explicit = {workspace_resource(value).lower(): workspace_resource(value) for value in (approved_workspaces or [])}
    if len(explicit) > 20:
        raise ValueError("Explicit workspace discovery budget exceeded")
    snapshot.validate_context(reader.context(), approved)
    report: ef.Record = {
        "discoveryVersion": "1.0.0", "sourceId": SOURCE, "scope": approved, "queryWindow": window,
        "readiness": "UNKNOWN", "reason": None, "selectedWorkspaceResourceId": None,
        "diagnosticSettingPages": [], "candidates": [], "checkedAtUtc": ef.utc_now(),
        "sourceSelection": "Log-Analytics-preferred-no-direct-fallback",
    }
    candidates: dict[str, ef.Record] = {}
    cursor = None
    seen = set()
    for _ in range(10):
        response, error = read_outcome(reader.workspace("destinations", "/subscriptions/" + subscription, cursor=cursor))
        ef.array(report["diagnosticSettingPages"]).append({"httpStatus": response["statusCode"], "error": error})
        if error:
            break
        body = ef.obj(response["body"])
        settings = ef.records(body.get("value"))
        if len(settings) > 100:
            raise ValueError("Diagnostic-settings row budget exceeded")
        for setting in settings:
            properties = ef.obj(setting.get("properties"))
            identifier = properties.get("workspaceId")
            if identifier is None:
                continue
            identifier = workspace_resource(identifier)
            candidate = candidates.setdefault(identifier.lower(), {
                "workspaceResourceId": identifier, "configuredCategories": [], "origins": [],
                "exportSettingProvesIngestion": False,
            })
            origin = {"settingName": ef.text(setting.get("name")), "source": "subscriptionDiagnosticSetting"}
            ef.array(candidate["origins"]).append(origin)
            logs = ef.records(properties.get("logs", []))
            if len(logs) > 100:
                raise ValueError("Diagnostic category budget exceeded")
            for log in logs:
                category = {key: log[key] for key in ("category", "categoryGroup", "enabled") if key in log}
                if "enabled" in category and category["enabled"] is not None and not isinstance(category["enabled"], bool):
                    raise ValueError("Invalid diagnostic category enabled flag")
                for key in ("category", "categoryGroup"):
                    if category.get(key) is not None:
                        ef.text(category[key])
                ef.array(candidate["configuredCategories"]).append(category)
        next_link = body.get("nextLink")
        if next_link is None:
            break
        cursor = {"nextLink": next_link}
        destination_cursor(subscription, cursor)
        fingerprint = ef.digest(cursor)
        if fingerprint in seen:
            raise ValueError("Repeated diagnostic-settings continuation")
        seen.add(fingerprint)
    else:
        raise ValueError("Diagnostic-settings page budget exhausted; no complete discovery claimed")
    for key, identifier in explicit.items():
        candidate = candidates.setdefault(key, {"workspaceResourceId": identifier, "configuredCategories": [],
                                                 "origins": [], "exportSettingProvesIngestion": False})
        ef.array(candidate["origins"]).append({"source": "explicitlyApprovedWorkspace"})
    if len(candidates) > 20:
        raise ValueError("Candidate workspace budget exceeded")
    available = []
    for key in sorted(candidates):
        candidate = candidates[key]
        identifier = ef.text(candidate["workspaceResourceId"])
        in_subscription = identifier.lower().startswith("/subscriptions/" + subscription + "/")
        if not in_subscription and key not in explicit:
            candidate.update({"readiness": "UNKNOWN", "reason": "WorkspaceReadScopeApprovalRequired", "preflight": None})
        else:
            evidence = preflight(reader, tenant, subscription, client, identifier, start, end)
            candidate.update({"readiness": evidence["readiness"], "reason": evidence["reason"], "preflight": evidence})
            if evidence["readiness"] == "AVAILABLE":
                available.append(identifier)
        ef.array(report["candidates"]).append(candidate)
    if len(available) == 1:
        report.update({"readiness": "AVAILABLE", "reason": "OneVerifiedWorkspace", "selectedWorkspaceResourceId": available[0]})
    else:
        report["reason"] = "ChooseAmongVerifiedWorkspaces" if available else "NoVerifiedWorkspaceHistory"
    return report


def validate_preflight(value: object, approved: ef.Record, window: ef.Record) -> ef.Record:
    result = ef.fields(value, {
        "preflightVersion", "sourceId", "scope", "workspaceResourceId", "workspaceId", "queryWindow",
        "checkedAtUtc", "planningTime", "readiness", "reason", "outcomes", "workspaceMetadata",
        "tableMetadata", "observedCoverage", "fullWindowCompletenessProven", "sourceSelection",
    })
    if (
        result["preflightVersion"] != "1.0.0" or result["sourceId"] != SOURCE or result["scope"] != approved
        or result["queryWindow"] != window or result["readiness"] != "AVAILABLE"
        or result["reason"] != "RelevantAzureActivityRowsObserved" or result["fullWindowCompletenessProven"] is not False
        or result["sourceSelection"] != "Log-Analytics-preferred-no-direct-fallback"
    ):
        raise ValueError("Workspace readiness/scope/window binding is not verified")
    workspace_resource(result["workspaceResourceId"])
    ef.canonical_uuid(ef.text(result["workspaceId"]))
    events.time(result["checkedAtUtc"])
    events.time(result["planningTime"])
    metadata = ef.fields(result["workspaceMetadata"], set(), {"retentionInDays", "publicNetworkAccessForQuery"})
    if metadata.get("retentionInDays") is not None:
        ef.integer(metadata["retentionInDays"])
    if metadata.get("publicNetworkAccessForQuery") is not None:
        ef.text(metadata["publicNetworkAccessForQuery"])
    table = ef.fields(result["tableMetadata"], {"plan", "columns", "schemaSources"},
                      {"retentionInDays", "totalRetentionInDays", "archiveRetentionInDays"})
    if table["plan"] != "Analytics":
        raise ValueError("Unsupported workspace table plan")
    for key in ("retentionInDays", "totalRetentionInDays", "archiveRetentionInDays"):
        if table.get(key) is not None:
            ef.integer(table[key])
    columns = [ef.text(entry) for entry in ef.array(table["columns"])]
    inventories = ef.fields(table["schemaSources"], set(), {"columns", "standardColumns"})
    declared = set()
    for values in inventories.values():
        if values is not None:
            declared.update(ef.text(entry) for entry in ef.array(values))
    if columns != sorted(declared):
        raise ValueError("Workspace combined columns differ from retained schema inventories")
    if len(columns) > 1000 or not {"TimeGenerated", "SubscriptionId", "EventDataId", "CategoryValue"} <= set(columns):
        raise ValueError("Workspace required columns are not verified")
    observed = ef.fields(result["observedCoverage"], {"categories", "relevantRecords", "missingCategories", "notes"})
    categories = ef.records(observed["categories"])
    relevant = 0
    available = set()
    seen_categories = set()
    for row in categories:
        ef.fields(row, set(SUMMARY_COLUMNS))
        category = ef.text(row["Category"])
        count, callers = ef.integer(row["Records"]), ef.integer(row["WithCaller"])
        if category not in CATEGORIES or category in seen_categories or not 0 <= callers <= count:
            raise ValueError("Workspace category counts disagree")
        seen_categories.add(category)
        if count:
            if not time_key(window["start"]) <= time_key(row["Earliest"]) <= time_key(row["Latest"]) <= time_key(window["end"]):
                raise ValueError("Workspace observed dates exceed approved range")
            available.add(category)
        elif row["Earliest"] is not None or row["Latest"] is not None:
            raise ValueError("Empty workspace category claims source dates")
        if category in CATEGORIES:
            relevant += count
    if relevant <= 0 or observed["relevantRecords"] != relevant or observed["missingCategories"] != [
        category for category in CATEGORIES if category not in available
    ]:
        raise ValueError("Workspace relevant-row/category coverage is not verified")
    for note in ef.array(observed["notes"]):
        ef.text(note)
    outcomes = ef.records(result["outcomes"])
    if len(outcomes) != 3 or [entry["operation"] for entry in outcomes] != ["describe", "table", "summary"]:
        raise ValueError("Workspace preflight operation coverage differs")
    for entry in outcomes:
        ef.fields(entry, {"operation", "httpStatus", "error"})
        if entry["httpStatus"] != 200 or entry["error"] is not None:
            raise ValueError("Workspace preflight contains failed/partial sources")
    return result


class BoundReader:
    def __init__(self, reader: Reader, result: ef.Record):
        self.reader, self.result = reader, result

    def context(self) -> ef.Record:
        return self.reader.context()

    def events(self, source: str, window: ef.Record, cursor: object) -> ef.Record:
        if source != SOURCE or window != self.result["queryWindow"]:
            raise ValueError("Workspace collection exceeds verified source/window")
        cursor_valid(ef.text(ef.obj(self.result["scope"])["subscriptionId"]), window, cursor)
        return self.reader.workspace("page", ef.text(self.result["workspaceResourceId"]),
                                     ef.text(self.result["workspaceId"]), window, cursor)


def capture(reader: Reader, tenant: str, subscription: str, client: str, capture_id: str, output_root: Path,
            resource_id: str, start: str, end: str, *, planning_time: str | None = None, resume: bool = False,
            retry_unconfirmed: bool = False, previous_capsule: Path | None = None) -> Path:
    import network_history as history
    approved = snapshot.scope(tenant, subscription, client)
    capture_id = ef.canonical_uuid(capture_id)
    resource_id = workspace_resource(resource_id)
    if previous_capsule is not None:
        previous = history.verify(previous_capsule)
        if (
            previous["sourceId"] != SOURCE or previous["scope"] != approved
            or ef.text(ef.obj(previous["workspace"])["workspaceResourceId"]).lower() != resource_id.lower()
            or ef.obj(previous["watermark"])["enumeratedThrough"] is None
        ):
            raise ValueError("Previous workspace source is incomplete or differs from approved scope")
        start = (events.time(ef.obj(previous["watermark"])["enumeratedThrough"]) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    if resume:
        state = ef.decode(ef.read_member(output_root / "history-acquisition" / capture_id / "state.json"))
        result = ef.obj(state.get("workspace"))
        if ef.text(result["workspaceResourceId"]).lower() != resource_id.lower():
            raise ValueError("Resume workspace differs from saved source")
    else:
        result = preflight(reader, tenant, subscription, client, resource_id, start, end, planning_time=planning_time)
        if result["readiness"] != "AVAILABLE":
            raise ValueError("Workspace Activity Log readiness UNKNOWN: " + ef.text(result["reason"]) + "; no direct fallback or capture attempted")
    window = query_window(start, end, ef.text(result["planningTime"]))
    validate_preflight(result, approved, window)
    return history.capture(BoundReader(reader, result), SOURCE, tenant, subscription, client, capture_id, output_root,
                           start, end, planning_time=ef.text(result["planningTime"]), resume=resume,
                           retry_unconfirmed=retry_unconfirmed, previous_capsule=previous_capsule, workspace=result)


class WorkspaceBridge(snapshot.ArmBridge):
    SCRIPT = "workspace_reader.ps1"

    def __init__(self, approved: ef.Record, approved_workspaces: list[str]):
        super().__init__(approved)
        self.workspaces = {workspace_resource(value).lower() for value in approved_workspaces}
        self.bindings: dict[str, str] = {}
        if len(self.workspaces) > 20:
            raise ValueError("Approved workspace count exceeds profile")

    def bootstrap_arguments(self) -> list[str]:
        return ["-ApprovedWorkspacesJson", json.dumps(sorted(self.workspaces))]

    def workspace(self, operation: str, resource_id: str, workspace_id: str | None = None,
                  window: ef.Record | None = None, cursor: object = None) -> ef.Record:
        subscription = ef.text(self.approved["subscriptionId"])
        if operation == "destinations":
            if resource_id != "/subscriptions/" + subscription or workspace_id is not None or window is not None:
                raise ValueError("Workspace discovery exceeds assessed subscription")
            destination_cursor(subscription, cursor)
        else:
            resource_id = workspace_resource(resource_id)
            if not resource_id.lower().startswith("/subscriptions/" + subscription + "/") and resource_id.lower() not in self.workspaces:
                raise ValueError("External workspace read scope is not approved")
            if operation not in ("describe", "table", "summary", "page"):
                raise ValueError("Unreviewed workspace operation")
            if operation == "describe" and (workspace_id is not None or window is not None or cursor is not None):
                raise ValueError("Unexpected workspace describe inputs")
            if operation != "describe":
                if workspace_id is None or ef.canonical_uuid(workspace_id) != workspace_id:
                    raise ValueError("Workspace query requires canonical workspace ID")
                if resource_id.lower() not in self.bindings:
                    metadata = self.workspace("describe", resource_id)
                    _, error = read_outcome(metadata)
                    if error:
                        return metadata
                if self.bindings[resource_id.lower()] != workspace_id:
                    raise ValueError("Workspace query ID differs from authoritative metadata")
            if operation in ("summary", "page"):
                if window is None:
                    raise ValueError("Workspace data query requires explicit time window")
                cursor_valid(subscription, window, cursor)
                if operation == "summary" and cursor is not None:
                    raise ValueError("Workspace summary cannot have a cursor")
                kql(operation, subscription, window, cursor)
            elif window is not None or cursor is not None:
                raise ValueError("Unexpected workspace metadata query inputs")
        result = self.exchange({"operation": operation, "workspaceResourceId": resource_id,
                                "workspaceId": workspace_id, "window": window, "cursor": cursor})
        if operation == "describe":
            _, error = read_outcome(result)
            if not error:
                body = ef.obj(result["body"])
                if ef.text(body.get("id")).lower() != resource_id.lower():
                    raise ValueError("Workspace metadata scope differs")
                self.bindings[resource_id.lower()] = ef.canonical_uuid(ef.text(ef.obj(body.get("properties")).get("customerId")))
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("discover", "preflight", "capture"):
        command = commands.add_parser(name)
        for argument in ("tenant-id", "subscription-id", "managed-identity-client-id", "start-time", "end-time"):
            command.add_argument("--" + argument, required=True)
        if name == "discover":
            command.add_argument("--approved-workspace-resource-id", action="append", default=[])
        else:
            command.add_argument("--workspace-resource-id", required=True)
        if name == "capture":
            command.add_argument("--capture-id", required=True)
            command.add_argument("--output-root", type=Path, required=True)
            command.add_argument("--resume", action="store_true")
            command.add_argument("--retry-unconfirmed", action="store_true")
            command.add_argument("--previous-capsule", type=Path)
        else:
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reader = None
    try:
        approved = snapshot.scope(args.tenant_id, args.subscription_id, args.managed_identity_client_id)
        workspaces = args.approved_workspace_resource_id if args.command == "discover" else [args.workspace_resource_id]
        reader = WorkspaceBridge(approved, workspaces)
        if args.command == "capture":
            directory = capture(reader, args.tenant_id, args.subscription_id, args.managed_identity_client_id,
                                args.capture_id, args.output_root, args.workspace_resource_id,
                                args.start_time, args.end_time, resume=args.resume,
                                retry_unconfirmed=args.retry_unconfirmed, previous_capsule=args.previous_capsule)
            import network_history
            readiness = ef.obj(ef.obj(network_history.verify(directory)["coverage"])["readiness"])
            print(ef.encoded({"status": "captured-workspace-activity" if readiness["status"] == "AVAILABLE" else "UNKNOWN",
                              "readiness": readiness, "capsule": str(directory), "capsuleVersion": CAPSULE_VERSION,
                              "assessmentPerformed": False}).decode().strip())
            return 0 if readiness["status"] == "AVAILABLE" else 2
        snapshot.checked_root(args.output.parent)
        if os.path.lexists(args.output):
            raise FileExistsError("Workspace readiness output already exists")
        result = (
            discover(reader, args.tenant_id, args.subscription_id, args.managed_identity_client_id,
                     args.start_time, args.end_time, approved_workspaces=workspaces)
            if args.command == "discover" else
            preflight(reader, args.tenant_id, args.subscription_id, args.managed_identity_client_id,
                      args.workspace_resource_id, args.start_time, args.end_time)
        )
        content = ef.encoded(result)
        ef.immutable_file(args.output, content)
        print(ef.encoded({"readiness": result["readiness"], "reason": result["reason"],
                          "output": str(args.output), "sha256": hashlib.sha256(content).hexdigest(),
                          "directFallbackAttempted": False}).decode().strip())
        return 0 if result["readiness"] == "AVAILABLE" else 2
    except (ValueError, OSError, snapshot.UnconfirmedRead) as error:
        parser.exit(2, "Workspace Activity Log operation failed: " + str(error) + "\n")
    finally:
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    raise SystemExit(main())
