"""Reviewed existing-event selection, explicit UTC windows and source policies."""

from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import configuration_profile as configuration
import evidence_files as ef


SOURCES = ("activity-log", "resource-changes", "service-health")
RETENTION = {"activity-log": 90, "resource-changes": 14, "service-health": None}
ACTIVITY_CATEGORIES = ("Administrative", "ResourceHealth", "ServiceHealth")
ACTIVITY_FIELDS = {
    "id": "text", "eventDataId": "text", "eventTimestamp": "text", "submissionTimestamp": "text",
    "caller": "text", "subscriptionId": "text", "tenantId": "text", "resourceId": "text",
    "resourceGroupName": "text", "correlationId": "text", "operationId": "text", "level": "text",
    **{name: {"value": "text", "localizedValue": "text"} for name in (
        "category", "operationName", "eventName", "resourceProviderName", "resourceType", "status", "subStatus",
    )},
    "authorization": {"action": "text", "scope": "text", "role": "text"},
}
ACTOR_CLAIMS = (
    "appid", "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "http://schemas.microsoft.com/identity/claims/applicationid",
)
ACTIVITY_HEALTH_PROPERTIES = {
    "title": "text", "currentHealthStatus": "text", "previousHealthStatus": "text",
    "cause": "text", "type": "text", "reason": "text", "occurredTime": "text", "reportedTime": "text",
    "eventCategory": "text",
    "eventProperties": {"title": "text", "currentHealthStatus": "text", "previousHealthStatus": "text",
                        "cause": "text", "type": "text", "reason": "text"},
}
HEALTH_PROPERTIES = {
    **{name: "text" for name in (
        "eventType", "eventSubType", "eventSource", "status", "eventLevel", "level", "title", "header", "summary",
        "reason", "lastUpdateTime", "impactStartTime", "impactMitigationTime", "externalIncidentId", "impactType",
    )},
    "platformInitiated": "bool", "isEventSensitive": "bool", "duration": "integer", "priority": "integer",
    "eventTags": ["text"],
    "impact": [{"impactedService": "text", "impactedRegions": [{
        "impactedRegion": "text", "status": "text", "impactStartTime": "text", "impactMitigationTime": "text",
        "updates": [{"summary": "text", "updateDateTime": "text", "eventTags": ["text"]}],
    }]}],
}
HEALTH_FIELDS = {"id": "text", "name": "text", "type": "text", "location": "text", "properties": HEALTH_PROPERTIES}
CHANGE_FIELDS = {"id": "text", "subscriptionId": "text", "targetResourceId": "text", "targetResourceType": "text",
                 "changeType": "text", "changeAttributes": {
                     "timestamp": "text", "changedBy": "text", "changedByType": "text", "clientType": "text",
                     "operation": "text", "correlationId": "text", "changesCount": "integer",
                     "previousResourceSnapshotId": "text", "newResourceSnapshotId": "text",
                 }}
QUERY_TEMPLATE = Path(__file__).with_name("resource-changes.kql").read_text(encoding="utf-8").strip()
PROFILE_SHA = ef.digest({"activity": ACTIVITY_FIELDS, "health": HEALTH_FIELDS, "changes": CHANGE_FIELDS,
                        "claims": ACTOR_CLAIMS, "activityHealth": ACTIVITY_HEALTH_PROPERTIES,
                        "retention": RETENTION, "query": QUERY_TEMPLATE, "configurationProfile": configuration.PROFILE_SHA,
                        "overlapHours": 24, "pageRows": 1000, "graphPageRows": 500, "maxRecords": 20000})


def time(value: object) -> datetime:
    text = ef.text(value)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})", text) is None:
        raise ValueError("Source timestamp is not an ISO timestamp with an offset")
    result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if result.utcoffset() is None:
        raise ValueError("Source timestamp has no offset")
    return result.astimezone(timezone.utc)


def utc(value: object) -> str:
    text = ef.text(value)
    if not text.endswith("Z"):
        raise ValueError("Requested source window must use UTC Z")
    time(text)
    return text


def query_window(source: str, start: str, end: str, planning_time: str) -> ef.Record:
    if source not in SOURCES:
        raise ValueError("Unsupported history source")
    first, last, planned = time(utc(start)), time(utc(end)), time(utc(planning_time))
    if first >= last or last > planned or last - first > timedelta(days=365):
        raise ValueError("History window must be positive, at most 365 days and not in the future")
    days = RETENTION[source]
    cutoff = planned - timedelta(days=days) if days is not None else first
    effective = max(first, cutoff)
    return {
        "start": effective.isoformat().replace("+00:00", "Z") if effective != first else start,
        "end": end, "expired": effective >= last,
        "selectionBasis": "lastUpdateTime" if source == "service-health" else "eventTimestamp" if source == "activity-log" else "changeAttributes.timestamp",
        "nativeLimitDays": days, "availabilityAssurance": "native-retention-limit" if days else "requested-history-not-proven-retention",
        "retentionGap": {"start": start, "end": min(cutoff, last).isoformat().replace("+00:00", "Z")} if first < cutoff else None,
        "boundary": "inclusive-source-timestamps; service-health-query-date-floor-and-client-upper-bound",
    }


def activity_filter(window: ef.Record) -> str:
    return "eventTimestamp ge '" + utc(window["start"]) + "' and eventTimestamp le '" + utc(window["end"]) + "'"


def request_url(source: str, subscription: str, window: ef.Record, cursor: object) -> str:
    if source == "resource-changes":
        return "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
    path = (
        "/subscriptions/" + subscription + "/providers/Microsoft.Insights/eventtypes/management/values"
        if source == "activity-log" else "/subscriptions/" + subscription + "/providers/Microsoft.ResourceHealth/events"
    )
    version = "2015-04-01" if source == "activity-log" else "2025-05-01"
    parameters = {"api-version": version}
    if source == "activity-log":
        parameters["$filter"] = activity_filter(window)
    else:
        parameters["queryStartTime"] = time(window["start"]).strftime("%m/%d/%Y")
    initial = "https://management.azure.com" + path + "?" + urllib.parse.urlencode(parameters)
    if cursor is None:
        return initial
    retained = ef.fields(cursor, {"nextLink"})
    uri = urllib.parse.urlsplit(ef.text(retained["nextLink"]))
    query = urllib.parse.parse_qsl(uri.query, keep_blank_values=True)
    values = dict(query)
    if (
        uri.scheme != "https" or uri.hostname != "management.azure.com" or uri.port not in (None, 443)
        or uri.username or uri.password or uri.fragment
        or urllib.parse.unquote(uri.path).lower() != path.lower()
        or len(query) != len(values) or values.get("api-version") != version
        or any(key not in ("api-version", "$filter", "queryStartTime", "$skiptoken", "$skipToken") for key in values)
        or not (values.get("$skiptoken") or values.get("$skipToken"))
        or ("$filter" in values and (source != "activity-log" or values["$filter"] != activity_filter(window)))
        or ("queryStartTime" in values and (source != "service-health" or values["queryStartTime"] != parameters["queryStartTime"]))
    ):
        raise ValueError("History continuation exceeds approved source/scope/window")
    return ef.text(retained["nextLink"])


def graph_body(subscription: str, window: ef.Record, cursor: object) -> ef.Record:
    query = QUERY_TEMPLATE.replace("__SUBSCRIPTION__", subscription).replace("__START__", utc(window["start"])).replace("__END__", utc(window["end"]))
    options: ef.Record = {"$top": 500, "resultFormat": "objectArray"}
    if cursor is not None:
        token = ef.text(ef.fields(cursor, {"skipToken"})["skipToken"])
        if not token or len(token) > 16000:
            raise ValueError("Invalid bounded Resource Graph continuation")
        options["$skipToken"] = token
    return {"subscriptions": [subscription], "query": query, "options": options}


def scoped(value: ef.Record, subscription: str, resource_field: str | None = None) -> None:
    if value.get("subscriptionId") is not None and ef.canonical_uuid(ef.text(value["subscriptionId"])) != subscription:
        raise ValueError("History record subscription differs from source scope")
    if resource_field and value.get(resource_field) is not None:
        identifier = ef.text(value[resource_field])
        if identifier.lower().startswith("/subscriptions/") and not (
            identifier.lower() == "/subscriptions/" + subscription or identifier.lower().startswith("/subscriptions/" + subscription + "/")
        ):
            raise ValueError("History resource reference exceeds source subscription")


def config_node(resource_type: str, path: str) -> configuration.Node | None:
    family = next((name for name, pair in configuration.TYPES.items() if pair[0].lower() == resource_type.lower()), None)
    if family is None:
        return None
    current: configuration.Node = configuration.schema(family + "-get")
    segments = re.findall(r"(?:^|\.)([A-Za-z][A-Za-z0-9_]*)(?:\[(\d+)\])?", path)
    reconstructed = ".".join(name + ("[" + number + "]" if number else "") for name, number in segments)
    if reconstructed != path:
        return None
    for name, number in segments:
        if not isinstance(current, dict) or name not in current:
            return None
        current = current[name]
        if number:
            if not isinstance(current, list):
                return None
            current = current[0]
    return current


def change_value(entry: ef.Record, key: str, shape: configuration.Node | None) -> ef.Record:
    if key not in entry:
        return {"status": "notProvided"}
    value = entry[key]
    if shape is None:
        return {"status": "unreviewedPathOmitted"}
    if value is None:
        return {"status": "selected", "value": None, "representation": "source-null", "omittedPaths": []}
    if isinstance(shape, str) and isinstance(value, str) and shape != "text":
        valid = (
            shape == "bool" and value.lower() in ("true", "false")
            or shape == "integer" and re.fullmatch(r"-?\d+", value) is not None
            or shape == "number" and re.fullmatch(r"-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", value) is not None
        )
        if not valid:
            return {"status": "unsupportedSourceValueShape"}
        return {"status": "selected", "value": value, "representation": "source-string", "omittedPaths": []}
    try:
        selected, omitted = configuration.select(value, shape)
    except ValueError:
        return {"status": "unsupportedSourceValueShape"}
    return {"status": "selected", "value": selected, "representation": "source-json", "omittedPaths": omitted}


def select_event(source: str, value: object, subscription: str) -> tuple[ef.Record | None, list[str]]:
    record = ef.obj(value)
    scoped(record, subscription, "targetResourceId" if source == "resource-changes" else "resourceId")
    if source == "activity-log":
        category = ef.obj(record["category"]).get("value") if record.get("category") is not None else None
        if category is not None and category not in ACTIVITY_CATEGORIES:
            return None, ["categoryNotInApprovedProfile"]
        selected, omitted = configuration.select(record, ACTIVITY_FIELDS)
        result = ef.obj(selected)
        claims = ef.obj(record["claims"]) if record.get("claims") is not None else {}
        result["actorClaims"] = {key: ef.text(claims[key]) if claims[key] is not None else None for key in ACTOR_CLAIMS if key in claims}
        result["actorClaimsSourceState"] = "notProvided" if "claims" not in record else "explicitNull" if record["claims"] is None else "selected"
        if "properties" in record and record["properties"] is None:
            result["healthProperties"] = None
        elif record.get("properties") is not None:
            health, omissions = configuration.select(record["properties"], ACTIVITY_HEALTH_PROPERTIES)
            result["healthProperties"] = health
            omitted.extend("/properties" + path for path in omissions)
        return result, sorted(set(omitted))
    if source == "service-health":
        selected, omitted = configuration.select(record, HEALTH_FIELDS)
        result = ef.obj(selected)
        properties = ef.obj(result["properties"]) if result.get("properties") is not None else {}
        if properties.get("isEventSensitive") is True:
            if "summary" in properties:
                del properties["summary"]
                omitted.append("/properties/summary")
            for impact in ef.records(properties.get("impact", [])):
                for region in ef.records(impact.get("impactedRegions", [])):
                    for update in ef.records(region.get("updates", [])):
                        update.pop("summary", None)
            omitted.append("/properties/impact/*/impactedRegions/*/updates/*/summary")
        return result, sorted(set(omitted))
    selected, omitted = configuration.select(record, CHANGE_FIELDS)
    result = ef.obj(selected)
    changes = ef.obj(record["changes"]) if record.get("changes") is not None else {}
    if len(changes) > ef.MAX_ROWS:
        raise ValueError("Changed-property count exceeds history profile")
    result["changedProperties"] = []
    resource_type = ef.text(record["targetResourceType"]) if record.get("targetResourceType") is not None else ""
    for path, raw in sorted(changes.items()):
        change = ef.obj(raw)
        shape = config_node(resource_type, path)
        is_truncated = change.get("isTruncated")
        if is_truncated is not None and not isinstance(is_truncated, (str, bool)):
            raise ValueError("Invalid source truncation marker")
        ef.array(result["changedProperties"]).append({
            "path": path, "sourceTruncation": is_truncated, "reviewedPath": shape is not None,
            "previous": change_value(change, "previousValue", shape), "new": change_value(change, "newValue", shape),
        })
    return result, sorted(set(omitted))


def record_times(source: str, record: ef.Record) -> tuple[object, object, object]:
    if source == "activity-log":
        return record.get("eventTimestamp"), None, record.get("submissionTimestamp")
    if source == "resource-changes":
        return (ef.obj(record["changeAttributes"]).get("timestamp") if record.get("changeAttributes") is not None else None), None, None
    properties = ef.obj(record["properties"]) if record.get("properties") is not None else {}
    return properties.get("impactStartTime"), properties.get("lastUpdateTime"), None


def in_window(source: str, record: ef.Record, window: ef.Record) -> bool:
    event, updated, _ = record_times(source, record)
    selection_time = updated if source == "service-health" else event
    if selection_time is None:
        return True
    return time(window["start"]) <= time(selection_time) <= time(window["end"])


def event_id(source: str, record: ef.Record) -> str | None:
    value = record.get("eventDataId") if source == "activity-log" else record.get("id")
    if value is None and source == "activity-log":
        value = record.get("id")
    return ef.text(value) if value is not None and ef.text(value) else None
