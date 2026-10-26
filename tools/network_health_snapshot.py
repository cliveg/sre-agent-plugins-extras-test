"""Reviewed configuration capture through the audited native SRE read transport."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shlex
import sys
import urllib.parse
from pathlib import Path
from typing import TypeAlias

import network_health_capsule as capsule
import network_health_sre as bridge

CAPTURE_SCRIPTS = bridge.ROOT / "plugins" / "azure-network-health" / "skills" / "azure-network-evidence-capture" / "scripts"
sys.path.insert(0, str(CAPTURE_SCRIPTS))
from configuration_profile import BASE, PROPERTIES, TYPES, ROOTS, OPS, CHILDREN


nh = bridge.nh
Node: TypeAlias = str | dict[str, "Node"] | list["Node"]
PROFILE = "native-configuration-snapshot"
PROFILE_VERSION = "1.0.0"
CAPSULE_VERSION = "0.2.0"
INDEX = "capture-index.json"
AUDIT = "native-audit.json"
MAX_PAGES = 100
MAX_JOBS = 500
MAX_READS = 100
META = "__sourceKeys"
DEFINITION_SHA = nh.digest({"types": TYPES, "operations": OPS, "properties": PROPERTIES, "base": BASE,
                           "rows": capsule.MAX_ROWS, "pages": MAX_PAGES, "jobs": MAX_JOBS})


def schema(op: str) -> dict[str, Node]:
    kind, family, suffix = OPS[op]
    return dict(BASE) if kind == "list" and suffix is None else {**BASE, "properties": PROPERTIES[family]}


def object_query(node: dict[str, Node], prefix: str = "@") -> str:
    fields = [META + ":keys(" + prefix + ")"]
    for name, child in sorted(node.items()):
        fields.append(name + ":" + node_query(child, prefix + "." + name))
    return "{" + ",".join(fields) + "}"


def node_query(node: Node, prefix: str) -> str:
    if isinstance(node, dict):
        return prefix + " && " + object_query(node, prefix)
    if isinstance(node, list):
        child = node[0]
        expression = "." + object_query(child) if isinstance(child, dict) else ""
        return prefix + " && " + prefix + "[:1001]" + expression
    return prefix


def query(op: str) -> str:
    if op == "context":
        return "{subscriptionId:id,tenantId:tenantId}"
    if OPS[op][0] == "get":
        return "{resource:" + object_query(schema(op)) + "}"
    return "{items:value[:1001]." + object_query(schema(op)) + ",nextLink:nextLink,reportedCount:length(value || `[]`)}"


CATALOG_SHA = nh.digest({"definition": DEFINITION_SHA, "queries": {op: query(op) for op in ("context", *OPS)}})


def resource_id(value: object, subscription: str, resource_type: str) -> str:
    identifier = nh.text(value)
    parts = identifier.lower().split("/")
    if (
        len(parts) < 9 or len(parts) % 2 != 1 or parts[1:3] != ["subscriptions", subscription]
        or parts[3] != "resourcegroups" or parts[5] != "providers"
        or "/".join([parts[6], *parts[7::2]]) != resource_type.lower()
        or any(part in ("", ".", "..") for part in parts[1:])
        or any(character in identifier for character in ("\\", "?", "#", "%"))
    ):
        raise ValueError("Snapshot resource identifier/type exceeds approved scope")
    return identifier


def initial_url(op: str, subscription: str, target: str | None) -> str:
    kind, family, suffix = OPS[op]
    resource_type, api = TYPES[family]
    if kind == "get":
        path = resource_id(target, subscription, resource_type)
    elif suffix:
        parent_type = resource_type.rsplit("/", 1)[0]
        path = resource_id(target, subscription, parent_type) + "/" + suffix
    else:
        if target is not None:
            raise ValueError("Root snapshot read cannot have a parent")
        path = "/subscriptions/" + subscription + "/providers/" + resource_type
    return "https://management.azure.com" + urllib.parse.quote(path, safe="/") + "?api-version=" + api


def validate_url(url: object, op: str, subscription: str, target: str | None) -> str:
    text = nh.text(url)
    actual, base = urllib.parse.urlsplit(text), urllib.parse.urlsplit(initial_url(op, subscription, target))
    parameters = urllib.parse.parse_qsl(actual.query, keep_blank_values=True)
    if (
        actual.scheme != "https" or actual.hostname != "management.azure.com" or actual.port not in (None, 443)
        or actual.username or actual.password or actual.fragment
        or urllib.parse.unquote(actual.path).lower() != urllib.parse.unquote(base.path).lower()
        or len(parameters) != len({key for key, _ in parameters})
        or any(key not in ("api-version", "$skiptoken", "$skipToken", "$top") for key, _ in parameters)
        or dict(parameters).get("api-version") != TYPES[OPS[op][1]][1]
        or (OPS[op][0] == "get" and parameters != urllib.parse.parse_qsl(base.query))
    ):
        raise ValueError("Snapshot continuation exceeds approved parent/scope/API")
    if "$top" in dict(parameters) and not 1 <= int(dict(parameters)["$top"]) <= capsule.MAX_ROWS:
        raise ValueError("Snapshot continuation row budget exceeds profile")
    return text


def command(job: nh.Record, subscription: str) -> list[str]:
    op = nh.text(job["operationId"])
    if op == "context":
        return ["az", "account", "show", "--subscription", subscription, "--query", query(op), "-o", "json"]
    target = None if job["targetId"] is None else nh.text(job["targetId"])
    url = validate_url(job["url"], op, subscription, target)
    return ["az", "rest", "--method", "get", "--url", url, "--subscription", subscription,
            "--query", query(op), "-o", "json"]


def job(op: str, subscription: str, target: str | None = None) -> nh.Record:
    return {"operationId": op, "targetId": target, "url": None if op == "context" else initial_url(op, subscription, target),
            "page": 1, "startedAtUtc": None}


def clean(value: object, node: Node, path: str = "") -> tuple[object, list[str]]:
    if value is None:
        return None, []
    if isinstance(node, dict):
        record = nh.obj(value)
        if not record:
            return {}, []
        capsule.fields(record, {META}, set(node))
        keys = [nh.text(key) for key in nh.array(record[META])]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate native source-key metadata")
        result: nh.Record = {}
        omitted = [path + "/" + key for key in keys if key not in node]
        for name, child in node.items():
            if name not in keys:
                if record.get(name) is not None:
                    raise ValueError("Native projection claims an unavailable field value")
                continue
            if name not in record:
                raise ValueError("Native projection omitted a reviewed source field")
            selected, omissions = clean(record[name], child, path + "/" + name)
            result[name] = selected
            omitted.extend(omissions)
        return result, sorted(omitted)
    if isinstance(node, list):
        values = nh.array(value)
        if len(values) > capsule.MAX_ROWS:
            raise ValueError("Snapshot array row budget exceeded")
        result = []
        omitted = []
        for position, entry in enumerate(values):
            selected, omissions = clean(entry, node[0], path + "/" + str(position))
            result.append(selected)
            omitted.extend(omissions)
        return result, sorted(omitted)
    if node == "text":
        nh.text(value)
    elif node == "bool":
        if not isinstance(value, bool):
            raise ValueError("Invalid reviewed snapshot boolean")
    elif node == "integer":
        nh.integer(value)
    elif node == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
            raise ValueError("Invalid reviewed snapshot number")
    else:
        raise ValueError("Unsupported snapshot schema leaf")
    return value, []


def selected(payload: nh.Record, op: str, subscription: str, tenant: str, target: str | None) -> tuple[list[nh.Record], str | None]:
    if op == "context":
        capsule.fields(payload, {"subscriptionId", "tenantId"})
        if nh.canonical_uuid(nh.text(payload["subscriptionId"])) != subscription or nh.canonical_uuid(nh.text(payload["tenantId"])) != tenant:
            raise ValueError("Native snapshot subscription/tenant context differs from approved scope")
        return [dict(payload)], None
    if OPS[op][0] == "get":
        capsule.fields(payload, {"resource"})
        raw_rows, next_link = [nh.obj(payload["resource"])], None
    else:
        capsule.fields(payload, {"items", "nextLink", "reportedCount"})
        raw_rows, next_link = nh.records(payload["items"]), payload["nextLink"]
        if nh.integer(payload["reportedCount"]) != len(raw_rows):
            raise ValueError("Native snapshot response exceeds selected row budget")
    if len(raw_rows) > capsule.MAX_ROWS:
        raise ValueError("Native snapshot response row budget exceeded")
    rows = []
    identifiers = set()
    for raw in raw_rows:
        configuration, omitted = clean(raw, schema(op))
        configuration = nh.obj(configuration)
        identifier = resource_id(configuration["id"], subscription, TYPES[OPS[op][1]][0])
        if nh.text(configuration["type"]).lower() != TYPES[OPS[op][1]][0].lower() or identifier.lower() in identifiers:
            raise ValueError("Native snapshot resource type/identity mismatch")
        if OPS[op][0] == "get" and identifier.lower() != nh.text(target).lower():
            raise ValueError("Native snapshot GET returned another resource")
        if OPS[op][2] and not identifier.lower().startswith(nh.text(target).lower() + "/"):
            raise ValueError("Native child list returned an external parent resource")
        identifiers.add(identifier.lower())
        rows.append({"configuration": configuration, "omittedPaths": omitted})
    return rows, None if next_link is None else validate_url(next_link, op, subscription, target)


def member_name(item: nh.Record) -> str:
    return nh.text(item["operationId"]) + "-" + nh.digest(item["targetId"])[:24] + "-p" + str(nh.integer(item["page"])).zfill(4) + ".json"


def schedule(progress: nh.Record, subscription: str, op: str, target: str) -> None:
    queue = nh.records(progress["jobs"])
    if any(entry["operationId"] == op and entry["targetId"] is not None
           and nh.text(entry["targetId"]).lower() == target.lower() for entry in queue):
        return
    if len(queue) >= MAX_JOBS:
        raise ValueError("Snapshot job budget exhausted; partial checkpoint retained")
    nh.array(progress["jobs"]).append(job(op, subscription, target))


def scope_identity(transport: bridge.SRETransport, tenant: str, subscription: str, run_id: str) -> nh.Record:
    return {"stateVersion": "1.0.0", "profileId": PROFILE, "profileVersion": PROFILE_VERSION,
            "catalogSha256": CATALOG_SHA, "endpoint": transport.endpoint, "threadId": transport.thread_id,
            "tenantId": tenant, "subscriptionId": subscription, "runId": run_id}


def read_pages(source: Path, references: object) -> dict[str, nh.Record]:
    result = {}
    for entry in nh.records(references):
        capsule.fields(entry, {"name", "bytes", "sha256"})
        name = nh.text(entry["name"])
        if "/" in name or "\\" in name or ":" in name or name in result:
            raise ValueError("Unsafe snapshot evidence reference")
        data = capsule.read_member(source / name)
        if capsule.descriptor(name, data) != entry:
            raise ValueError("Snapshot selected-page integrity mismatch")
        result[name] = capsule.decode(data)
    return result


def validate_page(record: nh.Record, subscription: str, tenant: str) -> None:
    capsule.fields(record, {"operationId", "targetId", "requestUrl", "page", "startedAtUtc", "completedAtUtc",
                            "status", "errorCode", "nativeExecutionId", "rows", "nextLink", "projectionSha256"})
    op = nh.text(record["operationId"])
    if op != "context" and op not in OPS:
        raise ValueError("Unsupported snapshot operation")
    capsule.timestamp(record["startedAtUtc"])
    capsule.timestamp(record["completedAtUtc"])
    if not 1 <= nh.integer(record["page"]) <= MAX_PAGES or record["projectionSha256"] != nh.digest(query(op)):
        raise ValueError("Snapshot page/profile binding mismatch")
    if op != "context":
        validate_url(record["requestUrl"], op, subscription, None if record["targetId"] is None else nh.text(record["targetId"]))
    elif record["requestUrl"] is not None or record["targetId"] is not None:
        raise ValueError("Invalid native context evidence target")
    if record["status"] not in ("succeeded", "permissionDenied", "failed", "unavailable", "unsupported"):
        raise ValueError("Unsupported snapshot outcome")
    if record["nativeExecutionId"] is not None:
        nh.text(record["nativeExecutionId"])
    if record["status"] != "succeeded":
        if record["rows"] is not None or record["nextLink"] is not None or not nh.text(record["errorCode"]):
            raise ValueError("Failed snapshot source claims observations")
        return
    if record["errorCode"] is not None:
        raise ValueError("Successful snapshot source claims a failure")
    rows = nh.records(record["rows"])
    if len(rows) > capsule.MAX_ROWS:
        raise ValueError("Snapshot retained row budget exceeded")
    if (op == "context" or OPS[op][0] == "get") and (record["page"] != 1 or len(rows) != 1 or record["nextLink"] is not None):
        raise ValueError("Snapshot single-resource/context page shape differs")
    if op == "context":
        if len(rows) != 1:
            raise ValueError("Missing native snapshot context proof")
        selected(rows[0], op, subscription, tenant, None)
        return
    identifiers = set()
    for row in rows:
        capsule.fields(row, {"configuration", "omittedPaths"})
        configuration = nh.obj(row["configuration"])
        validate_retained(configuration, schema(op))
        identifier = resource_id(configuration["id"], subscription, TYPES[OPS[op][1]][0])
        if nh.text(configuration["type"]).lower() != TYPES[OPS[op][1]][0].lower():
            raise ValueError("Retained snapshot type mismatch")
        if identifier.lower() in identifiers:
            raise ValueError("Duplicate retained snapshot resource identity")
        identifiers.add(identifier.lower())
        if OPS[op][0] == "get" and identifier.lower() != nh.text(record["targetId"]).lower():
            raise ValueError("Retained snapshot GET differs from requested target")
        if OPS[op][2] and not identifier.lower().startswith(nh.text(record["targetId"]).lower() + "/"):
            raise ValueError("Retained snapshot child differs from requested parent target")
        for omission in nh.array(row["omittedPaths"]):
            nh.text(omission)
    if record["nextLink"] is not None:
        validate_url(record["nextLink"], op, subscription, None if record["targetId"] is None else nh.text(record["targetId"]))


def validate_retained(value: object, node: Node) -> None:
    if value is None:
        return
    if isinstance(node, dict):
        record = capsule.fields(value, set(), set(node))
        for name, entry in record.items():
            validate_retained(entry, node[name])
    elif isinstance(node, list):
        values = nh.array(value)
        if len(values) > capsule.MAX_ROWS:
            raise ValueError("Retained snapshot array budget exceeded")
        for entry in values:
            validate_retained(entry, node[0])
    else:
        clean(value, node)


def bind_completed_source(source: Path, identity: nh.Record, progress: nh.Record) -> None:
    _, documents, _ = source_members(source)
    index = documents[INDEX]
    for key, expected in (
        ("captureId", identity["runId"]), ("scopeSubscriptionId", identity["subscriptionId"]),
        ("scopeTenantId", identity["tenantId"]), ("endpoint", identity["endpoint"]), ("threadId", identity["threadId"]),
    ):
        if index[key] != expected:
            raise ValueError("Completed snapshot source differs from checkpoint identity")
    retained = sorted((entry for entry in nh.records(index["artifacts"]) if entry["name"] != AUDIT),
                      key=lambda entry: nh.text(entry["name"]))
    if retained != sorted(nh.records(progress["members"]), key=lambda entry: nh.text(entry["name"])):
        raise ValueError("Completed snapshot source differs from checkpoint pages")


def acquire(transport: bridge.SRETransport, tenant: str, subscription: str, run_id: str,
            output_root: Path, resume: bool = False) -> Path:
    tenant, subscription, run_id = (nh.canonical_uuid(value) for value in (tenant, subscription, run_id))
    output_root = capsule.private_root(output_root)
    directory = output_root / "snapshot-acquisition" / run_id
    if not resume:
        directory.mkdir(parents=True, exist_ok=False)
    capsule.normal_path(directory)
    lock = directory / ".acquisition.lock"
    lock.mkdir(exist_ok=False)
    source = directory / "evidence"
    old_policy, old_collection = transport.collection_command_policy, transport.collection_only
    transport.collection_only = True
    try:
        identity = scope_identity(transport, tenant, subscription, run_id)
        if resume:
            state = capsule.fields(nh.load(directory / "state.json"),
                                   {*identity, "progress", "progressSha256", "pendingRead", "allowedCommands", "seenExecutions", "transportWarnings"})
            if any(state[key] != value for key, value in identity.items()) or state["progressSha256"] != nh.digest(state["progress"]):
                raise ValueError("Snapshot checkpoint scope/profile/integrity mismatch")
        else:
            source.mkdir()
            state = {**identity, "progress": {"current": 0, "jobs": [job("context", subscription), *[job(family + "-list", subscription) for family in ROOTS]],
                                             "members": [], "complete": False},
                     "progressSha256": "", "pendingRead": None, "allowedCommands": [], "seenExecutions": [], "transportWarnings": []}
        progress = capsule.fields(state["progress"], {"current", "jobs", "members", "complete"})
        queued_jobs = nh.records(progress["jobs"])
        if (
            not isinstance(progress["complete"], bool) or not 0 <= nh.integer(progress["current"]) <= len(queued_jobs)
            or not len(ROOTS) + 1 <= len(queued_jobs) <= MAX_JOBS
            or [entry["operationId"] for entry in queued_jobs[:len(ROOTS) + 1]] != ["context", *[family + "-list" for family in ROOTS]]
        ):
            raise ValueError("Invalid snapshot checkpoint progress/plan")
        pages = read_pages(source, progress["members"])
        for record in pages.values():
            validate_page(record, subscription, tenant)
        if nh.integer(progress["current"]) > 0 and not any(
            record["operationId"] == "context" and record["status"] == "succeeded" for record in pages.values()
        ):
            raise ValueError("Snapshot context proof is unavailable; resource reads are not authorized")
        if progress["complete"] is True or (
            nh.integer(progress["current"]) == len(queued_jobs) and (source / INDEX).exists()
        ):
            if nh.integer(progress["current"]) != len(queued_jobs):
                raise ValueError("Completed snapshot checkpoint still has pending jobs")
            bind_completed_source(source, identity, progress)
            if progress["complete"] is not True:
                progress["complete"] = True
                state["progressSha256"] = nh.digest(progress)
                bridge.save_state(directory, state)
            return source
        known = {family: set() for family in TYPES}
        for record in pages.values():
            if record["operationId"] != "context" and record["rows"] is not None:
                family = OPS[nh.text(record["operationId"])][1]
                known[family].update(nh.text(nh.obj(row["configuration"])["id"]).lower() for row in nh.records(record["rows"]))
        for queued in nh.records(progress["jobs"]):
            op = nh.text(queued["operationId"])
            if op != "context":
                kind, family, suffix = OPS[op]
                if kind == "get" and nh.text(queued["targetId"]).lower() not in known[family]:
                    raise ValueError("Snapshot GET parent was not discovered")
                if suffix:
                    parent_family = next(name for name, pair in TYPES.items() if pair[0] == TYPES[family][0].rsplit("/", 1)[0])
                    if nh.text(queued["targetId"]).lower() not in known[parent_family]:
                        raise ValueError("Snapshot child parent was not discovered")
                command(queued, subscription)
        allowed = {tuple(nh.text(value) for value in nh.array(values)) for values in nh.array(state["allowedCommands"])}
        permitted = {tuple(command(record_job(record), subscription)) for record in pages.values()}
        current = queued_jobs[nh.integer(progress["current"])] if nh.integer(progress["current"]) < len(queued_jobs) else None
        if current is not None:
            permitted.add(tuple(command(current, subscription)))
        if not allowed <= permitted:
            raise ValueError("Saved snapshot commands exceed retained/requested evidence")
        transport.allowed_commands = allowed
        transport.seen_executions = {nh.text(value) for value in nh.array(state["seenExecutions"])}
        transport.submission_warnings = nh.records(state["transportWarnings"])
        transport.pending_request = None if state["pendingRead"] is None else nh.obj(state["pendingRead"])
        if transport.pending_request is not None:
            pending = capsule.fields(transport.pending_request, {"command", "requestId", "prompt"})
            if current is None or nh.array(pending["command"]) != command(current, subscription) or tuple(nh.array(pending["command"])) not in allowed:
                raise ValueError("Snapshot pending request differs from current approved read")
            nh.canonical_uuid(nh.text(pending["requestId"]))
            if nh.text(pending["requestId"]) not in nh.text(pending["prompt"]) or not nh.text(pending["prompt"]).endswith(shlex.join(command(current, subscription))):
                raise ValueError("Snapshot pending nonce/prompt binding mismatch")
        transport.collection_command_policy = lambda actual: tuple(actual) in permitted

        def save() -> None:
            state["transportWarnings"] = transport.submission_warnings
            bridge.save_acquisition_snapshot(directory, state, progress, transport, error_prefix="Snapshot")

        def pending(request: nh.Record) -> None:
            state["pendingRead"] = request
            save()

        transport.save_pending = pending
        if not resume:
            save()
        reads = 0
        while nh.integer(progress["current"]) < len(nh.array(progress["jobs"])):
            if reads >= MAX_READS:
                raise ValueError("Snapshot invocation read budget exhausted; resume the same checkpoint")
            current = nh.records(progress["jobs"])[nh.integer(progress["current"])]
            op = nh.text(current["operationId"])
            permitted.add(tuple(command(current, subscription)))
            if current["startedAtUtc"] is None:
                current["startedAtUtc"] = nh.utc_now()
                save()
            before = set(transport.seen_executions)
            try:
                response = transport.read(command(current, subscription))
            except nh.ReadFailure as failure:
                rows, next_link, status, error = None, None, failure.status, failure.code
                identifiers = transport.seen_executions - before
                execution = next(iter(identifiers)) if len(identifiers) == 1 else None
            else:
                rows, next_link = selected(response.payload, op, subscription, tenant,
                                           None if current["targetId"] is None else nh.text(current["targetId"]))
                status, error, execution = "succeeded", None, response.execution_id
            reads += 1
            record = {"operationId": op, "targetId": current["targetId"], "requestUrl": current["url"],
                      "page": current["page"], "startedAtUtc": current["startedAtUtc"], "completedAtUtc": nh.utc_now(),
                      "status": status, "errorCode": error, "nativeExecutionId": execution, "rows": rows,
                      "nextLink": next_link, "projectionSha256": nh.digest(query(op))}
            name = member_name(current)
            path = source / name
            if path.exists():
                prior = capsule.decode(capsule.read_member(path))
                if any(prior[key] != value for key, value in record.items() if key != "completedAtUtc"):
                    raise ValueError("Recovered native page differs from retained selected evidence")
                record = prior
            validate_page(record, subscription, tenant)
            content = nh.encoded(record)
            if len(content) > capsule.MAX_MEMBER_BYTES:
                raise ValueError("Snapshot selected page exceeds member byte budget")
            nh.immutable_file(path, content)
            reference = capsule.descriptor(name, content)
            if reference not in nh.array(progress["members"]):
                nh.array(progress["members"]).append(reference)
            pages[name] = record
            if rows is not None and op != "context":
                family = OPS[op][1]
                for row in rows:
                    identifier = nh.text(nh.obj(row["configuration"])["id"])
                    known[family].add(identifier.lower())
                    if OPS[op][0] == "list":
                        schedule(progress, subscription, family + "-get", identifier)
                        for child in CHILDREN.get(family, ()):
                            schedule(progress, subscription, child, identifier)
            if next_link is not None:
                if nh.integer(current["page"]) >= MAX_PAGES:
                    raise ValueError("Snapshot page budget exhausted; selected checkpoint retained")
                current.update({"url": next_link, "page": nh.integer(current["page"]) + 1, "startedAtUtc": None})
            else:
                progress["current"] = nh.integer(progress["current"]) + 1
            state["pendingRead"] = None
            save()
            transport.pending_request = None
            if op == "context" and status != "succeeded":
                raise ValueError("Native snapshot context is unavailable; no resource reads authorized")
        if (source / AUDIT).exists():
            audit = capsule.decode(capsule.read_member(source / AUDIT))
            if (
                audit.get("status") != "verified-collection-only" or audit.get("endpoint") != transport.endpoint
                or audit.get("threadId") != transport.thread_id
                or set(nh.array(audit["nativeExecutionIds"])) != transport.seen_executions
                or audit.get("commandPolicySha256") != nh.digest([list(entry) for entry in sorted(transport.allowed_commands)])
            ):
                raise ValueError("Retained snapshot audit differs from native checkpoint")
        else:
            transport.wait_for_idle()
            audit = transport.audit()
            nh.immutable_file(source / AUDIT, nh.encoded(audit))
        references = [*nh.records(progress["members"]), capsule.descriptor(AUDIT, (source / AUDIT).read_bytes())]
        index = {"captureVersion": "1.0.0", "profileId": PROFILE, "profileVersion": PROFILE_VERSION,
                 "catalogSha256": CATALOG_SHA, "captureId": run_id, "scopeSubscriptionId": subscription,
                 "scopeTenantId": tenant, "endpoint": transport.endpoint, "threadId": transport.thread_id,
                 "artifacts": sorted(references, key=lambda entry: nh.text(entry["name"])),
                 "retention": "private reviewed configuration; retain until owner cleanup",
                 "timeBoundary": "client collection window; native execution timestamps not supplied",
                 "completedAtUtc": nh.utc_now()}
        nh.immutable_file(source / INDEX, nh.encoded(index))
        source_members(source)
        progress["complete"] = True
        save()
        return source
    finally:
        transport.save_pending = None
        transport.collection_command_policy, transport.collection_only = old_policy, old_collection
        lock.rmdir()


def record_job(record: nh.Record) -> nh.Record:
    return {"operationId": record["operationId"], "targetId": record["targetId"], "url": record["requestUrl"], "page": record["page"]}


def names(index: nh.Record) -> set[str]:
    if "artifacts" not in index:
        raise ValueError("Missing native snapshot artifact index")
    result = {INDEX, AUDIT}
    for entry in nh.records(index["artifacts"]):
        name = nh.text(entry["name"])
        if name in (AUDIT, INDEX):
            continue
        if "/" in name or "\\" in name or ":" in name or not name.endswith(".json") or name in result:
            raise ValueError("Unsafe/duplicate native snapshot member")
        result.add(name)
    if len(result) > MAX_JOBS * MAX_PAGES + 2:
        raise ValueError("Native snapshot member count exceeds profile")
    return result


def validate_documents(documents: dict[str, nh.Record], subscription: str) -> None:
    index = capsule.fields(documents[INDEX], {"captureVersion", "profileId", "profileVersion", "catalogSha256",
                                            "captureId", "scopeSubscriptionId", "scopeTenantId", "endpoint", "threadId",
                                            "artifacts", "retention", "timeBoundary", "completedAtUtc"})
    if (index["captureVersion"], index["profileId"], index["profileVersion"], index["catalogSha256"]) != (
        "1.0.0", PROFILE, PROFILE_VERSION, CATALOG_SHA,
    ) or index["scopeSubscriptionId"] != subscription:
        raise ValueError("Native snapshot scope/profile binding mismatch")
    tenant = nh.canonical_uuid(nh.text(index["scopeTenantId"]))
    nh.canonical_uuid(nh.text(index["captureId"]))
    nh.canonical_uuid(nh.text(index["threadId"]))
    bridge.valid_endpoint(nh.text(index["endpoint"]))
    capsule.timestamp(index["completedAtUtc"])
    references = capsule.descriptors(index["artifacts"], names(index) - {INDEX})
    execution_ids = set()
    commands = set()
    context = False
    roots = set()
    for name in sorted(names(index) - {INDEX, AUDIT}):
        record = documents[name]
        validate_page(record, subscription, tenant)
        if member_name(record_job(record)) != name:
            raise ValueError("Native snapshot member identity mismatch")
        commands.add(tuple(command(record_job(record), subscription)))
        if record["nativeExecutionId"] is not None:
            execution = nh.text(record["nativeExecutionId"])
            if execution in execution_ids:
                raise ValueError("Duplicate native snapshot execution identity")
            execution_ids.add(execution)
        if record["operationId"] == "context":
            context = record["status"] == "succeeded"
        if record["operationId"] in {family + "-list" for family in ROOTS}:
            roots.add(record["operationId"])
    if not context or roots != {family + "-list" for family in ROOTS}:
        raise ValueError("Native snapshot lacks context/root acquisition coverage")
    groups: dict[tuple[str, str | None], list[nh.Record]] = {}
    discovered = {family: set() for family in TYPES}
    for name in names(index) - {INDEX, AUDIT}:
        record = documents[name]
        op = nh.text(record["operationId"])
        target = None if record["targetId"] is None else nh.text(record["targetId"]).lower()
        groups.setdefault((op, target), []).append(record)
        if op != "context" and OPS[op][0] == "list" and record["rows"] is not None:
            discovered[OPS[op][1]].update(
                nh.text(nh.obj(row["configuration"])["id"]).lower() for row in nh.records(record["rows"])
            )
    required: set[tuple[str, str | None]] = {("context", None), *[(family + "-list", None) for family in ROOTS]}
    for family, identifiers in discovered.items():
        for identifier in identifiers:
            required.add((family + "-get", identifier))
            required.update((child, identifier) for child in CHILDREN.get(family, ()))
    if set(groups) != required:
        raise ValueError("Native snapshot missing required reads or contains undiscovered-parent reads")
    for (op, _), retained in groups.items():
        ordered = sorted(retained, key=lambda page: nh.integer(page["page"]))
        if [page["page"] for page in ordered] != list(range(1, len(ordered) + 1)):
            raise ValueError("Native snapshot page coverage has gaps or duplicates")
        for position, page in enumerate(ordered):
            if page["nextLink"] is not None:
                if position + 1 >= len(ordered) or not capsule.same_request(page["nextLink"], ordered[position + 1]["requestUrl"]):
                    raise ValueError("Native snapshot continuation coverage is incomplete")
            elif position + 1 != len(ordered):
                raise ValueError("Native snapshot has pages after a terminal outcome")
    audit = documents[AUDIT]
    if audit.get("status") != "verified-collection-only" or audit.get("endpoint") != index["endpoint"] or audit.get("threadId") != index["threadId"]:
        raise ValueError("Native snapshot audit context mismatch")
    if len(nh.array(audit["nativeExecutionIds"])) != len(execution_ids) or set(nh.array(audit["nativeExecutionIds"])) != execution_ids or audit["commandPolicySha256"] != nh.digest(
        [list(entry) for entry in sorted(commands)]
    ):
        raise ValueError("Native snapshot audit/execution bindings differ")
    for name, reference in references.items():
        if reference["sha256"] != hashlib.sha256(nh.encoded(documents[name])).hexdigest():
            raise ValueError("Native snapshot source-index byte binding mismatch")


def source_members(source: Path) -> tuple[dict[str, bytes], dict[str, nh.Record], str]:
    capsule.normal_path(source)
    index_bytes = capsule.read_member(source / INDEX)
    index = capsule.decode(index_bytes)
    expected_names = names(index)
    if set(path.name for path in source.iterdir()) != expected_names:
        raise ValueError("Missing or extra native snapshot source members")
    expected = capsule.descriptors(index["artifacts"], expected_names - {INDEX})
    payloads = {INDEX: index_bytes, **capsule.read_verified_members(source, expected, len(index_bytes))}
    documents = {name: capsule.decode(content) for name, content in payloads.items()}
    subscription = nh.canonical_uuid(nh.text(index["scopeSubscriptionId"]))
    validate_documents(documents, subscription)
    return payloads, documents, subscription


def coverage(documents: dict[str, nh.Record]) -> nh.Record:
    sources = []
    performed = set()
    for name in sorted(set(documents) - {INDEX, AUDIT}):
        record = documents[name]
        performed.add(record["operationId"])
        sources.append({key: record[key] for key in ("operationId", "targetId", "requestUrl", "page", "startedAtUtc",
                                                     "completedAtUtc", "status", "errorCode", "nativeExecutionId", "nextLink")})
        sources[-1].update({"member": name, "returnedRows": None if record["rows"] is None else len(nh.array(record["rows"]))})
    return {"collections": sources, "unperformedOperations": [
        {"operationId": op, "status": "notCollected", "reason": "no discovered parent or unavailable parent evidence"}
        for op in sorted(OPS) if op not in performed],
        "eventSources": [{"source": source, "status": "notCollected", "events": None} for source in capsule.EVENT_SOURCES],
        "boundary": "reviewed native configuration in selected visible scope; not permission-wide completeness or health"}


def replay_resources(documents: dict[str, nh.Record]) -> list[nh.Record]:
    resources: dict[str, nh.Record] = {}
    for name in sorted(set(documents) - {INDEX, AUDIT}):
        record = documents[name]
        if record["operationId"] == "context" or record["rows"] is None:
            continue
        for position, row in enumerate(nh.records(record["rows"])):
            configuration = nh.obj(row["configuration"])
            identifier = nh.text(configuration["id"]).lower()
            resource = resources.setdefault(identifier, {"id": identifier, "type": nh.text(configuration["type"]).lower(), "observations": []})
            nh.array(resource["observations"]).append({"member": name, "pointer": "/rows/" + str(position) + "/configuration",
                                                      "startedAtUtc": record["startedAtUtc"], "completedAtUtc": record["completedAtUtc"],
                                                      "nativeExecutionId": record["nativeExecutionId"], "configuration": configuration,
                                                      "omittedPaths": row["omittedPaths"]})
    return [resources[key] for key in sorted(resources)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("endpoint", "thread-id", "tenant-id", "subscription-id", "run-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    transport = bridge.SRETransport(args.endpoint, args.thread_id, bridge.access_token())
    try:
        source = acquire(transport, args.tenant_id, args.subscription_id, args.run_id, args.output_root, args.resume)
    except (ValueError, OSError) as error:
        parser.exit(2, "Native snapshot capture failed: " + str(error) + "\n")
    print(json.dumps({"source": str(source), "profileId": PROFILE, "profileVersion": PROFILE_VERSION,
                      "status": "captured-reviewed-configuration-not-a-health-assessment"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
