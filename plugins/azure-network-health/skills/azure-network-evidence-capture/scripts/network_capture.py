"""Hostless reviewed configuration capture, verification and offline replay."""

from __future__ import annotations

import argparse
import hashlib
import os
import queue
import subprocess
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Protocol
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent))
import configuration_profile as profile
import evidence_files as ef


PROFILE = "hostless-configuration-snapshot"
PROFILE_VERSION = "1.0.0"
CAPSULE_VERSION = "0.3.0"
MANIFEST = "manifest.json"
CONTEXT = "authentication-context.json"
EVENT_SOURCES = ("administrativeActivityLog", "resourceChanges", "resourceHealth", "serviceHealth", "historicalExports")
ASSURANCE = {"sourceAuthentication": "notSigned", "storageAccessControls": "operatorManaged", "encryption": "notVerified"}


class UnconfirmedRead(RuntimeError):
    """The request may have been sent, but no response was retained."""


class Reader(Protocol):
    def context(self) -> ef.Record: ...
    def get(self, url: str) -> ef.Record: ...


def scope(tenant: str, subscription: str, client: str) -> ef.Record:
    return {"tenantId": ef.canonical_uuid(tenant), "subscriptionId": ef.canonical_uuid(subscription),
            "managedIdentityClientId": ef.canonical_uuid(client)}


def checked_root(path: Path) -> Path:
    ef.normal_path(path)
    result = path.resolve(strict=True)
    if not result.is_dir() or result.is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError("Evidence root must be an existing directory outside installed skill assets")
    return result


def validate_context(value: object, expected: ef.Record) -> ef.Record:
    record = ef.fields(value, {*expected, "authentication", "powershellVersion", "azAccountsVersion"})
    if any(record[key] != entry for key, entry in expected.items()) or record["authentication"] != "managedIdentity":
        raise ValueError("Managed identity context differs from approved scope")
    ef.text(record["powershellVersion"])
    ef.text(record["azAccountsVersion"])
    return record


def job(operation: str, subscription: str, target: str | None = None) -> ef.Record:
    return {"operationId": operation, "targetId": target, "url": profile.initial_url(operation, subscription, target), "page": 1}


def page_name(entry: ef.Record) -> str:
    return ef.text(entry["operationId"]) + "-" + ef.digest(entry["targetId"])[:24] + "-p" + str(ef.integer(entry["page"])).zfill(4) + ".json"


def add_job(progress: ef.Record, operation: str, subscription: str, target: str) -> None:
    jobs = ef.records(progress["jobs"])
    if any(entry["operationId"] == operation and entry["targetId"] is not None
           and ef.text(entry["targetId"]).lower() == target.lower() for entry in jobs):
        return
    if len(jobs) >= profile.MAX_JOBS:
        raise ValueError("Capture job budget exhausted; partial checkpoint retained")
    ef.array(progress["jobs"]).append(job(operation, subscription, target))


def selected(body: object, operation: str, subscription: str, target: str | None) -> tuple[list[ef.Record], str | None]:
    kind, family, suffix = profile.OPS[operation]
    source = ef.obj(body)
    if kind == "get":
        raw, next_link = [source], None
    else:
        if "value" not in source:
            raise ValueError("ARM list response has no value array")
        raw, next_link = ef.records(source["value"]), source.get("nextLink")
    if len(raw) > ef.MAX_ROWS:
        raise ValueError("ARM response row budget exceeded")
    rows = []
    seen = set()
    for entry in raw:
        configuration, omissions = profile.select(entry, profile.schema(operation))
        configuration = ef.obj(configuration)
        identifier = profile.resource_id(configuration.get("id"), subscription, profile.TYPES[family][0])
        if ef.text(configuration.get("type")).lower() != profile.TYPES[family][0].lower() or identifier.lower() in seen:
            raise ValueError("ARM response type/identity mismatch")
        if kind == "get" and identifier.lower() != ef.text(target).lower():
            raise ValueError("ARM GET returned another target")
        if suffix and not identifier.lower().startswith(ef.text(target).lower() + "/"):
            raise ValueError("ARM child response exceeds discovered parent")
        seen.add(identifier.lower())
        rows.append({"configuration": configuration, "omittedPaths": omissions})
    if kind == "get" and len(rows) != 1:
        raise ValueError("ARM GET must return one resource")
    return rows, None if next_link is None else profile.validate_url(next_link, operation, subscription, target)


def outcome(response: object) -> tuple[str, str | None, int]:
    response = ef.fields(response, {"statusCode", "body", "requestId"}, {"errorCode", "transportOutcome"})
    status = ef.integer(response["statusCode"])
    if response["requestId"] is not None:
        ef.text(response["requestId"])
    if response.get("transportOutcome") == "responseTooLarge":
        return "unavailable", "RawResponseBudgetExceeded", status
    if status == 200:
        return "succeeded", None, status
    if status in (401, 403):
        return "permissionDenied", "ArmAuthorizationDenied", status
    if status == 404:
        return "unavailable", "ArmResourceNotFound", status
    if status == 429:
        return "unavailable", "ArmThrottled", status
    return "failed", "ArmHttpFailure", status


def validate_page(record: object, approved: ef.Record) -> ef.Record:
    record = ef.fields(record, {"operationId", "targetId", "requestUrl", "page", "attemptId", "startedAtUtc",
                               "completedAtUtc", "status", "errorCode", "httpStatus", "requestId", "rows", "nextLink"})
    operation = ef.text(record["operationId"])
    if operation not in profile.OPS:
        raise ValueError("Unreviewed capture operation")
    target = None if record["targetId"] is None else ef.text(record["targetId"])
    subscription = ef.text(approved["subscriptionId"])
    profile.validate_url(record["requestUrl"], operation, subscription, target)
    ef.canonical_uuid(ef.text(record["attemptId"]))
    start, end = ef.timestamp(record["startedAtUtc"]), ef.timestamp(record["completedAtUtc"])
    if datetime.fromisoformat(start.replace("Z", "+00:00")) > datetime.fromisoformat(end.replace("Z", "+00:00")):
        raise ValueError("Capture completion precedes attempt")
    if not 1 <= ef.integer(record["page"]) <= profile.MAX_PAGES:
        raise ValueError("Capture page exceeds profile")
    ef.integer(record["httpStatus"])
    if record["requestId"] is not None:
        ef.text(record["requestId"])
    if record["status"] != "succeeded":
        if record["status"] not in ("permissionDenied", "unavailable", "failed") or record["rows"] is not None or record["nextLink"] is not None:
            raise ValueError("Failed capture claims observations")
        ef.text(record["errorCode"])
        return record
    if record["httpStatus"] != 200 or record["errorCode"] is not None:
        raise ValueError("Capture HTTP outcome differs from status")
    kind, family, suffix = profile.OPS[operation]
    rows = ef.records(record["rows"])
    if len(rows) > ef.MAX_ROWS or (kind == "get" and (record["page"] != 1 or len(rows) != 1 or record["nextLink"] is not None)):
        raise ValueError("Retained capture row/page shape differs")
    seen = set()
    for row in rows:
        ef.fields(row, {"configuration", "omittedPaths"})
        profile.validate_retained(row["configuration"], profile.schema(operation))
        configuration = ef.obj(row["configuration"])
        identifier = profile.resource_id(configuration.get("id"), subscription, profile.TYPES[family][0]).lower()
        if ef.text(configuration.get("type")).lower() != profile.TYPES[family][0].lower() or identifier in seen:
            raise ValueError("Retained capture resource type/identity mismatch")
        if kind == "get" and identifier != ef.text(target).lower():
            raise ValueError("Retained GET differs from requested target")
        if suffix and not identifier.startswith(ef.text(target).lower() + "/"):
            raise ValueError("Retained child differs from requested parent")
        seen.add(identifier)
        for omission in ef.array(row["omittedPaths"]):
            if not ef.text(omission).startswith("/"):
                raise ValueError("Invalid omitted field path")
    if record["nextLink"] is not None:
        profile.validate_url(record["nextLink"], operation, subscription, target)
    return record


def validate_sources(documents: dict[str, ef.Record], approved: ef.Record) -> None:
    validate_context(documents[CONTEXT], approved)
    groups: dict[tuple[str, str | None], list[ef.Record]] = {}
    discovered = {family: set() for family in profile.TYPES}
    for name, record in documents.items():
        if name == CONTEXT or name.startswith("attempt-"):
            continue
        validate_page(record, approved)
        if name != page_name(record):
            raise ValueError("Capture member identity differs")
        operation = ef.text(record["operationId"])
        target = None if record["targetId"] is None else ef.text(record["targetId"]).lower()
        groups.setdefault((operation, target), []).append(record)
        if profile.OPS[operation][0] == "list" and record["rows"] is not None:
            discovered[profile.OPS[operation][1]].update(
                ef.text(ef.obj(row["configuration"])["id"]).lower() for row in ef.records(record["rows"])
            )
    required: set[tuple[str, str | None]] = {(family + "-list", None) for family in profile.ROOTS}
    for family, identifiers in discovered.items():
        for identifier in identifiers:
            required.add((family + "-get", identifier))
            required.update((child, identifier) for child in profile.CHILDREN.get(family, ()))
    if set(groups) != required:
        raise ValueError("Capture lacks required enrichment or contains undiscovered-parent reads")
    for retained in groups.values():
        ordered = sorted(retained, key=lambda record: ef.integer(record["page"]))
        if [record["page"] for record in ordered] != list(range(1, len(ordered) + 1)):
            raise ValueError("Capture page coverage has gaps/duplicates")
        for position, record in enumerate(ordered):
            if record["nextLink"] is not None:
                if position + 1 >= len(ordered) or not profile.same_request(record["nextLink"], ordered[position + 1]["requestUrl"]):
                    raise ValueError("Capture continuation is incomplete")
            elif position + 1 != len(ordered):
                raise ValueError("Capture contains pages after terminal outcome")
    for name, record in documents.items():
        if name.startswith("attempt-"):
            ef.fields(record, {"attemptId", "operationId", "targetId", "requestUrl", "startedAtUtc", "status"})
            if name != "attempt-" + ef.canonical_uuid(ef.text(record["attemptId"])) + ".json" or record["status"] != "unconfirmed":
                raise ValueError("Invalid unconfirmed attempt record")
            profile.validate_url(record["requestUrl"], ef.text(record["operationId"]), ef.text(approved["subscriptionId"]),
                                 None if record["targetId"] is None else ef.text(record["targetId"]))
            ef.timestamp(record["startedAtUtc"])


def validate_progress(progress: ef.Record, documents: dict[str, ef.Record], pending: object, approved: ef.Record) -> None:
    jobs = ef.records(progress["jobs"])
    current = ef.integer(progress["current"])
    if (
        not isinstance(progress["complete"], bool) or not 0 <= current <= len(jobs)
        or not len(profile.ROOTS) <= len(jobs) <= profile.MAX_JOBS
        or [entry["operationId"] for entry in jobs[:len(profile.ROOTS)]] != [family + "-list" for family in profile.ROOTS]
    ):
        raise ValueError("Invalid capture checkpoint progress/plan")
    ef.timestamp(progress["startedAtUtc"])
    known = {family: set() for family in profile.TYPES}
    for name, record in documents.items():
        if name == CONTEXT:
            validate_context(record, approved)
        elif name.startswith("attempt-"):
            continue
        else:
            validate_page(record, approved)
            if name != page_name(record):
                raise ValueError("Checkpoint member identity differs")
            operation = ef.text(record["operationId"])
            if profile.OPS[operation][0] == "list" and record["rows"] is not None:
                known[profile.OPS[operation][1]].update(
                    ef.text(ef.obj(row["configuration"])["id"]).lower() for row in ef.records(record["rows"])
                )
    for entry in jobs:
        ef.fields(entry, {"operationId", "targetId", "url", "page"})
        operation = ef.text(entry["operationId"])
        if operation not in profile.OPS or not 1 <= ef.integer(entry["page"]) <= profile.MAX_PAGES:
            raise ValueError("Unreviewed checkpoint job/page")
        kind, family, suffix = profile.OPS[operation]
        target = None if entry["targetId"] is None else ef.text(entry["targetId"])
        profile.validate_url(entry["url"], operation, ef.text(approved["subscriptionId"]), target)
        if kind == "get" and ef.text(target).lower() not in known[family]:
            raise ValueError("Capture GET parent was not discovered")
        if suffix:
            parent_type = profile.TYPES[family][0].rsplit("/", 1)[0]
            parent_family = next(name for name, pair in profile.TYPES.items() if pair[0] == parent_type)
            if ef.text(target).lower() not in known[parent_family]:
                raise ValueError("Capture child parent was not discovered")
    if pending is not None:
        attempt = ef.fields(pending, {"operationId", "targetId", "requestUrl", "page", "attemptId", "startedAtUtc"})
        if current == len(jobs) or any(attempt[key] != jobs[current][key] for key in ("operationId", "targetId", "page")):
            raise ValueError("Pending capture differs from current job")
        if attempt["requestUrl"] != jobs[current]["url"]:
            raise ValueError("Pending capture URL differs")
        ef.canonical_uuid(ef.text(attempt["attemptId"]))
        ef.timestamp(attempt["startedAtUtc"])


def coverage(documents: dict[str, ef.Record]) -> ef.Record:
    performed = set()
    collections = []
    attempts = []
    for name in sorted(documents):
        if name == CONTEXT:
            continue
        record = documents[name]
        if name.startswith("attempt-"):
            attempts.append({"member": name, **record})
            continue
        performed.add(record["operationId"])
        collections.append({key: record[key] for key in (
            "operationId", "targetId", "requestUrl", "page", "attemptId", "startedAtUtc", "completedAtUtc",
            "status", "errorCode", "httpStatus", "requestId", "nextLink",
        )} | {"member": name, "returnedRows": None if record["rows"] is None else len(ef.array(record["rows"]))})
    return {
        "collections": collections, "unconfirmedAttempts": attempts,
        "unperformedOperations": [{"operationId": operation, "status": "notCollected",
                                  "reason": "no discovered parent or unavailable parent evidence"}
                                 for operation in sorted(profile.OPS) if operation not in performed],
        "eventSources": [{"source": source, "status": "notCollected", "events": None} for source in EVENT_SOURCES],
        "boundary": "reviewed configuration in selected visible scope; not global completeness or health",
    }


def verified(directory: Path) -> tuple[ef.Record, dict[str, ef.Record], bytes]:
    root = checked_root(directory)
    manifest_bytes = ef.read_member(root / MANIFEST, ef.MAX_MANIFEST_BYTES)
    if ef.decode(manifest_bytes).get("profileId") in ("hostless-event-history", "hostless-workspace-activity"):
        import network_history
        return network_history.verified(root)
    manifest = ef.fields(ef.decode(manifest_bytes), {
        "capsuleVersion", "capsuleId", "profileId", "profileVersion", "profileSha256", "scope",
        "collectionWindow", "members", "coverage", "assurance",
    })
    if (manifest["capsuleVersion"], manifest["profileId"], manifest["profileVersion"], manifest["profileSha256"]) != (
        CAPSULE_VERSION, PROFILE, PROFILE_VERSION, profile.PROFILE_SHA,
    ) or manifest["assurance"] != ASSURANCE:
        raise ValueError("Unsupported capture capsule/profile/assurance")
    ef.canonical_uuid(ef.text(manifest["capsuleId"]))
    approved = ef.fields(manifest["scope"], {"tenantId", "subscriptionId", "managedIdentityClientId"})
    if approved != scope(ef.text(approved["tenantId"]), ef.text(approved["subscriptionId"]), ef.text(approved["managedIdentityClientId"])):
        raise ValueError("Noncanonical capsule scope")
    window = ef.fields(manifest["collectionWindow"], {"startedAtUtc", "completedAtUtc"})
    ef.timestamp(window["startedAtUtc"])
    ef.timestamp(window["completedAtUtc"])
    names = {ef.member_name(entry["name"]) for entry in ef.records(manifest["members"])}
    if CONTEXT not in names or MANIFEST in names or len(names) > profile.MAX_JOBS * profile.MAX_PAGES + 1001:
        raise ValueError("Capture member set differs from profile")
    expected = ef.descriptors(manifest["members"], names)
    if set(path.name for path in root.iterdir()) != names | {MANIFEST}:
        raise ValueError("Missing or extra capture capsule members")
    payloads = ef.read_verified_members(root, expected, len(manifest_bytes))
    documents = {name: ef.decode(content) for name, content in payloads.items()}
    validate_sources(documents, approved)
    if manifest["coverage"] != coverage(documents):
        raise ValueError("Capture coverage differs from retained evidence")
    return manifest, documents, manifest_bytes


def verify(directory: Path) -> ef.Record:
    return verified(directory)[0]


def replay(directory: Path) -> ef.Record:
    manifest, documents, manifest_bytes = verified(directory)
    if manifest["profileId"] in ("hostless-event-history", "hostless-workspace-activity"):
        import network_history
        return network_history.replay(directory)
    resources: dict[str, ef.Record] = {}
    for name in sorted(documents):
        record = documents[name]
        if name == CONTEXT or name.startswith("attempt-") or record["rows"] is None:
            continue
        for position, row in enumerate(ef.records(record["rows"])):
            configuration = ef.obj(row["configuration"])
            identifier = ef.text(configuration["id"]).lower()
            resource = resources.setdefault(identifier, {"id": identifier, "type": ef.text(configuration["type"]).lower(), "observations": []})
            ef.array(resource["observations"]).append({
                "member": name, "pointer": "/rows/" + str(position) + "/configuration",
                "startedAtUtc": record["startedAtUtc"], "completedAtUtc": record["completedAtUtc"],
                "requestId": record["requestId"], "configuration": configuration, "omittedPaths": row["omittedPaths"],
            })
    return {"replayVersion": "1.0.0", "capsuleId": manifest["capsuleId"], "profileId": PROFILE,
            "profileVersion": PROFILE_VERSION, "profileSha256": profile.PROFILE_SHA, "scope": manifest["scope"],
            "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(), "resources": [resources[key] for key in sorted(resources)],
            "coverage": manifest["coverage"], "eventSources": ef.obj(manifest["coverage"])["eventSources"], "assessmentPerformed": False}


def capture(reader: Reader, tenant: str, subscription: str, client: str, capture_id: str, output_root: Path,
            resume: bool = False, retry_unconfirmed: bool = False) -> Path:
    approved = scope(tenant, subscription, client)
    subscription = ef.text(approved["subscriptionId"])
    capture_id = ef.canonical_uuid(capture_id)
    root = checked_root(output_root)
    acquisition = root / "acquisition" / capture_id
    destination = root / "capsules" / capture_id
    if not resume:
        acquisition.mkdir(parents=True, exist_ok=False)
        (acquisition / "evidence").mkdir()
    ef.normal_path(acquisition)
    lock = acquisition / ".capture.lock"
    lock.mkdir(exist_ok=False)
    source = acquisition / "evidence"
    identity = {"stateVersion": "1.0.0", "profileId": PROFILE, "profileVersion": PROFILE_VERSION,
                "profileSha256": profile.PROFILE_SHA, "scope": approved, "captureId": capture_id}
    try:
        if resume:
            state = ef.fields(ef.decode(ef.read_member(acquisition / "state.json")), {*identity, "progress", "progressSha256", "pending"})
            if any(state[key] != value for key, value in identity.items()) or state["progressSha256"] != ef.digest(state["progress"]):
                raise ValueError("Capture checkpoint scope/profile/integrity mismatch")
        else:
            state = {**identity, "progress": {"jobs": [job(family + "-list", subscription) for family in profile.ROOTS],
                                             "current": 0, "members": [], "startedAtUtc": ef.utc_now(), "complete": False},
                     "progressSha256": "", "pending": None}
        progress = ef.fields(state["progress"], {"jobs", "current", "members", "startedAtUtc", "complete"})
        def save() -> None:
            state["progressSha256"] = ef.digest(progress)
            content = ef.encoded(state)
            if len(content) > 2 * ef.MAX_MEMBER_BYTES:
                raise ValueError("Capture checkpoint byte budget exceeded")
            ef.atomic_json(acquisition / "state.json", state)
        retained = ef.descriptors(progress["members"], {ef.member_name(entry["name"]) for entry in ef.records(progress["members"])})
        payloads = ef.read_verified_members(source, retained)
        documents = {name: ef.decode(content) for name, content in payloads.items()}
        validate_progress(progress, documents, state["pending"], approved)
        if progress["complete"] is True or os.path.lexists(destination):
            manifest = verify(destination)
            if manifest["scope"] != approved or manifest["capsuleId"] != capture_id:
                raise ValueError("Completed capsule differs from requested identity")
            if manifest["members"] != sorted(ef.records(progress["members"]), key=lambda entry: ef.text(entry["name"])):
                raise ValueError("Completed capsule differs from checkpoint evidence")
            if progress["complete"] is not True:
                progress["complete"] = True
                save()
            return destination
        if not resume:
            save()
        context = validate_context(reader.context(), approved)
        if CONTEXT not in documents:
            content = ef.encoded(context)
            ef.immutable_file(source / CONTEXT, content)
            reference = ef.descriptor(CONTEXT, content)
            ef.array(progress["members"]).append(reference)
            payloads[CONTEXT], documents[CONTEXT] = content, context
            save()
        if state["pending"] is not None:
            pending = ef.obj(state["pending"])
            name = page_name(pending)
            if not (source / name).exists():
                if not retry_unconfirmed:
                    raise UnconfirmedRead("Unconfirmed GET requires explicit --retry-unconfirmed; no new request sent")
                attempt = {key: pending[key] for key in ("attemptId", "operationId", "targetId", "requestUrl", "startedAtUtc")} | {"status": "unconfirmed"}
                attempt_name = "attempt-" + ef.text(attempt["attemptId"]) + ".json"
                content = ef.encoded(attempt)
                ef.immutable_file(source / attempt_name, content)
                reference = ef.descriptor(attempt_name, content)
                ef.array(progress["members"]).append(reference)
                payloads[attempt_name], documents[attempt_name] = content, attempt
                state["pending"] = None
                save()
        requests = 0
        while ef.integer(progress["current"]) < len(ef.array(progress["jobs"])):
            current = ef.records(progress["jobs"])[ef.integer(progress["current"])]
            operation = ef.text(current["operationId"])
            target = None if current["targetId"] is None else ef.text(current["targetId"])
            url = profile.validate_url(current["url"], operation, subscription, target)
            name = page_name(current)
            pending = state["pending"]
            if pending is not None and (source / name).exists():
                record = ef.decode(ef.read_member(source / name))
                validate_page(record, approved)
                if record["attemptId"] != ef.obj(pending)["attemptId"] or record["requestUrl"] != url:
                    raise ValueError("Retained interrupted page differs from checkpoint attempt")
            else:
                if requests >= profile.MAX_READS:
                    raise ValueError("Capture invocation read budget exhausted; resume the same checkpoint")
                pending = {"operationId": operation, "targetId": target, "requestUrl": url, "page": current["page"],
                           "attemptId": str(uuid4()), "startedAtUtc": ef.utc_now()}
                state["pending"] = pending
                save()
                response = reader.get(url)
                requests += 1
                status, error, http = outcome(response)
                rows, next_link = selected(response["body"], operation, subscription, target) if status == "succeeded" else (None, None)
                record = {**pending, "completedAtUtc": ef.utc_now(), "status": status, "errorCode": error,
                          "httpStatus": http, "requestId": response["requestId"], "rows": rows, "nextLink": next_link}
                validate_page(record, approved)
            content = ef.encoded(record)
            if len(content) > ef.MAX_MEMBER_BYTES or sum(len(entry) for entry in payloads.values()) + len(content) > ef.MAX_TOTAL_BYTES:
                raise ValueError("Capture selected evidence byte budget exceeded")
            ef.immutable_file(source / name, content)
            reference = ef.descriptor(name, content)
            if reference not in ef.array(progress["members"]):
                ef.array(progress["members"]).append(reference)
            payloads[name], documents[name] = content, record
            if record["rows"] is not None:
                for row in ef.records(record["rows"]):
                    identifier = ef.text(ef.obj(row["configuration"])["id"])
                    if profile.OPS[operation][0] == "list":
                        family = profile.OPS[operation][1]
                        add_job(progress, family + "-get", subscription, identifier)
                        for child in profile.CHILDREN.get(family, ()):
                            add_job(progress, child, subscription, identifier)
            if record["nextLink"] is not None:
                if ef.integer(current["page"]) >= profile.MAX_PAGES:
                    raise ValueError("Capture page budget exhausted; partial evidence retained")
                current.update({"url": record["nextLink"], "page": ef.integer(current["page"]) + 1})
            else:
                progress["current"] = ef.integer(progress["current"]) + 1
            state["pending"] = None
            save()
        validate_sources(documents, approved)
        manifest = {
            "capsuleVersion": CAPSULE_VERSION, "capsuleId": capture_id, "profileId": PROFILE,
            "profileVersion": PROFILE_VERSION, "profileSha256": profile.PROFILE_SHA, "scope": approved,
            "collectionWindow": {"startedAtUtc": progress["startedAtUtc"], "completedAtUtc": ef.utc_now()},
            "members": sorted(ef.records(progress["members"]), key=lambda entry: ef.text(entry["name"])),
            "coverage": coverage(documents), "assurance": dict(ASSURANCE),
        }
        manifest_bytes = ef.encoded(manifest)
        if len(manifest_bytes) > ef.MAX_MANIFEST_BYTES or sum(map(len, payloads.values())) + len(manifest_bytes) > ef.MAX_TOTAL_BYTES:
            raise ValueError("Capture manifest/total byte budget exceeded")
        destination.parent.mkdir(exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix="." + capture_id + ".", dir=destination.parent))
        published = False
        try:
            for name, content in {**payloads, MANIFEST: manifest_bytes}.items():
                ef.immutable_file(staging / name, content)
            verify(staging)
            if os.path.lexists(destination):
                raise FileExistsError("Capsule destination already exists")
            staging.rename(destination)
            published = True
        finally:
            if not published:
                for name in set(payloads) | {MANIFEST}:
                    (staging / name).unlink(missing_ok=True)
                staging.rmdir()
        progress["complete"] = True
        save()
        return destination
    finally:
        lock.rmdir()


class ArmBridge:
    SCRIPT = "arm_reader.ps1"

    def __init__(self, approved: ef.Record):
        self.approved = approved
        self.process: subprocess.Popen[bytes] | None = None
        self.ready: ef.Record | None = None
        self.replies: queue.Queue[bytes | OSError] = queue.Queue()

    def bootstrap_arguments(self) -> list[str]:
        return []

    def context(self) -> ef.Record:
        if self.ready is not None:
            return self.ready
        self.process = subprocess.Popen([
            "pwsh", "-NoProfile", "-File", str(Path(__file__).with_name(self.SCRIPT)),
            "-TenantId", ef.text(self.approved["tenantId"]), "-SubscriptionId", ef.text(self.approved["subscriptionId"]),
            "-ManagedIdentityClientId", ef.text(self.approved["managedIdentityClientId"]),
            *self.bootstrap_arguments(),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        threading.Thread(target=self.read_stream, daemon=True).start()
        reply = self.read_reply()
        if reply.get("status") != "ready":
            raise ValueError("Managed identity runtime unavailable: " + ef.text(reply.get("code", "UnknownBootstrapFailure")))
        self.ready = validate_context(reply["context"], self.approved)
        return self.ready

    def read_stream(self) -> None:
        if self.process is None or self.process.stdout is None:
            self.replies.put(OSError("ARM process stdout unavailable"))
            return
        try:
            while True:
                content = self.process.stdout.readline(2 * ef.MAX_MEMBER_BYTES + 1)
                self.replies.put(content)
                if not content or len(content) > 2 * ef.MAX_MEMBER_BYTES:
                    return
        except OSError as error:
            self.replies.put(error)

    def read_reply(self) -> ef.Record:
        if self.process is None or self.process.stdout is None:
            raise UnconfirmedRead("ARM process is unavailable; no retained response")
        try:
            content = self.replies.get(timeout=120)
        except queue.Empty:
            raise UnconfirmedRead("ARM process timed out; explicit retry required") from None
        if isinstance(content, OSError):
            raise UnconfirmedRead("ARM process response interrupted; explicit retry required") from None
        if not content or len(content) > 2 * ef.MAX_MEMBER_BYTES:
            raise UnconfirmedRead("ARM process response unavailable/over budget; explicit retry required")
        return ef.decode(content)

    def get(self, url: str) -> ef.Record:
        return self.exchange({"url": url})

    def exchange(self, request: ef.Record) -> ef.Record:
        self.context()
        if self.process is None or self.process.stdin is None:
            raise UnconfirmedRead("ARM request process is unavailable")
        try:
            self.process.stdin.write(ef.encoded(request).replace(b"\n", b" ") + b"\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise UnconfirmedRead("ARM request outcome unconfirmed; explicit retry required") from None
        reply = self.read_reply()
        if reply.get("transportOutcome") == "unconfirmed":
            raise UnconfirmedRead("ARM GET outcome unconfirmed; explicit retry required")
        return reply

    def close(self) -> None:
        if self.process is None:
            return
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("capture")
    for name in ("tenant-id", "subscription-id", "managed-identity-client-id", "capture-id"):
        create.add_argument("--" + name, required=True)
    create.add_argument("--output-root", type=Path, required=True)
    create.add_argument("--resume", action="store_true")
    create.add_argument("--retry-unconfirmed", action="store_true")
    for name in ("verify", "replay"):
        child = commands.add_parser(name)
        child.add_argument("--capsule", type=Path, required=True)
        if name == "replay":
            child.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reader = None
    try:
        if args.command == "capture":
            reader = ArmBridge(scope(args.tenant_id, args.subscription_id, args.managed_identity_client_id))
            directory = capture(reader, args.tenant_id, args.subscription_id, args.managed_identity_client_id,
                                args.capture_id, args.output_root, args.resume, args.retry_unconfirmed)
            result = {"capsule": str(directory), "status": "captured-reviewed-configuration", "assessmentPerformed": False}
        elif args.command == "verify":
            manifest = verify(args.capsule)
            result = {"capsuleId": manifest["capsuleId"], "status": "verified-retained-bytes", "members": len(ef.array(manifest["members"]))}
        else:
            parent = checked_root(args.output.parent)
            output = parent / args.output.name
            if os.path.lexists(output) or output.is_relative_to(args.capsule.resolve()):
                raise ValueError("Replay output must be new and outside the immutable capsule")
            content = ef.encoded(replay(args.capsule))
            ef.immutable_file(output, content)
            result = {"output": str(output), "sha256": hashlib.sha256(content).hexdigest(),
                      "processedAtUtc": ef.utc_now(), "assessmentPerformed": False}
    except (ValueError, OSError, UnconfirmedRead) as error:
        parser.exit(2, "Evidence runtime failed: " + str(error) + "\n")
    finally:
        if reader is not None:
            reader.close()
    print(ef.encoded(result).decode().strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
