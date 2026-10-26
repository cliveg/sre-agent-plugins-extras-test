"""Capture selected reference-network evidence using the existing collection engine."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import evidence_files as ef
import network_capture as capture_core
import reference_profile as profile


VERSION = "1.0.0"
MEMBERS = {"context.json", "selected-input.json", "request-journal.json"}

class CapturePaused(RuntimeError):
    pass


class Reader(Protocol):
    def context(self) -> ef.Record: ...
    def __call__(self, command: list[str]) -> profile.nh.ReadResponse: ...


def operation_for(command: list[str], subscription: str) -> ef.Record:
    kind = profile.nh.child_kind(command)
    token = profile.nh.request_token(command)
    target = profile.nh.command_target(command, subscription)
    size = int(command[command.index("--first") + 1]) if "--first" in command else 1000
    if not 1 <= size <= 1000:
        raise ValueError("Reference request row budget differs")
    matches = [
        operation for operation in ef.records(profile.catalog()["operations"])
        if profile.nh.operation_matches_kind(operation, kind, target)
        and profile.nh.command_for(operation, subscription, size, token, target) == command
    ]
    if len(matches) != 1:
        raise ValueError("Reference request is not an exact scoped catalog command")
    return matches[0]


def selected_reply(payload: ef.Record, operation: ef.Record, subscription: str) -> ef.Record:
    if operation["kind"] == "account":
        return {"subscriptionId": ef.canonical_uuid(ef.text(payload["subscriptionId"]))}
    result = {key: value for key, value in payload.items() if key in (
        "count", "data", "total_records", "totalRecords", "skip_token", "$skipToken",
        "nextLink", "resultTruncated", "hasContinuation",
    )}
    rows = ef.records(payload["data"])
    if len(rows) > 2000:
        raise ValueError("Reference response exceeds the reviewed row budget")
    if operation["kind"] == "graph":
        result["data"] = [profile.select_row(row, operation, subscription) for row in rows]
    elif operation["kind"] == "private-dns-record-metadata":
        result["data"] = [{key: value for key, value in row.items() if key in ("type", "ttl")} for row in rows]
    else:
        name = ef.text(operation["operationId"])
        fields = (
            profile.nh.NSP_FIELDS[name] if name in profile.nh.NSP_FIELDS else
            profile.nh.SERVICE_ACCESS_FIELDS if operation["kind"] == profile.nh.SERVICE_ARM_KIND else
            profile.nh.FIELDS[name]
        )
        allowed = set(fields)
        if operation["kind"] == profile.nh.SERVICE_ARM_KIND:
            allowed.update(field + "Known" for field in ("ipRuleCount", "virtualNetworkRuleCount", "resourceAccessRuleCount"))
        if name == "nsp-rules":
            allowed.update(field + "Known" for field in profile.nh.NSP_SELECTOR_FIELDS)
        result["data"] = [{
            **{key: value for key, value in row.items() if key in (
                "id", "name", "type", "location", "subscriptionId", "resourceGroup", "parentId",
            )},
            "properties": {key: value for key, value in ef.obj(row["properties"]).items() if key in allowed},
        } for row in rows]
    if len(ef.encoded(result)) > ef.MAX_MEMBER_BYTES:
        raise ValueError("Selected reference response exceeds its byte budget")
    return result


def _collect(reader, subscription, source_id, source, clock, progress=None, save_progress=None):
    result = profile.nh.collect(
        subscription, source_id, reader, source, clock=clock, include_nsp=True,
        dns_subscriptions=[subscription], acquisition=profile.catalog(), row_selector=profile.select_row,
        progress=progress, save_progress=save_progress,
    )
    return {**result, "inputVersion": VERSION}


def _replay(journal: ef.Record, scope: ef.Record, source_id: str, source: str) -> ef.Record:
    requests = ef.records(journal["requests"])
    retained: dict[str, ef.Record] = {}
    for entry in requests:
        command = [ef.text(value) for value in ef.array(entry["command"])]
        operation_for(command, ef.text(scope["subscriptionId"]))
        if entry["state"] == "retained":
            retained[ef.digest(command)] = entry
    clocks = iter(ef.array(journal["clockValues"]))

    def clock():
        try:
            return ef.timestamp(next(clocks))
        except StopIteration:
            raise ValueError("Reference journal collection-clock evidence is incomplete") from None

    def read(command):
        key = ef.digest(command)
        if key not in retained:
            raise ValueError("Reference journal lacks a retained scoped response")
        entry = retained[key]
        if entry.get("failure") is not None:
            failure = ef.obj(entry["failure"])
            raise profile.nh.ReadFailure(ef.text(failure["code"]), ef.text(failure["status"]))
        return profile.nh.ReadResponse(ef.obj(entry["reply"]), ef.text(entry["requestId"]))

    result = _collect(read, ef.text(scope["subscriptionId"]), source_id, source, clock)
    if list(clocks):
        raise ValueError("Reference journal has unmatched collection-clock evidence")
    return result


def verified(directory: Path) -> tuple[ef.Record, dict[str, ef.Record], bytes]:
    root = capture_core.checked_root(directory)
    content = ef.read_member(root / "manifest.json", ef.MAX_MANIFEST_BYTES)
    manifest = ef.fields(ef.decode(content), {
        "sourceVersion", "profileId", "sourceId", "scope", "collectionWindow",
        "catalogSha256", "source", "members", "assurance",
    })
    if (manifest["sourceVersion"], manifest["profileId"]) != (VERSION, "reference-network-source"):
        raise ValueError("Unsupported reference-network source profile")
    identifier = ef.text(manifest["sourceId"])
    if identifier != ef.canonical_uuid(identifier):
        raise ValueError("Noncanonical reference source identity")
    approved = ef.obj(manifest["scope"])
    expected_scope = capture_core.scope(
        ef.text(approved["tenantId"]), ef.text(approved["subscriptionId"]), ef.text(approved["managedIdentityClientId"]),
    )
    if approved != expected_scope or manifest["catalogSha256"] != ef.digest(profile.catalog()):
        raise ValueError("Reference source scope/catalog binding differs")
    if {path.name for path in root.iterdir()} != MEMBERS | {"manifest.json"}:
        raise ValueError("Reference source membership differs")
    descriptors = ef.descriptors(manifest["members"], MEMBERS)
    documents = {
        name: ef.decode(value) for name, value in ef.read_verified_members(root, descriptors, len(content)).items()
    }
    capture_core.validate_context(documents["context.json"], approved)
    journal = documents["request-journal.json"]
    if (journal["sourceId"], journal["scope"], journal["source"], journal["catalogSha256"]) != (
        identifier, approved, manifest["source"], manifest["catalogSha256"],
    ):
        raise ValueError("Reference journal identity/catalog differs")
    document = documents["selected-input.json"]
    if (document["inputVersion"], document["queryCatalogVersion"], document["runId"],
        document["requestedSubscriptionId"]) != ("1.0.0", "1.9.0", identifier, approved["subscriptionId"]):
        raise ValueError("Reference selected-input identity differs")
    operations = {ef.text(row["operationId"]): row for row in ef.records(profile.catalog()["operations"])}
    collections = ef.records(document["collections"])
    if len(collections) != len(operations) or {row["operationId"] for row in collections} != set(operations):
        raise ValueError("Every reference operation requires an explicit outcome")
    for collection in collections:
        operation = operations[ef.text(collection["operationId"])]
        expected_hash = hashlib.sha256(ef.text(operation["query"]).encode()).hexdigest() if operation["kind"] != "account" else None
        if (collection["requestedSubscriptionId"] != approved["subscriptionId"]
                or collection["source"] != manifest["source"] or collection["querySha256"] != expected_hash
                or collection["operationVersion"] != operation["operationVersion"]):
            raise ValueError("Reference collection scope/source/query differs")
        rows = ef.records(collection["rows"])
        if collection["retainedRowCount"] != len(rows):
            raise ValueError("Reference retained row count differs")
        for row in rows:
            if profile.select_row(row, operation, ef.text(approved["subscriptionId"])) != row:
                raise ValueError("Reference source contains unselected properties")
    profile.nh.normalize(profile.core_input(document))
    if ef.encoded(_replay(journal, approved, identifier, ef.text(manifest["source"]))) != ef.encoded(document):
        raise ValueError("Reference selected evidence differs from its retained request journal")
    return manifest, documents, content


def verify(directory: Path) -> ef.Record:
    return verified(directory)[0]


def capture(reader: Reader, tenant: str, subscription: str, client: str, source_id: str, output_root: Path, *,
            source: str = "managed-identity-arm", resume: bool = False, retry_unconfirmed: bool = False,
            read_budget: int = 100) -> Path:
    if not 1 <= ef.integer(read_budget) <= 100:
        raise ValueError("Reference invocation read budget must be between 1 and 100")
    approved = capture_core.scope(tenant, subscription, client)
    source_id = ef.canonical_uuid(source_id)
    root = capture_core.checked_root(output_root)
    parent = root / "reference-sources"
    parent.mkdir(exist_ok=True)
    ef.normal_path(parent)
    destination = parent / source_id
    if os.path.lexists(destination):
        if resume:
            existing = verify(destination)
            if existing["scope"] != approved or existing["source"] != source:
                raise ValueError("Completed reference source scope differs")
            return destination
        raise FileExistsError("Reference source already exists; immutable evidence is not overwritten")
    work = root / "reference-work" / source_id
    work.mkdir(parents=True, exist_ok=True)
    ef.normal_path(work)
    journal_path, progress_path = work / "request-journal.json", work / "collection-progress.json"
    if journal_path.exists() and not resume:
        raise FileExistsError("Existing reference progress requires explicit resume")
    lock = work / ".lock"
    with lock.open("x") as stream:
        stream.write(str(os.getpid()))
    try:
        if journal_path.exists():
            journal = ef.decode(ef.read_member(journal_path))
            if (journal["sourceId"], journal["scope"], journal["source"], journal["catalogSha256"]) != (
                source_id, approved, source, ef.digest(profile.catalog()),
            ):
                raise ValueError("Reference resume scope/catalog differs")
            retained = {ef.digest(entry["command"]) for entry in ef.records(journal["requests"]) if entry["state"] == "retained"}
            if any(entry["state"] == "pending" and ef.digest(entry["command"]) not in retained
                   for entry in ef.records(journal["requests"])) and not retry_unconfirmed:
                raise capture_core.UnconfirmedRead("Reference response outcome is unconfirmed; explicit retry approval is required")
            context = capture_core.validate_context(reader.context(), approved)
            original_context = ef.decode(ef.read_member(work / "context.json"))
        else:
            context = capture_core.validate_context(reader.context(), approved)
            original_context = context
            journal = {
                "journalVersion": VERSION, "sourceId": source_id, "scope": approved, "source": source,
                "catalogSha256": ef.digest(profile.catalog()), "startedAtUtc": ef.utc_now(),
                "requests": [], "clockValues": [],
                "executionReferenceMeaning": "client request-journal identity; not a native SRE tool execution ID",
            }
            ef.immutable_file(work / "context.json", ef.encoded(context))
            ef.atomic_json(journal_path, journal)
        progress = ef.decode(ef.read_member(progress_path)) if progress_path.exists() else {}

        def persist():
            if len(ef.encoded(journal)) > ef.MAX_MEMBER_BYTES:
                raise ValueError("Reference request journal exceeds its byte budget")
            ef.atomic_json(journal_path, journal)

        def clock():
            value = ef.utc_now()
            ef.array(journal["clockValues"]).append(value)
            persist()
            return value

        new_reads = 0

        def read(command):
            nonlocal new_reads
            operation = operation_for(command, subscription)
            requests = ef.records(journal["requests"])
            previous = [entry for entry in requests if entry["command"] == command]
            completed = [entry for entry in previous if entry["state"] == "retained"]
            if completed:
                entry = completed[-1]
            else:
                if previous and not retry_unconfirmed:
                    raise capture_core.UnconfirmedRead("Reference response is unconfirmed; explicit retry approval required")
                if new_reads >= read_budget:
                    raise CapturePaused("Reference invocation read budget reached; resume the same source")
                entry = {
                    "requestId": str(uuid4()), "operationId": operation["operationId"], "command": command,
                    "startedAtUtc": ef.utc_now(), "state": "pending",
                    "approvedRetryOf": previous[-1]["requestId"] if previous else None,
                }
                ef.array(journal["requests"]).append(entry)
                persist()
                new_reads += 1
                try:
                    response = reader(command)
                    reply = selected_reply(response.payload, operation, subscription)
                    entry.update({"reply": reply, "providerExecutionRef": response.execution_id, "failure": None})
                except profile.nh.ReadFailure as error:
                    entry.update({"reply": None, "failure": {"code": error.code, "status": error.status}})
                except (KeyError, ValueError) as error:
                    entry.update({"reply": None, "failure": {"code": "InvalidSelectedResponse:" + type(error).__name__, "status": "failed"}})
                entry.update({"state": "retained", "completedAtUtc": ef.utc_now()})
                persist()
            if entry.get("failure") is not None:
                failure = ef.obj(entry["failure"])
                raise profile.nh.ReadFailure(ef.text(failure["code"]), ef.text(failure["status"]))
            return profile.nh.ReadResponse(ef.obj(entry["reply"]), ef.text(entry["requestId"]))

        document = _collect(
            read, subscription, source_id, source, clock, progress,
            lambda value: ef.atomic_json(progress_path, value),
        )
        if ef.encoded(_replay(journal, approved, source_id, source)) != ef.encoded(document):
            raise ValueError("Collected reference evidence does not reproduce from retained responses")
        payloads = {
            "context.json": ef.encoded(original_context), "selected-input.json": ef.encoded(document),
            "request-journal.json": ef.encoded(journal),
        }
    finally:
        lock.unlink()
    if any(len(value) > ef.MAX_MEMBER_BYTES for value in payloads.values()):
        raise ValueError("Reference source member byte budget exceeded")
    manifest = {
        "sourceVersion": VERSION, "profileId": "reference-network-source", "sourceId": source_id,
        "scope": approved, "source": source, "catalogSha256": ef.digest(profile.catalog()),
        "collectionWindow": {"startedAtUtc": journal["startedAtUtc"], "completedAtUtc": ef.utc_now()},
        "members": [ef.descriptor(name, value) for name, value in sorted(payloads.items())],
        "assurance": {"sourceAuthentication": "notSigned", "rawResponsesPersisted": False},
    }
    content = ef.encoded(manifest)
    if len(content) > ef.MAX_MANIFEST_BYTES or len(content) + sum(len(value) for value in payloads.values()) > ef.MAX_TOTAL_BYTES:
        raise ValueError("Reference source total/manifest byte budget exceeded")
    destination.mkdir()
    for name, value in payloads.items():
        ef.immutable_file(destination / name, value)
    ef.immutable_file(destination / "manifest.json", content)
    verify(destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    create = actions.add_parser("capture")
    for name in ("tenant-id", "subscription-id", "managed-identity-client-id", "capture-id"):
        create.add_argument("--" + name, required=True)
    create.add_argument("--output-root", required=True, type=Path)
    create.add_argument("--resume", action="store_true")
    create.add_argument("--retry-unconfirmed", action="store_true")
    create.add_argument("--max-reads", type=int, default=100)
    check = actions.add_parser("verify")
    check.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "capture":
        from reference_arm import ReferenceArmReader
        approved = capture_core.scope(args.tenant_id, args.subscription_id, args.managed_identity_client_id)
        reader = ReferenceArmReader(approved)
        try:
            directory = capture(
                reader, args.tenant_id, args.subscription_id, args.managed_identity_client_id,
                args.capture_id, args.output_root, resume=args.resume, retry_unconfirmed=args.retry_unconfirmed,
                read_budget=args.max_reads,
            )
        except CapturePaused:
            print(json.dumps({
                "status": "paused-at-reference-read-budget", "sourceId": args.capture_id,
                "resumeRequired": True, "retryUnconfirmedRequired": False,
            }, sort_keys=True))
            return 3
        finally:
            reader.close()
    else:
        directory = args.source
    manifest, documents, _ = verified(directory)
    collections = ef.records(documents["selected-input.json"]["collections"])
    print(json.dumps({
        "sourceId": manifest["sourceId"], "source": manifest["source"], "directory": str(directory),
        "collectionOutcomes": len(collections), "selectedEvidenceVerified": True,
        "allOutcomesSucceeded": all(row["status"] == "succeeded" for row in collections),
        "retainedRows": sum(ef.integer(row["retainedRowCount"]) for row in collections),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
