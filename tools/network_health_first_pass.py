"""Controlled first-pass discovery through the existing audited SRE transport."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import network_health_sre as bridge
import first_pass as fp


def acquire(transport: bridge.SRETransport, tenant: str, run_id: str, output_root: Path, resume: bool = False) -> bridge.nh.Record:
    nh = bridge.nh
    tenant, run_id = nh.canonical_uuid(tenant), nh.canonical_uuid(run_id)
    directory = output_root.resolve() / "first-pass-acquisition" / run_id
    if not resume:
        directory.mkdir(parents=True, exist_ok=False)
    lock = directory / ".acquisition.lock"
    lock.mkdir(exist_ok=False)
    old_policy, old_collection = transport.collection_command_policy, transport.collection_only
    transport.collection_only = True
    try:
        identity = {"stateVersion": "1.0.0", "endpoint": transport.endpoint, "threadId": transport.thread_id,
                    "tenantId": tenant, "runId": run_id, "policySha256": nh.digest([fp.QUERY, fp.subscription_command(tenant)])}
        if resume:
            state = nh.load(directory / "state.json")
            if set(state) != {*identity, "progress", "progressSha256", "pendingRead", "allowedCommands", "seenExecutions"} or any(
                state[key] != value for key, value in identity.items()
            ) or nh.digest(state["progress"]) != state["progressSha256"]:
                raise ValueError("First-pass checkpoint identity/policy/hash mismatch")
        else:
            state = {**identity, "progress": {}, "progressSha256": nh.digest({}), "pendingRead": None,
                     "allowedCommands": [], "seenExecutions": []}
        progress = nh.obj(state["progress"])
        def permitted(command: list[str]) -> bool:
            subscriptions = [nh.text(row["subscriptionId"]) for row in nh.records(progress.get("subscriptions", []))]
            return fp.matches_command(command, tenant, subscriptions)
        transport.collection_command_policy = permitted
        commands = [[nh.text(value) for value in nh.array(values)] for values in nh.array(state["allowedCommands"])]
        if any(not permitted(command) for command in commands):
            raise ValueError("First-pass saved command exceeds discovered scope")
        transport.allowed_commands = {tuple(command) for command in commands}
        transport.seen_executions = {nh.text(value) for value in nh.array(state["seenExecutions"])}
        transport.pending_request = nh.obj(state["pendingRead"]) if state["pendingRead"] is not None else None
        if transport.pending_request is not None and tuple(nh.array(transport.pending_request["command"])) not in transport.allowed_commands:
            raise ValueError("First-pass pending request not bound to approved command")
        def snapshot() -> None:
            state["progress"] = progress
            bridge.save_acquisition_snapshot(directory, state, progress, transport, error_prefix="First-pass")
        def pending(request: bridge.nh.Record) -> None:
            state["pendingRead"] = request
            snapshot()
        def selected(updated: bridge.nh.Record) -> None:
            state.update({"progress": updated, "pendingRead": None})
            transport.pending_request = None
            snapshot()
        if not resume:
            snapshot()
        transport.save_pending = pending
        envelope = fp.collect(tenant, run_id, transport.read, progress, selected)
        transport.wait_for_idle()
        audit = transport.audit()
        bridge.save_document(directory / "audit.json", audit)
        return envelope
    finally:
        transport.collection_command_policy, transport.collection_only = old_policy, old_collection
        transport.save_pending = None
        lock.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint")
    parser.add_argument("--thread-id")
    parser.add_argument("--operator-cli-python", type=Path)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.operator_cli_python:
        if args.endpoint or args.thread_id or args.resume:
            parser.error("Operator collection is separate from SRE/resume; use a new run and output root")
        def operator_reader(command: list[str]) -> bridge.nh.ReadResponse:
            result = subprocess.run([str(args.operator_cli_python), "-IBm", "azure.cli", *command[1:]],
                                    capture_output=True, text=True, timeout=120, check=False,
                                    env={**bridge.os.environ, "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no"})
            if result.returncode:
                status = "permissionDenied" if "forbidden" in result.stderr.lower() or "authorizationfailed" in result.stderr.lower() else "failed"
                raise bridge.nh.ReadFailure("OperatorReadFailed", status)
            return bridge.nh.ReadResponse(bridge.nh.obj(json.loads(result.stdout)))
        envelope = fp.collect(args.tenant_id, args.run_id, operator_reader)
        envelope["executionSource"] = "operator-cli-not-SRE-identity"
        print(json.dumps(fp.write_summary(envelope, args.output_root), sort_keys=True))
        return 0
    if not args.endpoint or not args.thread_id:
        parser.error("SRE first pass requires --endpoint and --thread-id")
    transport = bridge.SRETransport(args.endpoint, args.thread_id, bridge.access_token())
    envelope = acquire(transport, args.tenant_id, args.run_id, args.output_root, args.resume)
    envelope["executionSource"] = "sre-native-tool-effective-identity-not-RBAC-certified"
    directory = args.output_root.resolve() / "first-pass" / bridge.nh.canonical_uuid(args.run_id)
    if directory.exists():
        expected = {"selected-input.json": bridge.nh.encoded(envelope),
                    "scope-summary.json": bridge.nh.encoded(fp.summarize(envelope)),
                    "scope-summary.md": fp.render(fp.summarize(envelope)).encode()}
        if set(path.name for path in directory.iterdir()) != set(expected) or any(
            (directory / name).is_symlink() or (directory / name).read_bytes() != data for name, data in expected.items()
        ):
            raise ValueError("Existing first-pass artifacts differ from checkpoint")
        print(json.dumps({"runId": args.run_id, "directory": str(directory), "phase": "first-pass-replayed-no-new-reads"}))
    else:
        print(json.dumps(fp.write_summary(envelope, args.output_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
