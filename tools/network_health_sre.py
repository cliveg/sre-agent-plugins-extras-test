"""Development-only lossless transport for the native SRE Agent Azure read tool."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "plugins" / "azure-network-health" / "skills" / "azure-network-health-assessment"
sys.path.insert(0, str(SKILL))
import network_health as nh


STATE_VERSION = "1.0.0"
INPUT_BUDGET = 5 * 1024 * 1024
ARTIFACT_NAMES = set(nh.REPORT_FILES)
AUDIT_POLICY_VERSION = "1.0.0"
AUDIT_SURFACES = (
    "azCliExecution", "kubectlExecution", "psqlExecution", "readFileResult",
    "fileWriteResult", "terminalResult", "pythonExecutionResult", "taskToolExecutionGroup",
    "mcpToolExecution", "genevaActionExecution", "hookExecution", "dGrepExecution",
    "similarIncidentSearchExecution", "armQuery",
)


def unclassified_surfaces(message: nh.Record) -> set[str]:
    return {
        key for key in message if key not in AUDIT_SURFACES and (
            "execution" in key.lower() or key.lower().endswith(("result", "query"))
        )
    }


def verify_collection_message(message: nh.Record) -> None:
    missing = set(AUDIT_SURFACES) - set(message)
    if missing:
        raise RuntimeError("Collection audit visibility is incomplete: " + ", ".join(sorted(missing)))
    unexpected = {
        key for key in AUDIT_SURFACES if key != "azCliExecution" and message[key] is not None
    } | {key for key in unclassified_surfaces(message) if message[key] is not None}
    if unexpected:
        raise RuntimeError("Noncatalogued collection activity on structured surfaces: " + ", ".join(sorted(unexpected)))
    if message["azCliExecution"] is not None:
        execution = nh.obj(message["azCliExecution"])
        if not {"id", "command", "status"} <= set(execution) or any(
            not nh.text(execution[key]) for key in ("id", "command", "status")
        ):
            raise RuntimeError("Malformed native execution surface in collection audit")


def valid_endpoint(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or not parsed.hostname.endswith(".azuresre.ai")
        or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in ("", "/") or parsed.port not in (None, 443)
    ):
        raise ValueError("Endpoint must be an approved HTTPS Azure SRE Agent origin")
    return value.rstrip("/")


def access_token() -> str:
    executable = shutil.which("az")
    if executable is None:
        raise RuntimeError("Azure CLI is required on the development host")
    result = subprocess.run(
        [executable, "account", "get-access-token", "--resource", "https://azuresre.dev",
         "--query", "accessToken", "-o", "tsv"],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("Cannot acquire SRE data-plane token; no login is attempted")
    return result.stdout.strip()


class SREHttpError(RuntimeError):
    def __init__(self, status: int) -> None:
        super().__init__("SRE transport HTTP " + str(status))
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("SRE attachment download redirects are not permitted")


class SRETransport:
    def __init__(self, endpoint: str, thread_id: str, token: str) -> None:
        self.endpoint = valid_endpoint(endpoint)
        self.thread_id = nh.canonical_uuid(thread_id)
        self.token = token
        self.seen_executions: set[str] = set()
        self.allowed_commands: set[tuple[str, ...]] = set()
        self.submission_warnings: list[nh.Record] = []
        self.pending_request: nh.Record | None = None
        self.save_pending: Callable[[nh.Record], None] | None = None
        self.collection_only = False
        self.approved_operations: dict[str, list[nh.Record]] | None = None
        self.approved_service_parents: set[str] | None = None
        self.approved_nsp_parents: dict[str, set[str]] | None = None
        self.collection_command_policy: Callable[[list[str]], bool] | None = None

    def request(self, path: str, data: bytes | None = None, content_type: str = "application/json") -> object:
        request = urllib.request.Request(
            self.endpoint + path, data=data,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": content_type},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise SREHttpError(exc.code) from None
        except urllib.error.URLError:
            raise RuntimeError("SRE transport network failure") from None

    def messages(self, descending: bool = False) -> Iterator[nh.Record]:
        skip = 0
        while True:
            order = "timestamp+desc" if descending else "timestamp"
            response = nh.obj(self.request(
                f"/api/v1/threads/{self.thread_id}/messages?skip={skip}&top=100&orderby={order}",
            ))
            messages = nh.records(response["value"])
            for message in messages:
                if self.collection_only:
                    verify_collection_message(message)
                yield message
            if len(messages) < 100:
                return
            skip += 100
            if skip > 5000:
                raise RuntimeError("Collection history exceeds its message budget")

    def executions(self) -> list[nh.Record]:
        return [nh.obj(message["azCliExecution"]) for message in self.messages(True)
                if message.get("azCliExecution")]

    def wait_for_idle(self) -> None:
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            response = nh.obj(self.request(
                f"/api/v1/threads/{self.thread_id}/messages?skip=0&top=1&orderby=timestamp+desc",
            ))
            if "state" not in response:
                raise RuntimeError("SRE thread readiness state is unavailable")
            if response["state"] == "Idle":
                return
            time.sleep(2)
        raise nh.ReadFailure("ThreadDidNotBecomeIdle", "unavailable")

    def read(self, command: list[str]) -> nh.ReadResponse:
        prior_collection_only = self.collection_only
        self.collection_only = True
        try:
            return self._read_command(command)
        finally:
            self.collection_only = prior_collection_only

    def _read_command(self, command: list[str]) -> nh.ReadResponse:
        if self.collection_command_policy is not None:
            if not self.collection_command_policy(command):
                raise ValueError("Command differs from the controlled first-pass policy")
        else:
            self._validate_acquisition_command(command)
        return self._dispatch_read(command)

    def _validate_acquisition_command(self, command: list[str]) -> None:
        kind = nh.child_kind(command)
        child_read = kind is not None
        if command[:3] not in (["az", "account", "show"], ["az", "graph", "query"]) and not child_read:
            raise ValueError("Only catalogued Azure reads are permitted")
        try:
            if command[1] == "account" or child_read:
                subscription = nh.canonical_uuid(command[command.index("--subscription") + 1])
                size, token = 1000, nh.request_token(command)
            else:
                subscription = nh.canonical_uuid(command[command.index("--subscriptions") + 1])
                size = int(command[command.index("--first") + 1])
                token = command[command.index("--skip-token") + 1] if "--skip-token" in command else None
        except (ValueError, IndexError):
            raise ValueError("Missing explicit scope or paging arguments") from None
        if not 1 <= size <= 1000 or not nh.matches_command(command, subscription, size):
            raise ValueError("Command differs from the approved acquisition catalog")
        target = nh.command_target(command, subscription)
        if kind == nh.SERVICE_ARM_KIND and self.approved_service_parents is not None:
            if target is None or nh.text(target["id"]).lower() not in self.approved_service_parents:
                raise ValueError("Service ARM command exceeds actually collected approved parents")
        if kind in nh.NSP_CHILD_KINDS and self.approved_nsp_parents is not None and (
            target is None or nh.text(target["id"]).lower() not in self.approved_nsp_parents[kind]
        ):
            raise ValueError("NSP command exceeds actually collected approved parents")
        if self.approved_operations is not None and not any(
            command == nh.command_for(
                op, subscription, size, token,
                target,
            ) for op in self.approved_operations.get(subscription, [])
            if nh.operation_matches_kind(op, kind, target)
        ):
            raise ValueError("Command exceeds approved workload/DNS-hosting operation scope")

    def _dispatch_read(self, command: list[str]) -> nh.ReadResponse:
        resuming = self.pending_request is not None
        if not self.allowed_commands and self.executions():
            raise ValueError("Use a fresh controlled thread without prior Azure executions")
        if not resuming:
            try:
                self.wait_for_idle()
            except nh.ReadFailure:
                if self.save_pending is not None:
                    raise RuntimeError("Native thread readiness interrupted; use --resume-acquisition") from None
                raise
        self.allowed_commands.add(tuple(command))
        serialized = shlex.join(command)
        request_id = str(uuid4())
        prompt = (
            f"Controlled development transport request {request_id}: execute exactly ONE approved read using "
            "RunAzCliReadCommands, then stop. Do not execute it in the terminal, install/login, "
            "set CLI defaults, load any skill, run file/terminal/MCP/Kubernetes/SQL tools, "
            "alter the command, add queries, or mutate Azure. "
            "Return only execution status; do not rewrite or paste resource rows. The developer "
            "will retrieve the structured execution output verbatim. Exact command:\n" + serialized
        )
        if resuming:
            pending = nh.obj(self.pending_request)
            if nh.array(pending["command"]) != command:
                raise ValueError("Outstanding native request differs from collector continuation")
            prompt, request_id = nh.text(pending["prompt"]), nh.text(pending["requestId"])
            accepted = any(
                message.get("text") == prompt and nh.obj(message["author"]).get("role") == "User"
                or message.get("azCliExecution") and (
                    tuple(shlex.split(nh.text(nh.obj(message["azCliExecution"])["command"]))) == tuple(command)
                    and nh.text(nh.obj(message["azCliExecution"])["id"]) not in self.seen_executions
                )
                for message in self.messages(True)
            )
            if not accepted:
                raise RuntimeError("Native request acceptance is unknown; refusing to repost")
        else:
            if self.save_pending is not None:
                self.pending_request = {"command": command, "requestId": request_id, "prompt": prompt}
                self.save_pending(self.pending_request)
            try:
                self.request(
                    f"/api/v1/threads/{self.thread_id}/messages",
                    json.dumps({"text": prompt, "role": "User", "displayName": "Network health development transport"}).encode(),
                )
            except SREHttpError as exc:
                transcript = nh.obj(self.request(
                    f"/api/v1/threads/{self.thread_id}/messages?skip=0&top=20&orderby=timestamp+desc",
                ))
                accepted = any(
                    message.get("text") == prompt and nh.obj(message["author"]).get("role") == "User"
                    for message in nh.records(transcript["value"])
                )
                if not accepted:
                    raise
                self.submission_warnings.append({
                    "httpStatus": exc.status, "requestId": request_id, "acceptedVerified": True,
                })
                if self.save_pending is not None:
                    self.save_pending(nh.obj(self.pending_request))
                print(
                    f"WARNING: SRE submission HTTP {exc.status}; exact nonce-bearing message "
                    "was independently verified as accepted. Waiting for its actual execution; not resubmitting.",
                    file=sys.stderr,
                )
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            executions = self.executions()
            matching = [execution for execution in executions if (
                tuple(shlex.split(nh.text(execution["command"]))) == tuple(command)
                and nh.text(execution["id"]) not in self.seen_executions
            )]
            if len(matching) > 1:
                raise RuntimeError("Duplicate outstanding native read executions")
            for execution in executions:
                execution_id = nh.text(execution["id"])
                actual = tuple(shlex.split(nh.text(execution["command"])))
                if actual not in self.allowed_commands:
                    raise RuntimeError("Unexpected Azure operation in controlled collection thread")
                if execution_id in self.seen_executions or actual != tuple(command):
                    continue
                if execution["status"] not in ("Completed", "Failed", "Cancelled", "Expired"):
                    continue
                self.seen_executions.add(execution_id)
                if execution["status"] != "Completed" or execution.get("error"):
                    error = str(execution.get("error", "")).lower()
                    if "forbidden" in error or "authorizationfailed" in error:
                        raise nh.ReadFailure("PermissionDenied", "permissionDenied")
                    if "extension" in error and ("installed first" in error or "requires" in error):
                        raise nh.ReadFailure("NativeReadCapabilityUnavailable", "unsupported")
                    raise nh.ReadFailure("NativeReadFailed")
                try:
                    payload = nh.obj(json.loads(nh.text(execution["output"])))
                except (ValueError, KeyError):
                    raise nh.ReadFailure("InvalidNativeJsonOutput") from None
                return nh.ReadResponse(payload, execution_id)
            time.sleep(2)
        if self.save_pending is not None:
            raise RuntimeError("Native read remains outstanding; use --resume-acquisition")
        raise nh.ReadFailure("NativeReadTimeout", "unavailable")

    def upload(self, name: str, content: bytes, before_send: Callable[[], None] | None = None) -> object:
        if len(content) > INPUT_BUDGET:
            raise ValueError("Projected input exceeds the development attachment budget")
        if "/" in name or "\\" in name or '"' in name or not name.endswith(".json"):
            raise ValueError("Attachment name must be a plain JSON filename")
        self.wait_for_idle()
        boundary = "network-health-" + uuid4().hex
        header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="files"; filename="{name}"\r\n'
            "Content-Type: application/json\r\n\r\n"
        ).encode()
        body = header + content + f"\r\n--{boundary}--\r\n".encode()
        if before_send is not None:
            before_send()
        return self.request(
            f"/api/v1/threads/{self.thread_id}/attachments", body,
            "multipart/form-data; boundary=" + boundary,
        )

    def download_url(self, url: str) -> str:
        parsed = urllib.parse.urlsplit(urllib.parse.urljoin(self.endpoint + "/", url))
        origin = urllib.parse.urlsplit(self.endpoint)
        decoded_path = urllib.parse.unquote(parsed.path)
        if (
            parsed.scheme != "https" or parsed.hostname != origin.hostname
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.query or parsed.fragment
            or not decoded_path.startswith(f"/api/files/{self.thread_id}/")
            or "\\" in decoded_path or "%" in decoded_path
            or any(part in (".", "..") for part in decoded_path.split("/"))
        ):
            raise ValueError("Attachment download must use the exact SRE origin and thread")
        return urllib.parse.urlunsplit(parsed)

    def download(self, url: str, max_bytes: int = INPUT_BUDGET) -> bytes:
        if not 1 <= nh.integer(max_bytes) <= 20 * INPUT_BUDGET:
            raise ValueError("Invalid bounded attachment download budget")
        request = urllib.request.Request(
            self.download_url(url), headers={"Authorization": "Bearer " + self.token},
        )
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
                content = response.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise SREHttpError(exc.code) from None
        except urllib.error.URLError:
            raise RuntimeError("SRE attachment download network failure") from None
        if len(content) > max_bytes:
            raise ValueError("Attachment download exceeds its expected byte budget")
        return content

    def audit(self) -> nh.Record:
        executions: set[str] = set()
        counts = {key: 0 for key in AUDIT_SURFACES}
        unclassified_nulls: set[str] = set()
        message_count = 0
        for message in self.messages():
            verify_collection_message(message)
            message_count += 1
            for key in AUDIT_SURFACES:
                counts[key] += message[key] is not None
            unclassified_nulls.update(unclassified_surfaces(message))
            if message["azCliExecution"] is None:
                continue
            execution = nh.obj(message["azCliExecution"])
            command = tuple(shlex.split(nh.text(execution["command"])))
            if command not in self.allowed_commands:
                raise RuntimeError("Unexpected Azure operation in collection audit")
            execution_id = nh.text(execution["id"])
            if execution_id in executions:
                raise RuntimeError("Duplicate native execution record in collection audit")
            if execution["status"] not in ("Completed", "Failed", "Cancelled", "Expired"):
                raise RuntimeError("Incomplete native execution in collection audit")
            executions.add(execution_id)
        if not message_count:
            raise RuntimeError("Collection audit history is empty; visibility is unavailable")
        if executions != self.seen_executions:
            raise RuntimeError("Unexpected duplicate or incomplete Azure read execution")
        return {
            "auditPolicyVersion": AUDIT_POLICY_VERSION, "endpoint": self.endpoint,
            "threadId": self.thread_id, "status": "verified-collection-only",
            "auditedAt": nh.utc_now(),
            "messagesAudited": message_count, "nativeExecutionIds": sorted(executions),
            "commandPolicySha256": nh.digest([list(command) for command in sorted(self.allowed_commands)]),
            "surfaceCoverage": {
                key: {"messagesExposingField": message_count, "nonNullOccurrences": counts[key]}
                for key in AUDIT_SURFACES
            },
            "unclassifiedNullSurfaceFields": sorted(unclassified_nulls),
            "visibilityBoundary": "structured-thread-fields-within-message-budget",
            "universalToolEnforcement": False,
        }


def state_directory(output_root: Path, run_id: str) -> Path:
    return output_root.resolve() / "network-health-transport" / nh.canonical_uuid(run_id)


def save_document(path: Path, document: nh.Record) -> None:
    nh.atomic_json(path, document)


def save_state(directory: Path, state: nh.Record) -> None:
    save_document(directory / "state.json", state)


def save_acquisition_snapshot(
    directory: Path, state: nh.Record, progress: nh.Record, transport: SRETransport,
    *, error_prefix: str,
) -> None:
    state.update({
        "progressSha256": nh.digest(progress),
        "allowedCommands": [list(command) for command in sorted(transport.allowed_commands)],
        "seenExecutions": sorted(transport.seen_executions),
    })
    if len(nh.encoded(state)) > 2 * INPUT_BUDGET:
        raise ValueError(error_prefix + " checkpoint exceeds its selected-evidence budget")
    save_state(directory, state)


def acquisition_directory(output_root: Path, run_id: str) -> Path:
    return output_root.resolve() / "network-health-acquisition" / nh.canonical_uuid(run_id)


def acquire(
    transport: SRETransport, subscription: str, run_id: str, output_root: Path,
    page_size: int | None = None, resume: bool = False, include_private: bool | None = None,
    include_dns_planning: bool | None = None, dns_subscriptions: list[str] | None = None,
    include_record_metadata: bool | None = None,
    include_dns_paths: bool | None = None,
    include_service_access: bool | None = None,
    include_service_arm: bool | None = None,
    include_nsp: bool | None = None,
) -> nh.Record:
    subscription, run_id = nh.canonical_uuid(subscription), nh.canonical_uuid(run_id)
    if page_size is not None and not 1 <= nh.integer(page_size) <= 1000:
        raise ValueError("Page size must be between 1 and 1000")
    directory = acquisition_directory(output_root, run_id)
    if not resume:
        directory.mkdir(parents=True, exist_ok=False)
    lock = directory / ".acquisition.lock"
    lock.mkdir(exist_ok=False)
    prior_collection_only = transport.collection_only
    prior_approved_operations = transport.approved_operations
    prior_service_parents = transport.approved_service_parents
    prior_nsp_parents = transport.approved_nsp_parents
    transport.collection_only = True
    try:
        return _acquire_locked(transport, subscription, run_id, output_root, page_size, resume, include_private,
                               include_dns_planning, dns_subscriptions, include_record_metadata, include_dns_paths,
                               include_service_access, include_service_arm, include_nsp)
    finally:
        transport.save_pending = None
        transport.collection_only = prior_collection_only
        transport.approved_operations = prior_approved_operations
        transport.approved_service_parents = prior_service_parents
        transport.approved_nsp_parents = prior_nsp_parents
        lock.rmdir()


def _acquire_locked(
    transport: SRETransport, subscription: str, run_id: str, output_root: Path,
    page_size: int | None, resume: bool, include_private: bool | None,
    include_dns_planning: bool | None, dns_subscriptions: list[str] | None,
    include_record_metadata: bool | None,
    include_dns_paths: bool | None,
    include_service_access: bool | None,
    include_service_arm: bool | None,
    include_nsp: bool | None,
) -> nh.Record:
    directory = acquisition_directory(output_root, run_id)
    identity: nh.Record = {
        "stateVersion": "1.0.0", "endpoint": transport.endpoint, "threadId": transport.thread_id,
        "subscriptionId": subscription, "runId": run_id, "capabilityVersion": nh.VERSION,
    }
    if resume:
        state = nh.load(directory / "state.json")
        if state.get("capabilityVersion") != nh.VERSION:
            raise ValueError("Acquisition checkpoint capability version differs")
        if include_nsp is not None and include_nsp != state["includeNsp"]:
            raise ValueError("NSP acquisition differs from saved mode")
        include_nsp = state["includeNsp"]
        if not isinstance(include_nsp, bool):
            raise ValueError("Invalid saved NSP mode")
        if include_service_arm is not None and include_service_arm != state["includeServiceArm"]:
            raise ValueError("Service ARM acquisition differs from saved mode")
        include_service_arm = state["includeServiceArm"]
        if not isinstance(include_service_arm, bool):
            raise ValueError("Invalid saved service ARM mode")
        if include_service_access is not None and include_service_access != state["includeServiceAccess"]:
            raise ValueError("Service access acquisition differs from saved mode")
        include_service_access = state["includeServiceAccess"]
        if not isinstance(include_service_access, bool):
            raise ValueError("Invalid saved service access mode")
        if include_dns_paths is not None and include_dns_paths != state["includeDnsPaths"]:
            raise ValueError("DNS path acquisition differs from saved mode")
        include_dns_paths = state["includeDnsPaths"]
        if not isinstance(include_dns_paths, bool):
            raise ValueError("Invalid saved DNS path mode")
        if include_record_metadata is not None and include_record_metadata != state["includeRepeatedZoneMetadata"]:
            raise ValueError("Repeated-zone metadata acquisition differs from saved mode")
        include_record_metadata = state["includeRepeatedZoneMetadata"]
        if not isinstance(include_record_metadata, bool):
            raise ValueError("Invalid saved repeated-zone metadata mode")
        if include_dns_planning is not None and include_dns_planning != state["includeDnsPlanning"]:
            raise ValueError("DNS planning acquisition scope differs from saved mode")
        if dns_subscriptions is not None and nh.dns_scopes(dns_subscriptions) != state["dnsHostingSubscriptionIds"]:
            raise ValueError("DNS-hosting subscription scope differs from saved scope")
        include_dns_planning = state["includeDnsPlanning"]
        dns_subscriptions = state["dnsHostingSubscriptionIds"]
        if not isinstance(include_dns_planning, bool) or (
            dns_subscriptions is not None and nh.dns_scopes([nh.text(v) for v in nh.array(dns_subscriptions)]) != dns_subscriptions
        ):
            raise ValueError("Invalid saved DNS planning mode/scope")
        if include_private is not None and include_private != state["includePrivateConnectivity"]:
            raise ValueError("Private connectivity acquisition scope differs from saved mode")
        include_private = state["includePrivateConnectivity"]
        if not isinstance(include_private, bool):
            raise ValueError("Invalid private connectivity acquisition mode")
        if include_dns_planning and not include_private:
            raise ValueError("Saved DNS planning mode requires private connectivity")
        if include_record_metadata and not include_dns_planning:
            raise ValueError("Saved metadata mode requires DNS planning")
        if include_dns_paths and not include_record_metadata:
            raise ValueError("Saved DNS path mode requires metadata mode")
        if include_service_access and not include_dns_paths:
            raise ValueError("Saved service access mode requires DNS path mode")
        if include_service_arm and not include_service_access:
            raise ValueError("Saved direct ARM mode requires service access mode")
        if include_nsp and not include_service_arm:
            raise ValueError("Saved NSP mode requires service ARM mode")
        acquisition_config = nh.catalog("1.8.0" if include_nsp else "1.7.0" if include_service_arm else "1.6.0" if include_service_access else "1.5.0" if include_dns_paths else "1.3.0" if include_record_metadata else "1.2.0" if include_dns_planning else "1.1.0" if include_private else "1.0.0")
        identity["catalogSha256"] = nh.digest(acquisition_config)
        if set(state) != {
            *identity, "pageSize", "includePrivateConnectivity", "includeDnsPlanning", "includeRepeatedZoneMetadata", "includeDnsPaths", "includeServiceAccess", "includeServiceArm", "includeNsp", "dnsHostingSubscriptionIds", "progress", "progressSha256", "pendingRead",
            "allowedCommands", "seenExecutions", "transportWarnings",
        } or any(state[key] != value for key, value in identity.items()):
            raise ValueError("Acquisition checkpoint endpoint/thread/scope/run/version/catalog mismatch")
        if page_size is not None and page_size != state["pageSize"]:
            raise ValueError("Acquisition checkpoint page size differs from requested size")
        page_size = nh.integer(state["pageSize"])
        if nh.digest(state["progress"]) != state["progressSha256"]:
            raise ValueError("Acquisition progress integrity mismatch")
    else:
        include_nsp = bool(include_nsp)
        include_service_arm = bool(include_service_arm) or include_nsp
        include_service_access = bool(include_service_access) or include_service_arm
        include_dns_paths = bool(include_dns_paths) or include_service_access
        include_record_metadata = bool(include_record_metadata) or include_dns_paths
        include_dns_planning = bool(include_dns_planning) or include_record_metadata
        dns_subscriptions = nh.dns_scopes(dns_subscriptions)
        if dns_subscriptions is not None and not include_dns_planning:
            raise ValueError("DNS-hosting subscriptions require DNS planning mode")
        include_private = bool(include_private) or include_dns_planning
        acquisition_config = nh.catalog("1.8.0" if include_nsp else "1.7.0" if include_service_arm else "1.6.0" if include_service_access else "1.5.0" if include_dns_paths else "1.3.0" if include_record_metadata else "1.2.0" if include_dns_planning else "1.1.0" if include_private else "1.0.0")
        identity["catalogSha256"] = nh.digest(acquisition_config)
        page_size = nh.integer(nh.catalog()["pageSize"]) if page_size is None else page_size
        state = {
            **identity, "pageSize": page_size, "includePrivateConnectivity": include_private,
            "includeDnsPlanning": include_dns_planning, "dnsHostingSubscriptionIds": dns_subscriptions,
            "includeRepeatedZoneMetadata": include_record_metadata,
            "includeDnsPaths": include_dns_paths,
            "includeServiceAccess": include_service_access,
            "includeServiceArm": include_service_arm,
            "includeNsp": include_nsp,
            "progress": {}, "progressSha256": nh.digest({}),
            "pendingRead": None, "allowedCommands": [], "seenExecutions": [], "transportWarnings": [],
        }
    if not 1 <= page_size <= 1000:
        raise ValueError("Page size must be between 1 and 1000")
    approved: dict[str, list[nh.Record]] = {}
    for operation, requested in nh.collection_plan(acquisition_config, subscription, dns_subscriptions):
        approved.setdefault(requested, []).append(operation)
    transport.approved_operations = approved
    progress = nh.obj(state["progress"])

    def refresh_service_parents() -> None:
        transport.approved_service_parents = {
            nh.text(row["id"]).lower() for collection in nh.records(progress.get("collections", []))
            if collection["operationId"] == "private-link-services" and collection["requestedSubscriptionId"] == subscription
            for row in nh.records(collection["rows"]) if row["type"] in nh.SERVICE_ACCESS_TYPES
        } if include_service_arm else None
        transport.approved_nsp_parents = {
            kind: {nh.text(row["id"]).lower() for collection in nh.records(progress.get("collections", []))
                   if collection["operationId"] == ("nsp-profiles" if kind == "nsp-rules" else "nsp-perimeters")
                   and collection["requestedSubscriptionId"] == subscription for row in nh.records(collection["rows"])}
            for kind in nh.NSP_CHILD_KINDS
        } if include_nsp else None

    refresh_service_parents()
    allowed = set()
    for values in nh.array(state["allowedCommands"]):
        command = [nh.text(value) for value in nh.array(values)]
        token = nh.request_token(command)
        scoped_subscription = nh.canonical_uuid(command[command.index(
            "--subscriptions" if "--subscriptions" in command else "--subscription"
        ) + 1])
        kind = nh.child_kind(command)
        target = nh.command_target(command, scoped_subscription)
        if kind == nh.SERVICE_ARM_KIND and transport.approved_service_parents is not None and (
            target is None or nh.text(target["id"]).lower() not in transport.approved_service_parents
        ):
            raise ValueError("Saved service ARM command exceeds collected approved parents")
        if kind in nh.NSP_CHILD_KINDS and transport.approved_nsp_parents is not None and (
            target is None or nh.text(target["id"]).lower() not in transport.approved_nsp_parents[kind]
        ):
            raise ValueError("Saved NSP command exceeds collected approved parents")
        if not any(command == nh.command_for(op, scoped_subscription, page_size, token, target)
                   for op in approved.get(scoped_subscription, [])
                   if nh.operation_matches_kind(op, kind, target)):
            raise ValueError("Acquisition checkpoint contains a noncatalogued command")
        allowed.add(tuple(command))
    transport.allowed_commands = allowed
    transport.seen_executions = {nh.text(value) for value in nh.array(state["seenExecutions"])}
    transport.submission_warnings = nh.records(state["transportWarnings"])
    transport.pending_request = nh.obj(state["pendingRead"]) if state["pendingRead"] is not None else None
    if transport.pending_request is not None:
        pending = transport.pending_request
        if set(pending) != {"command", "requestId", "prompt"} or tuple(nh.array(pending["command"])) not in allowed:
            raise ValueError("Invalid outstanding native request checkpoint")
        nh.canonical_uuid(nh.text(pending["requestId"]))
        if not progress or progress["current"] is None or not (
            nh.text(pending["requestId"]) in nh.text(pending["prompt"])
            and nh.text(pending["prompt"]).endswith(shlex.join([nh.text(v) for v in nh.array(pending["command"])]))
        ):
            raise ValueError("Outstanding native request is not bound to current page")
    if not resume:
        save_state(directory, state)

    def snapshot() -> None:
        refresh_service_parents()
        state["transportWarnings"] = transport.submission_warnings
        save_acquisition_snapshot(directory, state, progress, transport, error_prefix="Acquisition")

    def pending_read(request: nh.Record) -> None:
        state["pendingRead"] = request
        snapshot()

    def completed_page(updated: nh.Record) -> None:
        state["progress"] = updated
        state["pendingRead"] = None
        snapshot()
        transport.pending_request = None

    transport.save_pending = pending_read
    envelope = nh.collect(
        subscription, run_id, transport.read, source="sre-native-cli", page_size=page_size,
        progress=progress, save_progress=completed_page,
        include_private=include_private,
        include_dns_planning=include_dns_planning, dns_subscriptions=dns_subscriptions,
        include_record_metadata=include_record_metadata,
        include_dns_paths=include_dns_paths,
        include_service_access=include_service_access,
        include_service_arm=include_service_arm,
        include_nsp=include_nsp,
    )
    if progress["current"] is not None or progress["collections"] != envelope["collections"]:
        raise RuntimeError("Collector did not commit the complete acquisition checkpoint")
    transport.wait_for_idle()
    audit = transport.audit()
    audit.update({
        "runId": run_id, "subscriptionId": subscription, "catalogSha256": nh.digest(acquisition_config),
    })
    save_document(directory / "audit.json", audit)
    return envelope


def existing_bundle(model: nh.Record, assessment: nh.Record, output_root: Path) -> nh.Record:
    run_id = nh.canonical_uuid(nh.text(assessment["runId"]))
    directory = output_root.resolve() / "runs" / run_id
    if directory.is_symlink():
        raise ValueError("Existing resumed bundle directory is a symlink")
    if not directory.exists():
        return nh.bundle(model, assessment, output_root)
    summary, engineering = nh.render(assessment)
    expected = {
        "observed-network.json": nh.encoded(model), "assessment.json": nh.encoded(assessment),
        "network-assessment.md": summary.encode(), "network-evidence.md": engineering.encode(),
    }
    if set(path.name for path in directory.iterdir()) != ARTIFACT_NAMES:
        raise ValueError("Existing resumed bundle is incomplete")
    artifacts = {}
    for name, content in expected.items():
        path = directory / name
        if path.is_symlink() or path.read_bytes() != content:
            raise ValueError("Existing resumed bundle differs from checkpoint evidence")
        artifacts[name] = {"path": str(path), "sha256": hashlib.sha256(content).hexdigest()}
    return {"runId": run_id, "status": assessment["status"], "artifacts": artifacts}


def prepare_upload(
    transport: SRETransport, subscription: str, run_id: str,
    output_root: Path, envelope: nh.Record, result: nh.Record,
) -> None:
    content = nh.encoded(envelope)
    if len(content) > INPUT_BUDGET:
        raise ValueError("Projected input exceeds the development attachment budget")
    directory = state_directory(output_root, run_id)
    directory.mkdir(parents=True, exist_ok=False)
    with (directory / "selected-input.json").open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    result = {
        **result, "threadId": transport.thread_id,
        "inputSha256": hashlib.sha256(content).hexdigest(),
        "nativeReadExecutions": len(transport.seen_executions),
        "transportWarnings": transport.submission_warnings,
    }
    save_state(directory, {
        "stateVersion": STATE_VERSION, "endpoint": transport.endpoint,
        "threadId": transport.thread_id, "subscriptionId": nh.canonical_uuid(subscription),
        "runId": nh.canonical_uuid(run_id), "phase": "prepared", "receipt": None,
        "result": result,
    })


def validate_upload(
    transport: SRETransport, subscription: str, run_id: str, output_root: Path,
) -> tuple[nh.Record, bytes]:
    directory = state_directory(output_root, run_id)
    state = nh.load(directory / "state.json")
    if set(state) != {
        "stateVersion", "endpoint", "threadId", "subscriptionId", "runId", "phase", "receipt", "result",
    } or state["stateVersion"] != STATE_VERSION:
        raise ValueError("Unsupported upload checkpoint")
    identity = (transport.endpoint, transport.thread_id, nh.canonical_uuid(subscription), nh.canonical_uuid(run_id))
    if tuple(state[key] for key in ("endpoint", "threadId", "subscriptionId", "runId")) != identity:
        raise ValueError("Upload checkpoint endpoint/thread/scope/run mismatch")
    if state["phase"] not in ("prepared", "uploadStarted", "receiptStored", "verified"):
        raise ValueError("Invalid upload checkpoint phase")
    if (state["receipt"] is not None) != (state["phase"] in ("receiptStored", "verified")):
        raise ValueError("Upload checkpoint receipt/phase mismatch")
    content = (directory / "selected-input.json").read_bytes()
    if len(content) > INPUT_BUDGET:
        raise ValueError("Projected input exceeds the development attachment budget")
    result = nh.obj(state["result"])
    if set(result) != {
        "runId", "status", "artifacts", "threadId", "inputSha256",
        "nativeReadExecutions", "transportWarnings",
    }:
        raise ValueError("Unsupported upload checkpoint result metadata")
    if (
        result["runId"] != run_id or result["threadId"] != transport.thread_id
        or hashlib.sha256(content).hexdigest() != result["inputSha256"]
    ):
        raise ValueError("Selected input or checkpoint identity/hash mismatch")
    envelope = nh.obj(json.loads(content))
    if envelope["runId"] != run_id or envelope["requestedSubscriptionId"] != subscription:
        raise ValueError("Selected input run/scope mismatch")
    bundle_directory = output_root.resolve() / "runs" / run_id
    artifacts = nh.obj(result["artifacts"])
    if set(artifacts) != ARTIFACT_NAMES or set(p.name for p in bundle_directory.iterdir()) != ARTIFACT_NAMES:
        raise ValueError("Upload recovery requires exactly four canonical artifacts")
    for name, value in artifacts.items():
        description = nh.obj(value)
        path = bundle_directory / name
        if Path(nh.text(description["path"])) != path or path.is_symlink():
            raise ValueError("Artifact path differs from the selected run")
        if hashlib.sha256(path.read_bytes()).hexdigest() != description["sha256"]:
            raise ValueError("Existing artifact hash mismatch: " + name)
    model = nh.load(bundle_directory / "observed-network.json")
    assessment = nh.load(bundle_directory / "assessment.json")
    nh.validate_document(model, SKILL / "observed-network.schema.json")
    nh.validate_document(assessment, SKILL / "assessment.schema.json")
    nh.verify_observation(model)
    nh.verify_assessment(model, assessment)
    expected_model = nh.normalize(envelope)
    nh.obj(expected_model["run"])["capabilityVersion"] = nh.obj(model["run"])["capabilityVersion"]
    if expected_model != model or assessment["status"] != result["status"]:
        raise ValueError("Selected input differs from the existing observation bundle")
    nh.verify_reports(
        assessment, (bundle_directory / "network-assessment.md").read_text(encoding="utf-8"),
        (bundle_directory / "network-evidence.md").read_text(encoding="utf-8"),
    )
    return state, content


def attachment_receipt(value: object, name: str, size: int, transport: SRETransport) -> nh.Record:
    values = value if isinstance(value, list) else [value]
    if len(values) != 1:
        raise ValueError("Expected exactly one selected-input attachment receipt")
    receipt = nh.obj(values[0])
    keys = {"fileId", "fileName", "contentType", "fileSize", "downloadUrl"}
    if not keys <= set(receipt):
        raise ValueError("Attachment receipt metadata is incomplete")
    if receipt["fileName"] != name or receipt["fileSize"] != size or receipt["contentType"] != "application/json":
        raise ValueError("Attachment receipt filename/size/content type mismatch")
    if not nh.text(receipt["fileId"]) or not nh.text(receipt["downloadUrl"]):
        raise ValueError("Attachment receipt locator is empty")
    selected = {key: receipt[key] for key in sorted(keys)}
    selected["downloadUrl"] = urllib.parse.urlsplit(transport.download_url(nh.text(receipt["downloadUrl"]))).path
    return selected


def resume_upload(
    transport: SRETransport, subscription: str, run_id: str, output_root: Path,
    supplied_receipt: Path | None = None,
) -> nh.Record:
    subscription, run_id = nh.canonical_uuid(subscription), nh.canonical_uuid(run_id)
    directory = state_directory(output_root, run_id)
    lock = directory / ".upload.lock"
    lock.mkdir(exist_ok=False)
    try:
        state, content = validate_upload(transport, subscription, run_id, output_root)
        name = "collection-input-" + run_id + ".json"
        receipt = (
            attachment_receipt(state["receipt"], name, len(content), transport)
            if state["receipt"] is not None else None
        )
        if supplied_receipt is not None:
            imported = attachment_receipt(
                json.loads(supplied_receipt.read_text(encoding="utf-8")), name, len(content), transport,
            )
            if receipt is not None and imported != receipt:
                raise ValueError("Supplied receipt differs from the durable receipt")
            receipt = imported
        if receipt is None:
            if state["phase"] != "prepared":
                raise RuntimeError(
                    "Upload acceptance is unknown; supply an actual --attachment-receipt. "
                    "No attachment inventory is proven; refusing a blind retry.",
                )

            def before_send() -> None:
                state["phase"] = "uploadStarted"
                save_state(directory, state)

            receipt = attachment_receipt(transport.upload(name, content, before_send), name, len(content), transport)
        state.update({"receipt": receipt, "phase": "receiptStored"})
        save_state(directory, state)
        if transport.download(nh.text(nh.obj(receipt)["downloadUrl"])) != content:
            raise ValueError("Downloaded selected input differs from checkpoint bytes")
        state["phase"] = "verified"
        save_state(directory, state)
        return {
            **nh.obj(state["result"]), "attachment": [receipt], "uploadVerified": True,
            "uploadStatePath": str(directory / "state.json"),
        }
    finally:
        lock.rmdir()


def verify_report_saves(
    transport: SRETransport, state: nh.Record, subscription: str, run_id: str,
) -> nh.Record:
    run_id, subscription = nh.canonical_uuid(run_id), nh.canonical_uuid(subscription)
    files = nh.publication_files(state, run_id, transport.thread_id)
    if state["subscriptionId"] != subscription:
        raise ValueError("Report publication subscription differs from verification scope")
    verified = {}
    contents = {}
    for name, item in files.items():
        if item["key"] is None:
            continue
        content = transport.download(
            f"/api/files/{transport.thread_id}/" + nh.text(item["key"]), nh.integer(item["size"]),
        )
        if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError("Saved report download hash/size mismatch: " + name)
        contents[name] = content
        verified[name] = {"key": item["key"], "sha256": item["sha256"], "size": item["size"]}
    if len(verified) == len(nh.REPORT_FILES):
        model = nh.obj(json.loads(contents["observed-network.json"]))
        assessment = nh.obj(json.loads(contents["assessment.json"]))
        nh.validate_document(model, SKILL / "observed-network.schema.json")
        nh.validate_document(assessment, SKILL / "assessment.schema.json")
        nh.verify_observation(model)
        nh.verify_assessment(model, assessment)
        if nh.obj(model["scope"])["requestedSubscriptionIds"] != [subscription] or assessment["runId"] != run_id:
            raise ValueError("Saved report evidence differs from verification scope/run")
        nh.verify_reports(
            assessment, contents["network-assessment.md"].decode("utf-8"),
            contents["network-evidence.md"].decode("utf-8"),
        )
    return {
        "verificationVersion": "1.0.0", "runId": run_id, "threadId": transport.thread_id,
        "subscriptionId": subscription, "publicationSha256": nh.digest(state),
        "verifiedAt": nh.utc_now(),
        "status": "download-verified" if len(verified) == len(nh.REPORT_FILES) else (
            "partially-download-verified" if verified else "not-download-verified"
        ),
        "artifacts": verified, "remaining": [name for name in nh.REPORT_FILES if name not in verified],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--thread-id", required=True)
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--page-size", type=int, default=None)
    parser.add_argument("--output-root", type=Path, required=True)
    resume_mode = parser.add_mutually_exclusive_group()
    resume_mode.add_argument("--resume-upload", action="store_true")
    resume_mode.add_argument("--resume-acquisition", action="store_true")
    resume_mode.add_argument("--verify-report-saves", type=Path)
    parser.add_argument("--attachment-receipt", type=Path)
    parser.add_argument("--include-private-connectivity", action="store_true", default=None)
    parser.add_argument("--include-dns-planning", action="store_true", default=None)
    parser.add_argument("--dns-hosting-subscription-id", action="append")
    parser.add_argument("--include-repeated-zone-metadata", action="store_true", default=None)
    parser.add_argument("--include-dns-paths", action="store_true", default=None)
    parser.add_argument("--include-service-access", action="store_true", default=None)
    parser.add_argument("--include-service-arm", action="store_true", default=None)
    parser.add_argument("--include-nsp", action="store_true", default=None)
    args = parser.parse_args()
    if args.attachment_receipt and not args.resume_upload:
        parser.error("--attachment-receipt requires --resume-upload")
    if args.resume_upload and args.page_size is not None:
        parser.error("--resume-upload cannot be combined with --page-size")
    if (args.resume_upload or args.verify_report_saves) and (args.include_private_connectivity or args.include_dns_planning or args.dns_hosting_subscription_id or args.include_repeated_zone_metadata or args.include_dns_paths or args.include_service_access or args.include_service_arm or args.include_nsp):
        parser.error("Private acquisition flag cannot be combined with receipt-only verification")
    if args.verify_report_saves and (args.page_size is not None or args.attachment_receipt):
        parser.error("--verify-report-saves cannot be combined with acquisition/upload options")
    subscription, run_id = nh.canonical_uuid(args.subscription_id), nh.canonical_uuid(args.run_id)
    transport = SRETransport(args.endpoint, args.thread_id, access_token())
    if args.verify_report_saves:
        result = verify_report_saves(transport, nh.load(args.verify_report_saves), subscription, run_id)
        args.output_root.mkdir(parents=True, exist_ok=True)
        save_document(args.output_root / ("report-verification-" + run_id + ".json"), result)
        print(json.dumps(result, sort_keys=True))
        return 0
    if not args.resume_upload:
        bundle_directory = args.output_root.resolve() / "runs" / run_id
        if not args.resume_acquisition and any(os.path.lexists(path) for path in (
            bundle_directory, bundle_directory.with_name("." + run_id + ".pending"),
            state_directory(args.output_root, run_id),
            acquisition_directory(args.output_root, run_id),
        )):
            raise FileExistsError("Run already exists; use its explicit acquisition/upload resume mode")
        envelope = acquire(
            transport, subscription, run_id, args.output_root, args.page_size, args.resume_acquisition,
            args.include_private_connectivity,
            args.include_dns_planning, args.dns_hosting_subscription_id,
            args.include_repeated_zone_metadata,
            args.include_dns_paths,
            args.include_service_access,
            args.include_service_arm,
            args.include_nsp,
        )
        model = nh.normalize(envelope)
        assessment = nh.assess(model)
        result = existing_bundle(model, assessment, args.output_root)
        if state_directory(args.output_root, run_id).exists():
            _, content = validate_upload(transport, subscription, run_id, args.output_root)
            if content != nh.encoded(envelope):
                raise ValueError("Acquisition and upload checkpoints differ")
        else:
            prepare_upload(transport, subscription, run_id, args.output_root, envelope, result)
    result = resume_upload(transport, subscription, run_id, args.output_root, args.attachment_receipt)
    if not args.resume_upload:
        result["collectionAuditPath"] = str(acquisition_directory(args.output_root, run_id) / "audit.json")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
