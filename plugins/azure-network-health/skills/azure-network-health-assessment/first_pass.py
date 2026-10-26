"""Read-only first-pass subscription visibility and selected network components."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import network_health as nh


VERSION = "1.0.0"
SUBSCRIPTION_LIMIT = 100
PAGE_LIMIT = 100
PAGE_SIZE = 100
COMPONENT_TYPES = {
    "microsoft.network/virtualnetworks", "microsoft.network/virtualwans", "microsoft.network/virtualhubs",
    "microsoft.network/virtualhubs/hubvirtualnetworkconnections", "microsoft.network/azurefirewalls",
    "microsoft.network/virtualnetworkgateways", "microsoft.network/vpngateways", "microsoft.network/expressroutegateways",
    "microsoft.network/networksecuritygroups", "microsoft.network/routetables", "microsoft.network/natgateways",
    "microsoft.network/bastionhosts", "microsoft.network/privateendpoints", "microsoft.network/privatednszones",
    "microsoft.network/dnsresolvers", "microsoft.network/dnsforwardingrulesets",
    "microsoft.network/networksecurityperimeters", "microsoft.insights/privatelinkscopes",
    "microsoft.monitor/accounts", "microsoft.operationalinsights/workspaces",
}
QUERY = (
    "Resources | where type in~ (" + ",".join("'" + value + "'" for value in sorted(COMPONENT_TYPES))
    + ") | join kind=leftouter (Resources | where type =~ 'microsoft.network/virtualnetworks' "
    "| mv-expand peering=properties.virtualNetworkPeerings limit 2000 "
    "| where isnotempty(peering.properties.remoteVirtualNetwork.id) "
    "| summarize remoteVNetIds=make_set(tostring(peering.properties.remoteVirtualNetwork.id),2000) by id) on id "
    "| project id,name,type,subscriptionId,resourceGroup,location,remoteVNetIds,"
    "virtualWanId=properties.virtualWan.id,remoteVirtualNetworkId=properties.remoteVirtualNetwork.id,"
    "virtualNetworkId=properties.virtualNetwork.id | order by id asc"
)
BASELINE = {
    "classification": "DECLARED", "source": "project-owner-request-2026-10-11",
    "preference": "private-preferred-public-by-documented-exception",
    "exceptions": [],
    "limitations": [
        "This is an assessment preference, not evidence of customer policy approval or permission to change resources.",
        "No endpoint/DNS association alone proves private-only access or public reachability; service settings and ingress/control evidence are required.",
        "Exceptions need service resource identity, reason, owner and verified alternative-control evidence before acceptance.",
        "NSP is service-specific; a perimeter resource alone is not proof of enforced association or permitted access rules.",
        "Microsoft Learn lists Log Analytics workspace NSP integration; Azure Monitor workspace collection/querying is not supported by that integration.",
        "Azure Monitor workspaces have Private Link guidance; do not conflate Microsoft.Monitor/accounts with Log Analytics or automatically exempt them.",
    ],
    "references": [
        "https://learn.microsoft.com/azure/azure-monitor/fundamentals/network-security-perimeter",
        "https://learn.microsoft.com/azure/azure-monitor/fundamentals/private-link-azure-monitor-workspace",
    ],
}


def subscription_command(tenant: str) -> list[str]:
    tenant = nh.canonical_uuid(tenant)
    selected = "[?tenantId=='" + tenant + "'].{subscriptionId:id,displayName:name,state:state,tenantId:tenantId}"
    return ["az", "account", "list", "--all", "--query",
            "{count:length(" + selected + "),data:(" + selected + ")[:100]}", "-o", "json"]


def component_command(subscription: str, token: str | None = None) -> list[str]:
    op = {"kind": "graph", "query": QUERY}
    return nh.command_for(op, nh.canonical_uuid(subscription), PAGE_SIZE, token)


def matches_command(command: list[str], tenant: str, subscriptions: list[str]) -> bool:
    if command == subscription_command(tenant):
        return True
    token = nh.request_token(command)
    return any(command == component_command(subscription, token) for subscription in subscriptions)


def select_component(row: nh.Record, subscription: str) -> nh.Record:
    resource_id = nh.text(row["id"])
    match = nh.RESOURCE_PATTERN.match(resource_id)
    resource_type = nh.text(row["type"]).lower()
    if not match or nh.canonical_uuid(match.group(1)) != subscription or (
        nh.canonical_uuid(nh.text(row["subscriptionId"])) != subscription or resource_type not in COMPONENT_TYPES
    ):
        raise ValueError("First-pass component scope/type mismatch")
    selected: nh.Record = {
        "id": resource_id, "name": nh.text(row["name"]), "type": resource_type, "subscriptionId": subscription,
        "resourceGroup": row.get("resourceGroup"), "location": row.get("location"),
    }
    for key in ("resourceGroup", "location"):
        if selected[key] is not None and not isinstance(selected[key], str):
            raise ValueError("Invalid first-pass component metadata")
    for key in ("virtualWanId", "remoteVirtualNetworkId", "virtualNetworkId"):
        value = row.get(key)
        if value is not None and (not isinstance(value, str) or not nh.RESOURCE_PATTERN.match(value)):
            raise ValueError("Invalid first-pass reference")
        selected[key] = value
    remote = row.get("remoteVNetIds")
    if remote is not None and (not isinstance(remote, list) or len(remote) > 2000 or any(
        not isinstance(value, str) or not nh.RESOURCE_PATTERN.match(value) for value in remote
    )):
        raise ValueError("Invalid first-pass peering references")
    selected["remoteVNetIds"] = remote
    return selected


def collect(
    tenant: str, run_id: str, reader: Callable[[list[str]], nh.ReadResponse],
    progress: nh.Record | None = None, save: Callable[[nh.Record], None] | None = None,
    clock: Callable[[], str] = nh.utc_now,
) -> nh.Record:
    tenant, run_id = nh.canonical_uuid(tenant), nh.canonical_uuid(run_id)
    identity = {"firstPassVersion": VERSION, "tenantId": tenant, "runId": run_id,
                "querySha256": nh.digest(QUERY), "subscriptionQuerySha256": nh.digest(subscription_command(tenant))}
    progress = {} if progress is None else progress
    if not progress:
        progress.update({**identity, "subscriptionDiscovery": None, "subscriptions": [], "collections": [], "current": None})
    if set(progress) != {*identity, "subscriptionDiscovery", "subscriptions", "collections", "current"} or any(
        progress[key] != value for key, value in identity.items()
    ):
        raise ValueError("First-pass checkpoint identity/query mismatch")
    if progress["subscriptionDiscovery"] is None:
        started = clock()
        discovery: nh.Record = {"startedAt": started, "completedAt": started, "status": "succeeded",
                                "issues": [], "executionRefs": [], "reportedCount": None}
        try:
            response = reader(subscription_command(tenant))
        except nh.ReadFailure as exc:
            discovery.update({"status": exc.status, "issues": [exc.code]})
        else:
            discovery["executionRefs"] = [response.execution_id] if response.execution_id else []
            payload = response.payload
            rows = nh.records(payload["data"])
            count = payload.get("count")
            if type(count) is not int or count < len(rows) or len(rows) > SUBSCRIPTION_LIMIT:
                raise ValueError("Invalid bounded subscription discovery response")
            subscriptions = []
            ids = set()
            for row in rows:
                sub = nh.canonical_uuid(nh.text(row["subscriptionId"]))
                if row["tenantId"] != tenant or sub in ids:
                    raise ValueError("Subscription discovery tenant/identity mismatch")
                ids.add(sub)
                subscriptions.append({"subscriptionId": sub, "displayName": nh.text(row["displayName"]),
                                      "state": nh.text(row["state"]), "tenantId": tenant})
            progress["subscriptions"] = sorted(subscriptions, key=lambda row: nh.text(row["subscriptionId"]))
            discovery["reportedCount"] = count
            if count != len(rows):
                discovery.update({"status": "partial", "issues": ["SubscriptionSelectionBudgetExceeded"]})
        discovery["completedAt"] = clock()
        progress["subscriptionDiscovery"] = discovery
        if save:
            save(progress)
    subscriptions = nh.records(progress["subscriptions"])
    saved_ids = [nh.canonical_uuid(nh.text(sub["subscriptionId"])) for sub in subscriptions]
    if len(subscriptions) > SUBSCRIPTION_LIMIT or len(set(saved_ids)) != len(saved_ids):
        raise ValueError("Saved subscription scope exceeds budget or contains duplicate identities")
    for sub in subscriptions:
        if sub["tenantId"] != tenant:
            raise ValueError("Saved subscription tenant mismatch")
    collected = nh.records(progress["collections"])
    if len(collected) > len(subscriptions) or any(
        collection["subscriptionId"] != subscriptions[i]["subscriptionId"] for i, collection in enumerate(collected)
    ):
        raise ValueError("Saved first-pass collection scope mismatch")
    for subscription_row in subscriptions[len(collected):]:
        subscription = nh.text(subscription_row["subscriptionId"])
        current = progress["current"]
        if current is None:
            current = {"subscriptionId": subscription, "startedAt": clock(), "completedAt": clock(),
                       "status": "succeeded", "issues": [], "executionRefs": [], "rows": [],
                       "pageCount": 0, "token": None, "seenTokens": [], "totalSeen": 0, "expectedTotal": None}
            progress["current"] = current
            if save:
                save(progress)
        current = nh.obj(current)
        if current["subscriptionId"] != subscription or not 0 <= nh.integer(current["pageCount"]) <= PAGE_LIMIT:
            raise ValueError("First-pass page checkpoint mismatch")
        if current["token"] is not None and (
            not isinstance(current["token"], str) or not re.fullmatch(r"[A-Za-z0-9+/=_-]{1,8192}", current["token"])
            or current["token"] not in nh.array(current["seenTokens"])
        ):
            raise ValueError("First-pass checkpoint continuation is invalid")
        rows = {nh.text(row["id"]).lower(): row for row in nh.records(current["rows"])}
        for row in rows.values():
            if select_component(row, subscription) != row:
                raise ValueError("First-pass checkpoint contains nonselected evidence")
        if len(rows) != len(nh.records(current["rows"])):
            raise ValueError("Duplicate first-pass checkpoint resources")
        for _ in range(nh.integer(current["pageCount"]), PAGE_LIMIT):
            try:
                response = reader(component_command(subscription, nh.text(current["token"]) if current["token"] else None))
            except nh.ReadFailure as exc:
                current["status"] = "partial" if rows else exc.status
                nh.array(current["issues"]).append(exc.code)
                break
            payload = response.payload
            items = nh.records(payload["data"])
            if len(items) > PAGE_SIZE:
                raise ValueError("First-pass page exceeds selected budget")
            current["pageCount"] = nh.integer(current["pageCount"]) + 1
            current["totalSeen"] = nh.integer(current["totalSeen"]) + len(items)
            if response.execution_id:
                nh.array(current["executionRefs"]).append(response.execution_id)
            total = payload.get("total_records", payload.get("totalRecords"))
            if type(total) is not int or total < 0:
                nh.array(current["issues"]).append("TotalRecordCountUnavailable")
            else:
                if current["expectedTotal"] is not None and current["expectedTotal"] != total:
                    nh.array(current["issues"]).append("InventoryChangedDuringPaging")
                current["expectedTotal"] = total
            if payload.get("count") != len(items):
                nh.array(current["issues"]).append("PageCountMismatch")
            for item in items:
                try:
                    row = select_component(item, subscription)
                except (ValueError, KeyError) as exc:
                    nh.array(current["issues"]).append("RejectedRow:" + type(exc).__name__)
                    continue
                key = nh.text(row["id"]).lower()
                if key in rows:
                    nh.array(current["issues"]).append("RepeatedResource")
                else:
                    rows[key] = row
            current["rows"] = [rows[key] for key in sorted(rows)]
            token = payload.get("skip_token", payload.get("$skipToken"))
            if not token:
                if payload.get("resultTruncated") in (True, 1, "true"):
                    nh.array(current["issues"]).append("TruncatedWithoutContinuation")
                break
            if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9+/=_-]{1,8192}", token):
                nh.array(current["issues"]).append("UnsupportedContinuation")
                break
            if token in nh.array(current["seenTokens"]) or not items:
                nh.array(current["issues"]).append("RepeatedOrEmptyContinuation")
                break
            current["token"] = token
            nh.array(current["seenTokens"]).append(token)
            if save:
                save(progress)
        else:
            nh.array(current["issues"]).append("PageBudgetExceeded")
        if current["expectedTotal"] is not None and current["expectedTotal"] != len(rows):
            nh.array(current["issues"]).append("RetainedCountMismatch")
        if nh.array(current["issues"]) and current["status"] == "succeeded":
            current["status"] = "partial"
        current["completedAt"] = clock()
        current["issues"] = sorted(set(nh.text(value) for value in nh.array(current["issues"])))
        collected.append(current)
        progress.update({"collections": collected, "current": None})
        if save:
            save(progress)
    return {**identity, "subscriptionDiscovery": progress["subscriptionDiscovery"],
            "subscriptions": subscriptions, "collections": collected}


def summarize(envelope: nh.Record) -> nh.Record:
    expected_keys = {"firstPassVersion", "tenantId", "runId", "querySha256", "subscriptionQuerySha256",
                     "subscriptionDiscovery", "subscriptions", "collections"}
    if not expected_keys <= set(envelope) or set(envelope) - expected_keys - {"executionSource"}:
        raise ValueError("Unexpected first-pass envelope fields")
    if envelope["firstPassVersion"] != VERSION:
        raise ValueError("Unsupported first-pass input version")
    tenant = nh.canonical_uuid(nh.text(envelope["tenantId"]))
    nh.canonical_uuid(nh.text(envelope["runId"]))
    if envelope["querySha256"] != nh.digest(QUERY) or envelope["subscriptionQuerySha256"] != nh.digest(subscription_command(tenant)):
        raise ValueError("First-pass input query provenance differs")
    subscriptions = nh.records(envelope["subscriptions"])
    collections = nh.records(envelope["collections"])
    if len(subscriptions) != len(collections) or len(subscriptions) > SUBSCRIPTION_LIMIT:
        raise ValueError("Each discovered subscription requires an explicit first-pass outcome")
    ids = [nh.text(row["subscriptionId"]) for row in subscriptions]
    if len(ids) != len(set(ids)) or {c["subscriptionId"] for c in collections} != set(ids):
        raise ValueError("First-pass duplicate or mismatched scopes")
    summaries = []
    for subscription in subscriptions:
        sub = nh.canonical_uuid(nh.text(subscription["subscriptionId"]))
        if subscription["tenantId"] != tenant:
            raise ValueError("First-pass tenant mismatch")
        collection = next(c for c in collections if c["subscriptionId"] == sub)
        if not 0 <= nh.integer(collection["pageCount"]) <= PAGE_LIMIT:
            raise ValueError("First-pass collection page budget mismatch")
        if len({nh.text(row["id"]).lower() for row in nh.records(collection["rows"])}) != len(nh.records(collection["rows"])):
            raise ValueError("Duplicate first-pass retained resources")
        if collection["status"] not in ("succeeded", "partial", "permissionDenied", "unavailable", "unsupported", "failed"):
            raise ValueError("Invalid first-pass outcome")
        if collection["status"] == "succeeded" and (nh.array(collection["issues"]) or collection["expectedTotal"] != len(nh.records(collection["rows"]))):
            raise ValueError("First-pass succeeded outcome cannot hide incomplete selected inventory")
        rows = [select_component(row, sub) for row in nh.records(collection["rows"])]
        counts = Counter(nh.text(row["type"]) for row in rows)
        name = nh.text(subscription["displayName"])
        words = set(re.findall(r"[a-z0-9]+", name.lower()))
        roles = []
        for role, keywords in (("connectivity/shared-network", {"hub", "network", "connectivity", "shared"}),
                               ("management/observability", {"management", "monitor", "logging", "ops"}),
                               ("production-workload", {"prod", "production"}),
                               ("nonproduction-workload", {"dev", "test", "sandbox", "nonprod"})):
            if words & keywords:
                roles.append(role)
        signs = []
        peer_refs = {nh.text(value) for row in rows for value in nh.array(row.get("remoteVNetIds") or [])}
        if peer_refs:
            signs.append({"classification": "INFERRED", "pattern": "possible-peered-hub-spoke-or-mesh",
                          "basisResourceIds": sorted(nh.text(row["id"]) for row in rows if row.get("remoteVNetIds")),
                          "limitations": "Peering alone cannot distinguish hub/spoke from mesh or prove transit/traffic."})
        if counts["microsoft.network/virtualwans"] or counts["microsoft.network/virtualhubs"] or (
            counts["microsoft.network/virtualhubs/hubvirtualnetworkconnections"]
        ):
            signs.append({"classification": "INFERRED", "pattern": "possible-vwan-based-architecture",
                          "basisResourceIds": sorted(nh.text(row["id"]) for row in rows if row["type"] in (
                              "microsoft.network/virtualwans", "microsoft.network/virtualhubs",
                              "microsoft.network/virtualhubs/hubvirtualnetworkconnections")),
                          "limitations": "Selected resources are signs only; child indexing/connections and external hubs may be missing."})
        refs = peer_refs | {nh.text(row[key]) for row in rows for key in (
            "virtualWanId", "remoteVirtualNetworkId", "virtualNetworkId") if row.get(key)}
        external = sorted(value for value in refs if nh.canonical_uuid(nh.RESOURCE_PATTERN.match(value).group(1)) != sub)
        summaries.append({
            **subscription, "roleHints": {"classification": "INFERRED", "values": roles, "basis": "display-name-only-needs-customer-confirmation"},
            "collection": {key: value for key, value in collection.items() if key != "rows"},
            "componentCounts": dict(sorted(counts.items())), "selectedComponents": rows,
            "architectureSigns": signs, "externalReferences": external,
            "accessInterpretation": "accessible-indexed-results-only-not-permission-wide-proof",
            "nextAction": "Full inspection is a separate trigger; confirm workload and shared/DNS-host roles without automatic reference expansion.",
            "supplementalCommand": component_command(sub),
            "fullInspectionCommandTemplate": [
                "python", "tools\\network_health_sre.py", "--endpoint", "<same-SRE-origin>",
                "--thread-id", "<fresh-collection-thread>", "--subscription-id", sub,
                "--run-id", "<new-full-run-uuid>", "--output-root", "<private-output-root>",
                "--include-dns-paths",
            ],
        })
    return {
        "firstPassVersion": VERSION, "runId": envelope["runId"], "tenantId": tenant,
        "phase": "initial-scope-and-components-not-full-assessment",
        "inputSha256": nh.digest(envelope), "subscriptionDiscovery": envelope["subscriptionDiscovery"],
        "executionSource": envelope.get("executionSource", "supplied-input-identity-not-independently-authenticated"),
        "privateAccessBaseline": BASELINE, "subscriptions": summaries,
        "limitations": [
            "The current executing identity's visible subscriptions are not the SRE managed identity's RBAC scope or complete tenant inventory.",
            "Successful ARG queries can omit inaccessible/unindexed resources; zero results do not prove absence.",
            "No public-access settings, effective routes/security, records, telemetry or service-control enforcement were inspected.",
            "Subscription role names and architecture signs are INFERRED; customer names/central subscriptions and external references require confirmation.",
            "OBO temporarily uses eligible user permissions if platform-supported; it does not grant access. Required platform consent cannot be bypassed.",
            "If OBO is unavailable, run the exact selected read-only supplemental command as the operator; preserve original JSON and identity/time/query provenance.",
            "Do not load tokens/secrets into the SRE sandbox, grant roles, enable diagnostics or mutate resources.",
        ],
    }


def apply_supplement(envelope: nh.Record, supplement: nh.Record) -> nh.Record:
    summarize(envelope)
    if set(supplement) != {"subscriptionId", "querySha256", "identityDescription", "collectedAt", "payload"}:
        raise ValueError("Supplement must contain exact collection identity/time/query provenance and original selected payload")
    subscription = nh.canonical_uuid(nh.text(supplement["subscriptionId"]))
    if supplement["querySha256"] != nh.digest(QUERY) or not nh.text(supplement["identityDescription"]).strip():
        raise ValueError("Supplement query/identity provenance mismatch")
    timestamp = nh.text(supplement["collectedAt"])
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", timestamp):
        raise ValueError("Supplement collection time must be UTC")
    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    payload = nh.obj(supplement["payload"])
    rows = nh.records(payload["data"])
    total = payload.get("total_records", payload.get("totalRecords"))
    if payload.get("count") != len(rows) or type(total) is not int or total != len(rows) or (
        payload.get("skip_token") or payload.get("$skipToken") or payload.get("resultTruncated") in (True, 1, "true")
    ):
        raise ValueError("Supplement must be a complete selected response; use the operator collector for paged evidence")
    collections = nh.records(envelope["collections"])
    original = next((c for c in collections if c["subscriptionId"] == subscription), None)
    if original is None:
        raise ValueError("Supplement scope was not discovered; no automatic scope expansion")
    if "supplementalProvenance" in original:
        raise ValueError("Supplement already applied; use a separately versioned input rather than replacing provenance")
    selected = [select_component(row, subscription) for row in rows]
    if len({nh.text(row["id"]).lower() for row in selected}) != len(selected):
        raise ValueError("Supplement contains duplicate resources")
    replaced = {**original, "status": "succeeded", "issues": [], "rows": selected, "pageCount": 1,
                "startedAt": supplement["collectedAt"], "completedAt": supplement["collectedAt"],
                "totalSeen": len(selected), "expectedTotal": total, "token": None, "seenTokens": [], "executionRefs": [],
                "supplementalProvenance": {key: value for key, value in supplement.items() if key != "payload"},
                "originalAttempt": original}
    return {**envelope, "collections": [replaced if c is original else c for c in collections]}


def render(summary: nh.Record) -> str:
    lines = ["# Initial Azure Network Scope and Component Summary", "",
             "**Phase:** initial discovery only; not full inspection or network-health certification.",
             "**Run:** " + nh.text(summary["runId"]), "**Tenant:** " + nh.text(summary["tenantId"]),
             "**Input canonical hash:** " + nh.text(summary["inputSha256"]), "",
             "**Execution source:** " + nh.markdown(summary["executionSource"]), "",
             "## Private-access assessment preference", "",
             "DECLARED baseline: private preferred; public access by documented exception. No resource changes are authorized.",
             "Azure Monitor workspaces and Log Analytics workspaces are different resources. NSP is not an automatic Azure Monitor workspace exemption.", "",
             "## Subscription visibility and observations", "",
             "| Subscription | Name | Tentative roles (INFERRED) | Read outcome / pages | Observed component counts |",
             "|---|---|---|---|---|"]
    for sub in nh.records(summary["subscriptions"]):
        collection = nh.obj(sub["collection"])
        lines.append(f"| {nh.markdown(sub['subscriptionId'])} | {nh.markdown(sub['displayName'])} | "
                     + nh.markdown(", ".join(nh.text(v) for v in nh.array(nh.obj(sub["roleHints"])["values"])))
                     + f" | {nh.markdown(collection['status'])} / {collection['pageCount']} | "
                     + nh.markdown(json.dumps(sub["componentCounts"], sort_keys=True)) + " |")
    lines.extend(["", "## Architecture signs and access gaps", ""])
    for sub in nh.records(summary["subscriptions"]):
        lines.extend(["### " + nh.markdown(sub["displayName"]), "",
                      "Collection issues: " + nh.markdown("; ".join(nh.text(v) for v in nh.array(nh.obj(sub["collection"])["issues"])) or "None reported; completeness still UNKNOWN."),
                      "External configuration references: " + nh.markdown("; ".join(nh.text(v) for v in nh.array(sub["externalReferences"])) or "None retained; not proof of no external dependencies.")])
        if "supplementalProvenance" in nh.obj(sub["collection"]):
            provenance = nh.obj(nh.obj(sub["collection"])["supplementalProvenance"])
            lines.append("Operator-supplied supplemental evidence: " + nh.markdown(provenance["identityDescription"])
                         + " at " + nh.markdown(provenance["collectedAt"]) + "; original attempt outcome="
                         + nh.markdown(nh.obj(nh.obj(sub["collection"])["originalAttempt"])["status"])
                         + ". Operator metadata is not independently authenticated.")
        for sign in nh.records(sub["architectureSigns"]):
            lines.append("- INFERRED " + nh.markdown(sign["pattern"]) + ": " + nh.markdown(sign["limitations"]))
    lines.extend(["", "## Next step", "",
                  "Trigger full inspection separately using selected workload and DNS-host subscription IDs. No extra conversational approval is needed for already authorized read-only scope; platform OBO consent, if required, remains.",
                  "On access failure, request the runtime-supported OBO path without promising elevation. Otherwise run the exact supplemental command from scope-summary.json and return the original selected JSON with identity and collection time.", "",
                  "## Limitations", "", *["- " + nh.markdown(value) for value in nh.array(summary["limitations"])], "",
                  "## Baseline limitations and sources", "", *["- " + nh.markdown(value) for value in BASELINE["limitations"]],
                  *["- " + value for value in BASELINE["references"]], ""])
    return "\n".join(lines)


def write_summary(envelope: nh.Record, root: Path) -> nh.Record:
    summary = summarize(envelope)
    directory = root.resolve() / "first-pass" / nh.canonical_uuid(nh.text(envelope["runId"]))
    directory.parent.mkdir(parents=True, exist_ok=True)
    if directory.exists() or directory.is_symlink():
        raise FileExistsError("First-pass report already exists; do not overwrite")
    staging = directory.with_name("." + directory.name + ".pending")
    staging.mkdir(exist_ok=False)
    payloads = {"selected-input.json": nh.encoded(envelope), "scope-summary.json": nh.encoded(summary),
                "scope-summary.md": render(summary).encode()}
    for name, data in payloads.items():
        with (staging / name).open("xb") as file:
            file.write(data)
        if (staging / name).read_bytes() != data:
            raise ValueError("First-pass persisted bytes mismatch")
    staging.rename(directory)
    return {"phase": summary["phase"], "runId": envelope["runId"], "directory": str(directory),
            "artifacts": {name: {"path": str(directory / name), "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in payloads.items()}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--supplement", action="append", type=Path, default=[])
    args = parser.parse_args()
    envelope = nh.load(args.input)
    for path in args.supplement:
        envelope = apply_supplement(envelope, nh.load(path))
    print(json.dumps(write_summary(envelope, args.output_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
