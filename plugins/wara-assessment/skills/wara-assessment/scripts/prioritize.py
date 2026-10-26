#!/usr/bin/env python3
"""Deterministically prioritize normalized WARA findings and compare with the previous run of the same scope.

Inputs : derived/findings.json (normalize_findings.py), prioritization config (YAML/JSON),
         optional previous run's derived/prioritized-findings.json
Outputs: <out-dir>/prioritized-findings.json, prioritized-findings.csv, delta.json, prioritized-report.md
Stdout : one-line JSON summary (consumed by Invoke-WaraRun.ps1 for run.json)

Scoring (all factors configurable):
    score = impact[impact] * evidence[classification] * control[control] * criticality[level]
Severity (impact) is the potential impact from APRL/Advisor. Priority (band) is the recommended
action order for THIS environment. The next action for UNKNOWN evidence is validation, not remediation.
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from collections import Counter, OrderedDict

PRIORITIZER_VERSION = "1.0.1"


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:  # pragma: no cover
            sys.exit("PyYAML is required for YAML prioritization configs (or supply JSON).")
        cfg = yaml.safe_load(text)
    else:
        cfg = json.loads(text)
    cfg["_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return cfg


def load_json(path: str):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def criticality_for(finding: dict, cfg: dict) -> tuple[str, str]:
    crit = cfg.get("criticality", {})
    res = finding.get("resource") or {}
    for rule in crit.get("rules", []) or []:
        field = rule.get("field", "id")
        value = str(res.get(field) or "")
        if re.search(rule["match"], value, re.IGNORECASE):
            return rule["level"], f"rule:{rule.get('name') or rule['match']}"
    return crit.get("default", "standard"), "default"


def suppression_for(finding: dict, cfg: dict, today: _dt.date) -> dict | None:
    for s in cfg.get("suppressions", []) or []:
        if s.get("findingKey") and s["findingKey"] != finding["findingKey"]:
            continue
        if s.get("recommendationId") and (s["recommendationId"] or "").lower() != (finding.get("recommendationId") or "").lower():
            continue
        if s.get("resourceIdMatch") and not re.search(s["resourceIdMatch"], finding["resource"].get("id") or "", re.IGNORECASE):
            continue
        if not (s.get("findingKey") or s.get("recommendationId") or s.get("resourceIdMatch")):
            continue
        expires = s.get("expires")
        if expires and _dt.date.fromisoformat(str(expires)) < today:
            continue
        return {k: (str(v) if isinstance(v, _dt.date) else v) for k, v in s.items()}
    return None


def next_action(f: dict) -> str:
    ev = f["evidence"]
    if ev["classification"] == "OBSERVED":
        return "Remediate or formally accept the risk"
    if ev["reason"] == "no-guidance-for-type":
        return "Review applicability (no APRL/Advisor guidance)"
    return "Validate manually, then remediate or close"


def score(f: dict, cfg: dict) -> tuple[float, dict]:
    w = cfg.get("weights", {})
    impact = w.get("impact", {}).get(f.get("impact") or "", w.get("impact", {}).get("default", 1))
    evidence = w.get("evidence", {}).get(f["evidence"]["classification"], 0.5)
    control_w = w.get("control", {})
    control = control_w.get(f.get("control") or "", control_w.get("default", 1.0))
    level, basis = criticality_for(f, cfg)
    crit = cfg.get("criticality", {}).get("levels", {}).get(level, 1.0)
    value = round(float(impact) * float(evidence) * float(control) * float(crit), 3)
    return value, {"impact": impact, "evidence": evidence, "control": control,
                   "criticality": crit, "criticalityLevel": level, "criticalityBasis": basis}


def band_for(value: float, cfg: dict) -> str:
    for b in sorted(cfg.get("bands", []), key=lambda b: -float(b["min"])):
        if value >= float(b["min"]):
            return b["name"]
    return "P4"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--previous", help="previous run's prioritized-findings.json for the same scope")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--today", help="override date for suppression expiry (YYYY-MM-DD; tests)")
    args = ap.parse_args()

    doc = load_json(args.findings)
    cfg = load_config(args.config)
    today = _dt.date.fromisoformat(args.today) if args.today else _dt.datetime.now(_dt.timezone.utc).date()
    prev = load_json(args.previous) if args.previous else None
    scope_fields = ("type", "tenantId", "subscriptionId", "resourceGroup")
    scope_identity = lambda scope: tuple(str((scope or {}).get(k) or "").lower() for k in scope_fields)
    if prev and scope_identity(prev.get("scope")) != scope_identity(doc.get("scope")):
        raise ValueError("Previous run scope does not match the current run scope.")
    prev_by_key = {f["findingKey"]: f for f in (prev or {}).get("findings", [])}
    for item in (prev or {}).get("resolved", []):
        if item["status"] == "NOT_REOBSERVED":
            before = item["previousFinding"]
            prev_by_key.setdefault(before["findingKey"], before)
    coverage = doc.get("coverage", {})
    collection_complete = coverage.get("collectionStatus") == "Completed" and not coverage.get("collectionErrors")
    inventory = {rid.lower() for rid in coverage.get("inventoryIds", [])}
    run_id = doc.get("runId")

    out = []
    for f in doc.get("findings", []):
        value, factors = score(f, cfg)
        sup = suppression_for(f, cfg, today)
        p = dict(f)
        p["priority"] = {
            "score": value,
            "band": "Accepted" if sup else band_for(value, cfg),
            "nextAction": "Accepted risk - review at expiry" if sup else next_action(f),
            "factors": factors,
            "suppression": sup,
        }
        before = prev_by_key.get(f["findingKey"])
        p["lifecycle"] = {
            "status": "PERSISTING" if before else ("NEW" if prev else "BASELINE"),
            "firstSeenRunId": (before or {}).get("lifecycle", {}).get("firstSeenRunId") or (prev or {}).get("runId") if before else run_id,
            "previousBand": (before or {}).get("priority", {}).get("band"),
        }
        out.append(p)

    resolved = []
    current_keys = {f["findingKey"] for f in out}
    for key, before in prev_by_key.items():
        if key in current_keys:
            continue
        rid = (before.get("resource") or {}).get("id", "").lower()
        if not collection_complete:
            status = "NOT_REOBSERVED"
        elif rid and rid not in inventory:
            status = "RESOURCE_NOT_LISTED"
        elif before["evidence"]["classification"] == "OBSERVED":
            status = "NO_LONGER_DETECTED"
        else:
            status = "NO_LONGER_LISTED"
        resolved.append({"findingKey": key, "status": status, "title": before.get("title"),
                         "resource": before.get("resource"), "previousBand": before.get("priority", {}).get("band"),
                         "firstSeenRunId": before.get("lifecycle", {}).get("firstSeenRunId")})
        if status == "NOT_REOBSERVED":
            resolved[-1]["previousFinding"] = before

    order = {b["name"]: i for i, b in enumerate(sorted(cfg.get("bands", []), key=lambda b: -float(b["min"])))}
    order["Accepted"] = len(order)
    out.sort(key=lambda f: (order.get(f["priority"]["band"], 99), -f["priority"]["score"], f.get("title") or "", f["resource"].get("name") or ""))

    bands = Counter(f["priority"]["band"] for f in out)
    life = Counter(f["lifecycle"]["status"] for f in out)
    evid = Counter(f["evidence"]["classification"] for f in out)
    summary = OrderedDict(
        findings=len(out),
        bands=dict(sorted(bands.items(), key=lambda kv: order.get(kv[0], 99))),
        evidence=dict(evid),
        lifecycle=dict(life),
        resolved=sum(r["status"] != "NOT_REOBSERVED" for r in resolved),
        notReobserved=sum(r["status"] == "NOT_REOBSERVED" for r in resolved),
        previousRunId=(prev or {}).get("runId"),
    )

    os.makedirs(args.out_dir, exist_ok=True)
    result = {
        "schemaVersion": "1.0",
        "generatedBy": {"name": "wara-assessment/prioritize.py", "version": PRIORITIZER_VERSION},
        "runId": run_id,
        "scope": doc.get("scope"),
        "config": {"path": os.path.basename(args.config), "sha256": cfg["_sha256"], "version": cfg.get("version")},
        "summary": summary,
        "findings": out,
        "resolved": resolved,
    }
    with open(os.path.join(args.out_dir, "prioritized-findings.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)
    with open(os.path.join(args.out_dir, "delta.json"), "w", encoding="utf-8") as fh:
        json.dump({"runId": run_id, "previousRunId": summary["previousRunId"],
                   "new": [f["findingKey"] for f in out if f["lifecycle"]["status"] == "NEW"],
                   "persisting": [f["findingKey"] for f in out if f["lifecycle"]["status"] == "PERSISTING"],
                   "resolved": resolved}, fh, indent=2, default=str)
    write_csv(os.path.join(args.out_dir, "prioritized-findings.csv"), out)
    write_report(os.path.join(args.out_dir, "prioritized-report.md"), doc, result, cfg)
    print(json.dumps(summary))
    return 0


def write_csv(path: str, findings: list) -> None:
    cols = ["band", "score", "nextAction", "lifecycle", "impact", "control", "evidence", "evidenceReason", "source",
            "title", "resourceName", "resourceType", "resourceGroup", "subscriptionId", "location", "details",
            "recommendationId", "findingKey", "resourceId", "learnMore"]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in findings:
            r, pr, ev = f["resource"], f["priority"], f["evidence"]
            w.writerow([pr["band"], pr["score"], pr["nextAction"], f["lifecycle"]["status"], f.get("impact"), f.get("control"),
                        ev["classification"], ev["reason"], f["source"], f.get("title"), r.get("name"), r.get("type"),
                        r.get("resourceGroup"), r.get("subscriptionId"), r.get("location"), "; ".join(ev.get("details") or []),
                        f.get("recommendationId"), f["findingKey"], r.get("id"),
                        (f.get("learnMore") or [{}])[0].get("url", "")])


def _md(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def write_report(path: str, doc: dict, result: dict, cfg: dict) -> None:
    s = result["summary"]
    scope = doc.get("scope") or {}
    findings = result["findings"]
    L = []
    title = scope.get("resourceGroup") or ("subscription " + str(scope.get("subscriptionName") or scope.get("subscriptionId") or ""))
    L.append(f"# Prioritized reliability findings: {title}")
    L.append("")
    L.append(f"Run `{result['runId']}` | scope type **{scope.get('type', 'n/a')}** | subscription `{scope.get('subscriptionId', 'n/a')}` "
             f"| previous run `{s.get('previousRunId') or 'none (baseline)'}`")
    L.append("")
    L.append("> Deterministic view generated from `prioritized-findings.json` (prioritize.py "
             f"{PRIORITIZER_VERSION}, config sha256 `{result['config']['sha256'][:12]}`). Source data: Microsoft WARA collector "
             "+ APRL recommendations + Azure Advisor. UNKNOWN evidence means WARA could not evaluate the check automatically: "
             "it is a validation task, not a confirmed defect.")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| Band | Findings |")
    L.append("|---|---|")
    for band, n in s["bands"].items():
        L.append(f"| {band} | {n} |")
    L.append("")
    L.append(f"- Evidence: {', '.join(f'{k} {v}' for k, v in s['evidence'].items()) or 'none'}")
    L.append(f"- Lifecycle: {', '.join(f'{k} {v}' for k, v in s['lifecycle'].items()) or 'none'}; "
             f"no longer reported: {s['resolved']}; not reobserved (incomplete collection): {s['notReobserved']}")
    cov = doc.get("coverage", {})
    L.append(f"- Resources in scope inventory: {cov.get('inventoryCount', 'n/a')}; resource types without APRL/Advisor guidance: "
             f"{', '.join(cov.get('typesWithoutGuidance') or []) or 'none'}")
    L.append("")

    groups: "OrderedDict[tuple, list]" = OrderedDict()
    for f in findings:
        k = (f["priority"]["band"], f.get("title"), f.get("impact"), f.get("control"), f["evidence"]["classification"], f["priority"]["nextAction"])
        groups.setdefault(k, []).append(f)

    current = None
    for (band, t, impact, control, ev, action), items in groups.items():
        if band != current:
            current = band
            L.append(f"## {band}")
            L.append("")
            L.append("| Recommendation | Impact | Control | Evidence | Next action | Resources | New | Learn more |")
            L.append("|---|---|---|---|---|---|---|---|")
        names = sorted({i["resource"].get("name") or i["resource"].get("id") for i in items})
        new = sum(1 for i in items if i["lifecycle"]["status"] == "NEW")
        link = next((i["learnMore"][0]["url"] for i in items if i.get("learnMore")), "")
        L.append(f"| {_md(t)} | {_md(impact)} | {_md(control)} | {ev} | {_md(action)} | {_md(', '.join(names))} | {new or ''} | "
                 f"{f'[link]({link})' if link else ''} |")
    if result["resolved"]:
        L.append("")
        L.append("## Missing findings since previous run (not proof of remediation or deletion)")
        L.append("")
        L.append("| Status | Recommendation | Resource | Previous band |")
        L.append("|---|---|---|---|")
        for r in result["resolved"]:
            L.append(f"| {r['status']} | {_md(r.get('title'))} | {_md((r.get('resource') or {}).get('name'))} | {_md(r.get('previousBand'))} |")
    ctx = doc.get("context", {})
    L.append("")
    L.append("## Platform context (from WARA collector)")
    L.append("")
    for k in ("outages", "retirements", "serviceHealth", "supportTickets"):
        L.append(f"- {k}: {len(ctx.get(k) or [])} item(s)")
    L.append("")
    L.append("## Method")
    L.append("")
    L.append("`score = impact x evidence x control x criticality`; bands: " +
             ", ".join(f"{b['name']} >= {b['min']}" for b in sorted(cfg.get("bands", []), key=lambda b: -float(b["min"]))) +
             ". Weights, criticality rules and accepted-risk suppressions are in the prioritization config.")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
