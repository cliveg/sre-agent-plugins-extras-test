#!/usr/bin/env python3
"""Normalize a WARA collector JSON (WARA-File-*.json) into a stable, evidence-classified findings contract.

Output: derived/findings.json (schemaVersion 1.0)

Evidence classification (repository vocabulary):
  OBSERVED  the finding was produced by an authoritative source for this run:
            - an APRL Azure Resource Graph query matched the resource ("APRL - Queries"), or
            - Azure Advisor reported it (collector `advisory` section).
  UNKNOWN   WARA could not evaluate it automatically; the resource is in scope for the
            recommendation but must be validated manually. Never treat these as confirmed defects.

Each finding has a deterministic `findingKey` = sha1(source|recommendationId|lower(resourceId))[:16]
so the same issue on the same resource can be tracked across monthly runs.

Python 3.8+, standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter

SCHEMA_VERSION = "1.0"
NORMALIZER_VERSION = "1.0.1"

VALIDATION_MAP = [
    # (substring of WARA validationAction, classification, reason)
    ("APRL - Queries", "OBSERVED", "aprl-query-match"),
    ("cannot be validated with ARG", "UNKNOWN", "not-queryable"),
    ("Query under development", "UNKNOWN", "query-under-development"),
    ("not available in either APRL or Advisor", "UNKNOWN", "no-guidance-for-type"),
]


def classify(validation_action: str) -> tuple[str, str]:
    for needle, cls, reason in VALIDATION_MAP:
        if needle.lower() in (validation_action or "").lower():
            return cls, reason
    return "UNKNOWN", "unrecognized-validation-action"


def finding_key(source: str, rec_id: str, resource_id: str) -> str:
    raw = f"{source}|{(rec_id or '').lower()}|{(resource_id or '').lower()}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def load_json(path: str):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def links(rec: dict) -> list[dict]:
    out = []
    for item in rec.get("learnMoreLink") or []:
        if isinstance(item, dict) and item.get("url"):
            out.append({"name": item.get("name") or item["url"], "url": item["url"]})
    return out


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--collector-json", required=True)
    ap.add_argument("--run-json", help="run.json written by Invoke-WaraRun.ps1 (scope + provenance)")
    ap.add_argument("--recommendations", help="recommendations.json used for the run (enrichment)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    collector = load_json(args.collector_json)
    run = load_json(args.run_json) if args.run_json else {}
    catalog = {}
    if args.recommendations:
        for rec in load_json(args.recommendations):
            if isinstance(rec, dict) and rec.get("aprlGuid"):
                catalog[rec["aprlGuid"].lower()] = rec

    findings: dict[str, dict] = {}

    def upsert(source, rec_id, row, cls, reason, basis, meta):
        rid = row.get("id") or ""
        key = finding_key(source, rec_id, rid)
        params = [str(row.get(f"param{i}")) for i in range(1, 6) if row.get(f"param{i}") not in (None, "")]
        if key in findings:
            existing = findings[key]
            for p in params:
                if p not in existing["evidence"]["details"]:
                    existing["evidence"]["details"].append(p)
            # OBSERVED wins over UNKNOWN when WARA emits both for the same pair.
            if cls == "OBSERVED" and existing["evidence"]["classification"] != "OBSERVED":
                existing["evidence"].update({"classification": cls, "reason": reason, "basis": basis})
            return
        findings[key] = {
            "findingKey": key,
            "source": source,
            "recommendationId": rec_id or None,
            "title": meta.get("title"),
            "impact": meta.get("impact"),
            "control": meta.get("control"),
            "description": meta.get("description"),
            "potentialBenefits": meta.get("potentialBenefits"),
            "learnMore": meta.get("learnMore", []),
            "pgVerified": meta.get("pgVerified"),
            "resource": {
                "id": rid,
                "name": row.get("name"),
                "type": (row.get("type") or "").lower() or None,
                "resourceGroup": row.get("resourceGroup"),
                "subscriptionId": row.get("subscriptionId"),
                "location": row.get("location"),
            },
            "evidence": {"classification": cls, "reason": reason, "basis": basis, "details": params},
        }

    # APRL and WARA validation rows.
    for row in as_list(collector.get("impactedResources")):
        action = row.get("validationAction") or ""
        cls, reason = classify(action)
        rec_id = (row.get("recommendationId") or "").strip()
        rec = catalog.get(rec_id.lower(), {})
        if reason == "no-guidance-for-type":
            meta = {"title": f"No APRL/Advisor guidance for {row.get('type')}: review manually if applicable",
                    "impact": "Low", "control": "OtherBestPractices"}
        else:
            meta = {
                "title": rec.get("description") or f"APRL recommendation {rec_id}",
                "impact": rec.get("recommendationImpact"),
                "control": rec.get("recommendationControl"),
                "description": (rec.get("longDescription") or "").strip() or None,
                "potentialBenefits": rec.get("potentialBenefits"),
                "learnMore": links(rec),
                "pgVerified": rec.get("pgVerified"),
            }
        upsert("APRL", rec_id, row, cls, reason, action, meta)

    # Azure Advisor (HighAvailability + WARA "other" recommendations).
    for row in as_list(collector.get("advisory")):
        rec_id = (row.get("recommendationId") or "").strip()
        meta = {"title": row.get("description"), "impact": row.get("impact"), "control": row.get("category")}
        upsert("Advisor", rec_id, row, "OBSERVED", "advisor-reported", "Azure Advisor", meta)

    inventory = as_list(collector.get("resourceInventory"))
    in_scope_types = [
        {"type": r.get("Resource Type"), "count": r.get("Number Of Resources"), "guidance": r.get("Available in APRL/ADVISOR?")}
        for r in as_list(collector.get("resourceType"))
    ]
    ordered = sorted(findings.values(), key=lambda f: (f["resource"]["type"] or "", f["title"] or "", f["resource"]["name"] or ""))
    cls_counts = Counter(f["evidence"]["classification"] for f in ordered)

    script = collector.get("scriptDetails") or {}
    doc = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedBy": {"name": "wara-assessment/normalize_findings.py", "version": NORMALIZER_VERSION},
        "runId": run.get("runId"),
        "scope": run.get("scope") or {
            "subscriptionIds": script.get("SubscriptionIds"),
            "resourceGroups": script.get("ResourceGroups"),
            "tenantId": script.get("TenantId"),
        },
        "wara": {"version": script.get("Version"), "elapsed": script.get("ElapsedTime")},
        "coverage": {
            "collectionStatus": run.get("collector", {}).get("status", "UNKNOWN"),
            "collectionErrors": run.get("collector", {}).get("errors", []),
            "inventoryCount": len(inventory),
            "inventoryIds": sorted({(r.get("id") or "").lower() for r in inventory if r.get("id")}),
            "inScopeResourceTypes": in_scope_types,
            "typesWithoutGuidance": [t["type"] for t in in_scope_types if str(t.get("guidance")).lower() == "no"],
        },
        "context": {
            "outages": as_list(collector.get("outages")),
            "retirements": as_list(collector.get("retirements")),
            "serviceHealth": as_list(collector.get("serviceHealth")),
            "supportTickets": as_list(collector.get("supportTickets")),
            "notes": "Context sections are copied from the collector. null/empty means WARA returned nothing; "
                     "it is not proof of absence if the identity lacked permission.",
        },
        "counts": {"findings": len(ordered), **{k: v for k, v in sorted(cls_counts.items())}},
        "findings": ordered,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, default=str)
    print(json.dumps(doc["counts"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
