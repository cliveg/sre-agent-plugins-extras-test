#!/usr/bin/env python3
"""Build WARA recommendation inputs from a local Azure Proactive Resiliency Library (APRL) checkout.

Restricted-egress replacement for https://azure.github.io/WARA-Build/objects/*:

  recommendations.json      one object per APRL recommendation (YAML fields) plus `query`
                            = contents of kql/<aprlGuid>.kql (empty when no KQL exists)
  WARAinScopeResTypes.csv   WARA's in-scope resource type list. Base = WARA's bundled snapshot
                            (src/tests/data/wara/test_recommendationresourcetypesdata.csv); any APRL
                            resource type missing from the snapshot is appended as in scope.

Prints a JSON summary (counts + SHA-256 of both outputs) on stdout for run.json provenance.
Requires: Python 3.8+, PyYAML.
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import glob
import hashlib
import json
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: python3 -m pip install pyyaml")

FIELDS = ["WARAinScope", "ResourceType", "FriendlyName", "InAprlAndOrAdvisor"]
SOURCES = ("azure-resources", "azure-specialized-workloads")


def _json_default(value):
    if isinstance(value, (_dt.date, _dt.datetime)):
        return value.isoformat()
    raise TypeError(type(value))


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_recommendations(aprl_root: str) -> tuple[list[dict], int]:
    recs: list[dict] = []
    missing_kql = 0
    for source in SOURCES:
        pattern = os.path.join(aprl_root, source, "**", "recommendations.yaml")
        for yml in sorted(glob.glob(pattern, recursive=True)):
            with open(yml, encoding="utf-8") as f:
                items = yaml.safe_load(f) or []
            kql_dir = os.path.join(os.path.dirname(yml), "kql")
            for rec in items:
                if not isinstance(rec, dict) or not rec.get("aprlGuid"):
                    continue
                kql = os.path.join(kql_dir, f"{rec['aprlGuid']}.kql")
                if os.path.isfile(kql):
                    with open(kql, encoding="utf-8") as k:
                        rec["query"] = k.read()
                else:
                    rec["query"] = ""
                    missing_kql += 1
                rec.setdefault("tags", [])
                rec["aprlSource"] = os.path.relpath(yml, aprl_root).replace(os.sep, "/")
                recs.append(rec)
    return recs, missing_kql


def build_types(recs: list[dict], snapshot: str | None) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    if snapshot and os.path.isfile(snapshot):
        with open(snapshot, encoding="utf-8-sig") as f:
            rows = [{k: (r.get(k) or "") for k in FIELDS} for r in csv.DictReader(f)]
    known = {r["ResourceType"].lower() for r in rows}
    added: list[str] = []
    for rtype in sorted({str(r.get("recommendationResourceType") or "").strip() for r in recs} - {""}, key=str.lower):
        if rtype.lower() not in known:
            rows.append({"WARAinScope": "yes", "ResourceType": rtype, "FriendlyName": "", "InAprlAndOrAdvisor": "Yes"})
            known.add(rtype.lower())
            added.append(rtype)
    return rows, added


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--aprl", required=True, help="Path to an APRL v2 checkout")
    ap.add_argument("--types-snapshot", help="WARA bundled in-scope types CSV")
    ap.add_argument("--out", required=True, help="Output directory")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    recs, missing_kql = load_recommendations(args.aprl)
    if not recs:
        sys.exit(f"No APRL recommendations found under {args.aprl}")

    rec_path = os.path.join(args.out, "recommendations.json")
    with open(rec_path, "w", encoding="utf-8") as f:
        json.dump(recs, f, default=_json_default)

    rows, added = build_types(recs, args.types_snapshot)
    types_path = os.path.join(args.out, "WARAinScopeResTypes.csv")
    with open(types_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    in_scope = [r for r in rows if r["WARAinScope"].lower() == "yes"]
    print(json.dumps({
        "recommendations": len(recs),
        "recommendationsWithoutKql": missing_kql,
        "resourceTypeRows": len(rows),
        "resourceTypesInScope": len(in_scope),
        "resourceTypesInScopeWithoutGuidance": sum(1 for r in in_scope if r["InAprlAndOrAdvisor"].lower() == "no"),
        "resourceTypesAddedFromAprl": added,
        "typesSnapshotUsed": bool(args.types_snapshot and os.path.isfile(args.types_snapshot)),
        "recommendationsSha256": _sha256(rec_path),
        "resourceTypesSha256": _sha256(types_path),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
