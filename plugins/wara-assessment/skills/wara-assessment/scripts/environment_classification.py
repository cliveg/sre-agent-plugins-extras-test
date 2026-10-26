#!/usr/bin/env python3
"""Environment / criticality classification for WARA reporting (advisory overlay).

Classifies each resource (and the resource group scope) as PROD-PRIMARY, PROD-DR, UAT, TEST, DEV or
UNKNOWN from tags and the subscription offer, then maps each prioritized finding to a requirement level
(Required / Recommended / Optional / NotRequired) for that environment. It never changes the
deterministic P1-P4 band.

Precedence (first hit wins):
  1. explicit resource tag   2. explicit resource-group tag   3. explicit subscription tag
  4. non-production subscription offer (quotaId, e.g. MSDN / Visual Studio Dev/Test, Internal_*)
  5. heuristic resource tag  6. heuristic resource-group tag  7. heuristic subscription tag
  8. UNKNOWN (assessed as config.unknownAssessedAs, normally PROD-PRIMARY)

Dependencies: Python 3.9+ and PyYAML only.
"""
import argparse
import json
import re
import sys

import yaml

LEVELS = ["Required", "Recommended", "Optional", "NotRequired"]

def resource_key(resource):
    rid = resource.get("id")
    if rid:
        return rid.lower()
    return "|".join(str(resource.get(k) or "").lower() for k in ("resourceGroup", "type", "name"))


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    for key in ("tiers", "unknownAssessedAs", "explicitTagKeys", "heuristicTagKeys", "valuePatterns",
                "nonProductionOffers", "requirements", "actions", "profiles"):
        if key not in cfg:
            raise ValueError(f"environment classification config is missing '{key}'")
    for tier, req in cfg["requirements"].items():
        if tier not in cfg["tiers"]:
            raise ValueError(f"requirements references unknown tier {tier}")
        bad = [v for v in req.values() if v not in LEVELS]
        if bad or "default" not in req:
            raise ValueError(f"requirements[{tier}] needs a 'default' and levels from {LEVELS}")
    for o in cfg["nonProductionOffers"]:
        if o.get("tier") not in cfg["tiers"]:
            raise ValueError(f"nonProductionOffers entry {o} has an unknown tier")
    return cfg


def classify(cfg, evidence):
    """Return the classification document for an environment-evidence document."""
    pats = [(p["tier"], re.compile(p["regex"])) for p in cfg["valuePatterns"]]
    explicit = {k.lower() for k in cfg["explicitTagKeys"]}
    heuristic = {k.lower() for k in cfg["heuristicTagKeys"]}
    notes = []

    def match(value):
        v = str(value or "").lower()
        return next((t for t, rx in pats if rx.search(v)), None)

    def tag_hit(tags, keys, level, is_explicit):
        hits = []
        for k, v in sorted((tags or {}).items()):
            if k.lower() in keys:
                tier = match(v)
                if tier:
                    hits.append((tier, f"{level} tag {k}={v}"))
                    continue
                if is_explicit:
                    note = f"{level} tag {k}={v} is not a recognised environment value (ignored)"
                    if note not in notes:
                        notes.append(note)
        if len({t for t, _ in hits}) > 1:
            note = f"Conflicting {level} environment tags; assessed conservatively as PROD-PRIMARY"
            if note not in notes:
                notes.append(note)
            return "PROD-PRIMARY", note
        return hits[0] if hits else None

    sub = evidence.get("subscription") or {}
    offer = sub.get("quotaId") or ""
    offer_rule = next((o for o in cfg["nonProductionOffers"] if re.search(o["pattern"], offer, re.I)), None)
    if offer_rule:
        offer_desc = f"Subscription offer {offer}: {offer_rule.get('reason', 'non-production offer')} -> {offer_rule['tier']}"
    else:
        offer_desc = f"Subscription offer {offer or 'unknown'} is not configured as non-production (neutral)"
    rgs = {g["name"].lower(): g for g in evidence.get("resourceGroups") or []}

    def resolve(res_tags, rg_tags, res_label):
        steps = (
            (lambda: tag_hit(res_tags, explicit, res_label, True), "High"),
            (lambda: tag_hit(rg_tags, explicit, "resource group", True), "High"),
            (lambda: tag_hit(sub.get("tags"), explicit, "subscription", True), "High"),
            (lambda: (offer_rule["tier"], offer_desc) if offer_rule else None, "Medium"),
            (lambda: tag_hit(res_tags, heuristic, res_label, False), "Low"),
            (lambda: tag_hit(rg_tags, heuristic, "resource group", False), "Low"),
            (lambda: tag_hit(sub.get("tags"), heuristic, "subscription", False), "Low"),
        )
        for fn, confidence in steps:
            hit = fn()
            if hit:
                tier, basis = hit
                conflict = None
                if offer_rule and tier.startswith("PROD"):
                    conflict = (f"Production classification on subscription offer {offer}, which is configured as "
                                f"{offer_rule['tier']}; confirm the environment and licensing")
                return dict(tier=tier, basis=basis, confidence=confidence, conflict=conflict)
        return dict(tier="UNKNOWN", basis="no environment signal found", confidence="None", conflict=None)

    resource_groups = {name: resolve({}, g.get("tags"), "resource group") for name, g in rgs.items()}
    resources = {}
    for r in evidence.get("resources") or []:
        g = rgs.get((r.get("resourceGroup") or "").lower(), {})
        resources[resource_key(r)] = dict(id=r.get("id"), name=r["name"], type=r.get("type"), resourceGroup=r.get("resourceGroup"),
                                         **resolve(r.get("tags"), g.get("tags"), "resource"))
    return dict(subscription=dict(id=sub.get("id"), name=sub.get("name"), quotaId=offer,
                                  nonProductionOffer=bool(offer_rule), offerTier=offer_rule["tier"] if offer_rule else None,
                                  offerInterpretation=offer_desc, tags={k: v for k, v in (sub.get("tags") or {}).items()
                                                                     if k.lower() in explicit | heuristic},
                                  **resolve({}, {}, "subscription")),
                resourceGroups=resource_groups, resources=resources, notes=notes,
                evidenceCollectedUtc=evidence.get("collectedUtc"), evidenceCollectedBy=evidence.get("collectedBy"))


def assessed_tier(cfg, tier):
    return cfg["unknownAssessedAs"] if tier == "UNKNOWN" else tier


def overlay(cfg, cls, finding, scope_rg):
    """Requirement level of one prioritized finding for its classified environment."""
    res = finding.get("resource") or {}
    c = (cls["resources"].get(resource_key(res))
         or cls["resources"].get(resource_key({k: v for k, v in res.items() if k != "id"}))
         or cls["resourceGroups"].get((res.get("resourceGroup") or scope_rg or "").lower())
         or dict(tier="UNKNOWN", basis="not in evidence", confidence="None"))
    tier = assessed_tier(cfg, c["tier"])
    req = cfg["requirements"][tier]
    level = req.get(finding.get("control") or "", req["default"])
    action = cfg["actions"][level]
    if (finding.get("priority") or {}).get("band") == "Accepted":
        action = "Accepted risk - review the recorded acceptance and expiry; do not override it"
    elif (finding.get("evidence") or {}).get("classification") == "UNKNOWN":
        action = "Validate evidence and applicability first; not a confirmed defect or automatic risk acceptance"
    return dict(tier=c["tier"], assessedAs=tier, basis=c["basis"], confidence=c["confidence"],
                conflict=c.get("conflict"), requirement=level, action=action)


def main():
    ap = argparse.ArgumentParser(description="Classify environments from environment-evidence.json")
    ap.add_argument("--config", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    cfg = load_config(a.config)
    with open(a.evidence, encoding="utf-8") as fh:
        doc = classify(cfg, json.load(fh))
    text = json.dumps(doc, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    main()
