# WARA assessment guide

How to interpret and prioritize Well-Architected Reliability Assessment (WARA) results produced by the
wara-assessment plugin. Search key: "WARA assessment".

## Scope rules

- One WARA run per scope. Resource-group scope = `-ResourceGroups` only. Subscription scope =
  `-SubscriptionIds` only. WARA unions the two filters; passing both assesses the whole subscription.
- Typical rollout: one representative resource group first (fast, reviewable), then the subscription.
- Output folder: `wara/<subscription-label>/<rg-name or _subscription>/<runId>/`.
  New run IDs use UTC `yyyy-MM-ddTHHmmssfffZ-<random8>`; older IDs remain readable.

## Evidence classes

| Class | Source in WARA | Meaning | Next action |
|---|---|---|---|
| OBSERVED | `validationAction = "APRL - Queries"` | An APRL Resource Graph query matched the resource for this run | Remediate or formally accept the risk |
| OBSERVED | collector `advisory` | Azure Advisor reported it | Remediate or formally accept the risk |
| UNKNOWN | "Recommendation cannot be validated with ARGs" | No automatic check exists; the resource type is in scope | Validate manually |
| UNKNOWN | "Query under development" | APRL has no finished query yet | Validate manually |
| UNKNOWN | "Resource Type is not available in either APRL or Advisor" | No guidance exists for the type | Review applicability |

UNKNOWN items are not defects. Typically 60-70% of WARA rows are UNKNOWN; report them as a
validation backlog, separate from the remediation list.

## Priority vs severity

- Severity (`impact`: High/Medium/Low) comes from APRL/Advisor and is never changed.
- Priority (P1-P4) is the recommended order of action for this environment:
  `score = impact x evidence x control x criticality` (see `config/prioritization.yaml`).
- Default anchors: High-impact high-availability finding, OBSERVED, standard criticality = 3.6 (P1);
  the same finding UNKNOWN = 2.7 (P2, validate first); Medium OBSERVED high availability = 2.4 (P2).

## Reading deltas

| Lifecycle | Meaning |
|---|---|
| BASELINE | First run for this scope |
| NEW | Not present in the previous run of this scope |
| PERSISTING | Present before; `firstSeenRunId` shows how long it has been open |
| RESOURCE_NOT_LISTED | Resource absent from this collector's inventory; not proof of resource deletion |
| NO_LONGER_DETECTED | Was OBSERVED; not returned this time; confirm query coverage and remediation independently |
| NO_LONGER_LISTED | Was UNKNOWN; WARA no longer lists it (APRL or scope change: do not claim it is fixed) |
| NOT_REOBSERVED | Missing after collection errors or unknown coverage; retained for later comparisons, not resolved |

A change in APRL commit (`run.json.upstream.aprlCommit`) between runs can add or remove findings without
any change to the environment. Check it before attributing a delta to an environment change.

## Known noise

- APRL and Advisor may both flag the same concern for one resource (for example zone redundancy). Group them.
- Collector messages "No recommendation found for <type> with resource id ..." are informational.
- Context sections (outages, retirements, service health, support tickets) are pass-through from WARA.

## Accepted risks

Record accepted risks as `suppressions` in the customer's prioritization file, with `reason`, `owner`
and `expires`. Suppressed findings are shown in band `Accepted` and return automatically after expiry.

## Environment context in reports

`generate_reports.py` labels each finding Required / Recommended / Optional / NotRequired for the resource's
classified environment (PROD-PRIMARY, PROD-DR, UAT, TEST, DEV). Bands never change. Classification basis and
confidence: explicit tags (High), non-production subscription offer such as MSDN / Visual Studio Dev/Test or
`Internal_*` (Medium), naming tags such as `azd-env-name` (Low), none (UNKNOWN, assessed as Production).
NotRequired is a candidate for an accepted-risk suppression only after the owner confirms the environment;
recommend explicit `Environment` and `Criticality` tags. A Production tag on a non-production offer is a conflict.
