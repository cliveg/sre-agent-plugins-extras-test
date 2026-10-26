# WARA Reliability Assessment

Runs Microsoft's [Well-Architected Reliability Assessment](https://github.com/Azure/Well-Architected-Reliability-Assessment)
(WARA) collector and analyzer **one scope at a time**, keeps every run self-describing and comparable,
and turns the results into a **prioritized findings report** with month-over-month deltas.

It is an example of composing an existing Microsoft assessment tool into an Azure SRE Agent capability:
the standard WARA outputs are preserved unchanged, and our own deterministic layer is added on top.

| | |
|---|---|
| Runs in | Azure SRE Agent sandbox (default, restricted egress), Cloud Shell, workstation, Azure Automation, CI |
| Azure access | Read-only. Reader on the assessed scope is sufficient. |
| Status | 0.1.1; original 0.1.0 Azure validation reported by the generating SRE Agent on 2026-10-09 (16-resource RG and 320-resource subscription). Local hardening tests are separate evidence. |

## Three layers

| Layer | Produces | Owner |
|---|---|---|
| 1. Collect + analyze | `standard/WARA-File-*.json`, `standard/Expert-Analysis-v1-*.xlsx` | Microsoft WARA, unmodified, pinned |
| 2. Normalize | `derived/findings.json`: one finding per recommendation x resource, stable `findingKey`, evidence `OBSERVED` / `UNKNOWN` | this plugin |
| 3. Prioritize | `derived/prioritized-findings.json/.csv`, `prioritized-report.md`, `delta.json` | this plugin + customer config |

Then the SRE Agent (skill + `wara-reviewer` subagent) reviews the deterministic output, proposes validation
results for `UNKNOWN` items as clearly labelled AI review, and publishes.

## One scope per run

WARA **unions** `-SubscriptionIds` and `-ResourceGroups`: passing both assesses the whole subscription.
`Invoke-WaraRun.ps1` therefore passes only `-ResourceGroups` for a resource-group scope and only
`-SubscriptionIds` for a subscription scope, and records the exact parameters in `run.json`.

## Output layout (scope first, then run)

```
wara/
  <subscription-name>_<subscription-id-first-8>/
    _subscription/                     subscription scope
      2026-11-01T0600Z/ ...
      latest.json
    rg-app-prod/                       resource-group scope
      2026-10-09T1512Z/
        run.json                       scope, WARA parameters, upstream commits, identity, deviations, errors, hashes
        standard/                      WARA-File-*.json, Expert-Analysis-v1-*.xlsx
        derived/                       findings.json, prioritized-findings.json/.csv, prioritized-report.md, delta.json
      latest.json                      pointer used for the next run's delta
```

Scope-first keeps each scope's history together, so "what changed since last month" is a comparison of
sibling folders. New run IDs are UTC (`yyyy-MM-ddTHHmmssfffZ-<random8>`), safe on Windows/OneDrive/SharePoint,
and each run reserves a new directory without overwriting prior evidence. Older minute-resolution run
IDs remain valid comparison inputs. Do not run the same scope concurrently: `latest.json` publication
is not concurrency coordinated.
Treat the output as sensitive (resource IDs and reliability gaps): store it in a private repository or
access-controlled storage.

## Dependency modes

| Mode | Use when | Sources |
|---|---|---|
| `Restricted` (default) | Azure SRE Agent, or any environment where you do not want to open the PowerShell Gallery or `azure.github.io` | `github.com` (git) and `api.nuget.org` only |
| `Gallery` | Cloud Shell, workstations, Automation, CI with normal internet egress | PowerShell Gallery (`Install-Module`, pinned versions) |

Restricted mode substitutes, all recorded in `run.json.upstream.deviations`:

- **Az.Accounts** from the pinned nupkg on api.nuget.org.
- **Az.ResourceGraph** replaced by the bundled `Search-AzGraph` shim (Resource Graph REST API
  2022-10-01, `$skipToken` paging; validated 320/320 resources against Resource Graph's own count).
- **WARA** and **ImportExcel** from pinned GitHub commits.
- **Recommendation data** rebuilt from the Azure Proactive Resiliency Library (APRL) by
  `build_recommendation_data.py` instead of `azure.github.io/WARA-Build`. The in-scope resource-type list
  is WARA's bundled snapshot plus any newer APRL types.
- WARA's two data URLs are redirected to those local files for the duration of the run, and its
  Gallery version check is skipped. WARA's code is not modified.

Pinned versions live in [`skills/wara-assessment/config/dependencies.json`](skills/wara-assessment/config/dependencies.json).

## Usage

```powershell
# Restricted mode (SRE Agent sandbox) with a managed identity
./skills/wara-assessment/scripts/Invoke-WaraRun.ps1 `
  -ScopeType ResourceGroup -SubscriptionId <sub> -ResourceGroupName <rg> -TenantId <tenant> `
  -UseManagedIdentity -ManagedIdentityClientId <client-id> -OutputRoot <dir>

# Subscription scope, standard Gallery dependencies, already signed in with Connect-AzAccount
./skills/wara-assessment/scripts/Invoke-WaraRun.ps1 -ScopeType Subscription -SubscriptionId <sub> `
  -DependencyMode Gallery -OutputRoot <dir>

# Several scopes from a customer-owned file; newest APRL recommendations
./skills/wara-assessment/scripts/Invoke-WaraRun.ps1 -ScopesFile ./scopes.json -AprlRef main -OutputRoot <dir>
```

| Parameter | Default | Notes |
|---|---|---|
| `-ScopeType` / `-SubscriptionId` / `-ResourceGroupName` | | One scope. Or `-ScopesFile` (+ optional `-Scope` names). |
| `-TenantId` | current Az context | Required if not signed in. |
| `-OutputRoot` | `./wara-output` | Point at a cloned private output repository to keep history. |
| `-DependencyMode` | `Restricted` | `Gallery` outside restricted sandboxes. |
| `-RecommendationSource` | `Aprl` (Restricted) / `Published` (Gallery) | |
| `-AprlRef` | pinned commit | `main` for the latest APRL content; the resolved commit is recorded. |
| `-PrioritizationFile` | `config/prioritization.yaml` | Customer weights, criticality rules, accepted-risk suppressions. |
| `-UseManagedIdentity` / `-ManagedIdentityClientId` | | Otherwise uses the existing Az context. |
| `-CacheRoot` | `$WARA_CACHE` or `~/.cache/wara-assessment` | Pinned sources and built data are cached per commit. |
| `-SkipAnalyzer` / `-SkipDerived` | | |

Requirements: PowerShell 7.2+, git, Python 3.8+ with PyYAML (restricted mode and derived layer).

## Prioritization

`score = impact x evidence x control x criticality`, bands P1-P4 (see
[`config/prioritization.yaml`](skills/wara-assessment/config/prioritization.yaml)).

- **Impact** is APRL/Advisor severity and is never changed.
- **Evidence**: `OBSERVED` (APRL query matched or Advisor reported) vs `UNKNOWN` (WARA could not evaluate:
  "cannot be validated with ARG", "query under development", no guidance for the type). The next action for
  UNKNOWN is **validate**, not remediate.
- **Criticality** rules (regex on resource group, name, type, ID) let a customer weight production above sandboxes.
- **Suppressions** record accepted risks with reason, owner and expiry; expired suppressions are ignored.
- **Lifecycle** vs the previous run of the same scope: `NEW`, `PERSISTING` (with first-seen run),
  and `RESOURCE_NOT_LISTED` / `NO_LONGER_DETECTED` / `NO_LONGER_LISTED` for anything that disappeared
  from a collector run with no reported errors. These are not proof of deletion or remediation.
  With errors or unknown collection status, missing findings are `NOT_REOBSERVED` and retained for
  later comparisons, not counted as resolved. Missing previous artifacts or mismatched scopes fail
  comparison explicitly rather than silently resetting the baseline.

## Monthly automation

- **In Azure SRE Agent:** deploy the `wara-reviewer` subagent with `tools/deploy-extras.sh`, copy
  [`extras/scheduled-task-templates/wara-monthly.yaml`](extras/scheduled-task-templates/wara-monthly.yaml)
  into `extras/scheduled-tasks/` in your deployment copy, fill the placeholders, and deploy. The agent
  needs `RunInTerminal` allowed and a connected private output repository.
- **Elsewhere:** schedule `Invoke-WaraRun.ps1 -DependencyMode Gallery -ScopesFile ...` in Azure Automation
  (PowerShell 7.4 runbook, managed identity with Reader) or a CI scheduler, then commit `OutputRoot`.

## Reports and environment context

`Start-WARAReport` needs Windows with PowerPoint and Excel. `generate_reports.py` reproduces its outputs on
Linux from WARA's own templates and puts the prioritized findings first:

- **Executive Summary PPTX**: title, then a prioritized section (scope and environment context, band summary
  with environment requirement levels, P1/P2 tables with environment-adjusted actions, validation backlog and
  changes), then WARA's slides filled as `Start-WARAReport` fills them (workload summary, dashboard, charts,
  High/Medium/Low tables, outages, support requests, retirements).
- **Word report**: Part 1 prioritized findings and environment context; Part 2 the WARA report structure;
  appendices (impacted resources, inventory, method/provenance/deviations). WARA 1.0.6 has no Word output.
- **Assessment-Findings xlsx and CSV** as `Start-WARAReport` writes them (static pivot summaries).
- `environment-classification.json` and `report-manifest.json` (sha256 of inputs, templates and outputs).

Environment classification ([`config/environment-classification.yaml`](skills/wara-assessment/config/environment-classification.yaml))
uses, in order: explicit `Environment`/`Criticality`-style tags on the resource, resource group, then
subscription; a non-production subscription offer (MSDN / Visual Studio Dev/Test, `Internal_*` -> DEV);
naming heuristics such as `azd-env-name`; otherwise UNKNOWN, assessed as Production. Each tier maps WARA
controls to Required / Recommended / Optional / NotRequired. The overlay is advisory and never changes bands.

```bash
pwsh -File ./skills/wara-assessment/scripts/Get-EnvironmentEvidence.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> \
  -UseManagedIdentity -ManagedIdentityClientId <client-id> -OutFile <run>/reports/environment-evidence.json
python3 ./skills/wara-assessment/scripts/generate_reports.py --run-dir <run> \
  --environment-evidence <run>/reports/environment-evidence.json --customer "<customer>" --workload "<workload>"
```

Requires `python-pptx`, `python-docx`, `openpyxl`, `matplotlib`, `PyYAML`, and a WARA source cache from a
restricted-mode run (or `--ppt-template` / `--findings-template`).
Install the optional reporting dependencies using
`python -m pip install -r plugins/wara-assessment/requirements-reporting.txt`.

Reporting verifies recorded source hashes and run identity, uses the exact pinned template cache,
and rejects environment evidence from a different scope. It preserves accepted-risk findings and
UNKNOWN validation actions. Resource classification uses ARM IDs (a composite identity for legacy
evidence), not resource names alone. Conflicting explicit tags are conservatively assessed as
Production and reported; classification is not an automatic exemption or risk acceptance.

The evidence collector retains only tag keys configured for classification, not arbitrary tags.
Reports and retained environment evidence can still contain sensitive identifiers or tag values:
publish only to the approved private output repository. Preserve `wara-report-NOTICE.txt` with
the generated report bundle. Existing report manifests are never overwritten; use a new output
directory for a deliberate replay. Files have structural validation, not Office-rendered or
pixel-identical fidelity certification.

## Limitations

- `Start-WARAReport` itself is not run (Windows + Office only); see *Reports and environment context* for the
  reproduction and its differences (native charts instead of pasted Excel pivot charts, static pivot summaries,
  collector outages when the analyzer sheet is empty, case-insensitive grouping).
- Environment classification from naming heuristics is Low confidence; confirm before accepting risk.
- `Internal_* -> DEV` is an owner-selected default convention, not proof of non-production
  workload intent; explicit Production tags override it and expose the offer conflict.
- Restricted mode recommendation data comes from APRL, not the WARA-Build published file; they can differ.
- Context sections (outages, retirements, service health, support tickets) are passed through from WARA;
  empty means WARA returned nothing, not proof of absence if the identity lacked permission.
- APRL and Advisor can report the same concern for one resource; both are kept and grouped in the report.
- Findings are only as current as the pinned APRL commit unless `-AprlRef main` is used.
- WARA exposes collector-level errors, not a complete per-query coverage ledger. Even a `Completed`
  collector status is not authoritative evidence that every query succeeded. Validate apparent
  disappearance before closing findings.

## Upstream maintenance risk

At the time of writing, WARA's last commit was **2025-06-12 (v1.0.6)**, while APRL (the recommendation
content and queries) was updated **2026-10-05**. This plugin reduces exposure to an unmaintained WARA by
building recommendation data directly from APRL and keeping our derived layer independent of WARA's Excel
format: `normalize_findings.py` reads only the collector JSON. If WARA stops working, the collector
step is the only part to replace (for example, running APRL KQL directly), and the derived contract is unchanged.

## Credits

Composes, without modifying, Microsoft's
[Well-Architected Reliability Assessment](https://github.com/Azure/Well-Architected-Reliability-Assessment)
and [Azure Proactive Resiliency Library v2](https://github.com/Azure/Azure-Proactive-Resiliency-Library-v2)
(both MIT). See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Change log

- **0.2.0** (2026-10-09): `generate_reports.py` reproduces `Start-WARAReport` (PPTX from WARA's template,
  Assessment-Findings xlsx, CSV) on Linux and adds a Word report, with prioritized findings first;
  `Get-EnvironmentEvidence.ps1` and `environment_classification.py` add an advisory PROD/DR/UAT/TEST/DEV
  overlay from tags and subscription offer (`Internal_*` and Dev/Test offers -> DEV); classification tests.
- **0.1.1** (2026-10-09): CI test step; collision-resistant run directories; durable collector failure
  records; explicit missing-input/scope comparison errors; conservative missing-finding lifecycle
  with carry-forward after incomplete collection; Gallery initialization and exact-version fixes.
- **0.1.0** (2026-10-09): initial runner, restricted/gallery modes, Search-AzGraph shim, APRL data builder,
  normalize/prioritize layer, subagent, monthly task template.
