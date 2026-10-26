---
name: wara-assessment
description: |
  Runs Microsoft's Well-Architected Reliability Assessment (WARA collector + analyzer) for exactly one Azure scope (resource group or subscription) per run, records provenance, and produces a deterministic prioritized findings report with month-over-month deltas. Works in restricted-egress Azure SRE Agent sandboxes (no PowerShell Gallery / azure.github.io) and anywhere PowerShell 7 runs. Read-only against Azure.
tools:
  - RunInTerminal
  - ReadFile
  - CreateFile
  - SaveFileToBlob
  - SearchMemory
  - RunAzCliReadCommands
---

# WARA assessment (collect -> standard reports -> prioritized findings)

Use this skill when asked to run WARA / a Well-Architected Reliability Assessment, to refresh a monthly
reliability assessment, or to review/prioritize WARA results.

**Read-only.** Never create, change, or delete Azure resources while assessing. Report gaps; do not fix them.

## Files (relative to this skill's directory)

| Path | Purpose |
|---|---|
| `scripts/Invoke-WaraRun.ps1` | Single entry point. One run per scope. Writes the run folder below. |
| `scripts/build_recommendation_data.py` | Restricted mode: rebuilds WARA recommendation data from an APRL checkout. |
| `scripts/normalize_findings.py` | Collector JSON -> `derived/findings.json` (stable keys, OBSERVED/UNKNOWN evidence). |
| `scripts/prioritize.py` | Scores, bands (P1-P4), suppressions, delta vs previous run, `prioritized-report.md`. |
| `scripts/shims/Az.ResourceGraph/` | Restricted mode only: `Search-AzGraph` over the Resource Graph REST API. |
| `scripts/Get-EnvironmentEvidence.ps1` | Read-only: subscription offer (quotaId) and tags, resource group and resource tags -> `environment-evidence.json`. |
| `scripts/environment_classification.py` | Classifies PROD-PRIMARY / PROD-DR / UAT / TEST / DEV per resource; maps findings to a requirement level. |
| `scripts/generate_reports.py` | Reproduces `Start-WARAReport` outputs on Linux (PPTX from WARA's template, findings xlsx, CSV) plus a Word report; prioritized section first. |
| `config/dependencies.json` | Pinned WARA / APRL / Az.Accounts / ImportExcel versions and commits. |
| `config/prioritization.yaml` | Default scoring rules. Customers supply their own copy via `-PrioritizationFile`. |
| `config/environment-classification.yaml` | Default environment rules (tag keys, value patterns, non-production offers incl. `Internal_*` -> DEV, requirement matrix). |
| `config/scopes.example.json` | Example scopes file for `-ScopesFile`. |

## Output contract

```
<OutputRoot>/wara/<subscription-label>/<scope-folder>/<runId>/
    run.json        scope, exact WARA parameters, upstream commits, identity, deviations, errors, hashes
    standard/       WARA-File-*.json (collector)  Expert-Analysis-v1-*.xlsx (analyzer)
    derived/        findings.json  prioritized-findings.json/.csv  prioritized-report.md  delta.json
<OutputRoot>/wara/<subscription-label>/<scope-folder>/latest.json
```
`<scope-folder>` = resource group name, or `_subscription`. New `<runId>` values use
`yyyy-MM-ddTHHmmssfffZ-<random8>` (UTC); older minute-resolution IDs remain valid.
Serialize runs for the same scope; concurrent `latest.json` updates are not coordinated.

## Procedure

1. **Confirm scope.** Exactly one of: a resource group (`-ScopeType ResourceGroup -ResourceGroupName`) or a
   whole subscription (`-ScopeType Subscription`). WARA unions `-SubscriptionIds` and `-ResourceGroups`, so
   never ask the runner for both in one run. Recommended rollout: one resource group first, then the subscription.
2. **Check memory** (`SearchMemory "WARA assessment"`) for the customer's scopes file, prioritization file,
   managed identity client ID, and output repository. Do not guess these.
3. **Run** (Azure SRE Agent sandbox: restricted mode is the default):
   ```bash
   pwsh -NoProfile -File <skill>/scripts/Invoke-WaraRun.ps1 \
     -ScopeType ResourceGroup -SubscriptionId <sub> -ResourceGroupName <rg> -TenantId <tenant> \
     -UseManagedIdentity -ManagedIdentityClientId <client-id> \
     -OutputRoot <output-repo-or-dir> [-PrioritizationFile <customer.yaml>] [-AprlRef main]
   ```
   Or `-ScopesFile <scopes.json> [-Scope <name>,...]` for several scopes. Outside the sandbox
   (Cloud Shell, Automation, CI) add `-DependencyMode Gallery`.
   Allow up to ~10 minutes for the first run (dependency fetch); cached runs take about a minute per RG.
4. **Verify** `run.json`: `status` is `Succeeded` or `SucceededWithWarnings`; `scope.waraParameters`
   contains only the intended filter; read `collector.errors` (WARA's "No recommendation found for ..."
   lines are informational). If `derived.status` is `Failed`, report the error; do not hand-edit outputs.
5. **Review** `derived/prioritized-report.md` and `prioritized-findings.json`:
   - Lead with P1, then P2. Separate **Remediate** (OBSERVED) from **Validate** (UNKNOWN) actions.
   - For UNKNOWN items you may run read-only checks (`RunAzCliReadCommands`, Resource Graph) to propose a
     validation result, but label it **AI review (INFERRED)**. Never rewrite deterministic files; write
     your notes to `derived/review.md` and state which evidence you checked.
   - Call out NEW findings and anything RESOURCE_NOT_LISTED / NO_LONGER_DETECTED since the previous run.
     Neither proves deletion or remediation. NOT_REOBSERVED means incomplete collection: retain the
     prior finding and collect evidence before claiming resolution.
   - Duplicates between APRL and Advisor for the same resource are expected; group them, do not drop them.
6. **Reports (when asked for PowerPoint/Word, or when the schedule requests them).** Collect evidence, then generate:
   ```bash
   pwsh -NoProfile -File <skill>/scripts/Get-EnvironmentEvidence.ps1 -SubscriptionId <sub> [-ResourceGroupName <rg>] \
     -TenantId <tenant> -UseManagedIdentity -ManagedIdentityClientId <client-id> -OutFile <run>/reports/environment-evidence.json
   python3 <skill>/scripts/generate_reports.py --run-dir <run> --environment-evidence <run>/reports/environment-evidence.json \
     --customer "<customer>" --workload "<workload>" [--classification-config <customer.yaml>]
   ```
   Writes `<run>/reports/` (PPTX, DOCX, Assessment-Findings xlsx, CSV, `environment-classification.json`,
   `report-manifest.json` with input/output hashes). Needs python-pptx, python-docx, openpyxl, matplotlib and the
   WARA templates cached by a previous restricted-mode run. The environment overlay is advisory: it never changes
   bands. State the classification basis and confidence; Low confidence (naming heuristics only) must be confirmed
   with the owner before recommending risk acceptance. Report files are not part of the deterministic hashes in `run.json`.
   Keep the generated `wara-report-NOTICE.txt` with redistributed reports. Retain environment evidence
   (only configured classification tag keys) in the approved private output location. Verify every
   report-manifest input/output hash and its run ID before publishing. Generation failure must be
   reported separately from successful collection; never claim reports exist without verifying them.
   Accepted risks remain accepted and UNKNOWN findings remain validation tasks. An offer-based DEV
   classification is advisory, not permission to suppress findings. Existing report manifests are
   protected against overwriting; use a separate output directory for intentional replay.
7. **Publish.** If an output repository is configured, commit the run folder and `latest.json` with a
   message `wara: <scope-folder> <runId> (<status>)` and push. Otherwise `SaveFileToBlob` the report,
   workbook and `prioritized-findings.csv` and share the links. Commit `reports/` only when asked.
8. **Summarize** in chat: scope, run status, band counts, top P1 items, validation backlog size, deltas,
   and the deviations listed in `run.json.upstream.deviations`.

## Restricted mode: what differs from a stock WARA run (always disclose)

- Az.Accounts from api.nuget.org; ImportExcel and WARA from pinned GitHub commits (no PowerShell Gallery).
- `Search-AzGraph` provided by the bundled shim (same Resource Graph API, `$skipToken` paging).
- Recommendation data rebuilt from APRL (pinned commit or `-AprlRef main`) instead of
  `azure.github.io/WARA-Build`; in-scope types from WARA's bundled snapshot plus APRL types.
  The WARA-published file may differ slightly from APRL at the same point in time.
- Two URLs are redirected to those local files for the duration of the run (`Invoke-RestMethod` wrapper);
  WARA's Gallery version check is skipped. WARA code itself is not modified.
- `Start-WARAReport` (PowerPoint/Word) is never run: it needs Windows + Office. `generate_reports.py` reproduces
  its PowerPoint, findings workbook and CSV from WARA's own templates (native charts and static pivot summaries
  instead of Excel pivots; collector outages used when the analyzer sheet is empty; placeholder sample text replaced
  by "none reported"). WARA 1.0.6 has no Word output; the DOCX is an addition.

## Troubleshooting

| Symptom | Action |
|---|---|
| `git ... fetch` fails | github.com egress blocked; restricted mode needs github.com and api.nuget.org. |
| `Search-AzGraph (wara-assessment shim) failed: HTTP 403` | Identity lacks Reader on the scope. Grant Reader (read-only) and rerun. |
| Collector `Cannot bind argument to parameter 'TypesNotInAPRLOrAdvisor'` | The in-scope types CSV has no `InAprlAndOrAdvisor=No` rows; the WARA snapshot was not found. Check `wara.resourceTypesSnapshotPath`. |
| Findings include other resource groups | The run used a subscription scope. Check `run.json.scope.waraParameters`. |
| `@($result)` "Argument types do not match" | An older shim returned a PSObject-wrapped list; use the bundled shim. |
