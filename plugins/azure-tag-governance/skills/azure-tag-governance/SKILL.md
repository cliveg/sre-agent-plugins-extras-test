---
name: azure-tag-governance
description: |
  Runs a read-only Azure tag and basic resource-naming governance assessment for an explicit scope. Discovers candidate rules from Resource Graph evidence, preserves Azure Policy as separate declared intent, evaluates a frozen profile deterministically, and publishes an immutable evidence-backed run bundle.
tools:
  - RunInTerminal
  - ReadFile
  - CreateFile
  - SaveFileToBlob
  - SearchMemory
  - RunAzCliReadCommands
  - QueryLogAnalyticsByWorkspaceId
---

# Azure Tag Governance

Use this skill for read-only Azure tag-governance baselines, recurring tag and
basic naming assessments, governance-profile review, and comparison with a prior
compatible run.

Never create, update, rename, remediate, or delete Azure resources. Never deploy
or change Azure Policy. Never request Tag Contributor or Contributor.

## Required configuration

Use `SearchMemory "Azure Tag Governance"` for:

- explicit assessment scope;
- managed identity client ID when applicable;
- approved private output repository, branch, customer label, and root;
- whether the supplemental Log Analytics `arg()` path is enabled.

Do not infer a Git destination from tenant names or conversation text. After a
successful publication, verify the latest Git run and treat its profile as
authoritative. If Agent memory disagrees, stop and report the divergence.

## Procedure

1. **Confirm one explicit scope.** Management group, subscription list,
   subscription, or resource group are supported. Do not silently expand it.
2. **Load the prior verified run.** Verify `run.json` hashes and the Git commit.
   A missing prior run means this is a candidate-only baseline.
3. **Collect primary Resource Graph evidence.** Query `Resources` with bounded
   pages of at most 1,000 rows and continue with the returned skip token. Retain
   only `id`, `name`, `type`, `subscriptionId`, `resourceGroup`, `location`,
   `tags`, and collection metadata. Checkpoint pages. Retry only transient
   failures. Record permission denials and failed pages.
4. **Collect Azure Policy evidence separately.** Read relevant definitions,
   initiatives, assignments, exemptions, and compliance state. Label it
   `DECLARED`; do not copy it into the authoritative profile automatically.
5. **Optional supplemental query.** Only when enabled, use the SRE
   Agent-connected Log Analytics workspace with
   `QueryLogAnalyticsByWorkspaceId` and a validated
   `arg("").Resources` query. Do not use it as complete inventory: the preview
   path returns only the first 1,000 ARG records, has no documented paging, and
   may hide ARG errors. Avoid joins for inventory acquisition. Preserve this
   source separately and reconcile only by normalized Azure resource ID.
6. **Prepare bounded inputs.** Store collection coverage, times, query identity,
   failures, and source limitations. Do not treat empty or inaccessible results
   as absence or compliance.
7. **Run deterministic processing.**
   ```text
   python3 scripts/tag_governance.py build \
     --resources <resources.json> \
     --policy-evidence <policy.json> \
     --output-root <connected-output-root> \
     --subscription-label <stable-label> \
     --scope-folder <stable-scope-folder> \
     --scope-id <exact-arm-scope> \
     --plugin-build 0.1.0 \
     [--previous-run <verified-prior-run>] \
     [--ai-decisions <validated-decisions.json>]
   ```
8. **Verify the run.**
   ```text
   python3 scripts/tag_governance.py verify --run-dir <run-directory>
   ```
   On the first run, confirm there are candidates but no violations based only
   on inferred rules. On later runs, promotion is permitted only when the prior
   candidate is present, the run is comparable, and the structured AI decision
   is eligible, unexpired, evidence-backed, and non-conflicting.
9. **Review outputs.** Lead with coverage and limitations. Keep compliance
   status, confidence, severity, and priority separate. Naming outliers do not
   prove semantic error. Expired or inaccessible evidence produces gaps, not
   violations.
10. **Publish directly to the approved private repository.** Use
    `scripts/publish_run.py` with the previously read remote head. It validates
    the allowlisted GitHub remote, artifact hashes, immutable destination,
    expected branch head, staged paths, and remote read-back. Never force a
    last-writer-wins update. Resume the same run ID after a publication failure.
11. **Summarize.** State scope, coverage, profile version, candidate/promoted/
    stale counts, findings by status/severity/priority, limitations, run ID,
    commit receipt, and: `No Azure resources were changed.`

## Human governance actions

Before promoting a low-confidence candidate, creating an override, retiring a
rule, or approving an exception, show a structured before/after diff and obtain
explicit confirmation. Exceptions require stable ID, owner, rationale, approval
evidence, scope, affected rule/resource IDs, created time, expiry, and status.
Expired or unverifiable exceptions produce findings.

## Failure behavior

- Malformed, unsupported, or unavailable AI output leaves the candidate
  unresolved and records the error. Continue only with the last valid profile.
- A stale inferred rule stops producing definitive violations until revalidated.
- A profile conflict blocks evaluation for affected resources.
- Failed acquisition remains partial or failed with explicit coverage.
- Failed publication makes the run incomplete. Preserve the staged bundle and
  resume the same run ID; do not report publication success or create a new run.
