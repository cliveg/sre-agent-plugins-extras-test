# WARA capability continuation

Updated: 2026-10-09. This activity is separate from
[network-health development](network-health-handoff.md).

## Origin and approved direction

- SRE Agent generated [PR #1](https://github.com/cliveg/sre-agent-plugins-extras/pull/1),
  branch `sre-agent/wara-assessment`, original commit
  `<implementation-commit>`.
- Capability: [wara-assessment](../plugins/wara-assessment/README.md).
- Run inside Azure SRE Agent with restricted-egress substitutes rather than opening more egress.
  Preserve Gallery mode for other hosts.
- Exactly one scope per WARA run; RG first, subscription only as a separate explicit run.
- User approved installing on the existing development agent and scheduling **only the RG**.
  Target-specific identifiers and instantiated schedule stay in private deployment state, not
  reusable source assets.
- Output repository: `<repo>/sre-outputs`, existing `wara/` scope-first history.
  The user reported `main @ <output-commit>`, two RG runs plus `latest.json`, and subscription output.
  Historical `WARA/` paths were removed but remain in Git history. Do not recreate or delete history.
- Use default prioritization until customer criticality/accepted-risk policy is explicitly supplied.

## Original validation versus continuation evidence

The generating SRE Agent reported a restricted-mode managed-identity RG run (16 resources,
34 findings), repeat run (34 PERSISTING), and subscription run (320 resources, 390 findings).
These are historical agent-reported results, not independently reproduced by this continuation.
APRL freshness does not prove compatibility with every future APRL schema or query.

Continuation review added the omitted CI test step and hardened:

- Unique, non-overwriting run directories.
- Durable failed collector records and explicit missing-Python failure.
- Missing previous artifacts and mismatched-scope comparisons fail explicitly.
- Incomplete collection carries missing findings forward as NOT_REOBSERVED.
- RESOURCE_NOT_LISTED replaces deletion claims based only on WARA inventory.
- Gallery source initialization, exact required-version installation, and scope validation.

Local validation: marketplace validator passes four plugins; ten WARA tests pass, including
offline PowerShell runner execution for RG/subscription parameter isolation, unique run folders,
and durable collector failure. No live WARA collector was executed for these tests.

PR #1 merged as `<implementation-commit>` after CI passed
138 existing network-health tests and nine WARA tests. Initial Marketplace installation
returned that exact source commit and delivered the supporting skill bundle, but exposed
stale catalog version metadata (`0.1.0` versus plugin `0.1.1`). A follow-up synchronizes both
marketplace manifests and adds the tenth test to prevent this mismatch.

## Installed and scheduled

- Catalog-version correction: `<implementation-commit>`.
  Its [CI run](https://github.com/cliveg/sre-agent-plugins-extras/actions/runs/37964599206)
  passed marketplace validation, existing network-health tests and the ten-test WARA suite.
- Marketplace was refreshed and **only wara-assessment** reinstalled at that exact commit,
  version `0.1.1`, auto-update disabled.
- Eight installed skill/supporting-file hashes independently match canonical Git blob bytes.
  Compare against Git bytes, not Windows checkout line endings. Verification used actual
  untruncated native terminal results, not only the agent's summary.
- Connected output repository was verified at `main @ <output-commit>`
  with a clean working tree. No output data or customer policy was modified.
- Generic Bash deployer dry-run and real deployment completed using a private deployment copy.
  Uploaded guide is listed in indexed knowledge documents; deployed reviewer was read back.
- RG-only `wara-monthly` is **Active**, cron `0 6 2 * *`, assigned to `wara-reviewer`.
  First next execution was read back as **2026-11-02 06:00 UTC**, execution count zero.
  The unrelated pre-existing weekly task retained its ID, active status and cron.
- Default prioritization remains in use; no criticality rules or accepted risks were invented.
- The configured YAML and full deployment receipts are kept in private session deployment state.
  They contain target-specific identifiers and are deliberately not included in this repository.
- Initial installation verification did not execute WARA. The later user-approved live
  validation below exercised the actual scheduled task.

## User-approved live scheduled validation

On 2026-10-09, the signed-in portal confirmed installed version `0.1.1` and the enabled task.
The user explicitly approved one RG-only validation, including output-repository publication.
The existing scheduled task was triggered once; no duplicate schedule was created.

- Execution thread: `<thread-id>`.
- Run: `2026-10-09T175107979Z-d7f87f6e`, runner `0.1.1`, status `Succeeded`.
- Collector reported `Completed` with no errors; analyzer and derived output completed.
- WARA parameters contain exactly `TenantID` and `ResourceGroups`, not `SubscriptionIds`.
- Inventory: 16 resources. Findings: 34, comprising 12 OBSERVED and 22 UNKNOWN.
- Bands: P1 5, P2 4, P3 10, P4 15. All 34 persisted from the prior same-day run;
  zero new or missing findings. This is not yet a month-over-month comparison.
- APRL `main` resolved to `69d73cbdc2729f5e94ab1184304ef4b9a5119ba2`.
- Output publication independently verified at commit
  `<output-commit>` in the configured output repository.
  Changed paths are confined to the new RG run and that scope's latest.json.
- All seven recorded output SHA256 hashes independently match downloaded canonical Git bytes:
  collector JSON, analyzer workbook, findings JSON, prioritized JSON/CSV/Markdown and delta JSON.
  AI review is a separate un-hashed companion, not deterministic assessment evidence.
- A terminal command returned 128 after successful push because the clone lacked local origin/main.
  Native git ls-remote and independent GitHub reads confirmed publication; it was not blindly retried.
- Task remains Active, execution count one, next execution **2026-11-02 06:00 UTC**.
- Reported collector success does not establish complete per-query coverage or prove every
  finding's applicability. Host review requested correction of an AI-review completeness
  overstatement without changing deterministic outputs or collecting more Azure evidence.

The live pipeline and publication are verified. This does not certify every recommendation,
future APRL compatibility, or universal enforcement of read-only behavior.

## Deployment workflow

1. Push the reviewed changes to PR #1 and confirm the amended GitHub Actions run.
2. Merge only after validation succeeds.
3. Register/resolve the marketplace and install **only** wara-assessment; verify its commit/version
   and supporting skill files. Do not substitute a generic SKILL.md upload for the bundle.
4. Instantiate [the monthly template](../plugins/wara-assessment/extras/scheduled-task-templates/wara-monthly.yaml)
   under `extras/scheduled-tasks/` in a private deployment copy. Use RG-only scope and default
   prioritization, with the verified tenant and managed identity.
5. Run [the generic deployer](../tools/deploy-extras.sh) with `--dry-run`, then deploy that copy.
6. Read back the installed plugin, subagent and scheduled task; record the task ID and next run
   in private deployment state. Do not disturb unrelated schedules or plugins.

The first Azure MCP request had a tenant mismatch. Explicit target-tenant lookup and the existing
Azure CLI context subsequently read the selected agent successfully; no global authentication
context was changed.

## Remaining limits

- WARA collector-level errors are not a complete per-query coverage ledger.
- Missing findings never establish deletion or remediation without independent checks.
- Same-scope concurrent runs are not supported; unique folders do not coordinate latest.json.
- Windows/Office Start-WARAReport is intentionally excluded.
- Do not claim new Azure runtime validation solely from local synthetic tests or installation.

## Reporting increment (PR #3)

The owner approved review/fixes, merge when validated, installation and monthly report generation
with PPTX, DOCX, findings workbook/CSV, selected environment evidence, classification and manifest
retained alongside each run in the private output repository. The collector runner remains unchanged.

Review of the original `0e2b928` candidate found and corrected:

- Resource-name collisions: ARM IDs, with composite legacy fallback, now select classification.
- Accepted-risk report sorting/action failures; accepted findings retain their recorded state.
- UNKNOWN findings receiving remediation-first advice; they remain validation tasks.
- Conflicting explicit tags depending on dictionary order; conservatively assess Production and disclose.
- Arbitrary persisted tags; collect only configured classification tag keys and record that selection.
- Unpinned template-cache selection and unverified/glob-selected inputs; use the exact WARA pin,
  recorded artifact paths/hashes and matching evidence/run scope.
- Missing upstream template attribution: retain a WARA MIT companion notice in generated bundles.

Thirty-three tests passed locally. A real saved-run replay using pinned WARA templates generated
46-slide PPTX, DOCX, findings XLSX/CSV, classification JSON, notice and report manifest. All manifest
input/output hashes and Office package structure independently verified. The 34 original priority
bands were preserved; the saved offer-based scope remained DEV/Medium. No new Azure collection
was needed for this local replay. Visual Office/LibreOffice rendering was not performed.
Classification requirements are advisory policy, not proof that HA/DR is unnecessary or accepted.

PR #3 merged as `<implementation-commit>` after
[the amended CI run](https://github.com/cliveg/sre-agent-plugins-extras/actions/runs/37979859995)
passed, including reporting dependencies and regression tests. Marketplace-installed WARA is
`0.2.0` pinned to that commit, auto-update false. Seven reporting asset hashes independently
match canonical Git bytes.

The existing monthly task was updated through the generic Bash deployer after a dry run.
Its ID, active status, cron, execution count/history and next run (2026-11-02 06:00 UTC)
were preserved. Exact prompt read-back matches the private YAML. It now explicitly requests
selected environment evidence, PPTX/DOCX/findings workbook/CSV, classification, report manifest
and WARA notice under each run's reports/ directory, committed with the run. Missing dependencies,
generation failures and publication failures are reported separately from collection success.
The unrelated weekly task was preserved.

Installed reporting validation reused the saved `2026-10-09T175107979Z-d7f87f6e` assessment;
no collector/analyzer replay occurred. The installed metadata collector read only the same
RG/subscription context and retained 16 ARM-identified resources with configured tag keys.
The independent subscription ARM read corroborated the Internal offer and unrecognized
Environment=Hybrid signal. Generation produced 46 slides and the complete report bundle.
All recorded source artifacts plus run.json/latest.json remained unchanged; report input/output,
template, classification config and environment-evidence hashes verified. All 34 bands and
22 UNKNOWN validation actions were preserved. Office visual rendering is still unverified.

The installed report bundle was published at output-repository commit
`<output-commit>`. Independent Git downloads confirm exactly
eight added files under this run's reports/ directory, with no other path changes.
All six manifest outputs, five manifest inputs and retained evidence hashes match downloaded
Git bytes. The actual PPTX contains 46 slides; DOCX/XLSX package structures reopen successfully.
The downloaded evidence contains 16 ARM IDs and only the configured tag keys. DEV/Medium,
34 unchanged bands and 22 validation-first UNKNOWN actions reconcile with original findings.
Windows long-path lookup was avoided by reading canonical blobs by object ID, not by altering
any source/evidence paths. Private report copies and execution receipts remain in session state.
