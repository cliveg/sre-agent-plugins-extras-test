---
name: azure-network-evidence-capture
description: |
  Capture reviewed Azure configuration and change/health history, preferring verified Log Analytics AzureActivity. Supply reference-led comprehensive networking reports, public-source reviews, offline timelines and comparisons. Preserve source evidence and unknowns; verify and publish privately. Acquisition uses existing in-agent identity. Offline processing needs no Azure access or user-host tools; no logging changes, silent fallback or causal claims.
tools:
  - RunInTerminal
  - ReadFile
  - SearchMemory
---

# Azure Network Evidence Capture

Capture evidence before interpretation. Use this skill for reusable configuration
snapshots and the explicitly selected offline processors, not connectivity or
full-health certification.
Replay recorded evidence without refreshing its collection times.

For timelines over existing capsules, go directly to
[Offline evidence timeline](#offline-evidence-timeline). That branch needs Python
3.10+ and Git only for publication; it does not contact managed identity or Azure.
For before/after snapshots, use
[Offline configuration comparison](#offline-configuration-comparison) with the
same offline prerequisites. New snapshot acquisition requires its own read scope.
For unrestricted Internet-source configuration questions over retained evidence,
go directly to [Offline public-source restriction assessment](#offline-public-source-restriction-assessment).
That branch uses Python 3.10+ and Git only for authorized publication, not
PowerShell, managed identity, Azure CLI or fresh Azure collection.
For broader topology/routing/NSG/Private Endpoint/DNS/firewall/hybrid assessment,
use the sibling skill's
[reference-led comprehensive workflow](../azure-network-health-assessment/SKILL.md#reference-led-comprehensive-assessment).
It composes the core checks with the credited specialist/report procedures and
adds explicit assessment coverage, not a global health score.

## 1. Establish scope and prerequisites

For acquisition, obtain the actual tenant, one approved subscription, existing managed-identity
client ID, a new capture UUID, and a private workspace output directory. Use
supplied configuration or private memory; confirm ambiguity rather than taking
default subscriptions, identities or repository names.

Supported families are Storage Accounts, Key Vault vaults, Container Registries,
Log Analytics workspaces and their NSP/AMPLS configuration. References outside
collected parents remain references; they do not authorize additional reads.
Azure Monitor workspaces are not Log Analytics workspaces.

Use the **workspace RunInTerminal** runtime with Python 3.10+, PowerShell 7.2+,
an existing Az.Accounts module and Git for publication. WARA's existing module cache
is supported. Network-blocked Code Interpreter is not this runtime. Stop if
prerequisites or managed identity are unavailable; do not install packages, use
interactive login, transfer host credentials or grant roles.

Locate this installed skill's actual supporting-file directory. Required files:
`scripts/network_capture.py`, `arm_reader.ps1`, `configuration_profile.py`,
`configuration-profile.json`, `evidence_files.py`, and `publish_evidence.py`.
History also needs `network_history.py`, `event_profile.py`, `history_reader.ps1`,
`arm_context.ps1` and the fixed `resource-changes.kql` query. Configuration capture
shares `arm_context.ps1` for exact JSON/time preservation and managed identity.
Workspace Activity Log capture additionally requires `workspace_activity.py`,
`workspace_reader.ps1` and `workspace-base.kql`, `workspace-summary.kql`,
`workspace-page.kql`. Verify the installed files; do not reconstruct them in chat.
Use those installed files, not downloaded replacements or model-written evidence.
Offline timelines additionally use `network_timeline.py` and the existing Python
replay/profile/template files; their PowerShell readers are not executed.
Offline derived bundles share `evidence_bundle.py`; configuration comparison
also requires `network_comparison.py`.
Offline restriction assessment also requires `network_restriction.py`.
Reference-led review additionally uses `reference_capture.py`, `reference_arm.py`,
`reference_profile.py`, `reference_reviews.py`, `network_reference.py` and the
sibling legacy engine/schemas plus `reference-assessment.md`. Runtime dependency
pins are declared in `runtime-dependencies.json`; restoration is not automatic.

## 2. Capture

Execute the installed command through RunInTerminal:

```bash
python3 <skill-dir>/scripts/network_capture.py capture \
  --tenant-id <tenant-uuid> \
  --subscription-id <subscription-uuid> \
  --managed-identity-client-id <existing-client-uuid> \
  --capture-id <new-uuid> \
  --output-root <existing-private-workspace-directory>
```

Authentication is managed identity with process-scoped context only. The adapter
verifies the tenant/subscription and permits ARM GETs over the reviewed profile.
Discovery lists are followed by resource GETs and parent-bound control reads.
Source responses are filtered by the installed profile before persistence or
conversation output. No full unredacted provider bodies, secret/key values,
tokens, tags, contact data or diagnostic contents are retained.

The profile retains reviewed network/access rules, TLS/authentication toggles,
protection and retention settings, needed identity/key references, SKU/location
and system metadata. Missing fields stay missing, explicit null stays null, and
omitted field paths carry no values. Declared service defaults are not evidence.

On interruption, repeat the same command/scope/identity/capture ID with `--resume`.
Completed pages are reused, not recollected. If no response was retained for a
pending GET, stop and explain its uncertain outcome. Only after explicit approval
add `--retry-unconfirmed`; a new attempt/time is recorded alongside the original.
Never clear a lock or edit a checkpoint to force success.

The receipt identifies the sealed capsule. A finished capsule can include denied,
failed or unavailable collections; completion is not evidence completeness.
Report those gaps rather than equating empty results with global absence.

## Existing change and health history

**Prefer existing Log Analytics for Activity Log evidence.** First follow the
workspace discovery/preflight workflow below. A connector, table or export
setting alone is not proof of usable history. An inaccessible or empty source
stays UNKNOWN; do not silently start the direct Activity Log reader.

Use history only when explicitly requested. The owner may approve subscription-
wide event metadata even when configuration capture covers fewer families. Do not
filter events solely to today's inventory: deleted resources, deployments and
platform events can provide relevant context.

Use one new capsule UUID per source. Supply explicit UTC start/end timestamps;
request at most 365 days, ending no later than collection planning time.

```bash
python3 <skill-dir>/scripts/network_history.py \
  --source <activity-log|resource-changes|service-health> \
  --tenant-id <tenant-uuid> --subscription-id <subscription-uuid> \
  --managed-identity-client-id <existing-client-uuid> \
  --capture-id <new-history-uuid> --output-root <existing-private-directory> \
  --start-time <UTC-Z-timestamp> --end-time <UTC-Z-timestamp>
```

The three source profiles are:

- `activity-log`: existing Administrative, ResourceHealth and ServiceHealth
  categories, recorded caller/needed identity claims, operation/status and event/
  submission times. Native history is normally 90 days.
  This is the explicit direct-source alternative, not the default fallback.
- `resource-changes`: existing ARG `resourcechanges`, detected time, recorded
  System/Unspecified/client attribution, change type, permission action, changed
  paths and source truncation. Native history is 14 days. Before/after values
  are retained only for reviewed configuration paths/types; unsupported shapes
  and unreviewed values are explicitly omitted, never coerced into configuration.
- `service-health`: existing subscription ResourceHealth/events feed, retaining
  eventSource, status, impact/update times, affected services/regions and selected
  revisions. Its API filters by lastUpdateTime/date, not impactStartTime.
  A one-year request is not proof that a year of data exists. Sensitive summaries/
  update text are omitted; fetchEventDetails is never invoked.

Native retention gaps, denied sources, failures, discarded categories and
uncollected exported Log Analytics history remain explicit. No logs, retention,
exports, alerts or diagnostics are enabled. No tokens, caller IPs, unnecessary
claims, arbitrary request bodies or diagnostic contents are persisted. Recorded
automation identities do not establish the human who initiated them.

For incremental history, use `--previous-capsule <verified-same-source-capsule>`.
The previous terminal watermark determines a 24-hour overlap. Revised payloads
remain separate revisions; correlation IDs are not event identity or causation.
Partial/denied sources cannot advance that watermark. Paused collection uses
the same command with `--resume`; uncertain response retry requires explicit
approval and `--retry-unconfirmed`. Exhausted limits retain an incomplete
workspace checkpoint, not a falsely completed source or a silently skipped
interval. Do not advance from a denied capsule; resume applicable partial work
or obtain approval for a new explicit window after access is resolved.

Use the normal offline verify/replay and guarded publisher below for history
capsules as well. Replay is an evidence timeline, not an incident diagnosis,
slippage/compliance finding or root-cause attribution.

### Log Analytics-first workspace workflow

Discover the assessed subscription's existing export destinations:

```bash
python3 <skill-dir>/scripts/workspace_activity.py discover \
  --tenant-id <tenant-uuid> --subscription-id <assessed-subscription-uuid> \
  --managed-identity-client-id <existing-client-uuid> \
  --start-time <UTC-Z-timestamp> --end-time <UTC-Z-timestamp> \
  --output <new-private-discovery-json>
```

An external workspace reference is recorded, not followed automatically. After
explicit workspace-read approval, add `--approved-workspace-resource-id <id>`.
This flag can also name a specific existing workspace not in current settings.
Multiple usable candidates require a choice, not arbitrary first-result selection.
No other subscription resources, identities or tenants are enumerated/switched.

Preflight one explicit workspace using the same identity/scope/time arguments:

```bash
python3 <skill-dir>/scripts/workspace_activity.py preflight \
  --tenant-id <tenant-uuid> --subscription-id <assessed-subscription-uuid> \
  --managed-identity-client-id <existing-client-uuid> \
  --workspace-resource-id <approved-existing-workspace-arm-id> \
  --start-time <UTC-Z-timestamp> --end-time <UTC-Z-timestamp> \
  --output <new-private-readiness-json>
```

Preflight verifies the resource/customer-ID binding, Analytics table/schema,
existing retention metadata and actual subscription-filtered rows, categories,
dates and recorded-caller availability. A known destination that is in another
tenant may still be unreadable: report that access gap, never change login or
grant access. Current disabled categories and no matching rows do not establish
that all historical categories are absent.

`AVAILABLE` means relevant rows were observed, not full-range/permission-wide
coverage. Empty, denied, unsupported-plan and partial/error query results produce
UNKNOWN with a saved reason; CLI status is nonzero. Retention, observed earliest
date and missing categories remain separate. Archived data is not restored.

For an AVAILABLE workspace, capture with the installed command:

```bash
python3 <skill-dir>/scripts/workspace_activity.py capture \
  --tenant-id <tenant-uuid> --subscription-id <assessed-subscription-uuid> \
  --managed-identity-client-id <existing-client-uuid> \
  --workspace-resource-id <approved-existing-workspace-arm-id> \
  --capture-id <new-uuid> --output-root <existing-private-directory> \
  --start-time <UTC-Z-timestamp> --end-time <UTC-Z-timestamp>
```

The capture rechecks readiness, binds its evidence into capsule **0.5.0**, and
uses fixed server-side subscription/category/time filters and reviewed columns.
There is no caller-supplied KQL or arbitrary HTTP endpoint. HTTP-200 PartialError
results are incomplete, not success. Keyset pages retain exact timestamp precision;
identical reviewed rows are grouped with a copy count. No tokens, caller IPs or
unreviewed claims/properties are returned to the model or retained.

Use the same `--resume`, separately approved `--retry-unconfirmed`, and
`--previous-capsule` 24-hour overlap rules as other history sources. A completed
resume is offline. The paused direct-source checkpoint is unrelated and must not
be edited, resumed or replaced by this workflow. Old capsules remain unchanged.

## Offline evidence timeline

Select the exact already retained configuration/history capsules to process,
not an arbitrary latest branch. Use the installed 0.3.0/0.4.0/0.5.0 formats in
one tenant/subscription; earlier companion formats remain separate workflows.
Restore missing local files from approved, pinned private Git objects if needed,
preserving their actual bytes. Missing inputs stay gaps, not a reason to query
Azure or reconstruct evidence from conversation text.

Obtain a new timeline UUID and an existing private output directory outside all
source capsules. Build with one `--capsule` per selected input:

```bash
python3 -B <skill-dir>/scripts/network_timeline.py build \
  --capsule <verified-configuration-capsule> \
  --capsule <verified-history-capsule> \
  --timeline-id <new-timeline-uuid> \
  --output-root <existing-private-directory>
python3 -B <skill-dir>/scripts/network_timeline.py verify \
  --timeline <actual-derived-timeline-directory>
```

The self-contained bundle contains `timeline.json`, its deterministic
`timeline.md` view, a derived manifest and byte-identical capsules beneath
`sources/`. Completion requires exit 0 and `verified-offline-timeline`, with
member integrity and both views rederived from those sources. A failure is not a
publishable partial timeline; preserve the error and use a new UUID for another
explicit build rather than editing source or derived evidence.

### Compact, bounded pages

For a selected corpus that needs compact storage, explicitly add `--compact`
to the same build command. Storage/processor **1.1.0** keeps every selected
capsule embedded but replaces duplicate payload/witness metadata with references
to its original source pages. It creates bounded JSON/Markdown section pages and
a small root `timeline.json` index. The default **1.0.0** inline format and old
artifacts are unchanged; there is no silent format switch or limit increase.

Read `timeline.md` for page links and coverage. For complete machine analysis of
either version, use the installed Python interface:

```python
import network_timeline
document = network_timeline.read(actual_timeline_directory)
```

`actual_timeline_directory` is a `pathlib.Path`. The complete normalized logical
view includes every event payload and original witness; filter/aggregate it
inside the runtime and return only needed private results/evidence links.
The root index or one page is not the whole timeline. Do not dump the complete
normalized view into chat or treat missing root arrays as uncollected evidence.
Verification autodetects storage version and regenerates every page from sources.

Each section page has at most 500 entries, with byte-aware splitting, at most
100 pages per section, and the same 5 MiB/member, 64 KiB/manifest, 20 MiB/total and
input bounds. A residual overrun remains an explicit failure. See
[compact storage and reading](reference.md#compact-timeline-storage-110).

Review the input count, retained event rows versus deduplicated identities/
revisions, configuration observation windows, source outcomes and parent
bindings. Revisions remain separate; all overlap evidence references survive.
Recorded event/update/submission/ingestion times keep their own meanings.
Resource and recorded correlation-ID indexes are context, not deletion, shared
incident, successful change, impact or cause. Unbound health events remain in the
timeline. Source/profile/workspace identities are not collapsed across providers.

Both JSON and embedded evidence stay private. Markdown avoids unnecessarily
repeating actor identifiers and payloads; the private JSON/source records retain
approved attribution. Scope/retention/permission/omission gaps remain visible.
This produces neither configuration-difference verdicts nor new assessments.
See [timeline limits and identity rules](reference.md#offline-timeline-contract)
before handling an oversized, missing-parent or incompatible input.

To persist the verified bundle, follow the approved publication step below with
`--timeline <actual-derived-timeline-directory>` instead of `--capsule`.

## Offline configuration comparison

Select two explicitly approved configuration capsules, before then after.
Restore exact pinned private Git bytes if the local copies are unavailable;
never reconstruct evidence or silently collect a replacement. This processor
accepts the unchanged installed 0.3.0 configuration profile in one tenant/
subscription, with chronological nonoverlapping collection windows.

```bash
python3 -B <skill-dir>/scripts/network_comparison.py build \
  --before <verified-before-capsule> --after <verified-after-capsule> \
  --comparison-id <new-comparison-uuid> \
  --output-root <existing-private-directory-outside-both-sources>
python3 -B <skill-dir>/scripts/network_comparison.py verify \
  --comparison <actual-derived-comparison-directory>
```

Completion requires exit 0 and `verified-offline-comparison`. The separate
self-contained bundle contains `comparison.json`, deterministic `comparison.md`,
a manifest binding before/after roles and byte-identical source capsules.
Verification rebuilds both views from those sources. Publish only after it
passes, using the existing publisher with `--comparison` instead of `--capsule`.

Review settings differences, metadata differences, unknown resources, one-sided
visibility and field/collection gaps separately. Comparison uses successful
direct GETs, not sparse inventory rows or an inferred default. Missing fields
remain UNKNOWN, explicit null remains null, denied/omitted evidence is not an
empty result. Newly observed/not observed later are visibility statements, not
proof of creation/deletion. Even equal compared values do not certify an entire
resource unchanged.

Original source values/pointers remain private and unchanged. Only explicitly
listed membership arrays are compared without ordering, preserving duplicates;
metadata/provider state is separated from settings. These are observed
differences, not desired-state violations, security findings, slippage, impact
or causes. Read [comparison policy and limits](reference.md#configuration-comparison-contract)
for the supported normalization, privacy, chronology and coverage contract.

## Offline public-source restriction assessment

Select one explicitly approved, verified configuration **0.3.0** capsule and a
new run UUID. If missing locally, restore its exact pinned private Git bytes;
retain the original collection times. Fresh collection needs its own scope.
Use an existing private output directory outside the immutable source.

```bash
python3 -B <skill-dir>/scripts/network_restriction.py build \
  --capsule <verified-configuration-capsule> --run-id <new-run-uuid> \
  --output-root <existing-private-directory>
python3 -B <skill-dir>/scripts/network_restriction.py verify \
  --run <actual-created-run-directory>
```

Completion requires both commands to exit 0 with the expected `restrictionId`.
The run contains `observed-network.json`, `assessment.json`,
`network-assessment.md`, `network-evidence.md`, a manifest and unchanged
supporting source bytes. Both Markdown reports are deterministic views of
assessment JSON. These separate 1.0.0 companion profiles are not inputs to the
legacy 0.13 assessment runtime. Keep the entire run private.

Read measured statistics and necessary results from assessment JSON, preserving
the difference between local `serviceConfiguration` and overall
`criterionVerdict`. Log Analytics ingestion and query are independent.
UNKNOWN identifies missing or unqualified evidence, not a pass or default
Allow. Private-endpoint presence, NSP/AMPLS association or an Enforced label
alone is not qualification. Report original collection times, not current state.

Publish only after verification and explicit destination approval, using
`--restriction` in [Publish only when authorized](#4-publish-only-when-authorized).
Reuse an existing run's exact bytes after an uncertain publication; reconstructing
it under the same UUID with a new manifest is not an idempotent retry.
Write only the selected run/publication artifacts. Memory maintenance is outside
this workflow; audit surrounding agent activity separately from processor counters.

Read [restriction policy and qualification gates](reference.md#public-source-restriction-contract)
before interpreting results or proposing further collection. It defines address
unions, unsupported states, service/path gates and the limits of a positive result.

## 3. Verify and replay

```bash
python3 <skill-dir>/scripts/network_capture.py verify --capsule <actual-capsule-dir>
python3 <skill-dir>/scripts/network_capture.py replay \
  --capsule <actual-capsule-dir> --output <new-private-replay-file>
```

Both commands are offline. Verification checks exact membership, hashes,
scope/profile bindings, reviewed shapes, required enrichment and continuations.
Replay retains resource-specific observations, original client collection times,
omissions and source outcomes. Its receipt records processing time separately.

The output is evidence JSON, not `observed-network.json`, an assessment or a
private-access green verdict. Event sources are explicitly not collected.
That not-collected statement applies to configuration capsules; history capsules
declare their actual source coverage and timeline separately.
Configured controls do not establish effective enforcement, actual traffic or
customer-policy compliance. Existing assessment/check versions are unchanged.

## 4. Publish only when authorized

Obtain the actual connected output-repository path and explicit expected
`owner/repository`. Confirm the private destination and publication approval.
Code Access alone does not establish write access or privacy. Keep evidence out
of the capability/source repository.

```bash
python3 <skill-dir>/scripts/publish_evidence.py \
  --capsule <verified-capsule-dir> \
  --repository-root <actual-connected-output-clone> \
  --expected-repository <owner/repository> \
  --private-destination-reviewed \
  --receipt <new-private-publication-receipt>
```

Choose exactly one input option: `--capsule`, `--timeline`, `--comparison` or
`--restriction` or `--review`.
The publisher uses the existing runtime Git
connection and stages only that artifact's verified members in a separate
worktree. Source branches use `network-evidence/`; timeline branches use
`network-timeline/`, with files under `network-health/timelines/<timeline-id>/`.
Comparison branches use `network-comparison/`, with files under
`network-health/comparisons/<comparison-id>/`.
Restriction branches use `network-restriction/`, with all four views and embedded
source files under `network-health/runs/<run-id>/`.
Comprehensive reviews use `network-review/` and the same unique run path, with
explicit input-role bindings and unchanged embedded component artifacts.
Embedded source capsules are part of each derived bundle's verified membership.
No evidence publication mode updates main or existing WARA work. Explicit fetch/FETCH_HEAD
avoids assuming an `origin/main` tracking ref exists. Credentials and raw remote
URLs are never printed or copied into evidence.

Claim persistent publication only after remote ref and committed byte read-back
match the receipt. If a push outcome is uncertain, inspect the remote branch;
do not blindly repeat the push. An existing branch is reusable only when its
bytes match this capsule exactly. No merge, force-push or source publication.
The console summary is compact; the full receipt file retains every artifact
hash. Read that file if a terminal response is truncated rather than repeating
a successful capture or publication.

## Completion

Return the capture ID, scope, source outcome counts, capsule/replay paths and
verified output commit when published. Explicitly distinguish unread/denied/
omitted evidence, synthetic versus live validation and not-collected history.
Acquisition, replay, timelines and comparisons produce evidence, not health
findings or causal conclusions.
For timelines, return the timeline ID, input/source counts, identity/revision and
observation counts, coverage gaps and verified output commit instead. A verified
timeline is not certification of complete history or source authenticity.
For comparison return its ID, before/after capsule bindings, measured settings/
metadata differences, unknown/visibility/omission counts and verified private
commit. Preserve zero-difference results honestly; never fabricate a change to
demonstrate the workflow.
For restriction assessment, return the run ID, source capsule/hash/original
window, resource and service-path counts, local settings versus overall verdict
counts, qualification gaps and verified private commit when published. A
RESTRICTED result is the pinned technical configuration criterion, not
private-only connectivity, owner-allowlist compliance, authorization or
effective-enforcement certification. No impact severity or causal finding is
invented. Keep rule-address values and private evidence out of conversation logs.
For comprehensive review return the review ID, actual source windows, six-area
assessment coverage, contextual findings/positives/gaps and exact verified private
commit. Separate recorded context from cause and configured ingress from
reachability; processor counters do not audit surrounding agent actions.

See [runtime contracts and limits](reference.md) for storage, quotas, formats,
provenance, failure interpretation and compatibility.
