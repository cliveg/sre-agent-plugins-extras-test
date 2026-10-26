# Azure Network Health Assessment: restricted prototype

**0.21.2 released and installed:** a reference-led comprehensive report now adapts Usman
Mahmood's actual assessment/report specification and Network Desk Azure-only
specialist procedures. It composes the existing core checks and adds contextual
NSG selector/ingress review, firewall/hybrid/existing-monitoring configuration,
an evidence-bound architecture view, public-source results and recorded context.
Coverage is explicit, not a global Healthy score. Fresh installed lab evidence,
private report publication, exact Git-object read-back and independent direct
ARM corroboration passed. The six-area review retains 652 selected rows,
713 normalized nodes / 581 collected entities and 38 contextual records.
See [installed acceptance](runtime-validation.md#installed-reference-led-comprehensive-acceptance-2026-10-20-utc)
for source windows, measured limits, recovery history and remaining gaps.
Patch 0.21.1 removes indentation overhead from the new observation view after
fresh 0.21.0 collection exposed its byte-budget failure; it reuses sealed
evidence rather than recollecting it.
Patch 0.21.2 distinguishes collected entities from the normalized model's
context/configuration/reference nodes; it preserves every finding and source.
New assessment/bundle 1.0.1 carries the corrected statistics; the verifier
still reproduces immutable 1.0.0 reports with their original metadata.

## Reference-led comprehensive report

Use the installed network-health skill's
[reference-led workflow](skills/azure-network-health-assessment/SKILL.md#reference-led-comprehensive-assessment)
and [adapted method](skills/azure-network-health-assessment/reference-assessment.md).
This is substantive procedural adaptation plus composition of existing checks,
not merely attribution or a new discovery methodology. Exact sources/revisions,
permission, modifications and limits are recorded in
[the source map](../../docs/source-map.md#2026-10-19-reference-led-comprehensive-report-0210-candidate)
and [notices](THIRD-PARTY-NOTICES.md#version-0210-reference-led-comprehensive-workflow).

The new source collector uses the existing scoped/paged/resumable engine and
managed-identity ARM transport. A new profile 1.0.0 binds selected-input 1.0.0,
catalog 1.9.0, context and selected request journal; the original source bytes
are not relabelled as the legacy core projection. Both deterministic reports
follow the evidence scorecard/contextual finding/positive/validation structure,
with uncollected effective routes/rules, listeners, BGP, usage and intent explicit.
Public-source and timeline components retain their own windows unchanged.
The new observation profile uses deterministic compact JSON, retaining all
entities, assertions, relationships, evidence and values without indentation
overhead. Its assessment hash binds those exact bytes. Historical serializers
and the 5 MiB/member, 64 KiB/manifest and 20 MiB/bundle limits are unchanged;
oversized inputs or outputs still fail rather than being trimmed.

The user needs no host tools. Python/jsonschema/JMESPath and existing PowerShell/
Az.Accounts run in the agent; dependencies are not automatically installed.
For this approved lab iteration, only missing WARA-pinned Az.Accounts 3.0.4
and JMESPath 1.1.0 were restored into private runtime caches after explicit
approval. No global Python packages, CLI extensions, workloads, roles, logging,
memory or schedules were changed by that prerequisite operation.

**0.20.0 predecessor acceptance:** the existing evidence-capture skill routes retained
snapshots to the offline public-source restriction companion and supports its
guarded private publication. That installed source pin was
`<implementation-commit>`, automatic updates off.
All 35 canonical files across both skills then matched Git. Installed processing and
independent committed-object read-back reproduced the accepted 36-resource/
50-path result without Azure collection during processing. See
[installed acceptance](runtime-validation.md#installed-offline-restriction-acceptance-2026-10-19-utc).
No new acquisition profile or dependency is introduced; the 0.19.0 features
described below remain available unchanged.

Package **0.19.0** extends the dedicated `azure-network-evidence-capture`
skill for hostless reviewed configuration capture, offline verification/replay and
explicit private-repository publication with Log Analytics-first Activity Log
discovery/preflight/collection, existing change/health history and a separate
self-contained offline evidence timeline and conservative configuration comparison.
The existing assessment skill/runtime
below remains **0.13.0** with its original contracts. Installed-package acceptance
is recorded separately in [runtime-validation.md](runtime-validation.md);
the earlier one-resource feasibility spike alone does not establish the full package.

Patch 0.18.1 corrects the workspace page-cursor string comparison in both query
producers using Kusto `strcmp`. It preserves the original source/profile/cursor
contracts, old evidence bytes and budgets. A prior known-failed sealed capture
stays UNKNOWN; it is not repaired by `--retry-unconfirmed` or by rewriting a
checkpoint. See the runtime record for the failure and subsequent acceptance.

Package 0.19.0 adds explicit compact/paged timeline storage **1.1.0** without
changing default inline 1.0.0 output, source formats or comparison semantics.
Use `network_timeline.py build --compact` for bounded section pages backed by
unchanged embedded payloads; `network_timeline.read(Path(...))` returns the
complete normalized view of either version. Existing 5 MiB/member,
64 KiB/manifest and 20 MiB/total limits remain in force. No automatic source
trimming, bigger budgets or new Azure collection is introduced. See
[compact storage](skills/azure-network-evidence-capture/reference.md#compact-timeline-storage-110).

Installed 0.19.0 acceptance retained all ten selected capsules in a 139-file,
15,034,995-byte compact bundle. All 3,418 revisions, 3,747 event witnesses, 128
configuration observations and 3,933 Markdown links passed independent
committed-object/source-pointer checks; the full normalized reader matches the
legacy logical projection. All eight newly observed configuration IDs now have
recorded history context. This is not a creation, compliance, impact or causal
verdict. See the
[installed compact acceptance and audit limitations](runtime-validation.md#installed-compact-timeline-acceptance-2026-10-19-utc).

## Offline public-source restriction assessment (0.20.0)

The `scripts/network_restriction.py` companion consumes one verified
configuration **0.3.0** capsule without Azure calls, authentication, external
processes or new dependencies. Package 0.20.0 wires this workflow into the
existing evidence-capture skill and adds the guarded publisher's `--restriction`
input. Historical 0.13 schemas, source formats, acquisition, timeline and
comparison behavior remain unchanged. Actual installed acceptance is recorded
separately from processor counters.

From the evidence-capture scripts directory:

```text
python network_restriction.py build --capsule <existing-private-capsule> --run-id <new-uuid> --output-root <existing-private-directory>
python network_restriction.py verify --run <created-run-directory>
```

When explicitly authorized, use the existing publisher with `--restriction`,
the actual connected private output repository, its reviewed `owner/repository`
and a new receipt outside the immutable run. Unique `network-restriction/<id>`
branches contain all files under `network-health/runs/<id>/`; existing WARA work
and main are preserved. See the
[skill workflow](skills/azure-network-evidence-capture/SKILL.md#offline-public-source-restriction-assessment).

The immutable run contains `observed-network.json`, `assessment.json`,
`network-assessment.md`, `network-evidence.md`, a manifest and an unchanged
embedded source capsule. Separate observation/assessment profile IDs and
version **1.0.0** explicitly identify this as a new offline companion, not legacy
Observed Network Model or assessment input. Verification rederives every view
from the verified source; rehashing a forged report is not sufficient. The
original 5 MiB/member, 64 KiB/manifest and 20 MiB/total limits remain unchanged.

Storage, Key Vault and ACR have one data-plane result; Log Analytics has
independent ingestion/query results. `serviceConfiguration` describes the local
setting; `criterionVerdict` is `RESTRICTED`, `NOT_RESTRICTED` or `UNKNOWN`.
Missing/null/omitted/denied evidence is not a documented default. Exact IPv4
address unions detect `/0`, equivalent unions and public-space coverage even
when only private/reserved holes remain. Pinned IANA special-purpose facts
preserve globally reachable exceptions and deprecated-block uncertainty,
without runtime-varying `is_global` heuristics. Mathematical IPv6 whole-family
coverage is separate from service support; unsupported service selectors cannot
earn a positive verdict. A less-than-global range has no arbitrary size limit.

Positive NSP/AMPLS qualification is gated. Their presence, an Enforced label,
Learning/Transition mode or an approved private-endpoint connection is not
enforcement or private-connectivity proof. Overall Storage/Key Vault/Log
Analytics results remain UNKNOWN until precedence and service/path evidence
are qualified. ACR uses the explicitly pinned unsupported-NSP service policy;
a contradictory association also stays UNKNOWN. Empty visible control roots
are not global absence. Selected networks and public-disabled settings are not
customer-allowlist, anonymous-access, private-only or effective-reachability
certifications. Unknowns prioritize evidence collection, not automatic changes;
contextual impact severity and causal findings are not generated.

Only selected source configuration is embedded. Reports omit rule-address
values but contain resource identifiers and evidence references: keep the
entire run private. Both Markdown reports are deterministic views of assessment
JSON, with original collection times, source hashes and check IDs/versions.
Synthetic tests do not close live NSP/AMPLS gates. See
[source decisions and lineage](../../docs/source-map.md#2026-10-19-offline-public-source-restriction-assessment-unreleased).

The accepted private
report bundle (private output repository)
contains 50 files with all 45 original source files unchanged. Its 49
non-manifest files match local acceptance exactly; only actual processing time
differs in the manifest. Results remain three RESTRICTED/47 UNKNOWN overall.
Separate targeted follow-up confirmed the two missing-firewall ACR targets are
Basic tier; the scoped indexed control query returned no representative NSP/
AMPLS roots. Neither observation changes the frozen rule or proves default Allow
or global absence. Scheduling remains unconfigured until cadence/timezone and
source-refresh scope are agreed.

## Offline configuration comparison

The installed `network_comparison.py build` command compares two explicitly
selected verified configuration 0.3.0 capsules, before then after, without Azure
reads. It produces separate versioned JSON/Markdown plus unchanged source
capsules in a self-contained comparison bundle. The existing timeline, source
formats, capture profile and assessment contracts are unchanged.

Successful direct GETs support like-for-like retained-value comparison.
Settings and metadata/provider-state differences remain separate, missing/null/
omitted/denied evidence remains distinct, and documented membership-array order
does not fabricate a settings change. One-sided visibility is newly observed or
not observed later, not proof of creation/deletion. Differences are not defects,
desired-state violations, security verdicts, slippage, impact or causes.

Verify with `network_comparison.py verify`, then use the existing guarded
publisher's `--comparison` option. Unique private branches use
`network-comparison/`; paths use `network-health/comparisons/<comparison-id>/`.
Exact source pins, before/after roles, evidence references and rule/policy
versions bind the output. See the
[installed comparison workflow](skills/azure-network-evidence-capture/SKILL.md#offline-configuration-comparison)
and [policy/limits](skills/azure-network-evidence-capture/reference.md#configuration-comparison-contract).

Installed 0.18.0 acceptance compared two exact published snapshots: 28
comparable resources had zero retained settings/metadata differences, eight
resources were newly observed without before evidence, and 19 gaps remained
explicit. Independent raw GET payload sets corroborated the zero result.
The self-contained 85-file comparison was published privately and verified from
committed Git objects; all 66 evidence links and deterministic rebuild passed.
The separately approved second snapshot required restoring the pinned runtime
module cache, not changing Azure resources. See the
[actual installed results and limits](runtime-validation.md#installed-configuration-comparison-acceptance-2026-10-18-utc).

## Offline evidence timeline

Use installed `scripts/network_timeline.py build` with explicitly selected source
capsules, a new timeline UUID and an existing private output root. It accepts the
installed configuration/native-history/workspace formats 0.3.0/0.4.0/0.5.0 in one
tenant/subscription. Python is sufficient; neither Azure calls nor managed
identity, Azure CLI or PowerShell execution is needed for this branch.

The separate derived bundle contains JSON, deterministic Markdown, a manifest
and byte-identical supporting capsules. It retains source-specific identities,
all payload revisions and overlap evidence references, with exact original time
meanings and coverage gaps. Resource and recorded correlation-ID indexes provide
context; historical-only and unbound health events are retained. This is not
configuration-difference assessment, service/region impact matching or causation.

Run `network_timeline.py verify --timeline <directory>` before publication.
Verification rebuilds both views from the embedded verified sources. The same
guarded publisher accepts `--timeline` and writes a unique `network-timeline/`
branch under `network-health/timelines/<timeline-id>/` in the explicitly approved
private repository. Original capsules, source branches, assessment contracts and
the connected WARA worktree remain separate.

Bounds: 20 capsules, 20,000 input event/configuration observation rows including
overlap, existing 5 MiB member/64 KiB manifest/20 MiB total limits. A failure is
explicit; no evidence is silently dropped or recollected. See the
[installed workflow](skills/azure-network-evidence-capture/SKILL.md#offline-evidence-timeline)
and [identity, privacy and limit details](skills/azure-network-evidence-capture/reference.md#offline-timeline-contract).

Installed 0.17.0 acceptance restored six pinned private capsules and produced
340 source-bound event revisions with all 475 input witnesses, plus 56
configuration observations. Exact committed-byte verification, independent
source/provenance/index checks, 537 resolving evidence links and reverse-input
deterministic rebuild passed with zero Azure recollection. The self-contained
55-file bundle is published privately; the earlier workspace's unpublished
partial-capture checkpoint was unavailable after runtime replacement and was
not reconstructed or claimed preserved. See the
[installed acceptance and workspace-loss limitation](runtime-validation.md#installed-offline-timeline-acceptance-2026-10-18-utc).

## Preferred Activity Log source: existing Log Analytics

For Activity Log requests, the capture skill now prefers verified existing
`AzureActivity` data rather than automatically collecting from the direct API.
Use installed `scripts/workspace_activity.py discover`, then `preflight` or
`capture` for the explicitly selected workspace. Supply the assessed subscription/
tenant, existing managed identity, UTC start/end window and private result/output
paths; no user-host runtime is required.

Discovery reads the assessed subscription's current diagnostic settings. An
external destination is a reference until workspace-read scope is approved.
`--approved-workspace-resource-id` authorizes only that named existing workspace;
it does not authorize tenant switching, permission grants or other resource
discovery. Multiple verified candidates require selection.

Preflight binds the actual workspace resource/customer ID and reads current table
plan/schema/retention plus subscription-filtered category/date/caller counts.
An export setting, connector or table alone does not qualify a source. Empty,
denied, unsupported-plan and partial/error query results are **UNKNOWN**, with a
persisted reason and nonzero CLI status. Observed dates and retention metadata
never establish continuous history or global/RBAC completeness.

Workspace capture produces separate capsule **0.5.0**, retaining preflight
provenance and reviewed projected event columns. Fixed KQL filters by assessed
subscription, relevant category and explicit time range before data leaves the
query service. No caller-supplied KQL, arbitrary endpoints, caller IPs, tokens or
unreviewed claims/request bodies. HTTP-200 PartialError is refused, not treated as
complete data. Pages use a 501-row lookahead, 500-row retained keyset pages and
seven-digit timestamp precision. Identical reviewed rows carry a copy count;
unretained field differences cannot be reconstructed.

The maximum requested window is one year; unlike the direct native source,
workspace queries do not assume a 90-day limit. Existing queryable table history
determines availability; archives, retention and exports are never enabled.
The existing 24-hour overlap, revision-aware replay, explicit uncertain-read
retry, 100-page/100-request/20,000-returned-row and byte limits still apply.
If a workspace is unavailable, report the gap and stop. There is **no silent
direct-API fallback** or automatic resumption of an earlier direct checkpoint.

The normal offline verifier/replayer and guarded publisher support 0.5.0 alongside
the existing formats. A saved readiness/discovery JSON is not a completed history
capsule. Installed live acceptance now includes nonempty collection, incremental
parent/overlap bindings and pickup of two specific rows ingested after the prior
capture completed. The latest verified capsule contains 157 Administrative and
two ResourceHealth rows; all 129 prior identities were unchanged. Independent
canonical source bindings and replay of committed Git bytes matched. Earlier
denied/empty readiness results remain recorded, the other export destination was
not followed, and previous capsules/the paused direct checkpoint stayed
byte-identical. See
[installed late-arrival acceptance](runtime-validation.md#installed-late-arrival-pickup-2026-10-15-utc).
Workspace paging is now live-validated across six pages/2,694 rows, including a
ServiceHealth category row; native Resource Graph paging also completed two
pages/577 rows. Historical completeness/backfill, Service Health feed pagination,
complete health-field coverage and causal interpretation remain unvalidated. ResourceHealth category
rows are not proof of platform causation or diagnosis, and two successful pickups
do not guarantee recovery of every late arrival. This implementation uses the selected managed
identity rather than automatically consuming a different tenant's credentialed
connector.

## Existing subscription event-history capture

The existing direct-source history profile/capsule remains **0.4.0**. It
collects existing subscription management/change/health metadata, not only events
for today's inventory. Deleted/replaced resources and subscription-level platform
events remain relevant context. No configuration/check/report changes are made
to the assessment skill.

Run the installed `scripts/network_history.py` with explicit source, scope,
managed identity, capture UUID, private output root and UTC start/end times.
Three independent sources are supported:

| Source | Evidence and limits |
|---|---|
| `activity-log` | Explicit direct-source alternative only; existing Administrative, ResourceHealth and ServiceHealth categories, actor/operation/status and source times. Native retention normally 90 days. No automatic fallback from an unavailable workspace. |
| `resource-changes` | ARG `resourcechanges`; recorded System/Unspecified attribution, change type, authorization action, changed paths, truncation and reviewed before/after values. Native history 14 days. |
| `service-health` | Subscription ResourceHealth/events feed, eventSource, status, impact/update times and regional updates. Explicit lastUpdateTime start-date query; up to one year requested where available, not a guaranteed history ceiling. |

Original requested windows, actual source windows, native retention gaps, failures,
discarded categories and uncollected existing workspace exports are visible.
No exports, retention, diagnostics or alerts are enabled. Sensitive-event details
are never fetched. Actor identifiers and reviewed rules remain private; tokens,
caller IPs, unnecessary claims, request bodies and unreviewed change values are
omitted. An automation identity does not identify its human initiator.

Incremental history uses a verified same-source/scope previous capsule and
24-hour overlap. Known event IDs plus retained-payload hashes preserve revisions;
correlation IDs do not deduplicate events or establish causes. Missing source IDs/
times stay explicit and never receive collection time as an invented event time.
Partial/denied source coverage cannot advance the enumeration watermark.

Limits: 100 pages, 100 requests per invocation, 20,000 returned records, 5 MiB per
member and 20 MiB per source capsule. Exhaustion/uncertain response leaves a
workspace checkpoint for explicit resume; it does not publish falsely complete
coverage. Uncertain request retry remains separately explicit. Existing exported
Log Analytics history beyond the reviewed AzureActivity source, cross-snapshot
comparisons and causal analysis remain outside this increment.

The normal packaged verify/replay and guarded private publisher accept history
capsules without rewriting earlier configuration capsules. New history collection
uses only fixed read-only ARM GETs and a fixed, scoped Resource Graph query POST,
not arbitrary queries or resource writes.

Installed live acceptance now includes **176 Resource Graph change records** and
**five Service Health feed events**, separately verified/replayed and published
to private output branches. The change source's 14-day retention gap is explicit;
only two of 2,837 changed-path occurrences fall within the current reviewed
value-path policy. Other before/after values are omitted, not available for later
analysis. The Service Health feed is distinct from the workspace's unobserved
ServiceHealth category. Neither source establishes impact or causation.
External operator Resource Graph corroboration remains unavailable; a separate
direct read under the existing in-agent identity matched all 176 metadata
bindings. See the
[native source acceptance and access gap](runtime-validation.md#installed-native-change-and-service-health-sources-2026-10-16-utc)
for exact source windows, immutable output bindings and remaining gates.

## Dedicated hostless evidence capture

Ask the installed skill to capture reviewed configuration for one explicitly
approved tenant/subscription using an existing managed identity. Supply a capture
UUID and private workspace output root. It runs through SRE Agent's existing
workspace PowerShell/Az.Accounts and Python runtime; the user needs no local
collector, Azure CLI or host-installed tools.

The new skill retains the same reviewed configuration families as the native
companion: Storage, Key Vault, ACR, Log Analytics and parent-bound NSP/AMPLS
configuration. The packaged JSON catalog is the shared source of field/API policy;
the native companion's catalog fingerprint and earlier capsule formats remain
unchanged. Events, traffic, health verdicts, comparison and further resource
families are outside this increment.

The runtime requires preinstalled PowerShell 7.2+, Python 3.10+ and Az.Accounts
(or the existing WARA module cache). Git and an authenticated connected output
clone are needed only for explicitly requested publication. Missing prerequisites
fail clearly; no dependency installation, interactive login, grants or new
diagnostics are performed during assessment. Authentication is process-scoped
managed identity and does not transfer host credentials.
Workspace terminal tools must be enabled and available on the selected agent;
network-blocked Code Interpreter is not a substitute.

Captured responses are filtered before persistence/conversation output; only
reviewed values and omitted field paths are retained. No arbitrary raw provider
bodies, tags, credential/key values, contact fields or diagnostic contents.
Configuration snapshots are client collection windows, not atomic or universally
complete environment views.

Capsule **0.3.0** records direct ARM GET provenance separately from earlier native
CLI/audit provenance. Verification/replay is offline. Existing captured pages are
reused on resume; an interrupted GET with no retained result requires explicit
`--retry-unconfirmed` and gets a new attempt/time record. Earlier uncertainty is
preserved rather than treated as the same observation.

Read the installed [capture skill](skills/azure-network-evidence-capture/SKILL.md)
and [runtime contracts](skills/azure-network-evidence-capture/reference.md) for
commands and limits. A publisher checks the explicit connected remote, stages
only verified capsule files in a separate worktree, writes a unique branch and
verifies remote commit bytes. Its private-destination flag is operator review,
not a Git-only visibility check; output main and WARA worktrees are preserved.
No evidence is published to the capability/source repository.
The publisher retains full artifact hashes in its receipt file and emits a compact
console summary to avoid terminal truncation. Recover a truncated receipt from
the actual saved file; do not rerun a successful capture/push just to obtain output.
Completed publication/replay has been verified with the installed package on the
WARA-tested agent; see [installed acceptance](runtime-validation.md#installed-hostless-configuration-evidence-acceptance-2026-10-13-local--2026-10-14-utc).
Acquisition checkpoints remain workspace-local in this increment. A lost sandbox
before publication does not have a verified Git-backed partial-capture resume path;
only completed published capsules have the demonstrated remote replay path.

Version `0.13.0` implements **two-stage no-IaC configuration triage with opt-in private
connectivity, service-to-DNS planning and privacy-minimized repeated-zone review**, not a
connectivity certification or full operational-health assessment. Increment 0's
verified runtime record remains in [runtime-validation.md](runtime-validation.md).
For another PC or agent, start with the
[handoff and next implementation plan](../../docs/network-health-handoff.md).

## Start here: first-pass test, then full inspection

The user request is authorization for subscription listing and selected
first-pass component reads, without repetitive approval prompts. Specify the
tenant and run against the actual intended SRE Agent endpoint—not whichever
subscription or browser page happens to be default.

### Local test with an existing SRE agent

Use a fresh collection-only SRE conversation. This development companion needs
the existing authenticated Azure CLI on the **host**, not in the SRE sandbox.
No login, dependency installation, RBAC grant or resource mutation is performed.

```powershell
$env:PATH = 'C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;' + $env:PATH
python tools\network_health_first_pass.py `
  --endpoint 'https://<agent-endpoint>.azuresre.ai' `
  --thread-id '<fresh-collection-thread-uuid>' `
  --tenant-id '<tenant-id>' `
  --run-id '<new-first-pass-uuid>' `
  --output-root '<private-output-directory>'
```

On interruption, repeat the same arguments with `--resume`. Completed resume
verifies original summary bytes and makes no new reads; identity/query changes
fail. Keep selected evidence/checkpoints private and do not clear locks blindly.

The output is `first-pass/<run>/selected-input.json`, `scope-summary.json`,
`scope-summary.md`. It lists visible subscriptions, names/tentative role hints,
component counts/references, peering/hub/spoke/vWAN **signs**, per-scope read
outcomes and external references. It is an initial summary, not the full
assessment's four canonical artifacts. No rules, record values, diagnostics,
public-access settings or effective traffic are collected at this stage.
Discovery is bounded at 100 subscriptions; selected component pages at 100
rows/100 pages per subscription. Partial/unindexed/inaccessible scopes remain
explicit. Peering-array references are capped at 2,000; topology completeness
is never assumed.

### Contoso first pass

Use the customer's actual tenant and agent endpoint, not the lab values above.
Suggested request to the installed skill:

> Perform the initial authorized read-only scope/component pass for tenant
> `<customer-tenant>`. List visible subscriptions and use names only as inferred
> role hints. Summarize standard network components, possible hub/spoke or vWAN
> signs, central DNS references and collection gaps. Do not start detailed
> inspection, mutate resources or repeatedly ask for approval of these reads.
> Use the supported audited first-pass companion; if unavailable, state that
> prerequisite and provide the operator collection path. Default assessment
> preference is private access, with service-specific documented exceptions.

The first-pass bridge is still a development-host companion, not autonomous
in-sandbox acquisition. Once it produces the selected input, a separate
processing thread runs installed
`first_pass.py --input <actual-attachment> --output-root <fresh-root>`.
Keep actual hashes and independently verify saved summary downloads. Names
such as "connectivity", "hub", "prod" or "shared" are hints, not approved roles.
Seeing a spoke/reference does not imply access to all hub/shared subscriptions.

### Access gaps, OBO and supplemental evidence

OBO uses a supported runtime consent flow and an eligible administrator's
existing permissions; it doesn't grant access. Microsoft documents work/school
Entra accounts and SRE Agent Administrator requirements. Required platform
consent is unavoidable, but it is not an extra invented assessment approval.
This companion does not implement a token exchange or claim a verified CLI
OBO endpoint. Never copy tokens/credentials into the sandbox or auto-grant roles.
Use a fresh controlled collection after any supported identity-context change.

If OBO is unavailable, an operator can collect with existing Azure CLI Python
and their own signed-in context:

```powershell
python tools\network_health_first_pass.py `
  --operator-cli-python 'C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe' `
  --tenant-id '<customer-tenant-uuid>' --run-id '<new-operator-run-uuid>' `
  --output-root '<private-operator-output>'
```

This emits selected input labelled operator-not-SRE. It does not change CLI
defaults or authenticate for you. Return original selected input/summary JSON,
not a hand-rewritten narrative. For a single complete supplemental page,
provide an object with `subscriptionId`, `querySha256` (the selected-input's
canonical query hash), `identityDescription`, `collectedAt` (UTC Z) and `payload` (the
original selected ARG JSON). Use the exact summary `supplementalCommand`.
`first_pass.py --input <original-selected-input> --supplement <actual-json>
--output-root <new-root>` checks query/scope/coverage, keeps the original
failed attempt and records operator provenance. Partial pages require the
paged operator collector; do not mark an incomplete response complete.

### Trigger detailed inspection

After reviewing the first pass:

> Run the full supported read-only configuration inspection for workload
> subscriptions `<IDs>` and DNS-host subscriptions `<IDs>`, using the existing
> scoped collector. These reads are authorized. Keep private-preferred baseline
> and explicit service exceptions separate from observations; preserve missing
> evidence, use actual supplied intent only, and publish verified reports.

Run the normal `tools\network_health_sre.py --include-dns-paths` for each
workload with fresh thread/run and explicit `--dns-hosting-subscription-id`.
The summary includes a command template. Do not infer final role assignments or
automatically follow external references. This is the full **supported MVP**,
not every specialist/telemetry/effective-behavior domain or a health certificate.

### Private-preferred, public by documented exception

Both initial and detailed outputs preserve the DECLARED owner-requested baseline.
No public exposure or customer policy compliance is inferred from this preference.
Exceptions require service resource ID, owner/reason and actual alternative
control evidence; none are automatically accepted.
**Azure Monitor workspace is not Log Analytics workspace.** Current Microsoft
Learn's Azure Monitor NSP guidance supports Log Analytics and states Monitor
workspace collection/querying isn't supported by that integration. Monitor
workspaces have their own Private Link guidance. NSP association/enforcement/
profile/rules and service support must be checked before accepting any alternative.
Presence of an NSP/AMPLS/private endpoint or a missing DNS zone alone is not
proof of enforced access, private-only use or a defect.

References:
[SRE permissions/OBO](https://learn.microsoft.com/azure/sre-agent/permissions),
[Azure Monitor NSP](https://learn.microsoft.com/azure/azure-monitor/fundamentals/network-security-perimeter),
[Monitor workspace Private Link](https://learn.microsoft.com/azure/azure-monitor/fundamentals/private-link-azure-monitor-workspace).

## Detailed capability scope

### Opt-in service access-control evidence

For bounded NSP configuration evidence, use `--include-nsp`. It includes the
service-ARM/DNS prerequisites below and adds four scoped API 2024-07-01 lists:
perimeters, profiles, resource associations and access-rule metadata.
Acquisition 1.8.0/input-schema 0.9.0/check catalog 1.12.0 execute 30 operations
and 16 checks without optional intent/time (up to 18 with both).
`NET-NSP-001` 1.0.0 produces `nspConfigurationReview` in canonical assessment
JSON and deterministic executive/engineering views.

The collector follows only actual in-workload perimeter/profile parents,
preserving validated ARM pagination and bounded parent/page/row budgets.
External target/profile references are never followed. Recorded raw mode,
provisioning/issue flags, profile references, collection outcomes and rule
direction/selector counts are configuration evidence, not an enforcement test.
Enforced, Learning/Transition, Audit, unknown modes and incomplete provisioning/
profile/rule evidence remain distinct. SecuredByPerimeter with no observed
scoped association is an evidence gap, not a defect or global absence claim.

Rule values (CIDRs, FQDNs, subscription selectors, tags, emails and phone numbers)
are omitted. Missing arrays are UNKNOWN, never zero; retained rule counts are
not full coverage unless recorded parent-list coverage supports it. No active
tests, logs/diagnostic enablement, resource changes or automatic exception
approval are introduced. AMPLS, rule semantics, service synchronization, actual
client behaviour and operational enforcement remain unassessed. The older
indexed/direct service-control modes retain their behaviour.

To integrate direct ARM service-control evidence and source reconciliation,
use `--include-service-arm` instead of the indexed-only flag below. It includes
service-access/DNS-path prerequisites and adds three management GET operations:
Storage API 2023-05-01, Key Vault and ACR API 2023-07-01. Only actually
inventoried supported service IDs in the selected workload are read; separate
DNS-host allowlists do not authorize service reads. Maximum 100 parents per
family, with explicit gaps for unread/failed/invalid/budget-limited evidence.

Acquisition 1.7.0/input-schema 0.8.0/check catalog 1.11.0 execute 26 operations
and 15 checks without optional intent/time, up to 17 with both. The new
`NET-SERVICE-SOURCE-001` 1.0.0 produces `serviceControlReconciliation` in assessment
JSON and deterministic executive/engineering views. Direct reads retain separate
configuration objects and per-parent API/read-completion/outcome metadata;
indexed observations and the indexed-only `serviceAccessReview` are not overwritten.

Every field shows both source values and one of observed-match,
different-observed-values, both-unavailable, indexed-unavailable,
direct-unavailable, direct-not-collected or not-applicable. A match requires
two non-null values; absence of a field is never matching zero. Differences
can reflect API shape, collection times, index freshness or changes, not
automatically defects. Read the source matrix alongside the declared baseline
comparison before planning changes. No active tests, credentials/rule values,
resource mutation, automatic exception acceptance or scope expansion is added.
The indexed-only flag and all historical modes retain their original behaviour.

For a separately requested public/private service-control review, add
`--include-service-access` to the existing detailed host bridge command. It
includes the DNS-path/private-connectivity/planning prerequisites; no new
deployment mechanism, active test or Azure write is introduced.

Acquisition 1.6.0 still has 23 operations, but the mapped-service inventory now
selects privacy-minimized settings for **Storage Accounts, Key Vault vaults and
Container Registries**. Input/schema 0.7.0 produces `serviceAccessReview` in
assessment JSON and both deterministic Markdown reports. The new
`NET-SERVICE-ACCESS-001` check has version 1.0.0; check catalog 1.10.0 executes
14 checks without optional intent/time, up to 16 with both. Older modes keep
their existing queries, selected properties and check sets.

The matrix separates publicNetworkAccess, the service-specific firewall default
action, trusted-service bypass, IP/VNet/resource-instance rule counts, and scoped
approved PE group IDs. Rule values, IP ranges, identities and credentials are
not retained. Other mapped service families, including Monitor and Log Analytics,
remain explicitly unassessed. Missing or future setting values remain UNKNOWN:
documented service defaults are never substituted for missing evidence.

Enabled/Allow and Enabled/Deny are **P2 owner/exception review**, not automatically
defects or publicly reachable/anonymous services. Deny is selected-network public
endpoint configuration, not private-only use. Disabled is a configuration
observation, not a private-only certificate: trusted-service bypass remains
relevant, including Key Vault and ACR. SecuredByPerimeter retains an explicit
enforcement-evidence gap; no NSP/AMPLS exception is accepted without separate
association/profile/rule/enforcement and customer approval evidence.
Service data-plane authorization, actual DNS/traffic/reachability, all required
subresources and permission-wide completeness remain unverified.

Collect only one explicit subscription's context, VNets/address spaces/subnets/
peerings, configured route tables/routes/subnet associations, NSGs/rules/subnet
associations and minimal NIC/IP attachment references. Resource-group/region
context comes from the selected resource metadata; it does not imply a resource
group has the same region as its resources.

Explicitly approved `--include-private-connectivity` adds selected Private
Endpoints/connections and Private DNS zones/zone groups/VNet links. DNS records,
client resolution/forwarding, service public access and effective private
connectivity remain uncollected. Azure Firewall, VPN/ExpressRoute/vWAN, NAT, load balancers/
Application Gateway, telemetry, effective routes/security, IaC and architecture
documents are deferred. No resource changes, remediation, diagnostics/log/monitor
enablement, deployments, IaC generation or external publication.

## Marketplace and prerequisites

Use this repository's current Marketplace registration and install only
`azure-network-health`. Both repository manifests list it. Installation is
commit-pinned; keep auto-update off for prototype trials. Branch `/tree/` source
URLs failed the real clone test; the tested path uses the default branch.

The plugin contains one skill and no custom agent, scheduled task, MCP server or
knowledge-base extra. Installing it does not install or configure connectors.
Prerequisites are separate:

- SRE Agent Author/Administrator access for installation.
- Azure read permissions for the explicitly selected subscription.
- Native `RunAzCliReadCommands`, installed-file access, `RunInTerminal` and
  `SaveFileToBlob` in the target runtime.
- Python with existing `jsonschema` support; no automatic sandbox package install.
- A development host with Azure CLI and access to the SRE data plane.

The direct skill upload scripts send only `SKILL.md`; they are not a supporting-
file delivery test. The existing agent can expose unrelated tools; this skill
does not globally constrain its parent. Verify actual operation traces.

## Proven runtime constraint and development transport

**Hostless WARA-style route now has a bounded positive spike:** on the owner's
WARA-tested agent, `RunInTerminal` used existing PowerShell/Az.Accounts managed
identity to read one scoped resource, serialized selected evidence directly,
published two files through the connected private output repository, and replayed
from committed bytes in a fresh conversation without Azure recollection.
See [the hostless feasibility record](runtime-validation.md#wara-style-hostless-feasibility-2026-10-13).
This is not yet an installed hostless network-skill pass or the broader collector.
It uses the workspace execution environment, not network-blocked Code Interpreter.
The tested WARA cache and repository credentials must be verified on other agents.
Do not transfer host credentials, fall back to interactive login or model-rewrite
native results. Existing host companions remain the proven full-profile path
until the packaged replacement passes its own runtime gates.

The sandbox CLI lacks Resource Graph support. Native Azure read tools execute
elsewhere and do not provide a proven lossless local file output. Do not paste
resource rows through the model, install an extension, log in, or copy tokens
into the sandbox.

[tools/network_health_sre.py](../../tools/network_health_sre.py) is the optional
development bridge. It:

1. Drives exact approved native reads from the catalog, one command per page.
2. Retrieves actual structured `azCliExecution.output` without model rewriting.
3. Handles continuation/count metadata and explicitly records failures/partiality.
4. Keeps only allowlisted configuration and uploads that selected envelope using
   the app's conversation attachment API.
5. Lets the Marketplace-installed helper normalize/check/render the exact input.

The bridge token remains on the development host. Azure collection uses the
native SRE read tool's identity and records native execution IDs. This is a
development transport, not a claim of autonomous standalone skill acquisition.
When no bridge or approved input exists, the skill reports the missing prerequisite.

## Four-file run bundle

```text
runs\<run-id>\
  observed-network.json
  assessment.json
  network-assessment.md
  network-evidence.md
```

Observation JSON has no interpreted findings. Assessment JSON records each
check's ID/version, severity, priority/action type, evidence and recommended deep
dive. Markdown views are deterministic functions of assessment JSON alone.
Checks do not certify packet delivery or infer public reachability from NSG rules.

The six checks cover addressing overlap, peering state, contextual subnet NSG
association absence, configured route-table association, next-hop consistency
and collection/coverage gaps. Lack/presence of NSGs or route tables is not
automatically defective/healthy. Missing fields are UNKNOWN.

Successful collection covers accessible indexed results only. Permission-wide
completeness and index freshness remain unverified. A valid partial bundle is
not a successful acquisition or a healthy assessment.

### Bundle publication and recovery

The helper reserves `runs\.<run-id>.pending` exclusively, writes all four files,
flushes them and verifies their hashes by reading back the bytes. Only then does
it rename that sibling directory to `runs\<run-id>`. Consumers must read only
canonical run directories, not pending work. Existing final or pending paths are
never overwritten by another cooperating helper invocation.

Write, sync, integrity and publication errors propagate explicitly. Ordinary
failures remove only this invocation's staging files and directory, allowing a
retry with the same unchanged selected input and no repeated Azure acquisition.
An abrupt process kill may leave pending evidence; a later invocation refuses it.
Confirm no writer is active and resolve only that exact interrupted staging
directory through an authorized operator before retrying. Do not automatically
delete it, infer completion or merge run identities.

This is atomic directory visibility on the same filesystem, not proof of
power-loss durability, protection against unrelated processes modifying the
output directory, acquisition resumption or atomic conversation upload. If an
upload fails after publication, preserve the completed bundle and report the
upload failure; rerunning processing will correctly refuse overwrite.

Capability is `0.2.0`. The default nine-operation/six-check mode preserves
input/schema `0.1.0`, acquisition `1.0.0` and check catalog `1.2.0`.
Opt-in private mode uses input/schema `0.2.0`, acquisition `1.1.0` and check
catalog `1.3.0` (eight checks). Priority stays `1.1.0`; NET-ADDR-001/
NET-PEER-001 stay `1.1.0`, remaining/new private checks are `1.0.0`.
Historical assessments keep their recorded contracts/catalogs/policies and
capability `0.1.0` through `0.1.6` provenance without relabeling.
A pinned Marketplace installation does not update
until explicitly refreshed and reinstalled.

## Offline evidence capsule pilot (development companion)

### Reviewed native capture (development companion)

`tools\network_health_snapshot.py` captures a broader reviewed profile through the
existing **native SRE read transport**, not operator ARM responses. The host needs
existing SRE data-plane authentication and a fresh controlled collection thread.
This is still a host-controlled development companion, not autonomous installed-
skill acquisition.

```powershell
python tools\network_health_snapshot.py `
  --endpoint '<intended-agent-endpoint>' --thread-id '<fresh-controlled-thread>' `
  --tenant-id '<approved-tenant-uuid>' --subscription-id '<approved-subscription-uuid>' `
  --run-id '<new-capture-uuid>' --output-root '<existing-private-directory-outside-repo>'
```

Resume interrupted collection with the same arguments and `--resume`. Accepted
native reads are reconciled without reposting; completed-source resume is offline.
The capture begins with an explicit subscription/tenant context read. It then
discovers Storage, Key Vault, ACR and Log Analytics resources, GETs each discovered
resource, and enumerates/GETs NSP and AMPLS configuration over discovered parents.
References to other resources/subscriptions are retained but never authorize
following those references.

The versioned retention profile includes reviewed network access/rules, TLS and
authentication toggles, protection/retention/policy settings, needed identity/key
**references**, private-connection settings, SKU/location and recorded system
metadata. It does not fetch secret/key values, credentials, tokens, tags, contact
data, diagnostic contents or arbitrary properties. Projection occurs in the
native CLI query before structured output is retained. Source-key metadata
distinguishes missing fields from explicit null and records omitted field paths
without values. Missing values never receive documented defaults.

Bounds: 1,000 rows per response or reviewed array, 100 pages per operation,
500 planned operations and 100 native reads per invocation. A read-invocation
limit pauses the checkpoint for explicit resume, not a fresh full collection.
Other exhausted limits or invalid evidence fail explicitly and retain the partial
checkpoint. The existing 5 MiB member/20 MiB capsule budgets still apply.
The collection-only audit retains native execution IDs and exact-command policy
bindings; its visibility boundary is structured thread fields, not universal
tool enforcement or signed source authentication.

After a completed capture, the source is under
`<private-root>\snapshot-acquisition\<run-id>\evidence`. Seal it with the same
capsule CLI below. Native profile 1.0.0 produces capsule **0.2.0**, while legacy
selected-inventory profile 1.0.0 remains capsule **0.1.0**. Both verify/replay
offline; old capsules are not migrated, rewritten or relabelled. Native replay
retains source-specific observations, failures, field omissions and original
client collection times. Empty root lists do not validate nonempty child paths,
external scopes, operational enforcement, traffic or health.

No new event collection, diagnostic enablement, resource writes, scheduled
execution, canonical assessment/check changes or installed asset changes are
introduced by this mode. New retention fields/APIs need explicit profile review
and versioning.

### Sealing, verification and replay

`tools\network_health_capsule.py` seals an **already collected, reviewed
selected-inventory or native snapshot profile** into a private capsule and replays resource/evidence/
coverage JSON without Azure reads. It is not a generic file archive, a broader
collector, or a Marketplace-installed skill asset. Existing checkpoints, schema
versions and the canonical four-report assessment contract are unchanged.

The legacy input has `evidence-index.json` and its ten indexed selected-
inventory JSON members: ARG metadata; Storage, Key Vault, ACR and Log Analytics
selected ARM results; NSP/AMPLS root results; the Key Vault continuation and failed
attempt; and the inventory summary. The codec rejects other layouts, unexpected
fields, scope/API mismatches, duplicate JSON keys and invalid hash bindings.
The separate reviewed native profile uses `capture-index.json`, selected page
members and `native-audit.json`. Review a new retention profile before supporting
another input producer.

```powershell
python tools\network_health_capsule.py seal `
  --source '<reviewed-selected-inventory-directory>' `
  --output-root '<existing-private-directory-outside-the-repository>' `
  --capsule-id '<new-uuid>'

python tools\network_health_capsule.py verify `
  --capsule '<private-directory>\<capsule-uuid>'

python tools\network_health_capsule.py replay `
  --capsule '<private-directory>\<capsule-uuid>' `
  --output '<private-directory>\<new-replay-name>.json'
```

Version 0.1.0/profile 1.0.0 retains the eleven imported JSON members byte-for-byte.
Limits are **5 MiB per member, 64 KiB for the manifest, 20 MiB total including the
manifest, and 1,000 rows per response or rule array**. Existing destinations are
not overwritten; publication verifies a private staging directory before rename.
Member/manifest integrity, exact membership, reviewed field shapes and original
scope are checked before every replay. Links/reparse points are rejected.

Replay is deterministic, preserves raw selected rules, null/unavailable fields,
original collection times, distinct source observations and collection failures.
It does not substitute seal/processing time for observation time. The replay
receipt records processing time separately. Change, Activity Log, Resource Health,
Service Health and historical-export sources are explicitly **not collected**.
The output is not `observed-network.json`, a health assessment or a public-access
verdict, and cannot be treated as a complete input to the four-report workflow.

Capsule immutability is a no-overwrite/verification convention, not tamper-proof
storage. Hashes bind retained bytes, not source authenticity; an unsigned manifest
can be replaced. The operator must provide and review storage permissions and
encryption as needed. The codec enforces an external storage location, but does not
configure or attest ACLs/encryption. Keep identifiers/rules private and out of
reusable source assets. These modes do not close nonempty NSP/AMPLS live gates.
The native mode implements a reviewed subset of configuration capture; event
collection, comparison and assessments from these snapshots remain separate work.

## Run locally

From the repository root:

```text
python -m pip install -r plugins\azure-network-health\requirements-dev.txt
python -m unittest discover -s plugins\azure-network-health\tests -v
python tools\validate.py
python plugins\azure-network-health\skills\azure-network-health-assessment\network_health.py --subscription-id <UUID> --run-id <UUID> --output-root <private-output-directory>
```

Local collection uses the developer's existing CLI identity, with dynamic
extension installation disabled. The runtime calls only catalogued reads.
Input-only mode executes no Azure calls:

```text
python network_health.py --input <selected-collection-envelope.json> --output-root <private-output-directory>
```

To drive native SRE collection, first create a fresh controlled thread with MCP
or the supported app API; do not reuse an unrelated customer conversation:

```text
python tools\network_health_sre.py --endpoint <approved-SRE-origin> --thread-id <UUID> --subscription-id <UUID> --run-id <UUID> --output-root <private-output-directory>
```

The bridge returns the attachment metadata and exact input hash only after
downloading and verifying the uploaded selected-input bytes. Invoke the
installed skill in a **separate processing thread** with an unchanged copy of
the selected input and its hash. Keep the controlled collection thread idle:
loading skills or using file/terminal/other tools there violates the collection
protocol. Do not change a checkpoint's bound thread to transfer it. The developer
uploads the exact selected input to the processing thread through the existing
attachment API; that thread runs installed code unchanged, attaches the four
outputs and reports limitations. Compare downloaded bytes with local deterministic
results. A path in chat is not retrieval proof.

### Resume a selected-input upload

After local bundle completion, the bridge stores private recovery files under
`<output-root>\network-health-transport\<run-id>\`: `selected-input.json` and
`state.json`. State format `1.0.0` binds the endpoint, thread, selected
subscription, run, input hash, original artifact hashes and upload phase. It
contains no tokens or full raw responses. The four-file canonical bundle remains
unchanged; recovery files are gitignored but must still stay outside public
sync/source control and follow the same access/retention controls as evidence.

Reuse the original explicit endpoint, thread, subscription, run and output root:

```text
python tools\network_health_sre.py --endpoint <original-origin> --thread-id <original-UUID> --subscription-id <original-UUID> --run-id <original-UUID> --output-root <original-private-output-directory> --resume-upload
```

Recovery checks selected-input identity/hash, normalizes it in memory to verify
the existing observation, validates contracts and cross-artifact references,
and checks all four original artifact hashes. It does not recollect Azure,
reassess findings, regenerate/write reports or silently adopt another run.
Historical recorded capability versions are preserved when selected
configuration still matches the current normalizer/contract. Changed
normalization or moved bundle paths require explicit review, not relabeling.

- **Before dispatch:** a preparation/readiness failure leaves the upload retryable.
- **Receipt saved:** retry verifies that existing attachment's downloaded bytes;
  it does not send another POST. Expired/inaccessible/corrupt downloads remain
  explicit failures, not permission to recreate an attachment.
- **Dispatched without a durable receipt:** acceptance is UNKNOWN. The tested
  service has no proven attachment inventory; the bridge refuses a blind retry.
  Supply an actual service receipt containing `fileId`, `fileName`, `fileSize`,
  `contentType` and `downloadUrl`, as one object or a one-element array:

```text
python tools\network_health_sre.py --endpoint <original-origin> --thread-id <original-UUID> --subscription-id <original-UUID> --run-id <original-UUID> --output-root <original-private-output-directory> --resume-upload --attachment-receipt <private-actual-receipt.json>
```

Never invent receipt metadata or infer nonacceptance from an HTTP error. An
operator-supplied receipt is not trusted as proof until its downloaded bytes
match. Downloads are bounded to the selected-input budget and the exact
endpoint/thread; redirects and signed/query-bearing URLs are rejected before
credentials are sent or metadata is saved.

An exclusive `.upload.lock` prevents overlapping upload-recovery invocations.
Abrupt termination can leave that lock, an incomplete checkpoint or an ambiguous
phase. Confirm the writer stopped and resolve only the exact private checkpoint
through an authorized operator; never automatically clear locks or restart
collection. Older bridge runs without a recovery checkpoint cannot be resumed
by guessing input/receipts from report prose. Recovery of later report-save
operations remains separate work.

### Resume interrupted acquisition

New bridge collections reserve
`<output-root>\network-health-acquisition\<run-id>\` before any native reads.
Its private `state.json` checkpoints each processed page: selected rows,
counts/issues, continuation state, completed operations, original collection
times, native execution IDs and the exact outstanding nonce-bearing request.
State format `1.0.0` binds endpoint/thread/subscription/run, page size, capability
version and catalog fingerprint; progress has an integrity hash. Full raw
responses and credentials are not saved. Opaque continuation tokens and request
metadata are retained only because safe recovery needs them; treat them as
customer-internal alongside selected evidence.

```text
python tools\network_health_sre.py --endpoint <original-origin> --thread-id <original-UUID> --subscription-id <original-UUID> --run-id <original-UUID> --output-root <original-private-output-directory> --resume-acquisition
```

The saved page size is reused; if `--page-size` is provided, it must match.
Completed operations/pages are skipped. An outstanding accepted read is
reconciled against original native execution/message history and decoded without
reposting the command or model rewriting. Terminal permission/capability/
execution failures stay explicit and are not automatically retried. Missing
acceptance evidence, changed identity/catalog/helper version, duplicate/
unexpected executions or corrupted progress stop the run rather than fabricate
absence or restart from page one.

Only after all selected catalog operations have explicit outcomes does normalization/
assessment proceed. A completed existing bundle is compared in memory and
never rewritten; the separate receipt-verified upload recovery is then reused.
If upload acceptance is ambiguous, use `--resume-upload` with its actual receipt,
not another collection. Resume modes are mutually exclusive.

The `.acquisition.lock` is obtained before loading progress, preventing
overlapping fresh/resumed collectors for the same output/run. Normal exceptions
release it; abrupt process termination may leave it or an incomplete initial
checkpoint. An authorized operator must confirm the writer stopped before
resolving that exact path; the bridge never automatically removes stale locks.
Acquisition checkpoints are bounded to 10 MiB and selected input to 5 MiB;
exceeding either limit is an explicit failure, not a truncated success.

Resume needs retained native history and a still-valid continuation. It preserves
the original start times and records later completion, so the resumed result is
not a fresh point-in-time snapshot. Count drift remains an evidence gap.
Permission-wide completeness/index freshness remain UNKNOWN. Runs made before
this checkpoint feature cannot be reconstructed from reports or merged into a
new run. The audit covers paged structured Azure CLI execution history within
its message budget, not universal enforcement of every parent-agent tool.

## Collection audit policy

The development bridge's audit policy `1.0.0` now requires **collection-only
threads**. The inspected native API exposes 14 execution/result/query fields.
Before native submissions, during reconciliation/polling and at final audit,
the bridge requires those fields to be present and rejects non-null activity on
anything except approved structured Azure CLI executions. Empty objects/arrays
and false values are not silently treated as absence. Unknown non-null
execution/result/query fields and malformed/incomplete/duplicate native records
also stop the run.

After an idle, fully paged successful audit, the bridge atomically saves
`network-health-acquisition\<run-id>\audit.json` beside acquisition state. The
metadata-only record contains scope/thread, audit time/policy, message and
surface-presence counts, native execution IDs, a command-policy hash and explicit
visibility limits—not raw commands, tool outputs or credentials. Normal
collection/acquisition-resume CLI success returns `collectionAuditPath`; this
companion record does not add a fifth canonical report file.

This is visible-deviation detection, **not prevention or universal parent-tool
enforcement**. A null field means no activity exposed there, not proof that
unexposed actions did not occur. Unclassified null result fields are listed;
missing required fields are an explicit visibility failure. No operation is
rolled back or remediated.

This is an intentional host-transport protocol change approved by the user.
Acquisition audit/resume rejects a collection thread later used for processing
even when its terminal/file operations were legitimate. Use a fresh separate
processing thread instead. Receipt-only `--resume-upload` does not reclassify
those operations as approved collection or repeat resource reads. Older runs
without the new audit record are not retroactively certified. The installed
capability/check/schema versions were unchanged by that host-only increment at
`0.1.3`/their recorded versions; it did not auto-update the pinned plugin.
The later report-save recovery capability is separately versioned `0.1.4`.

## Report integrity

Dynamic report text is escaped as literal Markdown, not interpreted as links,
emphasis or code. Selected evidence remains unchanged JSON inside fenced blocks;
literal link/HTML syntax in those blocks is not treated as report navigation.
Verification requires the exact generated finding/evidence/collection links,
including target document and multiplicity, plus complete unique anchors.
Unsafe anchor identifiers and missing/duplicate/changed links fail explicitly.

Both current views show schema, capability, check-catalog and priority-policy
versions from assessment JSON. The engineering view lists all executed
check IDs/versions, including checks without findings. Version provenance and
check rows are verified, not filled with runtime guesses.

This `0.1.3` change affects presentation/verification only: observation semantics,
findings, severity/priority logic and all six check versions are unchanged.
Historical reports still verify without adding newer metadata or relabeling
their producer version. Existing upload recovery therefore does not rewrite old
reports. New renderings can differ in formatting across helper releases; use
the pinned helper when comparing historical report bytes.

## Opt-in Private Endpoint + Private DNS configuration

For service planning and separately scoped central DNS, see the next section.
Private-only enrichment remains fourteen operations/eight checks with its
existing 0.2.0 input/schema contract.

The scope must be explicitly approved; add `--include-private-connectivity` to
a fresh bridge or local collection command:

```text
python tools\network_health_sre.py --endpoint <approved-origin> --thread-id <fresh-collection-thread> --subscription-id <selected-subscription> --run-id <new-run> --page-size 50 --output-root <private-output> --include-private-connectivity
```

The default does not expand. The new mode has fourteen operation outcomes:
the original nine plus endpoint metadata, automatic/manual connection
configuration, private DNS zones, VNet links and zone groups. Zone-group
children are not indexed in Resource Graph; exact read-only CLI lists are
derived only from collected endpoint parents. Group resource type/parent scope
comes from collection-operation context; group location stays unavailable.
Each successful group-list page records its parent even when zero rows were
returned. Failed/unattempted/rejected evidence never becomes absence.

Parent requests use the existing bounded page budget (100 per operation);
large/partial parent sets retain explicit gaps rather than broaden scope or
truncate silently. Acquisition resume restores the saved opt-in mode; changing
it is rejected. Historical inputs/default contracts remain supported.

Only selected IDs/state/counts/subresources/zone references are retained.
Connection descriptions/request messages, service secrets, full responses and
DNS record-set payloads are omitted. Factual joins use `attachedToSubnet`,
`targetsPrivateLinkResource`, `referencesPrivateDnsZone`, `dnsLinkedToVNet`
and retained containment—not `dnsResolvesTo` or demonstrated traffic.

NET-PRIVATE-001 reports incomplete/unknown connection evidence and contextual
pending/rejected/disconnected/provisioning state. Aggregated Approved information
is configuration-only. NET-PRIVATE-DNS-001 joins selected zone groups/zones/
completed endpoint-VNet links, explains unavailable/partial/external evidence
and contextual successful-empty lists. A direct endpoint-VNet link is not a
blanket DNS requirement; custom/manual/shared forwarding architectures can be
valid and require evidence rather than automatic changes.

Even approved endpoints with configured DNS chains leave an explicit gap for
A/AAAA records, client resolution, forwarding/resolvers, effective routing/
security/traffic and target service public access. Private Endpoint existence
does not prove the service is private-only. No active tests, public-access
changes, monitoring or specialist execution are performed.

## Opt-in service-to-DNS planning and repeated-zone review

```text
python tools\network_health_sre.py --endpoint <approved-origin> --thread-id <fresh-collection-thread> --subscription-id <workload-subscription> --run-id <new-run> --page-size 50 --output-root <private-output> --include-dns-planning --dns-hosting-subscription-id <approved-dns-host-subscription>
```

`--include-dns-planning` includes private enrichment and one bounded ARG
service-resource metadata operation. It selects only IDs/names/types/RGs/
locations for resource types in the checked-in
[commercial mapping](skills/azure-network-health-assessment/private-dns-services.json).
No service properties, secrets, public-access settings, keys or DNS records
are collected. The default nine-operation mode and private-only mode are
unchanged. Planning uses input/schema 0.3.0, acquisition 1.2.0, ten checks/
catalog 1.4.0 and the existing priority policy 1.1.0.

Workload scope stays one subscription per run. Repeat
`--dns-hosting-subscription-id` for up to twenty explicitly approved DNS-hosting
subscriptions, including the workload subscription if it hosts DNS. Workload
DNS is always retained; additional hosts collect **only zones and VNet links**.
No subscription enumeration, automatic reference-following or workload/
endpoint expansion occurs. Repeat explicitly scoped runs for additional
workload subscriptions; these are not silently merged into tenant-wide claims.
Without a host allowlist, central DNS coverage is unknown. A permission failure,
rejected row or incomplete host remains an explicit outcome; even successful
queries cover accessible indexed results only. The allowlist and modes are
bound into acquisition checkpoints and restored on resume; changes fail.

Assessment JSON includes `dnsPlanning`, with version/hash/source revision,
scope/collection outcomes, all commercial service/subresource/zone options,
observed service and matching target/subresource connection IDs, per-zone name
matches and zone inventory/associations. Engineering Markdown renders the same
matrix, including available choices with no observed services. Service feature/
SKU/API use and customer private-access intent remain unverified: Cosmos APIs,
Foundry endpoint suffixes, Redis offerings, storage/secondary subresources and
region/configuration templates are not all mandatory requirements. ACR regional
data and App Service SCM are records within existing zones, not extra zones.
The catalog is a pinned snapshot, not fetched or silently updated during audits.
Historical/retired service entries do not establish current deployment support.
Sovereign-cloud mappings are not implemented.

NET-DNS-PLAN-001 separates service inventory, observed endpoint connections
and observed zones. "No observed matching connection" is limited to this
workload subscription; consumers can create endpoints elsewhere. "Zone not
observed in accessible scopes" does not establish global absence, or that its
absence caused a service not to use endpoints. Custom/external/shared DNS may
be valid. Name matches do not prove associations, resolution or private access.

NET-DNS-REPEAT-001 highlights the same case-insensitive zone name on distinct
resource IDs, across approved hosts/RGs, with retained VNet-link and endpoint
zone-group references. This is P2 contextual ownership/cleanup review, not an
automatic defect or deletion recommendation. Separate environments/tenants/
DNS views can intentionally duplicate names. Records, owners, forwarders and
cross-subscription consumers must be validated before consolidation; no zone
is certified unused or safe to delete.

Only the usual four canonical artifacts are written. Observations remain
facts/evidence; planning interpretations live in assessment JSON and its
deterministic reports. Acquisition/report recovery remains the same.

## Opt-in repeated-zone record-set metadata

```text
python tools\network_health_sre.py --endpoint <approved-origin> --thread-id <fresh-collection-thread> --subscription-id <workload-subscription> --run-id <new-run> --page-size 50 --output-root <private-output> --include-repeated-zone-metadata --dns-hosting-subscription-id <approved-dns-host-subscription>
```

This mode includes DNS planning and adds one repeated-zone metadata operation
per explicitly approved scope. Metadata reads are derived only from distinct
collected zones sharing a normalized name; singleton zones are not read.
Default/private-only/planning-only behavior stays unchanged. Metadata mode
uses input/schema 0.4.0, acquisition 1.3.0 and eleven checks/catalog 1.5.0;
the priority policy stays 1.1.0.

Exact `az network private-dns record-set list` projections return total count
and at most 2,000 selected rows containing only `type`/`ttl`. The CLI may fetch
full records internally, but its selected native output and persisted evidence
omit record-set names/IDs and all record values. Full record responses are
never persisted by the collector. Parent list calls are bounded at 100 per
operation/scope; count mismatches, unknown/invalid type or TTL, failed permissions
and incomplete repeated-zone discovery are explicit coverage gaps.

Observation configuration objects contain collector-derived summary IDs
(not actual Azure child-resource IDs), reported/selected record-set counts,
A/AAAA/CNAME/MX/PTR/SOA/SRV/TXT set counts, unavailable-type/TTL counts and
min/max TTL in seconds. Counts are **record sets**, not individual records or
IP values; TTL ranges cover available selected TTLs only. Checkpointed input,
assessment and reports retain aggregates, not per-record rows.

NET-DNS-META-001 surfaces contextual review plus incomplete coverage. The
engineering report adds a per-zone table beside links/zone-group associations.
Uncollected metadata is UNKNOWN, never zero. Zero sets or SOA-only results do
not prove an unused zone. Equal summaries do not prove equal records or shared
clients; different counts/TTLs may be intentional. Names and values are omitted
by design, so record equivalence cannot be evaluated.

No cleanup, consolidation or deletion is performed or certified safe. Owners,
record content, forwarding, all cross-subscription consumers and effective
resolution remain unverified. Resume restores the saved mode/explicit hosts
and reconciles accepted native reads without blindly repeating them. Old
acquisition states are not silently upgraded across helper versions.

## Opt-in configured DNS resolver and forwarding paths

```text
python tools\network_health_sre.py --endpoint <approved-origin> --thread-id <fresh-collection-thread> --subscription-id <workload-subscription> --run-id <new-run> --page-size 50 --output-root <private-output> --include-dns-paths --dns-hosting-subscription-id <approved-dns-host-subscription>
```

Explicit DNS-path approval includes prior metadata/planning/private reads and
seven new operations: separate VNet DNS configuration objects, resolver/
ruleset roots, inbound/outbound endpoints, forwarding rules and ruleset VNet
links. The workload has 23 collection outcomes/thirteen checks. Additional
DNS-hosting subscriptions retain only their previously approved zone/link/
repeated-metadata reads; no resolver/workload scope expansion is inferred.
Old modes keep their contracts and operation sets. DNS paths use input/schema
0.6.0, acquisition 1.5.0, check catalog 1.7.0 and priority policy 1.1.0.

Resolver roots/children use extension-free exact ARM `az rest --method get`
lists at the commercial management origin, stable API 2022-07-01. Selected
lists are bounded at 2,000 selected rows per page and 100 pages per operation/
scope, including all child parents and their pages. Current ARM continuation
is validated against the original HTTPS management origin, exact resource
path, subscription and stable API version. Only a bounded opaque skip token
and API-version query are permitted; credentials, signed URLs, nextLink URLs
pointing to different resource paths, traversal and extra parameters are rejected.
The collector does not interpret tokens or infer authorization from them.
Malformed/missing/repeated continuations, permission failures, changed/rejected
rows and page-budget exhaustion remain explicit **partial gaps**, never
complete inventory or absence evidence. Parent discovery failures retain
not-attempted child outcomes, never absent endpoints/rules.

VNet DHCP DNS-server defaults are separate configuration objects, preserving
VNet address/topology properties. Known empty arrays mean Azure-provided DNS
configuration; unknown fields are not empty arrays. Selected resolver-VNet,
endpoint-subnet, ruleset-outbound and ruleset-VNet references remain factual
configuration relationships. Inbound endpoints have selected IPs/subnets;
outbound endpoints have a subnet, not an invented private IP.

Forwarding rules retain state, domain suffix and ordered target-IP/port arrays.
Missing ports/addresses are not silently defaulted or independently flattened
into incorrectly paired targets. Selected addresses and domain suffixes belong
only in access-controlled engineering JSON/evidence, not public or executive
output. Tags, arbitrary metadata, secrets and full responses are omitted.

NET-DNS-PATH-001 and the deterministic `dnsPaths` view expose configured
objects and missing/unsupported field gaps. They do not establish actual
client/NIC/OS DNS-server selection, forwarding rule choice, target availability,
cached answers or successful resolution. No resolver/ruleset rows in the
workload scope does not establish no custom/on-premises/external DNS. Customer
DNS-server internals, overrides, external consumers and forwarding outside
scope remain uncollected. No active lookup, logs/diagnostics enablement,
resource changes or cleanup are performed.

ARM page and child-parent cursors are separately checkpointed; an empty
intermediate page can continue with a validated token without skipping the
next parent. Per-page `armHasContinuation` records ARM navigation independently
of parent iteration. Native accepted requests are reconciled on resume rather
than blindly reposted. Continuation URLs/tokens are private acquisition state,
not report evidence, and must not be included in public logs/summaries.
Historical input/schema 0.5.0/catalog 1.4.0 remains supported with its recorded
first-page-only limitations. Old acquisition states are not silently upgraded.
Check versions and comparison semantics are unchanged; complete multi-page
parent evidence now supports the same guarded adoption/intent comparisons.

## Resolver adoption and partial-transition review

DNS-path processing also executes NET-DNS-ADOPT-001 1.0.0 using the existing
selected input—no additional resource reads, scope or active testing.
Assessment JSON includes `dnsResolverAdoption`; engineering Markdown renders
the same consumer/ruleset matrix:

- Per collected VNet: known custom/Azure-provided DNS defaults (or UNKNOWN),
  candidate inbound-IP matches, observed links, succeeded rulesets and unready
  links, with collection/evidence references.
- Per ruleset: observed/succeeded consumer references, parent-list completeness,
  enabled/disabled/unknown-state rules and configured outbound references.
- Customer migration intent and actual client use remain UNKNOWN.

If a resolver/ruleset is observed, mixed DNS-default cohorts or uneven
succeeded associations are P2 **context review** signals. They can reflect
staged migration, deliberate isolation, different namespaces or custom DNS
architectures. Rulesets with a successful empty parent link list or no observed
enabled rules invite owner/rollout validation—not automatic linking, enabling
or deletion. Missing/failed/partial/continuation parent evidence is UNKNOWN,
never proof required links or rules are absent. Unknown link targets are
retained as unknown associations, not mistaken for a ruleset with no links.

Not every VNet needs a ruleset link or inbound endpoint. Inbound-only,
custom/on-premises DNS and intentionally isolated/staged designs can be valid.
Configured IP matches are candidates only, not demonstrated client use;
duplicate addresses can be ambiguous. Enabled rule counts do not establish
matching suffixes, rule choice or successful forwarding. External consumer
references are retained without expanding subscriptions. No inferred migration
percentage, readiness score, universal DNS requirement or safe cleanup.

Confirm customer target architecture, migration cohorts, owners, consumer
scope and effective DNS behavior before concluding a deployment is only partly
transitioned or planning changes. If there is no scoped resolver/ruleset,
the matrix remains descriptive and no partial-transition finding is invented.
Historical check catalogs/report delivery remain supported; old acquisition
states are not silently upgraded across capability versions.

## Optional customer DNS intent and migration cohorts

Process an existing DNS-path input with separately supplied intent:

```text
python plugins\azure-network-health\skills\azure-network-health-assessment\network_health.py --input <selected-input.json> --dns-intent <customer-intent.json> --output-root <fresh-private-root> --bundle-result <fresh-helper-result.json>
```

`--dns-intent` is processing-only; it cannot be used for acquisition or
publication actions. [dns-intent.schema.json](skills/azure-network-health-assessment/dns-intent.schema.json)
defines the bounded contract (256 KiB CLI input, 100 cohorts/500 consumers total).
Supply customer configuration outside reusable assets; the agent must not
invent intent from observations. Minimal structure:

```json
{
  "intentVersion": "1.0.0",
  "runId": "<existing-observation-run-uuid>",
  "subscriptionId": "<workload-subscription-uuid>",
  "source": {
    "documentId": "<customer-document-identity>",
    "revision": "<revision>",
    "owner": "<customer-owner>",
    "declaredAt": "<UTC-time>",
    "reviewedAt": "<UTC-time>"
  },
  "cohorts": [{
    "cohortId": "wave-one",
    "stage": "required-now",
    "vnetIds": ["<full-VNet-resource-ID>"],
    "dnsMode": "azure-provided-configured",
    "requiredRulesetIds": ["<full-ruleset-resource-ID>"],
    "requiredInboundEndpointIds": []
  }]
}
```

The placeholder example is not a valid executable input or a customer policy.
Supported stages: `planned`, `in-progress`, `required-now`, `excluded`. DNS
mode can also be `custom-configured` or `unspecified`. Named rulesets require
observed succeeded links; inbound targets require configured VNet DNS IP
matching to selected inbound endpoint IPs, not actual use. Inbound-only targets
do not implicitly require a ruleset. Azure-provided DNS defaults cannot also
require direct inbound-server assignment. Excluded cohorts must have no
expectations; required-now must have at least one. Consumer IDs must belong
to the workload subscription and to one cohort only, case-insensitively.
External target IDs remain unknown unless already collected; never auto-query.

Observations remain unchanged. Assessment embeds intent as **DECLARED**,
canonical supplied-JSON hash, document/revision/owner/times and deterministic
per-consumer comparison. The hash is not a hash of the source document, and
provenance is operator-supplied—not authenticated or presumed current.
Engineering Markdown renders the same expectations/differences/gaps.

NET-DNS-INTENT-001 1.0.0 adds one check only when intent is supplied (catalog
1.8.0/fourteen checks; no intent keeps catalog 1.7.0/thirteen). Required-now
differences are P2 contextual owner-validation, not automatic defects.
Planned/in-progress differences are P3 rollout context. Missing/partial
consumer/target/parent/state evidence or newer intent than the observation
interval is P2 evidence collection, not an absent-control finding. No declared
target is not evaluated; an excluded cohort is not compared. Even a match is
configured-only, not readiness, client behavior or migration completion.

No IaC, deployment, DNS tests, resource mutation or new collection scope.
Only four canonical files are produced; intent is embedded in assessment,
not a fifth report. Immutable report-save recovery continues to use original
bytes/hash; editing intent never authorizes overwriting a run.

## Optional evidence age and provenance review

```text
python plugins\azure-network-health\skills\azure-network-health-assessment\network_health.py --input <existing-selected-input.json> --review-at <explicit-UTC-Z-time> --output-root <fresh-private-root> --bundle-result <fresh-helper-result.json>
```

Optionally add the actual supplied `--dns-intent <customer-intent.json>`.
`--review-at` is processing-only and accepts an explicit UTC `Z` timestamp
with up to six fractional digits. No default wall clock is used. Input/
observation contracts, acquisition and existing checks remain unchanged.
The option adds NET-EVID-TIME-001 1.0.0/catalog 1.9.0; executed checks depend
on the selected input mode (seven for base inventory, fourteen for paths,
fifteen for paths plus intent).

The user selected **ages/provenance gaps only, without expiry thresholds**.
Assessment `provenanceTimeReview` and engineering Markdown report original
observation/collection intervals, coverage outcomes and exact age relative
to the supplied reference time. Ages are stored as integer microseconds and
rendered in seconds with six fractional digits. Future timestamps return
UNKNOWN age with explicit chronology gaps, never zero-clamped values.
Collection interval/run-boundary disagreement, missing/performed-read evidence
and mismatched retained evidence times are surfaced without rewriting facts.

If customer intent exists, its DECLARED source document/revision/owner,
declaration/review times and corresponding ages are shown separately.
Operator-provided provenance and review date do not authenticate the document
or establish approval/currentness. Intent validity remains UNKNOWN.
No supplied intent means no invented source dates or customer requirements.

Age does not prove stale/expired/current evidence, resource-change time,
index freshness, continuing validity, readiness, actual client use or migration
completion. No expiration policy, freshness score, age-based severity or
automatic recollection is inferred. Review gaps are P3 evidence/context
actions requiring owner/clock/source confirmation, not automatic defects.

Only four canonical reports are produced, with original observations retained.
Reopening or retrying delivery does not update reference time/ages or rewrite
the assessment. A new review requires a fresh output root and separately
approved inputs, not an overwrite or resource acquisition.

## End-to-end customer assessment acceptance

This workflow composes the existing acquisition, processing and publication
procedures. It adds no resource types, check semantics, expiry policy,
customer scope or deployment mechanism. Installing the skill is not evidence
that a customer assessment passed these gates. Run synthetic acceptance locally:

```text
python -m unittest discover -s plugins\azure-network-health\tests -p test_customer_acceptance.py -v
```

The three composed tests exercise successful and partial-permission journeys
and a contaminated-thread rejection. They use simulated native commands,
uploads and blob saves; they do not access Azure or prove live permissions.
The pipeline uses production helpers, including the real input-processing CLI.

| Gate | Operator / agent action | Required evidence before proceeding |
|---|---|---|
| 1. Select scope | Confirm agent endpoint, workload subscription, exact opt-in mode, explicit DNS hosts, handling/retention and run ID. Customer intent and review reference are optional, actual supplied inputs only. | Approved scope; separate customer configuration; no subscription enumeration or inferred requirements. Confirm consumer observations can legitimately be partial. |
| 2. Verify installation | Inspect installation API pin/version, auto-update setting, one imported skill and actual connector prerequisites. Compare supporting assets with canonical Git bytes. | Exact pin/hash match, required native tools and selected-input bridge availability. Do not infer flags from incomplete installed-file metadata. |
| 3. Acquire evidence | Use a fresh collection-only thread and the existing host bridge. Preserve paging, parent/scope binding, selected evidence and terminal permission outcomes. | Durable state, exact native execution IDs and strict structured audit. Surface contamination blocks collection; capability absence/denied access is not empty inventory. |
| 4. Recover acquisition/input delivery | Reuse the explicit resume mode and same identity/catalog. Reconcile accepted requests; block unknown acceptance. Ambiguous input upload requires a real receipt, not a second POST. | Same selected bytes/run/scope; authentic receipt/download verification. Completed replay adds no resource reads or canonical file changes. Do not automatically clear locks or retry terminal failures. |
| 5. Process selected evidence | In a separate processing thread, verify actual input and optional intent hashes/reference. Run installed helper unchanged with fresh output root and `--bundle-result`. | Exactly four canonical artifacts and actual helper-result manifest; correct checks/versions, facts versus DECLARED intent, UNKNOWN gaps, priority bands/counts and deterministic report links. No Azure reads in input mode. |
| 6. Review assessment | Check evidence coverage, scoped comparisons and any staged/required-now intent differences. Interpret ages only relative to the explicit reference, without expiry thresholds. | A partial run can pass honest-reporting acceptance while remaining an incomplete assessment. No completeness, health, client-use, migration or safe-cleanup certification. |
| 7. Publish/recover | Use original helper result, plan/begin/native-save/record and exact run/hash immutable aliases. Skip receipted files; ambiguous saves retry only the identical verified copy. | Actual returned keys and immutable ledger exports; no regenerated originals or exactly-once claim. `savedUnverified` is not successful downloaded delivery. |
| 8. Verify downloads | Authenticated host verifier downloads actual ledger/reports and validates bytes/hashes/contracts/links/run/subscription/thread. Return exact proof attachment/hash to the agent. | `download-verified`, no remaining files and all four bound artifact entries. Agent checks proof bindings, not its own remote read-back. Host authentication is not a signed-proof guarantee. |
| 9. Close and retain | Confirm originals, intent/reference and intermediate ledger snapshots are unchanged. Persist authoritative outputs privately and report remaining gaps. | Clear distinction between delivery verification, synthetic evaluation, live observations and customer acceptance. Record what was not validated; choose next evidence only with explicit authorization. |

Acceptance negative cases include scope mismatch before dispatch, response loss
after an accepted continuation, blocked blind upload retry, central-host
permission denial, partial report-download proof, identical-copy report-save
retry, corrupt download rejection and attempted canonical overwrite.
These gates preserve useful partial results without disguising missing evidence.

No custom subagent or scheduled task is introduced: collection remains owned
by the approved bridge and processing by the installed skill. Synthetic
acceptance results should accompany, not replace, direct authoritative
validation in the actual customer environment.

## Contextual addressing triage (Step 4)

NET-ADDR-001 `1.1.0` joins addressing to retained configuration relationships:

- **Overlap alone:** medium contextual potential risk, P2/context validation.
  Confirm connectivity intent before suggesting any address change.
- **Overlap plus a collected peering between the affected collected VNets:**
  medium potential risk, P1/evidence collection. Peering evidence supports the
  action priority; it does not prove outage, defective desired architecture or
  public reachability. Collect mode, selected-subnet/IPv6-only settings and
  reciprocal/effective context before assuming the overlapping ranges apply.
- **Scoped positive:** at most one aggregate positive covers collected VNets
  whose valid address ranges have no overlap with any other valid collected
  VNet. It is INFERRED from all compared evidence, INFO/no action, with no
  severity or overall-health score. It requires at least two collected VNets,
  successful VNet collection and nonempty/evaluable prefixes for every
  comparison; empty/invalid/partial evidence suppresses it.

Selective subnet/IPv6 peering modes exist in current Azure documentation but
are not collected by this slice. Permission-wide completeness, external/
inaccessible scope, future additions and packet behavior remain unknown.
No positive conclusion follows from NSG presence, no auto-remediation is
recommended, and no new resource collection or networking domain is added.
Priority is action ordering, not severity; a P1 evidence request is not a
critical incident.

## Directional peering triage

NET-PEER-001 `1.1.0` groups retained directional parent/remote relationships
between collected VNets, rather than assuming a named peering proves both
directions or connectivity.

- A unique reciprocal pair is evaluated once with both directions' evidence.
  Both Connected/provisioning Succeeded yields an OBSERVED informational
  configuration record, **not traffic, effective routes, permitted access or
  overall-health proof**. Partial/conflicting collection suppresses that record.
- Failed/Disconnected remains medium contextual validation—not a proved outage.
  Initiated and creation/update/deletion transitions get P2 context validation
  without assumed defect severity or persistence.
- Null/future states, ambiguous directions and incomplete collection are
  evidence gaps. An unobserved reverse direction is not proof it is absent.
- External, unknown, self-referential or reference-only endpoints get scoped
  reciprocity gaps. No cross-subscription expansion or automatic peering
  creation/deletion/retry occurs.

Access/forwarding/gateway intentions, NSGs, routes, selective/IPv6 peering modes,
timing and actual traffic can still require authorized specialist validation.
Recommended deep dives are not executed automatically. Current live validation
input has zero peerings; all richer peering-state cases are synthetic-tested,
not invented deployed scenarios.

## Agent-driven report-save recovery

The skill now has a verified-original publication protocol, not just a request
to attach four files. During fresh processing, preserve actual helper output
with `--bundle-result <fresh-private-helper-result.json>`. That file is created
exclusively and records original paths/hashes; it is not report prose or an
AI-reconstructed manifest.

```text
python network_health.py --input <selected-input.json> --output-root <private-thread-output> --bundle-result <fresh-helper-result.json>
python network_health.py --output-root <original-output> --run-id <UUID> --report-thread-id <current-processing-thread-UUID> --report-save-action plan --bundle-manifest <original-helper-result.json>
```

The plan verifies all four originals, contracts, cross-artifact links and hashes,
then creates immutable aliases containing the run UUID and full SHA-256.
Publication state/version `1.0.0` binds subscription/run/thread and original
manifest, and remains a private companion under `report-publication\<run-id>`.
Canonical `runs\<run-id>` still contains exactly four files.

For each `remaining` file, the agent:

1. Runs `--report-save-action begin --artifact <canonical-filename>`, recording
   `saveStarted` and receiving an exact verified copy path.
2. Calls native `SaveFileToBlob` on that path.
3. Runs `--report-save-action record --artifact <canonical-filename> --blob-key <actual-returned-key>`.

Reopening `plan` verifies originals/copies and skips durable receipted files.
An interrupted unreceipted save may retry only the same verified immutable copy.
This uses documented overwrite-by-name without clobbering another run; it does
not claim exactly-once saves, stable platform keys or native idempotency.
Wrong scope/thread/key, changed/corrupt/missing originals, conflicting receipts
or stale publication locks stop explicitly. No Azure recollection, assessment
rerun, report regeneration or automatic lock deletion is used for recovery.

The skill reports partial saves explicitly. Even four keys mean only
`saved-not-download-verified`: the native tool exposes no checksum/read-back.
Its immutable `ledgerExportPath` can be delivered via the same save tool as the
user's manifest. Its filename uses the digest of canonical JSON, not the SHA-256
of the formatted file bytes; compare each hash using its stated scope.
Once that exact ledger is independently downloaded:

```text
python tools\network_health_sre.py --endpoint <approved-origin> --thread-id <bound-processing-thread> --subscription-id <original-subscription> --run-id <original-run> --output-root <private-verification-directory> --verify-report-saves <downloaded-ledger.json>
```

The host performs bounded, authenticated same-origin/thread downloads, validates
expected per-file bytes/hashes and complete bundle scope/contracts/links, and
saves a separate verification proof. Partial verification is never labeled full
delivery. Credentials remain on the host, not in the sandbox/ledger.

This makes interrupted artifact delivery recoverable while originals remain
available; it does not reconstruct unsaved files after sandbox loss or establish
long-term blob retention. Local manifest/copy failures and expired/inaccessible/
corrupt downloads stay explicit. Native storage is used to deliver requested
reports/manifests, not as an archival/backup service.

## Data handling and validation

Generated run directories are gitignored. Keep live evidence outside public
source control. Synthetic fixtures contain no real tenant identifiers.

Full raw resource responses, tags, descriptions and credentials are not retained.
Selected identifiers/IP/configuration remain customer-internal and must stay in
access-controlled artifacts. Schema support records sensitivity, omissions,
retention decisions, identifier handling and hashes of retained evidence, not
unredacted original responses. Contoso retention policy is not finalized here.

Both contracts use JSON Schema Draft 2020-12 and a registered strict
`utc-date-time` format, avoiding silent optional-format dependency failures.
Cross-artifact validation checks run IDs, versions, entity/evidence/collection
links and integrity hashes. Independently verify selected observations against
direct Azure reads, not another AI agent's agreement.

## Attribution

Adapted discipline: Usman Mahmood's Azure Networking Assessment Agent under the
recorded permission. Acquisition/specialist foundations: Daniel Mauser's
MIT-licensed Network Desk. See [notices](THIRD-PARTY-NOTICES.md) and
[source map](../../docs/source-map.md). Inventory and specialist networking
procedures are not claimed as newly invented concepts.
