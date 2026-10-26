# Azure Network Health: cross-PC handoff and next implementation plan

**Updated:** 2026-10-19 UTC

**Hostless restriction 0.20.0 delivered and installed.** Source pin
`<implementation-commit>`, automatic updates off, two skills;
all **35** canonical Git files match (**22** capture/**13** legacy assessment).
The existing skill has an explicit offline restriction branch and the existing
publisher supports `--restriction`. No new collector, dependency, legacy schema
change or user-host tool requirement was introduced.

Installed processing reused the same October 18 capsule and reproduced all
accepted views with external access blocked. Private output commit
`<output-commit>`, branch
`network-restriction/bd3aee92-ab7f-4732-97f5-d3497addd0f2`, contains 50 files/
735,161 bytes under `network-health/runs/<id>/`. All 45 source files and all
49 non-manifest files are byte-identical; only actual manifest processing time differs.
Independent Git/raw-source checks pass for all 50 results, 108 references and
95 local links. Results remain three RESTRICTED/47 UNKNOWN overall over 36
resources/50 paths. Existing connected/WARA worktree bytes (72 files), HEAD,
status and output main were preserved.

The first preflight stopped before processing/Git because the agent changed one
expected file-size argument. It was preserved, not repaired. A frozen private
Git input and short unchanged hash-bound command succeeded under a new
acceptance ID. The audit shows only the two terminal attempts and the existing
prompt-only quality hook, not memory-writer or unexpected action surfaces.
The indexed knowledge list remains ten documents; this is not a synthesized-file
version audit or a guarantee that automatic backend memory is disabled.

Local regression: **439 cases, 438 pass/one existing Windows skip**; nineteen
focused cases, validator, generic dry run, historical compatibility and
implementation CI pass. Editor Pylance indexing of the isolated worktree
remains unavailable, not a claimed type-check. See the
[installed acceptance and exact pins](../plugins/azure-network-health/runtime-validation.md#installed-offline-restriction-acceptance-2026-10-19-utc).

Separate read-only MCP follow-up confirmed both missing-firewall ACR targets
remain Basic, and a scoped indexed NSP/AMPLS-root query returned no cases.
Premium-only IP-rule support is context, not an assumed default or a silent
1.0.0 verdict change. Positive nonempty NSP/AMPLS service/path qualification
still needs representative evidence; new rules must preserve old verification.
No workload resource/permission/logging change or fixture provisioning occurred.
Scheduling remains deferred: cadence/timezone and source-refresh scope have
not been agreed.

The following local-only record describes the preceding increment, before the
new delivery approval.

**Unreleased offline restriction companion verified:** the owner explicitly
approved `offline-first` for the technical unrestricted-source criterion.
Development is isolated on `network-health/offline-restrictions`, based on
`<implementation-commit>`; it is not committed, pushed,
released or installed. Existing package **0.19.0** and legacy assessment
**0.13.0** remain unchanged. Local personal planning/tickets stay Git-excluded.

New `network_restriction.py` uses one unchanged configuration 0.3.0 capsule and
the existing bounded bundle primitives. Separate 1.0.0 companion observations/
assessment plus both deterministic Markdown reports follow the four-file
`runs/<id>/` convention, explicitly not the old schema. No acquisition,
publisher mode, external dependency or remote-memory integration was added.

Private local run `bd3aee92-ab7f-4732-97f5-d3497addd0f2` reprocesses the October
18 snapshot `5f88092b` without new collection. It covers 36 resources/50 paths:
Storage 12, Key Vault 5, ACR 5 and Log Analytics 14 with independent ingestion/
query. Local settings: 17 public-disabled, 31 unrestricted, two UNKNOWN.
Overall criterion: three ACR public-disabled paths RESTRICTED, 47 UNKNOWN.
The two public-enabled ACR resources lack returned firewall structures; never
assume default Allow. Three Storage accounts and both paths on all 14 workspaces
are locally unrestricted, but NSP/AMPLS precedence/applicability remains
unqualified. This is not current state, effective reachability, anonymous
access, private connectivity, owner-allowlist compliance or causal analysis.

The 50-file/735,161-byte run preserves all 45 source files; largest member
264,073 bytes and manifest 11,088 bytes stay within old limits. Independent raw
checks covered all 50 results, 108 catalog references and 95 local Markdown
links. A fresh-process rebuild matches every non-manifest file. Fifteen focused
tests and the complete 437-case regression pass (436 pass/one existing Windows
skip); validator/generic dry run and old timeline/comparison verification pass.
Editor Pylance indexing of the isolated worktree remained unavailable; do not
claim a successful editor type-check.

No Azure calls, remote SRE Agent chat, memory write, dependency restore,
release/install or output publication occurred for this increment. Positive
NSP/AMPLS live gates remain open, including Enforced/PrivateOnly/approved-PE
qualification; synthetic cases do not close them. Do not perform another
runtime chat, collection, install or memory action without the necessary
approval. See the
[local acceptance and exact hashes](../plugins/azure-network-health/runtime-validation.md#offline-restriction-companion-acceptance-2026-10-19-utc-unreleased)
and [source decisions](source-map.md#2026-10-19-offline-public-source-restriction-assessment-unreleased).

**History refresh and compact timeline 0.19.0 complete:** installed source
`<implementation-commit>`, automatic updates off, two skills,
21 canonical Git-file matches. The approved refresh queried through the newer
configuration snapshot's exact end, `2026-10-18T22:36:27.508871Z`: workspace
2,694 rows on six pages, Resource Graph 577 on two pages, Service Health one
Active HealthAdvisory. The real second-page `RowKey > string` error was corrected
in 0.18.1 using Kusto `strcmp` in both producers; old failed evidence stayed
UNKNOWN/unmodified and a separate same-window identity completed.

The owner selected compact pages after the ten-input legacy view measured
13,992,672 JSON bytes and at least 23,196,441 total bytes, over existing limits.
Opt-in storage/processor 1.1.0 keeps all original source bytes embedded and
replaces duplicated payload/witness metadata with source references plus bounded
section pages. Default 1.0.0 artifacts and comparison/source contracts remain
byte-compatible. Use `network_timeline.read(Path(...))` for the complete logical
view; root JSON is an index, never the whole dataset.

Accepted compact timeline `88352d57-3587-40e5-bce3-f4a37ac5f568` is published
privately at `<output-commit>`, branch
`network-timeline/88352d57-3587-40e5-bce3-f4a37ac5f568`. It contains 112
unchanged source files plus 27 derived files: 139 files/15,034,995 bytes total,
largest member 1,784,824 bytes, 29,099-byte manifest and 209,350-byte root index.
All original 5 MiB/member, 64 KiB/manifest and 20 MiB/total limits hold.

The complete logical data has 3,373 source identities, 3,418 payload revisions,
3,747 event witnesses, 128 configuration observations over 36 configuration IDs,
394 resource contexts, 850 correlation groups, 26 unbound references and five
verified parent links. Independent verification resolves every payload/witness/
time/omission/index, all 3,933 Markdown links and all committed Git blobs.
Reversed-input rebuild matches all 138 non-manifest files; processing time stays
separate. The normalized reader's full hash equals the legacy projection.

All eight newly observed configuration IDs now have retained event context:
74 workspace revisions plus 30 change records, including eight recorded Create
and 22 Update classifications (recorded actor types User 18/Application 12).
These are not physical-change/person counts, desired-state or causal findings.
Sources were not recollected for compact formatting; no new source field,
resource/permission/logging/retention change or schedule was introduced.

**Memory follow-up:** the SRE Agent reported an after-acceptance memory overwrite.
Read-only audit shows `create` plus an index-note edit, no prior topic body, and
an available pre-edit index-note snapshot. Prior existence/content loss could
not be independently established in the six relevant threads inspected. No
restore/reconstruction/new agent chat was performed; the owner chose leaving
memory untouched and finalizing docs/receipts only. Evidence/repository bytes
were independently verified unaffected. Do not claim the topic's previous
contents permanently lost or recovered.

Full 422-case regression: 421 pass/one existing Windows skip; five-plugin
validation, generic Bash dry run and release CI pass. Failed `81238627` source,
available old evidence, current main/WARA/tag trees and prior refs remain
preserved. A separately overwritten early native read-back helper receipt is an
explicit audit limitation; do not reconstruct its original bytes or erase the
separate identity-count corrections. See the
[installed compact record](../plugins/azure-network-health/runtime-validation.md#installed-compact-timeline-acceptance-2026-10-19-utc).

**Conservative configuration comparison 0.18.0 released and installed:** pin
`<implementation-commit>`, automatic updates off, 21 exact
installed Git-byte matches and the same two skills. Shared self-contained bundle
mechanics preserve the existing timeline 1.0.0 views, source 0.3/0.4/0.5 formats
and assessment contracts.

The owner approved one second read-only configuration snapshot and then
separately approved restoring only missing WARA-pinned Az.Accounts 3.0.4 to the
agent's private cache. This was a runtime dependency write, not an Azure resource/
permission/identity/logging change or collector auto-bootstrap. New snapshot
`5f88092b-fd51-4e79-b168-c8f3c6c2b237` is durable at
`<output-commit>`; authoritative pages show 43
successful collections (36 GET/seven list), 72 observations and 36 resources.

The installed offline comparison against original snapshot `88e9b2ad` produced
**28 comparable resources, zero retained settings differences, zero metadata
differences, eight newly observed resources without before GETs and 19 evidence
gaps**. The gaps are eight missing comparable before observations and eleven
arrays with omitted unreviewed fields. Independent raw GET payload sets prove
the 28 common configurations equal without relying on comparator normalization.
Newly observed is not proof of creation; equality is not a whole-environment
or omitted-field assurance.

Comparison `48824180-c555-4ce4-9b97-ffd660fa5e1a` is published privately at
`<output-commit>`, branch
`network-comparison/48824180-c555-4ce4-9b97-ffd660fa5e1a`, with 85 files:
82 unchanged sources plus JSON/Markdown/manifest. Fresh committed-object verify,
all 128 observation references, all 66 Markdown links and same-ID deterministic
rebuild passed. The old 55-file timeline remains unchanged and verifies under
the extracted bundle module. No Azure calls occurred in the derived phase.

Full regression: 416 cases, 415 pass and one existing Windows symlink skip;
five-plugin validator, generic Bash dry run and release CI pass. Current main/
WARA work, prior refs/evidence and module cache were preserved. Earlier false
fingerprint/local-branch harness flags and the narrated 37/6 collection count
remain retained with separate corrections; committed pages establish 36/7.
No new findings, defect/slippage/desired-state/causal conclusions or schedules
were introduced. Live nonempty value-change classification is not demonstrated
by this zero-difference run. See the
[comparison runtime record](../plugins/azure-network-health/runtime-validation.md#installed-configuration-comparison-acceptance-2026-10-18-utc).

**Offline evidence timeline 0.17.0 released and installed:** source pin
`<implementation-commit>`, automatic updates off, the same two
skills and 19 installed files verified against canonical Git. Source capsules
0.3/0.4/0.5 and the assessment contracts remain unchanged. The separate timeline
bundle/view/processor is 1.0.0; no Azure recollection or managed-identity
authentication is needed to build it.

The installed workflow restored six exact private Git capsules and built
timeline `8ae2829f-f5a6-4c7b-8efd-9d101831354e`: 475 input event rows/witnesses,
340 source-bound identities/revisions (159 workspace, 176 changes, five Service
Health), 56 configuration observations over 28 configuration IDs, 122 resource
contexts and 116 recorded correlation groups. Five unbound health events and two
verified workspace parent links remain explicit. The 94 event-only IDs have no
configuration observation supplied, not inferred deletion or absence.

The self-contained 55-file bundle includes 52 byte-identical original source
files plus deterministic JSON/Markdown and a derived manifest. It is published
privately at `<output-commit>` in
`<repo>/sre-outputs`, branch
`network-timeline/8ae2829f-f5a6-4c7b-8efd-9d101831354e`. Both independent
committed-object checks and all 537 evidence links passed. A fresh installed
rebuild with reversed input order reproduced identical views while retaining a
new, separate processing time in its manifest.

**Current-runtime caveat:** the workspace was replaced after initial acceptance
checks. The earlier unpublished direct Activity Log checkpoint and first
marker-stop receipt are not present; old hashes remain known from prior
external receipts, but their current bytes are unverified, not reconstructed or
claimed unchanged. Published capsules recovered intact from Git. Incomplete
checkpoint recovery after workspace loss remains unimplemented. The live
`.sync-version` marker is also unavailable; installation metadata plus 19 exact
Git-byte matches establish this release pin instead.

The current main/WARA worktree, available receipts and installed files/cache
were preserved. An over-strict harness failure about the publisher's expected
new local branch is retained with a separate verified reconciliation, not erased.
No Azure resources, diagnostics, retention, identities, permissions or schedules
changed. Full regression: 407 cases, 406 pass and one existing Windows symlink
skip; five-plugin validator, generic Bash dry run and release CI pass. Standards
reported zero significant issues; Spec's one medium Windows argument-limit issue
was reproduced and fixed with a real 20-capsule/223-file publication fixture.
See the [installed timeline record](../plugins/azure-network-health/runtime-validation.md#installed-offline-timeline-acceptance-2026-10-18-utc).

This is evidence integration, not snapshot-difference or causal assessment.
Native retention and omitted values remain gaps. Configuration comparison,
service/region impact inference, complete history and live multi-page collection
are separate increments. Earlier sections below describe prior acceptance states.

**Native change and Service Health acquisition verified:** the unchanged 0.16.0
installation captured 176 Resource Graph change records and five subscription
Service Health feed events in separate 0.4.0 capsules. Both were verified,
replayed and published on new private branches; fresh-process replay of the
committed Git objects matched. Requested end remained
`2026-10-15T23:36:15.582Z` despite collection on 2026-10-16.

Resource changes comprise 22 Create and 154 Update records. The native 14-day
limit produced an actual query start of `2026-10-02T19:26:09.177256Z`; the earlier
requested year remains an explicit retention gap. Of 2,837 changed-path
occurrences, only two are within the current reviewed value-path policy; 2,835
unreviewed before/after values are omitted. Recorded actor types do not identify
the human who initiated automation.

The feed retained three PlannedMaintenance, one HealthAdvisory and one
ServiceIssue event; six were returned and one was discarded outside the explicit
lastUpdateTime window. This validates the native feed, not the workspace's
missing AzureActivity ServiceHealth category, historical completeness, customer
impact or platform causation.

External Resource Graph operator checks did not corroborate the capture (MCP
zero; explicit ARM HTTP 400 scope/access error). The gap is preserved. A separate
metadata-only source read under the approved in-agent managed identity matched
all 176 IDs and bindings; no identity/permission workaround was used. Service
Health metadata matched an independent operator ARM read.

Private output commits: resource changes
`<output-commit>`, capsule
`4b1097fc-9172-4332-a5d1-e5c8e3c71b73`; Service Health
`<output-commit>`, capsule
`454d34ee-b94f-4eb9-81b1-b1d57fa97ce6`. Prior evidence, paused direct checkpoint,
installed assets/cache and output main/WARA are unchanged. No Azure configuration,
logging, roles, credentials, budgets or schedules changed. Live multi-page
collection, broader reviewed change values, complete history and cross-source
correlation remain separate gates. Earlier sections record previous acceptance
states; see the
[native runtime record](../plugins/azure-network-health/runtime-validation.md#installed-native-change-and-service-health-sources-2026-10-16-utc)
for current source-specific validation and limitations.

**Known late-arrival pickup verified:** the next incremental workspace capsule
retained both rows previously observed after parent collection completed. Their
occurrences precede the parent watermark; each source RowKey was absent from the
129-row parent and present exactly once in the new committed page.

Capsule `9a71b4e2-7c8d-4387-9ef3-6e4094e04d2e` is published privately at
`<output-commit>`. It contains 159 records: 157
Administrative and the first two live ResourceHealth category rows. All 129
parent identities were unchanged; 30 were newly observed, including the two late
rows. Independent canonical source bindings, exact Git bytes and fresh-process
committed-object replay matched. The same unmodified 0.16.0 package and 24-hour
overlap were used; no Azure configuration, source asset or schedule changed.

This proves pickup of those two known rows, not all possible late arrivals or
historical completeness. ResourceHealth category presence is not platform-cause
or outage diagnosis. Nonempty ServiceHealth data, live paging over 500 rows,
other native history sources and causal correlation remain open gates. Parent,
paused direct checkpoint, output main/WARA and prior receipts remain unchanged;
the other workspace stays excluded. See the
[late-arrival runtime record](../plugins/azure-network-health/runtime-validation.md#installed-late-arrival-pickup-2026-10-15-utc).

**First incremental workspace run verified:** the unchanged installed 0.16.0
package captured 129 Administrative records using the prior capsule's terminal
watermark and 24-hour overlap. Six prior identities were unchanged, none were
missing or revised, and 123 identities were newly observed. Caller metadata was
present on 117 rows; the other 12 have no recorded Caller. Other retained
identity fields remain separate; no human actor was inferred.

Capsule `046e2400-2508-4266-af05-2ac50177a347` binds parent
`9bba5c4b-6e46-475e-aad4-4d1335cfbde5` and is published privately at
`<output-commit>`. Exact Git bytes, committed-object
replay and all 129 independent canonical source RowKeys matched. A raw string
comparison mismatch was traced to trailing fractional-zero representation and
reconciled with the existing exact-precision helper without editing any evidence;
the original failed operator receipt is retained.

Later independent queries observed additional ingestion after capture completion.
The immutable 129-row snapshot was not rewritten; later rows remain for a future
overlap run, not falsely claimed collected. No schedule was created. Parent,
paused direct checkpoint, output main/WARA and installed assets are unchanged;
the other export remains excluded. This is still a single-page run: live
multi-page and nonempty health-category gates remain open. See the
[incremental runtime record](../plugins/azure-network-health/runtime-validation.md#installed-incremental-workspace-capture-2026-10-15-utc).

**Log Analytics-first 0.16.0 readiness and first nonempty capture verified:** package pin
`<implementation-commit>`, automatic updates off, two skills
on the WARA-tested agent. All 18 installed evidence/profile/workspace files match
canonical Git bytes. Activity Log discovery/preflight/capture now uses the existing
Log Analytics source preferentially, with fixed subscription/category/time-filtered
queries, explicit external-workspace approval, reviewed columns and separate
workspace capsule 0.5.0. Native history capsule 0.4.0 and configuration formats
are unchanged; the assessment skill still uses its original 0.13.0 contracts.

Initial discovery refused an unapproved external destination. Once that named
workspace was approved, its metadata returned HTTP 401 and readiness remained
UNKNOWN. A different local workspace was accessible but had zero relevant rows.
Those exit-2 readiness outcomes remain retained privately.

The owner subsequently configured and selected a usable local export. Installed
discovery/preflight returned AVAILABLE, and capsule 0.5.0 retained six live
Administrative records on one page. Verification, replay, completed resume and
guarded private publication passed. Independent Azure MCP source-row bindings,
GitHub manifest bytes and fresh-process replay of committed Git objects matched.
The other destination was not queried or followed. The output commit is
`<output-commit>`, capsule
`9bba5c4b-6e46-475e-aad4-4d1335cfbde5`; output main and WARA were preserved.
This establishes single-page nonempty acquisition, not historical backfill/
completeness, live paging over 500 rows or nonempty ResourceHealth/ServiceHealth
events. Actual rows cover approximately two minutes on 2026-10-15; current
workspace/table retention is 30/90 days, not proof of older collected history.
This adapter still uses the existing selected identity; a cross-tenant
credentialed connector is not automatically substituted.

The previous direct Activity Log run stopped at 20 MiB after 67 pages/7,676
returned records and is still incomplete with no advanced watermark. Its
checkpoint hash stayed
`eefa2965dba58b74fc4ab2f37a86f5995c2b31395ab90bbd9b835eaf8fadcac9`;
the run was not resumed or edited. Other native history sources' live acceptance
was not completed after that budget stop. No logging/exports/retention/roles
were changed by the assessment workflow to create data. The new export was
configured by the owner, not by this read-only workflow.

Tests also cover missing/denied/partial sources, synthetic multi-page workspace
capture, custom plus standard schema columns, seven-digit cursors
and the case where a positive preflight is followed by empty collection: that
case cannot advance a watermark. Full regression: 393 cases, 392 pass and one
Windows symlink-creation skip. Generic Bash dry run and validator pass. Earlier
actual 0.1/0.2/0.3 replay hashes remain unchanged.
See the [workspace runtime record](../plugins/azure-network-health/runtime-validation.md)
and installed capture skill for the actual commands and remaining gates.

**Hostless evidence capture 0.14.1 installed acceptance complete:** the owner
selected a dedicated `azure-network-evidence-capture` skill alongside the unchanged
0.13.0 assessment skill. The package was released after approval and installed on
the WARA-tested `<lab-agent-name>` at
`<implementation-commit>`, automatic updates off, two imported
skills and no new extras/MCP connectors. All eight installed capture assets match
canonical Git bytes.

The installed PowerShell/Az.Accounts managed-identity adapter captured 28 resources
(Storage 8, Key Vault 4, ACR 5, Log Analytics 11) in 35 planned configuration
outcomes: seven root pages and 28 GETs. Authentication/context SDK traffic is
separate from that count. The capsule has 36 evidence members plus a manifest.
The installed publisher added only those 37 files to a private output branch,
preserving WARA's original worktree and output main. A fresh conversation verified
remote Git bytes and replayed without recollection; completed resume made zero
reader calls. A separate native ARG spot-check matched 19 known values and one
missing feature, without substituting defaults.

Private output commit:
`<output-commit>` in
`<repo>/sre-outputs`, capture
`88e9b2ad-6710-48d7-8c94-ecfce08f6091`. Manifest SHA-256
`c2d7761edd4f0d55fb63e97712a4689ace67862b72338b82dfa98249a1885d27`;
replay SHA-256
`496c609e8e9cb3d5d7757905f48dd087013b4283ae18ff606815a3cb8f849c31`.
The first full console publication receipt was truncated after success; recovery
read its persisted file without repeating the push. Patch 0.14.1 emits a compact
summary while retaining full hashes privately.

Use the dedicated capture skill for reviewed snapshots and offline replay, not
the host companions or Code Interpreter. The user needs no local tooling; a new
agent needs workspace tools, existing runtime/Az.Accounts, read identity and an
approved connected private repository. Current scope is the four service families
and discovered NSP/AMPLS configuration, not all Azure/network resources.
NSP/AMPLS roots were empty; nonempty child cases remain synthetic-only.
Events, comparisons, new findings and connectivity/enforcement certification are
not implemented by this capture skill. Partial checkpoints are workspace-local;
sandbox-loss recovery from Git before completed publication is not yet proven.
See the [installed acceptance record](../plugins/azure-network-health/runtime-validation.md)
and [capture skill](../plugins/azure-network-health/skills/azure-network-evidence-capture/SKILL.md).

**Installed 0.13.0 NSP acceptance complete:** implementation pin
`<implementation-commit>`, auto-update false, one imported
skill and no extras/MCP configuration. All thirteen installed asset hashes match
canonical Git bytes. 321 Windows and 321 native Linux cases pass; exact four
projections also passed Azure CLI JMESPath nonempty/missing/empty synthetic
evaluation. Installed helper processed unchanged actual input into sixteen
checks/24 records and canonical scoped-zero NSP JSON/Markdown views.

Actual run `f234acfe-086d-4fd6-93ba-3bd4245ff78a`: thirty collection IDs/
78 native execution IDs, only one NSP root request and zero child requests.
The terminal empty root was independently corroborated. Zero-read replay
preserved original input/golden; processing added zero Azure executions.
All four authenticated downloads matched golden bytes, and actual host proof
bindings closed external delivery against the unchanged ledger. A host
idle-wait timeout was resolved by inspecting completed history, without reposts,
reprocessing or repeated saves. Native ledger remains savedUnverified, not
remote read-back or signed source proof.

Nonempty stable child/mode/profile/association/rule paths remain synthetic-only,
not live compatibility or customer validation. No resources were created for
tests, diagnostics enabled or exceptions accepted. Enforced configuration is
not demonstrated enforcement; AMPLS, service synchronization, rule semantics,
client traffic and Contoso/OBO remain unvalidated. Obtain actual authorized
nonempty perimeter evidence before claiming those runtime paths validated.

**Bounded NSP continuation:** owner selected association/profile/enforcement-
configuration evidence, not AMPLS expansion or automatic exception approval.
Source 0.13.0 adds `--include-nsp`, four API 2024-07-01 lists over actual
workload perimeter/profile parents, raw access mode/provisioning/issue metadata,
rule selector counts without values and `nspConfigurationReview`. Enforced
configuration is not effective enforcement; Learning/Transition, Audit, unknown
modes and partial coverage remain distinct. External references are not followed.
Acquisition 1.8.0/input-schema 0.9.0/check catalog 1.12.0 execute thirty
operations/sixteen checks without optional intent/time (up to eighteen).

321 Windows tests, exact Azure CLI JMESPath projections, repository validation
and generic dry-run pass. Fresh C6 run `f234acfe-086d-4fd6-93ba-3bd4245ff78a`
completed thirty scoped outcomes/78 native executions/sixteen checks/24 records;
zero-read replay preserved actual input/current golden. Actual NSP root list
was terminal/empty and independently corroborated. No child lists ran: successful
empty child outcomes indicate no discovered parent, not global absence.
Nonempty/mode/denied/pagination paths remain synthetic-only; stable nonempty
child compatibility is unvalidated. No resources were created, diagnostics
enabled or customer exceptions accepted. Installed 0.13.0/Linux/download
acceptance remain separate gates until completed.

**Installed 0.12.0 reconciliation acceptance complete:** implementation pin
`<implementation-commit>`, auto-update false, one imported
skill and no extras/MCP configuration. All thirteen installed asset hashes
match canonical Git bytes; 306 Windows and 306 native Linux tests pass.
Installed helper processed unchanged real input into the canonical four
reports, byte-identical to host golden. Authenticated downloads and actual
host-proof binding checks closed external delivery; native ledger phases
remain savedUnverified, not remote read-back or signed proof.

Fresh run `43241181-89c2-4215-ba38-074088b63c2e`: 26 collection outcomes/
77 distinct native execution IDs, seventeen direct GETs, fifteen checks/
23 records. Processing added zero Azure executions and the exact original
execution-ID set remained unchanged. Seventeen service rows contain 102 field
comparisons: eighty non-null matches, ten both-unavailable, three
direct-unavailable legacy ACR counts and nine outside-profile fields. All
seventeen direct projections were independently corroborated. Source/API/time/
failure metadata and both raw selected values are now in canonical JSON and
Markdown, without replacing indexed state or inventing defaults/requirements.
Different known values and denied/budget cases were tested synthetically,
not encountered live. Source agreement does not prove enforcement, client use,
private-only access or health; Contoso/OBO and customer exception approval
remain unvalidated.

**Integrated ARM source reconciliation continuation:** owner chose to put direct
ARM service-control observations into the assessment rather than expand NSP/
customer scope. Source 0.12.0 adds `--include-service-arm`, three bounded
same-workload GET operations, separate direct configuration objects, per-parent
API/read-completion/outcome metadata and `serviceControlReconciliation`.
Older indexed-only and historical modes keep their behaviour. Null/unavailable,
not-attempted, non-applicable and different known values remain distinct; no
source replaces the other or becomes desired state/health certification.

306 Windows tests, repository validation and generic extras dry-run pass.
Fresh C6 run `43241181-89c2-4215-ba38-074088b63c2e` completed 26 outcomes/
77 audited reads, including seventeen direct service GETs. Zero-read replay
preserved actual input/current golden reports. Fifteen checks/23 records retain
80 matching non-null fields, ten both-unavailable, three direct-unavailable
legacy ACR VNet-rule counts and nine outside-profile fields. Seventeen
independent host ARM projections matched the integrated direct values. Actual
known-value conflicts/permission/budget failures remain synthetic validation.
Installation/Linux/download verification for 0.12.0 remain separate gates;
the earlier installed 0.11.0 pin below is authoritative until they complete.

**Installed 0.11.0 acceptance complete:** implementation pin
`<implementation-commit>`, auto-update false, one imported
skill and no extras. All thirteen installed asset hashes match canonical Git
bytes. 293 Windows and 293 native Linux regression cases pass. Installed
processing of the unchanged actual selected input produced fourteen checks/
21 records and four reports matching final host golden bytes. Native immutable
publication plus authenticated downloads are verified; all four downloads are
retained privately, processing made zero Azure reads, and the original exact
sixty collection IDs remain unchanged. Agent closure verified actual host proof
hash/bindings against the unchanged ledger; native phases remain savedUnverified,
not a remote read-back or signed proof. A local receipt-serialization failure
after successful proof upload was recovered without duplicate upload.

Supported actual rows: seventeen resources in three families; other twenty-two
resources are in eight families, all unassessed (not twenty-two families).
Thirteen Disabled settings are not private-only certification; four Enabled
settings need owner/context review. Three legacy ACR VNet-rule metadata
differences remain explicit despite matching access/firewall/bypass modes.
NSP/AMPLS enforcement, actual DNS/client/traffic behaviour, accepted exceptions,
permission-wide completeness and Contoso/OBO remain unvalidated.

**Service access-control continuation:** owner selected lab development rather
than Contoso execution, then selected Storage Accounts, Key Vaults and Container
Registries. Source 0.11.0 adds opt-in `--include-service-access`, acquisition
1.6.0/input-schema 0.7.0/check catalog 1.10.0. It changes only the mapped-service
projection within the existing 23-operation full mode and adds one check (14
without optional intent/time, up to 16). Observed access settings, firewall
action, bypass/rule counts and approved PE groups remain separate from declared
preference, owner review and UNKNOWN actual reachability/exception approval.
Other service families and NSP/AMPLS enforcement remain explicitly unassessed.
293 Windows tests, repository validation and extras dry-run pass.

Fresh audited native run `ae70703a-61ea-482a-8270-46bfbf1f3aae` made 60 reads/
23 successful outcomes in existing C6 workload/DNS scope; completed
acquisition-only resume added no reads. Supported inventory: eight Storage,
four Key Vault, five ACR; thirteen Disabled, two Enabled/Allow and two Enabled
with unavailable firewall action. Seventeen direct ARM reads matched all
public-access/firewall/bypass modes; three legacy ACR VNet-rule count differences
remain explicit (indexed zero versus unavailable ARM field), not defects.
Do not claim all fields matched, private-only use or customer compliance.
Original bridge reports remain immutable; final host golden processing uses a
separate output root after a development gap-label refinement. Installed 0.11.0
processing/delivery is a separate remaining gate; earlier installed 0.10.0
remains authoritative until that gate is completed.

**Full supported lab test:** owner continued after first-pass summary; fresh
0.10.0 inspection used only discovered C6 workload/DNS scope, 23 outcomes/
62 audited native reads and thirteen checks/sixteen records. All collections
succeeded within accessible scope; completed replay added no reads/changed
bytes. Fourteen independent ARM-backed reads corroborated selected addressing,
endpoint/group/zone/metadata/DNS-root facts. Installed four-report downloads
matched golden bytes, with zero processing Azure reads and declared private
baseline in both reports. No actual customer DNS intent/review time invented.
Important output: medium-impact potential overlap/P2, five repeated-name DNS
ownership reviews, four evidence gaps, configuration information—not health,
private-only/public-exposure compliance or cleanup certification.
Run `421ac747-434d-4554-bda5-56d88ffa4ae2`; installed pin unchanged
`<implementation-commit>`, auto-update false.
Next: apply first-pass to actual Contoso tenant/endpoint or supply customer
intent/approved nonempty resolver evidence. Service public-access/enforcement
and effective behavior remain uncollected; do not call those validated.

**Initial test readiness:** owner requested first-pass subscription/access/
component summary, then separately triggered full inspection, without redundant
approval prompts. Published/installed 0.10.0 adds selected subscription discovery,
tentative name roles and hub/spoke/vWAN signs, explicit per-scope gaps, audited
resume and operator supplemental collection. Private-preferred/public-exception
baseline stays DECLARED. Current Microsoft Learn distinguishes Monitor
workspace Private Link from Log Analytics NSP integration; no automatic
Monitor workspace exception. OBO is platform-supported temporary user access,
not grants; no CLI token flow or Contoso permissions claimed.
279 Windows/Linux tests pass. Live first pass used two native reads and found
one visible subscription/89 components; independent ARG rows matched and
completed resume added no reads. Operator fallback works with existing CLI.
Installed pin `<implementation-commit>`, auto-update false.
All three actual installed initial-summary downloads matched live golden bytes;
processing added zero Azure reads. The README start-here section supplies local
and Contoso tenant/endpoint/operator commands. OBO remains platform-driven,
not an implemented CLI access grant. Do not automatically trigger detailed
inspection from discovery; user supplies the selected workload/DNS scopes.

**End-to-end acceptance continuation:** user selected a complete customer-ready
acceptance workflow rather than more isolated checks. Published/installed 0.9.1 wires
nine scope/install/acquisition/recovery/processing/review/publication/download/
closure gates in README/skill and three composed acceptance tests. They
exercise accepted-continuation loss, scoped resume rejection, partial central
permissions, ambiguous input upload/real receipt, staged intent/age review,
partial proof, identical immutable save retry, corrupt/wrong-scope download
rejection and no canonical overwrite. 268 Windows/Linux cases pass; historical
actual reports verify. No new resource scope/check/deployment/subagent.
Installed pin `<implementation-commit>`, auto-update false.
Installed synthetic partial-permission report delivery was interrupted after
two receipts/third-save-without-receipt/fourth-pending. Actual partial proof
verified two outputs; publication-only recovery skipped receipts/retried
identical third bytes/saved fourth. All four actual downloads matched golden
bytes; the delivered assessment remains incomplete, not customer health/
completeness acceptance. An initially misreported plan-time ledger path was
explicitly corrected to the current snapshot before verification.
Next: apply gates to actual customer-supplied scope/evidence/intent, or review
the current bounded capability's remaining limitations before more expansion.

**Previous age/provenance continuation:** user chose ages/provenance gaps without expiry
thresholds. Published/installed 0.9.0 adds processing-only explicit `--review-at`,
NET-EVID-TIME-001 and deterministic age/chronology review. Exact integer
microsecond ages use the supplied UTC reference, never implicit wall clock.
Future/inconsistent/evidence-mismatched timestamps and failed/no-page collection
outcomes are explicit gaps; source/owner/revision/review dates do not authenticate
customer intent. No fresh/stale/expired/readiness or source-validity claim.
265 Windows/Linux tests pass across all modes; old actual deliveries verify.
No customer source or expiry policy was supplied. Installed pin
`<implementation-commit>`, auto-update false. All four actual
synthetic time/intent outputs matched golden downloaded bytes, with embedded
reference-time ages/intent/provenance recomputed and zero processing Azure reads.
Next: use actual customer-supplied observation/intent/reference provenance
for review, not invented expiry or validity policy.

**Previous ARM pagination continuation:** user approved bounded scope-validated resolver
ARM pagination/resume. Published/installed 0.8.0 uses input/schema 0.6.0/acquisition 1.5.0,
retaining historical 1.4.0 projections and gaps. No new resource/check types
or scope. Private page and child-parent cursors are separate; origin/path/API/
token parameters are validated before continuation dispatch. Empty pages,
multiple parents, malformed/repeated URLs, budgets and accepted-request resume
are tested. 251 Windows/Linux tests pass; two new native scoped root projections
matched independent ARM reads. Live roots were empty; nonempty multi-page
evaluation is synthetic-only. Actual prior intent report downloads still verify.
Installed pin `<implementation-commit>`, auto-update false.
All four actual installed synthetic multi-page report downloads matched golden
bytes with zero processing Azure reads. Next: use explicitly supplied customer
observation/intent scope for nonempty live validation, not invented lab data or
automatic customer subscription expansion.

**Previous DNS intent continuation:** user selected provenance-backed customer DNS intent
and cohort comparison. Published/installed 0.7.0 adds processing-only `--dns-intent`,
schema/source/revision/owner/time/run/subscription validation, disjoint cohorts
and stage-aware configured DNS-mode/ruleset/inbound comparisons. Intent is
DECLARED in assessment only, never observations. Required-now differences
are P2 owner-review, planned/in-progress differences P3 rollout context;
missing/partial/out-of-scope/time-order evidence is UNKNOWN. No client-use,
readiness/migration-completion or deployment claim. 237 Windows/Linux cases
passed and old delivered reports still verify. No customer intent was supplied;
installed evaluation uses clearly labelled synthetic intent only.
Final installed pin `<implementation-commit>`, auto-update
false (discovery-only follow-up to implementation `<implementation-commit>`). All four actual
saved synthetic outputs independently downloaded byte-identical to golden
files, with embedded intent/hash/comparison verified and zero processing Azure
reads. Next: accept an actual operator-supplied customer intent document with
approved observation scope; do not infer or invent customer migration targets.

**Previous resolver adoption continuation:** user highlighted deployed Private DNS
Resolver with partly transitioned/unevenly linked consumers. Published/installed 0.6.0
adds a contextual consumer/ruleset adoption matrix and NET-DNS-ADOPT-001,
without new acquisition or scope. Input/schema 0.5.0/acquisition 1.4.0 stay;
path processing has thirteen checks/catalog 1.7.0. 216 Windows/Linux tests
pass, including valid inbound-only/custom/isolated/staged designs, missing
parent-list/permission/continuation evidence, unready dependencies and
ambiguous inbound IP matches. No required link-every-VNet, inferred client
use, migration percentage or defect severity is invented.
Existing live selected input was replayed without recollection, with identical
observations/provenance except producer version; its absent scoped deployment
produced no partial-transition findings. Old delivered reports still verify.
Installed pin `<implementation-commit>`, auto-update false;
all four actual report downloads matched golden bytes with zero processing
Azure reads and unchanged original 62 execution IDs. Next: evaluate explicit
customer migration cohorts/target architecture and approved nonempty resolver
evidence; do not invent intent or broaden scopes to make a migration finding.

**Previous DNS path continuation:** user approved configuration-only VNet DNS defaults
and Azure DNS Private Resolver/endpoint/ruleset/rule/VNet-link reads in the
current subscription, including selected engineering-only suffixes/target
IP/port values. Published/installed 0.5.0 adds seven operations/configured references/
`dnsPaths` view/NET-DNS-PATH-001. 198 cases pass on Windows/Linux; old 0.4
delivered reports still verify. Native collection completed 23 outcomes/
62 reads and independent evidence verified six known empty VNet DNS arrays
and scoped empty resolver/ruleset roots. No custom DNS absence or actual
client DNS use is inferred. Nonempty child cases are synthetic-only.
Installed pin is `<implementation-commit>`, auto-update
false. All four actual downloads matched golden bytes with zero processing
Azure reads. Next: validate an explicitly supplied customer central-DNS scope
or architecture/consumer evidence, rather than infer client paths from this
lab's empty resolver roots. Keep uncollected ARM continuation, external
DNS/consumer scope and actual-behavior/cleanup gaps explicit.

**Previous record metadata continuation:** user approved privacy-minimized repeated-zone
record-set metadata in the current subscription. Published/installed 0.4.0 adds aggregate
record-set type counts and selected TTL ranges only; no record names/IDs/values,
active lookups or resource changes. Two direct probes proved Core CLI shape.
185 Windows/Linux tests pass; old 0.3.0 delivered reports still verify.
Mode includes planning and has acquisition 1.3.0/input-schema 0.4.0/eleven checks/
catalog 1.5.0. Missing/truncated/invalid summaries remain explicit gaps.
Native collection completed sixteen operations/59 audited reads and fifteen
zone summaries; all matched independent type/count/TTL lists (39 selected sets:
24 A/fifteen SOA). Completed replay added no reads or changed bytes. Final
185-case release passed on Windows/Linux. Installed pin
`<implementation-commit>`, auto-update false; all four actual
saved report downloads matched golden bytes with zero processing Azure reads.
Next: choose an explicitly approved owner/forwarding/consumer evidence increment
or additional live DNS-host scope supplied by the user. Never
interpret equal metadata, zero sets or SOA-only summaries as safe cleanup.

**Previous DNS planning continuation:** the user approved service metadata inventory and
an explicit DNS-hosting subscription allowlist, with live validation restricted
to the existing subscription. Published/installed 0.3.0 adds a commercial Microsoft
mapping (91 rows/71 types), fifteen workload operations/ten checks, a scoped
service/subresource/zone matrix and contextual repeated-name ownership review.
170 tests pass on Windows/Linux. Actual collection succeeded with 44 reads,
39 service resources/24 zones/five repeated zone names; independent ARM reads
confirmed service metadata and all zone IDs/name groups. Completed replay
added no reads or changed files. Cross-subscription DNS hosting remains
synthetic-only, and missing zone names cannot explain missing endpoints.
Installed pin is `<implementation-commit>`, auto-update off.
All four actual installed report downloads are byte-identical to the golden
bundle, with zero processing Azure reads and unchanged original 44 execution IDs.
Next: choose one explicitly approved DNS/consumer evidence increment, or an
additional live central-DNS scope supplied by the user. Keep DNS/consumer scope,
record/forwarder/owner gaps and no-safe-deletion limits explicit.

## Start here

Continue development of the Azure Network Health Assessment capability in
`cliveg/sre-agent-plugins-extras`. Increment 0 and the restricted Increment 1
vertical slice are implemented and exercised. **Do not restart the architecture,
build a full assessment, or assume autonomous SRE acquisition is finished.**

The restricted pipeline is now reproduced on this PC. The immediate objective
is Step 3 integrity/repeatability hardening using the development-host bridge;
remove that dependency only if a supported lossless runtime path is proven.

**Previous 0.2.0 continuation:** user-approved opt-in Private Endpoint/Private DNS
published/installed `0.2.0` has fourteen operations/eight configuration-only checks,
while the nine-operation/six-check default remains unchanged. Native collection
completed 43 unique approved reads; completed replay added none and preserved
all output bytes. Twelve independent ARM reads validated three private chains.
149 unchanged tests passed on Windows/native Linux; actual historical delivery
still verifies. Source-map/README/runtime-validation record exact lineage,
contracts and limitations. Exact installed pin is
`<implementation-commit>`, auto-update off. All four enriched
installed outputs independently downloaded byte-identical to golden outputs;
separate processing added zero Azure reads. Upstream WARA packaging was
preserved; this workflow did not install or execute WARA. Next: select one bounded
enrichment/evaluation goal with explicit approval; do not recollect or add
DNS resolution/traffic/public-access tests automatically.

**2026-10-08 continuation:** Step 1 was reproduced on a different user-selected
existing development target and explicitly selected subscription. All nine
restricted operations succeeded, including 40 NIC/IP attachments. Installed
commit `<implementation-commit>` produced four persisted outputs
that independently downloaded byte-for-byte identical to the local bundle.
Eight direct Azure reads verified selected observations; a separate NSG-rule
probe exercised native paging (10 + 10 + 8 rows). The Step 2 bounded file probe
found no accessible ToolOutputs responses; the bridge remains the proven path.
Proceed to Step 3 using the bridge baseline, not by assuming standalone
acquisition. Both read-only references have since been restored at their pinned
revisions and inspected for the first Step 3 increment. Details and current artifact hashes are in the runtime-validation
record. The historical partial run below remains partial.

**First Step 3 increment:** published capability `0.1.1` stages and verifies all
four files before publishing a canonical run directory. Ordinary failures are
retryable without recollecting Azure evidence; existing final/pending paths
remain protected. Abrupt termination may leave pending work requiring explicit
operator review. Input/schema versions and all six checks are unchanged.
This is not the whole Step 3: later report-save
recovery, broader audit surfaces and further integrity cases remain pending. The recorded
Marketplace-installed pin at that increment was `<implementation-commit>`.
After candidate runtime tests, the Marketplace source was explicitly refreshed
and only this plugin reinstalled. A fresh installed input-only replay produced
four saved outputs independently downloaded byte-for-byte identical to local
0.1.1 outputs, with zero Azure recollection. Current CI was not independently
inspected; do not extend the historical CI-pass claims to this commit.

**Selected-input upload recovery:** the development bridge now saves selected
input and scoped upload state privately after bundle completion, then verifies
actual downloaded attachment bytes before returning success. `--resume-upload`
validates the original four-file bundle and reuses a durable receipt without
Azure recollection or report regeneration. The user approved blocking ambiguous
retries: no authoritative attachment inventory was found, so a dispatched upload
without a saved receipt requires an actual `--attachment-receipt`, verified by
download. This is host transport state `1.0.0`, not a change to the installed
capability/checks/contracts. See the plugin README for commands and interruption
limits; do not clear pending upload locks automatically.

**Page-level acquisition resume:** published/installed `0.1.2` adds private selected-page
checkpoints and outstanding-native-request reconciliation. The controlled live
trial resumed a real interrupted subnet page, skipped two completed operations,
and finished 15 executions/15 unique exact commands; completed replay added no
reads or file writes. All nine restricted operations succeeded, and eight direct
Azure reads verified selected observations. The unchanged 95-case suite passed
locally and in an isolated native Linux runtime. Unknown acceptance, terminal
failures, changed identity/catalog/version, expired continuation and stale locks
remain explicit; no automatic fresh restart or missing-evidence inference.
Input/schema and check versions are unchanged. Installation is pinned at
`<implementation-commit>`, auto-update false. Eight supporting
asset hashes match canonical Git bytes; all four resumed-run outputs independently
downloaded byte-identical to local outputs. Installed processing added zero
Azure reads. Remaining work is narrower integrity/audit/report-save recovery
validation, not a reason to restart acquisition or expand domains.

**Literal report/link integrity:** published/installed `0.1.3` fixes schema-valid literal
Markdown and JSON-code link false positives, verifies the exact generated
internal links/anchors and exposes existing JSON version/check provenance.
The 102-case suite passed on Windows and native Linux. Replaying the existing
verified input added no Azure reads and preserved observations/findings apart
from capability/hash provenance; actual older report/upload recovery still
verified without file changes. This is presentation/verification hardening,
not new checks or domains. Broader execution-surface audit and remote
report-save recovery were still pending at that increment; the later bounded
increments below address them. Installed candidate verification is
recorded separately in runtime-validation. Current installed pin is
`<implementation-commit>`, auto-update false. Eight supporting
asset hashes match Git; all four saved views/JSON artifacts independently
downloaded byte-identical to local output and passed link/provenance checks.
Installed processing added zero Azure reads.

**Structured collection audit:** host policy `1.0.0` requires complete presence
of the inspected execution/result fields and rejects visible non-Azure or unknown
non-null activity. Collection and processing threads must be separate, an
intentional user-approved protocol change. Metadata-only `audit.json` is a
private companion to acquisition state, not a fifth canonical report. Detection
is limited to structured thread fields; do not claim prevention/universal
parent-tool enforcement or retroactive certification of older runs.

**Agent-driven report-save recovery:** published/installed `0.1.4` adds verified-original
publication planning, run/hash-specific immutable aliases, durable per-file
native-save phases/receipts and authenticated partial/full download proofs.
The user approved identical-copy retry after ambiguous saves based on documented
overwrite-by-name, not a platform idempotency claim. Local/native Linux tests
passed 122 cases. Installed pin is `<implementation-commit>`,
auto-update false. The actual trial stopped with two receipts, an accepted third
save without a ledger acknowledgement and a pending fourth. Recovery skipped
receipted files, retried only the identical third copy, saved the fourth and
preserved original bytes/mtime. Independent host downloads verified all four
against the golden bundle; processing added zero Azure reads. Missing originals
and native read-back/lifetime gaps remain explicit.

**Step 4 first value increment:** published/installed `0.1.5` contextualizes addressing.
NET-ADDR-001/check catalog/priority policy are `1.1.0`; the other five checks
remain `1.0.0`. Overlap with retained configured peering becomes P1 applicability
evidence collection (not higher severity/proven outage); generic overlap stays
P2. At most one aggregated INFERRED/INFO positive covers valid disjoint collected
ranges, with all comparison evidence and scope limits. 129-case Windows/Linux
tests passed; exact existing six-VNet input adds a four-VNet positive without
changing observations or introducing new domains. Selective/IPv6 peering mode
is uncollected and remains an explicit gap. Installed pin is
`<implementation-commit>`, auto-update false. Eight supporting
hashes match Git; all four saved outputs independently downloaded byte-identical
to local output, with verified positive4/6/all-comparison provenance and
versioned policy. The agent checked returned authenticated delivery proof; zero
new Azure reads or specialist execution.

**Step 4 directional peering:** published/installed `0.1.6` evaluates retained reciprocal
directions once; Connected/Succeeded is configuration-only information, not
traffic/health proof. Initiated/transitions, unknown/future state, ambiguous/
partial reciprocal evidence and external/reference-only targets have explicit
context or evidence records. NET-PEER-001 is `1.1.0`, check catalog `1.2.0`;
priority policy stays `1.1.0`. 138-case Windows/native Linux tests passed.
Existing actual no-peering evidence creates no invented peering findings;
richer peering cases remain synthetic-only. Installed pin is
`<implementation-commit>`, auto-update false. Eight supporting
hashes match Git; all four original reports independently downloaded byte-identical
to local output, with correct check provenance and no invented peering records.
The agent checked returned proof and closed externally verified delivery; zero
new Azure reads. No new domain collection.

Read these authoritative project files in order:

1. [Repository instructions](../.github/copilot-instructions.md).
2. [Source map and permission/lineage record](source-map.md).
3. [Plugin README](../plugins/azure-network-health/README.md).
4. [Runtime validation and historical artifact hashes](../plugins/azure-network-health/runtime-validation.md).
5. This handoff.

The user authorized iterative prototyping without routine per-step approval.
That does not authorize resource mutations, scope expansion, credential transfer,
or changes to either reference checkout. Stop for material new scope/safety
decisions, not routine execution of this plan.

## Published baseline and installation

| Item | Verified baseline |
|---|---|
| Primary repository | https://github.com/cliveg/sre-agent-plugins-extras |
| Branch | `main` |
| Current implementation and installed pin | `<implementation-commit>` |
| Historical Increment 1 validation baseline | `<implementation-commit>` |
| Historical installed partial-run implementation | `<implementation-commit>` |
| Plugin / skill | `azure-network-health` / `azure-network-health-assessment` |
| Capability version | `0.10.0` (first-pass contract `1.0.0`; default input/schema `0.1.0`; private `0.2.0`; planning `0.3.0`; metadata `0.4.0`; paginated paths `0.6.0`) |
| Marketplace registration used in development | `network-health-prototype` |
| Installation name | `network-health-prototype_azure-network-health` |
| Auto-update | Disabled |
| Current regression baseline | 279 passing unittest cases on Windows and isolated native Linux; all four plugins validate; packaging extras dry-run passed |
| Historical implementation CI | [Passed run](https://github.com/cliveg/sre-agent-plugins-extras/actions/runs/37701476025) |
| Historical validation-documentation CI | [Passed run](https://github.com/cliveg/sre-agent-plugins-extras/actions/runs/37701929490) |
| Current implementation CI | Not independently inspected; authenticated Actions tooling unavailable and unauthenticated API returned HTTP 404 |

Documentation may be newer than these implementation commits. Pull current `main`, but distinguish
current checkout version from the actual installed SRE Agent commit. Marketplace
installs are pinned; a Git push does not update the installed skill.

Both root [marketplace.json](../marketplace.json) and
[.github/plugin/marketplace.json](../.github/plugin/marketplace.json) must list the
same plugin set. The [validator](../tools/validate.py) enforces this.

## What is implemented

One Marketplace skill, flat supporting assets, deterministic processing, and an
optional development bridge. No new custom agents, tasks, connectors or hosted
services are needed for the current slice.

```text
Exact scoped reads
  -> selected collection envelope
  -> factual normalization
  -> observed-network.json
  -> six versioned checks
  -> assessment.json
  -> deterministic Markdown views
  -> conversation artifact save/retrieval
```

Every run produces:

```text
runs\<run-id>\
  observed-network.json
  assessment.json
  network-assessment.md
  network-evidence.md
```

Observation JSON has no interpreted findings. Collection operation metadata,
selected evidence, entities, assertions and relationships remain separate.
Assessment records reference checks, evidence and collections; severity and
priority are distinct. Report rendering uses assessment JSON alone.

### Current scope

- One explicitly selected subscription, without IaC.
- Subscription context and resource-group/region context of collected resources.
- VNets, address spaces, subnets, directional peerings.
- Configured route tables/routes and subnet associations.
- NSGs, custom/default rules and subnet associations.
- Minimal NIC/IP configuration attachment references.

### Current check set

All six checks initially used `checkVersion: 1.0.0`. NET-ADDR-001 and
NET-PEER-001 are `1.1.0` in published/installed capability `0.1.6`; check catalog is
`1.2.0` and priority policy stays `1.1.0`. The other four checks remain
`1.0.0`. Historical provenance is preserved.

| ID | Purpose |
|---|---|
| NET-ADDR-001 | Contextual overlap action priority and aggregate scoped disjoint-address positive; neither proves connectivity/overall health |
| NET-PEER-001 | Directional state/reciprocity context and scoped unknown evidence, not connectivity certification |
| NET-NSG-001 | Explicit subnet NSG association absence as contextual observation |
| NET-ROUTE-001 | Configured subnet route-table association as observation |
| NET-ROUTE-002 | Supported configured next-hop consistency, not reachability |
| NET-COVERAGE-001 | Collection/normalization gaps and unverified completeness |

No check infers public reachability from NSG rules. Missing association fields
remain UNKNOWN; presence/absence of an NSG or route table is not automatically
healthy/defective. Configuration is not effective behavior or packet flow.

## Implementation map

| Asset | Responsibility |
|---|---|
| [SKILL.md](../plugins/azure-network-health/skills/azure-network-health-assessment/SKILL.md) | Scope, safety, installed-file procedure, processing and retrieval |
| [acquisition.json](../plugins/azure-network-health/skills/azure-network-health-assessment/acquisition.json) | Exact allowlisted queries, operations, page/expansion budgets |
| [network_health.py](../plugins/azure-network-health/skills/azure-network-health-assessment/network_health.py) | Collection adapter, normalization, six checks, rendering and integrity verification |
| [runtime.py](../plugins/azure-network-health/skills/azure-network-health-assessment/runtime.py) | Increment 0 regression helper and shared JSON Schema/custom-format validation |
| [common.schema.json](../plugins/azure-network-health/skills/azure-network-health-assessment/common.schema.json) | Shared evidence, collection, configuration and data-handling definitions |
| [observed-network.schema.json](../plugins/azure-network-health/skills/azure-network-health-assessment/observed-network.schema.json) | Observation-only contract |
| [assessment.schema.json](../plugins/azure-network-health/skills/azure-network-health-assessment/assessment.schema.json) | Findings, priority, check lineage and deterministic report inputs |
| [checks.json](../plugins/azure-network-health/skills/azure-network-health-assessment/checks.json) | Check IDs/versions, priority-policy version and Learn references |
| [network_health_sre.py](../tools/network_health_sre.py) | Development-host bridge to exact native SRE reads and selected-input attachment |
| [Tests](../plugins/azure-network-health/tests) | Synthetic fixtures, contract/check/report/transport regression cases |
| [Notices](../plugins/azure-network-health/THIRD-PARTY-NOTICES.md) | Upstream attribution, permission and precise adaptation lineage |

## What was actually proven

- Real Marketplace installation delivered supporting files, schemas and helpers.
- Installed code executed through native `RunInTerminal` with Python 3.12.3 and
  existing jsonschema 4.26.0. No sandbox dependency installation.
- Native SRE `RunAzCliReadCommands` performed scoped reads.
- A development bridge obtained actual structured `azCliExecution.output`,
  without asking the model to rewrite resource rows.
- Native NSG-rule paging returned 50 + 50 + 4 = 104 rows.
- Conversation attachment upload preserved the selected input byte-for-byte.
- Installed and local helpers produced identical four-file bundles from that
  exact input; persisted downloads matched every hash.
- Nine independent direct ARM reads matched selected observations, including all
  VNets supporting the overlap records.
- Operation traces contained scoped reads, not assessed-resource mutation.

### Real-world partial-result exercise

The historical native run collected 10 VNets, 32 subnets, 5 peerings, 1 route
table, 0 configured routes, 16 NSGs and 104 rules. NIC/IP attachment collection
failed with native CLI extension-bootstrap warnings. The report correctly stayed
`incomplete-configuration-triage`: three contextual overlap risks, five route-table
observations and three evidence gaps.

A separate retry returned 50 of 66 IP configurations with continuation. It was
not followed or merged into the original run. A local host run collected all 66.
**Do not silently relabel the original partial run as complete.**

Historical run: `c439949d-7d41-4b61-8b42-c1017c7809ce`.
Historical SRE thread: `<thread-id>`.
Hashes and exact tested revisions are in the runtime-validation document.

## New-PC setup

Clone/pull the primary repository and use a clean branch for new changes. Do not
reset or overwrite unrelated work. Use the new PC's actual paths, not the old
machine's session-state directory.

On Windows, from the repository root:

```powershell
git fetch origin
git switch main
git pull --ff-only
git status --short

python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install PyYAML -r plugins\azure-network-health\requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest discover -s plugins\azure-network-health\tests -v
.\.venv\Scripts\python.exe tools\validate.py
```

Use an existing suitable virtual environment if present. Local validation used
Python 3.14; the deployed helper was exercised on Python 3.12. Do not assume the
editor interpreter matches the terminal. Keep the virtual environment untracked;
check ignore configuration before staging.

Connect Azure MCP/SRE Agent MCP through the new PC's normal authenticated tooling.
Reauthenticate Azure CLI and GitHub through normal user sign-in if required; do
not transfer token caches or secrets from this PC.

Required environment-specific inputs:

| Input | Handling |
|---|---|
| Assessment subscription UUID | Explicit user-selected scope; never infer from all accessible subscriptions |
| SRE Agent host subscription, resource group and agent name | May differ from the assessed subscription; verify the intended development target |
| SRE HTTPS endpoint | Resolve from the intended agent resource; bridge validates the `*.azuresre.ai` origin |
| Fresh controlled thread UUID | Create per collection; do not reuse an unrelated or historical thread |
| New run UUID | Generate locally; bundle creation refuses overwrite |
| Private output directory | Outside the repository/public sync; accessible only to authorized users |

The development target used previously was agent `<dev-agent-name>` in
resource group `<dev-agent-resource-group>`, East US 2. Obtain/verify its subscription and endpoint
from the intended Azure context; no credentials are embedded here. Do not assume
the CLI's default subscription hosts that agent.

That historical target was not available in the new-PC context. The continuation
used another existing agent explicitly selected by the user; reconfirm the
intended target and assessment subscription for future runs rather than reusing
either context implicitly. Azure CLI was installed but missing from the session
PATH; check its normal Windows installation path before treating a failed
`Get-Command az` as proof it is uninstalled. Host credentials stayed on the host.

## Reference repositories and permission

Make both references available read-only on the new PC:

| Reference | Upstream | Inspected revision |
|---|---|---|
| Usman Mahmood's assessment project | https://github.com/lavoizer-develop/azure-networking-agent-test-repo | `624bd5c3bf5bd5b8df625cc111c94531dff19148` |
| Daniel Mauser's Network Desk | https://github.com/dmauser/network-desk | `4104279fa4707c24e6038b35b2779fecfdd11eea` |

Workspace paths in the repository instructions describe the original PC; verify
the actual roots on the new PC. Do not modify the references. Inspect canonical
upstream assets and update the source map before new domain work.

Usman's reuse/adaptation/distribution permission is recorded as project-owner-
reported approval; it is not an MIT license. Preserve attribution and obtain/
retain original permission evidence for formal distribution review. Daniel's MIT
copyright/permission notice must remain with applicable adaptations. Upstream
feedback via PR is welcome, but not an automatic reference-edit instruction.

## Next steps, in dependency order

### Step 1: reproduce the restricted run and complete NIC collection

**Depends on:** new-PC local tests and authenticated development target.

1. Reconfirm installed commit, tool capabilities and unchanged agent/task/
   connector baseline. Install only the plugin through the existing Marketplace.
2. Create a fresh controlled SRE thread with MCP, asking it to wait for exact
   catalog commands. Do not invoke broad assessments or automatic approval mode.
3. Run the bridge with a new run ID and page size 50:

```powershell
.\.venv\Scripts\python.exe tools\network_health_sre.py `
  --endpoint <approved-SRE-origin> `
  --thread-id <fresh-thread-UUID> `
  --subscription-id <selected-subscription-UUID> `
  --run-id <new-run-UUID> `
  --page-size 50 `
  --output-root <private-output-directory>
```

4. Capture output metadata privately: input hash, attachment reference, exact
   execution IDs, warnings and local artifact hashes.
5. Keep the collection thread idle. Upload an unchanged copy of selected input
   and its exact hash to a fresh processing thread; have the installed skill
   process it there, attach all four files and summarize generated priorities
   only. Do not rebind acquisition/upload checkpoints to the processing thread.
6. Download and compare bytes to the local bundle; validate schemas, run IDs,
   check versions and evidence links.
7. Independently verify selected observations with direct scoped Azure reads.
8. If NIC collection fails again, retain the failure and test one bounded retry
   separately. Do not automatically install extensions, log in, alter defaults
   or broaden permissions. Preserve native-host failure versus permission-denial
   distinctions.

**Exit criteria:** a new retrievable, deterministic four-file run; all restricted
operations successful where supported, or explicit repeatable failures with a
bounded recovery design. Successful pages still do not prove permission-wide
completeness.

**Likely files:** transport, regression tests, runtime-validation and source map.
Do not add domain checks during this step.

### Step 2: prove a supported in-runtime lossless acquisition path

**Depends on:** reproducible Step 1 baseline.

Investigate before creating another service or connector:

- A later native read surfaced a saved
  `tmp/ToolOutputs/<thread>_RunAzCliReadCommands_<call>.json` reference. Its exact
  shape, completeness, accessibility and lifecycle were not proven. Check whether
  it contains the complete original structured response (including paging
  metadata), rather than a truncated display or model summary.
- Determine whether installed Python can read that file directly and retain only
  selected evidence. Verify it against the raw execution output independently.
- Check a supported native read/file contract or official runtime capability.
  Do not assume sandbox `az` authentication or install a Graph extension as a
  workaround.

Run a bounded experiment that proves: scoped read -> complete raw response in
memory/runtime file -> selected evidence -> normalized model, without host
credentials, model rewriting or unapproved Azure calls.

**Exit criteria:** one supported, repeatable lossless path with real pagination,
explicit failures and unchanged safety controls. If none exists, document that
the bridge remains a prototype dependency and identify the platform gap.

**Likely files:** acquisition adapter, skill procedure, transport tests, README
and validation record. Preserve the bridge until its replacement is proven.

### Step 3: harden repeatability and data integrity

**Depends on:** a stable transport choice from Step 2; does not require new domains.

Review and add focused cases for:

- Page-level acquisition resume is verified with selected checkpoints and
  accepted-request reconciliation. Preserve explicit unknown acceptance, native
  history/continuation retention needs and stale-lock/operator-review limits.
- Row-count drift, duplicate/conflicting rows, missing child arrays and unknown
  association properties.
- Evidence-supported identity, resource-group/region metadata and parent/target
  relationships, including inaccessible/out-of-scope reference-only entities.
- Complete structured audit paging now covers presence/activity of the inspected
  fields and enforces collection-only threads. Missing/new non-null fields stop
  explicitly; preserve unclassified-null/unexposed-surface uncertainty and
  never claim universal parent-tool enforcement.
- Atomic bundle publication/ordinary write cleanup, receipt-verified selected
  input upload recovery and installed report-save recovery are verified. Native
  saves use immutable copies/actual receipts; authenticated download proof is
  separate. Preserve missing-original, sandbox-loss and lifetime limitations.
- Literal-safe report text, JSON-code handling, exact generated links/anchors
  and explicit version/check provenance are verified. Preserve known/unknown
  distinctions, deterministic order and severity versus action priority.

**Exit criteria:** repeated identical-input results, explicit failed/interrupted
run semantics, no success-shaped fallbacks and no sensitive-data regression.
Update check/capability versions when logic changes; record the installed commit.

### Step 4: make the broad triage more useful within the existing scope

**Depends on:** transport/integrity gates above.

Use verified evidence to improve executive prioritization and selected positive
observations. Add only a few high-value checks where requirements and supporting
configuration are clear. Keep subnet/route-table absence contextual and avoid
invented architecture requirements or public-reachability claims.

Evaluate against known fixtures and direct Azure evidence before expanding.
Keep specialist deep dives as bounded recommendations; do not execute all
diagnostics automatically.

**Exit criteria:** measurable additional value without loss of contextual
discipline, report determinism or evidence traceability.

### Step 5: choose the next enrichment, then prove it narrowly

**Depends on:** stable, useful restricted triage.

The first user-approved expansion, **Private Endpoint and Private DNS
configuration together**, is implemented and validated in opt-in 0.2.0. It is
not full private-connectivity certification or approval for further reads.

Inspect Network Desk's exact endpoint/DNS assets and Usman's assessment criteria;
update classifications/downstream lineage first. Preserve DNS configuration
versus actual resolution and endpoint approval versus actual reachability.

Later candidates: relevant firewall/hybrid configuration, bounded effective
routes/security, existing telemetry, optional architecture/IaC/customer standards,
scheduled execution and report publication. Introduce each as a separate tested
increment. IaC must never become a prerequisite.

## Marketplace/API pitfalls to preserve

- Register the normal Git repository URL; `/tree/<branch>` failed literal cloning.
- Refreshing the source clone and reinstalling the plugin was the tested update
  path; check the returned source commit. Auto-update stayed off.
- App routes actually exercised:
  `POST /api/v2/plugins/marketplaces`,
  `GET /api/v2/plugins/marketplaces/<name>/resolve`,
  `POST /api/v2/plugins/marketplaces/<name>/plugins/azure-network-health/install`,
  and `GET /api/v2/plugins/installations`.
- Direct generic skill upload sends only `SKILL.md`, not the supporting bundle.
- Native read results are in structured thread execution fields; MCP's message
  text can omit them. The bridge uses the existing raw thread-messages API.
- HTTP 422 once followed acceptance/execution. Preserve nonce verification and
  idle synchronization; never blindly replay a failed submission.
- Conversation upload uses `POST /api/v1/threads/<thread-id>/attachments` with
  multipart field `files`. Input hash must match at runtime.
- Downloads use `/api/files/<thread-id>/<returned-key>` when the returned key does
  not already include the thread route. Avoid duplicating thread prefixes in an
  already complete `downloadUrl`; use the actual returned metadata.
- These app-observed routes are integration evidence, not a stable public SDK
  guarantee. Recheck behavior on the new PC/platform version.

## Artifact portability, privacy and publication

The previous PC's `.copilot/session-state/...` paths are **not dependencies** and
will not exist on the new PC. The repository contains schemas, synthetic fixtures,
validation history and hashes, not live environment payloads.

Prefer a fresh run. If historical comparison is needed, retrieve the saved
conversation artifacts through normal authenticated access and verify hashes
from the validation record. Retrieval after execution was proven; survival after
sandbox destruction/long-term expiry was not. If old artifacts are unavailable,
report that limitation and use synthetic cases or a new run; do not reconstruct
evidence from report prose.

Do not copy credentials, commit real run bundles, put raw responses in public
GitHub, or treat plaintext identifiers/IPs as nonsensitive. Retention decisions
remain prototype defaults, not Contoso policy.

Generation, conversation retrieval and external publication are separate.
GitHub/SharePoint/OneDrive publication, Outlook notifications and scheduled tasks
remain later work. No generic deployer modification is required for the present
skill-only prototype.

## Boundaries and completion checklist

- Both references remain read-only; all new code belongs in the primary repo.
- No Azure resource changes, remediation, monitoring/diagnostics/log enablement,
  deployments, Terraform/Bicep generation or IaC reconstruction.
- No hidden multi-cloud/multi-vendor import or proliferation of agents/skills.
- Customer standards, scope, knowledge, destinations and allowed tools remain
  configuration/context, not Contoso-specific core code.
- Preserve OBSERVED / DECLARED / INFERRED / UNKNOWN and selected evidence lineage.
- Update source map, notices and runtime-validation with actual outcomes.
- Run targeted tests and repository validator; verify relevant installed behavior.
- Use explicit development scope/identity and record failures/limitations.
- Commit/push coherent verified changes following repository conventions; never
  include secrets or private run data.

## Copyable prompt for the next agent

> Continue Azure Network Health development from `docs/network-health-handoff.md`.
> Read the repository instructions, source map, plugin README and runtime
> validation first. Increment 0 and restricted Increment 1 are implemented; do
> not restart or build the full assessment. The 2026-10-08 continuation reproduced
> Step 1, including NIC collection, native paging, installed processing,
> byte-identical artifact retrieval and selected direct Azure verification.
> The bounded Step 2 ToolOutputs probe found no accessible native response files;
> retain the development-host bridge and do not claim standalone acquisition.
> Begin Step 3 integrity/repeatability hardening on that proven baseline.
> The first Step 3 increment adds staged four-file publication in capability
> 0.1.1. The bridge also has selected-input upload recovery with actual receipt
> verification and ambiguous retries blocked, plus page-level acquisition resume
> in published/installed 0.1.2 with accepted-native-request reconciliation. Continue with
> remaining evaluation gaps or begin Step 4's higher-value contextual triage
> within the existing restricted scope, not new domains. Installed 0.1.4 has
> verified-original report-save recovery, actual-key ledgers and authenticated
> download proof; do not restart collection or regenerate missing originals.
> The first Step 4 value increment is now installed 0.1.5: contextual overlap
> priority and one aggregate INFERRED/INFO disjoint-address positive. Check and
> priority catalogs are 1.1.0; only NET-ADDR-001 changed. Preserve uncollected
> peering-mode/traffic/scope uncertainty and synthetic-only P1 validation.
> Installed 0.1.6 then adds NET-PEER-001 1.1.0 directional reciprocity/state
> triage; check catalog is 1.2.0, priority policy stays 1.1.0. Richer peering
> cases are synthetic-only because the current actual input contains no peers.
> Continue with a bounded next requirement, not automatic domain expansion.
> Host audit policy 1.0.0 now requires complete inspected structured fields and
> collection-only threads. Use a separate processing thread; visible terminal/
> file/MCP/other activity, missing fields or unknown non-null surfaces stop
> acquisition. Preserve unexposed/unclassified-null uncertainty; this is not
> universal parent-tool enforcement.
> Both reference checkouts are restored at their recorded revisions; recheck
> their status and inspect relevant portions before further implementation.
> Both upstream
> reference checkouts are read-only. Use the user's explicit development
> subscription/SRE target, preserve attribution and safety, and validate against
> underlying Azure evidence rather than AI agreement. Routine authorized
> prototyping need not stop for repeated approvals; material scope or safety
> changes still require a decision.
