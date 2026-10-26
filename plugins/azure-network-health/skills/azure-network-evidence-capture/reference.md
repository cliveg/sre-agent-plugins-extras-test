# Runtime contracts and limits

This skill's scripts run inside SRE Agent's workspace execution environment.
The user does not need Azure CLI, PowerShell or Git on a local host. A new agent
still needs its runtime prerequisites, existing managed identity, required read
permissions and an authenticated private output-repository connection.

## Formats

- Reference-network source 1.0.0 uses optional acquisition catalog 1.9.0,
  composing legacy catalog 1.8.0 plus reviewed specialist projections. Its
  selected-input 1.0.0 is a new source profile, not a relabelled old input.
- Reference-led bundle/assessment: 1.0.1; observation and new specialist checks:
  1.0.0, with explicit network/public-source/timeline input roles. The observation
  JSON is compact and lossless; assessment statistics distinguish normalized
  nodes from collected entities. Verification still reproduces original 1.0.0
  reviews and their historical statistics without rewriting them. The core
  projection composes legacy normalization/checks without changing source bytes.
- Configuration selection data: `reviewed-azure-configuration` 1.0.0.
- Runtime profile: `hostless-configuration-snapshot` 1.0.0.
- Capsule: 0.3.0; deterministic replay: 1.0.0.
- Existing-event history profile: `hostless-event-history` 1.0.0; capsule 0.4.0,
  source-specific revision replay 1.0.0.
- Verified workspace Activity Log profile: `hostless-workspace-activity` 1.0.0,
  capsule 0.5.0; no 90-day native-source clamp. Queries stay within an explicit
  maximum one-year range and the existing queryable table history.
- Derived timeline bundle/view/processor: 1.0.0, separate from source capsule
  formats and the assessment output contract.
- Opt-in compact timeline storage/processor: 1.1.0, with the same complete
  normalized 1.0.0 logical view through the public reader. Default inline output
  and existing artifacts remain unchanged.
- Derived configuration comparison bundle/view/processor and deterministic
  comparison rules: 1.0.0; source formats/selection profiles are unchanged.
- Offline restriction observation/assessment profiles, bundle and deterministic
  checks: 1.0.0, explicitly separate from legacy assessment/model schemas.
- Earlier companion capsules 0.1.0/0.2.0 and the assessment skill remain separate
  supported workflows, not silently migrated or relabelled.

Capture checkpoints are mutable recovery state; sealed capsules are immutable
by no-overwrite convention and hash verification. Neither hashes nor unsigned
Git commits by themselves establish source authenticity or tamper-proof storage.
Operator-managed storage permissions and private repository review are separate.

## Bounds

Each capture is one explicit subscription and tenant. Each response or reviewed
array is limited to 1,000 rows, each operation to 100 pages, the plan to 500 jobs
and each invocation to 100 GETs. Exhausted invocation budgets pause for resume;
other exhausted limits retain partial evidence and fail explicitly.

Retained members are limited to 5 MiB, manifests to 64 KiB and total capsules to
20 MiB including the manifest. The ARM bridge bounds raw responses and replies.
SDK authentication/context discovery may make management metadata requests;
collection counters describe the explicitly planned configuration GETs, not all
physical SDK traffic. ARM/network and tool timeouts remain runtime constraints.

History additionally limits returned records to 20,000 per source capsule,
100 pages and 100 requests per invocation. Query windows are explicit UTC,
at most 365 days; Activity Log and ARG changes are clamped to their native
90/14-day windows at planning time. Service Health's start-date filter is
last-update based with a local end bound. An empty result or earliest returned
event does not prove all older history is available.

Source-specific history capsules keep collection times separate from event,
submission and update times. Unknown times remain unknown. Missing source IDs
use capture-occurrence identity, not cross-capture deduplication. Known source
IDs plus retained-payload hashes preserve revisions and avoid collapsing all
events sharing a correlation ID. The hashes describe reviewed retained evidence,
not changes to omitted fields.

Incremental successful captures re-read a 24-hour overlap. The watermark means
terminal query enumeration, not a guarantee that all late events have arrived.
Failed/partial capture does not advance it; workspace partial checkpoints must
be resumed explicitly. Exported workspace history, sensitive detail fetches,
support tickets, configuration comparisons and causal conclusions are outside
this source increment.

## Preferred workspace Activity Log source

The assessed subscription's existing diagnostic settings are read with the
2021-05-01-preview API. They supply destination references and current category
flags, not ingestion/retention proof. Cross-subscription destinations require
explicit read approval. Same-subscription destinations and explicitly approved
existing workspace overrides receive resource/table metadata and a bounded
subscription-filtered AzureActivity summary. Discovery does not query arbitrary
tables or enumerate other subscriptions.

The exact workspace resource/customer-ID binding, source scope, readiness time,
query window, table plan/schema, current retention and observed category/date/
caller counts are retained in the new capsule manifest. None establish continuous
historical completeness. Empty sources and HTTP-200 partial/error responses stay
UNKNOWN. No archive search/restore, export setup, tenant switching, permission
grant or automatic direct-source fallback is implemented.

Data queries use fixed KQL files, select reviewed columns at the server, and
group identical reviewed rows with `Copies`. Differences in omitted fields
cannot be reconstructed from those groups. Paging orders TimeGenerated plus a
reviewed-row hash and uses a 501-row lookahead for 500-row retained pages; cursors
preserve seven fractional digits. A stable event ID is still used for replay
identity, with workspace identity included to keep exports/provenance distinct.
IngestedTime, TimeGenerated and EventSubmissionTimestamp remain separate.
The equal-time hash tie-break uses Kusto `strcmp(RowKey, cursorKey) > 0`:
Kusto rejects a direct relational `>` between strings. Python and PowerShell
query producers use the same intended ordering over fixed lower-case hex hashes.

Counts, access filters, late arrivals and changing ingestion can affect repeated
queries; this is not an atomic Log Analytics snapshot or a guarantee that all
events have arrived. The 24-hour overlap mitigates late arrival, and the watermark
only describes terminal enumeration of this workspace query. Missing categories
must not be hidden behind that watermark.

The 100-page/100-request/20,000-returned-row and 5/20 MiB history budgets remain.
No larger limits are silently enabled. The publisher accepts verified 0.5.0
capsules through the same guarded private-repository path. Readiness JSON itself
is not a completed history capsule. Workspace-local partial-checkpoint loss
remains an explicit limitation.

A known HTTP failure retained in a sealed capsule is not an unconfirmed request.
Completed resume reuses the sealed outcome; `--retry-unconfirmed` is not a repair
for a failed page. Preserve that artifact and obtain an explicit new same-window
run identity after correcting the cause, rather than editing evidence or
silently advancing its watermark.

## Selection and uncertainty

The canonical JSON profile declares resource types, API versions, operations and
approved field shapes. Unknown fields are omitted with paths, not stored as
arbitrary payloads. References and configured rules can be sensitive even when
not secrets: preserve them privately, without unnecessary conversational display.

A missing field is not false, zero, a default or proof of absence. A denied source
has no successful empty-row result. An empty parent list does not mean child list
requests were executed or that controls are absent outside visible scope.

GETs with unconfirmed completion are not automatically retried. A resume may
reuse an already retained page; otherwise explicit retry produces a new attempt
and time. Captures are collection windows, not atomic environment snapshots.

## Publication

The expected repository is supplied explicitly; the connected clone's remote
must match it. The private-destination flag records operator review, not an
unauthenticated GitHub visibility check. Existing connection credentials remain
runtime-managed; no credential-bearing URLs enter receipts.

Source paths are unique under `network-health/captures/<capture-id>/`; derived
timelines use `network-health/timelines/<timeline-id>/`; comparisons use
`network-health/comparisons/<comparison-id>/`. Choose exactly one of `--capsule`,
`--timeline` or `--comparison`. Only verified artifact members are staged. Separate
worktrees preserve original connected/WARA changes. Existing remote branches are
verified against the exact artifact bytes, never overwritten. Publication
receipts live outside the artifact. Remote read-back verifies actual Git object
bytes at the published commit. Process-scoped Git long-path support handles the
nested timeline members on Windows without changing global Git configuration.

## Offline timeline contract

Timeline input is explicitly selected, verified installed capsule formats
0.3.0/0.4.0/0.5.0 from one tenant/subscription. Source scopes, profiles, workspace
identities, manifest/member hashes and every source outcome remain attached.
Older companion formats are not silently accepted or migrated.

The bundle freezes byte-identical sources beneath `sources/<capsule-id>/`.
This makes JSON pointers and Markdown evidence links resolvable offline and on
the derived private branch, without assuming that source branches are checked
out together. The verifier checks exact nested membership and source integrity,
then rebuilds JSON and Markdown rather than trusting rehashed derived claims.
Hashes/unsigned manifests are integrity bindings, not source signatures.

Known event identity is source/profile/scope/workspace-specific. The retained
payload hash identifies its revision; multiple revisions survive. Missing source
IDs use capture-occurrence identity and are not deduplicated across captures.
Overlap deduplicates a matching identity/revision while retaining every witness.
Neither equal correlation IDs nor equal timestamps merge unrelated events.
Raw retained payload differences can reflect representation/ingestion changes,
not substantive configuration changes.

Configuration rows remain observations with collection windows and evidence
references, not invented configuration-change events. Canonical resource IDs
join them to recorded targets; historical-only targets are not inferred deleted.
Subscription-level or otherwise unbound events stay unbound. Correlation groups
mean shared recorded identifiers only; service/region impact matching and causal
analysis are not performed.

Original event/update/submission/ingestion/collection timestamps remain separate,
with exact seven-digit time ordering. Missing time is UNKNOWN, not collection or
processing time. `processedAtUtc` is separate manifest metadata. JSON/Markdown
views are deterministic for the same timeline identity and selected source bytes
regardless of input ordering; a new build retains its actual processing time.

Per-input query/retention/readiness/permission/omission outcomes stay intact.
Unprovided source types and missing parent capsules are explicit gaps. A provided
parent must match the source identity, scope and exact referenced manifest hash.
No aggregate completeness watermark or synthetic coverage interval is created.
A not-provided source is not proof that Azure has no data for it and does not
authorize automatic recollection.

Limits are 20 input capsules and 20,000 aggregate retained event rows plus
configuration observation rows, counting overlap before deduplication. Input
bytes and the self-contained output each remain within 20 MiB; every member,
including the derived JSON/Markdown, is at most 5 MiB and the derived manifest at
most 64 KiB. A smaller member limit can be reached before the row limit. Budget
failure is explicit, not truncation, sharding or automatic limit increases.
Outputs are immutable and must be outside every selected source. There is no
derived-build resume; an incomplete directory is not a verified bundle.

## Compact timeline storage 1.1.0

Explicit `--compact` chooses storage/processor 1.1.0. The source capsule formats,
reviewed fields and normalized logical semantics remain unchanged; no additional
Azure acquisition occurs. All selected source bytes stay embedded.

The root `timeline.json` is an index, not a partial normalized document. It
retains scope, full source manifests, statistics, original coverage/parent
bindings, a source-member registry and descriptors for five paged collections:
events, configuration observations, resource contexts, recorded correlation
groups and unbound event references. Each page descriptor binds its JSON path,
Markdown path, record count and JSON hash; the bundle manifest additionally
binds every actual file.

Compact events keep their identities, revisions, scope/source keys, recorded
target/correlation information and distinct time fields. They do not duplicate
`record` or full witness metadata. `recordStorage=first-witness` identifies the
original payload at the first witness; every witness uses a registry
`memberIndex` and original JSON `pointer`. The registry preserves source capsule,
manifest/member hashes and exact member path. Omissions and collection metadata
remain in the original page/row and are never replaced with defaults or lost.
Configuration observations similarly retain their payload digest and original
witness reference. Multiple source witnesses/revisions still survive.

`network_timeline.read(Path(...))` first verifies either storage version, then
returns the complete normalized **logical 1.0.0** view, including all original
payloads, witnesses and indexes. That view can be larger than a single stored
member: it is an in-process analysis value, not an oversized bundle file.
Filter/aggregate in Python rather than returning it wholesale to the model.
Direct JSON consumers must follow every declared page and source reference;
reading only the root or first page is never complete analysis.

The verifier checks exact membership/hashes, re-verifies sources and regenerates
the root plus every page deterministically. Rehashing a false witness, omitted
page or changed count does not make it authoritative. Unknown versions and
comparison 1.1.0 are rejected; comparison remains 1.0.0. The same publisher
autodetects verified timeline storage and commits the entire self-contained set.

Pages are capped at 500 entries, split further when the actual JSON or Markdown
would exceed 5 MiB. A single overlarge entry or more than 100 pages per section
fails explicitly. The root, all parts, original sources and manifest together
remain within 20 MiB, with a 64 KiB manifest. Existing 20-capsule/20,000-input-row
limits apply, including overlap. No data is dropped and no bound is raised.

## Configuration comparison contract

`network_comparison.py` compares two distinct verified configuration 0.3.0
capsules using the existing profile and explicit before/after manifest bindings.
They must share tenant/subscription and have chronological, nonoverlapping
collection windows. Exact per-GET time order is checked too. Source identity,
profile, coverage and original timestamps remain available; processing time is
separate manifest metadata.

Successful direct resource GETs support comparable retained observations.
Sparse inventory-only rows, denied/unavailable GETs and inconsistent repeated
direct observations remain UNKNOWN. Field absence is not a removal/default;
explicit null is an observed value. All source outcomes, omitted paths and
not-collected operations are retained. One-sided resource visibility is
`newlyObserved` or `notObservedLater`, not authoritative creation/deletion.

The versioned policy lists the currently reviewed ACL/permission/address/
reference membership arrays. It compares those as multisets, preserving
duplicates and nested membership semantics; unlisted arrays retain ordering.
Absolute ARM identifier casing and equivalent integral number representations
are normalized only for comparison. Original values and evidence pointers are
unchanged. No IP-range union equivalence, Azure enforcement, effective reachability
or missing-default inference is implemented.

System data, resource identity metadata and named provider-state/timestamp
fields are classified separately from settings. Metadata-only changes inside
membership arrays are not reported as settings changes. Differences retain
`checkId=configuration-retained-value-difference`, `checkVersion=1.0.0`;
the policy hash records the explicit semantics. These are deterministic evidence
comparisons, not assessment findings, severity/priority verdicts, desired-state
compliance or causation. Mixed array changes are reported at their retained
array path rather than inventing item identities.

The self-contained bundle uses the same verified packaging module as timelines,
with separate comparison views/identity/output paths. Markdown shows paths,
categories, gaps and source links without unnecessarily repeating private values
or actors. JSON and source members retain approved private evidence.

Limits are two input capsules, 20,000 input observation rows, and 20,000 aggregate
compared value paths plus emitted differences/gaps. Existing 5 MiB member,
64 KiB manifest and 20 MiB input/output bounds apply. Exhaustion is explicit;
there is no automatic sharding, truncation, bootstrap or source recollection.
Output must be outside both sources and is never overwritten.

## Public-source restriction contract

`network_restriction.py` reads one verified configuration 0.3.0 capsule offline.
Separate `retained-source-restriction-observations` and
`retained-source-restriction-assessment` profiles are **1.0.0**, with explicit
noncompatibility flags for the legacy 0.13 model/assessment schemas. The four-file
run, manifest and unchanged source capsule are independently verifiable. Both
Markdown reports derive only from assessment JSON.

Successful consistent direct GETs are configuration authority. Inventory-only,
denied, missing, null, omitted, malformed and unsupported evidence does not become
a service default or absence. All original collection outcomes, selected values,
scope, source hashes, exact time strings and omission paths remain available.
Observed facts and inferred/unknown conclusions stay separate.

Each Storage, Key Vault and ACR resource has one data-plane result; Log Analytics
ingestion/query have separate results. `serviceConfiguration` is the local gate:
`PUBLIC_DISABLED`, `SELECTED_NETWORKS`, `UNRESTRICTED` or `UNKNOWN`.
`criterionVerdict` is the qualified technical criterion: `RESTRICTED`,
`NOT_RESTRICTED` or `UNKNOWN`. It is not an owner-approved allowlist check.
Disabled public access is not proof of private connectivity or absent
trusted-service exceptions. Monitor diagnostic ingestion may use a separate
secure Microsoft channel.

Default-Allow and exact bounded IP unions detect unrestricted local settings.
The versioned policy pins IANA IPv4 special-purpose exclusions, global exceptions,
deprecated-block uncertainty and RFC 1112 multicast facts. Excluding only
private/reserved space does not earn a restriction. No runtime-varying
`is_global` heuristic or arbitrary less-than-global range-size threshold is used.
IPv6 whole-family detection is mathematical only; unsupported service selectors
remain UNKNOWN. Address values are retained privately, not printed in reports.

Positive NSP/AMPLS qualification remains gated by representative evidence and
service/path validation. Bare presence, Learning/Transition, Enforced mode or an
approved private endpoint alone never qualifies. Storage/Key Vault/Monitor
overall results remain UNKNOWN when precedence/applicability is unresolved.
ACR uses the inspected unsupported-NSP service policy; a contradictory observed
association also yields UNKNOWN, not invented future support. Empty visible
roots do not prove global or cross-subscription absence.

Deterministic results carry check IDs/versions and a pinned policy hash.
Severity remains unassigned without impact context; priority identifies the next
action, including evidence collection. There are no active reachability,
authorization, customer-policy, private-only, impact or causal certifications.
Processor `azureReads`/`memoryWrites` counters describe its own work, not all
surrounding agent activity. Installed acceptance and memory side-effect audit
must be independently established; the CLI does not certify its installation.

Limits are one source, 20,000 input observation rows and at most 1,000 selectors
per reviewed rule inventory. Existing 5 MiB/member, 64 KiB/manifest and
20 MiB/total limits remain unchanged; exhaustion fails explicitly. Runs are
immutable and output stays outside the source. Publication uses the existing
guarded publisher's `--restriction`, unique `network-restriction/<run-id>`
branches and `network-health/runs/<run-id>/` paths. Exact existing bytes may be
verified again; a new processing-time manifest is not the same publication.

## Reference-led comprehensive assessment contract

`reference_capture.py` uses the existing collection/paging/checkpoint engine,
an explicit managed-identity ARM source and exact reviewed projections.
`reference_profile.py` supplies only the specialist additions: firewall/policy,
gateway/circuit/connection, existing flow-log/Connection Monitor configuration
and public-IP attachment references. Azure-only guidance is adapted from the
credited Network Desk assets; the actual assessment/report sequence and fields
adapt Usman's specification. The sibling
[adapted method](../azure-network-health-assessment/reference-assessment.md)
identifies exact portions and exclusions.

The collector reuses the installed ARM reader in explicit reference-profile
mode. GET paths/APIs are allowlisted; POST is limited to read-only Resource
Graph with one approved subscription. No Azure CLI extension, interactive login,
host credentials, identity substitution or role grant is required. Runtime
dependencies are declared, not bootstrapped. Approved JMESPath is read from its
private directory; existing WARA-pinned Az.Accounts cache is reused.

Each invocation permits at most 100 new logical reads; SDK authentication
metadata traffic is separate. A budget pause is explicit and resumes without
recollection. A durable request journal is written before a physical read and
retains only the selected response or explicit failure. Unconfirmed outcomes
require approved retry and retain the earlier attempt. Completed sources resume
without authentication/reads. Clock evidence and selected-input replay reproduce
the source; SourceAuthentication remains notSigned, not a platform attestation.
Partial native child continuations stay partial, not complete DNS chains.

`network_reference.py build/verify` composes the legacy addressing/peering/
routing/PE/DNS/service checks, deterministic NSG selector/path review and bounded
firewall/hybrid/monitoring configuration questions. The source 1.9.0 core view
is projected to the existing 1.8.0 interface, explicitly recorded as an adapter
view rather than a rewritten original input. Both Markdown views derive from
assessment JSON.

Each of six scorecard areas states evaluated/unassessed questions and actual
source outcomes. Zero findings or empty indexed rows do not produce Healthy.
NSG candidates preserve unsupported/missing selector gaps, default/custom
distinction and effective/admin/listener uncertainty. Public-IP/NIC/subnet
references are configured path candidates only. Firewall rule/hit-count and
hybrid BGP/learned/effective evidence remain uncollected unless explicitly
provided; neither a Connected label nor configured telemetry proves health.
No key/credential, unused-rule, broad-CIDR severity or active-test inference.

Optional verified public-source and compact/legacy timeline bundles are embedded
unchanged. Their tenant/subscription must match; original windows and different
time meanings remain distinct. Recorded event/resource-ID context is not cause,
initiating-human proof or current configuration. The new outer observation file
contains facts/references, not interpreted findings. Compliance remains
unassessed without supplied owner requirements.

Original 5 MiB/member, 64 KiB/manifest and 20 MiB/total limits hold, including
all embedded inputs. Exhaustion fails explicitly. The existing publisher's
`--review` uses unique `network-review/<id>` branches and
`network-health/runs/<id>/`, with adds-only exact membership, unchanged original
connected/WARA worktree and committed-byte read-back. Existing source, timeline,
comparison, restriction and legacy modes remain supported.

## Lineage

Managed-identity/cached-module execution and connected-repository publication
compose this repository's WARA implementation and verified runtime procedure.
Profile fields/parent validation compose its existing native network snapshot
work. Evidence-file primitives follow the primary assessment implementation.
No upstream collector or mutation/rollback code is copied.

Network Desk's snapshot guidance and Usman's contextual evidence discipline
remain acknowledged conceptual foundations. See the primary
[source map](../../../../docs/source-map.md) and the plugin's existing attribution
and permission notices. Future domain expansion requires reference-first review.
History adapts WARA's existing incident/advisory endpoint pattern while adding
separate Activity Log actors, ARG property changes, paging and source revision
contracts. WARA's output named `serviceHealth` is alert-rule configuration;
its outage/retirement reads are the actual incident/advisory foundation.
