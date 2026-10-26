# Azure Network Health Assessment source map

**Decision date:** 2026-10-07  
**Status:** Reference-led read-only configuration report installed and validated; limitations explicit

**Primary repository:** [sre-agent-plugins-extras](https://github.com/cliveg/sre-agent-plugins-extras)  
**Governing instructions:** [copilot-instructions.md](../.github/copilot-instructions.md)

## Purpose and conclusions

### 2026-10-19: reference-led comprehensive report (0.21.0 candidate)

The owner approved fresh read-only evidence in the existing lab subscription,
all six selected areas (topology/addressing/peering; configured routing/egress;
NSG rules and ingress/effective-evidence gaps; Private Endpoint/DNS; existing
telemetry/recorded context; firewall/hybrid), and end-to-end private delivery.
The existing approved Log Analytics destination remains the only workspace for
Activity Log refresh; established 24-hour overlaps and original source times
are retained. No external subscriptions are followed. Resource/permission/
logging changes, active traffic/DNS tests, memory edits and scheduling remain
excluded. Public collector, assessment build/verify and publisher interfaces
were explicitly confirmed as the testing seams.

Both read-only reference roots, canonical origins and clean revisions were
reverified: Network Desk `4104279fa4707c24e6038b35b2779fecfdd11eea`;
Usman's agent `624bd5c3bf5bd5b8df625cc111c94531dff19148`. Permission status is
unchanged: Network Desk MIT with Daniel Mauser attribution/notice retained;
Usman's 2026-10-07 project-owner-reported permission covers the approved reuse/
adaptation/distribution scope, not MIT or an independently verified written grant.

| Capability | Classification | Exact upstream portions | Downstream adaptation / integration |
|---|---|---|---|
| Assessment workflow | ADAPT procedure, not unchanged agent execution | Usman `.github/agents/azure-networking.agent.md`, Operating Workflow, Repository Discovery, Modification Policy and Required Deliverable; `.github/skills/azure-networking/SKILL.md`, Review Principles/Finding Evidence. | Requirements/scope before interpretation; reconcile documentation and observed evidence without treating either as automatically authoritative; separate facts/assumptions/dependencies; persist and verify the authoritative artifact. Adapt repository/IaC-first discovery to connected Azure evidence. No upstream implementation or workload mutation permission is imported. |
| Comprehensive report structure and finding content | ADAPT report specification | Usman `.github/skills/assessment-reporting/SKILL.md`, Reporting Principles, Required Report Structure, Priority Findings, Architecture Observations/Diagram, Requirements Compliance, Recommended Remediation Plan, Positive Findings, Assumptions/Validation and Quality Checks. | `network_reference.py` composes existing findings and specialist reviews into an evidence scorecard, contextual observed/expected/risk/recommendation/dependency records, positive observations and validation actions. Unknown/unassessed is explicit; zero findings never means Healthy. Both Markdown files remain deterministic views of assessment JSON rather than importing the upstream Markdown-authoritative storage convention. Diagrams are configuration-only and evidence-bound, never packet-flow proof. |
| Network inventory and core configuration assessment | ADAPT acquisition procedures / COMPOSE existing primary engine | Network Desk canonical `extensions/network-desk/specialists/vnet-architect/skills/migration-planner/SKILL.md`, Phase 1 Assess; `vnet-architect/skills/peering-advisor/SKILL.md`, Azure directional/key settings/non-transitivity; `network-troubleshooter/skills/routing-debug/SKILL.md`, route evidence workflow. | Reuse primary scoped/paged/checkpointed `network_health.collect`, normalization and existing addressing/peering/routing/PE/DNS checks. The target-runtime adapter is NEW integration, not a new inventory method. Preserve the old catalogs/formats and check behavior; the new optional acquisition catalog adds only reviewed specialist projections. No peering creation, migration, active tests or universal flag/limit heuristic is copied. |
| NSG specialist review | ADAPT Azure procedure / independent deterministic implementation | Network Desk `extensions/network-desk/specialists/network-security/skills/nsg-audit/SKILL.md`, Azure Audit Commands, broad-source management/database selectors, priority/default-rule and usage-evidence review. | Review configured rule candidates, associations and collected public-IP attachment references. Preserve uncertainty from service tags, NIC/subnet combination, priorities, admin rules, effective routes/rules and listeners. An NSG rule or configured attachment alone is not proof of public reachability. Do not copy automatic Critical/High labels, arbitrary CIDR-size thresholds or unsupported unused/shadowed-rule claims. |
| Private Endpoint and DNS specialist review | COMPOSE primary checks / ADAPT specialist procedure | Network Desk `extensions/network-desk/specialists/private-link/agents/private-link.md`, `skills/dns-integration/SKILL.md` and `skills/troubleshoot/SKILL.md`; Usman's private-access/DNS dependency context. | Reuse collected endpoint/approval/zone-group/zone-link/resolver configuration and existing checks. Inspect central/custom DNS alternatives; no universal every-VNet zone-link requirement, DNS mutation or active resolution test. Configured chains remain distinct from proven client resolution or private-only access. |
| Firewall, hybrid and existing telemetry review | ADAPT bounded Azure procedure, deeper evidence explicitly gated | Network Desk `extensions/network-desk/specialists/firewall-engineer/skills/rule-audit/SKILL.md`, Azure export/log evidence and audit categories; `hybrid-connectivity/skills/troubleshoot/SKILL.md`, BGP/tunnel/route evidence; `network-monitor/agents/network-monitor.md`, existing-monitoring requirements and inventory. | First configuration pass retains reviewed firewall/policy, gateway/circuit/connection and existing flow-log/Connection Monitor metadata. Full rule/hit-count, BGP/learned/effective-route, traffic and logging coverage remain unassessed unless actually collected. Reuse verified event-capture profiles for recorded context, not causation. No shared/authorization keys, new monitors, log enablement, multi-cloud procedures or remediation are imported. |
| Versioned report assembly and hostless acquisition | COMPOSE primary primitives / NEW integration | Existing legacy selected-input/normalized/check interfaces; capture identity/exact-JSON/integrity helpers; verified restriction/history artifacts; guarded private Git publisher. | New reference-source and comprehensive-review profiles bind original selected evidence, exact source windows and assessment coverage without changing old artifact bytes. Reuse the existing publisher and deterministic verification, not a separate deployment mechanism. Customer scope remains private configuration, not reusable source defaults. |

Live acceptance on 2026-10-20 retained all 34 network collection outcomes and
652 selected rows, but the observation view's indented JSON was 5,480,343 bytes,
exceeding the unchanged 5 MiB member limit by 237,463 bytes. Patch 0.21.1's
correction is **NEW lossless serialization integration**, not a new assessment
procedure: emit the new observation profile as deterministic compact JSON while
retaining every value, evidence pointer and original source byte. Reinspection
of Usman's reporting skill (Reporting Principles and Quality Checks) and
Network Desk's canonical network-diagram skill at the revisions above found
report/diagram foundations, not this bounded machine-readable storage contract.
Their procedural attribution and permission status are unchanged. Legacy
serializations, budgets and published artifacts must remain unchanged; the
public build/verify seam must reproduce and lock down the measured boundary.
Independent committed-object read-back then found that the new report's
`collectedEntities` statistic also counted context, configuration-object and
reference-only nodes. Patch 0.21.2 is a **NEW integration correction**: preserve
the full normalized model and expose its total separately from entities whose
existing collection state is `collected`. This changes reporting metadata, not
upstream procedures, evidence, classifications or check results. Previously
published reports remain immutable; regenerate under a new review identity.
The corrected assessment/bundle is explicitly versioned **1.0.1**. Verification
of published **1.0.0** reviews retains their original statistics and bytes;
source/observation profiles and all check versions remain unchanged. A synthetic
golden bundle generated by the committed 0.21.1 public API tests this boundary.

Installed 0.21.2 acceptance on 2026-10-20 exercised these actual adaptations
across all six approved areas, using 34 successful outcomes / 652 retained rows
and unchanged public-source/history components. The private 80-file report was
independently fetched and verified; 75 embedded source/component files remained
byte-identical through the corrections. Direct underlying ARM reads corroborated
important VNet/NSG observations rather than relying on agreement between agents.
Source windows, conditional findings, missing effective/operational evidence and
limited action-surface assurance remain explicit. See
[measured installed acceptance](../plugins/azure-network-health/runtime-validation.md#installed-reference-led-comprehensive-acceptance-2026-10-20-utc);
this is not a claim that every upstream specialist procedure or a complete
operational-health assessment has been implemented.

Current runtime inspection found Python/jsonschema/PowerShell available, but
JMESPath and Az.Accounts unavailable. The owner explicitly approved restoring
only WARA-pinned Az.Accounts 3.0.4 from its existing official NuGet URI and
JMESPath 1.1.0 into capability-private runtime storage. These are real dependency
writes, not Azure resource changes or "zero environment writes"; no global
Python packages, Azure CLI extensions, host credentials or role grants are added.
Current Microsoft platform facts are separately checked against primary docs;
upstream examples are not automatically accepted as current limits or requirements.
The native-CLI child projections are adapted to raw ARM shapes using documented
Private DNS zone-group List API 2026-01-01 and Private DNS record-set List API
2018-09-01. Both are GET-only; returned continuation is retained as coverage
evidence, not silently treated as complete enumeration. The existing ARM reader
gains an explicit reference-profile mode; its default PaaS profile is unchanged.
The evidence-bound diagram adapts Network Desk's canonical
`extensions/network-desk/specialists/vnet-architect/skills/network-diagram/SKILL.md`,
Standard Node Shapes/Connection Types/Labeling Conventions, alongside Usman's
Architecture Diagram specification. It uses plain canonical product labels for
portable deterministic rendering, omits unneeded addresses/icons and depicts
only collected configuration relationships. Upstream traffic-arrow examples,
invented hub roles, universal bidirectionality and unsupported external nodes
are excluded; original notices and revisions above apply.

### 2026-10-19: hostless restriction delivery (0.20.0)

The owner approved proceeding with the proposed hostless skill workflow,
guarded private output publication and a pinned release/install acceptance over
the same retained snapshot. This supersedes the previous local-only delivery
boundary for this increment. Offline assessment itself still performs no Azure
collection. Targeted evidence follow-up is read-only and separately recorded;
resource provisioning, memory edits and an unspecified schedule are excluded.

| Capability | Classification | Exact lineage / permission | Decision and integration |
|---|---|---|---|
| Persisted evidence and verified assessment artifacts | ADAPT (conceptual only) | Daniel Mauser / Network Desk `4104279fa4707c24e6038b35b2779fecfdd11eea`, `plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`, Pre-Change Health Snapshot, lines 291-318. MIT, copyright 2025 dmauser; existing notice retained. Usman Mahmood `624bd5c3bf5bd5b8df625cc111c94531dff19148`, `.github/skills/assessment-reporting/SKILL.md`, Reporting Principles and Quality Checks, especially complete persistent artifacts, evidence/count consistency and sensitivity. Both actual read-only roots, clean revisions and canonical origins rechecked. Usman's existing 2026-10-07 project-owner-reported permission remains applicable, not MIT or an independently verified written grant. | No upstream implementation or mutation/rollback procedure copied. Retain the snapshot/persistence/evidence discipline without claiming the underlying concepts are new. Synthetic cases do not close live NSP/AMPLS gates. |
| Hostless offline assessment and private publication | COMPOSE primary assets / NEW workflow integration | Existing restriction companion 1.0.0 build/verify/render and evidence-bundle primitives; existing capture skill, WARA-proven runtime/connected repository and guarded `publish_evidence.py` paths/worktree/committed-byte verification. | Add an explicit offline restriction branch to the existing Azure SRE Agent skill and a `--restriction` publisher input. Use unique `network-restriction/<id>` branches and `network-health/runs/<id>/` output paths. Embed sources unchanged, retain both JSON and Markdown views, preserve the original connected/WARA worktree, and keep source publication separate from evidence publication. Existing source, timeline, comparison and legacy assessment contracts remain unchanged. |
| Installed acceptance and side-effect audit | COMPOSE existing supported management/runtime procedure | Existing direct installer metadata, canonical Git supporting-file hashes, audited RunInTerminal execution and private Git read-back. The prior memory side effect is an unresolved runtime-behavior limitation, not permission to edit memory or a guarantee that a skill can disable automatic behavior. | Package 0.20.0 is a candidate until local checks, actual installed bytes and retained-snapshot runtime/private committed-object acceptance pass. Require matching 36-resource/50-path results and all original non-manifest bytes, with no Azure access during processing. Audit agent-side memory/tool activity separately from processor counters; report any unexpected side effect and stop. No user-host tooling requirement, new dependency, resource change or schedule is introduced. |

Acceptance completed at source pin `<implementation-commit>`,
with all 35 installed Git files verified, unchanged 1.0.0 policy/results and
private output commit `<output-commit>`. All 50
published members were independently fetched; 49 non-manifest files are byte-identical to local
acceptance and all 45 source files remain unchanged. Raw-source/result/link
checks and implementation CI pass. An initial model-transcribed argument failed
preflight; byte-preserved private Git input plus a short exact command recovered
without weakening validation or modifying the failed attempt.

The audited thread contains only the controlled terminal attempts and the
existing prompt-only quality hook; no memory-writer surface was observed.
Indexed knowledge metadata is unchanged but is not synthesized-file history.
Separate read-only follow-up used existing MCP registry listings and a scoped
Resource Graph root query, not a new collector: two Basic ACR targets were
confirmed and no visible indexed NSP/AMPLS roots returned. The existing
[ACR IP-rule contract](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-access-selected-networks)
requires Premium; source documentation commit
`b3cb6805089228a11f733e108a28b84f1a1b8935`. This factual context neither supplies
an omitted default nor closes positive control gates. The frozen assessment,
source profile and permissions stay unchanged. Scheduling has no agreed cadence.

### 2026-10-19: offline public-source restriction assessment (unreleased)

Historical local-only increment; its subsequent 0.20.0 delivery is recorded above.

The owner approved a bounded implementation over retained snapshots and selected
**offline-first**, explicitly excluding new Azure collection, remote agent chat,
memory writes and release/installed acceptance for this increment. It assesses
the technical unrestricted-source criterion, not an owner-approved allowlist,
anonymous access, effective enforcement, reachability, impact or causation.
Log Analytics ingestion/query have independent results. Positive NSP/AMPLS
qualification remains gated by missing representative evidence/live validation.

| Capability | Classification | Exact lineage / permission | Decision and integration |
|---|---|---|---|
| Public/private control distinction and evidence discipline | ADAPT (conceptual only) | Daniel Mauser / Network Desk `4104279fa4707c24e6038b35b2779fecfdd11eea`, `plugins/network-desk/skills/network-desk-pl/reference/security-review/SKILL.md`, Disabling Public Access, and `reference/endpoint-design/SKILL.md`, public-access pitfall. MIT, copyright 2025 dmauser, existing notice retained. Usman Mahmood `624bd5c3bf5bd5b8df625cc111c94531dff19148`, `.github/skills/azure-networking/SKILL.md`, Review Principles, Private Endpoints and Finding Evidence. Project-owner-reported permission from 2026-10-07, not MIT or independently verified written grant. Both read-only roots/origins/revisions rechecked. | No upstream implementation copied. Reuse the distinction between a public-disabled setting and validated private connectivity; preserve uncertainty and requirements separately. Exclude mutation, active tests and generic severity heuristics. |
| Existing configuration interpretation and artifact persistence | COMPOSE primary implementation / NEW companion profile | Existing `network_health.py:service_access_review` establishes the configuration/reachability distinction but only has rule counts and excludes Log Analytics. Compose verified 0.3.0 source capsules, canonical retained selection, evidence integrity and self-contained bundle primitives instead of expanding its historical schemas. | Unreleased `network_restriction.py` consumes a single explicitly selected configuration capsule offline. Separate versioned companion observations/assessment and deterministic executive/evidence Markdown follow the four-file convention under a new `runs/<id>/`; they are not accepted as legacy 0.13 assessment/Observed Network Model inputs and do not alter those schemas or source artifacts. No deployment/publisher/runtime change is required for local validation. |
| Address-union and service-path criterion | NEW independently implemented rules | First-party service contracts below plus IANA IPv4 Special-Purpose Address Registry, `iana-ipv4-special-registry-1.csv`, inspected 2026-10-19; RFC 1112 multicast allocation. Registry address facts only, no copied source implementation. | Exact bounded address-interval union, including /0/equivalent unions. Distinguish whole-family coverage from potential public-unicast coverage so excluding private/reserved-only space cannot earn a false restricted verdict. Preserve the registry's indeterminate/deprecated range as uncertainty. IPv6 whole-family detection is supported mathematically; no unsupported service IPv6 rule is accepted as a positive configuration restriction. Every deterministic result includes check ID/version. |

First-party semantics inspected: Storage firewall rules, limitations (public
setting precedence, trusted-service/resource exceptions, IPv4 selectors), and
Storage NSP (perimeter precedence); Key Vault network security (IPv4 network
rules, public settings and enforced perimeter precedence); ACR selected public
networks/trusted-service exceptions; Azure Monitor NSP supported resources/rules
and Private Link design (independent ingestion/query settings and diagnostic-log
exceptions). Official references are retained in the companion assessment.

Local settings and overall criterion are separate. A selected/default-Allow or
disabled local gate does not resolve missing perimeter precedence/applicability.
The inspected onboarded-resource list does not include ACR; the pinned initial
policy treats ACR NSP as unsupported and never infers future support. Contradictory
ACR perimeter-association evidence does not establish supported
enforcement; an explicit association to an assessed ACR resource contradicts the
pinned support assumption and keeps its overall result UNKNOWN. Matching
NSP/AMPLS references are retained as unqualified evidence, never control success.
Missing fields/selectors, unfamiliar modes, malformed address rules, omitted control
fields and denied GETs stay UNKNOWN. No authentication-only rule, private
endpoint presence or Learning/Transition mode earns a source-restriction pass.
Source times, scope and omissions remain unchanged; no severity/causal finding
is invented. Focused synthetic rules and actual retained-data checks are separate.

### 2026-10-19: compact, paged retained-evidence timeline

The owner selected compact bounded pages after the real ten-capsule build
measured 13,992,672 bytes for its inline JSON and 23,196,441 bytes for sources/
views before the derived manifest, exceeding the existing 5/20 MiB limits.
All three refreshed sources are already durable. This change reprocesses them
offline; it does not recollect Azure data, discard selected inputs or increase
capture/member/manifest/total budgets.

| Capability | Classification | Exact lineage / permission | Decision and integration |
|---|---|---|---|
| Complete evidence, provenance and readable reporting | ADAPT (conceptual only) | Daniel Mauser / Network Desk at `4104279fa4707c24e6038b35b2779fecfdd11eea`, `plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`, Pre-Change Health Snapshot; MIT copyright 2025 dmauser. Usman Mahmood at `624bd5c3bf5bd5b8df625cc111c94531dff19148`, `.github/skills/assessment-reporting/SKILL.md`, Reporting Principles and Quality Checks, especially complete artifact/evidence/count/privacy checks. Existing 2026-10-07 project-owner-reported permission, not MIT or independently verified written grant. Both read-only roots/revisions/remotes reverified. | No upstream implementation copied and no existing snapshot/report concept claimed new. Preserve every selected payload, omission, collection time and witness while keeping human views bounded. |
| Source-backed compact indexes and page-level integrity | NEW derived-storage integration / COMPOSE primary primitives | Primary `network_timeline.py` normalization, source identity/revisions and coverage; `evidence_bundle.py` exact membership/bounds/view rederivation; existing guarded publisher. No equivalent paged immutable cross-source storage implementation was found in the inspected reference portions. | Opt-in timeline storage 1.1.0: unchanged embedded source capsules, deduplicated source-member registry, compact witness/payload references and bounded section JSON/Markdown pages. The small root index declares every page/count/hash. Existing 1.0.0 timeline/comparison/source artifacts remain supported byte-for-byte. Public normalized reading hides the storage layout without returning incomplete pages as whole timelines. |

Initial derived paging is at most 500 entries per page and 100 pages per section,
with byte-aware splitting before the unchanged 5 MiB/member limit. Root/pages,
all selected source files and the derived manifest together stay within 20 MiB;
the manifest remains at most 64 KiB and the existing input-record/capsule bounds
remain in force. Any residual overrun fails explicitly. Pagination is not
permission to trim evidence, silently raise limits or create assessment/causal
findings. Source payloads are referenced, not removed from the self-contained
bundle or reconstructed from conversation.

### 2026-10-18: workspace keyset query correction

The first live second-page Logs request exposed Kusto semantic error `SEM0064`:
the generated predicate compared two strings with `>`. A constant-only direct
Azure Monitor query reproduced the error; changing only that comparison to
`strcmp(...) > 0` returned HTTP 200. Microsoft Learn's
[strcmp contract](https://learn.microsoft.com/en-us/kusto/query/strcmp-function)
defines the ordinal comparison result for Azure Monitor as well as other Kusto
hosts. This is **COMPOSE primary query integration**, not a new collector or
networking procedure: correct both Python/PowerShell producers while preserving
the original reviewed projections, source/cursor/profile contracts and budgets.
The earlier reference/permission decisions above remain applicable; no upstream
implementation is copied. Preserve the failed source artifact and its UNKNOWN
watermark; a fixed same-window run uses a new identity, not a rewritten capsule.

### 2026-10-18: conservative configuration-snapshot comparison

The owner selected configuration comparison and approved one new read-only
snapshot using the existing lab/profile, conservative evidence rules,
self-contained private JSON/Markdown output and release/installed validation.
Routine approval pauses are streamlined; focused checks still protect against
false change reports. Both capability and output repositories were independently
confirmed private. Neither that visibility nor publication permits Azure writes.

The read-only reference roots/origins/revisions were reverified before
implementation. Network Desk's existing snapshot/change guidance is a foundation,
not a new discovery or drift-detection concept.

| Capability | Classification | Exact foundations / permission | Decision and integration |
|---|---|---|---|
| Before/after evidence and cautious interpretation | ADAPT (conceptual only) | Daniel Mauser / Network Desk at `4104279fa4707c24e6038b35b2779fecfdd11eea`, canonical `extensions/network-desk/specialists/network-automation/skills/drift-detection/SKILL.md`, configuration-drift purpose, change-query examples and audit/correlation guidance; `plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`, Pre-Change Health Snapshot. MIT copyright 2025 dmauser, existing attribution retained. Usman Mahmood at `624bd5c3bf5bd5b8df625cc111c94531dff19148`, `.github/skills/azure-networking/SKILL.md`, Review Principles and Finding Evidence. Existing project-owner-reported permission from 2026-10-07, not MIT or independently verified written grant. | No upstream implementation copied. Compare retained deployed observations, not automatically authoritative IaC or a desired-state baseline. Exclude upstream mutation, rollback, scheduling, logging enablement and automatic severity heuristics. |
| New snapshot, verification and persistent private publication | COMPOSE primary implementation | Existing installed 0.17 collector, canonical `configuration-profile.json`, `network_capture.py`, `configuration_profile.py`, evidence primitives and guarded publisher. WARA/runtime/source attribution remains unchanged. | One new unchanged-profile read-only capture, verified and published before comparison. No broader families, fields, scope or uncertain retry. Source formats and acquisition semantics remain unchanged. |
| Comparable observations, explicit value/coverage states and derived comparison | NEW integration / COMPOSE verified sources | No equivalent immutable, source-bound snapshot comparison was found in the inspected reference portions. Primary 0.3.0 capsules expose selected direct GETs, inventory observations, omissions, collection times and per-operation coverage. | New offline comparison processor accepts chronological compatible configuration snapshots in one tenant/subscription. Successful direct observations support settings/metadata differences; missing, denied, omitted or inconsistent evidence remains UNKNOWN. One-sided resource visibility is not a creation/deletion assertion. Rule IDs/versions identify deterministic comparison semantics without creating assessment findings. |
| Self-contained bundle mechanics | COMPOSE / extract primary timeline mechanics | Existing `network_timeline.py` membership, byte limits, self-contained source copying and deterministic view verification, plus `publish_evidence.py` exact staged-set/new-branch/read-back guards. | Share the packaging mechanism between timeline and comparison rather than duplicating it. Preserve the timeline 1.0.0 views and old source replays. Comparison has its own identity, processor, output path/branch and before/after bindings. |

Comparison normalization is a versioned **retained-value comparison policy**:
explicit current ACL/permission/reference/address membership arrays are compared
as multisets, preserving duplicates and original bytes/pointers. Future or
unlisted arrays are not automatically sorted. ARM identifier casing and
equivalent numeric representations do not fabricate settings changes.
Unreviewed values and missing fields do not become defaults, and equal reviewed
arrays do not certify equivalent Azure enforcement. Metadata and provider state
are separate from configured settings; no semantic IP-range equivalence,
security verdict, service impact, requirement violation or causal inference is
introduced. Initial limits remain two input capsules, 20,000 input observation/
derived-entry rows, 5 MiB/member, 64 KiB/manifest and 20 MiB total.

### 2026-10-16: offline evidence timeline and context indexes

The owner approved a versioned JSON/Markdown timeline with resource and recorded
correlation-ID indexes, test-first implementation, release/installed validation,
and private persistence. The self-contained derived bundle retains selected
verified source capsules byte-for-byte so its evidence links and offline
verification do not depend on several source branches remaining checked out.
Source capsules and the assessment's four output contracts are not rewritten.

Both read-only reference roots, origins and revisions were reverified before
implementation. Searches covered timeline, change-history, Activity Log and
snapshot-comparison foundations, including the reference's hidden `.github`
skill directory. General snapshots, change queries and reporting are established
foundations, not claimed as new concepts.

| Capability | Classification | Exact foundations / permission | Decision and integration |
|---|---|---|---|
| Snapshot/change context and provenance-aware reporting discipline | ADAPT (conceptual only) | Daniel Mauser / Network Desk, `4104279fa4707c24e6038b35b2779fecfdd11eea`, `plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`, Pre-Change Health Snapshot; canonical `extensions/network-desk/specialists/network-automation/skills/drift-detection/SKILL.md`, change-query examples and Best Practices audit/correlation guidance. MIT, copyright 2025 dmauser; existing notice preserved. Usman Mahmood, `624bd5c3bf5bd5b8df625cc111c94531dff19148`, `.github/skills/azure-networking/SKILL.md`, Review Principles/Finding Evidence, and `.github/skills/assessment-reporting/SKILL.md`, Reporting Principles/Quality Checks. Existing project-owner-reported 2026-10-07 permission, not MIT or independently verified written grant. | Preserve original times, traceable evidence, omissions and uncertainty. No upstream implementation copied. Do not copy remediation, Terraform deployment, logging enablement, severity heuristics or desired-state assumptions. |
| Input verification, source-specific normalization and private publication | COMPOSE primary implementation | Installed `network_capture.py` and `network_history.py` verify/replay, reviewed configuration/event/workspace profiles, exact-precision time helper, `evidence_files.py` integrity primitives and `publish_evidence.py` guarded Git workflow. Existing WARA/runtime attributions remain unchanged. | Initially accept installed capsule formats 0.3.0/0.4.0/0.5.0 only. Preserve source-specific identity/revisions, all supporting references and per-input coverage. Extend the same publisher for a separately verified timeline artifact; do not duplicate deployment or Git mechanisms. |
| Self-contained cross-capsule evidence timeline and context indexes | NEW derived contract / COMPOSE existing primitives | No equivalent immutable multi-capsule timeline implementation was found in the inspected reference portions. Primary capsule/replay contracts provide the source data; the new work is their normalized integration and persistent derived view, not discovery or general change analysis. | `scripts/network_timeline.py`: source-bound deduplication and revision retention, exact resource-ID/recorded correlation-ID context indexes, configuration observation references, deterministic JSON/Markdown and self-contained integrity verification. Same tenant/subscription only; no Azure calls, implicit source expansion, snapshot-difference verdicts, service/region impact inference or causal conclusions. |

Initial bounds reuse the current 5 MiB member, 64 KiB manifest and 20 MiB total
evidence limits, with at most 20 input capsules and 20,000 input event/configuration
observation records. Exhaustion is explicit failure, not truncation or a partial
success-shaped timeline. Publication remains separately approved, capsule/source
bytes remain immutable, and original collection time never becomes event time.

### 2026-10-15: Log Analytics-first Activity Log evidence

The owner selected Log Analytics-first discovery/collection after the direct
Activity Log pilot reached its declared byte budget. That existing capture stays
paused. Workspace access is not inferred from a configured export or a connector;
cross-subscription workspace reads require explicit approval and inaccessible/
empty/partial evidence remains UNKNOWN. No automatic direct-source fallback,
tenant switch, identity change, diagnostic/export/retention changes or grants.

| Capability | Classification | Exact lineage / permission | Decision and integration |
|---|---|---|---|
| Destination selection and history-boundary discovery | COMPOSE primary SLA guidance / NEW guarded integration | `plugins/sla-reporting/skills/sla-availability/SKILL.md`, Step 4 workspace precedence and history query; `extras/knowledge-base/sla-methodology.md`, Choosing the Activity Log workspace. Preserve existing Guil Lima attribution. The original skill's logging-setup actions and empty-result-as-no-setting inference are not reused. | Explicit approved workspace or current subscription export destination, followed by actual subscription-filtered rows/categories/date checks. Missing history is not proof that exports do not exist. |
| Workspace/table/schema and retention review | ADAPT (conceptual only) | Network Desk N=`4104279fa4707c24e6038b35b2779fecfdd11eea`, `plugins/network-desk/skills/network-desk-nmon/reference/traffic-analytics/SKILL.md`, Log Analytics Workspace Requirement/schema validation; MIT. Usman U=`624bd5c3bf5bd5b8df625cc111c94531dff19148`, `.github/skills/azure-networking/SKILL.md`, Finding Evidence; existing project-owner-reported permission, not MIT. Read-only roots/origins rechecked; no upstream implementation copied. | Read existing metadata only. Analytics-query availability, table retention and observed dates are distinct; missing/archive coverage is recorded, never enabled or treated as absence. |
| Fixed Logs queries, bounded paging and immutable provenance | NEW integration / COMPOSE primary runtime | Azure Monitor Logs API `/v1/workspaces/<id>/query`, official AzureActivity schema and HTTP-200 PartialError contract. Primary managed-identity context, history checkpoints, reviewed event selection, capsule/publisher integrity. | Server-side subscription/category/window filters and reviewed columns, explicit workspace-ID binding, keyset pages and partial-result refusal. Separate profile/capsule from existing native Activity Log evidence; original event times and actor attribution remain private. |

First-party references: Microsoft Learn `azure/azure-monitor/logs/api/access-api`,
`request-format`, `response-format`; `azure/azure-monitor/reference/tables/azureactivity`;
Monitor Subscription Diagnostic Settings List 2021-05-01-preview. Logs credentials
remain process-local and are never printed, persisted, passed through the model or
copied from a host. Query operations are read-only POSTs, not resource changes.
Nonempty live acceptance remains open while no approved accessible workspace has
the assessed subscription's Activity Log data.

### 2026-10-14: hostless existing change and health-event history

The owner approved subscription-wide event metadata, before/after values only
for reviewed configuration paths, three source-specific capsules, native
retention-aware windows, a 24-hour incremental overlap and installed runtime
validation. Existing exported Log Analytics history is explicitly outside this
increment; no exports, diagnostics or alerts are created.

| Capability | Classification | Exact foundations / permission | Decision and integration |
|---|---|---|---|
| Incident/advisory history acquisition | ADAPT procedural foundation / COMPOSE primary runtime | Microsoft Azure WARA at `86832273f857b7298b625b26d18e2e0dbb06714c`, `src/modules/wara/outage/outage.psm1`, `Get-WAFOldOutage`, and `src/modules/wara/retirement/retirement.psm1`, `Get-WAFResourceRetirement`, ResourceHealth/events GET patterns. MIT, copyright 2024 Microsoft Azure; no upstream implementation copied. Primary WARA's managed-identity runtime and installed capture bridge remain shared foundations. | Broader first-party subscription event feed with paging, request outcomes and retained revisions. WARA's hardcoded three-month/unpaginated subsets do not prove full history. `src/modules/wara/servicehealth/servicehealth.psm1` collects alert-rule configuration, not an incident feed. |
| Actor metadata and property-change evidence | NEW integration / ADAPT existing guidance | Network Desk N=`4104279fa4707c24e6038b35b2779fecfdd11eea`, `plugins/network-desk/skills/network-desk-nauto/reference/drift-detection/SKILL.md`, ARG change-query examples and Activity Log actor correlation guidance. MIT; no example copied as an executable collector. Usman U=`624bd5c3bf5bd5b8df625cc111c94531dff19148`, `.github/skills/azure-networking/SKILL.md`, Finding Evidence; existing project-owner-reported permission, not MIT. Both read-only roots/origins rechecked. | Native Activity Log and fixed read-only Resource Graph queries. Retain recorded attribution, System/Unspecified, missing fields and reviewed deltas without treating correlation/permission action as causation/actual operation. No Entra identity lookups or current-inventory-only filtering. |
| Source-specific history capsule and revision replay | NEW contract / COMPOSE primary evidence primitives | Installed `evidence_files.py`, managed-identity process transport, capsule publisher and reviewed `configuration-profile.json`. | Separate history profile/capsule, original timestamps, retention gaps, explicit cursor/denial/partial outcomes and no watermark advance on gaps. Existing configuration/assessment/capsule bytes remain separate and compatible. |

First-party contracts: Activity Logs List 2015-04-01 (restricted timestamp
filter; caller/category and event/submission times); Resource Graph resources
query 2022-10-01 and `resourcechanges` (14-day native history, changesCount,
changeType, changeAttributes, source truncation); ResourceHealth/events
2025-05-01 (subscription health feed, queryStartTime based on lastUpdateTime,
nextLink, eventSource and per-region updates). The latter requests up to one
year where available; its default three-day filter or lack of an explicit
upper-retention guarantee is not treated as proof of one-year completeness.
SDK Resource Graph POST is a fixed query operation, not a resource write.
No sensitive-event fetchEventDetails call or unreviewed payload retention.

Downstream: installed capture skill history command/supporting modules,
source-specific verify/replay and the existing guarded private publisher.
Capsule completion means finalized selected bytes, not universal source
availability, desired state, root cause, or operational health certification.

### 2026-10-13: packaged hostless configuration-evidence skill

The owner approved a dedicated capture skill in the existing plugin, preserving
the assessment skill, and approved an isolated primary test branch/installed
package validation. Capture uses only existing managed identity and ARM GETs;
private evidence publication is separately explicit. Unconfirmed reads require
an explicit retry with an additional attempt/time record. No workload changes,
new diagnostics, grants, interactive authentication or package bootstrap.

| Capability | Classification | Exact foundation and permission | Packaged integration |
|---|---|---|---|
| In-agent managed-identity ARM transport | COMPOSE / ADAPT primary WARA runtime | Primary WARA `scripts/Invoke-WaraRun.ps1`, `Connect-WaraAzure` managed-identity branch; `scripts/Get-EnvironmentEvidence.ps1`, cached-module import and ARM wrapper; primary revision `<implementation-commit>` (WARA change `<implementation-commit>`). Repository MIT, Clive Graven. No upstream collector/report implementation copied. | Packaged process-scoped PowerShell/Az.Accounts transport. Authentication/context metadata only; raw provider bodies remain process-local and are filtered before persistence/model output. |
| Reviewed fields, scope/parent validation and byte integrity | COMPOSE existing primary evidence work | `tools/network_health_snapshot.py` reviewed schema/API catalog and `tools/network_health_capsule.py` bounded file/hash guards; primary `network_health.py` canonical JSON/immutable-write primitives. | Share reviewed profile data and evidence-file helpers with the installed capture runtime. New runtime provenance is not falsely labelled native CLI audit. Legacy capture/capsule formats and assessment assets retain their intended behavior. |
| Private repository publication/readback | COMPOSE WARA procedure / NEW guarded integration | WARA skill publication instructions, scheduled `codeRefs` output convention and actual hash-verified publication spike. Connected-repo credentials are runtime-managed, never copied from host or stored in evidence. | Explicit expected repository, unique output branch/worktree, capsule-only staging, remote commit/hash confirmation, fresh replay; no automatic primary/source branch changes. |
| Observation/requirements separation | ADAPT (conceptual only) | Usman's `.github/skills/azure-networking/SKILL.md`, Review Principles, U=`624bd5c3bf5bd5b8df625cc111c94531dff19148`, existing project-owner-reported permission, not MIT. Network Desk snapshot foundation `plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`, N=`4104279fa4707c24e6038b35b2779fecfdd11eea`, MIT. Read-only roots/origins rechecked. | Snapshot observations/coverage/replay only. No health, compliance, source-signing, effective traffic or causal claims. Event history and comparison remain separate increments. |

Downstream assets: `skills/azure-network-evidence-capture/` and its supporting
scripts, within `plugins/azure-network-health`. The existing generic installer/
extras deployer remains the packaging workflow; no capability-specific deployer.
Retain existing plugin and WARA/APRL attribution/notices. Runtime prerequisites
are checked, not silently installed. A new installed-package pass must verify
actual supporting-file bytes, not just the Markdown skill content.

### 2026-10-13: WARA-style hostless runtime and evidence publication spike

The owner confirmed the existing private output repository and selected
`<lab-agent-name>`, the WARA-tested hosting agent. Retention cleanup is
outside this spike. No workload writes, permission grants, diagnostics enablement
or execution of the WARA assessment itself is authorized.

| Capability | Classification | Exact lineage / permission | Decision and integration |
|---|---|---|---|
| Sandbox execution and managed-identity ARM access | COMPOSE existing primary WARA foundation | `plugins/wara-assessment/skills/wara-assessment/scripts/Invoke-WaraRun.ps1`, `Connect-WaraAzure` (managed-identity branch only); `scripts/Get-EnvironmentEvidence.ps1`, cached-module loading and `Invoke-Arm`. Repository MIT, Clive Graven; existing upstream WARA/APRL notices retained. | Reuse the existing PowerShell/Az.Accounts runtime and process-scoped managed identity. No interactive fallback, package bootstrap or host credential transfer. Directly serialize reviewed values from the in-agent ARM result, not chat text. |
| Connected private output-repository publication | COMPOSE existing WARA procedure | WARA `SKILL.md`, output commit/push procedure; `extras/scheduled-task-templates/wara-monthly.yaml`, connected `codeRefs` output root; `docs/wara-handoff.md`, independently verified Git-byte hashes. | Publish only a new, uniquely scoped feasibility artifact and manifest using the agent's existing Git connection; independently read committed bytes and verify hashes. No primary-source repository publication or unrelated worktree changes. |
| Small deterministic network evidence/manifest probe | NEW integration | Existing network capsule byte/provenance discipline, adapted to WARA's proven in-runtime acquisition/output path. | A single scoped management GET and a fresh-process replay/publish test establish feasibility, not a full collector, an installed-skill pass or universal source completeness. |

Read-only external reference roots/origins remain N=`4104279fa4707c24e6038b35b2779fecfdd11eea`
and U=`624bd5c3bf5bd5b8df625cc111c94531dff19148`. Network Desk's
`plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`,
Pre-Change Health Snapshot, and Usman's `.github/skills/azure-networking/SKILL.md`,
Review Principles, remain conceptual foundations, with MIT and the existing
project-owner-reported permission respectively. No external implementation is
copied. WARA sections named outages/serviceHealth do not alone establish exact
historical endpoint/time-window coverage; inspect the pinned upstream collector
before composing those data sources.

### 2026-10-12: reviewed native configuration snapshot acquisition

Both reference roots/origins were rechecked at unchanged N/U revisions:
Network Desk `4104279fa4707c24e6038b35b2779fecfdd11eea`
(`https://github.com/dmauser/network-desk`), MIT, and Usman
`624bd5c3bf5bd5b8df625cc111c94531dff19148`
(`https://github.com/lavoizer-develop/azure-networking-agent-test-repo`),
existing project-owner-reported permission, not MIT.

| Capability | Classification | Exact foundation / permission | Decision and integration |
|---|---|---|---|
| Resource discovery, configuration reads and retained snapshots | ADAPT (procedural/conceptual foundation) | Network Desk, `plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`, Pre-Change Health Snapshot; `plugins/network-desk/skills/network-desk-pl/reference/security-review/SKILL.md`, public-access/private-endpoint distinction. MIT notice remains applicable to any copied implementation; none is copied here. | Independently implemented, versioned reviewed configuration profile. Do not copy mutation, rollback, logging enablement or public-upload examples. |
| Contextual evidence and external dependencies | ADAPT (conceptual only) | Usman, `.github/skills/azure-networking/SKILL.md`, Review Principles and Private Endpoints. Existing reported permission/attribution preserved. | Retain source fields, omissions and external references without inventing requirements, health, reachability or policy findings. |
| Native snapshot acquisition, source/capsule contracts and replay | NEW integration / COMPOSE primary transport | Existing `tools/network_health_sre.py` exact native dispatch, nonce recovery, collection-only audit, atomic checkpoint snapshots; `tools/network_health_capsule.py` immutable publication and member verification. | `tools/network_health_snapshot.py`: explicit subscription/tenant context, reviewed root/per-resource/parent-bound child reads, bounded paging, durable resume and captured native provenance. Extend capsule profile handling without modifying legacy source shapes, checkpoints, assessment schemas or installed assets. |

The owner chose native SRE acquisition rather than an operator-ARM collector.
The development host controls collection through the existing SRE transport;
this is not an autonomous in-sandbox collector or an operator read substituted
for a native result. Scope is the four service families plus NSP/AMPLS configuration.
Control references do not authorize external resource/subscription reads.

First-party ARM references are API/property contracts, not copied implementation
or generated deployable IaC: Storage 2023-05-01, Key Vault and ACR 2023-07-01,
Log Analytics 2023-09-01, NSP 2024-07-01 and AMPLS 2021-07-01-preview.
Reviewed selection retains network/security/reliability configuration, needed
policy/identity references and exact rules; no key/secret values, tokens, tags,
contact data or diagnostics. Presence/omission metadata must distinguish missing
from null rather than applying documented defaults. Native projection syntax is
tested against the Azure CLI JMESPath language before a live read.

### 2026-10-12: offline selected-evidence capsule pilot

Reference roots, canonical origins and revisions were rechecked unchanged:
Daniel Mauser/Network Desk `4104279fa4707c24e6038b35b2779fecfdd11eea`
(`https://github.com/dmauser/network-desk`), MIT; Usman Mahmood
`624bd5c3bf5bd5b8df625cc111c94531dff19148`
(`https://github.com/lavoizer-develop/azure-networking-agent-test-repo`),
existing project-owner-reported permission, not an MIT license.

| Capability | Classification | Exact foundation and decision | Downstream integration |
|---|---|---|---|
| Configuration snapshot retention | ADAPT (conceptual only) | Network Desk, `plugins/network-desk/skills/network-desk-nauto/reference/rollback/SKILL.md`, Pre-Change Health Snapshot. Existing topology/effective-route/NSG snapshot guidance is an established foundation, not a new concept. No commands, deployment, rollback or public-upload implementation is copied. | Development-only offline capsule over an already collected, reviewed selected-inventory profile. No broader collection is implemented. |
| Evidence versus requirements and assumptions | ADAPT (conceptual only) | Usman, `.github/skills/azure-networking/SKILL.md`, Review Principles and Finding Evidence. Preserve attribution and existing permission record; no upstream implementation copied. | Replay contains resource/configuration observations, provenance and coverage, not findings, desired state or causal claims. |
| Capsule manifest, bounded member integrity and deterministic replay | NEW integration / COMPOSE existing primary primitives | Primary `network_health.py` canonical encoding, UUID/JSON guards and immutable file helper; existing tool-side companion conventions. No equivalent normalized capsule contract was found in the inspected snapshot/assessment portions. | `tools/network_health_capsule.py` seals, verifies and replays selected evidence outside the repository, preserving exact source bytes, unavailable fields, failures and original times. Supported profile/format versions are explicit. Existing checkpoints, schemas, installed assets and four reports are unchanged. |
| Change and health timeline collection, comparison and restriction verdicts | NOT_NEEDED for this pilot | Network Desk change-query guidance and existing SLA health-query foundations remain relevant for later work. An inventory capsule cannot fabricate their evidence. | Explicit not-collected source coverage; no Azure calls, log enablement, scheduling, resource provisioning or new assessment check. |

This independently implemented pilot uses synthetic public-interface tests and
offline replay of private selected evidence. Private resource identifiers, rule
values, actor evidence and storage paths do not belong in reusable source assets.
Hash bindings establish retained-byte integrity, not source authenticity or
tamper-proof storage. Storage access is operator-managed and reviewed separately;
no encryption or ACL enforcement is claimed by the offline codec.

### 2026-10-12: development acquisition checkpoint snapshot locality

Both reference roots and canonical origins were verified at unchanged revisions:
Daniel Mauser/Network Desk `4104279fa4707c24e6038b35b2779fecfdd11eea`
(`https://github.com/dmauser/network-desk`), and Usman Mahmood
`624bd5c3bf5bd5b8df625cc111c94531dff19148`
(`https://github.com/lavoizer-develop/azure-networking-agent-test-repo`).
Searches for checkpoint/resume/pending-read/seen-execution/lock mechanics in
their Markdown, Python, PowerShell and shell assets found no equivalent runner.

| Capability | Classification | Inspected foundations / permission | Decision and integration |
|---|---|---|---|
| Durable acquisition snapshot mechanics | COMPOSE existing primary implementation | `tools/network_health_sre.py` and `tools/network_health_first_pass.py`, snapshot callbacks: progress hashing, sorted approved commands/execution IDs, selected-evidence budget and atomic state persistence. No external implementation copied or adapted. | Share only snapshot persistence in the existing development transport module. Preserve caller-specific validation, warnings, progress/pending ordering, locks, formats and versions. No migration or installed-asset change. |
| Network inventory/snapshot and evidence foundations | NOT_NEEDED for this refactor | Network Desk, `plugins/network-desk/skills/network-desk-vnet/reference/migration-planner/SKILL.md`, Phase 1 inventory/export examples; `network-desk-vwan/reference/secured-vhub-design/SKILL.md`, Observability snapshot guidance. MIT, copyright 2025 dmauser. Usman, `.github/skills/azure-networking/SKILL.md`, Review Principles and Finding Evidence; existing project-owner-reported permission, not MIT. | These are established conceptual/procedural foundations, not durable native-request recovery implementations. No new networking procedure, reference implementation reuse, telemetry enablement or Azure read is introduced. Existing attribution and permission records remain unchanged. |

Validation uses the existing acquisition entry points with synthetic native
transport, not a new helper-specific test seam. Baseline checkpoint and canonical
artifact bytes are compared before/after with fixed synthetic time and nonces.
This is development-tool locality work, not additional live/customer validation.

### 2026-10-11: bounded NSP configuration evidence

The owner selected NSP association/profile/enforcement-configuration evidence,
not customer exception approval or AMPLS expansion. Both read-only roots and
canonical origins were rechecked at unchanged N/U revisions. Exact searches
for "network security perimeter"/NSP found no corresponding capability in the
inspected Markdown/JSON/Terraform/Python assets; N's IPv6 compatibility references
use NSP to mean **Network-Specific Prefix**, not this Azure control.

| Capability | Classification | Inspected foundations / permission | Decision and integration |
|---|---|---|---|
| Contextual alternative-control assessment | ADAPT (conceptual only) | Daniel Mauser/Network Desk N, `plugins/network-desk/skills/network-desk-pl/reference/security-review/SKILL.md`, security checklist and PE/public-access pitfall; Usman Mahmood U, `.github/skills/azure-networking/SKILL.md`, sections 7/10. Existing MIT notice and project-owner-reported U permission remain unchanged. | Retain distinction between configuration and demonstrated reachability/enforcement; no copied mutation, active-test, logging-enablement or customer requirements. |
| NSP selected acquisition and normalized configuration review | NEW integration / COMPOSE existing primary transport | No NSP implementation found in the inspected reference portions. Compose existing scoped ARM pagination, native audit, parent discovery/checkpoints and four-report publication. | Opt-in acquisition 1.8.0/input-schema 0.9.0, four API 2024-07-01 lists: perimeters, profiles, resource associations and access-rule metadata. References outside workload/collected parents remain references only. |
| Operational NSP enforcement, rule-value interpretation, exception acceptance and AMPLS | NOT_NEEDED for this increment | Public-mode/resource presence is not actual enforcement or owner approval. Rule values add unnecessary sensitivity for this first bounded configuration pass. | Preserve raw configured mode and state, profile/target IDs and selector counts only; never accept an exception, equate Enforced configuration to demonstrated enforcement or enable diagnostics. |

First-party sources, inspected as guidance/API contracts, not copied source:

- [NSP concepts](https://learn.microsoft.com/azure/private-link/network-security-perimeter-concepts),
  `articles/private-link/network-security-perimeter-concepts.md`, revision
  `5bbc523a9a6a999e3c3c029879e78e32fd699eb5`: Transition (formerly Learning)
  versus Enforced, profiles/associations and supported Monitor resource types.
  Azure Monitor workspace is not Log Analytics; no general Monitor exception.
- [List by subscription, 2024-07-01](https://learn.microsoft.com/rest/api/network-security-perimeter/network-security-perimeters/list-by-subscription?view=rest-network-security-perimeter-2024-07-01),
  `docs-ref-autogen/network-security-perimeter/rest-network-security-perimeter-2024-07-01/Network-Security-Perimeters/List-By-Subscription.yml`,
  revision `93be31cf21878555480582e96429309478ad0d0d`; documented `$top` bound 1–20.
- Microsoft schema-reference revision
  `a80a6ca0ce31aae2ff0424e8453153664e18bc8b`,
  `arm-schema-ref/Microsoft.Network/2024-07-01/networksecurityperimeters/`:
  [resourceassociations.md](https://learn.microsoft.com/azure/templates/microsoft.network/2024-07-01/networksecurityperimeters/resourceassociations),
  [profiles.md](https://learn.microsoft.com/azure/templates/microsoft.network/2024-07-01/networksecurityperimeters/profiles),
  [profiles/accessrules.md](https://learn.microsoft.com/azure/templates/microsoft.network/2024-07-01/networksecurityperimeters/profiles/accessrules).
  These were inspected for properties only, not to generate deployable IaC.
  API enum Audit/Enforced/Learning remains raw; unfamiliar modes stay UNKNOWN.
- Child-list REST documentation views requested for 2024-07-01 fell back to
  2023-08-01-preview. Inspected revision
  `a8cc930f2418a5d1bdf850fb62f2770c483e8e7a`,
  `docs-ref-autogen/network-security-perimeter/rest-network-security-perimeter-2023-08-01-preview/`:
  `Nsp-Profiles/List.yml`, `Nsp-Associations/List.yml`, `Nsp-Access-Rules/List.yml`.
  Do not mislabel these as 2024 REST documentation or claim nonempty stable
  child-list runtime validation without actual evidence. Stable resource schemas
  and these list paths ground the adapter; actual permission/API failures remain
  explicit. Microsoft retains authorship.

Only provisioning state, association target/profile/mode/issue flag, rule
direction and array-selector counts are selected. No IP prefixes, FQDNs,
subscription selectors, service-tag values, email/phone values or full responses
are retained. Missing arrays never imply zero. Enforced, transition/learning,
audit, unknown/provisioning issues, incomplete profile/rule coverage and services
with perimeter mode but unobserved associations remain distinct. Zero accessible
perimeters does not prove no perimeter outside scope or no protected service.

### 2026-10-11: integrated direct ARM service-control reconciliation

The owner selected direct ARM evidence/reconciliation rather than NSP expansion
or Contoso execution. Both reference roots, canonical origins and revisions
were rechecked: N=`4104279fa4707c24e6038b35b2779fecfdd11eea`,
U=`624bd5c3bf5bd5b8df625cc111c94531dff19148`. References remain read-only;
N's MIT notice and U's existing project-owner-reported permission remain unchanged.

| Capability | Classification | Exact lineage and decision | Downstream integration |
|---|---|---|---|
| Targeted service configuration acquisition | ADAPT (procedural foundation) | Daniel Mauser/Network Desk, N, `plugins/network-desk/skills/network-desk-pl/reference/security-review/SKILL.md`, Azure checklist's `az storage account show ... --query publicNetworkAccess`; `reference/endpoint-design/SKILL.md`, PE/public-access pitfall. Existing MIT notice retained. Use bounded management GETs rather than copy mutation/active-test examples or fetch secrets/keys. | Opt-in same-workload Storage/Key Vault/ACR GET operations over actually collected mapped-service parents; no inferred extra scope. |
| Evidence-source difference interpretation | ADAPT (conceptual only) | Usman Mahmood, U, `.github/skills/azure-networking/SKILL.md`, sections 7 and 10: public network settings require contextual requirements; PE presence is not private-only. Permission is project-owner-reported, not MIT. Independently implemented comparison does not copy customer requirements. | Index and direct values remain separate OBSERVED assertions; differences, unavailable fields and failed reads do not imply defects or desired state. |
| Shared per-field direct/index reconciliation and durable failure coverage | NEW integration | No equivalent normalized, provenance-aware deterministic reconciliation contract was found in the inspected reference portions. Compose the repository's existing acquisition checkpoints, audit, bounded parent loops and four-report publication rather than duplicate transport. | Acquisition 1.7.0/input-schema 0.8.0; three selected management GET operations, separate configuration objects and source/API/read-time/outcome metadata; `NET-SERVICE-SOURCE-001` and deterministic JSON/Markdown source review. Older acquisition/check modes preserved. |
| Perimeter enforcement, client tests and automatic remediation | NOT_NEEDED | Existing access-control limitations remain: no NSP/AMPLS enforcement or exception acceptance inferred, no active DNS/traffic/log enablement and no resource writes. | Read-only configuration reconciliation, not private-only/health certification. |

Microsoft Learn REST guidance inspected (conceptual API contract only, no
documentation/specification implementation copied):
[Storage Get Properties, 2023-05-01](https://learn.microsoft.com/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2023-05-01),
`docs-ref-autogen/storagerp/rest-storagerp-2023-05-01/Storage-Accounts/Get-Properties.yml`,
revision `4695652b8394a18f9fe0150054d2a4fffbf02e8d`;
[ACR Registries Get, 2023-07-01](https://learn.microsoft.com/rest/api/container-registry/registries/get?view=rest-container-registry-2023-07-01),
`docs-ref-autogen/container-registry/rest-container-registry-2023-07-01/Registries/Get.yml`,
revision `10e0ed76f7b1b6d5a3d7a3473999c06e2c64b21e`; and
[Key Vault management Get](https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/get?view=rest-keyvault-keyvault-2024-11-01),
`docs-ref-autogen/keyvault/keyvault/rest-keyvault-keyvault-2024-11-01/Vaults/Get.yml`,
revision `55b16f163141af68329f44c87dd2580df8c6829a`.
The requested older Key Vault documentation view fell back to 2024-11-01:
do not claim it documents 2023-07-01. The collector retains the 2023-07-01 GET
already exercised successfully against all four lab vaults in the preceding
increment. Record actual per-operation API versions; do not conflate a newer
documentation view, indexed fields or API-unavailable fields with actual reads.
Microsoft retains source authorship. Null/missing counts must not become zero;
array counts are retained only when the selected source reports an array.

### 2026-10-11: bounded service access-control evidence

The owner selected Storage Accounts, Key Vaults and Container Registries for the
first opt-in access-control increment. Both read-only reference roots and HEADs
were rechecked: U and N remain at the revisions in the baseline table. Network
Desk's current local origin is the canonical `dmauser/network-desk`; the earlier
fork-remote statement records the earlier inspection, not the current checkout.

| Capability | Classification | Exact inspected foundations and decision | Downstream integration |
|---|---|---|---|
| Public access and Private Endpoint configuration review | ADAPT | Daniel Mauser/Network Desk, N, `plugins/network-desk/skills/network-desk-pl/reference/security-review/SKILL.md`, "Disabling Public Access" and Azure checklist; `reference/endpoint-design/SKILL.md`, group/subresource selection and public-access pitfall. MIT notice remains in the plugin's existing notices. Adapt the read-only public-access inspection concept, not the mutation, active DNS or diagnostic-enablement examples. | Versioned opt-in selected service inventory and configuration comparison in `network_health.py`; existing PE connection evidence is composed rather than recollected by a new collector. |
| Contextual declared-baseline comparison | ADAPT (conceptual influence only) | Usman Mahmood, U, `.github/skills/azure-networking/SKILL.md`, sections 7 and 10, and `docs/network-requirements.md` Storage/Key Vault private-connectivity requirement. Project-owner-reported permission of 2026-10-07 applies, not MIT or an independently verified grant. No customer requirement or upstream implementation is copied. | Owner-requested DECLARED private preference remains separate from OBSERVED properties and INFERRED owner-review records; enabled access is not automatically a defect or exposure. |
| Privacy-minimized service-specific projection and deterministic evidence matrix | NEW integration | No shared normalized/versioned matrix or bounded projection was found in the inspected foundations. Independently implement explicit property values, firewall action, trusted-service bypass, rule counts, scoped approved PE group IDs, unavailable evidence and unsupported families. Do not retain IP rules, rule IDs/values, credentials or full service responses. | Acquisition 1.6.0 derives from 1.5.0, changes only the mapped-service projection/version; input/schema 0.7.0 and `NET-SERVICE-ACCESS-001` feed the existing four-artifact contract. Older acquisition modes retain their original query/properties. |
| NSP/AMPLS enforcement, reachability and exception acceptance | NOT_NEEDED for this increment | A perimeter mode or resource presence is not association/profile/rule/enforcement evidence. Missing service settings are not disabled access. Trusted-service bypass can matter even when public access is disabled. | Explicit UNKNOWN enforcement, data-plane behaviour and exception approval; no automatic accepted exception, active tests, resource writes or scope expansion. |

First-party semantic sources inspected on 2026-10-11 (guidance, not copied
implementation): Microsoft Learn
[Storage default access](https://learn.microsoft.com/azure/storage/common/storage-network-security-set-default-access),
source `articles/storage/common/storage-network-security-set-default-access.md`,
revision `0482a8a09071a1574ea614049da1310458e68a16`;
[Key Vault network security](https://learn.microsoft.com/azure/key-vault/general/network-security),
source `articles/key-vault/general/network-security.md`,
revision `8dfb50ed846e99053e32805d00bf6bd9eface9c4`; and
[ACR selected networks](https://learn.microsoft.com/azure/container-registry/container-registry-access-selected-networks),
source `articles/container-registry/container-registry-access-selected-networks.md`,
revision `b3cb6805089228a11f733e108a28b84f1a1b8935`.
Microsoft authors/projects retain authorship; these links/revisions record
conceptual semantics only, not a copied documentation asset or licensing claim.
Key Vault's current guidance explicitly preserves trusted-service bypass with
`Disabled` and describes perimeter override; ACR documents trusted-service bypass
with disabled public access. Never label `Disabled` as certified private-only.

This document preserves technical lineage, prevents accidental reimplementation,
enforces licensing gates, identifies the genuinely new contribution, and supports
later Marketplace and official Azure SRE Agent ecosystem contribution review.
It records intended use and the bounded Increment 0 runtime evidence below,
not a completed network assessment or general deployment compatibility. The
document itself does not implement skills, agents, collectors or reports.

- Usman Mahmood's assessment workflow and reporting assets are **ADAPT** candidates
  under project-owner-reported permission confirmed on 2026-10-07. Preserve
  attribution and distinguish that permission from an open-source license.
- Daniel Mauser's MIT-licensed Network Desk provides foundations for acquisition,
  snapshots, specialist analysis, diagrams, reporting, documentation grounding,
  coordination, and packaging.
- Network Desk's inventory and snapshot procedures are embedded guidance and
  examples, not a standalone normalized collector.
- The shared normalized, provenance-aware observation and evidence contract is
  **NEW**. The acquisition adapter is **NEW integration** built by **ADAPT**ing
  existing Network Desk procedures.
- Discovery, inventory, topology snapshots, effective-route/NSG exports, diagrams,
  and specialist procedures must not be described as wholly new concepts.

## Reference baselines and licensing gates

Revision keys below resolve to these exact inspected revisions. Every asset and
capability referencing a key inherits its full revision, not an upstream branch
tip. Future changes require renewed inspection and an updated decision.

| Key | Source project and author | Local repository root | Inspected source revision | License or permission status |
|---|---|---|---|---|
| U | [Usman Mahmood's Azure Networking Assessment Agent](https://github.com/lavoizer-develop/azure-networking-agent-test-repo) | `<local-clone-root>\azure-networking-agent-test-repo` | `624bd5c3bf5bd5b8df625cc111c94531dff19148` | No tracked open-source license found. Project-owner-reported permission confirmed 2026-10-07 covers copying, adaptation, Marketplace/customer redistribution and potential upstream contributions; see permission record below. |
| N | [Daniel Mauser's Network Desk](https://github.com/dmauser/network-desk) | `<local-clone-root>\network-desk` | `4104279fa4707c24e6038b35b2779fecfdd11eea` | MIT; copyright (c) 2025 dmauser. Retain copyright and permission notice in copies or substantial portions. |
| P | [Primary repository, Clive Graven](https://github.com/cliveg/sre-agent-plugins-extras) | `<local-clone-root>\sre-agent-plugins-extras` | `<implementation-commit>` | [MIT](../LICENSE); copyright (c) 2026 Clive Graven. Existing capability-specific credits must also be preserved. |

Both external repositories are **read-only**. The local Network Desk checkout
uses a fork remote; upstream attribution belongs to Daniel Mauser's Network Desk.
The primary repository revision pins existing integration examples; the newly
created instructions and this register are not claimed to exist in that commit.

Legal/context assets inspected: U's [README][U4] and tracked filename inventory;
N's [LICENSE][N27], [README][N28], [package metadata][N29],
[project conventions][N30], and [privacy document][N31].
No separate tracked NOTICE, CONTRIBUTING, AUTHORS, or attribution file was found
in either reference. Absence of a license in U is not itself permission to copy;
the subsequent permission record is the basis for proceeding.

### Usman permission record

- **Recorded:** 2026-10-07, following the initial permission-gated analysis.
- **Evidence source:** Project owner's statement in this development conversation:
  Usman said to "use it however we want."
- **Scope confirmation:** When explicitly asked whether copying, adaptation,
  Marketplace redistribution, customer deployments and potential upstream
  contributions were covered, the project owner confirmed: "Yes, all of those
  uses are covered."
- **Status:** Permission reported by the project owner; not an independently
  inspected written grant or a tracked open-source license. This permits
  development within the confirmed scope; do not label the source MIT licensed.
- **Distribution-review evidence:** Retain the original correspondence or a written
  confirmation in an approved location, or record a future applicable license,
  before formal Marketplace/upstream permission review. No such external evidence
  attachment or link was provided in this conversation.
- **Collaboration:** Usman welcomes feedback through pull requests. This does not
  authorize modifying the read-only reference checkout or automatically creating
  a PR; upstream contribution work requires an explicit task.
- **History:** C01 and C02 were REFERENCE_PENDING_PERMISSION in the initial
  register. They are now ADAPT because confirmed use still requires target-runtime
  changes. The reference revision and inspected licensing facts are unchanged.

### Classification rules

| Classification | Decision rule |
|---|---|
| REUSE | Asset suitable substantially as-is and licensing or explicit permission permits use. |
| ADAPT | Existing asset requires modification and licensing or explicit permission permits it. |
| COMPOSE | Orchestrate existing capabilities without duplicating implementation. |
| NEW | Required capability not found in the inspected references; do not claim novelty beyond this search. |
| NOT_NEEDED | Outside the initial MVP scope. |
| REFERENCE_PENDING_PERMISSION | Relevant source, but direct reuse/adaptation blocked by unresolved permission. |

COMPOSE does not bypass licensing, tool availability, or runtime validation.
No current end-to-end capability is classified REUSE: the inspected candidates
need integration, composition or adaptation.

### Attribution policies used in entries

- **AU:** Credit Usman Mahmood and his assessment project for conceptual influence
  and any reused/adapted assets, with exact files/revision and downstream changes.
  Preserve existing notices and the permission record. Reuse/adaptation may
  proceed within the confirmed scope; do not claim an MIT license or describe
  independent implementations as his original assets.
- **AN:** Credit Daniel Mauser and Network Desk; retain the applicable copyright
  and complete MIT permission notice for reused/adapted portions; identify exact
  files, revision, modifications, and downstream locations. Prefer canonical
  specialist sources over generated plugin copies.
- **AP:** Preserve primary repository copyright, licensing, and existing
  capability-specific credits. Reuse structural integration conventions rather
  than claim existing SLA methodology as new network-assessment work.
- **AO:** Attribute this project's independent contribution accurately and retain
  conceptual/source influences through AU/AN where specified. No reference code
  or text has been copied merely by classifying an entry NEW.

## Exact source asset catalog

Capability entries below refer to these exact assets, not entire repositories.
External links pin the inspected revision. N's canonical sources are used unless
a generated packaging surface is explicitly identified.

| Asset | Project/revision | Exact source file or asset | Relevant contribution |
|---|---|---|---|
| U1 | U | [`.github/agents/azure-networking.agent.md`][U1] | Requirements-led workflow, modification boundary, authoritative artifact and persistence check. |
| U2 | U | [`.github/skills/azure-networking/SKILL.md`][U2] | Contextual network assessment, evidence, dependencies, severity guidance. |
| U3 | U | [`.github/skills/assessment-reporting/SKILL.md`][U3] | Assessment structure, finding/evidence fields, compliance, remediation, positives and assumptions. |
| U4 | U | [`README.md`][U4] | Learning/test scenario and deliberately imperfect infrastructure context. |
| U5 | U | [`docs/network-requirements.md`][U5] | Documented target-state fixture. |
| U6 | U | [`docs/current-architecture.md`][U6] | Documented current-state and shared-platform dependencies; not deployed-state verification. |
| N1 | N | [`extensions/network-desk/specialists/vnet-architect/skills/migration-planner/SKILL.md`][N1] | Assess phase: inventory/dependency method and VNet, route-table, NSG JSON export examples. |
| N2 | N | [`extensions/network-desk/specialists/network-automation/skills/rollback/SKILL.md`][N2] | Pre-Change Health Snapshot: topology, effective-route/NSG exports and retained baseline artifacts. Only the read/snapshot portion is relevant. |
| N3 | N | [`extensions/network-desk/specialists/network-automation/skills/drift-detection/SKILL.md`][N3] | Desired/deployed drift guidance, Terraform examples and Azure Resource Graph change queries. |
| N4 | N | [`extensions/network-desk/specialists/vnet-architect/agents/vnet-architect.md`][N4] | Workload/address inventory, requirements, topology, peering and diagrams. |
| N5 | N | [`extensions/network-desk/specialists/vnet-architect/skills/hub-spoke-design/SKILL.md`][N5] | Hub/spoke, shared services, transit and Azure peering guidance. |
| N6 | N | [`extensions/network-desk/specialists/vnet-architect/skills/peering-advisor/SKILL.md`][N6] | Peering, overlap and transitive-routing considerations. |
| N7 | N | [`extensions/network-desk/specialists/network-troubleshooter/skills/routing-debug/SKILL.md`][N7] | Effective routes, next hop, UDR/return path and BGP observations. |
| N8 | N | [`extensions/network-desk/specialists/dns-specialist/agents/dns-specialist.md`][N8] | Current DNS topology and resolution/forwarding-chain workflow. |
| N9 | N | [`extensions/network-desk/specialists/dns-specialist/skills/resolver-design/SKILL.md`][N9] | Resolver endpoints, conditional forwarding and hybrid DNS. |
| N10 | N | [`extensions/network-desk/specialists/dns-specialist/skills/record-audit/SKILL.md`][N10] | Zone/record inspection and CLI audit examples. |
| N11 | N | [`extensions/network-desk/specialists/private-link/agents/private-link.md`][N11] | PaaS inventory, endpoint/DNS/approval workflow. |
| N12 | N | [`extensions/network-desk/specialists/private-link/skills/dns-integration/SKILL.md`][N12] | Private zones, VNet links, zone groups and custom DNS. |
| N13 | N | [`extensions/network-desk/specialists/private-link/skills/troubleshoot/SKILL.md`][N13] | Endpoint state, DNS, network and service diagnosis. |
| N14 | N | [`extensions/network-desk/specialists/network-security/skills/nsg-audit/SKILL.md`][N14] | Rule exports, effective NSGs, permissive/shadowed rule heuristics. |
| N15 | N | [`extensions/network-desk/specialists/firewall-engineer/skills/rule-audit/SKILL.md`][N15] | Azure policy exports and firewall log/hit-count examples. |
| N16 | N | [`extensions/network-desk/specialists/firewall-engineer/skills/troubleshoot/SKILL.md`][N16] | Packet-flow, policy, NAT, routes, return-path and logging diagnosis. |
| N17 | N | [`extensions/network-desk/specialists/hybrid-connectivity/agents/hybrid-connectivity.md`][N17] | WAN inventory, VPN/ExpressRoute/BGP and resilience workflow. |
| N18 | N | [`extensions/network-desk/specialists/hybrid-connectivity/skills/troubleshoot/SKILL.md`][N18] | BGP/tunnel status, effective/learned/advertised routes and asymmetry. |
| N19 | N | [`extensions/network-desk/specialists/network-troubleshooter/agents/network-troubleshooter.md`][N19] | Follow-the-packet method and Network Watcher topology/diagnostic guidance. |
| N20 | N | [`extensions/network-desk/specialists/network-troubleshooter/skills/connectivity-test/SKILL.md`][N20] | Active connection testing and diagnostic result interpretation. |
| N21 | N | [`extensions/network-desk/specialists/network-monitor/agents/network-monitor.md`][N21] | Existing telemetry, flow logs, connection monitors, baselines and coverage. |
| N22 | N | [`extensions/network-desk/specialists/network-monitor/skills/traffic-analytics/SKILL.md`][N22] | Flow analytics and example KQL; workspace schemas need validation. |
| N23 | N | [`extensions/network-desk/specialists/network-monitor/skills/baseline-analysis/SKILL.md`][N23] | Time-windowed baselines and anomaly interpretation. |
| N24 | N | [`extensions/network-desk/specialists/report-builder/agents/report-builder.md`][N24] | Packaging separate from technical analysis; source preservation and output locations. |
| N25 | N | [`extensions/network-desk/specialists/report-builder/skills/report-structure/SKILL.md`][N25] | Markdown-first report guidance, quality checks and format selection. |
| N26 | N | [`extensions/network-desk/specialists/vnet-architect/skills/network-diagram/SKILL.md`][N26] | Mermaid node/edge conventions and topology templates, not a normalized observation schema. |
| N27 | N | [`LICENSE`][N27] | MIT permission and copyright notice. |
| N28 | N | [`README.md`][N28] | Analysis-first runtime, output-file conventions, distribution and license. |
| N29 | N | [`package.json`][N29] | Upstream author/repository, MIT declaration, version and Node runtime metadata. |
| N30 | N | [`.github/copilot-instructions.md`][N30] | Canonical/generated asset distinction and development conventions. |
| N31 | N | [`PRIVACY.md`][N31] | Runtime data handling, local files and optional outbound update check. |
| N32 | N | [`extensions/network-desk/registry.mjs`][N32] | Domain catalog, routing triggers and centralized Microsoft Learn grounding policy. |
| N33 | N | [`extensions/network-desk/extension.mjs`][N33] | Five parameterized content/routing tools and policy injection; not Azure resource collectors. |
| N34 | N | [`extensions/network-desk/scripts/build-plugin.mjs`][N34] | Generator from registry/canonical specialists to native plugin assets. |
| N35 | N | [`plugins/network-desk/agents/network-desk.md`][N35] | Generated coordinator and multi-domain sequencing. |
| N36 | N | [`plugins/network-desk/.github/plugin/plugin.json`][N36] | Generated manifest, skill index and read-CLI/Python tool declarations. |
| N37 | N | [`extensions/network-desk/renderers/_common.py`][N37] | Rendering helpers, output paths and local Mermaid bridge. |
| N38 | N | [`extensions/network-desk/renderers/make_html.py`][N38] | Markdown-to-HTML renderer; not a publication service. |
| P1 | P | [`README.md`](../README.md) | Marketplace-plus-extras distribution, customer installation and existing credits. |
| P2 | P | [`plugins/sla-reporting/plugin.json`](../plugins/sla-reporting/plugin.json) | Existing Azure SRE Agent manifest and tool declarations. |
| P3 | P | [`plugins/sla-reporting/extras/agents/sla-analyzer.yaml`](../plugins/sla-reporting/extras/agents/sla-analyzer.yaml) | Existing read-only subagent configuration and report attachment pattern. |
| P4 | P | [`plugins/sla-reporting/extras/scheduled-tasks/sla-monthly-report.yaml`](../plugins/sla-reporting/extras/scheduled-tasks/sla-monthly-report.yaml) | Existing ScheduledTask configuration, cron and agent prompt pattern. |
| P5 | P | [`tools/deploy-extras.sh`](../tools/deploy-extras.sh) | Existing generic deployment of skills/extras; not customer assessment-report publication. |

## Capability decisions

The three tables below form one record per stable ID. Together they contain all
required fields: capability, classification, source project/assets/revision,
license/permission, source contribution, intended use, required integration,
attribution, rationale, limitations, and MVP inclusion.

**MVP statuses are recommendations, not implementation claims.** "Included"
means part of the planned assessment-only boundary. "Conditional" depends on
available inputs/resources or a decision noted below. "Deferred" is outside the
initial execution scope. Permission blocks copying, not independent development.

### A. Classification, source and licensing

| ID | Capability | Classification | Source project / exact assets | Inspected source revision | License or permission status | Attribution requirements |
|---|---|---|---|---|---|---|
| C01 | Assessment orchestration and workflow | ADAPT | Usman: U1, U2 | U | Project-owner-reported permission within confirmed scope; no tracked license. | AU; identify reused/adapted workflow portions. |
| C02 | Assessment reporting | ADAPT | Usman: U3, U1 | U | Project-owner-reported permission within confirmed scope; no tracked license. | AU; identify reused/adapted reporting portions. |
| C03 | Azure network resource discovery | ADAPT | Network Desk: N1, N2, N3, N19 | N | MIT permits adaptation subject to notice retention. | AN, exact acquisition portions. |
| C04 | Acquisition adapter | NEW | Primary independent integration; foundations N1, N2, N7, N14 | N for foundations; no upstream adapter found | Original adapter; adapted procedures remain MIT-governed. | AO + AN; distinguish adapter from upstream procedures. |
| C05 | Normalized Observed Network Model | NEW | Primary independent contract; related but insufficient N1, N2, N26 and U6 | N, U for related evidence; no shared model found | Original model; U6 remains conceptual input here, permitted within confirmed scope. | AO + AN/AU for influence, not ownership of the new model. |
| C06 | Evidence and provenance contract | NEW | Primary independent contract; conceptual U2, U3; observation inputs N2, N7 | U, N for foundations; no shared contract found | Original contract; any U adaptation must record permission and actual source portions. | AO + AU/AN for conceptual/input lineage. |
| C07 | Collection scope and coverage model | NEW | Primary independent model; bounded inventory/snapshot examples N1, N2 | N for foundations; no common coverage model found | Original model; MIT conditions apply to adapted examples. | AO + AN. |
| C08 | Partial-result and permission-failure handling | NEW | Primary independent acquisition semantics; N33 has content-loader errors only | N for comparison; no collection-level implementation found | Original handling; do not present loader errors as collector behavior. | AO; AN if relevant N portions are later used. |
| C09 | VNet and subnet topology | COMPOSE | Network Desk: N4, N5, N26; acquisition C03 | N | MIT; compatibility still requires verification. | AN. |
| C10 | Peering and transit assessment | COMPOSE | Network Desk: N5, N6, N7 | N | MIT. | AN. |
| C11 | Routing assessment | COMPOSE | Network Desk: N7, N16, N18 | N | MIT. | AN. |
| C12 | DNS assessment | COMPOSE | Network Desk: N8, N9, N10, N12 | N | MIT. | AN. |
| C13 | Private Link assessment | COMPOSE | Network Desk: N11, N12, N13 | N | MIT. | AN. |
| C14 | NSG and network-security assessment | ADAPT | Network Desk: N14, N19; contextual influence U2 | N, U | N MIT; U adaptation permitted within confirmed scope. | AN + AU; record any U criteria adapted. |
| C15 | Azure Firewall assessment | COMPOSE | Network Desk: Azure-specific portions of N15, N16 | N | MIT. | AN; retain Azure-only extraction lineage. |
| C16 | Hybrid connectivity assessment | COMPOSE | Network Desk: N17, N18, N9 | N | MIT. | AN. |
| C17 | Network troubleshooting | COMPOSE | Network Desk: N19, N7, N13, N20 | N | MIT; source permission is not permission for active diagnostics. | AN. |
| C18 | Network monitoring and telemetry coverage | ADAPT | Network Desk: N21, N22, N23 | N | MIT. | AN; identify schema/threshold adaptations. |
| C19 | IaC reconciliation | ADAPT | Network Desk: N3; Usman fixture U5, U6 | N, U | N MIT; U fixture adaptation permitted within confirmed scope. | AN + AU; identify actual fixture portions used. |
| C20 | Architecture-intent reconciliation | ADAPT | Network Desk: N4, N8, N17; Usman U1, U5, U6 | N, U | N MIT; U adaptation permitted within confirmed scope. | AN + AU for requirements-led influence and adaptations. |
| C21 | Prioritized health reporting | NEW | Primary cross-domain aggregation; N25 foundation; U3 reporting foundation | N, U; no normalized cross-domain health implementation found | Original aggregation; N MIT and confirmed U permission govern adapted source portions. | AO + AN/AU; not a claim that severity ranking is new. |
| C22 | Deep-dive recommendation and orchestration | ADAPT | Network Desk: N32, N33, N35 | N | MIT. | AN; generated coordinator is evidence, canonical registry is preferred. |
| C23 | SRE Agent integration | ADAPT | Network Desk: N34, N36, N33; primary P1, P2, P3, P5 | N, P | MIT in both; retain applicable source notices and credits. | AN + AP. |
| C24 | Scheduled assessment | ADAPT | Primary P4, P5; N3 schedules drift checks, not this assessment | P, N | P MIT; N MIT only if actual portions are used. | AP; AN if using N schedule guidance. |
| C25 | Report rendering | COMPOSE | Network Desk: N24, N25, N37, N38 | N | MIT. | AN. |
| C26 | Report publication | NEW | Primary customer/runtime publication integration; related N24, N28, P3, P5 | N, P; no end-to-end publication capability found | Original integration; source conditions apply to reused portions. | AO + AN/AP for related conventions actually used. |
| C27 | Network Desk coordination and grounding foundation | ADAPT | Network Desk: N32, N33, N35 | N | MIT. | AN; preserve documentation-grounding lineage. |
| C28 | Assessment-report assembly integration | ADAPT | Network Desk: N24, N25; Usman U3 | N, U | N MIT; U report adaptation permitted within confirmed scope. | AN + AU; separate original, adapted and independently authored portions. |

### B. Source contribution, intended use and changes

| ID | What the source provides | Intended use | Changes or integration required | Reason for classification |
|---|---|---|---|---|
| C01 | Repository-led review sequence and persistent-artifact completion rule. | Adapt the scope/evidence/assessment workflow with explicit attribution. | Translate repository discovery to connected Azure reads and target-runtime artifact verification; record actual adaptations. | Permission scope is confirmed; target-runtime changes are still required. |
| C02 | Rich evidence, compliance, assumptions and remediation-oriented report guidance. | Adapt reporting guidance for persistent executive/engineering assessments. | Integrate the observation/evidence contract and target-runtime storage; coordinate assembly through C28. | Permission scope is confirmed; reporting requires adaptation rather than unchanged reuse. |
| C03 | JSON inventory exports, topology/effective-route/NSG snapshots and ARG examples. | Acquire deployed-network evidence without IaC. | Validate read commands, explicit scope, paging, dependencies and timestamps; feed C04-C08. | Existing procedures need adaptation, not reinvention. |
| C04 | No standalone target-runtime adapter; multiple acquisition examples exist. | Connect permitted Azure/SRE Agent tools to normalized acquisition. | Implement scoped reads, paging, tool mappings and collection outcomes by adapting C03 procedures. | NEW glue; underlying inventory/snapshot procedures are ADAPT foundations. |
| C05 | Raw exports and diagrams, but no shared normalized graph. | Stable entities/relationships across topology, routes, DNS, endpoints, security, firewall, gateways and later telemetry. | Define and evaluate a common machine-readable model, with resource identity and temporal consistency. | Normalization/joining contract is absent from inspected references. |
| C06 | Evidence-driven concepts and snapshot inputs, not shared evidence semantics. | Preserve OBSERVED, DECLARED, INFERRED and UNKNOWN with provenance. | Define source, scope, time, evidence references and uncertainty; separate configuration, effective behavior and intent. | Shared provenance-aware contract is the new contribution. |
| C07 | Examples bounded to particular inventories or resource groups. | Make assessment completeness and collection boundaries explicit. | Record requested/attempted/completed scope, resource kinds, paging and per-source coverage. | No unified coverage representation found. |
| C08 | Content-loading failure responses, not Azure collection partiality. | Preserve usable evidence alongside permission failures and missing data. | Define typed collection outcomes, explicit errors and uncollected versus verified-absent semantics. | Collector-level result handling is not supplied. |
| C09 | Topology/address/diagram specialist guidance. | Interpret acquired VNet/subnet relationships and optionally diagram supported connections. | Supply C05 evidence; distinguish configured relationships from verified connectivity. | Compose expertise rather than duplicate topology procedures. |
| C10 | Peering flags, overlap, gateway-transit and non-transitive routing analysis. | Assess actual directional peering/transit against requirements. | Join both peering directions and route/gateway evidence; preserve external dependencies. | Existing specialist analysis is an orchestration input. |
| C11 | Effective routes, next hops, UDRs, BGP and asymmetric-path analysis. | Assess egress, inspection and return paths. | Keep configured/effective routes distinct; correlate intended traffic and observation time. | Existing routing expertise should be composed. |
| C12 | Current DNS topology, zones/records, resolver and forwarding procedures. | Assess resolution paths separately from network reachability. | Join DNS settings, zone links/groups and forwarding evidence; distinguish resolver configuration from actual resolution. | Multiple complementary upstream capabilities already exist. |
| C13 | Endpoint state, approval, placement, DNS and service checks. | Assess private connectivity and public-access intent. | Correlate target/subresource, zone groups, service state and client path; avoid blanket private-only requirements. | Existing private-connectivity procedures cover the domain. |
| C14 | Rule export/effective-NSG procedures and broad risk heuristics. | Assess controls in the context of actual paths and documented requirements. | Adapt severity, service tags, associations and exposure reasoning; an NSG rule alone is not public reachability. | Heuristics require contextual modification, not direct adoption. |
| C15 | Azure policy exports, firewall logs, routes and NAT diagnosis. | Assess configured inspection and available operational evidence. | Select Azure portions; join firewall policy, routing and existing logs; recognize externally managed firewalls. | Compose existing Azure-specific procedures. |
| C16 | WAN inventory, ExpressRoute/VPN/BGP and hybrid diagnostics. | Assess available hybrid evidence and external dependency gaps. | Join cloud gateway/routes/DNS; request or label missing on-premises evidence. | Existing expertise is useful without duplicating its implementation. |
| C17 | Follow-the-packet hypotheses, configuration checks and active-test examples. | Recommend or perform permitted read-only evidence analysis and deep dives. | Restrict MVP execution to approved reads; separate recommendations from probes/captures and prerequisite changes. | Compose diagnostic reasoning; do not silently execute active procedures. |
| C18 | Telemetry sources, flow analytics, baselines and monitoring guidance. | Assess existing telemetry and coverage; identify operational blind spots. | Validate actual tables/fields, retention and sample windows; remove setup actions from assessment execution. | Deployment-oriented guidance must become read-only coverage analysis. |
| C19 | Desired/deployed drift examples and Terraform/ARG guidance. | Reconcile optional partial Terraform/Bicep with observed state. | Account for ownership, unmanaged resources, partial IaC and declaration/observation differences; Bicep support needs independent work. | Adapt comparison foundations without claiming a complete reconciler exists. |
| C20 | Requirements gathering and existing-topology discovery concepts. | Reconcile architecture documents/standards with IaC and observations. | Map requirement sources to scoped evidence; preserve staleness, ambiguity and external dependencies. | Adapt N and permitted U foundations with explicit lineage. |
| C21 | Existing report prioritization guidance, not common health/evidence aggregation. | Explain significant cross-domain findings and priorities for both audiences. | Build evidence-linked aggregation with explicit unknowns, dependencies and operational impact; avoid unsupported numerical scores. | NEW shared integration; reporting and ranking concepts are not new. |
| C22 | Keyword/domain routing and multi-specialist sequencing. | Recommend deep dives based on findings, uncertainty and evidence gaps. | Add evidence-driven triggers, rationale, bounded scopes and handoff context; translate tools to the target runtime. | Existing coordination needs adaptation from prompt routing to assessment routing. |
| C23 | CLI extension, generated plugin/tool declarations and primary deployment patterns. | Support local validation, interactive SRE Agent use and Marketplace delivery. | Verify manifests/schemas/tools, references and artifact persistence; use generic primary deployment tooling. | Adapt existing packaging; direct CLI-runtime compatibility is not established. |
| C24 | Existing read-only ScheduledTask/cron pattern in the primary repository. | Eventually repeat the same governed assessment pipeline. | Bind approved scope/identity and retention; verify task schema, run isolation and failure reporting. | Existing scheduling pattern can be adapted later. |
| C25 | Markdown-first source preservation and optional renderers. | Produce persistent Markdown; optionally compose richer rendering later. | Confirm target filesystem/dependencies, diagram support and source-to-output traceability. | Compose existing packaging rather than recreate renderers. |
| C26 | Local saved-output conventions and an existing SRE report attachment pattern. | Deliver durable, authorized customer-visible executive/engineering artifacts. | Decide storage/access/retention/versioning/redaction and verify publication; do not confuse KB uploads with report delivery. | NEW end-to-end delivery integration, not a claim that saving files is new. |
| C27 | Central domain registry and Microsoft Learn validation policy. | Ground claims and coordinate permitted specialist references. | Translate CLI-specific connector setup; preserve exact citations and explicit unverified status. | Useful architecture needs target-runtime adaptation. |
| C28 | Markdown structure, quality checks, assessment guidance and packaging separation. | Assemble persistent executive/engineering assessments from attributed foundations. | Integrate C02, C05-C08 evidence links/coverage, C21 priorities and C26 persistence checks; record source portions and modifications. | Adapt N's licensed packaging and U's permitted assessment guidance without claiming existing reporting concepts are new. |

### C. Known limitations and MVP inclusion

| ID | Known limitations | MVP inclusion status |
|---|---|---|
| C01 | VS Code/repository workflow, not live Azure assessment; permission reported by project owner, not a tracked license. | Included: attributed adaptation within confirmed scope. |
| C02 | Required report path is an instruction contract; generated assessment absent in inspected U checkout; permission is not a tracked license. | Included: attributed adaptation within confirmed scope. |
| C03 | Embedded examples, not complete collector; command/schema correctness and collection completeness not validated against live Azure. | Included: scoped read-only discovery. |
| C04 | Runtime tools, credentials, permissions, paging and acquisition limits remain unvalidated. | Included: NEW adapter; implementation not started. |
| C05 | Raw inventories and diagrams do not prove connectivity; model format/identity/versioning unresolved. | Included: NEW normalized model. |
| C06 | Connected source authority and freshness vary; not all inference can be eliminated. | Included: NEW contract. |
| C07 | Cross-subscription/shared-platform scope may be inaccessible; no inferred completeness. | Included: NEW coverage model. |
| C08 | Permission-denied, no data, uncollected and verified absence must remain distinct; runtime error taxonomy unresolved. | Included: NEW partial-result semantics. |
| C09 | Diagrams are descriptions/templates, not proof of actual traffic paths. | Included: VNet/subnet model; simple diagram conditional. |
| C10 | Directional/configured peering does not establish functional transit. | Included where peering/transit is present. |
| C11 | Effective-route observations depend on suitable sources/NICs; never substitute configured UDRs silently. | Included; missing effective evidence explicitly UNKNOWN. |
| C12 | On-prem DNS may be unavailable; configuration alone does not verify name resolution. | Included; active client-resolution testing is not assumed. |
| C13 | Approval and DNS configuration do not prove application connectivity; upstream example claims need grounding. | Included where relevant services/endpoints exist. |
| C14 | Broad source rules require ingress-path evidence; flow-log evidence may be absent. | Included with contextual validation. |
| C15 | Policy, logs or shared platform may be inaccessible; unused rules cannot be inferred from missing logs. | Conditional on Azure Firewall presence and accessible evidence. |
| C16 | On-prem devices/circuit/provider state may lie outside connected scope. | Conditional on hybrid dependencies; report unknowns. |
| C17 | Active probes/captures can have prerequisites and side effects; read-only configuration analysis is not equivalent. | Included: reasoning/read analysis and recommendations; no default active tests. |
| C18 | Legacy example schemas/thresholds require validation; sources may have no historical telemetry. | Included: existing telemetry/coverage only; no enablement. |
| C19 | Partial IaC cannot establish full environment intent; Terraform guidance is not a Bicep parser. | Conditional on supplied IaC; reading/reconciliation only. |
| C20 | Documents can be incomplete/stale; differences alone are not defects. | Conditional on supplied intent; do not fabricate requirements. |
| C21 | No proven universal score or severity formula; unknown coverage cannot produce a healthy default. | Included: priorities and explanations, no unsupported scoring. |
| C22 | Current routing is domain/keyword based, not evidence driven; SRE handoffs unvalidated. | Included: recommendations; automatic specialist execution conditional. |
| C23 | Manifest tool names do not establish runtime compatibility; P schemas are examples, not automatically current authority. | Included: local and interactive integration, subject to validation. |
| C24 | No network-assessment scheduled task exists; N's drift schedule is not a reusable assessment runner. | Deferred: after interactive validation. |
| C25 | Python/renderer dependencies and target filesystem unverified; Mermaid rendering may require local tooling. | Included: Markdown; rich formats deferred. |
| C26 | No selected storage/publication destination or verified delivery API; deployer uploads extras, not assessment artifacts. | Included: verified persistent delivery; destination unresolved. |
| C27 | Policy text does not prove docs were queried; CLI content tools do not collect Azure state. | Included: grounding and bounded coordination. |
| C28 | Both report foundations need the new evidence contract and target-runtime persistence; U permission is not an MIT license. | Included: attributed report-assembly integration. |

## Explicit initial-MVP exclusions

Each row below is an exclusion record with its own source, permission, lineage,
rationale and limitation. Excluding execution does not exclude reading related
existing configuration as assessment evidence.

| ID / Capability | Classification | Source project / exact asset / inspected revision | License or permission / attribution | What source provides / intended use | Changes or integration required | Reason / known limitations | MVP inclusion status |
|---|---|---|---|---|---|---|---|
| X01 Automatic remediation | NOT_NEEDED | Network Desk N2, N3 / N | MIT / AN if later reused | Rollback/apply/remediation examples; reference only for future separate work. | Separate approved change workflow and engineering validation. | Assessment must not change resources; source examples are not authorization. | Excluded. |
| X02 Deployment pipelines | NOT_NEEDED | Network Desk N3, N2 / N | MIT / AN if later reused | CI drift/change workflows; not part of assessment execution. | Separate future deployment scope. | Distinct from packaging a capability with P5; that convention remains relevant. | Excluded from assessment MVP. |
| X03 Enabling monitoring during assessment | NOT_NEEDED | Network Desk N21; [`flow-log-setup/SKILL.md`][NX1], [`connection-monitor/SKILL.md`][NX2] / N | MIT / AN if later reused | Log/monitor deployment procedures; assess existing coverage only. | Remove enable/create/update actions from assessment paths. | Enabling flow logs, diagnostics, monitors or alerts changes environment state. | Excluded. |
| X04 Multi-cloud coverage | NOT_NEEDED | Network Desk N4, N8, N11, N17, N21 / N | MIT / AN | AWS/GCP alongside Azure; preserve lineage, select Azure portions. | Azure-only scoping for initial capability. | Multi-cloud support expands tooling, model and evaluation scope. | Excluded. |
| X05 All firewall vendors | NOT_NEEDED | Network Desk N15, N16, N32 / N | MIT / AN | Fourteen-vendor guidance; only Azure Firewall portions are candidates. | Retain attribution when selecting Azure material. | Full vendor migration/configuration/audit breadth is not required. | Excluded; Azure Firewall C15 remains conditional. |
| X06 Multiple rich export formats | NOT_NEEDED | Network Desk N24, N25, N37, N38; [`make_pdf.py`][NX3], [`make_docx.py`][NX4], [`make_xlsx.py`][NX5] / N | MIT / AN if later reused | Existing HTML/PDF/DOCX/XLSX renderers; future optional composition. | Verify dependencies, filesystem, diagrams and output support later. | Initial persistent Markdown does not require all renderers or new export implementations. | Excluded initially. |

## Genuine contribution and evidence boundaries

The NEW entries C04-C08, C21 and C26 are bounded integration/model contributions,
not claims of research novelty. The central contribution is C05-C08 together:
a shared normalized observation/evidence contract with scope, provenance,
uncertainty, partial results and permission failures.

Maintain these distinctions throughout implementation and reporting:

- **OBSERVED:** directly verified through an authoritative connected source.
- **DECLARED:** documentation, standards, architecture or IaC specifies it.
- **INFERRED:** reasoning from available evidence; never relabel as OBSERVED.
- **UNKNOWN:** evidence insufficient, inaccessible or uncollected.

Separate deployed configuration from effective behavior, and both from intent.
Absence of collected evidence is not proof of absence. An IaC resource is not
proof of deployment; documentation is not automatically current; deployed state
is not automatically correct. Configuration differences are not automatically
defects. Preserve time/scope/source references and do not invent healthy defaults
for inaccessible evidence.

## Unresolved decisions and review gates

### Increment 1 restricted implementation boundary

The next slice collects only subscription/resource-group/region context, VNets,
address spaces, subnets, peerings, configured route tables/routes/associations,
NSGs/rules/subnet associations and minimal NIC/IP attachment references. It does
not collect effective routes/security, endpoints/DNS, firewalls/gateways, NAT,
application delivery, telemetry, IaC or architecture documents.

| Source-map entry | Downstream asset | Decision and precise lineage |
|---|---|---|
| C03, C04 | `acquisition.json`, `network_health.py`, optional development transport | ADAPT Network Desk N1's inventory/export foundation to bounded, pageable Resource Graph projections. The adapter is NEW integration, not a claim that inventory is new. N2 effective-state snapshots remain deferred. |
| C05-C08 | `common.schema.json`, `observed-network.schema.json`, normalizer | NEW shared observation/evidence/coverage contract. Stable ARM identifiers and explicit property-supported relationships; no inferred traffic paths or interpreted findings in observation JSON. |
| C01, C02, C21, C28 | `assessment.schema.json`, `checks.json`, deterministic reports | ADAPT Usman U1-U3's contextual evidence/risk/recommendation/persistence discipline under the recorded permission; independent code integrates six versioned checks and separate severity/priority. N25 remains reporting quality/reference lineage, not a copied renderer. |
| C09-C11, C14 | Six checks and selected references | COMPOSE/ADAPT only addressing, peering state, subnet associations and configured next-hop consistency. N6 and N7 are exact specialist foundations; do not copy their mutation commands or broaden into transit/effective-state diagnostics. |
| C23, C26 | Marketplace skill and run-bundle delivery | ADAPT the proven installed-file/native-terminal path. Preserve four canonical output files. External publication remains deferred. |

The live sandbox has no Resource Graph CLI extension, and its native Azure read
tool executes in a separate environment. Lossless output transfer must be
proved; model-rewritten/pasted resource rows are not an acceptable adapter.
The development-host adapter
[network_health_sre.py](../tools/network_health_sre.py) captures actual structured
native execution results and uses the app's conversation attachment API. It
records native execution IDs, requested scope and input integrity. Actual native
NSG paging, installed-helper processing and byte-for-byte four-artifact retrieval
have been exercised; the initial run remains partial because NIC acquisition
failed. Nine selected direct ARM reads verified observations independently.
See [runtime validation](../plugins/azure-network-health/runtime-validation.md).
This is not standalone skill acquisition. Never copy credentials into the
sandbox or install/login automatically.

On 2026-10-08, a new-PC replay on a separately selected development target
verified all nine restricted operations, including minimal NIC attachments,
installed-file hashes, four-artifact retrieval, eight selected direct Azure reads
and a separate three-page native NSG-rule probe. The historical partial run
remains unchanged. A bounded runtime-file inspection found no accessible
ToolOutputs responses for that probe, so the development bridge remains required
on the proven path. Both documented reference checkouts were unavailable on this
PC and were not searched; no new source assets, acquisition method, criteria or
domain implementation were introduced. C03/C04/C23/C26 classifications, upstream
revisions and permission/notice requirements above are unchanged. Exact outcomes
and limits are in the linked runtime-validation record.

### Step 3 atomic publication decision: 2026-10-08

Both references were restored at the recorded U/N revisions under the documented
`<local-clone-root>` roots, using their canonical upstream URLs, and inspected read-only.
Network Desk's MIT notice is unchanged. Usman's tracked license/notice inventory
still contains no license grant; the project-owner-reported permission above
remains the authorization basis, not an MIT license.

| Capability | Classification | Exact inspected foundations and decision | Downstream integration |
|---|---|---|---|
| Atomic four-artifact bundle publication and failed-write recovery | NEW integration (C23/C26) | U1 workflow steps 5-7 and its final file-write failure rule require persistence verification; U3 Reporting Principles preserves evidence-based reports. N24 workflow step 4 and guardrails 1-5 separate packaging from analysis, forbid unsolicited overwrite and preserve source; N25 Quality checklist/Output location preserves source beside rendered files. These are conceptual foundations, not copied implementation. No atomic multi-file publisher or same-run write reservation was found in these inspected portions. | Independently implemented staging, file hash verification and directory publication in `network_health.py`, with synthetic failure/retry tests. No new collection operations, findings, renderer content or Azure writes. |

Conceptual influence remains attributed to Usman Mahmood's assessment project
(U revision `624bd5c3bf5bd5b8df625cc111c94531dff19148`) and Daniel Mauser's Network
Desk (N revision `4104279fa4707c24e6038b35b2779fecfdd11eea`). No upstream code/text
is copied for this increment; existing notices and adaptation lineage remain.
Publication must keep the canonical run directory absent until all four files
are verified, refuse overwrite and concurrent same-run work, and propagate
write/publication failures. Abrupt termination may leave a private staging
directory; automatic resumption, Azure recollection and attachment-upload
recovery remain separate unimplemented work.

This first increment is published and installed at
`<implementation-commit>`, capability `0.1.1`. Validation covers
62 local/native Linux synthetic cases, a packaging dry run, unchanged live-input
semantics and installed four-artifact retrieval/hash comparison with no Azure
recollection. Schema/input versions and all six check versions are unchanged.
This closes only bundle publication/ordinary failure cleanup, not the remaining
Step 3 acquisition/upload recovery or broader audit requirements.

### Step 3 upload recovery decision: 2026-10-08

U/N roots and pinned revisions were reconfirmed, with clean read-only worktrees.
Searches covered U1's authoritative artifact/write-verification rules, U3's
persistence/evidence guidance, and N24/N25 source preservation, no-overwrite,
retry and output-location guidance. License/permission status is unchanged.

| Capability | Classification | Exact foundations and decision | Downstream integration |
|---|---|---|---|
| Selected-input upload checkpoint, receipt verification and upload-only recovery | NEW integration (C04/C26) | U1 workflow steps 5-7 and failed-write rule; U3 persistence principles; N24 guardrails 3-5 and N25 Output location. These inspected portions provide conceptual persistence/source-preservation foundations, not an SRE attachment reconciler. No implementation is copied; attribution remains Usman Mahmood/U and Daniel Mauser/Network Desk/N at the recorded revisions. | `tools/network_health_sre.py` persists only selected input/scoped metadata beside, not inside, the four-file bundle. Recovery validates local identity/contracts/hashes and remote receipt bytes without Azure recollection or rewriting reports. |

The official app client exposes attachment POST and returned download metadata,
but no attachment-inventory GET was found. A bounded GET of the attachments
route returned HTML; thread metadata exposed no authoritative upload inventory.
The user approved receipt-verified recovery with ambiguous retries blocked:
after a dispatched upload without a durable receipt, require a saved or
operator-supplied actual receipt and verify its downloaded bytes. Never treat
an HTTP error or missing response as proof the upload was not accepted. This
does not implement acquisition checkpoints/resume or a new networking domain.

Validation of this host-only increment includes 78 local regressions and a
controlled synthetic real-service fault trial. A single instrumented attachment
POST was recovered after injected response loss using its actual receipt, then
verified by fresh-process CLI download. Unchanged installed code produced four
synthetic reports independently downloaded byte-for-byte equal to the original
local bundle, without Azure resource collection. Exact evidence and limitations
are recorded in runtime-validation; no plugin/check version or upstream
permission/notice changed.

### Step 3 page-level acquisition resume decision: 2026-10-08

U/N pinned roots/revisions were reconfirmed. Inspected portions: N1's Assess/
inventory examples (lines 97-102), N2's Pre-Change Health Snapshot (lines 291-317,
read/snapshot portion only), U1's evidence/persistence/write-verification
workflow, and U2's evidence-supported observations. Existing license/permission
and attribution requirements are unchanged.

| Capability | Classification | Exact foundations and decision | Downstream integration |
|---|---|---|---|
| Selected-page checkpoint and outstanding-native-request reconciliation | NEW integration (C04/C06-C08) | ADAPT inventory/snapshot foundations remain N1/N2; U1/U2 preserve evidence and uncertainty discipline. No SRE-native nonce journal, selected-page resume or accepted-request reconciler was found in these inspected portions. No mutation, rollback implementation or raw snapshot exporter is copied. | Independent optional collector progress contract and host bridge journal. Preserve selected rows, counters, continuation, original collection times and terminal failures; retrieve an accepted outstanding execution without reposting. |

The user chose conservative page-level recovery. Checkpoints bind subscription,
run, endpoint/thread, page size, helper capability and catalog fingerprint.
They contain selected configuration and necessary continuation/request metadata,
not full raw responses or credentials. Unknown acceptance, duplicate/unexpected
executions, changed identity/configuration and stale locks must stop explicitly.
This is not a fresh point-in-time snapshot, an authorization to retry terminal
failures, an Azure change or a new assessment domain.

This increment is published and installed at
`<implementation-commit>`, capability `0.1.2`.
Validation: 95 local/native Linux regressions, actual interrupted/resumed native
paging with 15 executions/15 unique commands, eight independent scoped Azure
reads, completed replay without new reads/writes, canonical installed-asset
fingerprints and four persisted downloads matching local bytes. Check/schema
versions and upstream permission/notice requirements remain unchanged.

### Step 3 literal report/link integrity decision: 2026-10-08

Both read-only reference roots/revisions were reconfirmed. Exact foundations:
U3 Reporting Principles and Quality Checks (lines 263-278: valid Markdown tables,
readability, evidence and consistent findings), and N25 Quality checklist
(lines 67-78) plus Output location/source-preservation guidance. Existing
permission/notice requirements remain unchanged.

| Capability | Classification | Decision and precise lineage | Downstream integration |
|---|---|---|---|
| Literal-safe dynamic report text, exact internal-link verification and explicit JSON version provenance | NEW integration (C23/C28), with existing ADAPT reporting discipline | U3 and N25 supply conceptual report-quality foundations, not this deterministic Markdown escape/link verifier. No upstream renderer/template implementation is copied. Preserve attribution to Usman Mahmood/U and Daniel Mauser/Network Desk/N at their recorded revisions. | Independent changes to `network_health.py` and focused tests. Fix schema-valid literal text/code-block link false positives, reject malformed/missing/duplicate generated references and expose existing schema/capability/check/priority provenance. No new collection, assessment checks, severity policy or domain. |

Reproduced failures before implementation: literal `](#...)` in a finding title
causes a false unresolved-link error; the same syntax inside a valid selected
evidence `name` JSON field is incorrectly treated as an active Markdown link.
The new capability version records the presentation/verification change, while
schema shape and check/catalog versions remain unchanged. Historical report
verification must preserve valid older bundles and their recorded provenance.

This increment is published and installed at
`<implementation-commit>`, capability `0.1.3`. Validation
includes 102 Windows/native Linux regressions, actual historical report/upload
compatibility, unchanged-observation/finding replay without Azure recollection,
eight canonical installed-asset fingerprints and four byte-identical persisted
downloads. Broader execution-surface audit and remote report-save recovery are
not claimed complete.

### Step 3 collection-only surface audit decision: 2026-10-08

Both read-only U/N roots/revisions were reconfirmed. Relevant inspected portions:
U1 Modification Policy (lines 43-58), U2 Finding Evidence (lines 248-258), N2's
audit/fail-safe guidance (conceptual only; no rollback commands copied), and
N24 guardrails separating rendering from infrastructure operations. Existing
permission/notice and attribution requirements remain unchanged.

| Capability | Classification | Decision and exact evidence | Downstream integration |
|---|---|---|---|
| Metadata-only structured execution-surface coverage and strict collection-only protocol | NEW integration (C04/C23) | U1/U2 evidence/modification boundaries and N2/N24 audit/separation principles are conceptual foundations, not an SRE thread-surface classifier. Read-only live API inspection found 14 execution/result/query fields exposed on every message; the collection thread had only 15 Azure CLI executions, while a separate processing thread exposed terminal/file reads. No upstream implementation copied. | `tools/network_health_sre.py` gates collection, records counts/presence/IDs without outputs and requires separate processing threads. |

The user approved fail-closed collection-only threads: reject visible non-Azure
activity, missing required surface fields and unknown non-null execution/result/
query fields; retain explicit limits for unclassified null/unexposed fields.
This is detection of visible deviations, not prevention or proof of absence of
all parent-agent activity. Processing in a collection thread becomes a protocol
violation for acquisition audit/resume; receipt-only upload verification remains
separate. No new networking domain, Azure mutation or assessment check is added.

Validation: 112 Windows/isolated native Linux regressions and independent
download/hash verification of the full Linux log; actual existing collection
history accepted (48 messages, 15 reads), actual separate processing history
rejected, five unclassified null result fields explicitly recorded, and
historical receipt-only recovery unchanged. No resource recollection or installed
plugin change. Metadata-only audit records stay private; no universal prevention/
visibility or later report-save recovery is claimed.

### Remote report-save recovery decision: 2026-10-08 (local)

Pinned U/N roots/revisions were reconfirmed. Relevant portions: U1 artifact-write
verification/failure rule, U3 persistent report and Quality Checks (complete
artifact written), N24 workflow step 4/guardrails 3-5 (no unsolicited overwrite,
preserve source, explicit failure/retry), and N25 Output location/source
preservation. Existing permission/notice requirements are unchanged.

| Capability | Classification | Exact foundations and decision | Downstream integration |
|---|---|---|---|
| Verified-original report-save plan, durable native-save receipts and partial-save recovery | NEW integration (C23/C26/C28) | U1/U3 and N24/N25 provide conceptual persistence/source-preservation foundations, not this SRE publication ledger. No upstream implementation/template is copied. Native tool-definition preflight exposes required `filePath`, returned key and overwrite-by-name, but no native read-back/checksum/listing or idempotency guarantee. | Independent helper/installed skill procedure: bind original bundle hashes/run/thread, immutable run+hash filenames, begin/actual-key recording, recover remaining or ambiguous identical copies. Host authenticated download verifies saved bytes. |

The user approved retrying only verified identical immutable copies after
interrupted native saves. This relies on documented overwrite-by-name, not an
exactly-once/idempotent-platform claim. Saved receipts remain unverified until
authenticated downloads match expected bytes. Never recollect Azure or rebuild
missing originals, overwrite another run's artifacts, invent keys or mark a
printed link as retrieval proof. Collection-only and processing threads remain
separate; no new Azure resource mutation, assessment domain or custom agent.

Published/installed at `<implementation-commit>`, capability
`0.1.4`. Validation includes 122 Windows/native Linux regressions, eight canonical
supporting-asset hashes and an actual partial/ambiguous native-save trial.
Installed recovery skipped two receipts, retried identical third bytes and
completed the fourth without regeneration. Authenticated downloads verified all
four against original golden bytes, and the SRE Agent checked the externally
produced proof. No resource recollection or additional findings; runtime
read-back/retention limitations and original collection intervals remain explicit.

### Step 4 contextual addressing decision: 2026-10-09

Pinned U/N roots/revisions were reconfirmed. Relevant portions: U2 IP Addressing
and Subnets (lines 52-64: evidence/context before CIDR recommendations), U2
Positive Findings (lines 304-315), U3 positive/priority/report-quality guidance,
and N6 Azure peering/overlap/decision guidance. Existing permission/notice
requirements are unchanged; no upstream implementation or mutation procedure
is copied.

| Capability | Classification | Exact foundations and decision | Downstream integration |
|---|---|---|---|
| Peering-context overlap action priority and aggregated scoped disjoint-address positive | ADAPT discipline/COMPOSE guidance (C01/C02/C09), NEW deterministic integration | Usman Mahmood/U2-U3 supplies evidence/context/positive discipline; Daniel Mauser/Network Desk N6 supplies peering/address foundations, not this normalized check implementation. Current Microsoft Learn peering overview/subnet-peering documentation was inspected 2026-10-09 and exposes selective/IPv6-only modes not collected by this slice. | Version NET-ADDR-001 with OBSERVED configuration-relationship support, P1 evidence/context validation (not proven defect/outage), and one INFERRED scoped positive only with successful VNet collection and valid nonempty prefixes. |

The user approved both bounded changes. Generic overlap stays contextual P2;
only retained `contains`/`peeringTo` relationships between collected affected
VNets justify higher next-action ordering. Unknown peering mode, intent,
reciprocal/effective behavior and decommissioning remain explicit. Do not infer
full-VNet peering applicability or public reachability.

The positive is an aggregate of collected VNets disjoint from all other valid
collected ranges; all compared evidence supports it, not just the affected
subset. Empty/invalid/incomplete VNet evidence suppresses it. Accessible indexed
scope is not permission-wide completeness; this is not a healthy score or
customer architecture compliance claim. No NSG-presence positive, new acquisition
operation/domain or resource mutation.

This bounded first Step 4 increment is published and installed at
`<implementation-commit>`, capability `0.1.5`; NET-ADDR-001/
catalog/priority policy `1.1.0`. Validation includes 129 Windows/native Linux
regressions, historical catalog/upload compatibility, unchanged observation
replay, measured one-positive/four-of-six result with all comparison evidence,
eight canonical installed hashes and authenticated four-artifact downloads
matching golden bytes. P1 linked-overlap applicability remains synthetic-only;
no fictitious Azure defect was created. Existing read-backed evidence was reused
without new collection or domain expansion.

### Step 4 directional peering triage decision: 2026-10-09

The user chose deeper peering triage within existing acquisition scope, not
Private Endpoint/DNS expansion. Pinned U/N roots/revisions were reconfirmed.
Exact foundations: U2 VNet Peering (lines 66-80: both directions, access/forwarded/
gateway settings, dependencies, directionality); N6 Azure peering bidirectional
examples/key settings (lines 9-52, guidance only, no mutation commands copied).
Current Microsoft Learn manage-peering Requirements/constraints was inspected:
Initiated is the first direction, Connected is expected for both directions.
Selective/IPv6 peering-mode and effective-flow uncertainty from the previous
increment remain explicit. Licensing/permission/notice requirements unchanged.

| Capability | Classification | Decision and lineage | Downstream integration |
|---|---|---|---|
| Reciprocal peering configuration-state triage with scoped missing/ambiguous evidence | ADAPT discipline/COMPOSE U2/N6 guidance (C10), NEW deterministic integration | Usman Mahmood/U2 supplies directional/context assessment; Daniel Mauser/Network Desk N6 supplies bidirectional peering foundations. Current Learn grounds state interpretation; no copied template/commands or automatic changes. | NET-PEER-001 versioned deterministic grouping using retained OBSERVED parent/remote relationships. One paired state record rather than duplicate directions; explicit unknown/unobserved/out-of-scope/partial reciprocal evidence, no packet/healthy claims. |

Unobserved reciprocal configuration is an evidence gap, never proof of absent
peering or missing connectivity. Connected/Succeeded on two unique retained
directions is an OBSERVED configuration-only informational record, not a
positive operational-health score; access/NSG/routes/peering modes/traffic are
not established. Failed/Disconnected remains contextual medium; Initiated/
transition states require context, not automatic defect or severity inflation.
Reference-only/external targets are not queried and no new acquisition domain
or Azure resource mutation is authorized.

Published/installed at `<implementation-commit>`, capability
`0.1.6`; NET-PEER-001 `1.1.0`, catalog `1.2.0`, priority policy unchanged
`1.1.0`. Validation: 138 Windows/native Linux regressions with independently
retrieved original logs, previous delivered catalog compatibility, unchanged
actual no-peering observation replay, eight installed Git fingerprints and four
native-saved artifact downloads matching golden bytes. No deployed peerings were
fabricated; all richer pair/state cases remain synthetic-only. No scope expansion,
new acquisition or change to upstream attribution/permission.

### Private Endpoint/Private DNS first increment: approved 2026-10-09

The user explicitly approved read-only enrichment of Private Endpoints and
Private DNS together. Existing selected-subscription/development-target scope
and assessment safety boundaries remain; no deployment, diagnostic enablement,
traffic test, external publication or automatic cross-subscription discovery.

Pinned U/N roots/revisions were reconfirmed. Inspected exact foundations:
U2 Private Endpoints/Private DNS (lines 130-162: target/subresource/subnet, public
access distinction, zone groups/VNet links and DNS-versus-IP validation);
N11 private-link agent Azure workflow phases 3-6/cross-cutting DNS/public-access
guidance; N12 dns-integration How Private Endpoint DNS Works, VNet Linking,
A Record Management and custom-DNS sections. Network Desk MIT notice and
project-owner-reported Usman permission remain unchanged. Canonical reference
files are read-only; no mutation examples, blanket requirements or multi-cloud
procedures are copied.

| Capability | Classification | Decision and exact lineage | Planned downstream integration |
|---|---|---|---|
| Scoped Private Endpoint/Private DNS evidence acquisition and factual joins | ADAPT Network Desk N11/N12 procedures, NEW target-runtime integration (C04/C12/C13) | Existing endpoint approval/DNS-zone-group/VNet-link foundations are not new inventory concepts. Actual Resource Graph child indexing and ARM projections must be proven before collector claims. | Allowlisted selected configuration with collection scope/times/coverage/failures and evidence-supported endpoint→subnet/target, zone-group→zone and VNet-link relationships; unsupported/uncollected child evidence stays UNKNOWN. |
| Limited private connectivity configuration triage | ADAPT U2 contextual discipline, COMPOSE N11/N12 guidance, NEW deterministic integration | Approval is not reachability; zone group/link is not successful DNS resolution; private endpoint is not proof public access is disabled. Custom/shared DNS and external dependencies are not automatic defects. | Only narrowly evidenced state/link records and explicit gaps; no mandatory zone convention, healthy/private-only score or automatic specialist execution. |

Read-only shape probes are authorized only for these types in the explicitly
selected subscription and must retain no full raw resource responses by default.
Exact inspected response methods, limitations and completed integrations are
recorded below before implementation; a successful indexed empty result is not
proof a child configuration is absent.

### Proven first acquisition shape and implementation boundary

Correctly scoped host Resource Graph REST (explicit subscription list, existing
tenant sign-in) found 28 Private Endpoints, 24 private DNS zones and 24
VNet links. The generic ARM MCP query in its other effective context returned
zero; that result was not treated as resource absence. Resource Graph did not
index private DNS zone-group children. Parent endpoint properties also lacked an
embedded zone-group array.

Two exact scoped direct endpoint reads and parent-scoped
`az network private-endpoint dns-zone-group list` probes proved automatic/manual
connection arrays and child-zone configuration. The CLI child-list projection
has no `type`/location field, so normalization derives only operation type and
parent scope from the exact approved call; group location stays unavailable.
Only selected IDs/state/counts/group IDs/zone IDs are retained, not descriptions,
request messages, record-set payloads or full responses.

Implement an explicitly gated `--include-private-connectivity` collection mode:
retain the nine-operation default, add five narrowly bounded operations for
endpoints/connections/zones/VNet links and parent-scoped zone-group lists. Group
reads are derived solely from collected in-scope endpoint parents and bounded
by the existing per-operation budget. Each successful child-list page carries
its parent ID, including zero rows; failed/unattempted parents never become
absence evidence. Contract/schema version is additive `0.2.0` for enriched
models, with historical `0.1.0` input/models and default scan preserved.
Initial deterministic private checks cover connection state and configured DNS
joins/gaps only; A/AAAA records, resolver/forwarding configuration, DNS resolution,
service public access, effective routing/security and traffic remain deferred.

The implementation now provides those five operations and NET-PRIVATE-001/
NET-PRIVATE-DNS-001 (1.0.0) configuration-only checks. Native collection in the
approved subscription completed fourteen operations with 43 unique approved
reads: 28 endpoints/connections/groups and 24 zones/links. Completed resume added
no reads and preserved all four outputs. Twelve independent ARM-backed reads
validated three endpoint/connection/group/zone/link chains; no raw responses
were retained. The unchanged 149-case suite passed on Windows and native Linux;
the original Linux log was independently downloaded/hash-verified. Actual
historical delivered reports still verified under the additive contract.
These validations do not establish resolution, traffic or private-only service
access. Publication/installed replay is recorded separately in runtime validation.

### Private DNS service planning and repeated-zone review (approved 2026-10-09)

The user approved bounded Private Link service inventory in the existing
workload subscription, with a separate explicit DNS-hosting subscription
allowlist. Live validation remains restricted to the previously approved
subscription; no tenant-wide discovery or automatic subscription expansion.

References were rechecked read-only at U revision
`624bd5c3bf5bd5b8df625cc111c94531dff19148` and N revision
`4104279fa4707c24e6038b35b2779fecfdd11eea`.
N `private-link/skills/endpoint-design/SKILL.md` lines 73-89 already maps
service/group IDs to DNS zones; N12 DNS integration lines 114-152 covers
centralized/shared DNS and forwarding. U2 lines 130-162 covers target/subresource,
public access, DNS and customer-intent validation; lines 40-47 mention accidental
duplicate platform resources. These foundations are not described as new.
Network Desk remains MIT (notice retained); Usman's owner-reported permission
record remains unchanged.

| Capability | Classification | Rationale / downstream boundary |
|---|---|---|
| Service/subresource/zone mapping and central-DNS context | COMPOSE N endpoint-design/N12; ADAPT Microsoft Learn factual mapping | Versioned commercial-cloud planning catalog, preserving regional/conditional values and special record-versus-zone footnotes. Not a universal list of required zones or proof of service feature eligibility. |
| Scoped service inventory and central-DNS acquisition | NEW integration of existing discovery foundations | Selected resource metadata only; explicit DNS-host scopes query only zones/links, not their workloads/endpoints. Omitted/inaccessible scopes are UNKNOWN. Scope/resume/command audit remain bound. |
| Deterministic service planning matrix and repeated-zone review | NEW evidence-contract/check integration; ADAPT U contextual discipline | Separate observed target/subresource connections from unobserved connections. Never infer missing endpoints *because* a DNS zone is absent. Same normalized zone name across distinct IDs is contextual cleanup review, not proof of a mistake or permission to delete. |

Microsoft source: [Private Endpoint DNS values](https://learn.microsoft.com/azure/private-link/private-endpoint-dns),
MicrosoftDocs/azure-docs `articles/private-link/private-endpoint-dns.md`, inspected
file revision `3e5a15284eb79de0cba78c4dc29ece41a2db44d2`, commercial tables and
footnotes 1-4. The repository LICENSE is CC BY 4.0, independently checked.
The structured factual catalog is an adaptation attributed to Microsoft,
with a source/revision/date/license record and explicit transformation notes;
it is not silently relicensed as original implementation. No narrative,
mutations, active tests or sovereign-cloud assumptions are copied.

The structured catalog has 91 mappings covering all 71 resource types in the
pinned commercial table. Independent source comparison found no missing types
or zone/subresource values after the documented ACR/SCM record-name exclusions.
This is a catalog snapshot, not a claim of perpetual service availability.

Downstream integration is now in `network_health.py`, `network_health_sre.py`,
the additive schemas, catalog/check files and installed skill procedure.
The default and private-only modes retain their contracts. Opt-in planning
has fifteen workload operations/ten checks, plus only DNS zone/link operations
in each additional allowlisted host. 170 tests pass on Windows and unchanged
native Linux, including scope-injection rejection and accepted central-page
reconciliation without reposting. Live validation in the approved subscription
collected 39 services/24 zones with 44 audited native reads; a separate
ARM-backed list confirmed five repeated-name groups, not accidental duplication.
Additional-subscription hosting is synthetic-only; no source/permission scope
was silently broadened.

### Privacy-minimized repeated-zone record metadata (approved 2026-10-09)

The user selected read-only record-set metadata for repeated zone names in the
existing approved subscription: types, counts and TTL ranges only. Record-set
names/IDs, IP/address/alias/MX/SRV/TXT values, full responses and active DNS
tests are excluded. This is cleanup-review evidence, not proof that zones are
unused, equivalent or safe to remove.

Both references were rechecked at the U/N revisions recorded above. N12
`private-link/skills/dns-integration/SKILL.md` lines 87-109 and 211-239, plus
`private-link/skills/troubleshoot/SKILL.md` lines 48-70, already cover record
inspection alongside zone groups/client paths. U2 accidental-duplicate
platform context (lines 40-47) and Private DNS/external dependency discipline
(lines 145-180) apply. Network Desk MIT notice and Usman's project-owner-reported
permission remain unchanged.

| Capability | Classification | Decision and downstream boundary |
|---|---|---|
| Record inspection for repeated-zone review | COMPOSE N12/troubleshoot; ADAPT U2 contextual discipline | Reuse conceptual investigation order, not create/delete/active lookup examples or blanket missing-record remediation. |
| Privacy-minimized type/count/TTL summary acquisition | NEW adapter integration of existing record-list procedure | Exact parent-scoped `az network private-dns record-set list` projection; local arithmetic summaries explicitly marked as configuration objects, not actual Azure child resources. Bounded selection, explicit truncation/invalid metadata/permission gaps, saved modes/scopes and native request reconciliation. |
| Metadata review in deterministic report | NEW evidence-contract/check integration | Record sets are not individual record values. Counts/TTL differences require context; equal summaries do not prove equality, shared clients or safe consolidation. |

Microsoft CLI reference inspected 2026-10-09:
https://learn.microsoft.com/cli/azure/network/private-dns/record-set
(documentation revision `2fca3eed9046b3284f2c6eb3722c1328dd8c984c`).
It confirms a read-only Core/GA zone-scoped list; projected runtime shape and
read compatibility must be proved before claiming executable acquisition.

Two direct reads against known repeated ACR zones proved the actual Core CLI
projection: three selected sets each, types A/SOA, TTLs 10/3600, no names/IDs/
values in output. The candidate implements opt-in acquisition 1.3.0/input 0.4.0
and NET-DNS-META-001 1.0.0; prior default/private/planning modes keep their
contracts. All 185 tests pass on Windows and unchanged native Linux, including
metadata privacy, explicit zero/unavailable/truncated distinctions, repeated
parent scope, TTL/count invariants, accepted-request resume and report integrity.
Actual historical 0.3.0 delivered reports still verify. Live full-scope metadata
collection and installed delivery are recorded separately in runtime-validation.

Current-subscription native collection completed sixteen operations/59 audited
reads, including fifteen repeated-zone metadata lists. All fifteen summaries
matched independent ARM-backed type/count/TTL projections; 39 selected sets
(24 A/fifteen SOA), without record names/IDs/values. Completed replay added no
reads or changed report bytes. Final unchanged 185-case release passed on
Windows/Linux. No additional subscriptions or cleanup/active tests were run.

### Configured DNS resolver and forwarding paths (approved 2026-10-09)

The user approved existing VNet DNS-server settings and Azure DNS Private
Resolver/endpoint/ruleset/rule/VNet-link configuration in the existing workload
subscription. Domain suffixes and target IPs/ports may be retained only in
access-controlled engineering evidence. No customer-managed DNS-server
inspection, active resolution tests, diagnostics or resource changes.

U2 Private DNS/external dependency portions (lines 145-180) and N12 centralized/
custom-DNS guidance (lines 114-147), plus N private-link agent line 122, were
rechecked at the recorded U/N revisions. Their networking foundations are not
new. Existing MIT notice and owner-reported Usman permission remain applicable.

| Capability | Classification | Decision / downstream assets |
|---|---|---|
| Resolver/forwarder investigation and contextual interpretation | COMPOSE N12/private-link agent; ADAPT U2 evidence/dependency discipline | Inspect selected configuration, not blanket every-VNet-zone links or inferred client use. Outbound endpoints have subnet configuration, not an invented private IP. |
| Target-runtime selected DNS-path acquisition | NEW adapter integration of existing investigation foundations | VNet settings in a distinct configuration object; extension-free exact ARM GET root/parent lists using stable 2022-07-01. Selected states/references, inbound IPs, rule domain/target IPs/ports only. No metadata/tags/secrets/full responses; external targets remain unqueried. |
| Deterministic configuration path view | NEW evidence-contract/check/report integration | Direct configured VNet/subnet/outbound/link references can be observed; configured addresses/rules are not proven forwarding/client use. Missing resolver roots does not imply no custom/external DNS. |

Microsoft guidance inspected 2026-10-09:
`private-resolver-endpoints-rulesets` document revision
`fb2bffef7c187084d68e891abfcef957fb752117`, inbound/outbound/ruleset/VNet-link
semantics; ARM schema references for 2022-07-01 at revision
`9a8f8820ebf02dc4524627037dcf7fa736fe7337`; Azure REST API specs
`specification/dnsresolver/resource-manager/Microsoft.Network/DnsResolver/stable/2022-07-01/dnsresolver.json`
GET/list shapes. No deployment snippets or narrative copied.
Two direct ARM GET root probes in the approved subscription succeeded with zero
accessible resolver/ruleset rows and no continuation. This is scoped evidence,
not permission-wide/custom-DNS absence. Live nonempty child paths remain
unproven until separately authorized evidence is available.

The candidate now provides seven selected DNS-path operations, factual
configured references, a deterministic `dnsPaths` view and NET-DNS-PATH-001
1.0.0 with field/actual-behavior gaps. 198 cases passed on Windows and unchanged
native Linux; exact ARM JMES projections were separately executed synthetically,
including positional null-port preservation. Actual VNet DNS projection
selected six known empty DNS-server arrays. Native collection completed
23 operation outcomes/62 audited reads; independent ARM-backed reads verified
all six VNet DNS defaults and both scoped empty resolver/ruleset roots.
Completed replay added no reads or changed bytes. Nonempty resolver/endpoint/
forwarding cases remain synthetic-only; no customer-managed DNS, active
resolution, other subscriptions or resource changes were inspected/performed.

### Resolver adoption / partial-transition review (requested 2026-10-09)

The user highlighted customers with an Azure DNS Private Resolver deployed but
only partially or inconsistently transitioned consumers/ruleset links. This
increment assesses already selected configuration only; no additional Azure
scope, acquisition operation, active DNS test or resource change.

Both read-only reference roots/revisions were rechecked at U
`624bd5c3bf5bd5b8df625cc111c94531dff19148` and N
`4104279fa4707c24e6038b35b2779fecfdd11eea`. U2 Private DNS and external
dependency discipline (lines 145-180), N12 hub/spoke/custom-DNS examples
(lines 114-147) and N private-link resolver guidance remain relevant.
Network Desk MIT attribution and Usman's project-owner-reported permission
are unchanged.

| Capability | Classification | Rationale / downstream integration |
|---|---|---|
| Contextual resolver migration review | COMPOSE N12/private-link guidance; ADAPT U2 requirements/dependency discipline | Mixed defaults, link patterns, rules and endpoints are review signals, not proof of a defect, percentage migrated or universal every-VNet-link requirement. |
| Evidence-backed consumer/ruleset adoption matrix | NEW deterministic evidence-contract/check/report integration | Join selected VNet DNS defaults and ruleset links; preserve incomplete parent-list/permission/continuation evidence, external consumers and unknown intent. Unobserved links are not required links; matching configured inbound IPs are candidates, not client-use proof. |

Microsoft's [resolver endpoints/rulesets guidance](https://learn.microsoft.com/azure/dns/private-resolver-endpoints-rulesets),
revision `fb2bffef7c187084d68e891abfcef957fb752117`, was rechecked. Ruleset
links and inbound/custom-DNS paths can serve different architectures; peering
is not required merely for ruleset-linked DNS resolution. Do not copy
blanket linking/forwarding requirements or deployment/active-test examples.
The existing live sample has no scoped resolver/ruleset resources; richer
partial-transition patterns require synthetic evaluation unless separately
approved nonempty evidence becomes available.

Implementation adds NET-DNS-ADOPT-001 1.0.0 and the deterministic
`dnsResolverAdoption` assessment/view contract, using unchanged acquisition
1.4.0/input-schema 0.5.0. 216 Windows/Linux cases passed, including complete
parent-list proof, staged/disabled rules, valid inbound-only designs, mixed
defaults/associations, unready or unknown outbound references, ambiguous IP
candidates and external consumers. Existing selected live input was replayed
without Azure recollection; factual observations/provenance matched the prior
model except producer version. Its six VNet rows and absent scoped resolver/
ruleset deployment produced no invented partial-migration finding. Actual
0.5.0 delivered reports still verified. Rich transition scenarios remain
synthetic-only, not live customer validation.

Final contextual findings directly cite selected DNS setting/link/outbound
evidence, rather than relying only on VNet inventory references. Complete
parent/root-page proof gates unobserved-association interpretation; unknown
targets and unavailable/unready outbound references are explicit evidence
gaps. Deployment/link observations are not a resolver readiness certificate.

### Customer DNS intent and migration-cohort comparison (approved 2026-10-10)

The user selected structured customer DNS intent input rather than broader
Azure acquisition. U/N read-only roots and recorded revisions were rechecked:
U `624bd5c3bf5bd5b8df625cc111c94531dff19148`, N
`4104279fa4707c24e6038b35b2779fecfdd11eea`. U2 assessment principles
(lines 14-31) separate documented requirements/assumptions/dependencies from
observed implementation; N12 centralized/custom-DNS patterns (lines 114-147)
offer alternative architectures, not universal required links. Usman's
owner-reported permission and Network Desk MIT notice remain applicable.

| Capability | Classification | Downstream boundary |
|---|---|---|
| Requirements-versus-observation discipline | ADAPT U2; COMPOSE N12 alternative DNS architectures | Customer-provided owner/revision/time/cohort intent stays DECLARED; deployed configuration stays OBSERVED. Planned/in-progress rollout is not a required-now defect. |
| Structured DNS intent and comparison contract | NEW independent integration | Optional run/subscription-bound processing input; explicit disjoint VNet cohorts, stage and configured DNS/ruleset/inbound targets. No desired-state deployment, automatic resource acquisition or assumed customer intent. |
| Persistent intent comparison report | NEW deterministic check/view integration | Persist canonical intent/hash/provenance in assessment only, compare evidence-backed configuration, retain incomplete/out-of-scope targets and time-order gaps. Matching configuration is not actual DNS use, readiness or migration completion. |

No upstream prompt/narrative/deployment implementation is copied. Source
document identity is operator-supplied provenance, not an independently
authenticated grant or proof the supplied customer standard is current.

The independent implementation uses `dns-intent.schema.json`, processing-only
`--dns-intent`, NET-DNS-INTENT-001 1.0.0 and a deterministic assessment/report
view. No-intent check sets remain unchanged; supplied intent selects catalog
1.8.0/fourteen checks. 237 Windows/Linux cases verify source/scope/run/time/
cohort conflicts, required/planned/excluded stages, incomplete parent evidence,
external targets and immutable four-report delivery. Existing actual selected
input replay preserved observations except producer version and did not add
requirements or reads. Intent evaluation is synthetic-only: no customer
document or actual customer intent was supplied.

### Scope-validated ARM pagination and resume (approved 2026-10-10)

The user selected bounded pagination for the existing resolver GET lists.
Read-only U/N references remain at the recorded revisions
`624bd5c3bf5bd5b8df625cc111c94531dff19148` /
`4104279fa4707c24e6038b35b2779fecfdd11eea`. Targeted searches of Network Desk
network-automation and Usman's Markdown did not identify a resolver-specific
continuation implementation. Existing inventory/snapshot/recovery foundations
and licensing/permission attribution still apply.

Classification: NEW target-runtime pagination integration, not new discovery
or resolver investigation concepts. Downstream collector/bridge/checkpoint
changes preserve exact read-only origin/subscription/parent/API/projection
binding. Continuations are treated as untrusted navigation, not instructions.
Only approved query parameters, bounded token/URL sizes and existing page
budgets are accepted; malformed/repeated/cross-scope continuation preserves
selected evidence and explicit partial gaps. Root/child paging and parent
iteration must remain distinct on resume. Historical acquisition 1.4.0 inputs
retain their original first-page limitation and provenance.

The implementation now derives acquisition 1.5.0 ARM projections from the
unchanged historical catalog, with explicit nextLink selection, operation
version 1.1.0 and separate canonical page/parent cursor state. No new resource
types or customer scope. Input/schema 0.6.0 retains per-page ARM-continuation
flags; complete multi-page evidence feeds existing guarded adoption/intent
views. 251 tests passed on Windows and unchanged Linux, including scope/API/
query rejection, opaque encoded tokens, multiple parents/pages, empty pages,
missing metadata, budgets and accepted-request resume without reposting.
Two actual native scoped empty-root projections matched independent ARM reads.
Historical delivered intent reports still verified. Nonempty multi-page
customer evidence remains unvalidated; synthetic pagination is clearly labelled.

### Age and provenance review without expiry policy (approved 2026-10-11)

The user selected observation freshness/customer-intent review, then explicitly
chose ages and provenance gaps only, without expiry thresholds. No time-to-live
policy, stale/expired label, automatic recollection or validity certification.
Use an operator-supplied UTC reference time for deterministic processing.

Both U/N roots/revisions were verified read-only at the recorded revisions.
U2 principles separate requirements/observations/assumptions; U reporting
`assessment-reporting/SKILL.md` lines 20, 43 and 269 establish fact/assessment
date discipline. N `report-builder/skills/report-structure/SKILL.md` line 70
requires dated/sourced numbers. Licensing/owner-reported permission and
existing notices remain unchanged.

Classification: ADAPT U evidence/provenance discipline; COMPOSE N dated-source
reporting guidance; NEW independent deterministic temporal-contract/check
integration. Selected collection intervals and evidence/source timestamps
remain observations/provenance, not proof data or intent are still valid.
Reference time, exact ages and chronology gaps belong in assessment/views,
not rewritten observations. Chronology inconsistencies/future timestamps must
be explicit; no silent clamping or wall-clock drift when reopening reports.

Implementation adds processing-only `--review-at`, NET-EVID-TIME-001 1.0.0
and deterministic `provenanceTimeReview`, using integer microsecond ages and
original timestamps. Input/acquisition schemas/read scope are unchanged.
265 Windows/Linux cases verify exact fractions, no wall-clock drift/thresholds,
all existing modes, future/inconsistent timestamps, evidence timestamp
disagreement, failed/no-page outcomes, unauthenticated intent metadata,
tamper rejection and four-file processing-only delivery. Actual earlier
report downloads still verify. The installed time/intent evaluation is
synthetic-only, not a customer source-validity judgment.

### End-to-end customer assessment acceptance workflow (approved 2026-10-11)

The user selected a complete acceptance workflow using synthetic fixtures and
existing approved evidence, not more isolated criteria or customer scope.
Both read-only reference roots/revisions were verified at the recorded U/N
pins. U `assessment-reporting/SKILL.md` quality checks (lines 264-275) cover
authoritative persistence, evidence/count consistency and sensitivity; N
`report-builder/skills/report-structure/SKILL.md` quality checklist (lines 67-77)
covers sourced/dated facts and actionable reporting. Existing MIT notice and
project-owner-reported Usman permission remain applicable.

Classification: ADAPT U evidence/persistent-artifact acceptance discipline;
COMPOSE N reporting quality gates; NEW independent cross-stage acceptance
test integration. Reuse existing collector, transport checkpoints/upload
recovery, intent/time comparison, four-file renderer and publication verifier
rather than duplicate implementations. Explicit scope, terminal permissions,
accepted-request interruption, ambiguous upload, partial report save and final
download proof must be tested together. A synthetic pass is not live customer
acceptance, universal tool enforcement or permission-wide completeness.

The independent `test_customer_acceptance.py` composes complete and
partial-permission journeys plus collection-thread contamination rejection.
It executes production processing CLI/publication/verification helpers using
mocked native/read/upload/blob boundaries, including accepted-page response
loss, scoped resume rejection, actual-receipt upload recovery, staged intent/
age review, partial proof, identical-copy retry, corrupt download rejection
and immutable completion. All 268 Windows/Linux cases passed. Customer-facing
README and installed skill now wire explicit acceptance gates and limits;
there is no new subagent, collector, check or Azure resource mutation.

### First-pass access and architecture scope summary (approved 2026-10-11)

The owner requested an initial component/access summary before full inspection,
subscription discovery/name-based role hints, private-preferred services with
explicit public exceptions, and OBO/operator supplemental collection for
Contoso. Subscription listing and first-pass reads are authorized by this
request; no redundant agent approval gates. Full inspection remains a separate
user trigger, not automatic expansion from discovery.

U agent operating workflow/repository-discovery (lines 16-43) and U2 documented
versus observed dependency discipline were rechecked at U
`624bd5c3bf5bd5b8df625cc111c94531dff19148`. N hub-spoke design fundamentals/
Azure examples (lines 9-38), vnet-architect workload discovery and migration
planner inventory (lines 98-103) were rechecked at N
`4104279fa4707c24e6038b35b2779fecfdd11eea`. These are existing topology/
inventory foundations; licensing and project-owner-reported permission remain.

Classification: COMPOSE N discovery/topology guidance, ADAPT U scope/evidence/
requirements discipline, NEW first-pass target-runtime contract/integration.
List visible subscription metadata and collect narrowly selected component
references, not full rules/effective behavior/records. Names are INFERRED role
hints, not customer-approved roles or scope proof. Peering/hub connections
provide signs of hub/spoke/vWAN, not complete tenant architecture or traffic.
External references/denied reads remain gaps; identity visibility is not RBAC
certification. Supplemental input is source-labelled and never fabricated.

Private-preferred is a DECLARED owner-requested assessment baseline, not
observed desired state or permission to disable public access. Exceptions
need service identity, reason, owner and control evidence; absent endpoints/
DNS alone do not prove exposure. Microsoft Learn NSP documentation inspected
2026-10-11 lists Log Analytics workspaces (Microsoft.OperationalInsights/
workspaces) and states Azure Monitor workspace collection/querying is not
supported by that integration. Azure Monitor workspaces (Microsoft.Monitor/
accounts) have their own Private Link guidance. Do not copy the suggested
NSP exception as a universal Azure Monitor workspace exemption.
Sources: azure-monitor/fundamentals/network-security-perimeter and
private-link-azure-monitor-workspace.

Azure SRE Agent permissions documentation confirms managed identity access
and temporary OBO use of a qualifying administrator's existing permissions,
not access grants; personal Microsoft accounts cannot authorize OBO. Required
platform consent cannot be bypassed. No proven CLI OBO endpoint is assumed.

First-pass implementation is in installed `first_pass.py` and companion
`tools/network_health_first_pass.py`, composing the existing strict native
transport/audit. 279 Windows/Linux cases passed. Two actual native reads found
one visible subscription/89 selected components; rows matched an independent
scoped ARG query. Completed replay added no reads or changed bytes. Operator
CLI collection was separately exercised and labelled operator-not-SRE.
OBO token exchange and Contoso permissions remain unvalidated. The private
baseline is DECLARED in assessment/views, never observed exposure.

### Increment 0 implementation boundary

The runtime feasibility spike uses `plugins/azure-network-health/` and one skill,
`azure-network-health-assessment`. It performs only an explicitly selected
subscription-context read, not network inventory or assessment.

| Source-map entry | Downstream asset | Increment 0 decision |
|---|---|---|
| C01, C02 | `skills/azure-network-health-assessment/SKILL.md`, plugin notices | ADAPT the attributed evidence/persistence discipline from Usman; no substantial source template is copied in this spike. |
| C03, C04 | Primary skill and `runtime.py` | NEW target-runtime integration; the sole read is subscription context. Network Desk inventory/snapshot procedures remain foundations for Increment 1, not newly claimed concepts. |
| C06-C08 | `feasibility.schema.json`, `runtime.py` | NEW minimal proof contract with explicit outcome, redacted identifier and no full resource payload. Not the Observed Network Model schema. |
| C23 | `plugin.json`, both marketplace manifests, installed supporting files | ADAPT existing primary repository Marketplace conventions; verify actual file delivery rather than infer it from manifest validation. |
| C25, C26 | Runtime-created `runs/<run-id>/runtime-feasibility.json` | NEW artifact generation/retrieval proof. No rich rendering or external publication. |

The inspected upstream revisions and permission record remain unchanged. Exact
runtime results are recorded in
[runtime-validation.md](../plugins/azure-network-health/runtime-validation.md):
actual Marketplace installation at commit
`<implementation-commit>`, installed-file integrity, native
terminal execution, a structured scoped-read execution record, and independently
downloaded/schema-validated artifact bytes. No custom agent,
scheduled task, connector, or knowledge-base extra is packaged in Increment 0.

The approved subsequent run bundle separates `observed-network.json` from
`assessment.json`; Markdown reports are deterministic views of assessment JSON.
Acquisition/normalization must not infer packet flow. Checks and findings carry
`checkId` and `checkVersion`, with severity separate from priority.

| Gate | Affected entries | Required resolution |
|---|---|---|
| Usman distribution-review evidence | C01, C02, C05, C06, C14, C19-C21, C28 | Development may proceed under confirmed project-owner-reported permission. Preserve original correspondence/written confirmation or a future applicable license for formal distribution review; do not represent permission as MIT licensing. |
| Observation contract design | C05-C08, C21 | Increment 1 implements version 0.1.0 observation/assessment schemas, explicit configuration relationships, provenance and partiality. Validate installed-runtime behavior before expanding the contract. |
| Acquisition/tool validation | C03, C04, C09-C18 | Validate commands/APIs, paging, least-privilege reads, accessible sources and real partial/failure cases using Azure tooling. Agreement between AI agents is not validation. |
| SRE Agent and Marketplace compatibility | C22-C25, C27 | Validate actual schemas, tools, reference loading, handoffs, dependencies and persistence with Azure SRE Agent; do not assume CLI compatibility. |
| Optional inputs and scope | C15, C16, C19, C20 | Establish accessible firewall/hybrid dependencies and provided documents/IaC. Mark uncollected evidence UNKNOWN; no production access is implied. |
| Report delivery | C25, C26, C28 | Select approved customer storage/access, redaction, retention, versioning and persistence/publication verification. No external publication destination is authorized here. |
| Scheduling | C24 | Defer until interactive assessment and failure/coverage reporting are repeatably validated; then adapt the existing task convention. |

### Classification summary

| Classification | Records |
|---|---:|
| REUSE | 0 |
| ADAPT | 12 |
| COMPOSE | 9 |
| NEW | 7 |
| NOT_NEEDED | 6 |
| REFERENCE_PENDING_PERMISSION | 0 |
| **Total** | **34** |

Before implementation or distribution, update this register with actual
downstream paths, source portions copied/adapted, preserved notices, permission
evidence, validation outcomes and remaining gaps. Keep customer configuration and
sensitive evidence out of reusable source assets. Mature components should retain
this lineage for Marketplace, Contoso/customer deployment and potential official
ecosystem contribution review.

## WARA assessment plugin lineage (separate from the network-health register)

**Decision date:** 2026-10-09. These records are scoped to `plugins/wara-assessment` and are not
included in the network-health classification summary above.

| Capability | Classification | Upstream and inspected revision | Licence | Downstream asset | Rationale |
|---|---|---|---|---|---|
| WARA collector and analyzer | COMPOSE | [Azure/Well-Architected-Reliability-Assessment](https://github.com/Azure/Well-Architected-Reliability-Assessment) `86832273f857b7298b625b26d18e2e0dbb06714c` (v1.0.6, last commit 2025-06-12) | MIT, (c) 2024 Microsoft Azure | `skills/wara-assessment/scripts/Invoke-WaraRun.ps1` invokes `Start-WARACollector` / `Start-WARAAnalyzer` unmodified; downloaded at run time, not redistributed | Standard Microsoft assessment output is preserved; only orchestration, scoping and provenance are added. |
| WARA in-scope resource-type snapshot | COMPOSE | Same revision, `src/tests/data/wara/test_recommendationresourcetypesdata.csv` | MIT | Read at run time by `build_recommendation_data.py` | Restricted-egress substitute for the published `WARAinScopeResTypes.csv`. |
| APRL recommendations and KQL | COMPOSE | [Azure/Azure-Proactive-Resiliency-Library-v2](https://github.com/Azure/Azure-Proactive-Resiliency-Library-v2) `69d73cbdc2729f5e94ab1184304ef4b9a5119ba2` (overridable with `-AprlRef`) | MIT, (c) Microsoft Corporation | `build_recommendation_data.py` builds WARA's `recommendations.json` at run time | Restricted-egress substitute for `azure.github.io/WARA-Build`; APRL is actively maintained. |
| `Search-AzGraph` subset | NEW | Independent implementation over the public Resource Graph REST API (2022-10-01); no Azure PowerShell source used | Repository MIT | `scripts/shims/Az.ResourceGraph/` | PowerShell Gallery is not reachable from the SRE Agent sandbox; loaded only when the real module is absent and recorded in `run.json`. |
| Normalized findings, prioritization, delta, report | NEW | n/a | Repository MIT | `normalize_findings.py`, `prioritize.py`, `config/prioritization.yaml` | Customer-specific prioritization and month-over-month tracking independent of WARA's Excel format. |
| Az.Accounts, ImportExcel | COMPOSE | Az.Accounts 3.0.4 (nuget.org or Gallery); ImportExcel `5387c061461c811d106b125588f064c4739342cb` | Azure PowerShell licence; Apache-2.0 | Downloaded at run time | Runtime dependencies of WARA. |

Upstream maintenance risk: WARA had no commits between 2025-06-12 and the decision date; APRL was
updated 2026-10-05. The derived layer reads only the collector JSON so the collector can be replaced
without changing the findings contract.

### WARA 0.2.0 reporting lineage

Inspected 2026-10-09 at WARA revision `86832273f857b7298b625b26d18e2e0dbb06714c`.
The read-only upstream checkout and its root LICENSE confirm MIT,
Copyright (c) 2024 Microsoft Azure.

| Capability | Classification | Exact upstream portions | Downstream decision |
|---|---|---|---|
| Cross-platform PowerPoint, findings workbook and CSV | ADAPT | `src/modules/wara/reports/3_wara_reports_generator.ps1`: Build-PPTSlide12/16/17/23/24/25/28/29/30, Initialize/Export-ExcelRecommendations, impacted-resource exports and Build-SummaryActionPlan; `reports.psm1` Start-WARAReport entry point | `generate_reports.py` independently ports the aggregation and shape-filling procedures. Native charts/static summaries replace COM pivots; no claim of pixel-identical or Office-validated output. |
| PowerPoint and workbook templates | ADAPT | `src/modules/wara/reports/Mandatory - Executive Summary presentation - Template.pptx`, `Assessment-Findings-Report-v1.xlsx` | Read pinned cached templates, fill and distribute resulting reports with the upstream MIT notice included as a companion. |
| Environment evidence and requirement overlay, Word narrative | NEW | No corresponding WARA classifier or executable Word generation was identified in the inspected reporting script | Separate advisory overlay and DOCX; not upstream WARA output or proof of desired state. Tags/offers are signals, not automatic risk acceptance. |

Retain WARA attribution and the MIT permission notice for adapted template outputs.
Raw arbitrary tags are unnecessary for classification and must not be persisted by default.
Resource identity, evidence scope and collection time remain explicit. Report generation
must preserve the deterministic source artifacts, UNKNOWN validation actions and accepted risks.

## Pinned upstream links

[U1]: https://github.com/lavoizer-develop/azure-networking-agent-test-repo/blob/624bd5c3bf5bd5b8df625cc111c94531dff19148/.github/agents/azure-networking.agent.md
[U2]: https://github.com/lavoizer-develop/azure-networking-agent-test-repo/blob/624bd5c3bf5bd5b8df625cc111c94531dff19148/.github/skills/azure-networking/SKILL.md
[U3]: https://github.com/lavoizer-develop/azure-networking-agent-test-repo/blob/624bd5c3bf5bd5b8df625cc111c94531dff19148/.github/skills/assessment-reporting/SKILL.md
[U4]: https://github.com/lavoizer-develop/azure-networking-agent-test-repo/blob/624bd5c3bf5bd5b8df625cc111c94531dff19148/README.md
[U5]: https://github.com/lavoizer-develop/azure-networking-agent-test-repo/blob/624bd5c3bf5bd5b8df625cc111c94531dff19148/docs/network-requirements.md
[U6]: https://github.com/lavoizer-develop/azure-networking-agent-test-repo/blob/624bd5c3bf5bd5b8df625cc111c94531dff19148/docs/current-architecture.md
[N1]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/vnet-architect/skills/migration-planner/SKILL.md
[N2]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-automation/skills/rollback/SKILL.md
[N3]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-automation/skills/drift-detection/SKILL.md
[N4]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/vnet-architect/agents/vnet-architect.md
[N5]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/vnet-architect/skills/hub-spoke-design/SKILL.md
[N6]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/vnet-architect/skills/peering-advisor/SKILL.md
[N7]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-troubleshooter/skills/routing-debug/SKILL.md
[N8]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/dns-specialist/agents/dns-specialist.md
[N9]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/dns-specialist/skills/resolver-design/SKILL.md
[N10]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/dns-specialist/skills/record-audit/SKILL.md
[N11]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/private-link/agents/private-link.md
[N12]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/private-link/skills/dns-integration/SKILL.md
[N13]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/private-link/skills/troubleshoot/SKILL.md
[N14]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-security/skills/nsg-audit/SKILL.md
[N15]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/firewall-engineer/skills/rule-audit/SKILL.md
[N16]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/firewall-engineer/skills/troubleshoot/SKILL.md
[N17]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/hybrid-connectivity/agents/hybrid-connectivity.md
[N18]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/hybrid-connectivity/skills/troubleshoot/SKILL.md
[N19]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-troubleshooter/agents/network-troubleshooter.md
[N20]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-troubleshooter/skills/connectivity-test/SKILL.md
[N21]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-monitor/agents/network-monitor.md
[N22]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-monitor/skills/traffic-analytics/SKILL.md
[N23]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-monitor/skills/baseline-analysis/SKILL.md
[N24]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/report-builder/agents/report-builder.md
[N25]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/report-builder/skills/report-structure/SKILL.md
[N26]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/vnet-architect/skills/network-diagram/SKILL.md
[N27]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/LICENSE
[N28]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/README.md
[N29]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/package.json
[N30]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/.github/copilot-instructions.md
[N31]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/PRIVACY.md
[N32]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/registry.mjs
[N33]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/extension.mjs
[N34]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/scripts/build-plugin.mjs
[N35]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/plugins/network-desk/agents/network-desk.md
[N36]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/plugins/network-desk/.github/plugin/plugin.json
[N37]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/renderers/_common.py
[N38]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/renderers/make_html.py
[NX1]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-monitor/skills/flow-log-setup/SKILL.md
[NX2]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/specialists/network-monitor/skills/connection-monitor/SKILL.md
[NX3]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/renderers/make_pdf.py
[NX4]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/renderers/make_docx.py
[NX5]: https://github.com/dmauser/network-desk/blob/4104279fa4707c24e6038b35b2779fecfdd11eea/extensions/network-desk/renderers/make_xlsx.py
