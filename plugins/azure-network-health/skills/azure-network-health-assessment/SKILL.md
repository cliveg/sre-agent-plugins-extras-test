---
name: azure-network-health-assessment
description: |
  Assess Azure networks with the reference-led comprehensive workflow: topology/peering, configured routing, contextual NSG rule/ingress review, Private Endpoint/DNS, existing telemetry/recorded context and firewall/hybrid configuration. Adapt Usman Mahmood's evidence/reporting workflow and Network Desk specialist procedures. Also supports the legacy first-pass/full inspection. Preserve evidence gaps; no resource/logging changes, active tests or invented health/enforcement.
tools:
  - RunAzCliReadCommands
  - GetAzCliHelp
  - RunInTerminal
  - ReadFile
  - SaveFileToBlob
---

# Azure Network Health Assessment

Version `0.13.0` is restricted configuration triage, not a full health assessment.
Package 0.21.2 builds the separate reference-led assessment/bundle 1.0.1 below
and still verifies published 1.0.0 reviews. It composes that core rather than
changing old check/report contracts.
Use one explicitly selected workload subscription and, only for DNS planning,
separately approved DNS-hosting subscriptions. No Azure resource changes,
remediation, diagnostics/log/monitor enablement, deployments, IaC generation,
implicit external publication, sandbox login or package installation. The
reference-led branch permits only explicitly approved private publication and
existing managed-identity authentication; dependency restoration requires its
own approval and is never automatic.

For the technical unrestricted Internet-source criterion over retained
configuration capsules, use the sibling `azure-network-evidence-capture` skill's
offline public-source restriction workflow. Its separate companion JSON is not
input to this legacy runtime; keep local settings, overall qualification and
unavailable evidence distinct.

## Reference-led comprehensive assessment

For a comprehensive or broader networking report, start here rather than using
the legacy development-host bridge. Read
[the adapted assessment method](reference-assessment.md) before interpreting
results. It specifies the actual Usman/Network Desk procedures, report fields,
context gates and excluded operations.

1. Confirm one workload subscription, tenant and existing managed-identity client
   ID; explicitly allow the DNS-host scope. The current collector uses that
   same subscription only. External references remain references.
2. Locate both installed skills' actual supporting directories. The capture
   skill supplies `reference_capture.py`, `reference_arm.py`,
   `reference_profile.py`, `reference_reviews.py`, `network_reference.py` and
   existing integrity/identity/bundle/publisher helpers. Python 3.10+,
   jsonschema, JMESPath 1.1.0, PowerShell 7.2+, existing Az.Accounts and Git for
   publication run inside SRE Agent. The user needs no host tools. Stop and
   report missing prerequisites; do not bootstrap them.
3. Collect selected configuration using the installed collector:

```bash
python3 -B <capture-skill-dir>/scripts/reference_capture.py capture \
  --tenant-id <tenant> --subscription-id <workload-subscription> \
  --managed-identity-client-id <existing-client> --capture-id <new-source-uuid> \
  --output-root <existing-private-directory>
```

Use the same source/scope with `--resume` after a reported read-budget pause.
Unconfirmed outcomes require explicit `--retry-unconfirmed` approval; finished
sources resume without reauthentication/recollection. Preserve partial/denied
outcomes, not empty-success substitutions.

4. When requested, reuse the capture skill's existing PaaS configuration/
   public-source review and history/timeline workflows. Refresh history only
   for the approved sources/window/destination; retain overlaps, parent bindings
   and all time meanings. No cross-tenant fallback or new telemetry collection.
5. Build and verify the broader report, optionally composing those verified
   private artifacts unchanged:

```bash
python3 -B <capture-skill-dir>/scripts/network_reference.py build \
  --network-source <verified-reference-source> --run-id <new-review-uuid> \
  --output-root <existing-private-directory> \
  --restriction <verified-public-source-review> --timeline <verified-timeline>
python3 -B <capture-skill-dir>/scripts/network_reference.py verify \
  --review <actual-created-review-directory>
```

Omit optional inputs only when absent; their unassessed/freshness gaps remain
explicit. Completion requires exit 0 and `verified-reference-network-review`.
Both Markdown files derive from assessment JSON, original sources remain
embedded, and the profile is separate from the legacy model/assessment schemas.

6. After destination/privacy/publication approval, use the existing installed
   publisher with `--review` and a new receipt outside the immutable run.
   Unique `network-review/<id>` branches write `network-health/runs/<id>/`;
   verify remote committed bytes and preserve main/WARA work.
7. Return scope/source windows, per-area assessment coverage, contextual findings,
   positives and next evidence/actions, plus verified private report links.
   Zero findings is not Healthy. Configuration, coarse connection state,
   recorded context and public-IP references are not traffic, effective-rule,
   private-only, customer-compliance or causation certification. Write only the
   selected artifacts; memory maintenance and schedules are outside this workflow.

## First-pass test workflow (before full inspection)

When asked for a first pass, do not launch all detailed checks. The user request
authorizes listing subscriptions visible to the executing identity in the
specified tenant and bounded selected component reads (maximum 100 subscriptions,
100 pages each); no repetitive conversational approvals. The existing companion
`tools/network_health_first_pass.py` runs exact native reads in a fresh
collection-only thread, using the same strict audit/accepted-request recovery.
Run with `--endpoint`, `--thread-id`, `--tenant-id`, `--run-id`, `--output-root`.
Use `--resume` on the same saved scope/thread; never blindly repost unknown
acceptance or silently change identities. Required platform OBO consent cannot
be bypassed.

Subscription names are INFERRED role hints only. VNet peering, vWAN/virtual hubs,
firewalls/gateways, DNS, endpoints, NSGs, routes, Monitor/Log Analytics, AMPLS
and NSP are selected component inventory, not public reachability, effective
behavior, complete architecture or customer-approved roles. Retain external
references without following them; one observed spoke need not expose its
central hub/DNS subscriptions. Accessible subscription listing is not the
managed identity's RBAC scope or complete tenant inventory.

First-pass artifacts live under `first-pass/<run>/`: `selected-input.json`,
`scope-summary.json`, `scope-summary.md`, separate from detailed assessment
`runs/`. In a separate processing thread, verify the actual selected-input hash
then run installed `first_pass.py --input <actual-file> --output-root <fresh-root>`.
Do not model-rewrite the inventory or invent a denied/empty result. Save the
actual summary files and verify downloads before claiming persistent delivery.
This phase stops at initial observations and scope/access gaps, not full checks.

If a read is denied, explain source identity/time/scope and request only the
runtime-supported OBO route. OBO temporarily uses an eligible administrator's
existing permissions, not a grant. Work/school Entra accounts and platform
consent may be required; do not promise OBO support from this CLI or grant roles.
Do not put tokens in the sandbox. Perform platform consent outside controlled
collection and use a fresh collection thread afterwards.

If unavailable, provide the exact `supplementalCommand` and metadata contract
from the summary. The operator can use the same collector with
`--operator-cli-python <existing-Azure-CLI-python>` in their signed-in environment
to create original selected evidence labelled operator-not-SRE. Single complete
page supplements can be processed by installed `first_pass.py --input <original>
--supplement <actual-supplement-json> --output-root <new-root>`; keep original
failed attempts. No arbitrary new scope or raw secret-containing responses.

For "full inspection", use a fresh detailed collection run/thread per selected
workload subscription, with explicit DNS-host IDs. Reuse the normal bridge/
checks/intent/report workflow below. The user's trigger authorizes those
read-only scopes without redundant approval; do not automatically infer every
subscription role or extend to references. Do not advertise complete network
health: effective traffic, telemetry and specialist domains remain limited.

## Private-preferred access baseline

For explicitly requested NSP configuration evidence, use the existing host
bridge with `--include-nsp`. It includes existing service-ARM/DNS prerequisites
and adds four scoped ARM lists using API 2024-07-01: perimeters, profiles,
resource associations and access-rule metadata. Acquisition 1.8.0/input-schema
0.9.0/check catalog 1.12.0 execute 30 operations and 16 checks without optional
intent/time (up to 18). Reuse validated pagination/resume and actual collected
parents; `$top` in continuation is bounded to 1-20. Never follow external
target/profile references or use the DNS-host allowlist to inspect their NSPs.

`nspConfigurationReview` in assessment and both reports records raw configured
modes, provisioning/issue flags, actual target/profile references, collection
coverage, rule direction and selector counts. Never retain IP/FQDN/subscription/
service-tag/email/phone selector values, infer zeros from missing arrays or
assume a retained rule count is complete without its recorded coverage.
Enforced configuration is not effective enforcement or service synchronization.
Learning/Transition, Audit, unknown modes, provisioning issues and partial
profile/rule evidence remain distinct, not automatic defects or mode changes.
SecuredByPerimeter without a collected association is a scope/evidence gap,
not proof of missing configuration. No association or zero accessible NSPs
establishes global absence. No public-access exception is accepted automatically.
AMPLS, rule-value semantics, actual client traffic and customer approval remain
unassessed; do not call generic Monitor/Monitor workspace integration verified.

For explicitly requested integrated direct ARM evidence, use the existing host
bridge with `--include-service-arm`. This includes the existing service-access/
DNS-path prerequisites and adds three bounded, same-workload management GET
operations over actual indexed Storage/Key Vault/ACR parents: 26 operations,
acquisition 1.7.0, input/schema 0.8.0, check catalog 1.11.0, 15 checks without
optional intent/time (up to 17 with both). Each family is limited to 100 parents;
failed, invalid or unattempted reads remain explicit, and accepted-read recovery
does not repost. Do not follow extra DNS-host or external service references.

Direct observations are separate configuration objects, never merged into or
used to overwrite indexed service properties. `serviceControlReconciliation`
records both values per selected field, source/collection/evidence references,
actual API version and each direct parent read's completion/outcome/error.
Only two non-null equal values are observed-match. Missing/unsupported fields
and failed reads never become matching zero, absent controls or proven endpoints.
Differences may reflect time, index freshness, API shape or changes, not defects
or desired-state instructions. Retain both original source observations and
review the source matrix alongside the indexed-only `serviceAccessReview`.
No source agreement, Disabled setting, perimeter mode or PE approval certifies
private-only access, enforcement, reachability, health or accepted exceptions.

For explicitly requested service access-control evidence, run the existing host
bridge with `--include-service-access` in a fresh controlled full-inspection
thread. This includes DNS-path/private-connectivity/planning prerequisites:
23 operations, acquisition 1.6.0, input/schema 0.7.0, 14 checks without optional
intent/time (up to 16 with both), check catalog 1.10.0. Only the service-inventory
query changes; older modes keep their original query/properties/check set.
Processing the resulting actual attachment needs no acquisition flag.

The installed helper produces `serviceAccessReview` in assessment JSON and
deterministic executive/engineering views. Storage Accounts, Key Vault vaults
and Container Registries retain publicNetworkAccess, service-specific firewall
default action, trusted-service bypass and rule counts, never rule values or
credentials. Other inventoried families remain explicitly unassessed.
Missing/unknown settings do not inherit defaults. Approved scoped PE group IDs
are configuration only, not complete required-subresource coverage or client use.
Enabled/Allow and Enabled/Deny request contextual owner/exception review, not
an automatic defect, exposure claim or resource change. Disabled is not a
private-only certificate: trusted-service bypass can still matter. Perimeter
mode is not verified NSP association/profile/rules/enforcement and is never an
automatically accepted exception. AMPLS enforcement and service authorization,
DNS resolution, reachability and traffic remain unassessed.

Default assessment preference is DECLARED: private access preferred and public
access only by documented service-specific exception. This is not observed
desired state or permission to modify resources. Record exceptions by actual
service resource ID, reason, owner, approved scope and alternative-control
evidence; no exceptions are automatically accepted or invented.
Endpoint/DNS presence alone does not prove public access disabled, and absent
endpoint/zone evidence alone does not prove exposure or noncompliance.

Distinguish Azure Monitor workspace (`Microsoft.Monitor/accounts`) from
Log Analytics (`Microsoft.OperationalInsights/workspaces`). Microsoft Learn's
Azure Monitor NSP integration lists Log Analytics support and states Monitor
workspace collection/querying isn't supported by that integration. Monitor
workspaces have Private Link guidance. An NSP resource is not enforcement
proof: service support, association, mode/profile/rules and workload path need
verification before accepting a public-access exception. Do not substitute NSP
for AMPLS or apply a universal "Monitor workspace exception".

## Detailed assessment acceptance gates

For a customer assessment, compose the procedures below; do not skip straight
from tool responses to an unverified completion claim.

1. Confirm the actual selected endpoint/workload/DNS-host scope, opt-in mode,
   run, evidence sensitivity/retention and optional actual customer intent/
   explicit UTC reference. Do not invent customer inputs or expand scope.
2. Require independently verified installation pin/asset hashes and native
   read/file/terminal/save prerequisites. Canonical Git bytes, not Windows
   worktree line endings, are the hash comparison source.
3. Keep acquisition in a fresh collection-only thread, controlled by the host
   bridge. The bridge owns paging/checkpoints/audit/accepted-read reconciliation.
   If absent, state the prerequisite; never rewrite selected rows yourself.
4. Preserve denied/partial/uncollected evidence. Resume with the same bound
   state; ambiguous upload acceptance requires an actual receipt verified by
   download, not an inferred success or blind repeat.
5. Process only verified selected input in a separate thread, using installed
   helper and fresh output root/actual `--bundle-result`. Exactly four canonical
   reports; observed facts remain separate from declared intent/interpretation.
6. Confirm versions/check/count/priority/evidence-link/age/reference consistency.
   A partial assessment may deliver correctly but is not complete/healthy.
7. Publish originals with plan/begin/actual native-save/record. Receipted files
   are skipped; ambiguous saves retry only identical verified immutable copies.
8. Stop at saved-not-download-verified until the authenticated host downloads
   and validates exact outputs. Check actual proof bytes/hash/bindings against
   the ledger before external-delivery closure; do not claim native read-back.
9. Keep report/intent/reference/original/intermediate bytes unchanged. Explain
   remaining scope/permission/behavior/ownership gaps and whether evaluation
   was synthetic or live. Never promote delivery integrity to customer health
   acceptance or automatically authorize another collection/deployment.

On failure, name the blocked gate and available durable state/explicit recovery
option. Do not clear locks, discard failed operations, rerun canonical bundles
or respond as though the assessment succeeded.

## Selected collection scope

Only subscription and required resource-group/region context, VNets/address
spaces/subnets/peerings, configured route tables/routes/subnet associations,
NSGs/rules/subnet associations and minimal NIC/IP attachment references.
With explicit user approval, the bridge's `--include-private-connectivity`
mode adds selected Private Endpoints, automatic/manual connection state,
private DNS zones/VNet links and parent-scoped zone-group lists. Without that
flag the nine-operation default remains unchanged. DNS records/client resolution/
forwarding, target-service public access, effective connectivity, firewall/
gateways, VPN/ExpressRoute/vWAN, NAT, application delivery, telemetry, IaC and
architecture documents remain deferred.

User-approved `--include-dns-planning` includes private-connectivity collection
and adds selected service resource metadata from the versioned commercial-cloud
mapping in `private-dns-services.json`. The helper derives the exact service
query; this is not permission for ad-hoc service reads. Explicit repeated
`--dns-hosting-subscription-id <UUID>` flags collect only zones/VNet links in
those additional scopes. Do not enumerate subscriptions, auto-follow references
or collect their workloads/endpoints. Workload scope and DNS scope remain
separate; no allowlist means central hosting is UNKNOWN. Resume restores both
scopes/modes; mismatches fail. Up to twenty explicit DNS-hosting subscriptions
are supported; each operation remains bounded and independently records failures.

Only with explicit approval, `--include-repeated-zone-metadata` includes DNS
planning and adds record-set metadata for collected repeated-name zones in
the approved workload/DNS-hosting scopes. The exact parent-derived CLI
projection returns only record-set type and TTL, plus a total count. The helper
retains aggregate per-type counts, selected/reported set counts, min/max TTL
and unavailable-type/TTL counts; it never retains record-set names/IDs, IP/
alias/TXT/MX/SRV/SOA contents or full responses. Selected record sets are capped
at 2,000 per zone, with explicit truncation gaps, and parent reads at 100 per
operation/scope. Do not replace the projection with full record reads or active
DNS tests. Record values remain deferred; metadata is not DNS resolution.

## Acquire without inventing or rewriting evidence

Read installed `acquisition.json`. Its operations and query projections are the
only permitted acquisition catalog. Always provide `--subscriptions <UUID>` for
Graph reads; preserve pagination tokens until exhausted, bounded by the catalog.
Private zone groups are not indexed in Resource Graph: their exact allowlisted
CLI list commands are derived only from collected in-scope endpoint parents.
Successful empty parent lists differ from unavailable/failed/unattempted lists.
The bridge owns that bounded parent iteration and checkpoints; do not generate
additional child/service/public-access/DNS-record queries yourself.
Never substitute unscoped subscription discovery, `az account set`, broad
`Resources` queries, full resource properties or shell pipelines.

The current sandbox cannot directly run `az graph query`, and the native Azure
read tool's text output is not a supported lossless Python input file.
Do not install the extension, copy credentials, paste/model-rewrite rows or claim
standalone collection is available.

For this prototype, a developer runs `tools/network_health_sre.py` outside the
sandbox. It drives exact native Azure read commands, captures actual structured
`azCliExecution.output`, applies paging/redaction, and uploads the selected
collection envelope through the conversation attachment API. The bridge records
native execution IDs and a SHA-256 of the exact input bytes.

The host bridge checkpoints selected pages and can resume the same scoped run.
It owns request reconciliation and continuation; an interrupted or resumed
bridge is not permission for the agent to repeat commands, restart collection
or retry terminal failures. Wait for the developer's next exact command/input.

When that adapter is not running and no approved input is attached, state this
prerequisite explicitly. Do not generate empty findings as a fallback. Requests
from the controlled transport to execute one exact native read must execute only
that command and stop; the adapter owns pagination and aggregation.

## Normalize, assess, render

Use a separate processing thread, never the bridge's collection-only thread.
If canonical outputs already exist, skip acquisition/processing and use the
verified-original recovery procedure below. Do not rerun the helper to overwrite
or recreate an existing bundle.

1. Read installed supporting files: `reference.md`, `network_health.py`,
   `runtime.py`, `acquisition.json`, `checks.json`, `common.schema.json`,
   `observed-network.schema.json`, `assessment.schema.json`.
   For planning input, also read `private-dns-services.json`; preserve its
   Microsoft attribution, version/hash/revision and commercial-only boundary.
2. Locate the actual uploaded `collection-input-<run-id>.json`. Confirm its
   SHA-256 against the developer-provided hash. It contains allowlisted selected
   configuration, not full raw responses. Do not modify it.
3. Run the installed helper unchanged using native `RunInTerminal`:
   `python3 <installed-network_health.py> --input <uploaded-file> --output-root <permitted-thread-directory> --bundle-result <fresh-private-helper-result.json>`.
   No Azure command is executed in input mode. Do not rewrite the helper, schemas
   or check logic. Missing files/dependencies or validation failures must be
   reported explicitly.
4. The helper creates exactly four canonical files under `runs/<run-id>/`:
   - `observed-network.json`: factual normalized evidence only.
   - `assessment.json`: six versioned checks, contextual findings and priorities.
   - `network-assessment.md`: deterministic executive view of assessment JSON.
   - `network-evidence.md`: deterministic engineering view of assessment JSON.
   Files are written and verified in a sibling `.<run-id>.pending` directory
   before the complete directory is published. Write/hash/publication errors
   are explicit; ordinary failures clean up staging so the same unchanged input
   can be retried without Azure recollection. Existing final or pending runs
   are never overwritten. After abrupt process termination, a pending directory
   may remain: stop and report it rather than deleting it, resuming implicitly
   or claiming a completed bundle.
5. Preserve the helper's original result manifest and use the verified
   publication plan below. Save only the helper-verified immutable copies, then
   durably record each actual returned key. This is delivery of requested reports,
   not backup/archive. The authenticated route is
   `/api/files/<thread-id>/<key>`; do not invent keys or download success.
6. Summarize the generated priorities and limitations only. Do not add AI findings
   to the deterministic records or Markdown. Recommended deep dives are not
   executed. Subsequent retrieval must use existing files, not regeneration.

## Recover and complete report saves

The installed helper owns integrity/state; do not rewrite its logic or assemble
state from report prose. Use the original output root/run and the actual current
processing thread UUID. Publication options execute no Azure calls or assessment.

1. Run:
   `python3 <installed-network_health.py> --output-root <original-root> --run-id <UUID> --report-thread-id <current-thread-UUID> --report-save-action plan --bundle-manifest <original-helper-result.json>`.
   After initialization, the durable plan can be reopened without supplying the
   manifest. It verifies all four original hashes/contracts/links, creates
   run-and-full-hash-specific immutable copies and returns exact publication
   paths, remaining files and ledger path. The ledger is a private companion
   under `report-publication/<run-id>/`, not a fifth canonical report.
2. For each remaining canonical artifact, run the same bound options with
   `--report-save-action begin --artifact <canonical-filename>`. This verifies
   originals/copies and records `saveStarted` before the native save.
3. Call `SaveFileToBlob` on that artifact's exact returned immutable copy path.
   Then immediately run:
   `python3 <installed-network_health.py> --output-root <original-root> --run-id <UUID> --report-thread-id <current-thread-UUID> --report-save-action record --artifact <canonical-filename> --blob-key <actual-returned-key>`.
   Record only the actual tool response, not a guessed URL or inferred key.
4. After an interruption, reopen the plan. Receipted files are skipped; remaining
   `pending`/`saveStarted` entries may retry only the same verified immutable
   copy. Native overwrite-by-name permits identical-content retry without
   clobbering another run, but no exactly-once/platform-idempotency guarantee is
   claimed. A corrupted copy, changed identity or differing stored receipt stops
   recovery. Never auto-clear stale publication locks.
5. Report `partial-report-save` until all four keys are recorded; even then the
   state is `saved-not-download-verified`. The native tool has no supported
   read-back/checksum tool. Return real keys/hashes and save the exact
   helper-returned `ledgerExportPath` with `SaveFileToBlob` as the immutable
   delivery manifest, not a generic `state.json` basename. Its actual key allows
   authenticated independent download verification through the development
   bridge's `--verify-report-saves` mode. Do not claim retrieval from local hashes
   or a printed link.

Missing originals/manifests, expired/inaccessible blobs, sandbox loss or write/
save/verification errors are explicit limitations—not permission to recollect
Azure, regenerate reports, install dependencies or reconstruct evidence. Actual
download verification produces a separate proof; it does not change findings
or turn a limited assessment into operational-health certification.

## Evidence and interpretation

Acquisition/normalization do not infer traffic paths. `hasConfiguredNextHop`
is not effective forwarding or observed traffic. Missing association fields are
UNKNOWN, not proof of absent controls. Public reachability cannot be inferred from
NSG rules alone. Route-table or NSG absence/presence is not automatically a defect
or healthy outcome. Guidance is not a customer requirement.

Severity is potential impact; priority is next-action ordering. No universal
health score or connectivity certification is produced. Permission-wide
completeness, index freshness and operational behavior remain unverified.

NET-ADDR-001 `1.1.0` uses retained peering configuration to prioritize overlap
applicability evidence (P1), not declare a peering defect/outage. Generic overlap
stays P2/context validation. Peering mode/subnet-selection/IPv6-only settings are
not collected; preserve that gap. The one aggregated disjoint-address positive,
when generated, is INFERRED/INFO and limited to valid accessible collected
ranges, not overall health or complete subscription visibility. Summarize those
generated distinctions without elevating severity or executing deep dives.

NET-PEER-001 `1.1.0` evaluates retained reciprocal directions once. Connected/
Succeeded on both unique directions is OBSERVED configuration information,
not demonstrated traffic or permitted access. Initiated/transitions require
context, not assumed defect severity. Unobserved reverse direction, unknown/
future states, ambiguous/partial data and external/reference-only endpoints
remain evidence gaps; do not infer absence or expand subscriptions. Summarize
the helper's actual directional findings and recommend only bounded, authorized
direct/effective validation. The check catalog is `1.2.0`; priority policy
remains `1.1.0`.

Opt-in private mode executes NET-PRIVATE-001/NET-PRIVATE-DNS-001 `1.0.0`,
check catalog `1.3.0` and contract `0.2.0`. Default historical scope keeps
six checks/catalog `1.2.0`/contract `0.1.0`. Approval and configured zone/link
chains are OBSERVED configuration information, not private-only exposure,
DNS resolution or traffic proof. Missing zone groups with a successful empty
parent list require custom/manual/shared DNS intent, not automatic remediation.
Uncollected/rejected child rows, reference-only external zones, unavailable
links, records/resolver/client evidence and service public access remain UNKNOWN.
Do not expand subscriptions or elevate gaps into defects.

DNS planning mode uses contract `0.3.0`, acquisition `1.2.0`, check catalog
`1.4.0` and ten checks. NET-DNS-PLAN-001 compares the declared Microsoft
service/subresource/zone values with observed service IDs, actual matching
target/subresource connections and separately observed zone IDs. Include
services without observed connections for future planning, not as defects.
No observed connection is workload-scope-only; endpoints may be in other
subscriptions. A missing observed zone never establishes *why* an endpoint was
not deployed. SKU/API/features, customer private-access intent, custom DNS,
central hosting and consumer scope need validation. Catalog rows with no
observed resource remain future planning choices, not unused-service proof.
Regional/configuration-dependent zone templates remain candidates requiring
context. ACR regional data and App Service SCM names are records within existing
zones, not additional required zones; Foundry/Cosmos/Redis alternatives are not
all mandatory zones. Do not fetch or silently update the catalog during a run.

NET-DNS-REPEAT-001 groups distinct collected zone IDs by case-insensitive DNS
name (ignoring a terminal dot). Highlight them with retained VNet-link and
endpoint-zone-group associations for ownership/architecture/cleanup review.
Isolated environments, tenants and disconnected DNS views may legitimately
repeat names. No zone is certified unused or safe to delete: records, owners,
forwarders and consumers outside the workload scope remain uncollected.
Summarize the helper's planning matrix and repeated-name rows faithfully; both
Markdown reports remain deterministic views of assessment JSON.

Metadata mode uses input/schema `0.4.0`, acquisition `1.3.0`, eleven checks/
catalog `1.5.0`. NET-DNS-META-001 `1.0.0` reports contextual aggregate
type/count/TTL evidence and explicit unavailable/partial metadata gaps.
Configuration-object summary IDs are collector-derived objects, not Azure
record-set IDs. No summary means uncollected, not an empty zone. Zero selected
sets or SOA-only results do not prove non-use; equal summaries do not prove
equal records, and TTL/count differences are not automatically defects.
Preserve owners, record-content, forwarding, external-consumer and resolution
gaps before any separately authorized consolidation planning. No deletion or
consolidation commands are generated/executed. Metadata mode/scopes and exact
parent reads are bound into checkpoints; unknown accepted reads are never
blindly repeated.

With explicit approval, `--include-dns-paths` includes metadata/planning/private
collection and adds seven operations for VNet DNS defaults, resolver/ruleset
roots and parent-scoped inbound/outbound endpoints, rules and ruleset VNet
links. DNS paths are collected only in the workload subscription; the separate
DNS-host allowlist does not authorize resolver/customer-managed DNS inspection.
External references are retained but never automatically queried.

Use only the helper-generated exact `az rest --method get` ARM lists at
`https://management.azure.com`, API `2022-07-01`, with explicit subscription
and selected `--query`. No bodies, extra headers, writes, arbitrary URLs or
arbitrary continuation requests. In current acquisition 1.5.0, only the bridge
validates and follows returned nextLink URLs for the same origin/subscription/
resource path/API version and allowlisted opaque skip-token parameters.
Do not construct/alter nextLink URLs yourself or restart an interrupted page.
Each list selects at most 2,000 rows;
parent iteration is bounded at 100 reads per operation. Root failure skips
unobserved child parents with explicit outcomes.

Selected DNS-server IPs, forwarding domain suffixes and ordered target IP/port
pairs are customer-internal engineering evidence. Do not repeat them in the
executive summary/public output. Omit tags, arbitrary metadata, secrets and
full responses. Null ports/addresses and unavailable fields remain UNKNOWN,
not silent defaults. Inbound addresses/subnet references differ from outbound
subnet configuration; never invent an outbound private IP.

DNS-path mode uses input/schema `0.5.0`, acquisition `1.4.0`, twelve checks/
catalog `1.6.0` in historical capability 0.5.0. NET-DNS-PATH-001 `1.0.0` presents selected configuration and
field/coverage/actual-behavior gaps. Known empty VNet DNS-server arrays mean
Azure-provided DNS *configuration*, not proof of client DNS selection; NIC/OS
overrides and custom/on-premises forwarding are uncollected. Resolver/VNet,
inbound/subnet, outbound/subnet, ruleset/outbound and ruleset/VNet references
are factual configured links. No resolver roots in scope does not imply no
custom DNS or defective DNS. Do not infer that a forwarding rule was selected,
clients use a resolver, a zone serves a specific client path, or DNS resolution
succeeded. No active lookup, diagnostics enablement or cleanup is performed.

Current DNS-path acquisition uses input/schema `0.6.0`, acquisition `1.5.0`
and scope-validated ARM pagination. Older `0.5.0`/`1.4.0` inputs retain their
first-page-only gaps; do not silently relabel old runs. Page and parent cursors
are separate and checkpointed. Invalid/missing/repeated continuation, changed
counts, unavailable pages and the existing 100-page budget yield explicit
partial evidence. Empty intermediate ARM pages can continue only with a
validated nextLink. Accepted native requests reconcile without blind reposting.
Continuation state is private transport data, not a fifth report; keep tokens
out of public summaries. Schema/catalog/scope changes reject old acquisition
states instead of silently migrating them.

Current DNS-path processing uses thirteen checks/catalog `1.7.0`; input/schema
`0.5.0`, acquisition `1.4.0` and selected reads are unchanged. NET-DNS-ADOPT-001
`1.0.0` adds an evidence-backed consumer/ruleset adoption matrix and contextual
partial-transition review. It requires no recollection or additional scope.
Summarize actual `priority.band` (P1/P2/P3/INFO), not ordinal `priority.rank`;
severity is potential impact, not that ordering.

When resolver/ruleset deployment is observed, mixed custom/Azure-provided VNet
DNS defaults or uneven succeeded ruleset associations are migration-context
signals, not defects or proof a transition is incomplete. Highlight rulesets
with no observed links or no enabled rules only when that parent's accessible
list is complete. Failed/partial/missing/continuation pages, unknown target or
rule fields and unready link states remain explicit UNKNOWN evidence gaps.
Known external VNet references do not authorize querying those subscriptions.

Do not mandate every VNet to link to a ruleset, use inbound endpoints or deploy
both inbound and outbound endpoints. Inbound-only, custom/on-premises DNS,
isolated environments and intentionally staged/unused rulesets can be valid.
Matching configured DNS IPs to collected inbound IPs produces candidates only;
duplicate addresses may be ambiguous. Do not rewrite these as observed client
use. Enabled rule counts do not prove relevant suffix coverage, rule selection
or successful forwarding. Request customer migration cohorts/target architecture
and owners before recommending changes. Migration intent, actual client use
and percentage migrated remain unknown; no readiness score or cleanup is
invented. If no scoped resolver/ruleset is observed, render scope/unknown facts
without inventing a partial-transition finding.

## Optional declared customer DNS intent

Only when the operator supplies an actual customer intent document, process
existing DNS-path input with `--dns-intent <uploaded-json>` alongside `--input`.
Read `dns-intent.schema.json` first. This option never authorizes acquisition
or source retrieval. Do not write an intent file from observed resources or
invent customer owners, requirements, migration stage or approvals.

The bounded schema binds run/subscription, document identity/revision, owner,
declared/reviewed UTC times and disjoint explicit VNet cohorts (500 consumers
total maximum). Stages are planned, in-progress, required-now or excluded.
Expectations are configured DNS mode, succeeded links to named rulesets and/or
configured DNS-server matching of named inbound endpoint IPs—not actual DNS
use. Inbound direct-server targets conflict with Azure-provided DNS defaults.
Excluded cohorts cannot require configuration; undeclared VNets inherit nothing.

Intent stays DECLARED in assessment `dnsIntentComparison`, including canonical
supplied-JSON hash/provenance. It is never added to observed-network.json or
presented as authenticated/current source material. Engineering reports retain
the source/owner/revision/times, expectations, differences and evidence gaps;
do not expose customer source metadata in public summaries. Operator-provided
provenance does not prove the referenced source document was retrieved or valid.

NET-DNS-INTENT-001 1.0.0 runs only with supplied intent (fourteen checks/catalog
1.8.0; no-intent mode keeps thirteen/catalog 1.7.0). Planned/in-progress
differences are rollout context (P3); required-now configuration differences
are owner-validation actions (P2), not automatic defects or remediation.
Unknown consumer/target/port/state/parent evidence and intent declared after
the observation interval require evidence collection (P2). No target means
not evaluated, not matched. Matches are configured-only, never readiness,
resolution or completed migration. Preserve both intent and observed times.

Save the four canonical reports and use verified-original publication unchanged.
The intent document is embedded in assessment, not a fifth canonical report.
Publication retries must use the original immutable assessment/intent hash,
not re-read an edited intent file or regenerate old outputs.

## Optional age and provenance chronology review

Process existing selected input with `--review-at <explicit-UTC-Z-timestamp>`,
optionally with actual supplied `--dns-intent`. This option never authorizes
acquisition or publication regeneration. Do not silently use the current wall
clock, invent a customer reference time or update ages when reopening a report.
A supplied reference time is operator provenance, not an authenticated clock.

NET-EVID-TIME-001 1.0.0 adds one check/catalog 1.9.0 only when reference time is
supplied. The customer selected ages/provenance gaps **without expiry
thresholds**: never label old evidence/intent stale, expired, valid or current
merely from age. Report exact observation/collection and supplied-intent
declaration/review ages, original UTC intervals, failed/unperformed collection
coverage, timestamp disagreements and future/inconsistent intervals. Negative
ages are UNKNOWN with explicit chronology gaps, never silently clamped to zero.

The deterministic `provenanceTimeReview` assessment/view retains reference time,
exact integer microsecond ages and source provenance. Observations and intent
are not rewritten. Operator-provided document/owner/revision/review metadata
remain unauthenticated; document validity and actual client use stay UNKNOWN.
A review date does not prove approval or that a customer standard is current.
No expiry policy, freshness score, readiness or automatic refresh is inferred.
Reopened reports preserve their original reference time and age values.

## Lineage

ADAPT Usman Mahmood's evidence-driven assessment/reporting discipline, revision
`624bd5c3bf5bd5b8df625cc111c94531dff19148`, under the permission recorded in this
project's source map. ADAPT/COMPOSE Daniel Mauser's MIT-licensed Network Desk
inventory and specialist foundations, revision
`4104279fa4707c24e6038b35b2779fecfdd11eea`. The normalized contracts and transport
are independent new integration work, not new inventory concepts. Preserve exact
source lineage and upstream notices. No mutation procedures are imported.
