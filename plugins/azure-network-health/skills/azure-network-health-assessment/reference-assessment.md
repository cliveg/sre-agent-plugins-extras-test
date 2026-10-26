# Reference-led Azure network assessment method

This method **adapts** Usman Mahmood's assessment workflow/report specification
and selected Azure-only Network Desk specialist procedures, and **composes** the
primary collector/normalizer/checks. It is not a claim that these networking
procedures or reporting concepts are new.

## Attribution and permitted scope

- **Usman Mahmood**, Azure Networking Assessment Agent, revision
  `624bd5c3bf5bd5b8df625cc111c94531dff19148`:
  `.github/agents/azure-networking.agent.md`, Operating Workflow/Repository
  Discovery/Required Deliverable; `.github/skills/azure-networking/SKILL.md`,
  Review Principles/Finding Evidence; `.github/skills/assessment-reporting/SKILL.md`,
  report structure, contextual findings, architecture, positives, assumptions and
  quality checks. Project-owner-reported permission from 2026-10-07 covers this
  adaptation/distribution scope; it is **not MIT or an independently inspected
  written grant**.
- **Daniel Mauser / Network Desk**, revision
  `4104279fa4707c24e6038b35b2779fecfdd11eea`, canonical specialist assets listed
  below. MIT, copyright 2025 dmauser. The applicable
  [MIT notice](../../LICENSES/Network-Desk-MIT.txt) and
  [third-party notices](../../THIRD-PARTY-NOTICES.md) remain part of the package.

Adapted portions remain attributed to their sources, not relicensed merely by
inclusion. Queries, target-runtime adapter, normalized evidence integration and
deterministic implementation are independently authored primary code.
Exact decisions and limitations are in the primary
[source map](../../../../docs/source-map.md).

## Assessment sequence adapted from Usman

1. **Establish scope and expectations.** Confirm the actual workload/DNS scopes,
   owner requirements and supplied documentation/IaC, if any. Keep declared
   intent separate from observed configuration; missing intent is not a failed
   requirement or permission to invent architecture.
2. **Gather implementation evidence.** Use reviewed read-only connected sources,
   original times, selected fields, explicit outcomes and safe continuation.
   Retain permission failures, missing fields, uncollected evidence and index
   freshness limits. Azure access is not automatically tenant-wide completeness.
3. **Review by specialist question.** Apply the procedures below to actual
   evidence. Reuse existing checks instead of duplicating their implementation.
   Record what was evaluated and what could not be evaluated.
4. **Write contextual findings.** Each interpreted record carries evidence,
   observed state, expected state or its absence, risk, recommendation,
   dependencies/considerations, confidence, check/version and next-action
   priority. Potential impact severity is distinct from action ordering.
5. **Include supported positives and architecture.** Positive observations need
   evidence too. Diagrams contain collected configuration relationships only;
   they are not traffic diagrams or invented hub/spoke roles.
6. **Persist executive and engineering views.** Adapt the upstream dashboard,
   area scorecard, prioritized findings, positive observations and validation
   requirements into the repository's four-file contract. Here assessment JSON
   is authoritative and both Markdown artifacts are deterministic views.
7. **Verify before completion.** Verify source/role bindings, original data,
   versions, counts, links and exact private committed bytes. A successful
   command or a second agent agreeing is not authoritative validation.

## Specialist review procedures

### Topology, addressing and peering

Sources: Network Desk `vnet-architect/skills/migration-planner/SKILL.md`, Phase 1
Assess; `peering-advisor/SKILL.md`, Azure settings/non-transitivity.

- Inventory returned VNets/subnets, address prefixes and actual directional
  peerings. Compose existing contextual overlap/reciprocity checks.
- Review remote references, state and access/forwarding/gateway flags separately.
  A flag does not create an NVA, route or working transit.
- Compare address overlap to actual relationships and declared connectivity
  intent. Isolated overlapping networks are not automatically defects.
- Leave external networks, peering mode/quota applicability and effective
  transit unknown where evidence is missing. No migration/create commands.

### Configured routing and egress

Source: Network Desk `network-troubleshooter/skills/routing-debug/SKILL.md`,
route/next-hop/return-path evidence workflow.

- Compose existing subnet route-table and configured-next-hop checks.
- Distinguish absent returned associations from unavailable fields.
- Use `hasConfiguredNextHop` meaning, not demonstrated traffic flow.
- Effective NIC routes, learned routes, appliance behavior, listeners and return
  paths are separate evidence. No active tests or inferred outage.

### NSG rules and configured ingress context

Source: Network Desk `network-security/skills/nsg-audit/SKILL.md`, Azure audit
commands, broad-source management/database examples, priority/default/usage review.

- Review custom inbound Allow selectors and the versioned review-port examples.
  Respect singular/plural fields, wildcard/Internet/address unions and unsupported
  selectors; missing direction/access/protocol is an explicit review gap.
- Keep source default rules distinct from custom rules. Do not import automatic
  Critical/High labels or an arbitrary CIDR-size threshold.
- Bind only collected public-IP/NIC/subnet/NSG configuration references. A load
  balancer/NAT reference does not establish an equivalent direct NIC path.
- Earlier rules, effective NIC/subnet/admin rules, routes and actual listeners
  remain required before claiming reachability. Zero unvalidated log hits do not
  establish unused rules; complete shadowing is not asserted from partial matches.

### Private Endpoints and DNS

Sources: Network Desk `private-link/agents/private-link.md`,
`skills/dns-integration/SKILL.md` and `skills/troubleshoot/SKILL.md`; Usman's
private-access and external-dependency discipline.

- Compose existing approval, zone-group, zone-link, repeated-zone, resolver and
  forwarding configuration checks.
- Review service/subresource applicability and central/custom-DNS alternatives.
  Missing direct spoke-zone linkage alone is not a defect.
- Endpoint approval and configured DNS linkage are not proof of resolution,
  actual traffic, disabled public access or accepted customer exceptions.
- No DNS creation/linking/cleanup, lookup or traffic test is part of assessment.

### Existing telemetry and recorded change context

Sources: Network Desk `network-monitor/agents/network-monitor.md` and Azure
log-evidence portions of `firewall-engineer/skills/rule-audit/SKILL.md`.

- Inventory existing flow-log/Connection Monitor configuration only. Configuration
  does not prove data emission, test success, latency, coverage or rule usage.
- Reuse the verified event timeline. Keep source-specific time meanings,
  revisions, recorded identities, unknown times, gaps and overlap witnesses.
- Resource-ID/correlation context is not initiating-human proof or causation.
- Validate applicable existing tables/schema/window/retention before interpreting
  telemetry. No logging/monitor/alert enablement or active testing.

### Firewall and hybrid connectivity

Sources: Network Desk `firewall-engineer/skills/rule-audit/SKILL.md`, Azure
rule export/log evidence; `hybrid-connectivity/skills/troubleshoot/SKILL.md`,
BGP/tunnel/route validation.

- Review returned firewall/policy and gateway/circuit/connection metadata with
  exact source coverage. Classic versus policy rules must be distinguished.
- Complete rule groups, validated hit counts, BGP peers, learned/effective routes
  and counterpart evidence remain explicit deeper-review requirements.
- A Connected label is not traffic proof; a coarse indexed nonconnected label
  alone is not a verified outage.
- Never request VPN shared keys or ExpressRoute authorization keys. No gateway,
  routing-intent, firewall-rule or monitor mutation is imported.

## Report completion rules

Use an assessment-coverage scorecard, not a synthetic health score. Each area
states evaluated and unassessed questions. Empty indexed results are scoped
returned observations, not global absence, and zero findings do not mean Healthy.
Compliance is unassessed without owner requirements. The executive view leads
with scope/window, supported observations, prioritized next actions and gaps;
the engineering view retains evidence links, checks and full contextual records.

All diagrams, service-control reviews and recorded context retain their own
source windows and qualifications. A broader report is not a certification of
network completeness, effective security, application connectivity or causation.
