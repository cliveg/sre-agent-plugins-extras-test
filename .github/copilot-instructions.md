# Repository instructions

## Project purpose and existing conventions

`sre-agent-plugins-extras` is the development repository for reusable Azure SRE
Agent capabilities. Where practical, design new assets for:

1. Local development and validation.
2. Azure SRE Agent use.
3. SRE Agent Marketplace distribution using this repository's conventions.
4. Customer deployment, initially including Contoso.
5. Potential later contribution of mature assets to the official Azure SRE Agent
   ecosystem.

Keep reusable components modular and minimize customer- or project-specific
assumptions. Separate customer configuration from reusable capability assets.

Preserve the hybrid packaging model described in [README.md](../README.md):

- Capabilities live under `plugins/<capability>/`, with `plugin.json`, `README.md`,
  and `skills/<skill>/SKILL.md`.
- Register marketplace plugins in `.github/plugin/marketplace.json`; preserve the
  existing root `marketplace.json` conventions when applicable.
- Marketplace-installed skills and MCP connectors are distinct from companion
  extras. Subagent YAML, scheduled-task YAML, and knowledge-base Markdown belong
  under the plugin's `extras/agents/`, `extras/scheduled-tasks/`, and
  `extras/knowledge-base/` directories.
- Use the existing generic `tools/install.sh` and `tools/deploy-extras.sh` workflow
  rather than introducing a capability-specific deployment mechanism.
- Follow existing plugin manifests, skill frontmatter, Azure SRE Agent schemas,
  tool declarations, naming, and deployment patterns. Do not assume VS Code or
  Copilot CLI customization files run unchanged in Azure SRE Agent.
- For plugin/schema changes, run `python tools/validate.py`, as used by
  `.github/workflows/validate.yml`. Use the documented deployer `--dry-run` for
  relevant packaging changes; dry runs are not approval to deploy.
- Preserve existing credits, licensing, and attribution, including those for
  established plugins.

## Azure Network Health Assessment initiative

Build incrementally toward a capability that:

- Discovers actual Azure network environments without requiring IaC.
- Creates a normalized, machine-readable, evidence-backed Observed Network Model.
- Preserves provenance, collection coverage, uncertainty, permission failures,
  and missing evidence.
- Assesses architecture, configuration, reliability, security, and operational
  health; prioritizes findings and explains their significance.
- Recommends specialist deep-dive assessments where appropriate.
- Incorporates partial Terraform or Bicep when available.
- Reconciles documented intent, IaC intent, deployed configuration, effective
  behavior, telemetry, and assumptions without conflating them.
- Produces persistent executive and engineering reports.
- Supports interactive and, eventually, scheduled Azure SRE Agent execution.

These are ultimate goals, not permission to expand an individual task or bypass
the assessment MVP's safety boundaries.

## Reference-first development

The following workspace repositories are external, read-only references:

| Reference | Workspace path | Upstream repository |
|---|---|---|
| Usman Mahmood's Azure Networking Assessment Agent | `<local-clone-root>\azure-networking-agent-test-repo` | `https://github.com/lavoizer-develop/azure-networking-agent-test-repo` |
| Daniel Mauser's Network Desk | `<local-clone-root>\network-desk` | `https://github.com/dmauser/network-desk` |

Never modify either reference repository. Verify their actual roots and revisions
before relying on them; the local Network Desk checkout may use a fork remote.
If a reference is unavailable, disclose the limitation rather than claim it was
searched.

Before creating networking skills, specialist procedures, acquisition methods,
assessment criteria, or report functionality:

1. Search both reference repositories for relevant foundations.
2. Identify the exact upstream files and relevant portions.
3. Check licensing and decide whether to reuse, adapt, compose, implement new
   functionality, or exclude it.
4. Record the decision and technical lineage in `docs/source-map.md` in this
   primary repository before implementation.
5. Avoid silently recreating existing upstream capabilities.

Use these classifications consistently:

| Classification | Meaning |
|---|---|
| REUSE | An existing asset can be used substantially as-is and licensing or explicit permission permits it. |
| ADAPT | An existing asset can be modified and licensing or explicit permission permits it. |
| COMPOSE | Existing capabilities should be orchestrated without duplicating their implementations. |
| NEW | A required capability was not found in the inspected references. |
| NOT_NEEDED | The capability is outside the current scope. |
| REFERENCE_PENDING_PERMISSION | The source is technically relevant, but direct reuse or adaptation is blocked until licensing or written permission is established. |

Source-map entries should identify the capability, classification, rationale,
author/project, upstream repository and inspected revision, exact source files or
portions, licensing/permission status, and downstream assets or integration.
Record conceptual influence separately from copied or adapted implementation.
COMPOSE does not bypass licensing or runtime compatibility checks.

## Licensing and attribution

Network Desk is MIT licensed. When reusing or adapting its assets:

- Retain the applicable copyright and MIT permission notice.
- Preserve attribution to Daniel Mauser and the Network Desk project.
- Record the upstream repository and inspected revision.
- Identify precise files or substantial portions used or adapted.
- Prefer canonical source assets over generated copies where possible.

Usman's inspected repository has no tracked open-source license. On 2026-10-07,
the project owner reported Usman's approval to "use it however we want" and
explicitly confirmed that copying, adaptation, Marketplace redistribution,
customer deployments, and potential upstream contributions are covered.
Record this as project-owner-reported permission, not as an MIT license or
independently verified written grant. See `docs/source-map.md` for the permission
record and remaining distribution-review evidence needs.

- Reuse and adaptation within that confirmed scope may proceed.
- Preserve attribution to Usman Mahmood and his project, exact upstream assets
  and revisions, any existing notices, and downstream modifications.
- Distinguish reused/adapted assets from conceptual influence and independently
  implemented assets; do not misrepresent authorship.
- Do not claim Usman's assets are MIT licensed or covered by this repository's
  license merely because they are included.
- For uses outside the confirmed scope or sources without permission, retain
  REFERENCE_PENDING_PERMISSION until authorization is established.
- Usman welcomes feedback through pull requests. Reference checkouts remain
  read-only; only prepare or submit upstream contributions when explicitly
  authorized for that task.

Recheck permission status when references change. Never remove upstream
authorship, copyright, license, attribution, or provenance information.

## New contribution boundary

Discovery, network inventory, topology snapshots, effective-route exports,
effective-NSG exports, diagrams, and specialist networking procedures already have
foundations in Network Desk. Do not describe those general concepts as wholly new.

The primary new capability under investigation is a shared, normalized,
provenance-aware observation and evidence contract that:

- Normalizes resources into stable entities and relationships.
- Records source, scope, collection time, and coverage.
- Represents permission failures and unavailable evidence.
- Distinguishes absence from evidence that was not collected.
- Separates deployed configuration from effective behavior.
- Separates observed state from documented and IaC-declared intent.
- Joins topology, routes, DNS, endpoints, security controls, firewalls, gateways,
  and eventually telemetry.
- Provides a machine-readable contract for assessment and reporting.

A target-runtime acquisition adapter may be NEW integration work, but should
adapt Network Desk's existing acquisition procedures rather than claim those
underlying procedures are new. Distinguish upstream guidance/examples from
executable collectors and verify compatibility before claiming functionality.

## Evidence model

Keep observation and assessment separate in `runs/<run-id>/`:
`observed-network.json`, `assessment.json`, `network-assessment.md`, and
`network-evidence.md`. Observations contain collections, selected evidence,
entities, assertions, relationships, provenance and coverage, not interpreted
findings. Both Markdown files are deterministic views of assessment JSON.

Acquisition collects evidence; normalization creates only evidence-supported
configuration relationships. Use precise relationships such as
`hasConfiguredNextHop`, `hasEffectiveNextHop`, and `observedTrafficVia`; never
represent configured routing as demonstrated traffic flow.

Retain only needed evidence, with sensitivity, redaction/omission, identifier
handling and retention decisions. Do not persist full unredacted responses by
default. Every deterministic check and generated finding carries `checkId` and
`checkVersion`. Severity is potential impact; priority is recommended action
ordering, including whether the next action is evidence collection.

| Classification | Meaning |
|---|---|
| OBSERVED | Directly verified using an authoritative connected source. |
| DECLARED | Specified by documentation, standards, architecture material, or IaC. |
| INFERRED | Reasoned from available evidence. |
| UNKNOWN | Evidence is insufficient, inaccessible, or not collected. |

Never present INFERRED information as OBSERVED. Do not treat inaccessible or
uncollected evidence as proof that a resource, relationship, or control is absent.
Preserve provenance wherever practical, including scope, time, collection source,
coverage, failures, and links to supporting evidence.

## Assessment discipline

Usman's evidence-driven workflow is a conceptual influence: establish scope and
requirements, gather implementation evidence, distinguish facts from requirements,
assumptions, and dependencies, produce contextual findings with observed and
expected state, explain risk and recommendations, prioritize next steps, and
persist and verify the authoritative assessment artifact.

Adapt this discipline within the confirmed permission scope and visibly
attribute both conceptual influence and any reused/adapted assets in project
documentation. Use Network Desk specialist guidance for deeper analysis where
applicable.

Do not allow broad severity heuristics to replace contextual validation. An NSG
rule alone is not proof of public reachability without corresponding ingress-path
evidence. Document gaps and validation needs rather than invent findings.

## Assessment MVP safety

- Assessment is read-only by default. Do not modify Azure resources during the
  assessment MVP.
- Do not enable logs, alerts, monitors, diagnostics, or flow collection during
  assessment. Assess existing telemetry and report missing coverage instead.
- Observed state is not desired state. IaC is not automatically authoritative;
  deployed configuration is not automatically correct; documentation is not
  automatically current.
- Differences between evidence sources are not automatically defects.
- Do not generate deployable Terraform or Bicep during the MVP.
- If IaC reconstruction is explored later, label it as an unvalidated
  representation of observed state requiring engineering review. Never
  automatically deploy reconstructed IaC.
- Keep customer evidence and secrets out of reusable source assets and public
  reports; preserve useful provenance without unnecessary sensitive values.

These network-assessment restrictions do not change the intended behavior of
unrelated existing capabilities or authorize their execution.

## Development workflow

For each substantial capability:

1. Inspect existing `sre-agent-plugins-extras` conventions.
2. Inspect relevant reference assets.
3. Check licensing and reuse status.
4. Update `docs/source-map.md`.
5. Implement the smallest useful increment.
6. Validate against Azure using available Azure MCP tooling, within the permitted
   scope and read-only assessment boundaries.
7. Exercise Azure SRE Agent through MCP where useful.
8. Independently validate important observations against underlying Azure
   evidence.
9. Add repeatable evaluation cases.
10. Document permission failures, partial collection, limitations, and evidence
    gaps.
11. Only then expand the capability.

Agreement between two AI agents is not authoritative validation. If tooling,
permissions, or evidence are unavailable, explicitly report what was not
validated; do not claim success. Prefer existing Azure SRE Agent schemas,
packaging, and Marketplace conventions, and design suitable components to
potentially graduate into the official Azure SRE Agent ecosystem.
