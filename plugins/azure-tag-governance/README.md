# Azure Tag Governance

Azure Tag Governance is a read-only Azure SRE Agent capability that discovers
tag and basic resource-naming patterns, maintains an evidence-backed governance
profile, evaluates resources deterministically, and publishes immutable results
to an approved private Git repository.

The capability never writes tags, renames resources, deploys Azure Policy,
creates tickets, or changes Azure resources.

## MVP behavior

- Requires an explicit management-group, subscription, subscription-list, or
  resource-group scope.
- Uses direct Azure Resource Graph as the primary inventory source.
- Can use `arg("").Resources` through the SRE Agent-connected Log Analytics
  workspace as an opt-in supplemental source. This preview path is capped at
  1,000 ARG rows, has no documented pagination, can hide ARG errors, and is
  never treated as complete inventory.
- Collects relevant Azure Policy definitions, initiatives, assignments,
  exemptions, and compliance state as separate `DECLARED` evidence.
- Produces candidate rules on the first run. Inferred candidates cannot produce
  definitive violations on that baseline run.
- Allows a validated AI decision to promote a non-conflicting candidate only
  after a second comparable run. AI cannot automatically override, weaken,
  delete, or relax an authoritative rule.
- Automatic promotion requires an explicit `high` confidence category,
  supporting evidence, complete decision coverage, and a rollback reference to
  the verified baseline. These are output-integrity gates, not numeric
  prevalence or sample-size thresholds.
- Overlapping inherited rules block automatic additions for the same subject.
  Repeated promotion is idempotent; stale rules with an unchanged identity can
  be revalidated without creating duplicate IDs.
- Evaluates the frozen effective profile with deterministic Python checks.
- Records inaccessible and uncollected evidence as `UNKNOWN`.
- Retains only finding-linked resource fields plus aggregate inference evidence.

## Output contract

The layout intentionally follows the WARA run-only hierarchy:

```text
<output-root>/tag-governance/<subscription-label>/<scope-folder>/<run-id>/
  run.json
  governance-profile.json
  observations.json
  assessment.json
  delta.json
  executive-report.md
  engineering-report.md
<output-root>/tag-governance/<subscription-label>/<scope-folder>/latest.json
```

Every run contains the exact effective profile used for evaluation. After the
first successful publication, the latest verified Git profile snapshot is
authoritative; Agent memory is only a cache and destination pointer.

Runs are comparable only when the exact plugin build and profile version match.
Artifacts use stable object IDs and SHA-256 hashes. Git retention is append-only
in the MVP; deleting a current file does not remove historical Git data.

### Reading candidate rules

The engineering report describes each proposed rule in plain language, retaining
its stable candidate ID for correlation with the profile. Required-tag candidates
show the exact tag key, resource type, scope, observed presence/missing counts,
percentage, and distinct-value count without exposing raw tag values. Naming
candidates show the proposed format, exact regular expression, scope, and
matching-name counts. Entries are ordered by resource type and rule kind.
When a candidate has been reviewed for promotion, its structured decision is
retained in the profile and the report shows confidence, rationale, model/prompt
metadata, and revalidation date. Unavailable model metadata must be recorded as
unknown rather than invented.

`INFERRED` means the proposed requirement was derived from observed patterns,
not declared by the customer. Candidates are not enforced and are not compliance
findings. A tag present on one of two resources is evidence for a proposal, not
proof that the other resource violates a requirement. Naming matches establish
format consistency only, not semantic correctness.

Historical run bundles remain immutable. Report-format changes apply to newly
generated reports; do not overwrite an old report or its integrity hashes.

## Input files

`scripts/tag_governance.py build` accepts:

- a Resource Graph collection document;
- optional Azure Policy evidence;
- an optional prior run directory;
- optional strictly structured AI decisions;
- explicit scope and output labels.

See `tests/fixtures/` for bounded examples. Resource input is an object with
`resources`, `coverage`, and `collectedAt`. Each resource requires `id`, `name`,
and `type`; `tags` is optional.

AI decisions do not contain raw inventory. Each decision references a stable
candidate ID and includes supporting and contrary evidence, coverage, rationale,
model and prompt versions, confidence, expiry, and rollback metadata.

## Read-only permissions

Use the least privilege required for:

- Resource Graph and resource metadata reads at the explicit target scope;
- relevant Azure Policy reads;
- `Log Analytics Reader` on the SRE Agent-connected workspace only when the
  supplemental `arg()` path is enabled.

Do not grant Tag Contributor, Contributor, policy-write, or remediation roles.

## Run locally for deterministic validation

Local execution validates the deterministic implementation but is not a
supported product runtime:

```text
python plugins/azure-tag-governance/skills/azure-tag-governance/scripts/tag_governance.py build \
  --resources plugins/azure-tag-governance/tests/fixtures/resources.json \
  --output-root <output-directory> \
  --subscription-label example-subscription \
  --scope-folder example-rg \
  --scope-id /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example-rg \
  --plugin-build 0.1.0
```

## Validation

```text
python -m unittest discover -s plugins/azure-tag-governance/tests -v
python tools/validate.py
tools/deploy-extras.sh --plugin plugins/azure-tag-governance --dry-run --with-skill
```

On Windows, use PowerShell 7 for the generic deployer dry run:

```powershell
pwsh.exe -NoProfile -File tools\deploy-extras.ps1 -Plugin plugins\azure-tag-governance -Endpoint https://example.azuresre.ai -DryRun -WithSkill
```

The first live validation must use a small approved non-production scope.
Technical success verifies read-only completion, coverage accounting,
deterministic replay, artifact integrity, and Git publication. It does not claim
that finding accuracy has been human-benchmarked.

## Limitations

- Resource Graph is eventually consistent. This MVP does not re-read findings
  through ARM.
- The Log Analytics `arg()` supplemental path is preview functionality and
  cannot establish complete coverage.
- AI confidence is case-specific rather than threshold-based. Its decisions are
  auditable but not deterministic.
- Cost-related rules validate tag conformance only; they do not reconcile Azure
  billing or prove correct cost allocation.
- Basic naming checks identify configured format inconsistencies, not semantic
  correctness or ownership.
