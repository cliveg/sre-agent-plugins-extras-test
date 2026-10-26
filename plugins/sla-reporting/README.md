# SLA Reporting — Azure SRE Agent plugin

Estimates how available your Azure resources have been, per **region × service
category × month**, and renders an SLA service-credit **heatmap**. Built as a
fully native SRE Agent capability — no Automation Account, no Excel.

This is a native adaptation of Guil Lima's PowerShell tool
**[gplima89/AzureSLA](https://github.com/gplima89/AzureSLA)**. All credit for the
original methodology and report design goes to that project.

## How it works — executive summary

This report answers one question for leadership: **"How available has our Azure
estate actually been, and where should we focus?"** It does that by turning
Azure's own health telemetry into a simple, colour-coded scorecard.

- **Observed, not promised.** Availability is derived from how your resources
  *actually behaved* — Azure **Resource Health** records each time a resource
  was `Unavailable` or `Degraded`. We do **not** read Microsoft's contractual
  SLA figures; we estimate real-world experience.
- **Aggregated the way leaders think.** Results roll up into a grid of
  **region × service category × month**, so you can see trends and outliers at a
  glance rather than per-resource noise.
- **Fleet-weighted impact.** Each unhealthy event counts in proportion to how
  much of the fleet it touched (one VM down out of fifty is not a regional
  outage), then is translated into estimated downtime minutes for that month.
- **Graded against familiar tiers.** Each cell is coloured using the **Azure VM
  SLA service-credit tiers** (🟢 ≥ 99.9% → 🔴 < 95%), so a "red" cell maps to a
  recognisable service-credit conversation, not an arbitrary threshold.
- **Platform incidents shown for context.** Microsoft-declared **Service Health**
  incidents are listed alongside the scorecard for narrative context but do
  **not** change the availability percentage — the number reflects *your*
  resources, not platform-wide investigation windows.

## Accuracy & key caveats

> **This is a decision-support estimate, not an official SLA measurement.** Treat
> it as a directional indicator for prioritisation and trend-spotting — not as a
> basis for service-credit claims or contractual reporting.

- **Not Microsoft's contractual SLA.** The percentages approximate observed
  experience from Resource Health; they are not Azure's official SLA metrics and
  should not be used to claim or dispute service credits. Validate against your
  own monitoring before presenting or acting on the numbers.
- **Event-based approximation.** Downtime is estimated from point-in-time health
  events (each weighted by fleet impact), not from continuous second-by-second
  probing. Short blips between samples can be missed, and Resource Health events
  can lag roughly 5–15 minutes.
- **Gaps are reported honestly, never as 100%.** Months before health-history
  collection began — or that have aged out of Log Analytics retention — are shown
  as **"No data"**, not as fully available. Absence of data is not evidence of
  uptime.
- **Scope is four service categories.** Only **Compute, SQL DB, Web Apps, and
  Storage** are assessed today; other resource types are not reflected in the
  scorecard.
- **Depends on the right workspace and retention.** Numbers are only as complete
  as the Log Analytics workspace they read from. If history points at the wrong
  workspace or retention is short, coverage shrinks — see
  [Pinning the Log Analytics workspace](#pinning-the-log-analytics-workspace---workspace).
- **Read-only and point-in-time.** The report observes and summarises; it changes
  nothing in your environment, and each run reflects the data available at that
  moment.

## What it measures

Availability is computed from **real-world Resource Health only** (fleet-weighted
`Unavailable` / `Degraded` events). Service Health `ServiceIssue` incidents are
collected and shown for context (Incidents & Health Timeline sections) but do
**not** change the availability percentage.

Colour bands follow the **Azure VM SLA service-credit tiers**:

| Band | Rule | SLA credit |
|------|------|-----------|
| 🟢 Green  | ≥ 99.9%          | none |
| 🟡 Yellow | < 99.9% and ≥ 99% | 10% |
| 🟠 Orange | < 99% and ≥ 95%   | 25% |
| 🔴 Red    | < 95%            | 100% |
| Grey (N/A) | no resources of that type in the region | — |

## What's in this plugin

```
plugins/sla-reporting/
├── plugin.json                         # plugin manifest (marketplace-installable)
├── skills/
│   └── sla-availability/SKILL.md       # ← the marketplace installs THIS
└── extras/                             # ← NOT carried by the marketplace; deploy with tools/deploy-extras.sh
    ├── agents/sla-analyzer.yaml         # autonomous subagent that drives the report
    ├── scheduled-tasks/sla-monthly-report.yaml   # monthly cron (1st @ 06:00 UTC)
    └── knowledge-base/sla-methodology.md          # methodology reference doc
```

The **Plugin Marketplace installs skills (and MCP connectors) only.** Subagents,
scheduled tasks, and knowledge-base files are deployed separately via the
repo's [`tools/deploy-extras.sh`](../../tools/deploy-extras.sh).

## Install

A complete capability is **two steps**: the marketplace installs the skill, and
one Cloud Shell command deploys the extras.

**1. Skill — via the marketplace (portal)**

In the SRE Agent portal: **Builder → Plugins → Install from URL**, then fill in:

- **GitHub repository URL:** `https://github.com/cliveg/sre-agent-plugins-extras-test`
  (or just `cliveg/sre-agent-plugins-extras-test`)
- **Path in repo:** `plugins/sla-reporting`

Click **Install**. The `sla-availability` skill imports in seconds, version-pinned
to the commit.

> The **Path in repo** field is required — it points the installer at this
> plugin's `plugin.json`. Leaving it blank fails with *"No plugin found in repo"*.

**2. Extras — one Cloud Shell command (no clone)**

Open [Azure Cloud Shell](https://shell.azure.com) and run:

```bash
curl -fsSL https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/tools/install.sh \
  | bash -s -- --plugin sla-reporting --resource-group <your-rg>
```

This downloads only this plugin's extras plus the deployer, uploads the
knowledge base, creates the subagent, and registers the monthly scheduled task.
By default the **skill is not touched** (it came from the marketplace in step 1).

**Advanced (cloned repo / CI):** run the deployer directly from the repo root:

```bash
tools/deploy-extras.sh \
  --plugin plugins/sla-reporting \
  --endpoint https://<your-agent>.<region>.azuresre.ai
```

Re-run after any edit. Use `--dry-run` to preview, `--status` to check what's
deployed, or `--with-skill` to also push the skill from this repo instead of the
marketplace.

### Pinning the Log Analytics workspace (`--workspace`)

By default the plugin **auto-discovers** the workspace that receives
`ResourceHealth` / `ServiceHealth` logs (agent connector first, then the
subscription's Activity Log diagnostic export). If your environment has multiple
workspaces and the report shows "no history" when data actually exists, the
auto-discovery picked the wrong one. Pin the correct workspace explicitly:

```bash
tools/deploy-extras.sh --plugin plugins/sla-reporting \
  --endpoint https://<your-agent>.<region>.azuresre.ai \
  --workspace <name|guid|resourceId>
```

Accepts a workspace **name**, ARM **resource ID**, or `customerId` **GUID** (also
settable via `LOG_ANALYTICS_WORKSPACE`). The flag injects a `WORKSPACE OVERRIDE:`
directive into the deployed subagent and monthly task so unattended runs use it
too. Precedence: **explicit `--workspace` > agent connector / default >
auto-discovery**.

> **Cloud Shell + Conditional Access:** if the extras step fails with *"Could not
> acquire a data-plane token"*, your tenant likely requires a compliant/Entra-joined
> device. Cloud Shell can't satisfy that — run the deployer from a managed
> workstation (Git Bash/WSL) or VM instead. See the repo
> [Troubleshooting](../../README.md#troubleshooting) section.

## Prerequisites

- Azure CLI logged in (`az login`) with the **SRE Agent Administrator** role on
  the target agent.
- `python3`/`python` with `PyYAML`, plus `curl`.
- A **Log Analytics workspace** that receives the subscription's
  `ResourceHealth` / `ServiceHealth` activity logs. **The plugin discovers this
  automatically** — it never hardcodes a workspace name. It prefers the agent's
  Log Analytics workspace connector, otherwise resolves the workspace from the
  subscription's Activity Log diagnostic export. If neither exists yet, the
  skill includes the one-time setup command to enable it.

## Tools used by the subagent

`SearchMemory`, `RunAzCliReadCommands`, `GetAzCliHelp`,
`QueryLogAnalyticsByWorkspaceId`, `ExecutePythonCode`,
`PlotAreaChartWithCorrelation`, `PlotPieChart`. **Strictly read-only.**

## Credits

Original methodology and report design: **Guil Lima** —
<https://github.com/gplima89/AzureSLA>.
