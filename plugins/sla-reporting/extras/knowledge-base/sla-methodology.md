# SLA Methodology & Thresholds (knowledge base)

This note backs the `sla-analyzer` subagent and the `sla-availability` skill.
It is the native port of the calculation method in Guil Lima's
`Get-AzureSLAReport.ps1`. Surface it via `SearchMemory` for "SLA methodology"
and "SLA thresholds".

## Disclaimer (always state first)

This report is an **estimation tool, not an official SLA measurement**. The
availability percentages are approximations from Azure Resource Health and
Service Health tracking data — they are **not** Microsoft's contractual SLA
metrics. Official SLAs are at the Service Level Agreements for Online Services.
Always validate against the customer's own monitoring before presenting or
acting on the numbers.

## Data sources

| Source | Provides | Scope |
|--------|----------|-------|
| `HealthResources` (Resource Graph) | Current per-resource availability status (Available / Unavailable / Degraded) | Current snapshot per resource |
| `servicehealthresources` (Resource Graph) | Service-level `ServiceIssue` incidents | Tenant-wide, filter to in-scope regions |
| Activity Log (`AzureActivity`) | Resource/Service Health events over time | Per subscription / workspace |

Both Resource Graph tables are **tenant-scoped** — de-duplicate (`resourceId`
for HealthResources, tracking-id `name` for servicehealthresources) when
batching across subscriptions.

### Choosing the Activity Log workspace

The Activity Log (`AzureActivity`) history is read from a Log Analytics
workspace, selected in this priority order:

1. **Explicit override** — a workspace named by the operator (a
   `WORKSPACE OVERRIDE:` directive in the run/scheduled-task prompt, or the
   deploy `--workspace` flag). Wins over everything else. May be a workspace
   name, resource ID, or `customerId` GUID.
2. **Configured connector** — the agent's Log Analytics workspace connector.
3. **Auto-discovery** — the workspace named by the subscription's Activity Log
   diagnostic export.

An environment can have multiple connectors; only the workspace that actually
receives the `ResourceHealth` / `ServiceHealth` categories returns rows. An
empty `AzureActivity` result usually means the wrong workspace was queried —
specify the override when the right workspace differs from the connector.

## Service categories

- **Compute** — VMs, VM Scale Sets
- **SQL DB** — SQL DBs, SQL Servers, Managed Instances
- **Web Apps** — App Service sites, App Service plans
- **Storage** — Storage accounts

## Availability formula

Per **region x service category x month** cell:

```
Availability % = ((MinutesInMonth - EstimatedDowntimeMinutes) / MinutesInMonth) * 100
```

`EstimatedDowntimeMinutes` = the **resource-health component only** (Guil's
real-world approach).

1. **Resource health component (the only signal that affects %)**
   `(unhealthy_events / resource_count) * 30` minutes.
   Each `Unavailable` / `Degraded` status is a point-in-time event weighted by
   the fraction of the fleet affected, valued at 30 minutes.

2. **Service health incidents — context only, not counted**
   `ServiceIssue` windows are collected and shown in the Incidents & Alerts and
   Health Timeline sections, but they do **not** reduce the availability
   percentage. Availability reflects how the resources themselves actually
   behaved, not platform-wide investigation windows.

`ImpactStartTime` / `ImpactMitigationTime` from servicehealthresources are
.NET **ticks**; convert to UTC datetime before bucketing (used for the
incident sections only).

## Colour thresholds

Colour bands follow the **Azure VM SLA service-credit tiers**. 100% is always
green; cells only turn warm-coloured at a genuine SLA-credit breach.

| Band | Rule | SLA service credit |
|------|------|--------------------|
| 🟢 Green | ≥ 99.9% | None — within SLA |
| 🟡 Yellow | < 99.9% and ≥ 99% | 10% credit |
| 🟠 Orange | < 99% and ≥ 95% | 25% credit |
| 🔴 Red | < 95% | 100% credit |
| N/A (light grey) | resource_count == 0 | No resources of that type in that region |
| No data (slate) | month precedes collected history | Resource Health not yet collected — not assessed |

The heatmap colours by **discrete band index (0–3)**, not by raw percentage, so
a continuous gradient never renders 100% as an extreme (red) colour.

## What "N/A" vs "No data" means

A cell is `N/A` (light grey) only when there are **zero** resources of that
category in that region — there is nothing to measure. Do **not** render it as
100%.

A cell is `No data` (slate) when the month **precedes the start of collected
Resource Health history** (or Log Analytics retention has aged the data out).
This is reported honestly as **No data** and is **never** counted as available —
absence of collected history is not evidence of uptime. The report footnote
states the collection-start date and the workspace retention window, and
recommends extending retention so future reports can reach further back (history
is never backfilled).

## What counts toward downtime

- **Only real-world Resource Health (`Unavailable` / `Degraded`) reduces the
  percentage.** Availability measures how the resources actually behaved.
- Service Health incidents (`ServiceIssue`), planned maintenance, and health
  advisories are listed in the Incidents & Alerts / Health Timeline sections for
  context but are **excluded** from the availability calculation.
- Resource Health events in the Activity Log can lag 5–15 minutes.

## Report structure (three sections)

1. **SLA Overview** — region x service category, one column per month, with
   resource counts and colour bands.
2. **Incidents & Alerts** — `ServiceIssue` incidents from the last month:
   Source, Type, Status, Title, Impact Start/End, Duration, Affected
   Services/Regions, Summary.
3. **Health Timeline** — the same incidents across the full reporting window
   (default 12 months), grouped by month.
