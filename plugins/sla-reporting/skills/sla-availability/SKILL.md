---
name: sla-availability
description: |
  Estimates Azure resource availability (SLA) per region, service category, and month, and lists Service Health incidents that affected the environment. Uses Azure Resource Graph (HealthResources, servicehealthresources) and the Activity Log. Read-only.
tools:
  - RunAzCliReadCommands
  - GetAzCliHelp
  - QueryLogAnalyticsByWorkspaceId
  - ExecutePythonCode
---

# Azure SLA / Availability Estimation

Estimates per-region, per-service-category availability from Azure Resource
Health and Service Health signals. Produces a Markdown report with heatmap.

> **Estimation only — not an official SLA measurement.** Availability is
> approximated from Resource Health data. Service Health incidents are listed
> for context but do not change the availability percentage.

## Service categories

| Category | Resource types |
|----------|----------------|
| Compute | `microsoft.compute/virtualmachines`, `microsoft.compute/virtualmachinescalesets` |
| SQL DB | `microsoft.sql/servers/databases`, `microsoft.sql/servers`, `microsoft.sql/managedinstances` |
| Web Apps | `microsoft.web/sites`, `microsoft.web/serverfarms` |
| Storage | `microsoft.storage/storageaccounts` |

VMSS instances are included in resource counts (Steps 1–2) but **excluded**
from Activity Log queries (Steps 4b/4c) and Section 5 detail.

## Prerequisites

- Agent identity needs **Reader** on target subscription(s).
- `Microsoft.ResourceHealth` provider must be registered.
- For multi-month history, route `ResourceHealth` and `ServiceHealth`
  activity-log categories to a Log Analytics workspace via a
  **subscription-level diagnostic setting**:

```bash
az monitor diagnostic-settings subscription create \
  --name sla-resourcehealth \
  --location <region> \
  --workspace "<workspace-resource-id>" \
  --logs '[
    {"category":"ResourceHealth","enabled":true},
    {"category":"ServiceHealth","enabled":true}
  ]'
```

Discover the target workspace (do not hardcode):

```bash
az monitor diagnostic-settings subscription list \
  --query "value[?contains(to_string(logs), 'ResourceHealth') || contains(to_string(logs), 'ServiceHealth')].workspaceId" \
  -o tsv
```

## Determinism rules

1. Run `az graph query` commands **exactly** as written, including pagination.
2. Run the Step 5 Python script **verbatim** via `ExecutePythonCode`.
3. Emit the report using the exact section order the script prints.
4. If a data source is empty, report the zero result as-is.

## Step 0 — Enumerate subscriptions & handle paging

```bash
az account list --query "[?state=='Enabled'].id" -o tsv
```

Pass to every graph call as `--subscriptions $SUBS`. Page with skip tokens
(max 1000 rows per call):

```bash
az graph query -q "<QUERY>" --subscriptions $SUBS --first 1000 -o json
# If skip_token is non-empty, request next page:
az graph query -q "<QUERY>" --subscriptions $SUBS --first 1000 --skip-token "<token>" -o json
```

## Step 1 — Resource counts per region + category

```bash
az graph query -q "Resources
| where type in~ ('microsoft.compute/virtualmachines','microsoft.compute/virtualmachinescalesets','microsoft.sql/servers/databases','microsoft.sql/servers','microsoft.sql/managedinstances','microsoft.web/sites','microsoft.web/serverfarms','microsoft.storage/storageaccounts')
| extend ServiceCategory = case(
    type =~ 'microsoft.compute/virtualmachines','Compute',
    type =~ 'microsoft.compute/virtualmachinescalesets','Compute',
    type startswith 'microsoft.sql/','SQL DB',
    type startswith 'microsoft.web/','Web Apps',
    type =~ 'microsoft.storage/storageaccounts','Storage','Other')
| summarize ResourceCount = count() by location, ServiceCategory
| order by location asc, ServiceCategory asc" --subscriptions $SUBS --first 1000 -o json
```

Summarise by `location, ServiceCategory` only — do **not** add `subscriptionId`.
Zero resources = `N/A`, not 100%.

## Step 2 — Current health snapshot (HealthResources)

```bash
az graph query -q "HealthResources
| where type == 'microsoft.resourcehealth/availabilitystatuses'
| extend resourceId = tolower(tostring(properties.targetResourceId))
| extend availabilityState = tostring(properties.availabilityState)
| extend occurredTime = todatetime(properties.occurredTime)
| extend reasonType = tostring(properties.reasonType)
| extend resourceType = tostring(properties.targetResourceType)
| extend healthLocation = tostring(properties.location)
| where resourceType in~ ('microsoft.compute/virtualmachines','microsoft.compute/virtualmachinescalesets','microsoft.sql/servers/databases','microsoft.sql/servers','microsoft.sql/managedinstances','microsoft.web/sites','microsoft.web/serverfarms','microsoft.storage/storageaccounts')
| extend ServiceCategory = case(
    resourceType =~ 'microsoft.compute/virtualmachines','Compute',
    resourceType =~ 'microsoft.compute/virtualmachinescalesets','Compute',
    resourceType startswith 'microsoft.sql/','SQL DB',
    resourceType startswith 'microsoft.web/','Web Apps',
    resourceType =~ 'microsoft.storage/storageaccounts','Storage','Other')
| join kind=leftouter (Resources | project _jid = tolower(id), _resLocation = location) on \$left.resourceId == \$right._jid
| extend location = iif(isempty(healthLocation), _resLocation, healthLocation)
| project resourceId, availabilityState, occurredTime, reasonType, location, ServiceCategory
| order by location asc, ServiceCategory asc, occurredTime desc" --subscriptions $SUBS --first 1000 -o json
```

The `leftouter` join backfills location from `Resources` when
`properties.location` is empty (common for Unavailable/Unknown states).

HealthResources is **current-state only** — historical outages require Step 4.

## Step 3 — Service Health incidents (servicehealthresources)

`ImpactStartTime` / `ImpactMitigationTime` are **.NET ticks** — cast to string
to avoid Int64 precision loss. Convert in Python (Step 5).

```bash
az graph query -q "servicehealthresources
| where type =~ 'microsoft.resourcehealth/events'
| where tostring(properties.EventType) =~ 'ServiceIssue'
| extend status = tostring(properties.Status)
| extend summary = tostring(properties.Summary)
| extend eventLevel = tostring(properties.EventLevel)
| extend impactedServices = properties.Impact
| extend ImpactStartTime = tostring(properties.ImpactStartTime)
| extend ImpactMitigationTime = tostring(properties.ImpactMitigationTime)
| project id, name, Title = tostring(properties.Title), status, summary, eventLevel, impactedServices, ImpactStartTime, ImpactMitigationTime" --subscriptions $SUBS --first 1000 -o json
```

De-duplicate by `name` (tracking ID). Region names in `impactedServices` are
display names (`"East US"`); the Step 5 script's `norm_region()` normalises
them to match location codes (`"eastus"`).

## Step 4 — Activity Log (history)

Requires the subscription diagnostic setting from Prerequisites. Choose the
Log Analytics workspace in priority order:

1. **Explicit override** — `WORKSPACE OVERRIDE:` directive in the prompt.
2. **Agent connector** — if a Log Analytics workspace connector is configured.
3. **Discover** from diagnostic export:

```bash
WS_ID=$(az monitor diagnostic-settings subscription list \
  --query "value[?contains(to_string(logs), 'ResourceHealth')].workspaceId | [0]" -o tsv)
az monitor log-analytics workspace show --ids "$WS_ID" --query customerId -o tsv
```

Find the history boundary:

```kql
AzureActivity
| where CategoryValue in ("ResourceHealth", "ServiceHealth")
| summarize HistoryStart = min(TimeGenerated)
```

**Interpret the result and set the Step 5 inputs accordingly:**

- Returns a `HistoryStart` value -> set `HISTORY_START` to it **and**
  `HISTORY_AVAILABLE = True`.
- Returns **no rows / a null `HistoryStart`** -> the subscription has **no
  diagnostic setting** routing `ResourceHealth` / `ServiceHealth` to Log
  Analytics. Set `HISTORY_AVAILABLE = False`. The report then renders every
  month as **No data** (never a misleading 100%) and prints an action item to
  enable the diagnostic setting. Do **not** leave it as if availability were
  measured.

### Step 4a — Subscription-to-region mapping

```bash
az graph query -q "Resources
| where type in~ ('microsoft.compute/virtualmachines','microsoft.compute/virtualmachinescalesets','microsoft.sql/servers/databases','microsoft.sql/servers','microsoft.sql/managedinstances','microsoft.web/sites','microsoft.web/serverfarms','microsoft.storage/storageaccounts')
| summarize ResourceCount = count() by subscriptionId, location
| order by subscriptionId asc, location asc" --subscriptions $SUBS --first 1000 -o json
```

### Step 4b — Historical unhealthy events (monthly summary)

Use `contains` (not `has`) for substring matching in the `case` statement.
Extract resource type from `_ResourceId` path segments (not `Properties.type`).

```kql
let userInitCorrelations = AzureActivity
| where CategoryValue == "ResourceHealth"
| where TimeGenerated >= ago(365d)
| extend cause = tostring(parse_json(Properties).cause)
| where cause == "UserInitiated"
| distinct CorrelationId;
AzureActivity
| where CategoryValue == "ResourceHealth"
| where TimeGenerated >= ago(365d)
| where CorrelationId !in (userInitCorrelations)
| extend parsed = parse_json(Properties)
| extend availState = tostring(parsed.currentHealthStatus)
| where availState == "Unavailable"
| extend resId = tolower(_ResourceId)
| extend subId = tolower(tostring(split(resId, "/")[2]))
| where subId in ("<sub1>", "<sub2>", ...)
| extend segments = split(resId, "/")
| extend resType = strcat(tostring(segments[6]), "/", tostring(segments[7]))
| where resType in ("microsoft.compute/virtualmachines",
    "microsoft.sql/servers", "microsoft.sql/managedinstances",
    "microsoft.web/sites", "microsoft.web/serverfarms",
    "microsoft.storage/storageaccounts")
| extend ServiceCategory = case(
    resType contains "virtualmachine", "Compute",
    resType startswith "microsoft.sql/", "SQL DB",
    resType startswith "microsoft.web/", "Web Apps",
    resType contains "storageaccounts", "Storage", "Other")
| extend cause = tostring(parsed.cause)
| extend mo = format_datetime(TimeGenerated, "yyyy-MM")
| summarize UnhealthyEvents=count(), UniqueResources=dcount(resId) by mo, ServiceCategory, subId
| order by mo asc, ServiceCategory asc
```

Replace `<sub1>`, `<sub2>`, ... with actual subscription IDs from Step 0.
VMSS excluded. The `let` subquery excludes entire correlation groups containing
any UserInitiated event.

### Step 4c — Per-incident detail

Group by `CorrelationId` for one row per discrete incident. The `resolvedCause`
lookup replaces `cause: "Unknown"` with the actual cause from a later event.
Carry `CorrelationId` through to the script's `impacted_detail` rows — it is the
**connected incident id** surfaced in the Top 10 table and the downloadable CSV.

```kql
let userInitCorrelations = AzureActivity
| where CategoryValue == "ResourceHealth"
| where TimeGenerated >= ago(365d)
| extend cause = tostring(parse_json(Properties).cause)
| where cause == "UserInitiated"
| distinct CorrelationId;
let resolvedCause = AzureActivity
| where CategoryValue == "ResourceHealth"
| where TimeGenerated >= ago(365d)
| where CorrelationId !in (userInitCorrelations)
| extend cause = tostring(parse_json(Properties).cause)
| where cause != "Unknown" and cause != ""
| summarize ResolvedCause = take_any(cause) by CorrelationId;
AzureActivity
| where CategoryValue == "ResourceHealth"
| where TimeGenerated >= ago(365d)
| where CorrelationId !in (userInitCorrelations)
| extend parsed = parse_json(Properties)
| extend availState = tostring(parsed.currentHealthStatus)
| where availState == "Unavailable"
| extend cause = tostring(parsed.cause)
| extend resId = tolower(_ResourceId)
| extend subId = tolower(tostring(split(resId, "/")[2]))
| where subId in ("<sub1>", "<sub2>", ...)
| extend segments = split(resId, "/")
| extend resType = strcat(tostring(segments[6]), "/", tostring(segments[7]))
| where resType in ("microsoft.compute/virtualmachines",
    "microsoft.sql/servers", "microsoft.sql/managedinstances",
    "microsoft.web/sites", "microsoft.web/serverfarms",
    "microsoft.storage/storageaccounts")
| extend ServiceCategory = case(
    resType contains "virtualmachine", "Compute",
    resType startswith "microsoft.sql/", "SQL DB",
    resType startswith "microsoft.web/", "Web Apps",
    resType contains "storageaccounts", "Storage", "Other")
| lookup kind=leftouter resolvedCause on CorrelationId
| extend FinalCause = iif(isempty(ResolvedCause), cause, ResolvedCause)
| summarize
    Events = count(),
    ImpactStart = min(TimeGenerated),
    ImpactEnd = max(TimeGenerated),
    DurationMin = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated))
  by CorrelationId, resId, subId, ServiceCategory, FinalCause
| order by DurationMin desc
```

### Step 4d — Customer deallocate events (false-positive filter)

```kql
AzureActivity
| where CategoryValue == "Administrative"
| where OperationNameValue in~ (
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/powerOff/action")
| where ActivityStatusValue == "Success"
| project resId = tolower(_ResourceId),
    DeallocTime = TimeGenerated,
    Caller = Caller
| distinct resId, DeallocTime
| order by resId asc, DeallocTime asc
```

### Step 4e — Tag lookup (Resource Graph)

```bash
az graph query -q "Resources
| where type in~ ('microsoft.compute/virtualmachines','microsoft.compute/virtualmachinescalesets','microsoft.sql/servers/databases','microsoft.sql/servers','microsoft.sql/managedinstances','microsoft.web/sites','microsoft.web/serverfarms','microsoft.storage/storageaccounts')
| project id, name, resourceGroup, location, tags
| order by id asc" --subscriptions $SUBS --first 1000 -o json
```

Page with skip tokens if >1000 rows.

## Step 5 — Compute availability (run verbatim)

Run via `ExecutePythonCode`. Assign the JSON `data` arrays from previous steps
to the input variables — change **nothing else**.

Availability formula per (region, category, month) cell:

```
Availability % = (FleetMinutes - DowntimeMinutes) / FleetMinutes * 100
```

where `DowntimeMinutes` = sum of per-incident `DurationMin` from filtered
Step 4c data, and `FleetMinutes` = `resource_count * minutes_in_month`.

The deallocate filter runs **before** the availability calculation so SLA
Overview, heatmap, and Section 5 all use the same filtered dataset.

```python
# ============================================================
# SLA availability report — DETERMINISTIC. Do not edit logic.
# Paste the data arrays from each step below, then run.
# ============================================================
from datetime import datetime, timezone, timedelta
import calendar

# --- INPUTS ---
count_rows    = []   # Step 1: {location, ServiceCategory, ResourceCount}
health_rows   = []   # Step 2: {location, ServiceCategory, availabilityState, ...}
incident_rows = []   # Step 3: {name, Title, ImpactStartTime, ImpactMitigationTime, impactedServices, ...}
impacted_detail = [] # Step 4c: {resId, subId, ServiceCategory, cause, Events, ImpactStart, ImpactEnd, DurationMin, CorrelationId}
vm_tags       = []   # Step 4e: {id, name, resourceGroup, location, tags}
deallocate_events = [] # Step 4d: {resId, DeallocTime}
sub_region_map = []  # Step 4a: {subscriptionId, location, ResourceCount}
REPORT_MONTHS = 12   # max months (capped by HISTORY_START)
HISTORY_START = None # ISO-8601 str or None
HISTORY_AVAILABLE = None  # Step 4 boundary result: True if the Activity Log
                          # returned ResourceHealth/ServiceHealth records; False
                          # if NONE were found (diagnostic setting not enabled)
                          # -> months render as "No data", NOT a misleading 100%.
                          # None = unknown (treated as no history, the honest default).

CATEGORIES   = ["Compute", "SQL DB", "Web Apps", "Storage"]
SVC_KEYWORDS  = {
    "Compute": ["virtual machine", "compute", "vm scale"],
    "SQL DB":  ["sql"],
    "Web Apps":["app service", "web app", "web sites"],
    "Storage": ["storage"],
}

def ticks_to_dt(ticks):
    if ticks in (None, "", "0"): return None
    try: t = int(ticks)
    except (TypeError, ValueError): return None
    if t <= 0: return None
    dt = datetime(1, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=t // 10)
    return dt if dt.year >= 2000 else None

def incident_category(inc):
    text = (str(inc.get("impactedServices", "")) + " " + str(inc.get("Title", ""))).lower()
    return [c for c, kws in SVC_KEYWORDS.items() if any(k in text for k in kws)]

def norm_region(name):
    return "".join(str(name).lower().split()) if name else ""

def incident_regions(inc):
    out = set()
    imp = inc.get("impactedServices")
    if isinstance(imp, list):
        for svc in imp:
            if not isinstance(svc, dict): continue
            for rg in svc.get("ImpactedRegions", []) or []:
                if isinstance(rg, dict):
                    name = rg.get("ImpactedRegion") or rg.get("RegionName")
                else:
                    name = rg
                if name: out.add(norm_region(name))
    return out

now = datetime.now(timezone.utc)
_hist = None
if HISTORY_START:
    try:
        _hist = datetime.fromisoformat(str(HISTORY_START).replace("Z", "+00:00"))
        if _hist.tzinfo is None: _hist = _hist.replace(tzinfo=timezone.utc)
    except ValueError:
        _hist = None

if _hist is not None:
    hist_months = (now.year - _hist.year) * 12 + (now.month - _hist.month) + 1
    REPORT_MONTHS = min(REPORT_MONTHS, max(1, hist_months))

# NO_HISTORY: there is NO durable Resource Health history to measure against --
# either diagnostics were flagged disabled (HISTORY_AVAILABLE False) or no history
# boundary was found at all. Without history we CANNOT measure availability, so
# every month renders as "No data" (never a misleading 100%). Honest default:
# unless a boundary was found (_hist set) or history was explicitly confirmed.
NO_HISTORY = (HISTORY_AVAILABLE is False) or (HISTORY_AVAILABLE is not True and _hist is None)

months = []
y, m = now.year, now.month
for _ in range(REPORT_MONTHS):
    months.append((y, m)); m -= 1
    if m == 0: m = 12; y -= 1
months.reverse()
month_labels = [f"{calendar.month_abbr[m]} {y}" for (y, m) in months]

def month_minutes(y, m):
    return calendar.monthrange(y, m)[1] * 24 * 60

counts = {}
for r in count_rows:
    k = (norm_region(r["location"]), r["ServiceCategory"])
    counts[k] = counts.get(k, 0) + int(r["ResourceCount"])
regions = sorted({loc for (loc, _) in counts})

_sub_region_total = {}
for sr in sub_region_map:
    sid = sr.get("subscriptionId", "").lower()
    _sub_region_total[sid] = _sub_region_total.get(sid, 0) + int(sr.get("ResourceCount", 0))
_sub_primary = {}
for sr in sub_region_map:
    sid = sr.get("subscriptionId", "").lower()
    loc = norm_region(sr.get("location", ""))
    cnt = int(sr.get("ResourceCount", 0))
    if sid not in _sub_primary or cnt > _sub_primary[sid][1]:
        _sub_primary[sid] = (loc, cnt)

tag_map = {}
for t in vm_tags:
    tag_map[t.get("id", "").lower()] = t

def _get_location(resId, subId):
    t = tag_map.get(resId.lower(), {})
    loc = t.get("location", "")
    if loc: return norm_region(loc)
    pr = _sub_primary.get(subId.lower())
    return pr[0] if pr else ""

seen, incidents = set(), []
for inc in incident_rows:
    nm = inc.get("name")
    if nm in seen: continue
    seen.add(nm)
    s = ticks_to_dt(inc.get("ImpactStartTime")); e = ticks_to_dt(inc.get("ImpactMitigationTime"))
    incidents.append({**inc, "_start": s, "_end": e,
                      "_regions": incident_regions(inc), "_cats": incident_category(inc)})

# --- DEALLOCATE FILTER (before availability) ---
dealloc_days = set()
for de in deallocate_events:
    rid = de.get("resId", "").lower()
    dt_str = str(de.get("DeallocTime", ""))[:10]
    if rid and dt_str:
        dealloc_days.add((rid, dt_str))
        try:
            _d = datetime.strptime(dt_str, "%Y-%m-%d")
            dealloc_days.add((rid, (_d + timedelta(days=1)).strftime("%Y-%m-%d")))
        except ValueError:
            pass

_filtered_detail = []
_excluded_dealloc = 0
for d in impacted_detail:
    rid = d.get("resId", "").lower()
    impact_day = str(d.get("ImpactStart", ""))[:10]
    if (rid, impact_day) in dealloc_days:
        _excluded_dealloc += 1
        continue
    _filtered_detail.append(d)
impacted_detail = _filtered_detail

# --- PER-MONTH DOWNTIME ---
monthly_downtime = {}
for d in impacted_detail:
    rid = d.get("resId", "").lower()
    sub = d.get("subId", "")
    cat = d.get("ServiceCategory", "")
    dur = int(d.get("DurationMin", 0))
    start_str = str(d.get("ImpactStart", ""))
    try:
        if 'T' in start_str:
            _dt = datetime.fromisoformat(start_str.split('+')[0].replace('Z',''))
        else:
            _dt = datetime.strptime(start_str[:10], "%Y-%m-%d")
        mo_y, mo_m = _dt.year, _dt.month
    except (ValueError, IndexError):
        continue
    region = _get_location(rid, sub)
    if not region: continue
    key = (region, cat, mo_y, mo_m)
    monthly_downtime[key] = monthly_downtime.get(key, 0) + dur

def availability(region, cat, y, mo):
    rc = counts.get((region, cat), 0)
    if rc == 0: return None
    fleet_min = rc * month_minutes(y, mo)
    down = monthly_downtime.get((region, cat, y, mo), 0)
    return max(0.0, ((fleet_min - down) / fleet_min) * 100)

def has_history(y, mo):
    if _hist is None: return True
    m_end = datetime(y, mo, calendar.monthrange(y, mo)[1], 23, 59, tzinfo=timezone.utc)
    return m_end >= _hist

SLA_BANDS = [
    (99.9, 0, "\U0001F7E2", "#2E7D32", ">=99.9% (no credit)"),
    (99.0, 1, "\U0001F7E1", "#F2C744", "<99.9% (10% credit)"),
    (95.0, 2, "\U0001F7E0", "#E8862E", "<99% (25% credit)"),
    (0.0,  3, "\U0001F534", "#C62828", "<95% (100% credit)"),
]

def band_index(p):
    for thr, idx, _emoji, _hex, _lbl in SLA_BANDS:
        if p >= thr: return idx
    return 3

# "No data" band: a month with no collected Resource Health history. Distinct
# from N/A (no resources). Rendered slate, never counted toward availability.
NODATA_INDEX = len(SLA_BANDS)  # 4

def band(p):
    if p is None: return "N/A"
    return f"{SLA_BANDS[band_index(p)][2]} {p:.4f}%"

# --- SECTION 1: SLA Overview ---
print("> **Estimation only -- not an official SLA measurement.** Validate against your own monitoring.\n")
print(f"_Reporting window: {month_labels[0]} -- {month_labels[-1]} . Regions: {len(regions)} . Generated: {now:%Y-%m-%d %H:%M UTC}_\n")
if _hist is not None:
    print(f"_Resource Health history begins {_hist:%Y-%m-%d}. Report window limited to {REPORT_MONTHS} measured months._\n")
if NO_HISTORY:
    print("> **\u26a0\ufe0f No Resource Health history available.** No `ResourceHealth` / `ServiceHealth` "
          "records were found in the Activity Log, so per-month availability **cannot be measured** "
          "and is shown as **No data** \u2014 it is **not** assumed to be 100%. **Action required:** enable a "
          "subscription-level **diagnostic setting** routing `ResourceHealth` and `ServiceHealth` to a "
          "Log Analytics workspace (command in **Health Timeline** below). Future reports will then show "
          "measured availability as history accrues._\n")
print("_Legend: \U0001F7E2 >=99.9% no credit . \U0001F7E1 <99.9% 10% . \U0001F7E0 <99% 25% . \U0001F534 <95% 100% . N/A no resources . \U0001F537 No data (history not collected)_\n")
print("## 1. SLA Overview\n")
hdr = ["Region", "Service", "Resource Count"] + month_labels
print("| " + " | ".join(hdr) + " |")
print("|" + "---|" * len(hdr))
breaches = []
for region in regions:
    for cat in CATEGORIES:
        rc = counts.get((region, cat), 0)
        cells = []
        for (yy, mm) in months:
            if rc == 0:
                cells.append("N/A")
                continue
            if NO_HISTORY or not has_history(yy, mm):
                cells.append("No data")  # no collected history -> not assessed (NOT assumed 100%)
                continue
            p = availability(region, cat, yy, mm)
            cells.append(band(p))
            if p is not None and p < 99.9:
                breaches.append((region, cat, f"{calendar.month_abbr[mm]} {yy}", p))
        print("| " + " | ".join([region, cat, str(rc)] + cells) + " |")

# --- SECTION 2: Incidents & Alerts (last month) ---
print("\n## 2. Incidents & Alerts (last month)\n")
last_y, last_m = months[-1]
recent = [i for i in incidents if i["_start"] and (i["_start"].year, i["_start"].month) == (last_y, last_m)]
if not recent:
    print("_No ServiceIssue incidents recorded in the last month._")
else:
    print("| Status | Title | Impact Start | Impact End | Regions | Summary |")
    print("|---|---|---|---|---|---|")
    for i in sorted(recent, key=lambda x: x["_start"]):
        print(f"| {i.get('status','')} | {str(i.get('Title',''))[:60]} | "
              f"{i['_start']:%Y-%m-%d %H:%M} | {(i['_end'].strftime('%Y-%m-%d %H:%M') if i['_end'] else 'ongoing')} | "
              f"{', '.join(sorted(i['_regions'])) or 'n/a'} | {str(i.get('summary',''))[:80]} |")

# --- SECTION 3: Health Timeline ---
print("\n## 3. Health Timeline (full window)\n")
if NO_HISTORY:
    print("Availability could not be measured \u2014 no Resource Health history is being collected.\n")
    print("**Action required:** enable a subscription-level diagnostic setting so future reports can measure availability and detect SLA-credit breaches:\n")
    print("```bash")
    print("az monitor diagnostic-settings subscription create \\")
    print("  --name sla-resourcehealth \\")
    print("  --location <region> \\")
    print("  --workspace \"<workspace-resource-id>\" \\")
    print("  --subscription <subscription-id> \\")
    print("  --logs '[{\"category\":\"ResourceHealth\",\"enabled\":true},{\"category\":\"ServiceHealth\",\"enabled\":true}]'")
    print("```")
elif not breaches:
    print("All in-scope regions and services met the 99.9% SLA threshold (no service credit due).")
else:
    print("Cells below 99.9% (SLA service credit may apply):\n")
    for region, cat, label, p in breaches:
        print(f"- {SLA_BANDS[band_index(p)][2]} **{region} / {cat} / {label}** -- {p:.4f}% ({SLA_BANDS[band_index(p)][4]})")

# --- HEATMAP ---
heatmap_rows, heatmap_pct, heatmap_band, heatmap_counts = [], [], [], []
for region in regions:
    for cat in CATEGORIES:
        rc = counts.get((region, cat), 0)
        pct_row, band_row = [], []
        for (yy, mm) in months:
            if rc == 0:
                pct_row.append(None); band_row.append(None)
            elif NO_HISTORY or not has_history(yy, mm):
                pct_row.append(None); band_row.append(NODATA_INDEX)
            else:
                p = availability(region, cat, yy, mm)
                pct_row.append(round(p, 4) if p is not None else None)
                band_row.append(band_index(p) if p is not None else None)
        heatmap_rows.append(f"{region} / {cat} ({rc})")
        heatmap_pct.append(pct_row)
        heatmap_band.append(band_row)
        heatmap_counts.append(rc)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap, BoundaryNorm
from matplotlib.patches import Patch

NA_COLOR = "#BDBDBD"
NODATA_COLOR = "#90A4AE"
band_cmap = ListedColormap([b[3] for b in SLA_BANDS] + [NODATA_COLOR])
band_cmap.set_bad(NA_COLOR)
band_norm = BoundaryNorm([0, 1, 2, 3, 4, 5], band_cmap.N)

nrows, ncols = len(heatmap_rows), len(month_labels)
Z = np.ma.masked_invalid(np.array(
    [[(np.nan if b is None else b) for b in row] for row in heatmap_band],
    dtype=float))

fig_w = max(8.0, 0.95 * ncols + 3.0)
fig_h = max(2.5, 0.55 * nrows + 2.0)
fig, ax = plt.subplots(figsize=(fig_w, fig_h))
ax.imshow(Z, aspect="auto", cmap=band_cmap, norm=band_norm)

ax.set_xticks(range(ncols))
ax.set_xticklabels(month_labels, rotation=45, ha="right", fontsize=8)
ax.set_yticks(range(nrows))
ax.set_yticklabels(heatmap_rows, fontsize=8)
ax.set_title(
    f"Azure Estimated Availability (%) -- {month_labels[0]} to {month_labels[-1]}",
    fontsize=11, fontweight="bold", loc="left")
ax.set_xticks(np.arange(-0.5, ncols, 1), minor=True)
ax.set_yticks(np.arange(-0.5, nrows, 1), minor=True)
ax.grid(which="minor", color="white", linewidth=1.5)
ax.tick_params(which="minor", length=0)

for i in range(nrows):
    for j in range(ncols):
        b = heatmap_band[i][j]
        p = heatmap_pct[i][j]
        if heatmap_counts[i] == 0:
            txt, fg = "N/A", "#666666"
        elif b == NODATA_INDEX:
            txt, fg = "n/d", "white"
        elif b is None:
            txt, fg = "--", "#333333"
        else:
            txt = f"{p:.2f}" if p is not None else "--"
            fg = "black" if b == 1 else "white"
        ax.text(j, i, txt, ha="center", va="center", fontsize=7, color=fg)

legend_handles = [Patch(facecolor=b[3], label=b[4]) for b in SLA_BANDS] + \
                 [Patch(facecolor=NA_COLOR, label="N/A (no resources)"),
                  Patch(facecolor=NODATA_COLOR, label="No data (history not collected)")]
ax.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(0.5, -0.22),
          ncol=6, fontsize=7, frameon=False)

import os, tempfile
HEATMAP_PNG = os.path.join(tempfile.gettempdir(), "sla_availability_heatmap.png")
fig.savefig(HEATMAP_PNG, dpi=150, bbox_inches="tight")
plt.close(fig)
print("\n## 4. Heatmap\n")
print(f"Heatmap image saved -- ATTACH THIS FILE to the report: {HEATMAP_PNG}")
print("Do NOT re-plot with PlotHeatmap (wrong palette and column ordering).")

# --- SECTION 5: Impacted Resource Detail (Top 10 + downloadable CSV) ---
if impacted_detail:
    print("\n## 5. Impacted Resource Detail\n")
    print("Resources that reported `Unavailable` Resource Health events")
    print("(excluding UserInitiated and customer-deallocated VMs).\n")

    if _excluded_dealloc > 0:
        print(f"_Excluded {_excluded_dealloc} deallocate false positive(s)._\n")

    # Per-incident rows (one row per CorrelationId x resource) -> full CSV export.
    rows_out = []
    for d in impacted_detail:
        rid = d.get("resId", "")
        t = tag_map.get(rid.lower(), {})
        parts = rid.rstrip("/").split("/")
        res_name = t.get("name", parts[-1] if parts else rid)
        rg = t.get("resourceGroup", "")
        if not rg and len(parts) > 4:
            rg = parts[4]
        rows_out.append({
            "name": res_name,
            "resId": rid,
            "rg": rg,
            "sub": d.get("subId", ""),
            "cat": d.get("ServiceCategory", ""),
            "cause": d.get("cause", ""),
            "events": int(d.get("Events", 0)),
            "start": str(d.get("ImpactStart", ""))[:19],
            "end": str(d.get("ImpactEnd", ""))[:19],
            "dur": int(d.get("DurationMin", 0)),
            "incident_id": d.get("CorrelationId", ""),
        })
    rows_out.sort(key=lambda r: -r["dur"])

    # Write the downloadable CSV of ALL impacted resources.
    import csv
    CSV_PATH = os.path.join(tempfile.gettempdir(), "sla_impacted_resources.csv")
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as _f:
        _w = csv.writer(_f)
        _w.writerow(["Name", "ResourceId", "ResourceGroup", "SubscriptionId",
                     "ServiceCategory", "Reason", "Events",
                     "ImpactStartUTC", "ImpactEndUTC", "DurationMinutes",
                     "IncidentId"])
        for r in rows_out:
            _w.writerow([r["name"], r["resId"], r["rg"], r["sub"], r["cat"],
                         r["cause"], r["events"], r["start"], r["end"],
                         r["dur"], r["incident_id"]])

    # Top 10 resources by TOTAL downtime (aggregated across their incidents).
    per_res = {}
    for r in rows_out:
        a = per_res.get(r["resId"])
        if a is None:
            a = {"name": r["name"], "rg": r["rg"], "sub": r["sub"],
                 "cat": r["cat"], "dur": 0, "events": 0,
                 "incidents": set(), "causes": set(),
                 "start": r["start"], "end": r["end"]}
            per_res[r["resId"]] = a
        a["dur"] += r["dur"]
        a["events"] += r["events"]
        if r["incident_id"]: a["incidents"].add(r["incident_id"])
        if r["cause"]: a["causes"].add(r["cause"])
        if r["start"] and (not a["start"] or r["start"] < a["start"]): a["start"] = r["start"]
        if r["end"] and r["end"] > a["end"]: a["end"] = r["end"]
    top10 = sorted(per_res.values(), key=lambda x: -x["dur"])[:10]

    print("### Top 10 impacted resources by total downtime\n")
    print("| # | Resource | Resource Group | Subscription | Category | Reason(s) | Incidents | Total Downtime (min) | First Impact (UTC) | Last Impact (UTC) |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for n, a in enumerate(top10, 1):
        reasons = ", ".join(sorted(a["causes"])) or "Unknown"
        inc = ", ".join(sorted(a["incidents"])) or "-"
        print(f"| {n} | {a['name']} | {a['rg']} | {a['sub']} | {a['cat']} | "
              f"{reasons[:60]} | {inc[:40]} | {a['dur']} | {a['start']} | {a['end']} |")

    print(f"\n_Top 10 of {len(per_res)} impacted resource(s); {len(rows_out)} total impact incident-row(s)._")
    print(f"\n**Downloadable CSV (all impacted resources) -- ATTACH THIS FILE to the report:** {CSV_PATH}")
    print("_CSV columns: Name, ResourceId, ResourceGroup, SubscriptionId, ServiceCategory, Reason, Events, ImpactStartUTC, ImpactEndUTC, DurationMinutes, IncidentId._")
else:
    print("\n## 5. Impacted Resource Detail\n")
    print("_No impacted resource detail available. Run Step 4c to populate._")
```

## Step 5b — Accuracy rubberduck of the Top 10 (cross-check with utilization metrics)

After Step 5, **rubberduck the Top 10 impacted resources** (the table the script
printed in Section 5) to verify each claimed impact is real. A genuinely
*Unavailable* resource cannot serve traffic — so if utilization/availability
metrics show it was actively running and reachable **during the claimed impact
window**, the Resource Health event is suspect and we must say so transparently.

For each of the Top 10, query metrics over a window of **6h before -> 6h after**
the impact (use `AnalyzeMetrics` or `az monitor metrics list`), picking the
signal that proves reachability for that resource type:

| Category | Resource type | Primary signal | Corroborating signals |
|----------|---------------|----------------|------------------------|
| Compute  | `Microsoft.Compute/virtualMachines` | `VmAvailabilityMetric` (Average) | `Percentage CPU`, `Network In/Out Total` |
| Compute  | `Microsoft.Compute/virtualMachineScaleSets` | `VmAvailabilityMetric` | `Percentage CPU` |
| SQL DB   | `Microsoft.Sql/servers/databases` | `cpu_percent` / `dtu_consumption_percent` | `connection_successful`, `storage_percent` |
| Web Apps | `Microsoft.Web/sites` | `Requests` + `Http5xx` | `CpuTime`, `HealthCheckStatus` |
| Storage  | `Microsoft.Storage/storageAccounts` | `Availability` (Average %) | `Transactions`, `SuccessE2ELatency` |

Interpretation (per resource, during the impact window):

- **Confirmed** — the signal shows the resource was down/unreachable (VM
  `VmAvailabilityMetric` ~0, Storage `Availability` < 100%, Web Apps serving
  only `Http5xx` with no successful `Requests`, SQL no successful connections).
- **Contradicted (transparency flag)** — the resource was clearly *up and
  serving* during the window (steady non-zero CPU, successful requests/
  transactions, `VmAvailabilityMetric` = 1.0, Storage `Availability` = 100%).
  The Resource Health *Unavailable* event likely does **not** reflect real
  customer impact (platform annotation, health-probe blip, metadata event).
  **Disclose it** — keep the row but mark it Contradicted.
- **Customer-off** — `VmAvailabilityMetric` all-zero with no CPU/network and a
  nearby deallocate/stop -> false positive; remove from Section 5 totals.
- **Inconclusive** — metric missing, resource deleted (404), or flat at the
  default with no corroboration -> cannot verify; state so.

Emit a **Section 5a** table and be explicit about anything we could not stand
behind:

```markdown
### 5a. Accuracy validation -- Top 10 rubberduck

| # | Resource | Category | Claimed Downtime (min) | Signal checked | Observed during window | Verdict |
|---|---|---|---|---|---|---|
```

Transparency rule: if **any** Top 10 row is *Contradicted* or *Customer-off*,
add a short note under the table naming those resources and stating that their
Resource Health events were not corroborated by utilization metrics, so the
real availability impact is likely lower than the Resource Health-derived
estimate. Only *Customer-off* rows are removed from totals; *Contradicted* rows
stay but are flagged. Step 5b adjusts Sections 5 and 5a only — it does NOT change
the SLA Overview or heatmap (those remain the deterministic Resource Health
estimate).

## Step 6 — Report output

Attach the heatmap PNG at the top of the report. Do **not** call `PlotHeatmap`
(wrong palette, alphabetical column sort). The script renders the heatmap with
correct SLA-credit-tier colours and chronological months.

The script also writes a **downloadable CSV** of all impacted resources
(`sla_impacted_resources.csv`, path printed in Section 5). **Attach that CSV**
to the report alongside the heatmap PNG.

Report sections (in order):
1. **SLA Overview** — region × category, one column per month, colour-banded
   (`No data` = month has no collected Resource Health history; `N/A` = no resources)
2. **Incidents & Alerts** — Service Health incidents from the last month
3. **Health Timeline** — SLA breach callouts across the full window
4. **Heatmap** — attached PNG
5. **Impacted Resource Detail** — Top 10 by total downtime + downloadable CSV (all impacted resources)
5a. **Accuracy validation** — Top 10 rubberducked against utilization/availability metrics (transparency flags)