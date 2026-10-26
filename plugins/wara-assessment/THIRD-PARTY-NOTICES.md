# Third-party notices: wara-assessment

The dependency modules below are downloaded at run time from
their upstream sources at the pinned versions in
[`skills/wara-assessment/config/dependencies.json`](skills/wara-assessment/config/dependencies.json),
and used unmodified. Their licences apply to that use. The separately attributed reporting
adaptation and filled-template outputs are described below.

| Component | Upstream | Pinned | Licence | How it is used |
|---|---|---|---|---|
| Well-Architected Reliability Assessment (WARA) | https://github.com/Azure/Well-Architected-Reliability-Assessment | commit `86832273f857b7298b625b26d18e2e0dbb06714c` (v1.0.6) or Gallery `WARA` 1.0.6 | MIT, Copyright (c) 2024 Microsoft Azure | `Start-WARACollector`, `Start-WARAAnalyzer`; the bundled in-scope resource-type snapshot CSV is read as input |
| Azure Proactive Resiliency Library v2 (APRL) | https://github.com/Azure/Azure-Proactive-Resiliency-Library-v2 | commit `69d73cbdc2729f5e94ab1184304ef4b9a5119ba2` (overridable) | MIT, Copyright (c) Microsoft Corporation | `recommendations.yaml` and `kql/*.kql` are read to build WARA's recommendation input |
| Az.Accounts | https://www.nuget.org/packages/Az.Accounts / PowerShell Gallery | 3.0.4 | Azure PowerShell licence (https://aka.ms/azps-license) | Authentication and `Invoke-AzRestMethod` |
| Az.ResourceGraph | PowerShell Gallery | 1.0.0 (Gallery mode only) | Azure PowerShell licence | `Search-AzGraph` in Gallery mode |
| ImportExcel | https://github.com/dfinke/ImportExcel | commit `5387c061461c811d106b125588f064c4739342cb` (7.8.10) | Apache License 2.0 | Required by `Start-WARAAnalyzer` |

## Original work in this plugin

`Invoke-WaraRun.ps1`, `build_recommendation_data.py`, `normalize_findings.py`, `prioritize.py`, the
`Az.ResourceGraph` shim (an independent implementation of the `Search-AzGraph` subset WARA uses, over the
public Azure Resource Graph REST API; it contains no Azure PowerShell source), configuration, skill and
extras are original work under this repository's [MIT licence](../../LICENSE).

## Adapted reporting assets (0.2.0)

`generate_reports.py` ports WARA's reporting aggregation and template-filling procedures from
`src/modules/wara/reports/3_wara_reports_generator.ps1` at revision
`86832273f857b7298b625b26d18e2e0dbb06714c`. Its PPTX and Assessment Findings XLSX outputs
adapt WARA's `Mandatory - Executive Summary presentation - Template.pptx` and
`Assessment-Findings-Report-v1.xlsx`. Native charts/static summaries replace COM pivots;
the Word report and advisory environment classifier are additions.

These are adapted assets, not entirely original reporting work. Generated reports redistribute
filled upstream templates. Keep the generated `wara-report-NOTICE.txt` with those outputs; it
retains Copyright (c) 2024 Microsoft Azure and the full MIT permission notice.
See [reporting lineage](../../docs/source-map.md#wara-020-reporting-lineage).

The shim is **not** a Microsoft module. It is loaded only in restricted mode when no real
`Az.ResourceGraph` module is installed, and every run that uses it records this in `run.json`.
