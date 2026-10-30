# Azure Tag Governance Executive Report

- Run: `2026-10-30T164232000Z-f90f51d0`
- Profile: `1.0.0`
- Resources assessed: 470
- Findings: 5170
- Evidence gaps: 0
- Profile conflicts: 0
- Coverage complete: true
- Assessment mode: approved standards (no AI rule promotion)
- Standard: `cloud-tagging-standard-provisional-demo`, version `1.0.0`
- Standard source: `'Cloud Tagging Standard.xlsx' sheet 'Azure Tag Standard' (sha256 46e4915fb4981f1cb6eef8f04c07129884f3ebc551f8094e3b1440e2b36e581e; A10 'Last updated March 2023'). Agent translation for a PROVISIONAL DEMO; standardId/version are agent-assigned. Not customer acceptance.`
- Approval reference: `System Administrator (100320063A1C7E15) - provisional reviewer, not standard owner` at `2026-10-30T14:59:05Z`
- Standard digest: `6fcd2cbc1e298ecbab4ab4ce1302430d125a638554a9a36806210b91f4132bf0`
- Approval status (declared, not authenticated): `PROVISIONAL`
- Approval evidence: `Reviewer 'System Administrator (100320063A1C7E15)' selected 'Approve ce6b8eae…1e24' in SRE Agent thread ea37eae6-9280-4cf9-9526-c44be6b7d3e9 for content digest ce6b8eaed6e0c4cea0971e6b2be22591f669137995696e6e89767b6b85461e24; provisional demo only, NOT customer acceptance`
- Collection coverage complete: true
- Supplied-check assessment coverage complete: false
- Check outcomes: `{"FAIL": 5170, "NOT_EVALUATED": 470}`
- Completeness refers to supplied checks only, not full customer acceptance.
- Resource outcomes: `{"NONCOMPLIANT": 470}`

## Detailed results

- [Grouped engineering report](engineering-report.md)
- [All findings (CSV)](findings.csv)
- [All check outcomes (CSV)](check-outcomes.csv)
- [Complete assessment (JSON)](assessment.json)

## Limitations

- Resource Graph is eventually consistent and findings were not re-read through ARM.
- Finding accuracy has not been quantitatively or qualitatively human-benchmarked.
- Compliance covers supplied standards only; no ServiceNow or ownership accuracy was verified.
- NOT_ASSESSED: `Azure Tag Standard!A12`: `No APPID value format is defined (D12 is only an example). APPID existence and eligibility (C12: Operational Status Live/Planning/Legacy) require ServiceNow lookup, not implemented.` (source `Azure Tag Standard!C12, Azure Tag Standard!D12`)
- NOT_ASSESSED: `Azure Tag Standard!A15,A17,A19,A21:A25`: `Values of CMDB-sourced tags (Application Name, Business Criticality, Data Classification, Primary Business Capability, Regulatory Controlled Information, Support Group, TIS Application Owner, TIS Portfolio Executive) were not compared with ServiceNow CMDB; no allowed-value lists are defined for them (examples only).` (source `Azure Tag Standard!C15,C17,C19,C21:C25`)
- NOT_ASSESSED: `Azure Tag Standard!A18`: `CreatedOnDate value format is not defined ('UTC date/time', automated); only presence is checked.` (source `Azure Tag Standard!C18, Azure Tag Standard!D18`)
- NOT_ASSESSED: `No tagging-standard requirement`: `The standard defines no resource or resource-group naming conventions; naming is not assessed.` (source `Azure Tag Standard (absence of rule)`)
- NOT_ASSESSED: `Azure Tag Standard!A22`: `Example value '<blank>' (D22) is ambiguous (empty value vs literal text); presence is checked and any present value, including blank, satisfies presence.` (source `Azure Tag Standard!D22`)
- NOT_ASSESSED: `Azure Tag Standard!A4`: `A4 describes an inherit-from-resource-group policy; inheritance behaviour is not assessed.` (source `Azure Tag Standard!A4`)
- NOT_ASSESSED: `No tagging-standard requirement`: `The tagging standard defines no leading/trailing whitespace rule (ATG-REQ-007 is in the separate requirements workbook, not this standard); whitespace defects are not reported.` (source `Azure Tag Standard (absence of rule)`)
- UNRESOLVED: `Azure Tag Standard!A13`: `'Allocation' is listed under A6 'required tags' but B13 describes it as experimental; mandatory status and applicability await the standard owner. Excluded from scoring; not waived and not passed. Allocation percentages/shared-service applicability not inferred.` (source `Azure Tag Standard!A6, Azure Tag Standard!B13`)

No Azure resources were changed.
