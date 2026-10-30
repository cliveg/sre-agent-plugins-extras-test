# Azure Tag Governance Engineering Report

- Run: `2026-10-30T164232000Z-f90f51d0`
- Profile digest: `93df69db367f0b5ca777bc4b44379d9e14344d98d54a2547019fc13bddc54300`
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

## Summary

- Collected objects: 470
- Finding records: 5170
- Affected objects with findings: 470
- Finding counts, affected-object counts and check counts are different measures.
- Samples show up to 3 deterministic examples per group, not statistical samples.

## Complete detail

- [All findings (CSV)](findings.csv)
- [All check outcomes (CSV)](check-outcomes.csv)
- [Complete assessment (JSON)](assessment.json)
- [Effective rules and exceptions (JSON)](governance-profile.json)
- CSV rows retain all findings/check outcomes; this report groups repeated detail.
- CSV text is spreadsheet-escaped; assessment JSON retains original values.

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
- Severity and priority are engine defaults, not customer-contextual risk judgments.

## Grouped findings

### `required-appid`: `Required tag 'APPID' is missing`

- Requirement: `Azure Tag Standard!A12`; section `Azure Tag Standard!A12 'APPID': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `APPID`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "APPID"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-12abced2678390d6`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-be5b7a38b56cb49c`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-c01851879afeb54d`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-appid`.

### `required-application-name`: `Required tag 'Application Name' is missing`

- Requirement: `Azure Tag Standard!A15`; section `Azure Tag Standard!A15 'Application Name': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `Application Name`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "Application Name"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-52716181c6afcb67`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-b80b4017034cfca7`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-3dc751ee7490fe16`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-application-name`.

### `required-business-criticality`: `Required tag 'Business Criticality' is missing`

- Requirement: `Azure Tag Standard!A17`; section `Azure Tag Standard!A17 'Business Criticality': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `Business Criticality`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "Business Criticality"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-140d76a080f87dda`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-7cca64df4ce26cb1`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-e2a0a0f5927604b4`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-business-criticality`.

### `required-createdondate`: `Required tag 'CreatedOnDate' is missing`

- Requirement: `Azure Tag Standard!A18`; section `Azure Tag Standard!A18 'CreatedOnDate': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `CreatedOnDate`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "CreatedOnDate"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-80087470108f4f9c`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-cfdde7ed7cc3165a`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-b627fa156d6fb2fe`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-createdondate`.

### `required-data-classification`: `Required tag 'Data Classification' is missing`

- Requirement: `Azure Tag Standard!A19`; section `Azure Tag Standard!A19 'Data Classification': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `Data Classification`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "Data Classification"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-2df41a527e92d9fa`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-003e0a965f8bf23b`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-7c4228c87c7af458`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-data-classification`.

### `required-environment-type`: `Required tag 'Environment Type' is missing`

- Requirement: `Azure Tag Standard!A14`; section `Azure Tag Standard!A14 'Environment Type': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `Environment Type`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "Environment Type"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-23a33d5852e6bd5b`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-dcb975081c24796e`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-978a5f3208919b24`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-environment-type`.

### `required-primary-business-capability`: `Required tag 'Primary Business Capability' is missing`

- Requirement: `Azure Tag Standard!A21`; section `Azure Tag Standard!A21 'Primary Business Capability': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `Primary Business Capability`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "Primary Business Capability"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-5edadf3c6c4958e6`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-ca7cf6dfd1e98fa2`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-b0cd5ba58c645ca2`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-primary-business-capability`.

### `required-regulatory-controlled-information`: `Required tag 'Regulatory Controlled Information' is missing`

- Requirement: `Azure Tag Standard!A22`; section `Azure Tag Standard!A22 'Regulatory Controlled Information': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `Regulatory Controlled Information`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "Regulatory Controlled Information"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-8a556e6b09b7f1d4`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-456f152939d0ec32`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-837229696b10a151`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-regulatory-controlled-information`.

### `required-support-group`: `Required tag 'Support Group' is missing`

- Requirement: `Azure Tag Standard!A23`; section `Azure Tag Standard!A23 'Support Group': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `Support Group`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "Support Group"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-f8b3b15b8b1ff62b`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-73c46e648ae2ceda`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-172cdda033754c38`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-support-group`.

### `required-tis-application-owner`: `Required tag 'TIS Application Owner' is missing`

- Requirement: `Azure Tag Standard!A24`; section `Azure Tag Standard!A24 'TIS Application Owner': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `TIS Application Owner`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "TIS Application Owner"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-6a5dec887cac59dc`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-38f78f327e5c0048`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-dbe8542b379a14b7`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-tis-application-owner`.

### `required-tis-portfolio-executive`: `Required tag 'TIS Portfolio Executive' is missing`

- Requirement: `Azure Tag Standard!A25`; section `Azure Tag Standard!A25 'TIS Portfolio Executive': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- Tag/rule kind: `TIS Portfolio Executive`
- Check: `atg.requiredTag`; version `1.1.0`
- Status: NONCOMPLIANT; severity: MEDIUM; priority: P2; evidence: OBSERVED
- Finding records: 470; affected objects: 470
- Scope: `{"scopeId": "/subscriptions/c6ff369b-f07e-48be-b675-274d61324591"}`
- Expected: `{"kind": "requiredTag", "normalization": {"emptyIsMissing": false, "keyCaseSensitive": true, "rejectSurroundingWhitespace": false, "trimWhitespace": false, "valueCaseSensitive": true, "whitespaceIsMissing": false}, "tagKey": "TIS Portfolio Executive"}`
- Example objects and finding IDs:
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`; `finding-94f2582497c39869`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`; `finding-6d4a93eae6d82677`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`; `finding-8ac97e0ee4b3ab29`
- Showing 3 of 470 findings; filter findings.csv by ruleId `required-tis-portfolio-executive`.

## Resource outcomes

Supplied checks only; see assessment.json for every object.
- NONCOMPLIANT: 470 objects; showing 3.
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/default-activitylogalerts/providers/microsoft.insights/actiongroups/agowner`
  - `/subscriptions/c6ff369b-f07e-48be-b675-274d61324591/resourcegroups/mcapsgovernance`

## Per-rule check outcomes

Counts are check outcomes, not findings. NOT_EVALUATED means the value check did not run.

| Rule | PASS | FAIL | UNKNOWN | EXEMPT | NOT_APPLICABLE | NOT_EVALUATED |
|---|---:|---:|---:|---:|---:|---:|
| `allowed-environment-type` | 0 | 0 | 0 | 0 | 0 | 470 |
| `required-appid` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-application-name` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-business-criticality` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-createdondate` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-data-classification` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-environment-type` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-primary-business-capability` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-regulatory-controlled-information` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-support-group` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-tis-application-owner` | 0 | 470 | 0 | 0 | 0 | 0 |
| `required-tis-portfolio-executive` | 0 | 470 | 0 | 0 | 0 | 0 |

## Approved rules

- `allowed-environment-type`: `allowedValues`; requirement `Azure Tag Standard!A43:A65`; section `Azure Tag Standard!A43:A65 'Environment Type - as per SNOW CMDB' (22 values; identical set in C14). Exact, case-sensitive; present blank or whitespace-only values fail; absent tag is NOT_EVALUATED.`
- `required-appid`: `requiredTag`; requirement `Azure Tag Standard!A12`; section `Azure Tag Standard!A12 'APPID': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-application-name`: `requiredTag`; requirement `Azure Tag Standard!A15`; section `Azure Tag Standard!A15 'Application Name': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-business-criticality`: `requiredTag`; requirement `Azure Tag Standard!A17`; section `Azure Tag Standard!A17 'Business Criticality': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-createdondate`: `requiredTag`; requirement `Azure Tag Standard!A18`; section `Azure Tag Standard!A18 'CreatedOnDate': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-data-classification`: `requiredTag`; requirement `Azure Tag Standard!A19`; section `Azure Tag Standard!A19 'Data Classification': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-environment-type`: `requiredTag`; requirement `Azure Tag Standard!A14`; section `Azure Tag Standard!A14 'Environment Type': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-primary-business-capability`: `requiredTag`; requirement `Azure Tag Standard!A21`; section `Azure Tag Standard!A21 'Primary Business Capability': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-regulatory-controlled-information`: `requiredTag`; requirement `Azure Tag Standard!A22`; section `Azure Tag Standard!A22 'Regulatory Controlled Information': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-support-group`: `requiredTag`; requirement `Azure Tag Standard!A23`; section `Azure Tag Standard!A23 'Support Group': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-tis-application-owner`: `requiredTag`; requirement `Azure Tag Standard!A24`; section `Azure Tag Standard!A24 'TIS Application Owner': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`
- `required-tis-portfolio-executive`: `requiredTag`; requirement `Azure Tag Standard!A25`; section `Azure Tag Standard!A25 'TIS Portfolio Executive': listed under A6 'required tags'; A3 policy enforces presence; A11 tag name case-sensitive. Presence only (standard states no nonblank or whitespace rule).`

## Evidence gaps and conflicts

- None. Structured limitations above still apply.

- [Supporting evidence](supporting-evidence.json): integrity-linked, not proof of source authenticity.

No Azure resources were changed.
