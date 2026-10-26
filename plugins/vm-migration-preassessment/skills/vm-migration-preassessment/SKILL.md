---
name: vm-migration-preassessment
description: |
  Runs and interprets a governed Azure VM migration pre-assessment using AzVMTools Deep preflight through a private GitHub Actions runner. Use for VM migration readiness, GO/NO-GO scope, blocker analysis, zone/SKU/NVMe/VNet/SSD v2 planning, and change-window scoping. Performs no migration actions.
tools:
  - SearchMemory
  - RunAzCliReadCommands
  - GetAzCliHelp
---

# Azure VM Migration Pre-Assessment

Produce a repeatable, evidence-based migration change scope without performing
any migration.

> **No migration actions are permitted.**

## Required external capability

This skill requires an Azure SRE Agent **GitHub Connector** attached to a
private operations repository, with capabilities to:

- dispatch a GitHub Actions workflow
- list/get workflow runs and status
- read and update private issues

Azure SRE Agent does not publish stable literal names for GitHub connector
tools. Use the live Builder tool picker. Never guess a connector tool name.

If those capabilities are not available, stop and explain the connector setup
required. Do not fall back to Azure write commands, shell commands, or direct
migration.

## Hard safety rules

1. Never invoke `Invoke-AzVMTools.ps1`.
2. Never run Azure CLI write commands.
3. Never create, update, resize, deallocate, start, restart, or delete a VM.
4. Dispatch only the approved workflow in the named **private** runner
   repository.
5. Default `allowPowerStateChanges` to `false`.
6. Never paste full CSV/JSON artifacts into chat or a public issue.
7. Use the sanitized private `vm-preassessment` issue as the interpretation
   input.
8. End every result with: **No migration actions were performed.**

## Required inputs

Collect all values before dispatch:

```text
RUNNER REPOSITORY: owner/private-repository
WORKFLOW FILE: vm-preassessment.yml
WORKFLOW REF: main
SUBSCRIPTION ID: GUID
RESOURCE GROUP: name
SCOPE MODE: list | resourceGroup
VM LIST: comma-separated names (required for list)
TARGET VM SIZE: Standard_...
TARGET ZONE: 1 | 2 | 3
TARGET DISK CONTROLLER: NVMe | SCSI
NVME LAYOUT: SingleDisk | Stripe
NVME ALLOCATION UNIT: 4096 | 8192 | 16384 | 32768 | 65536
TARGET SUBNET ID: optional full resource ID
ALLOW POWER STATE CHANGES: false by default
AZVMTOOLS REF: pinned commit preferred
```

For interactive use, echo the complete scope and require explicit confirmation
before dispatch. A scheduled task's reviewed configuration is its approval to
dispatch.

## Procedure

### Step 1 — Validate the runner

Using the GitHub Connector:

1. Confirm the repository exists and is private.
2. Confirm the workflow file exists on the requested ref.
3. Confirm the workflow is the approved private caller for
   `cliveg/AzVMTools/.github/workflows/vm-preassessment-reusable.yml`.
4. Refuse public repositories.
5. Prefer an AzVMTools commit SHA rather than `main`.

### Step 2 — Validate scope

Use Azure CLI **read commands only** to confirm:

- subscription is enabled
- resource group exists
- named VMs exist when scope mode is `list`

Do not duplicate the migration assessment with improvised Azure queries.
AzVMTools is the assessment authority.

### Step 3 — Dispatch exactly once

Dispatch the private workflow with these exact input keys:

```json
{
  "subscriptionId": "<guid>",
  "resourceGroup": "<rg>",
  "scopeMode": "list|resourceGroup",
  "vmList": "<comma-list-or-empty>",
  "newVmSize": "<sku>",
  "targetZone": "1|2|3",
  "targetDiskController": "NVMe|SCSI",
  "nvmeLayout": "SingleDisk|Stripe",
  "nvmeAllocationUnitSize": "4096",
  "targetSubnetId": "<resource-id-or-empty>",
  "allowPowerStateChanges": "false",
  "azvmtoolsRef": "<commit-or-ref>"
}
```

Do not dispatch a second run because polling is slow. Record the workflow run
ID and URL.

### Step 4 — Track completion

Poll the same run until:

- `completed/success`
- `completed/failure`
- `completed/cancelled`
- timeout

Do not rerun automatically. On failure, report the run URL and workflow stage.

### Step 5 — Read the sanitized issue

The private workflow creates or updates an issue labelled:

```text
vm-preassessment
```

Match the issue title to:

- resource group
- target SKU
- target zone

Confirm the issue links to the workflow run ID from Step 3. If it does not,
stop rather than interpreting stale results.

### Step 6 — Categorize blockers

SearchMemory for:

```text
Azure VM migration pre-assessment blocker playbook
```

Map every NO-GO issue to one of:

- assessment incomplete
- resource lock
- Azure Disk Encryption
- SKU/zone/allocation
- quota
- Hyper-V generation/Trusted Launch
- NVMe guest support
- local ephemeral storage
- networking/VNet
- PPG/VMSS Flex
- SQL/tempdb
- Marketplace virtual appliance
- uncategorized/manual review

Do not invent remediation commands. State prerequisites and ownership.

### Step 7 — Produce the scoped change plan

Use this exact structure:

```markdown
# Azure VM Migration Pre-Assessment

## Assessment evidence
- Workflow run:
- Runner repository:
- AzVMTools ref:
- Subscription:
- Resource group:
- Planned target:
- Power-state changes allowed: No

## Scope summary
| Status | Count |
|---|---:|
| GO | |
| NO-GO | |
| Incomplete Deep assessment | |

## Proposed change-window scope
### Include
- VM — reason

### Exclude
- VM — blocker and prerequisite

## Blockers and prerequisites
| VM | Category | Evidence | Prerequisite | Owner | Validation |
|---|---|---|---|---|---|

## Cross-cutting risks
- quota/capacity
- networking/DNS/firewall/load balancer
- local ephemeral storage
- application shutdown and sequencing
- rollback assets and retention
- Marketplace appliance/vendor validation

## Next assessment
- required follow-up
- owner
- expected evidence

No migration actions were performed.
```

## Interpretation rules

- GO means the tested conditions passed; it is not a capacity reservation.
- NO-GO means exclude the VM until reassessed.
- A stopped VM skipped by `NoPowerStateChanges` is incomplete and NO-GO.
- Marketplace virtual appliances are untested and require vendor approval.
- `Stripe` is zero-redundancy ephemeral storage.
- SSD v2 applies to eligible data disks, not OS disks.
- VNet migration creates a replacement NIC and changes private IP.
- The agent may recommend GitHub Copilot for sanitized investigation, but must
  not treat AI guidance as vendor or Azure support.
