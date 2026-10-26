# Azure VM Migration Pre-Assessment — SRE Agent plugin

Turns AzVMTools Deep preflight into a governed, repeatable Azure SRE Agent
capability. The agent gathers the planned migration scope, triggers a protected
GitHub Actions runner, waits for the result, interprets blockers, and produces
a scoped change plan.

> **No migration actions are performed.**

## Architecture

Azure SRE Agent orchestrates and interprets; it does not directly execute the
PowerShell toolkit:

```text
SRE Agent skill/subagent
        |
        | GitHub workflow dispatch + status
        v
Private operations repository
        |
        | calls reusable workflow
        v
cliveg/AzVMTools
        |
        | OIDC + Test-AzVMTools.ps1 -Deep
        v
Azure VMs
```

Full CSV/JSON reports stay in the **private operations repository** as
short-retention Actions artifacts. The SRE Agent consumes a sanitized private
issue and workflow status.

## What's included

```text
plugins/vm-migration-preassessment/
├── plugin.json
├── skills/vm-migration-preassessment/SKILL.md
└── extras/
    ├── agent-templates/vm-preassessment-auditor.yaml
    ├── knowledge-base/vm-migration-blocker-playbook.md
    ├── github/vm-preassessment.yml
    ├── azure/vm-preassessment-runcommand-role.json
    └── scheduled-task-templates/vm-preassessment-weekly.yaml
```

The subagent and scheduled task are templates and are not auto-deployed.
GitHub connector tool names are discovered from each tenant's live Builder
tool picker and are not published as stable identifiers by Microsoft.

## Security model

- The runner repository **must be private**. Both the caller and reusable
  workflow reject public callers.
- Azure authentication uses GitHub OIDC. No client secret is required.
- Assign the workflow identity `Reader` plus the included narrowly scoped
  Run Command custom role.
- Deep guest inspection uses Azure VM Run Command. Run Command is powerful
  remote execution even though AzVMTools sends inspection-only commands.
- By default `NoPowerStateChanges` is enabled. Stopped VMs become NO-GO rather
  than being started.
- The runner never imports or calls `Invoke-AzVMTools.ps1`.
- Migration and assessment identities must remain separate.
- The private GitHub environment `vm-preassessment` should require reviewers.

## Setup

### 1. Install the skill

Add this marketplace in Azure SRE Agent:

```text
https://github.com/cliveg/sre-agent-plugins-extras-test
```

Install **Azure VM Migration Pre-Assessment**, or install only:

```text
Repository: cliveg/sre-agent-plugins-extras-test
Path: plugins/vm-migration-preassessment
```

### 2. Create a private operations repository

Create or choose a private GitHub repository, then copy:

```text
extras/github/vm-preassessment.yml
```

to:

```text
.github/workflows/vm-preassessment.yml
```

Do not put the runner in a public repository. VM reports contain
infrastructure and guest-configuration details.

From the private repository root, download it directly:

```bash
mkdir -p .github/workflows
curl -fsSL \
  https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/plugins/vm-migration-preassessment/extras/github/vm-preassessment.yml \
  -o .github/workflows/vm-preassessment.yml
```

The template currently pins both the reusable workflow logic and checked-out
script content to AzVMTools commit
`dcf72230d91c204154f2ddd5d78c36460cc766f5`. Update both pins together only
after testing a newer commit.

### 3. Configure Azure OIDC

Create a dedicated Entra application or user-assigned managed identity with a
federated GitHub credential for the private runner repository.

Add private repository secrets:

```text
AZURE_CLIENT_ID
AZURE_TENANT_ID
```

The subscription ID is a validated workflow input, not a secret.

Assign at the approved resource-group scope:

1. Azure `Reader`
2. the custom role in
   `extras/azure/vm-preassessment-runcommand-role.json`

Download the role template:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/plugins/vm-migration-preassessment/extras/azure/vm-preassessment-runcommand-role.json \
  -o vm-preassessment-runcommand-role.json
```

If you intentionally enable `allowPowerStateChanges`, separately grant and
approve VM start/deallocate actions. The default workflow does not need them.

### 4. Configure GitHub protections

Create a GitHub environment named:

```text
vm-preassessment
```

Add required reviewers for production assessment scopes. Protect the default
branch and restrict who can dispatch workflows.

### 5. Connect the private repository to SRE Agent

Configure the Azure SRE Agent GitHub Connector for:

- Actions workflow dispatch/status
- private issue read/write

Grant only the private runner repository, not broad organization access.

### 6. Deploy companion assets

From a managed workstation or Cloud Shell:

```bash
curl -fsSL https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/tools/install.sh \
  | bash -s -- \
      --plugin vm-migration-preassessment \
      --resource-group <sre-agent-resource-group>
```

This uploads the blocker playbook. The subagent template is configured in the
next step.

### 7. Configure the companion subagent

Open:

```text
extras/agent-templates/vm-preassessment-auditor.yaml
```

Import it in Builder, then use the Form tool picker to attach these capabilities
from your configured GitHub Connector:

- workflow dispatch
- workflow run list/get/status
- issue read
- issue create/update

Do not type guessed tool identifiers into the YAML. After saving and testing,
export the tenant-resolved YAML. If you want the generic extras deployer to
manage that finalized subagent, place the exported file in `extras/agents/`.

Download the template directly:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/plugins/vm-migration-preassessment/extras/agent-templates/vm-preassessment-auditor.yaml \
  -o vm-preassessment-auditor.yaml
```

## First test

Dispatch the private workflow manually first. Confirm:

1. environment approval is required
2. OIDC succeeds
3. AzVMTools runs `Test-AzVMTools.ps1 -Deep`
4. stopped VMs are not started by default
5. full reports are private artifacts
6. a sanitized `vm-preassessment` issue is created or updated
7. no migration actions occur

Then ask SRE Agent:

```text
Use vm-preassessment-auditor to assess:
RUNNER REPOSITORY: <owner>/<private-repo>
WORKFLOW FILE: vm-preassessment.yml
SUBSCRIPTION ID: <guid>
RESOURCE GROUP: <rg>
SCOPE MODE: list
VM LIST: vm-01,vm-02
TARGET VM SIZE: Standard_E4ads_v6
TARGET ZONE: 1
TARGET DISK CONTROLLER: NVMe
NVME LAYOUT: SingleDisk
NVME ALLOCATION UNIT: 4096
ALLOW POWER STATE CHANGES: false
```

Expected outcome:

- workflow run link
- GO/NO-GO counts
- blockers grouped by category
- remediation prerequisites and owners
- proposed change-window scope
- final statement: **No migration actions were performed.**

## Scheduling

After manual runs are reliable, customize
`extras/scheduled-task-templates/vm-preassessment-weekly.yaml`.

Do not schedule broad production scopes until:

- the workflow is pinned to a reviewed AzVMTools tag or commit
- GitHub environment approval is working
- issue sanitization has been reviewed
- the Azure identity scope has been verified

## Limitations

- Azure SRE Agent does not directly run AzVMTools PowerShell.
- Deep inspection relies on VM Run Command permission.
- Stopped VMs are incomplete/NO-GO unless power-state changes are explicitly
  enabled and approved.
- Marketplace virtual appliances remain untested by AzVMTools.
- Preflight is planning evidence, not an Azure capacity reservation.
