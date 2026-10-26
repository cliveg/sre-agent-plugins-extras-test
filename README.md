# SRE Agent Plugins — Extras

A community marketplace of reusable **Azure SRE Agent** plugins, plus the
companion **"extras"** (subagents, scheduled tasks, knowledge-base files) that
the Plugin Marketplace itself does not carry.

> Inspired by the official [Azure/sre-agent-plugins](https://github.com/Azure/sre-agent-plugins)
> and [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official)
> marketplaces. Read the model in the
> [Plugin Marketplace docs](https://learn.microsoft.com/azure/sre-agent/plugin-marketplace).

## Why this repo

The SRE Agent [Plugin Marketplace](https://learn.microsoft.com/azure/sre-agent/plugin-marketplace)
is great at distributing **skills** and **MCP connectors** — install once,
version-pinned, reusable across every agent in your org. But a complete
operational capability often also needs a **subagent**, a **scheduled task**,
and a **knowledge-base doc** — and those are *not* part of a marketplace
install.

This repo embraces a **hybrid model**:

- **Skills** live where the marketplace expects them → installable in one click.
- **Extras** (subagents, scheduled tasks, KB) live alongside each plugin and
  deploy with a single generic script → [`tools/deploy-extras.sh`](tools/deploy-extras.sh).

Add new capabilities by dropping a folder under `plugins/` and adding one entry
to [`.github/plugin/marketplace.json`](.github/plugin/marketplace.json).

## Repository layout

```
sre-agent-plugins-extras/
├── .github/plugin/marketplace.json     # marketplace manifest (lists all plugins)
├── plugins/
│   └── sla-reporting/                   # one folder per capability
│       ├── plugin.json
│       ├── README.md
│       ├── skills/<skill>/SKILL.md       # ← marketplace-installable
│       └── extras/                       # ← deployed via tools/deploy-extras.sh
│           ├── agents/*.yaml
│           ├── scheduled-tasks/*.yaml
│           └── knowledge-base/*.md
└── tools/
    ├── install.sh                        # Cloud Shell bootstrap (curl | bash, no clone)
    └── deploy-extras.sh                  # generic, file-driven deployer
```

## Plugins

| Plugin | Category | Description |
|--------|----------|-------------|
| [Azure Network Health (restricted prototype)](plugins/azure-network-health) | Reliability | No-IaC network configuration triage with separate observation/assessment JSON, six versioned checks and deterministic reports. Uses a development transport for lossless native-read results; does not change resources or execute deep diagnostics. |
| [Azure Tag Governance](plugins/azure-tag-governance) | Governance | Builds an evidence-backed tag and basic naming profile from read-only Azure evidence, evaluates a frozen profile deterministically, and publishes immutable run bundles without changing resources. |
| [SLA Reporting](plugins/sla-reporting) | Reliability | Estimates Azure availability/SLA per region, service, and month from real-world Resource Health; renders an SLA service-credit heatmap; lists Service Health incidents for context. |
| [Azure VM Migration Pre-Assessment](plugins/vm-migration-preassessment) | Reliability | Runs governed AzVMTools Deep preflight through a private GitHub Actions runner and produces a scoped change plan without migration actions. |
| [WARA Reliability Assessment](plugins/wara-assessment) | Reliability | Runs Microsoft's Well-Architected Reliability Assessment one scope at a time (works in restricted-egress SRE Agent sandboxes), keeps run provenance, and produces a prioritized findings report with month-over-month deltas. Read-only. |

## Quick start (easiest path — no clone)

A complete capability is **two steps**: the marketplace installs the **skill**,
and a single Cloud Shell command deploys the **extras**.

### 1. Install the skill from the marketplace (portal)

You have two options:

**Option A — Add the whole marketplace (recommended; browse & install any plugin).**
In the SRE Agent portal: **Builder → Plugins → Add marketplace**, then enter the
repository:

- **GitHub repository URL:** `https://github.com/cliveg/sre-agent-plugins-extras-test`
  (or just `cliveg/sre-agent-plugins-extras-test`)
- Leave **Path in repo** blank.

The portal reads [`.github/plugin/marketplace.json`](.github/plugin/marketplace.json)
and lists **every** plugin in this repo, so you can install one or many without
re-adding the source. New plugins appear automatically as they're added.

**Option B — Install a single plugin from URL.**
Use **Builder → Plugins → Install from URL** when you only want one plugin:

- **GitHub repository URL:** `cliveg/sre-agent-plugins-extras-test`
- **Path in repo:** `plugins/sla-reporting`

Either way the `sla-availability` skill imports in seconds, pinned to the exact
commit.

> **Path note:** *Add marketplace* points at the repo root (it finds the
> `marketplace.json` itself). *Install from URL* needs the path to a specific
> plugin folder — pointing it at the repo root or `plugins` fails with *"No
> plugin found in repo"* because there's no `plugin.json` there.

### 2. Deploy the extras from Azure Cloud Shell

Open [Azure Cloud Shell](https://shell.azure.com) (already signed in) and run —
no repo clone needed:

```bash
curl -fsSL https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/tools/install.sh \
  | bash -s -- --plugin sla-reporting --resource-group <your-rg>
```

Or target the agent directly by URL:

```bash
curl -fsSL https://raw.githubusercontent.com/cliveg/sre-agent-plugins-extras-test/main/tools/install.sh \
  | bash -s -- --plugin sla-reporting --endpoint https://<your-agent>.<region>.azuresre.ai
```

The installer downloads only the chosen plugin's extras plus the deployer, then
runs it. By default it deploys **extras only** — the skill comes from the
marketplace in step 1. Pass `--with-skill` to also push the skill from this repo.

### Advanced: clone and run the deployer directly

If you've cloned the repo (maintainers, CI):

```bash
tools/deploy-extras.sh \
  --plugin plugins/sla-reporting \
  --endpoint https://<your-agent>.<region>.azuresre.ai
```

| Flag | Purpose |
|------|---------|
| `--plugin <path>` | Which plugin folder to deploy (required) |
| `--endpoint <url>` | Agent data-plane endpoint (or `--resource-group`, or `SRE_AGENT_ENDPOINT`) |
| `--resource-group <rg>` | Resolve the endpoint from this resource group (auto-discovers the agent) |
| `--agent-name <name>` | Pin a specific agent when the resource group has more than one |
| `--workspace <name\|guid\|resourceId>` | Optional. Pin the Log Analytics workspace used for the Activity Log / history queries, overriding the agent's connector or auto-discovery. Accepts a workspace name, ARM resource ID, or `customerId` GUID. Also settable via `LOG_ANALYTICS_WORKSPACE`. Use this when ResourceHealth/ServiceHealth logs land in a workspace other than the one the agent connector points at. |
| `--status` | Show what's currently deployed |
| `--dry-run` | Build request bodies but push nothing |
| `--with-skill` | Also push the skill from this repo (default: skill comes from marketplace) |
| `--skills-only` | Push ONLY the skill (for maintainers who don't use the marketplace) |

> **Why `--workspace`?** Resource/Service Health history is read from a Log
> Analytics workspace. Environments often have **multiple** workspaces/connectors,
> but only the one targeted by the subscription's Activity Log diagnostic export
> actually receives `ResourceHealth` / `ServiceHealth` rows. If the report shows
> "no history" even though data exists, you probably queried the wrong workspace —
> pass the correct one with `--workspace`. The flag injects a `WORKSPACE OVERRIDE:`
> directive into the deployed subagent and scheduled task so unattended runs use
> it too.

The script is **file-driven**: skill/subagent/task names, tools, and cron are
read straight from the files, so the files stay the single source of truth.
Re-run it after any edit.

### Prerequisites

- Azure CLI logged in (`az login`) with the **SRE Agent Administrator** role on
  the target agent. (Cloud Shell is already signed in.)
- `python3`/`python` with `PyYAML`, plus `curl`.
- On Windows (cloning locally), run the script with **Git Bash**
  (`"C:\Program Files\Git\bin\bash.exe"`).

## Troubleshooting

### "Could not acquire a data-plane token" in Azure Cloud Shell

The deployer needs a bearer token for the SRE Agent data plane
(`az account get-access-token --resource https://azuresre.dev`). In most tenants
Cloud Shell is already signed in and this just works. But if your tenant has a
**Conditional Access** policy that requires a **compliant or Entra-joined
device**, token acquisition for this audience is **blocked in Cloud Shell** —
because Cloud Shell is not an enrolled device. Running `az login` there does not
help (and may fail the same policy, e.g. `AADSTS53000` / `AADSTS53003`); you
cannot enroll Cloud Shell as a managed device.

**What to do instead — run the deployer from a device that satisfies the policy:**

- A **managed/compliant workstation** with the Azure CLI. On Windows use
  **Git Bash** or **WSL**:
  ```bash
  az login            # completes because the device is compliant
  az account set --subscription <id>
  tools/deploy-extras.sh --plugin plugins/sla-reporting \
    --endpoint https://<your-agent>.<region>.azuresre.ai
  ```
- Or a **managed Azure VM** (Entra-joined / Intune-enrolled) that meets the
  Conditional Access requirement, with the CLI installed.

The deployer now prints the exact Azure CLI error when the token can't be
acquired, so you can confirm whether it's Conditional Access, the wrong
subscription, or a missing **SRE Agent Administrator** role assignment.

> The **skill** itself still installs fine from the portal marketplace (step 1) —
> only the **extras** deploy step needs the data-plane token, so this only blocks
> the Cloud Shell shortcut, not the whole plugin.

## Contributing a new plugin

1. Create `plugins/<your-plugin>/` with `plugin.json`, a `README.md`, a
   `skills/<skill>/SKILL.md`, and optional `extras/`.
2. Add matching entries to `marketplace.json` and `.github/plugin/marketplace.json`.
3. Validate with `tools/deploy-extras.sh --plugin plugins/<your-plugin> --dry-run`.

## License

[MIT](LICENSE).

## Credits

The **WARA Reliability Assessment** plugin composes, without modifying, Microsoft's
[Well-Architected Reliability Assessment](https://github.com/Azure/Well-Architected-Reliability-Assessment)
and [Azure Proactive Resiliency Library v2](https://github.com/Azure/Azure-Proactive-Resiliency-Library-v2)
(both MIT). See [its third-party notices](plugins/wara-assessment/THIRD-PARTY-NOTICES.md).

The **SLA Reporting** plugin is a native SRE Agent adaptation of Guil Lima's
[gplima89/AzureSLA](https://github.com/gplima89/AzureSLA). All credit for the
original methodology and report design goes to that project.
