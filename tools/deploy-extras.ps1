<#
.SYNOPSIS
  deploy-extras.ps1 — PowerShell port of deploy-extras.sh (TESTING ONLY).

.DESCRIPTION
  Deploys a plugin's SRE Agent "extras" to a running agent. The Plugin
  Marketplace installs the SKILL (and MCP connectors); this script deploys the
  pieces the marketplace does NOT carry: the subagent(s), scheduled task(s),
  and knowledge-base files. By DEFAULT it deploys ONLY those extras — the skill
  is expected to come from the marketplace.

  It is GENERIC and FILE-DRIVEN: point it at any plugin folder and it discovers
    <plugin>/extras/knowledge-base/*.md            -> /api/v1/AgentMemory/upload
    <plugin>/extras/agents/*.yaml                  -> /api/v2/extendedAgent/agents
    <plugin>/extras/scheduled-tasks/*.yaml         -> /api/v1/scheduledtasks
    <plugin>/skills/*/SKILL.md  (only with -WithSkill / -SkillsOnly)
  Names/tools/cron are read straight from the files. Re-run after any edit.

  This is a convenience copy for local testing on Windows. The bash script
  (deploy-extras.sh) remains the supported/published deployer.

.PARAMETER Plugin
  Plugin folder, e.g. plugins/sla-reporting. Resolved relative to the repo root
  (the parent of tools/) if not an absolute/relative match. If omitted and the
  repo has exactly one plugin under plugins/, that one is used automatically.

.PARAMETER ResourceGroup
  Resource group containing the SRE Agent (used to auto-discover the endpoint).

.PARAMETER AgentName
  Specific agent name when the resource group has more than one agent.

.PARAMETER Endpoint
  Agent data-plane endpoint, e.g. https://<agent>.<region>.azuresre.ai
  (or set $env:SRE_AGENT_ENDPOINT).

.PARAMETER Workspace
  Optional. Pin the Log Analytics workspace used for Activity Log / history
  queries (name | guid | resourceId). Overrides connector / auto-discovery.
  Also settable via $env:LOG_ANALYTICS_WORKSPACE.

.PARAMETER Status
  Show what is currently deployed and exit.

.PARAMETER DryRun
  Build the request bodies but push nothing.

.PARAMETER WithSkill
  Also push the skill(s) from this repo (default: skill comes from marketplace).

.PARAMETER SkillsOnly
  Push ONLY the skill(s) and exit.

.EXAMPLE
  ./deploy-extras.ps1 -Plugin plugins/sla-reporting -Endpoint https://my-agent.eastus2.azuresre.ai

.EXAMPLE
  ./deploy-extras.ps1 -Plugin plugins/sla-reporting -ResourceGroup my-rg -Status

.EXAMPLE
  ./deploy-extras.ps1 -Endpoint <url> -DryRun        # auto-detects the single plugin

.NOTES
  Prereqs: PowerShell 7+, Azure CLI (logged in). The 'powershell-yaml' module is
  auto-installed (CurrentUser scope) on first run if missing. No Python needed.
  Auth: your account needs the "SRE Agent Administrator" role on the agent.
#>
[CmdletBinding()]
param(
    [Alias('p')][string]$Plugin,
    [Alias('g')][string]$ResourceGroup,
    [string]$AgentName,
    [string]$Endpoint,
    [Alias('w')][string]$Workspace,
    [switch]$Status,
    [switch]$DryRun,
    [switch]$WithSkill,
    [switch]$SkillsOnly
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "X This script requires PowerShell 7+. You are on $($PSVersionTable.PSVersion)." -ForegroundColor Red
    Write-Host "  Install: winget install Microsoft.PowerShell, then run with 'pwsh'." -ForegroundColor Red
    exit 1
}

function Write-Info { param($m) Write-Host $m -ForegroundColor Blue }
function Write-Step { param($m) Write-Host $m -ForegroundColor Yellow }
function Write-Ok   { param($m) Write-Host $m -ForegroundColor Green }
function Write-Err  { param($m) Write-Host $m -ForegroundColor Red }

# ── YAML support: native via the 'powershell-yaml' module (no Python needed) ──
# Auto-install per-user if missing so this works on a bare Windows box.
if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
    if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
        Write-Info "  Installing the 'powershell-yaml' module (CurrentUser scope, one-time)..."
        try {
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
            }
            Install-Module -Name powershell-yaml -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } catch {
            Write-Err "X Could not install the 'powershell-yaml' module: $($_.Exception.Message)"
            Write-Host "  Install it manually, then re-run:"
            Write-Host "    Install-Module powershell-yaml -Scope CurrentUser -Force"
            exit 1
        }
    }
    Import-Module powershell-yaml -ErrorAction Stop
}

# ── Paths ─────────────────────────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir

# ── Resolve the plugin directory ──────────────────────────────────────────────
if (-not $Plugin) {
    $candidates = @(Get-ChildItem -Path (Join-Path $RepoRoot 'plugins') -Directory -ErrorAction SilentlyContinue)
    if ($candidates.Count -eq 1) {
        $Plugin = "plugins/$($candidates[0].Name)"
        Write-Info "  (auto-detected plugin: $Plugin)"
    } elseif ($candidates.Count -gt 1) {
        Write-Err "X -Plugin is required: the repo has multiple plugins ($($candidates.Name -join ', '))."
        Write-Host "  e.g. -Plugin plugins/$($candidates[0].Name)"
        exit 1
    } else {
        Write-Err "X -Plugin <path> is required (e.g. -Plugin plugins/sla-reporting)."
        exit 1
    }
}
$PluginDir = $null
foreach ($p in @($Plugin, (Join-Path $RepoRoot $Plugin))) {
    if (Test-Path -PathType Container $p) { $PluginDir = (Resolve-Path $p).Path; break }
}
if (-not $PluginDir) { Write-Err "X Plugin folder not found: $Plugin"; exit 1 }

$SkillsGlob = Join-Path $PluginDir 'skills'
$KbDir      = Join-Path $PluginDir 'extras/knowledge-base'
$AgentsDir  = Join-Path $PluginDir 'extras/agents'
$TasksDir   = Join-Path $PluginDir 'extras/scheduled-tasks'

# Optional workspace override (param wins over env).
$LawWorkspace = if ($PSBoundParameters.ContainsKey('Workspace') -and $Workspace) { $Workspace }
                elseif ($env:LOG_ANALYTICS_WORKSPACE) { $env:LOG_ANALYTICS_WORKSPACE }
                else { '' }

# ── YAML / frontmatter helpers (native, via the powershell-yaml module) ───────
function Read-YamlFile {
    param([Parameter(Mandatory)][string]$Path)
    (Get-Content -Raw -Encoding utf8 $Path) | ConvertFrom-Yaml
}
function Get-SkillFrontmatter {
    param([Parameter(Mandatory)][string]$Path)
    $text = Get-Content -Raw -Encoding utf8 $Path
    $m = [regex]::Match($text, '(?s)\A---\r?\n(.*?)\r?\n---')
    if (-not $m.Success) { return @{} }
    $fm = $m.Groups[1].Value | ConvertFrom-Yaml
    if ($null -eq $fm) { return @{} }
    $fm
}
function Get-SkillName {
    param([string]$Path)
    $fm = Get-SkillFrontmatter $Path
    if ($fm.name) { return $fm.name }
    return (Split-Path -Leaf (Split-Path -Parent $Path))
}
function Get-SpecName {
    param([string]$Path)
    (Read-YamlFile $Path).spec.name
}

# ── Data-plane bearer token (audience = https://azuresre.dev) ─────────────────
function Get-Token {
    (az account get-access-token --resource https://azuresre.dev --query accessToken -o tsv 2>$null | Out-String).Trim()
}
function Get-TokenError {
    (az account get-access-token --resource https://azuresre.dev --query accessToken -o tsv 2>&1 1>$null | Out-String).Trim()
}

# ── Resolve the agent endpoint ────────────────────────────────────────────────
function Resolve-Endpoint {
    if ($Endpoint) { return $Endpoint }
    if ($env:SRE_AGENT_ENDPOINT) { return $env:SRE_AGENT_ENDPOINT }
    $ep = (azd env get-value SRE_AGENT_ENDPOINT 2>$null | Out-String).Trim()
    if ($ep -match 'http') { return $ep }
    if ($ResourceGroup) {
        if (-not $AgentName) {
            $AgentName = (az resource list -g $ResourceGroup --resource-type Microsoft.App/agents --query "[0].name" -o tsv 2>$null | Out-String).Trim()
        }
        if ($AgentName) {
            return (az resource show -g $ResourceGroup --resource-type Microsoft.App/agents --name $AgentName --query "properties.agentEndpoint" -o tsv 2>$null | Out-String).Trim()
        }
    }
    return ''
}

$AgentEndpoint = (Resolve-Endpoint).TrimEnd('/')
if (-not $AgentEndpoint -or $AgentEndpoint -notmatch 'http') {
    Write-Err "X Could not resolve the SRE Agent endpoint."
    Write-Host "  Pass one of: -Endpoint <url>, -ResourceGroup <rg>, or set `$env:SRE_AGENT_ENDPOINT."
    exit 1
}

Write-Info "==========================================================="
Write-Info "  Deploy plugin extras -> SRE Agent (PowerShell test port)"
Write-Info "==========================================================="
Write-Host "  Plugin:   $(Split-Path -Leaf $PluginDir)"
Write-Host "  Endpoint: $AgentEndpoint"
Write-Host "  Source:   $PluginDir"
if ($LawWorkspace) { Write-Host "  Workspace override (Activity Log): $LawWorkspace" }
if ($DryRun)       { Write-Host "  DRY RUN - bodies will be built but nothing is pushed" }
Write-Host ""

if (-not $DryRun -and -not (Get-Token)) {
    Write-Err "X Could not acquire a data-plane token (audience https://azuresre.dev)."
    $err = Get-TokenError
    if ($err) { Write-Step "  Azure CLI said:"; $err -split "`n" | ForEach-Object { Write-Host "     $_" } }
    Write-Host ""
    Write-Host "  Common causes:"
    Write-Host "    - Not signed in / wrong subscription -> 'az login' then 'az account set --subscription <id>'."
    Write-Host "    - Conditional Access requires a compliant/Entra-joined device. Azure Cloud"
    Write-Host "      Shell is NOT a managed device, so token acquisition for this audience can be"
    Write-Host "      blocked (AADSTS53000/53003). Run this deployer from an enrolled/compliant"
    Write-Host "      workstation, or from a managed VM that satisfies the policy."
    Write-Host "    - Your account lacks the 'SRE Agent Administrator' role on the target agent."
    exit 1
}

# ── HTTP helper: PUT/POST JSON, return @{ Code; Body } ────────────────────────
function Invoke-Json {
    param(
        [Parameter(Mandatory)][ValidateSet('Put', 'Post', 'Delete')][string]$Method,
        [Parameter(Mandatory)][string]$Url,
        [string]$BodyJson,
        [Parameter(Mandatory)][string]$Token
    )
    $params = @{
        Method             = $Method
        Uri                = $Url
        Headers            = @{ Authorization = "Bearer $Token" }
        SkipHttpErrorCheck = $true
    }
    if ($BodyJson) {
        $params.ContentType = 'application/json'
        $params.Body        = [System.Text.Encoding]::UTF8.GetBytes($BodyJson)
    }
    $resp = Invoke-WebRequest @params
    # Capture the Allow header (present on 405 responses) so callers can pick a
    # supported method instead of guessing.
    $allow = ''
    try { if ($resp.Headers.Allow) { $allow = (@($resp.Headers.Allow) -join ', ') } } catch {}
    [pscustomobject]@{ Code = [int]$resp.StatusCode; Body = $resp.Content; Allow = $allow }
}
function Short { param($s) if (-not $s) { '' } else { $s.Substring(0, [Math]::Min(200, $s.Length)) } }

# Coalesce a YAML scalar/list/null into a clean JSON array. A null or missing
# YAML value becomes `@()` which serialises to `[]`. Without this, `@($null)`
# produces a one-element array containing $null -> `[null]`, and the agent
# gateway rejects `[null]` with a misleading HTTP 405. The leading comma keeps
# single-element results typed as an array (PowerShell otherwise unwraps them
# to a scalar that ConvertTo-Json emits without brackets).
function To-JsonArray { param($value) if ($null -eq $value) { , @() } else { , @($value | Where-Object { $null -ne $_ }) } }

# Fetch the scheduled-tasks list as a proper array. Invoke-RestMethod can
# mis-parse a top-level JSON array into a single merged object (its .name/.id
# become parallel arrays), so we parse the raw content ourselves.
function Get-ScheduledTasks {
    param([Parameter(Mandatory)][string]$Token)
    try {
        $r = Invoke-WebRequest -Uri "$AgentEndpoint/api/v1/scheduledtasks" `
            -Headers @{ Authorization = "Bearer $Token" } -SkipHttpErrorCheck
        if ([int]$r.StatusCode -ge 400 -or -not $r.Content) { return @() }
        return @($r.Content | ConvertFrom-Json)
    } catch { return @() }
}

$skillFiles = @(Get-ChildItem -Path (Join-Path $SkillsGlob '*/SKILL.md') -ErrorAction SilentlyContinue)
$agentFiles = @(Get-ChildItem -Path (Join-Path $AgentsDir '*.yaml') -ErrorAction SilentlyContinue)
$taskFiles  = @(Get-ChildItem -Path (Join-Path $TasksDir  '*.yaml') -ErrorAction SilentlyContinue)

# ── Status-only mode ──────────────────────────────────────────────────────────
if ($Status) {
    $token = Get-Token
    $hdr = @{ Authorization = "Bearer $token" }
    Write-Step "Deployed state:"
    foreach ($s in $skillFiles) {
        $n = Get-SkillName $s.FullName
        $r = Invoke-WebRequest -Uri "$AgentEndpoint/api/v2/extendedAgent/skills/$n" -Headers $hdr -SkipHttpErrorCheck
        if ($r.StatusCode -eq 200) { Write-Ok "  [ok] skill   $n" } else { Write-Err "  [x] skill   $n (HTTP $($r.StatusCode))" }
    }
    foreach ($a in $agentFiles) {
        $n = Get-SpecName $a.FullName
        $r = Invoke-WebRequest -Uri "$AgentEndpoint/api/v2/extendedAgent/agents/$n" -Headers $hdr -SkipHttpErrorCheck
        if ($r.StatusCode -eq 200) { Write-Ok "  [ok] agent   $n" } else { Write-Err "  [x] agent   $n (HTTP $($r.StatusCode))" }
    }
    $allTasks = @()
    try { $allTasks = Get-ScheduledTasks -Token $token } catch {}
    foreach ($t in $taskFiles) {
        $n = Get-SpecName $t.FullName
        $found = @($allTasks | Where-Object { $_.name -eq $n }).Count
        if ($found -ge 1) { Write-Ok "  [ok] task    $n" } else { Write-Err "  [x] task    $n" }
    }
    exit 0
}

# ── 1/4 Skills ────────────────────────────────────────────────────────────────
if ($WithSkill -or $SkillsOnly) {
    Write-Step "[1/4] Skills - skills/*/SKILL.md"
    if ($skillFiles.Count -eq 0) { Write-Step "  (skip) no skills found" }
    foreach ($sf in $skillFiles) {
        $name = Get-SkillName $sf.FullName
        $fm = Get-SkillFrontmatter $sf.FullName
        $content = Get-Content -Raw -Encoding utf8 $sf.FullName
        $body = [ordered]@{
            name = $name
            type = 'Skill'
            properties = [ordered]@{
                description  = (("" + $fm.description)).Trim()
                tools        = @($fm.tools)
                skillContent = $content
            }
        } | ConvertTo-Json -Depth 20
        if ($DryRun) {
            Write-Info "  dry-run -> PUT /api/v2/extendedAgent/skills/$name ($($body.Length) chars)"
        } else {
            $res = Invoke-Json -Method Put -Url "$AgentEndpoint/api/v2/extendedAgent/skills/$name" -BodyJson $body -Token (Get-Token)
            if ($res.Code -in 200,201,202,204) { Write-Ok "  [ok] $name (HTTP $($res.Code))" }
            else { Write-Err "  [x] $name HTTP $($res.Code): $(Short $res.Body)" }
        }
    }
} else {
    Write-Step "[1/4] Skills - installed from the marketplace (use -WithSkill to push from this repo)"
}
Write-Host ""
if ($SkillsOnly) { Write-Ok "Done (skills only)."; exit 0 }

# ── 2/4 Knowledge base ────────────────────────────────────────────────────────
Write-Step "[2/4] Knowledge base - extras/knowledge-base/*.md"
$kbFiles = @(Get-ChildItem -Path (Join-Path $KbDir '*.md') -ErrorAction SilentlyContinue)
if ($kbFiles.Count -gt 0) {
    $names = ($kbFiles | ForEach-Object { $_.Name }) -join ' '
    if ($DryRun) {
        Write-Info "  dry-run -> POST /api/v1/AgentMemory/upload : $names"
    } else {
        $form = @{
            triggerIndexing = 'true'
            files           = @($kbFiles | ForEach-Object { Get-Item $_.FullName })
        }
        $r = Invoke-WebRequest -Method Post -Uri "$AgentEndpoint/api/v1/AgentMemory/upload" `
            -Headers @{ Authorization = "Bearer $(Get-Token)" } -Form $form -SkipHttpErrorCheck
        if ([int]$r.StatusCode -in 200,201,202) { Write-Ok "  [ok] uploaded: $names" }
        else { Write-Err "  [x] HTTP $($r.StatusCode): $(Short $r.Content)" }
    }
} else {
    Write-Step "  (skip) no .md files in extras/knowledge-base"
}
Write-Host ""

# ── 3/4 Subagents ──────────────────────────────────────────────────────────────
Write-Step "[3/4] Subagents - extras/agents/*.yaml"
if ($agentFiles.Count -eq 0) { Write-Step "  (skip) no agents in extras/agents" }
foreach ($af in $agentFiles) {
    $spec = (Read-YamlFile $af.FullName).spec
    $instructions = "" + $spec.system_prompt
    if ($LawWorkspace) {
        $instructions = $instructions.TrimEnd() + "`n`n" +
            "WORKSPACE OVERRIDE: When querying the Activity Log / Log Analytics for " +
            "history, use the workspace '$LawWorkspace' with QueryLogAnalyticsByWorkspaceId. " +
            "This overrides any connector or auto-discovery. If '$LawWorkspace' is a " +
            "customerId GUID, pass it directly; if it is a workspace name or resource ID, " +
            "resolve its customerId first."
    }
    $name = $spec.name
    $body = [ordered]@{
        name  = $name
        type  = 'ExtendedAgent'
        tags  = @()
        properties = [ordered]@{
            instructions           = $instructions
            handoffDescription     = ("" + $spec.handoff_description)
            handoffs               = (To-JsonArray $spec.handoffs)
            tools                  = (To-JsonArray $spec.tools)
            mcpTools               = (To-JsonArray $spec.mcp_tools)
            allowParallelToolCalls = $true
            enableSkills           = $true
        }
    } | ConvertTo-Json -Depth 20
    if ($DryRun) {
        Write-Info "  dry-run -> PUT /api/v2/extendedAgent/agents/$name ($($body.Length) chars)"
    } else {
        # PUT /agents/{name} upserts the subagent. The body MUST send empty
        # arrays (not [null]) for unset handoffs/tools/mcpTools - see To-JsonArray.
        $res = Invoke-Json -Method Put -Url "$AgentEndpoint/api/v2/extendedAgent/agents/$name" -BodyJson $body -Token (Get-Token)
        if ($res.Code -in 200,201,202,204) { Write-Ok "  [ok] $name (HTTP $($res.Code))" }
        else { Write-Err "  [x] $name HTTP $($res.Code): $(Short $res.Body)" }
    }
}
Write-Host ""

# ── 4/4 Scheduled tasks (update in place so run history is preserved) ─────────
Write-Step "[4/4] Scheduled tasks - extras/scheduled-tasks/*.yaml"
if ($taskFiles.Count -eq 0) { Write-Step "  (skip) no tasks in extras/scheduled-tasks" }
foreach ($tf in $taskFiles) {
    $spec = (Read-YamlFile $tf.FullName).spec
    $prompt = "" + $spec.agent_prompt
    if ($LawWorkspace) {
        $prompt = $prompt.TrimEnd() + "`n`n" +
            "WORKSPACE OVERRIDE: When querying the Activity Log / Log Analytics for " +
            "history, use the workspace '$LawWorkspace' with QueryLogAnalyticsByWorkspaceId - " +
            "this overrides connector/auto-discovery. If '$LawWorkspace' is a customerId GUID, " +
            "pass it directly; if it is a workspace name or resource ID, resolve its " +
            "customerId first."
    }
    $name = $spec.name
    $taskDesc = if ($spec.description) { $spec.description } else { $name }
    $bodyMap = [ordered]@{
        name           = $name
        description    = (("" + $taskDesc)).Trim()
        cronExpression = $spec.cron
        agentPrompt    = $prompt
    }
    if ($spec.agent) { $bodyMap['agent'] = $spec.agent }
    $body = $bodyMap | ConvertTo-Json -Depth 20

    if ($DryRun) {
        Write-Info "  dry-run -> PUT /api/v1/scheduledtasks/{id} if it exists, else POST /api/v1/scheduledtasks ($name)"
    } else {
        $token = Get-Token
        $hdr = @{ Authorization = "Bearer $token" }
        $existingId = ''
        try {
            $tasks = Get-ScheduledTasks -Token $token
            # NB: do not name this $matches - that is a reserved PowerShell automatic
            # variable (regex match groups) and indexing into it corrupts the value.
            $taskMatches = @($tasks | Where-Object { $_.name -eq $name -and $_.id } | Sort-Object { "" + $_.createdAt })
            if ($taskMatches.Count -gt 0) {
                $existingId = $taskMatches[0].id
                if ($taskMatches.Count -gt 1) {
                    foreach ($t in $taskMatches[1..($taskMatches.Count - 1)]) {
                        if ($t -and $t.id) {
                            try { Invoke-Json -Method Delete -Url "$AgentEndpoint/api/v1/scheduledtasks/$($t.id)" -Token $token | Out-Null } catch {}
                        }
                    }
                }
            }
        } catch { $existingId = '' }

        if ($existingId) {
            $res = Invoke-Json -Method Put -Url "$AgentEndpoint/api/v1/scheduledtasks/$existingId" -BodyJson $body -Token $token
            $verb = 'updated (history kept)'
        } else {
            $res = Invoke-Json -Method Post -Url "$AgentEndpoint/api/v1/scheduledtasks" -BodyJson $body -Token $token
            $verb = 'scheduled'
        }
        if ($res.Code -in 200,201,202) { Write-Ok "  [ok] $name $verb (HTTP $($res.Code)) - cron $($spec.cron)" }
        else { Write-Err "  [x] $name HTTP $($res.Code): $(Short $res.Body)" }
    }
}
Write-Host ""

Write-Ok "Done. Re-run after any edit to a skill, subagent, or scheduled task."
if (-not $DryRun) {
    Write-Host "Verify with: ./deploy-extras.ps1 -Plugin $Plugin -Endpoint $AgentEndpoint -Status"
}
