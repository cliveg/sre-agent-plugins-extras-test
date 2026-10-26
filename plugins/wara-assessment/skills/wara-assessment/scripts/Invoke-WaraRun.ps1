#Requires -Version 7.2
<#
.SYNOPSIS
    Runs a Well-Architected Reliability Assessment (WARA) for exactly ONE scope and writes a
    self-describing, comparable run folder (standard WARA output + provenance + derived findings).

.DESCRIPTION
    Layer 1 (standard): Start-WARACollector + Start-WARAAnalyzer, unmodified, pinned versions.
    Layer 2/3 (ours):   normalize_findings.py + prioritize.py (deterministic) -> derived/.

    Output layout (scope-first so month-over-month comparison is a sibling-folder diff):
      <OutputRoot>/wara/<subscription-label>/<scope-folder>/<runId>/
          run.json            provenance: scope, exact WARA parameters, upstream commits, identity,
                              dependency mode, deviations, collector errors, output hashes
          standard/           WARA-File-*.json (collector), Expert-Analysis-*.xlsx (analyzer)
          derived/            findings.json, prioritized-findings.json/.csv, prioritized-report.md, delta.json
      <OutputRoot>/wara/<subscription-label>/<scope-folder>/latest.json

    <scope-folder> is '_subscription' for a subscription scope, otherwise the resource group name.
    New run IDs include UTC milliseconds and a random suffix. Serialize runs for each scope.

    Scope semantics: WARA UNIONS -SubscriptionIds and -ResourceGroups. This runner never passes both:
      ResourceGroup scope -> -ResourceGroups only;  Subscription scope -> -SubscriptionIds only.

    DependencyMode:
      Restricted (default) - no PowerShell Gallery and no azure.github.io. Uses only github.com (git)
                             and api.nuget.org: Az.Accounts from nuget.org, WARA/ImportExcel/APRL from
                             pinned git commits, a bundled Search-AzGraph shim, and recommendation data
                             rebuilt from APRL. Designed for Azure SRE Agent sandboxes.
      Gallery              - standard installs from the PowerShell Gallery (Cloud Shell, workstation,
                             Azure Automation, CI runners). No shims.

.EXAMPLE
    ./Invoke-WaraRun.ps1 -ScopeType ResourceGroup -SubscriptionId <sub> -ResourceGroupName rg-app `
        -OutputRoot ./out -UseManagedIdentity -ManagedIdentityClientId <clientId>

.EXAMPLE
    ./Invoke-WaraRun.ps1 -ScopeType Subscription -SubscriptionId <sub> -DependencyMode Gallery -OutputRoot ./out

.EXAMPLE
    ./Invoke-WaraRun.ps1 -ScopesFile ./scopes.json -Scope rg-app,_subscription -OutputRoot ./out
#>
[CmdletBinding(DefaultParameterSetName = 'Explicit')]
param(
    [Parameter(ParameterSetName = 'Explicit', Mandatory)]
    [ValidateSet('ResourceGroup', 'Subscription')]
    [string] $ScopeType,

    [Parameter(ParameterSetName = 'Explicit', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $SubscriptionId,

    [Parameter(ParameterSetName = 'Explicit')]
    [string] $ResourceGroupName,

    [Parameter(ParameterSetName = 'Explicit')]
    [string] $ScopeName,

    [Parameter(ParameterSetName = 'ScopesFile', Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string] $ScopesFile,

    [Parameter(ParameterSetName = 'ScopesFile')]
    [string[]] $Scope,

    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')]
    [string] $TenantId,

    [string] $OutputRoot = (Join-Path (Get-Location) 'wara-output'),

    [ValidateSet('Restricted', 'Gallery')]
    [string] $DependencyMode = 'Restricted',

    [ValidateSet('', 'Aprl', 'Published')]
    [string] $RecommendationSource = '',

    [string] $AprlRef,

    [string] $CacheRoot = $(if ($env:WARA_CACHE) { $env:WARA_CACHE } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cache/wara-assessment' }),

    [switch] $UseManagedIdentity,
    [string] $ManagedIdentityClientId,

    [string] $PrioritizationFile,
    [switch] $SkipAnalyzer,
    [switch] $SkipDerived
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$SkillRoot = Split-Path -Parent $PSScriptRoot
$Deps = Get-Content -Raw (Join-Path $SkillRoot 'config/dependencies.json') | ConvertFrom-Json
if (-not $RecommendationSource) { $RecommendationSource = if ($DependencyMode -eq 'Restricted') { 'Aprl' } else { 'Published' } }
if (-not $AprlRef) { $AprlRef = $Deps.aprl.gitCommit }
if (-not $PrioritizationFile) { $PrioritizationFile = Join-Path $SkillRoot 'config/prioritization.yaml' }
$RunnerVersion = '0.1.1'
$script:WaraSourceDir = $null

function Write-Step([string] $Message) { Write-Host "[wara] $Message" -ForegroundColor Cyan }

function Get-Sha256([string] $Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

function Invoke-Git {
    $out = & git @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed: $out" }
    $out
}

function Sync-GitSource([string] $Url, [string] $Ref, [string] $Destination) {
    # Shallow checkout of an exact commit (or branch/tag). Reuses the cache when the commit matches.
    $isSha = $Ref -match '^[0-9a-f]{40}$'
    if ($isSha -and (Test-Path (Join-Path $Destination '.git'))) {
        $head = (Invoke-Git -C $Destination rev-parse HEAD | Select-Object -Last 1).Trim()
        if ($head -eq $Ref) { return $head }
    }
    if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Invoke-Git -C $Destination init -q | Out-Null
    Invoke-Git -C $Destination remote add origin $Url | Out-Null
    Invoke-Git -C $Destination fetch -q --depth 1 origin $Ref | Out-Null
    Invoke-Git -C $Destination checkout -q FETCH_HEAD | Out-Null
    return (Invoke-Git -C $Destination rev-parse HEAD | Select-Object -Last 1).Trim()
}

function Add-ModulePath([string] $Path) {
    $sep = [IO.Path]::PathSeparator
    if (($env:PSModulePath -split [regex]::Escape($sep)) -notcontains $Path) { $env:PSModulePath = "$Path$sep$env:PSModulePath" }
}

function Get-Python {
    foreach ($name in 'python3', 'python') {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function ConvertTo-Label([string] $Text) {
    $t = ($Text.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($t.Length -gt 40) { $t = $t.Substring(0, 40).Trim('-') }
    return $t
}

# --------------------------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------------------------
function Initialize-WaraDependencies {
    $info = [ordered]@{ dependencyMode = $DependencyMode; recommendationSource = $RecommendationSource; deviations = [System.Collections.Generic.List[string]]::new() }
    $moduleCache = Join-Path $CacheRoot 'modules'
    New-Item -ItemType Directory -Force -Path $moduleCache | Out-Null
    Add-ModulePath $moduleCache

    if ($DependencyMode -eq 'Gallery') {
        foreach ($m in @(
                @{ Name = 'Az.Accounts'; Version = $Deps.azAccounts.galleryVersion },
                @{ Name = 'Az.ResourceGraph'; Version = $Deps.azResourceGraph.galleryVersion },
                @{ Name = 'ImportExcel'; Version = $Deps.importExcel.galleryVersion },
                @{ Name = $Deps.wara.galleryModule; Version = $Deps.wara.galleryVersion })) {
            if (-not (Get-Module -ListAvailable -Name $m.Name | Where-Object { $_.Version -eq [version]$m.Version })) {
                Write-Step "Installing $($m.Name) $($m.Version) from the PowerShell Gallery"
                Install-Module -Name $m.Name -RequiredVersion $m.Version -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            }
        }
        Import-Module $Deps.wara.galleryModule -RequiredVersion $Deps.wara.galleryVersion -Force -Global
        $info.waraSource = "PowerShell Gallery $($Deps.wara.galleryModule) $($Deps.wara.galleryVersion)"
        $info.resourceGraphProvider = "Az.ResourceGraph $((Get-Module -ListAvailable Az.ResourceGraph | Sort-Object Version -Descending | Select-Object -First 1).Version)"
    }
    else {
        # Az.Accounts: reuse any installed >= 3.0, otherwise the pinned nupkg from nuget.org.
        if (-not (Get-Module -ListAvailable -Name Az.Accounts | Where-Object { $_.Version -ge [version]'3.0.0' })) {
            $dest = Join-Path $moduleCache "Az.Accounts/$($Deps.azAccounts.version)"
            Write-Step "Installing Az.Accounts $($Deps.azAccounts.version) from api.nuget.org"
            $pkg = Join-Path $CacheRoot "az.accounts.$($Deps.azAccounts.version).nupkg"
            Invoke-WebRequest -Uri $Deps.azAccounts.nugetPackageUri -OutFile $pkg
            if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($pkg, $dest)
            $info.deviations.Add("Az.Accounts $($Deps.azAccounts.version) installed from api.nuget.org instead of the PowerShell Gallery.")
        }
        # Az.ResourceGraph: prefer a real module if present, otherwise the bundled shim.
        $realArg = Get-Module -ListAvailable -Name Az.ResourceGraph | Where-Object { $_.Path -notlike "*$([IO.Path]::DirectorySeparatorChar)shims$([IO.Path]::DirectorySeparatorChar)*" } | Sort-Object Version -Descending | Select-Object -First 1
        if ($realArg) {
            $info.resourceGraphProvider = "Az.ResourceGraph $($realArg.Version)"
        }
        else {
            Add-ModulePath (Join-Path $PSScriptRoot 'shims')
            $info.resourceGraphProvider = 'wara-assessment Search-AzGraph shim (Resource Graph REST API 2022-10-01)'
            $info.deviations.Add('Az.ResourceGraph replaced by the bundled Search-AzGraph shim (same Resource Graph REST API, paging via skipToken).')
        }
        # ImportExcel (analyzer only).
        if (-not $SkipAnalyzer -and -not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-Step "Fetching ImportExcel $($Deps.importExcel.gitCommit.Substring(0,7)) from GitHub"
            Sync-GitSource $Deps.importExcel.gitRepository $Deps.importExcel.gitCommit (Join-Path $moduleCache 'ImportExcel') | Out-Null
            $info.deviations.Add("ImportExcel loaded from GitHub commit $($Deps.importExcel.gitCommit) instead of the PowerShell Gallery.")
        }
        # WARA from a pinned commit.
        $waraDir = Join-Path $CacheRoot "src/wara-$($Deps.wara.gitCommit.Substring(0,12))"
        Write-Step "Preparing WARA source $($Deps.wara.gitCommit.Substring(0,12))"
        $info.waraCommit = Sync-GitSource $Deps.wara.gitRepository $Deps.wara.gitCommit $waraDir
        Import-Module (Join-Path $waraDir $Deps.wara.manifestPath) -Force -Global
        $info.waraSource = "GitHub $($Deps.wara.gitRepository) @ $($info.waraCommit)"
        $info.deviations.Add('WARA module loaded from its GitHub source at a pinned commit instead of the PowerShell Gallery; the Gallery version check is skipped.')
        $script:WaraSourceDir = $waraDir
    }
    $info.waraVersion = (Get-Module wara).Version.ToString()
    $info.azAccountsVersion = (Get-Module -ListAvailable Az.Accounts | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()
    $ie = Get-Module -ListAvailable ImportExcel | Sort-Object Version -Descending | Select-Object -First 1
    $info.importExcelVersion = if ($ie) { $ie.Version.ToString() } else { $null }

    # Recommendation data.
    $dataDir = $null
    if ($RecommendationSource -eq 'Aprl') {
        $py = Get-Python
        if (-not $py) { throw 'RecommendationSource Aprl requires python3 with PyYAML.' }
        $aprlDir = Join-Path $CacheRoot "src/aprl-$(ConvertTo-Label $AprlRef)"
        Write-Step "Preparing APRL $AprlRef"
        $info.aprlCommit = Sync-GitSource $Deps.aprl.gitRepository $AprlRef $aprlDir
        $info.aprlRef = $AprlRef
        if (-not $script:WaraSourceDir) {
            $script:WaraSourceDir = Join-Path $CacheRoot "src/wara-$($Deps.wara.gitCommit.Substring(0,12))"
            Sync-GitSource $Deps.wara.gitRepository $Deps.wara.gitCommit $script:WaraSourceDir | Out-Null
        }
        $dataDir = Join-Path $CacheRoot "data/aprl-$($info.aprlCommit.Substring(0,12))"
        $snapshot = Join-Path $script:WaraSourceDir $Deps.wara.resourceTypesSnapshotPath
        $summary = & $py (Join-Path $PSScriptRoot 'build_recommendation_data.py') --aprl $aprlDir --types-snapshot $snapshot --out $dataDir
        if ($LASTEXITCODE -ne 0) { throw "build_recommendation_data.py failed: $summary" }
        $info.recommendationData = ($summary | Select-Object -Last 1) | ConvertFrom-Json
        $info.deviations.Add("Recommendation data rebuilt from APRL commit $($info.aprlCommit) instead of $($Deps.published.recommendationDataUri); in-scope resource types from WARA's bundled snapshot plus APRL types.")
    }
    else {
        $dataDir = Join-Path $CacheRoot ("data/published-" + (Get-Date).ToUniversalTime().ToString('yyyyMMdd'))
        New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
        Invoke-WebRequest -Uri $Deps.published.recommendationDataUri -OutFile (Join-Path $dataDir 'recommendations.json')
        Invoke-WebRequest -Uri $Deps.published.resourceTypesUri -OutFile (Join-Path $dataDir 'WARAinScopeResTypes.csv')
        $info.recommendationData = [ordered]@{
            source               = 'published'
            recommendationsSha256 = Get-Sha256 (Join-Path $dataDir 'recommendations.json')
            resourceTypesSha256   = Get-Sha256 (Join-Path $dataDir 'WARAinScopeResTypes.csv')
        }
    }
    $script:RecommendationsPath = Join-Path $dataDir 'recommendations.json'
    $script:ResourceTypesPath = Join-Path $dataDir 'WARAinScopeResTypes.csv'
    return $info
}

function Enable-WaraRedirects {
    # Session-scoped: WARA's collector and analyzer read the published data URLs (the analyzer hard-codes
    # the resource-type URL). Serve local files for exactly those two URLs; every other call is untouched.
    $global:WaraRedirectMap = @{
        $Deps.published.recommendationDataUri = $script:RecommendationsPath
        $Deps.published.resourceTypesUri      = $script:ResourceTypesPath
    }
    function global:Invoke-RestMethod {
        $uri = $null
        for ($i = 0; $i -lt $args.Count; $i++) {
            if ("$($args[$i])" -match '^-Uri:?$') { $uri = "$($args[$i + 1])"; break }
        }
        if (-not $uri -and $args.Count -gt 0 -and "$($args[0])" -notmatch '^-') { $uri = "$($args[0])" }
        if ($uri -and $global:WaraRedirectMap.ContainsKey($uri)) {
            $local = $global:WaraRedirectMap[$uri]
            $raw = Get-Content -Raw -LiteralPath $local
            if ($local -like '*.json') { return ($raw | ConvertFrom-Json -Depth 100) }
            return $raw
        }
        Microsoft.PowerShell.Utility\Invoke-RestMethod @args
    }
    if ($DependencyMode -eq 'Restricted') {
        # WARA's update check calls Find-Module against the PowerShell Gallery; it is unreachable by design here.
        function global:Find-Module { return $null }
    }
}

function Disable-WaraRedirects {
    foreach ($f in 'Invoke-RestMethod', 'Find-Module') {
        if (Test-Path "function:global:$f") { Remove-Item "function:global:$f" -Force }
    }
    Remove-Variable -Name WaraRedirectMap -Scope Global -ErrorAction SilentlyContinue
}

# --------------------------------------------------------------------------------------------
# Azure context
# --------------------------------------------------------------------------------------------
function Connect-WaraAzure {
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if ($UseManagedIdentity) {
        $p = @{ Identity = $true; WarningAction = 'SilentlyContinue' }
        if ($ManagedIdentityClientId) { $p.AccountId = $ManagedIdentityClientId }
        if ($TenantId) { $p.Tenant = $TenantId }
        Connect-AzAccount @p | Out-Null
        $ctx = Get-AzContext
    }
    elseif (-not $ctx) {
        if (-not $TenantId) { throw 'No Azure context. Sign in first (Connect-AzAccount), pass -UseManagedIdentity, or pass -TenantId for interactive sign-in.' }
        Connect-AzAccount -Tenant $TenantId -WarningAction SilentlyContinue | Out-Null
        $ctx = Get-AzContext
    }
    if (-not $script:TenantId) { $script:TenantId = $ctx.Tenant.Id }
    return $ctx
}

# --------------------------------------------------------------------------------------------
# One scope
# --------------------------------------------------------------------------------------------
function Invoke-WaraScope([hashtable] $S, $DepInfo, $Ctx) {
    $sub = $S.SubscriptionId.ToLowerInvariant()
    if ($S.ScopeType -eq 'ResourceGroup' -and -not $S.ResourceGroupName) { throw "Scope '$($S.ScopeName)': ResourceGroupName is required for ResourceGroup scope." }

    $subName = $null
    try { $subName = (Get-AzSubscription -SubscriptionId $sub -TenantId $script:TenantId -WarningAction SilentlyContinue -ErrorAction Stop).Name } catch { }
    $subLabel = if ($S.SubscriptionLabel) { $S.SubscriptionLabel } elseif ($subName) { "$(ConvertTo-Label $subName)_$($sub.Substring(0,8))" } else { "sub_$($sub.Substring(0,8))" }
    $scopeFolder = if ($S.ScopeName) { $S.ScopeName } elseif ($S.ScopeType -eq 'Subscription') { '_subscription' } else { $S.ResourceGroupName }

    $runId = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHHmmssfff'Z'") + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $scopeDir = Join-Path $OutputRoot "wara/$subLabel/$scopeFolder"
    $runDir = Join-Path $scopeDir $runId
    $stdDir = Join-Path $runDir 'standard'
    $derDir = Join-Path $runDir 'derived'
    New-Item -ItemType Directory -Force -Path $scopeDir | Out-Null
    New-Item -ItemType Directory -Path $runDir | Out-Null
    New-Item -ItemType Directory -Path $stdDir, $derDir | Out-Null

    $previous = $null
    $latestPath = Join-Path $scopeDir 'latest.json'
    if (Test-Path $latestPath) { $previous = Get-Content -Raw $latestPath | ConvertFrom-Json }

    $waraParams = [ordered]@{ TenantID = $script:TenantId }
    if ($S.ScopeType -eq 'Subscription') { $waraParams.SubscriptionIds = "/subscriptions/$sub" }
    else { $waraParams.ResourceGroups = "/subscriptions/$sub/resourceGroups/$($S.ResourceGroupName)" }

    $run = [ordered]@{
        schemaVersion = '1.0'
        runId         = $runId
        status        = 'Running'
        startedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        completedUtc  = $null
        runner        = [ordered]@{ name = 'wara-assessment/Invoke-WaraRun.ps1'; version = $RunnerVersion }
        scope         = [ordered]@{
            type              = $S.ScopeType
            folder            = $scopeFolder
            tenantId          = $script:TenantId
            subscriptionId    = $sub
            subscriptionName  = $subName
            subscriptionLabel = $subLabel
            resourceGroup     = $S.ResourceGroupName
            waraParameters    = $waraParams
        }
        identity      = [ordered]@{ account = $Ctx.Account.Id; type = "$($Ctx.Account.Type)" }
        host          = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; sreAgent = [bool]($env:IDENTITY_ENDPOINT) }
        upstream      = $DepInfo
        previousRunId = if ($previous) { $previous.runId } else { $null }
        collector     = [ordered]@{ status = $null; errors = @() }
        analyzer      = [ordered]@{ status = $null; error = $null }
        derived       = [ordered]@{ status = $null; error = $null; summary = $null }
        outputs       = [ordered]@{}
    }
    $runJson = Join-Path $runDir 'run.json'
    $save = { $run | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $runJson -Encoding utf8 }
    & $save

    try {
    Write-Step "Scope $($S.ScopeType) '$scopeFolder' -> $runDir"
    Push-Location $stdDir
    try {
        # ---- Layer 1: WARA collector (standard) ----
        $Error.Clear()
        try {
            Start-WARACollector @waraParams -ErrorAction Continue
            $run.collector.status = 'Completed'
        }
        catch {
            $run.collector.status = 'Failed'
            $run.collector.errors = @("$_")
        }
        $noise = 'Find-Package|No match was found for the specified search criteria|Get-PSRepository'
        $errs = @($Error | ForEach-Object { "$_" } | Where-Object { $_ -and $_ -notmatch $noise } | Select-Object -Unique -First 50)
        if ($errs.Count) { $run.collector.errors = @($run.collector.errors) + $errs; if ($run.collector.status -eq 'Completed') { $run.collector.status = 'CompletedWithErrors' } }
        $collectorJson = Get-ChildItem -LiteralPath $stdDir -Filter 'WARA-File-*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($run.collector.status -eq 'Failed' -or -not $collectorJson) {
            $run.collector.status = 'Failed'
            throw 'Start-WARACollector failed or produced no WARA-File-*.json.'
        }
        $run.outputs.collectorJson = [ordered]@{ path = "standard/$($collectorJson.Name)"; sha256 = Get-Sha256 $collectorJson.FullName }
        & $save

        # ---- Layer 1: WARA analyzer (standard) ----
        if ($SkipAnalyzer) { $run.analyzer.status = 'Skipped' }
        else {
            try {
                Start-WARAAnalyzer -JSONFile $collectorJson.FullName | Out-Host
                $xlsx = Get-ChildItem -LiteralPath $stdDir -Filter 'Expert-Analysis-*.xlsx' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($xlsx) {
                    $run.analyzer.status = 'Completed'
                    $run.outputs.analyzerWorkbook = [ordered]@{ path = "standard/$($xlsx.Name)"; sha256 = Get-Sha256 $xlsx.FullName }
                }
                else { $run.analyzer.status = 'Failed'; $run.analyzer.error = 'No Expert-Analysis-*.xlsx produced.' }
            }
            catch { $run.analyzer.status = 'Failed'; $run.analyzer.error = "$_" }
        }
        $run.analyzer.note = 'Start-WARAReport (PowerPoint/Word) is not run: it requires Windows with Microsoft Office.'
        & $save
    }
    finally { Pop-Location }

    # ---- Layer 2/3: normalize + prioritize (ours, deterministic) ----
    if ($SkipDerived) { $run.derived.status = 'Skipped' }
    else {
        $py = Get-Python
        if (-not $py) { $run.derived.status = 'Failed'; $run.derived.error = 'python3 not found' }
        else {
            try {
                $findings = Join-Path $derDir 'findings.json'
                $o = & $py (Join-Path $PSScriptRoot 'normalize_findings.py') --collector-json $collectorJson.FullName --run-json $runJson --recommendations $script:RecommendationsPath --out $findings 2>&1
                if ($LASTEXITCODE -ne 0) { throw "normalize_findings.py: $o" }
                $pArgs = @((Join-Path $PSScriptRoot 'prioritize.py'), '--findings', $findings, '--config', $PrioritizationFile, '--out-dir', $derDir)
                if ($previous) {
                    $prevFile = Join-Path $scopeDir "$($previous.runId)/derived/prioritized-findings.json"
                    $pArgs += @('--previous', $prevFile)
                }
                $o = & $py @pArgs 2>&1
                if ($LASTEXITCODE -ne 0) { throw "prioritize.py: $o" }
                $run.derived.status = 'Completed'
                $run.derived.summary = ($o | Select-Object -Last 1) | ConvertFrom-Json
                foreach ($f in Get-ChildItem -LiteralPath $derDir -File) { $run.outputs["derived/$($f.Name)"] = Get-Sha256 $f.FullName }
            }
            catch { $run.derived.status = 'Failed'; $run.derived.error = "$_" }
        }
    }

    $failed = @($run.collector.status, $run.analyzer.status, $run.derived.status) -contains 'Failed'
    $partial = $run.collector.status -eq 'CompletedWithErrors'
    $run.status = if ($failed) { 'PartiallySucceeded' } elseif ($partial) { 'SucceededWithWarnings' } else { 'Succeeded' }
    $run.completedUtc = (Get-Date).ToUniversalTime().ToString('o')
    & $save

    [ordered]@{ runId = $runId; path = $runId; status = $run.status; completedUtc = $run.completedUtc; scopeType = $S.ScopeType } |
        ConvertTo-Json | Set-Content -LiteralPath $latestPath -Encoding utf8

    Write-Step "Run $runId finished: $($run.status)"
    [pscustomobject]@{ Scope = $scopeFolder; RunId = $runId; Status = $run.status; RunPath = $runDir; Summary = $run.derived.summary }
    }
    catch {
        $run.status = 'Failed'
        $run.completedUtc = (Get-Date).ToUniversalTime().ToString('o')
        $run.failure = "$_"
        & $save
        throw
    }
}

# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------
$scopes = @()
if ($PSCmdlet.ParameterSetName -eq 'ScopesFile') {
    $cfg = Get-Content -Raw $ScopesFile | ConvertFrom-Json
    if (-not $TenantId -and $cfg.PSObject.Properties['tenantId']) { $TenantId = $cfg.tenantId }
    foreach ($s in $cfg.scopes) {
        if ($Scope -and ($Scope -notcontains $s.name)) { continue }
        if ($s.PSObject.Properties['enabled'] -and -not $s.enabled) { continue }
        $scopes += @{
            ScopeName         = $s.name
            ScopeType         = $s.type
            SubscriptionId    = $s.subscriptionId
            ResourceGroupName = if ($s.PSObject.Properties['resourceGroup']) { $s.resourceGroup } else { $null }
            SubscriptionLabel = if ($s.PSObject.Properties['subscriptionLabel']) { $s.subscriptionLabel } else { $null }
        }
    }
    if (-not $scopes) { throw "No enabled scopes matched in $ScopesFile." }
}
else {
    $scopes += @{ ScopeName = $ScopeName; ScopeType = $ScopeType; SubscriptionId = $SubscriptionId; ResourceGroupName = $ResourceGroupName; SubscriptionLabel = $null }
}
$script:TenantId = $TenantId
foreach ($s in $scopes) {
    if ($s.ScopeType -notin 'ResourceGroup', 'Subscription') { throw "Invalid scope type: $($s.ScopeType)" }
    if (-not [guid]::TryParse($s.SubscriptionId, [ref]([guid]::Empty))) { throw "Invalid subscription ID: $($s.SubscriptionId)" }
    if ($s.ScopeType -eq 'ResourceGroup' -and -not $s.ResourceGroupName) { throw 'ResourceGroupName is required.' }
    if ($s.ScopeType -eq 'Subscription' -and $s.ResourceGroupName) { throw 'A subscription scope must not specify ResourceGroupName.' }
    foreach ($label in $s.ScopeName, $s.SubscriptionLabel, $s.ResourceGroupName) {
        if ($label -and ($label -in '.', '..' -or $label -notmatch '^[a-zA-Z0-9_.()-]+$')) { throw "Invalid scope folder label: $label" }
    }
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $OutputRoot, $CacheRoot | Out-Null

$depInfo = Initialize-WaraDependencies
$ctx = Connect-WaraAzure
$results = @()
try {
    if ($RecommendationSource -eq 'Aprl' -or $DependencyMode -eq 'Restricted') { Enable-WaraRedirects }
    foreach ($s in $scopes) { $results += Invoke-WaraScope $s $depInfo $ctx }
}
finally { Disable-WaraRedirects }
$results
