#Requires -Version 7
<#
.SYNOPSIS
    Collects read-only environment evidence (subscription offer and tags, resource group tags, resource tags)
    for generate_reports.py environment classification.

.DESCRIPTION
    GET /subscriptions/{id} (quotaId, tags) and Resource Graph queries for resource groups and resources in
    the scope. Uses Az.Accounts (the runner's cached copy under $CacheRoot/modules when present) and
    Invoke-AzRestMethod only. Never modifies Azure.

.EXAMPLE
    pwsh -File Get-EnvironmentEvidence.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> -TenantId <tenant> `
        -UseManagedIdentity -ManagedIdentityClientId <client-id> -OutFile <run>/reports/environment-evidence.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [string] $ResourceGroupName,
    [string] $TenantId,
    [switch] $UseManagedIdentity,
    [string] $ManagedIdentityClientId,
    [Parameter(Mandatory)] [string] $OutFile,
    [string] $ClassificationConfig = (Join-Path $PSScriptRoot '../config/environment-classification.yaml'),
    [string] $CacheRoot = $(if ($env:WARA_CACHE) { $env:WARA_CACHE } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cache/wara-assessment' })
)
$ErrorActionPreference = 'Stop'
$guid = [guid]::Empty
if (-not [guid]::TryParse($SubscriptionId, [ref]$guid)) { throw 'Invalid SubscriptionId.' }
if ($ResourceGroupName -and $ResourceGroupName -notmatch '^[a-zA-Z0-9_.()-]+$') { throw 'Invalid ResourceGroupName.' }
$python = Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $python) { throw 'Python with PyYAML is required to select classification tag keys.' }
$keysJson = & $python.Source -c "import json,sys,yaml; c=yaml.safe_load(open(sys.argv[1],encoding='utf-8')); print(json.dumps(c['explicitTagKeys']+c['heuristicTagKeys']))" $ClassificationConfig
if ($LASTEXITCODE -ne 0) { throw 'Unable to read classification tag keys.' }
$tagKeys = @($keysJson | ConvertFrom-Json | ForEach-Object { $_.ToLowerInvariant() })
function Select-ClassificationTags($Tags) {
    $selected = @{}
    if ($Tags) {
        foreach ($key in $Tags.Keys) {
            if ($tagKeys -contains $key.ToLowerInvariant()) { $selected[$key] = $Tags[$key] }
        }
    }
    return $selected
}

$moduleCache = Join-Path $CacheRoot 'modules'
$sep = [IO.Path]::PathSeparator
if ((Test-Path $moduleCache) -and (($env:PSModulePath -split [regex]::Escape($sep)) -notcontains $moduleCache)) {
    $env:PSModulePath = "$moduleCache$sep$env:PSModulePath"
}
Import-Module Az.Accounts -ErrorAction Stop

$ctx = Get-AzContext -ErrorAction SilentlyContinue
if ($UseManagedIdentity) {
    $p = @{ Identity = $true; WarningAction = 'SilentlyContinue' }
    if ($ManagedIdentityClientId) { $p.AccountId = $ManagedIdentityClientId }
    if ($TenantId) { $p.Tenant = $TenantId }
    Connect-AzAccount @p | Out-Null
}
elseif (-not $ctx) {
    if (-not $TenantId) { throw 'No Azure context. Sign in first, pass -UseManagedIdentity, or pass -TenantId.' }
    Connect-AzAccount -Tenant $TenantId -WarningAction SilentlyContinue | Out-Null
}
$account = (Get-AzContext).Account.Id

function Invoke-Arm([string] $Method, [string] $Path, $Body) {
    $p = @{ Method = $Method; Path = $Path }
    if ($Body) { $p.Payload = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    $r = Invoke-AzRestMethod @p
    if ($r.StatusCode -ge 300) { throw "$Method $Path failed: HTTP $($r.StatusCode) $($r.Content)" }
    return $r.Content | ConvertFrom-Json -Depth 50 -AsHashtable
}

function Search-Graph([string] $Query) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $body = @{ subscriptions = @($SubscriptionId); query = $Query; options = @{ '$top' = 1000; resultFormat = 'objectArray' } }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    do {
        $r = Invoke-Arm POST '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' $body
        foreach ($x in $r.data) { $rows.Add($x) }
        $body.options['$skipToken'] = $r['$skipToken']
        if ($r['$skipToken'] -and -not $seen.Add($r['$skipToken'])) { throw 'Resource Graph repeated a continuation token.' }
        if ($r.resultTruncated -eq 'true' -and -not $r['$skipToken']) { throw 'Resource Graph truncated evidence without a continuation token.' }
    } while ($r['$skipToken'])
    return , $rows
}

$sub = Invoke-Arm GET "/subscriptions/$($SubscriptionId)?api-version=2022-12-01"
$rgFilter = if ($ResourceGroupName) { "| where resourceGroup =~ '$($ResourceGroupName.Replace("'", "''"))'" } else { '' }
$rgNameFilter = if ($ResourceGroupName) { "| where name =~ '$($ResourceGroupName.Replace("'", "''"))'" } else { '' }
$rgs = Search-Graph "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' $rgNameFilter | project name, location, tags"
$res = Search-Graph "resources $rgFilter | project id, name, type, resourceGroup, location, tags"

$doc = [ordered]@{
    schemaVersion  = '1.0'
    collectedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    collectedBy    = "Get-EnvironmentEvidence.ps1 as $account (read-only: GET subscription; Resource Graph resourcecontainers/resources)"
    scope          = [ordered]@{ subscriptionId = $SubscriptionId; resourceGroup = $ResourceGroupName }
    subscription   = [ordered]@{
        id            = $SubscriptionId
        name          = $sub.displayName
        quotaId       = $sub.subscriptionPolicies.quotaId
        spendingLimit = $sub.subscriptionPolicies.spendingLimit
        tags          = Select-ClassificationTags $sub.tags
    }
    resourceGroups = @($rgs | ForEach-Object { [ordered]@{ name = $_.name; location = $_.location; tags = Select-ClassificationTags $_.tags } })
    resources      = @($res | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; type = $_.type; resourceGroup = $_.resourceGroup; location = $_.location; tags = Select-ClassificationTags $_.tags } })
    coverage       = [ordered]@{ status = 'Completed'; tagSelection = 'Only configured classification keys retained; other tags omitted' }
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null
$doc | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutFile -Encoding utf8
Write-Host "[wara] Environment evidence: $($doc.resourceGroups.Count) resource group(s), $($doc.resources.Count) resource(s), offer $($doc.subscription.quotaId) -> $OutFile"
