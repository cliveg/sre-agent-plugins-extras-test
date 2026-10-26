# Restricted-egress stand-in for Az.ResourceGraph (wara-assessment plugin).
# Implements the subset of Search-AzGraph that WARA 1.0.6 uses (-Query, -First, -Skip, -SkipToken,
# -Subscription, -ManagementGroup, -UseTenantScope) on top of the Azure Resource Graph REST API
# (api-version 2022-10-01) via Az.Accounts' Invoke-AzRestMethod.
#
# Output contract matches the real PSResourceGraphResponse closely enough for WARA:
# the result enumerates as rows and exposes .Data and .SkipToken.
# Note: a PSObject-wrapped List with note properties breaks @($result) in PowerShell 7.6
# ("Argument types do not match"), hence the compiled response type returned unwrapped.

if (-not ('WaraAssessment.ResourceGraphResponse' -as [type])) {
    Add-Type -TypeDefinition @'
namespace WaraAssessment {
    public class ResourceGraphResponse : System.Collections.Generic.List<object> {
        public string SkipToken { get; set; }
        public System.Collections.Generic.List<object> Data { get { return this; } }
    }
}
'@
}

function Search-AzGraph {
    [CmdletBinding(DefaultParameterSetName = 'Subscription')]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Query,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $First = 100,

        [Parameter()]
        [int] $Skip = 0,

        [Parameter()]
        [string] $SkipToken,

        [Parameter(ParameterSetName = 'Subscription')]
        [string[]] $Subscription,

        [Parameter(ParameterSetName = 'ManagementGroup')]
        [string[]] $ManagementGroup,

        [Parameter(ParameterSetName = 'Tenant')]
        [switch] $UseTenantScope
    )

    $body = @{
        query   = $Query
        options = @{ resultFormat = 'objectArray'; '$top' = $First }
    }
    if ($Skip -gt 0) { $body.options['$skip'] = $Skip }
    if ($SkipToken) { $body.options['$skipToken'] = $SkipToken }
    if ($Subscription) {
        $body.subscriptions = @($Subscription | ForEach-Object { $_ -replace '^/subscriptions/', '' })
    }
    elseif ($ManagementGroup) {
        $body.managementGroups = @($ManagementGroup)
    }
    elseif (-not $UseTenantScope) {
        $ctx = Get-AzContext
        if ($ctx -and $ctx.Subscription) { $body.subscriptions = @($ctx.Subscription.Id) }
    }

    $payload = $body | ConvertTo-Json -Depth 10 -Compress
    $path = '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'

    $resp = $null
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        $resp = Invoke-AzRestMethod -Method POST -Path $path -Payload $payload
        if ($resp.StatusCode -eq 429 -or $resp.StatusCode -ge 500) {
            Start-Sleep -Seconds ([math]::Min(60, [math]::Pow(2, $attempt)))
            continue
        }
        break
    }
    if ($resp.StatusCode -ne 200) {
        throw "Search-AzGraph (wara-assessment shim) failed: HTTP $($resp.StatusCode) $($resp.Content)"
    }

    $json = $resp.Content | ConvertFrom-Json -Depth 100
    $out = [WaraAssessment.ResourceGraphResponse]::new()
    foreach ($row in @($json.data)) { if ($null -ne $row) { $out.Add($row) } }
    $out.SkipToken = $json.'$skipToken'
    return , $out
}

Export-ModuleMember -Function Search-AzGraph
