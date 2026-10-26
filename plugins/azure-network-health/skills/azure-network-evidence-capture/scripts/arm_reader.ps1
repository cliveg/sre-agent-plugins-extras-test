param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ManagedIdentityClientId,
    [switch]$ReferenceProfile
)
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

. (Join-Path $PSScriptRoot 'arm_context.ps1')

try {
    $context = Initialize-ReadIdentity $TenantId $SubscriptionId $ManagedIdentityClientId
    $profile = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'configuration-profile.json') -Raw |
        ConvertFrom-Json -Depth 100 -AsHashtable
    $allowed = [System.Collections.Generic.List[object]]::new()
    $types = @($profile.types.Values)
    if ($ReferenceProfile) {
        $types += @(
            @('Microsoft.Network/privateEndpoints/privateDnsZoneGroups', '2026-01-01'),
            @('Microsoft.Network/privateDnsZones/ALL', '2018-09-01'),
            @('Microsoft.Network/dnsResolvers', '2022-07-01'),
            @('Microsoft.Network/dnsResolvers/inboundEndpoints', '2022-07-01'),
            @('Microsoft.Network/dnsResolvers/outboundEndpoints', '2022-07-01'),
            @('Microsoft.Network/dnsForwardingRulesets', '2022-07-01'),
            @('Microsoft.Network/dnsForwardingRulesets/forwardingRules', '2022-07-01'),
            @('Microsoft.Network/dnsForwardingRulesets/virtualNetworkLinks', '2022-07-01')
        )
    }
    foreach ($entry in $types) {
        $parts = $entry[0].Split('/')
        $provider = [regex]::Escape($parts[0])
        $root = [regex]::Escape($parts[1])
        if ($parts.Count -eq 2) {
            $allowed.Add(@{ pattern = "^/subscriptions/$SubscriptionId/providers/$provider/$root$"; version = $entry[1] })
        }
        $path = "^/subscriptions/$SubscriptionId/resourceGroups/[^/]+/providers/$provider"
        for ($i = 1; $i -lt $parts.Count; $i++) {
            $path += '/' + [regex]::Escape($parts[$i]) + '/[^/]+'
        }
        $allowed.Add(@{ pattern = $path + '$'; version = $entry[1] })
        if ($parts.Count -gt 2) {
            $parent = "^/subscriptions/$SubscriptionId/resourceGroups/[^/]+/providers/$provider"
            for ($i = 1; $i -lt $parts.Count - 1; $i++) {
                $parent += '/' + [regex]::Escape($parts[$i]) + '/[^/]+'
            }
            $allowed.Add(@{ pattern = $parent + '/' + [regex]::Escape($parts[-1]) + '$'; version = $entry[1] })
        }
    }
    Write-ReadIdentity $TenantId $SubscriptionId $ManagedIdentityClientId
} catch {
    Write-Reply @{ status = 'failed'; code = 'ManagedIdentityRuntimeUnavailable' }
    exit 2
}

while ($null -ne ($line = [Console]::In.ReadLine())) {
    try {
        if ($line.Length -gt 16384) { throw 'Request byte budget exceeded' }
        $request = Read-ExactJson $line
        if ($ReferenceProfile -and $request.ContainsKey('query')) {
            if ($request.Keys.Count -ne 3 -or -not $request.ContainsKey('first') -or
                -not $request.ContainsKey('skipToken') -or $request.query -isnot [string] -or
                $request.query.Length -gt 32768 -or $request.first -isnot [long] -or
                $request.first -lt 1 -or $request.first -gt 1000 -or
                ($null -ne $request.skipToken -and (
                    $request.skipToken -isnot [string] -or $request.skipToken -cnotmatch '^[A-Za-z0-9+/=_-]+$'
                ))) { throw 'Invalid read-only Resource Graph request' }
            $options = @{ '$top' = $request.first; resultFormat = 'objectArray' }
            if ($null -ne $request.skipToken) { $options['$skipToken'] = $request.skipToken }
            $body = @{ subscriptions = @($SubscriptionId); query = $request.query; options = $options }
            Write-Reply (Invoke-ReviewedRead $context 'POST' `
                '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' $body)
            continue
        }
        if ($request.Keys.Count -ne 1 -or -not $request.ContainsKey('url')) { throw 'Invalid request shape' }
        $uri = [uri]$request.url
        if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'management.azure.com' -or
            $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment) { throw 'Unapproved ARM origin' }
        $path = [uri]::UnescapeDataString($uri.AbsolutePath)
        if ($path -match '[\\%]' -or ($path.Split('/') | Where-Object { $_ -in @('.', '..') })) {
            throw 'Unapproved ARM path'
        }
        $parameters = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        foreach ($part in $uri.Query.TrimStart('?').Split('&')) {
            $pair = $part.Split('=', 2)
            if ($pair.Count -ne 2) { throw 'Invalid ARM query' }
            $key = [uri]::UnescapeDataString($pair[0])
            if ($key -cnotin @('api-version', '$skiptoken', '$skipToken', '$top') -or $parameters.ContainsKey($key)) {
                throw 'Unapproved ARM query'
            }
            $parameters.Add($key, [uri]::UnescapeDataString($pair[1]))
        }
        $match = @($allowed | Where-Object { $path -match $_.pattern -and $parameters['api-version'] -eq $_.version })
        if (-not $match.Count) { throw 'Unapproved ARM resource/API' }
        if ($parameters.ContainsKey('$top') -and ([int]$parameters['$top'] -lt 1 -or [int]$parameters['$top'] -gt 1000)) {
            throw 'Unapproved ARM row budget'
        }
    } catch {
        Write-Reply @{ statusCode = 0; body = $null; requestId = $null; errorCode = 'ArmScopePolicyRejected' }
        continue
    }
    Write-Reply (Invoke-ReviewedRead $context 'GET' $uri.PathAndQuery)
}
