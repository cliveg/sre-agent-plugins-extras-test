param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ManagedIdentityClientId
)
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'arm_context.ps1')

try {
    $context = Initialize-ReadIdentity $TenantId $SubscriptionId $ManagedIdentityClientId
    $template = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'resource-changes.kql') -Raw).Trim()
    Write-ReadIdentity $TenantId $SubscriptionId $ManagedIdentityClientId
} catch {
    Write-Reply @{ status = 'failed'; code = 'ManagedIdentityRuntimeUnavailable' }
    exit 2
}

while ($null -ne ($line = [Console]::In.ReadLine())) {
    try {
        if ($line.Length -gt 32768) { throw 'History request byte budget exceeded' }
        $request = Read-ExactJson $line
        if ($request.Keys.Count -ne 4 -or
            (@('source','start','end','cursor') | Where-Object { -not $request.ContainsKey($_) })) {
            throw 'Unexpected history request shape'
        }
        if ($request.source -cnotin @('activity-log','resource-changes','service-health')) { throw 'Unreviewed history source' }
        foreach ($stamp in @($request.start, $request.end)) {
            if ($stamp -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$') { throw 'Non-UTC history window' }
            [DateTimeOffset]::Parse($stamp) | Out-Null
        }
        $start = [DateTimeOffset]::Parse($request.start)
        $end = [DateTimeOffset]::Parse($request.end)
        if ($start -ge $end -or ($end - $start).TotalDays -gt 365) { throw 'Unbounded history window' }
        $method = 'GET'
        $payload = $null
        if ($request.source -ceq 'resource-changes') {
            $path = '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
            $query = $template.Replace('__SUBSCRIPTION__', $SubscriptionId).Replace('__START__', $request.start).Replace('__END__', $request.end)
            $options = @{ '$top' = 500; resultFormat = 'objectArray' }
            if ($null -ne $request.cursor) {
                if ($request.cursor.Keys.Count -ne 1 -or -not $request.cursor.ContainsKey('skipToken') -or
                    -not ($request.cursor.skipToken -is [string]) -or
                    $request.cursor.skipToken.Length -eq 0 -or $request.cursor.skipToken.Length -gt 16000) {
                    throw 'Invalid Resource Graph continuation'
                }
                $options['$skipToken'] = $request.cursor.skipToken
            }
            $payload = @{ subscriptions = @($SubscriptionId); query = $query; options = $options }
            $method = 'POST'
        } else {
            $activity = $request.source -ceq 'activity-log'
            $basePath = if ($activity) {
                "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/eventtypes/management/values"
            } else {
                "/subscriptions/$SubscriptionId/providers/Microsoft.ResourceHealth/events"
            }
            $version = if ($activity) { '2015-04-01' } else { '2025-05-01' }
            $filter = "eventTimestamp ge '$($request.start)' and eventTimestamp le '$($request.end)'"
            $date = $start.UtcDateTime.ToString('MM/dd/yyyy', [Globalization.CultureInfo]::InvariantCulture)
            if ($null -eq $request.cursor) {
                $path = "$basePath`?api-version=$version"
                if ($activity) { $path += '&$filter=' + [uri]::EscapeDataString($filter) }
                else { $path += '&queryStartTime=' + [uri]::EscapeDataString($date) }
            } else {
                if ($request.cursor.Keys.Count -ne 1 -or -not $request.cursor.ContainsKey('nextLink')) {
                    throw 'Invalid history continuation'
                }
                $uri = [uri]$request.cursor.nextLink
                if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'management.azure.com' -or
                    $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment -or
                    [uri]::UnescapeDataString($uri.AbsolutePath) -ine $basePath) { throw 'Unapproved history continuation origin/path' }
                $parameters = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
                foreach ($part in $uri.Query.TrimStart('?').Split('&')) {
                    $pair = $part.Split('=', 2)
                    if ($pair.Count -ne 2) { throw 'Invalid continuation query' }
                    $key = [uri]::UnescapeDataString($pair[0])
                    if ($key -cnotin @('api-version','$skiptoken','$skipToken','$filter','queryStartTime') -or $parameters.ContainsKey($key)) {
                        throw 'Unapproved continuation query'
                    }
                    $parameters.Add($key, [uri]::UnescapeDataString($pair[1]))
                }
                if ($parameters['api-version'] -cne $version -or
                    -not ($parameters.ContainsKey('$skiptoken') -or $parameters.ContainsKey('$skipToken'))) {
                    throw 'Unapproved continuation API/token'
                }
                if ($parameters.ContainsKey('$filter') -and (-not $activity -or $parameters['$filter'] -cne $filter)) {
                    throw 'Continuation changed requested time window'
                }
                if ($parameters.ContainsKey('queryStartTime') -and ($activity -or $parameters['queryStartTime'] -cne $date)) {
                    throw 'Continuation changed requested history date'
                }
                $path = $uri.PathAndQuery
            }
        }
    } catch {
        Write-Reply @{ statusCode = 0; body = $null; requestId = $null; errorCode = 'HistoryReadPolicyRejected' }
        continue
    }
    Write-Reply (Invoke-ReviewedRead $context $method $path $payload)
}
