param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ManagedIdentityClientId,
    [string]$ApprovedWorkspacesJson = '[]'
)
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'arm_context.ps1')

function Test-Workspace([string]$Identifier) {
    $pattern = '^/subscriptions/([0-9a-f-]{36})/resourceGroups/[^/?#\\%]+/providers/Microsoft\.OperationalInsights/workspaces/[^/?#\\%]+$'
    if ($Identifier -notmatch $pattern) { throw 'Invalid workspace resource scope' }
    [guid]::Parse($Matches[1]) | Out-Null
    if ($Matches[1] -ine $SubscriptionId -and -not $approved.Contains($Identifier.ToLowerInvariant())) {
        throw 'Workspace read scope is not approved'
    }
}

function Get-FixedQuery([string]$Operation, $Window, $Cursor) {
    foreach ($name in @('start','end')) {
        $stamp = $Window[$name]
        if (-not ($stamp -is [string]) -or $stamp -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$') {
            throw 'Non-UTC query window'
        }
    }
    $start = [DateTimeOffset]::Parse($Window.start)
    $end = [DateTimeOffset]::Parse($Window.end)
    if ($start -ge $end -or ($end - $start).TotalDays -gt 365 -or $end -gt [DateTimeOffset]::UtcNow) {
        throw 'Unbounded or future workspace query'
    }
    $query = $base.Replace('__SUBSCRIPTION__', $SubscriptionId).Replace('__START__', $Window.start).Replace('__END__', $Window.end)
    if ($Operation -ceq 'summary') {
        if ($null -ne $Cursor) { throw 'Summary query cannot page' }
        return "$query`n$summary"
    }
    $after = 'true'
    if ($null -ne $Cursor) {
        if ($Cursor.Keys.Count -ne 2 -or -not $Cursor.ContainsKey('afterTime') -or -not $Cursor.ContainsKey('afterKey') -or
            $Cursor.afterKey -cnotmatch '^[0-9a-f]{64}$' -or
            $Cursor.afterTime -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$') {
            throw 'Unreviewed workspace paging cursor'
        }
        $stamp = [DateTimeOffset]::Parse($Cursor.afterTime)
        if ($stamp -lt $start -or $stamp -gt $end) { throw 'Workspace cursor exceeds approved window' }
        $after = "TimeGenerated > datetime('$($Cursor.afterTime)') or (TimeGenerated == datetime('$($Cursor.afterTime)') and strcmp(RowKey, '$($Cursor.afterKey)') > 0)"
    }
    return "$query`n$($page.Replace('__AFTER__', $after))"
}

function Invoke-LogsRead([string]$WorkspaceId, [string]$Query, $Window) {
    try {
        $token = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io' -DefaultProfile $context -ErrorAction Stop
        $secret = if ($token.Token -is [Security.SecureString]) {
            ConvertFrom-SecureString -SecureString $token.Token -AsPlainText
        } else { [string]$token.Token }
        if (-not $secret) { throw 'Missing Logs token' }
    } catch {
        return @{ statusCode = 401; body = $null; requestId = $null; errorCode = 'LogsCredentialUnavailable' }
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(90)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post,
        "https://api.loganalytics.azure.com/v1/workspaces/$WorkspaceId/query")
    $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $secret)
    $request.Headers.Add('Prefer', 'wait=60')
    $body = @{ query = $Query; timespan = "$($Window.start)/$($Window.end)" } | ConvertTo-Json -Compress
    $request.Content = [Net.Http.StringContent]::new($body, [Text.Encoding]::UTF8, 'application/json')
    $response = $null
    try {
        $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $status = [int]$response.StatusCode
        $requestId = $null
        if ($response.Headers.Contains('x-ms-request-id')) {
            $requestId = [string]($response.Headers.GetValues('x-ms-request-id') | Select-Object -First 1)
        }
        if ($status -ne 200) { return @{ statusCode = $status; body = $null; requestId = $requestId } }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buffer = [byte[]]::new(8192)
        $memory = [IO.MemoryStream]::new()
        try {
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $memory.Write($buffer, 0, $read)
                if ($memory.Length -gt 5MB) {
                    return @{ statusCode = $status; body = $null; requestId = $requestId
                        transportOutcome = 'responseTooLarge'; errorCode = 'LogsResponseBudgetExceeded' }
                }
            }
            $selected = Read-ExactJson ([Text.Encoding]::UTF8.GetString($memory.ToArray()))
            return @{ statusCode = $status; body = $selected; requestId = $requestId }
        } finally {
            $memory.Dispose()
            $stream.Dispose()
        }
    } catch {
        return @{ statusCode = 0; body = $null; requestId = $null; transportOutcome = 'unconfirmed' }
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
        $secret = $null
        $token = $null
    }
}

try {
    $context = Initialize-ReadIdentity $TenantId $SubscriptionId $ManagedIdentityClientId
    $approved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($identifier in (Read-ExactJson $ApprovedWorkspacesJson)) {
        if (-not ($identifier -is [string]) -or
            $identifier -notmatch '^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/?#\\%]+/providers/Microsoft\.OperationalInsights/workspaces/[^/?#\\%]+$') {
            throw 'Invalid explicit workspace scope'
        }
        $approved.Add($identifier.ToLowerInvariant()) | Out-Null
    }
    if ($approved.Count -gt 20) { throw 'Workspace scope count exceeds profile' }
    $known = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $base = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'workspace-base.kql') -Raw).Trim()
    $summary = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'workspace-summary.kql') -Raw).Trim()
    $page = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'workspace-page.kql') -Raw).Trim()
    Write-ReadIdentity $TenantId $SubscriptionId $ManagedIdentityClientId
} catch {
    Write-Reply @{ status = 'failed'; code = 'WorkspaceManagedIdentityRuntimeUnavailable' }
    exit 2
}

while ($null -ne ($line = [Console]::In.ReadLine())) {
    try {
        if ($line.Length -gt 32768) { throw 'Workspace request byte budget exceeded' }
        $frame = Read-ExactJson $line
        if ($frame.Keys.Count -ne 5 -or (@('operation','workspaceResourceId','workspaceId','window','cursor') |
            Where-Object { -not $frame.ContainsKey($_) })) { throw 'Unreviewed workspace request' }
        $operation = $frame.operation
        if ($operation -cnotin @('destinations','describe','table','summary','page')) { throw 'Unreviewed workspace operation' }
        $identifier = [string]$frame.workspaceResourceId
        if ($operation -ceq 'destinations') {
            if ($identifier -cne "/subscriptions/$SubscriptionId" -or $null -ne $frame.workspaceId -or $null -ne $frame.window) {
                throw 'Diagnostic discovery scope differs'
            }
            $path = "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
            if ($null -ne $frame.cursor) {
                if ($frame.cursor.Keys.Count -ne 1 -or -not $frame.cursor.ContainsKey('nextLink')) { throw 'Invalid discovery continuation' }
                $uri = [uri]$frame.cursor.nextLink
                if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'management.azure.com' -or $uri.Port -ne 443 -or
                    $uri.UserInfo -or $uri.Fragment -or $uri.AbsolutePath -ine $path.Split('?')[0]) {
                    throw 'Discovery continuation exceeds approved subscription'
                }
                $parameters = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
                foreach ($part in $uri.Query.TrimStart('?').Split('&')) {
                    $pair = $part.Split('=', 2)
                    if ($pair.Count -ne 2) { throw 'Malformed discovery continuation' }
                    $key = [uri]::UnescapeDataString($pair[0])
                    if ($key -cnotin @('api-version','$skiptoken','$skipToken') -or $parameters.ContainsKey($key)) {
                        throw 'Unreviewed discovery continuation parameters'
                    }
                    $parameters.Add($key, [uri]::UnescapeDataString($pair[1]))
                }
                if ($parameters['api-version'] -cne '2021-05-01-preview' -or
                    -not ($parameters.ContainsKey('$skiptoken') -or $parameters.ContainsKey('$skipToken'))) {
                    throw 'Discovery continuation API/token differs'
                }
                $path = $uri.PathAndQuery
            }
        } else {
            Test-Workspace $identifier
            if ($operation -ceq 'describe') {
                if ($null -ne $frame.workspaceId -or $null -ne $frame.window -or $null -ne $frame.cursor) {
                    throw 'Unreviewed metadata inputs'
                }
                $path = "$identifier`?api-version=2023-09-01"
            } else {
                $guid = [guid]::Parse($frame.workspaceId).ToString()
                if ($guid -cne $frame.workspaceId -or -not $known.ContainsKey($identifier) -or $known[$identifier] -cne $guid) {
                    throw 'Workspace ID differs from authoritative metadata'
                }
                if ($operation -ceq 'table') {
                    if ($null -ne $frame.window -or $null -ne $frame.cursor) { throw 'Unexpected table metadata inputs' }
                    $path = "$identifier/tables/AzureActivity?api-version=2022-10-01"
                } else {
                    $query = Get-FixedQuery $operation $frame.window $frame.cursor
                }
            }
        }
    } catch {
        Write-Reply @{ statusCode = 0; body = $null; requestId = $null; errorCode = 'WorkspaceReadPolicyRejected' }
        continue
    }
    if ($operation -cin @('summary','page')) {
        Write-Reply (Invoke-LogsRead $guid $query $frame.window)
        continue
    }
    $reply = Invoke-ReviewedRead $context 'GET' $path
    if ($operation -ceq 'describe' -and $reply.statusCode -eq 200) {
        try {
            if ($reply.body.id -ine $identifier) { throw 'Workspace metadata ID differs' }
            $known[$identifier] = [guid]::Parse($reply.body.properties.customerId).ToString()
        } catch {
            Write-Reply @{ statusCode = 0; body = $null; requestId = $null; errorCode = 'WorkspaceMetadataBindingFailed' }
            continue
        }
    }
    Write-Reply $reply
}
