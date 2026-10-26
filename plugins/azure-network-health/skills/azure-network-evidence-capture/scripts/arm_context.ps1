function Write-Reply($Value) {
    [Console]::Out.WriteLine(($Value | ConvertTo-Json -Depth 100 -Compress))
    [Console]::Out.Flush()
}

function Convert-JsonElement($Element) {
    switch ($Element.ValueKind.ToString()) {
        'Object' {
            $value = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
            foreach ($property in $Element.EnumerateObject()) {
                if ($value.ContainsKey($property.Name)) { throw 'Duplicate JSON field' }
                $value.Add($property.Name, (Convert-JsonElement $property.Value))
            }
            return ,$value
        }
        'Array' {
            $value = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) { $value.Add((Convert-JsonElement $item)) }
            return ,$value.ToArray()
        }
        'String' { return $Element.GetString() }
        'Number' {
            $number = [long]0
            if ($Element.TryGetInt64([ref]$number)) { return $number }
            return $Element.GetDouble()
        }
        'True' { return $true }
        'False' { return $false }
        'Null' { return $null }
        default { throw 'Unsupported JSON kind' }
    }
}

function Read-ExactJson([string]$Json) {
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 100
    $document = [System.Text.Json.JsonDocument]::Parse($Json, $options)
    try { return ,(Convert-JsonElement $document.RootElement) }
    finally { $document.Dispose() }
}

function Initialize-ReadIdentity([string]$TenantId, [string]$SubscriptionId, [string]$ManagedIdentityClientId) {
    foreach ($value in @($TenantId, $SubscriptionId, $ManagedIdentityClientId)) {
        if ([guid]::Parse($value).ToString() -cne $value) { throw 'Noncanonical scope identifier' }
    }
    $cache = if ($env:WARA_CACHE) { $env:WARA_CACHE } else {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cache/wara-assessment'
    }
    $modules = Join-Path $cache 'modules'
    if (Test-Path -LiteralPath $modules) {
        $env:PSModulePath = "$modules$([IO.Path]::PathSeparator)$env:PSModulePath"
    }
    Import-Module Az.Accounts -ErrorAction Stop
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -Identity -AccountId $ManagedIdentityClientId -Tenant $TenantId `
        -Subscription $SubscriptionId -Scope Process -WarningAction SilentlyContinue | Out-Null
    $context = Get-AzContext
    if ($context.Tenant.Id -ne $TenantId -or $context.Subscription.Id -ne $SubscriptionId) {
        throw 'Managed identity scope mismatch'
    }
    return $context
}

function Write-ReadIdentity([string]$TenantId, [string]$SubscriptionId, [string]$ManagedIdentityClientId) {
    Write-Reply @{
        status = 'ready'
        context = @{
            subscriptionId = $SubscriptionId
            tenantId = $TenantId
            managedIdentityClientId = $ManagedIdentityClientId
            authentication = 'managedIdentity'
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            azAccountsVersion = (Get-Module Az.Accounts).Version.ToString()
        }
    }
}

function Invoke-ReviewedRead($Context, [ValidateSet('GET','POST')][string]$Method, [string]$Path, $Payload = $null) {
    if ($Method -eq 'POST' -and $Path -cne '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01') {
        throw 'POST is limited to the read-only Resource Graph query endpoint'
    }
    try {
        $arguments = @{ Method = $Method; Path = $Path; DefaultProfile = $Context; ErrorAction = 'Stop' }
        if ($Method -eq 'POST') {
            $arguments.Payload = $Payload | ConvertTo-Json -Depth 20 -Compress
        }
        $reply = Invoke-AzRestMethod @arguments
        $requestId = $null
        if ($reply.Headers -is [System.Collections.IDictionary] -and $reply.Headers.Keys -contains 'x-ms-request-id') {
            $requestId = [string]$reply.Headers['x-ms-request-id']
        }
        if ([Text.Encoding]::UTF8.GetByteCount($reply.Content) -gt 5MB) {
            return @{ statusCode = [int]$reply.StatusCode; body = $null; requestId = $requestId
                transportOutcome = 'responseTooLarge'; errorCode = 'RawResponseBudgetExceeded' }
        }
        $body = if ($reply.StatusCode -eq 200) { Read-ExactJson $reply.Content } else { $null }
        return @{ statusCode = [int]$reply.StatusCode; body = $body; requestId = $requestId }
    } catch {
        $status = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        if ($status -ge 400) {
            return @{ statusCode = $status; body = $null; requestId = $null }
        }
        return @{ statusCode = 0; body = $null; requestId = $null; transportOutcome = 'unconfirmed' }
    }
}
