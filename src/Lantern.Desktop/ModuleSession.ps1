$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
. "$PSScriptRoot/ActivityCommands.ps1"
$context = $null
try {
    while ($line = [Console]::ReadLine()) {
        try {
            $request = $line | ConvertFrom-Json
            $result = $null
            switch ($request.action) {
                'connect' {
                    $module = Get-Module -ListAvailable Microsoft.Graph.Authentication | Where-Object Version -ge ([version]'2.36.1') | Sort-Object Version -Descending | Select-Object -First 1
                    if (!$module) { throw 'Missing Graph module' }
                    Import-Module $module.Path
                    $scopes = @('AuditLog.Read.All','User.Read.All','Device.Read.All')
                    if ($request.includeGrants) { $scopes += 'Directory.Read.All' }
                    Connect-MgGraph -TenantId $request.tenant -Scopes $scopes -ContextScope Process -NoWelcome | Out-Null
                    $context = Get-MgContext
                    if ($context.TenantId -ne $request.tenant -or $context.ContextScope -ne 'Process' -or $context.AuthType -ne 'Delegated') { throw 'Context mismatch' }
                    $result = @{tenant=$context.TenantId; account=$context.Account}
                }
                'graph' {
                    if (!$context) { throw 'Not connected' }
                    $uri = [uri]$request.uri
                    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'graph.microsoft.com' -or $uri.Port -ne 443 -or ($uri.AbsolutePath -notin @('/v1.0/auditLogs/signIns','/beta/auditLogs/signIns','/v1.0/auditLogs/directoryAudits','/v1.0/users','/v1.0/oauth2PermissionGrants','/v1.0/reports/authenticationMethods/userRegistrationDetails') -and $uri.AbsolutePath -notmatch '^/v1\.0/users/[0-9a-fA-F-]{36}/registeredDevices$') -or $uri.UserInfo -or $uri.Fragment) { throw 'Invalid endpoint' }
                    try {
                        $body = Invoke-MgGraphRequest -Method GET -Uri $uri.AbsoluteUri -OutputType Json
                        $result = @{status=200;body=$body}
                    } catch {
                        $status = 500
                        if ($_.Exception.Response.StatusCode) { $status = [int]$_.Exception.Response.StatusCode }
                        # Do not send server error bodies through the pipe.
                        $result = @{status=$status;body='{}'}
                    }
                }
                { $_ -in @('exchange','activity') } {
                    if (!$context) { throw 'Not connected' }
                    $module = Get-Module -ListAvailable ExchangeOnlineManagement | Where-Object Version -ge ([version]'3.7.0') | Sort-Object Version -Descending | Select-Object -First 1
                    if (!$module) { throw 'Missing Exchange module' }
                    Import-Module $module.Path
                    try {
                        if (@(Get-ConnectionInformation).Count -eq 0) { Connect-ExchangeOnline -UserPrincipalName $context.Account -DisableWAM -ShowBanner:$false -ShowProgress:$false -CommandName Get-Mailbox,Get-InboxRule,Get-MessageTraceV2,Search-UnifiedAuditLog -EnableErrorReporting:$false | Out-Null }
                        $connections = @(Get-ConnectionInformation)
                        if ($connections.Count -ne 1 -or $connections[0].TenantID -ne $context.TenantId -or $connections[0].UserPrincipalName -ne $context.Account) { throw 'Exchange context mismatch' }
                        if ($request.action -eq 'activity') { $result = Invoke-LanternActivity $request; break }
                        $mailbox = $null; $rules = @(); $mailboxOk = $false; $rulesOk = $false
                        try {
                            $mailbox = Get-Mailbox -Identity $request.account | Select-Object UserPrincipalName,PrimarySmtpAddress,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
                            $mailboxOk = $null -ne $mailbox
                        } catch { }
                        try {
                            $rules = @(Get-InboxRule -Mailbox $request.account -IncludeHidden | Select-Object Identity,Name,Enabled,Priority,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder,MarkAsRead,StopProcessingRules,Description)
                            $rulesOk = $true
                        } catch { }
                        $result = @{rulesOk=$rulesOk;mailboxOk=$mailboxOk;rules=$rules;mailbox=$mailbox}
                    } catch { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; if ($request.action -eq 'activity') { $result = @{status='connectionUnavailable';rows=@()} } else { $result = @{rulesOk=$false;mailboxOk=$false;rules=@();mailbox=$null} } }
                }
                'disconnect' { break }
                default { throw 'Unknown operation' }
            }
            if ($request.action -eq 'disconnect') { break }
            [Console]::WriteLine(('LANTERN:' + (@{ok=$true;result=$result} | ConvertTo-Json -Depth 30 -Compress)))
        } catch {
            if ($request.action -eq 'activity') { [Console]::WriteLine('LANTERN:{"ok":true,"result":{"status":"connectionUnavailable","rows":[]}}') }
            elseif ($request.action -eq 'exchange') { [Console]::WriteLine('LANTERN:{"ok":true,"result":{"rulesOk":false,"mailboxOk":false,"rules":[],"mailbox":null}}') }
            else { [Console]::WriteLine('LANTERN:{"ok":false}') }
        }
    }
} finally {
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
    if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    $context = $null
}
