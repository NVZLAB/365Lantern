. "$PSScriptRoot/ActivityCommands.ps1"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
try {
    Import-Module ExchangeOnlineManagement -MinimumVersion 3.7.0 -ErrorAction Stop
    if ([Console]::ReadLine() -eq 'preflight') { [Console]::WriteLine('ready'); exit 0 }
    $request = [Console]::ReadLine() | ConvertFrom-Json
    Connect-ExchangeOnline -AccessToken $request.token -UserPrincipalName $request.operator -ShowBanner:$false -ShowProgress:$false -CommandName Get-Mailbox,Get-InboxRule,Get-MessageTraceV2,Search-UnifiedAuditLog -EnableErrorReporting:$false -ErrorAction Stop | Out-Null
    $request.token = $null
    if ($request.activity) { [Console]::WriteLine((Invoke-LanternActivity $request.activity | ConvertTo-Json -Depth 30 -Compress)); exit 0 }
    $rules = @(); $mailbox = $null; $rulesOk = $false; $mailboxOk = $false
    try {
        $mailbox = Get-Mailbox -Identity $request.account -ErrorAction Stop | Select-Object UserPrincipalName,PrimarySmtpAddress,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
        $mailboxOk = $null -ne $mailbox
    } catch { }
    try {
        $rules = @(Get-InboxRule -Mailbox $request.account -IncludeHidden -ErrorAction Stop | Select-Object Identity,Name,Enabled,Priority,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder,MarkAsRead,StopProcessingRules,Description)
        $rulesOk = $true
    } catch { }
    [Console]::WriteLine((@{ rulesOk=$rulesOk; mailboxOk=$mailboxOk; rules=$rules; mailbox=$mailbox } | ConvertTo-Json -Depth 12 -Compress))
} catch {
    [Console]::WriteLine('{"rulesOk":false,"mailboxOk":false,"rules":[],"mailbox":null}')
    exit 1
} finally {
    $request = $null
    if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
