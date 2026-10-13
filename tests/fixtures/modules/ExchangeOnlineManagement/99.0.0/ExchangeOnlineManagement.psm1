function Connect-ExchangeOnline { param($UserPrincipalName,[switch]$DisableWAM,[switch]$Device,$ShowBanner,$ShowProgress,$CommandName,$EnableErrorReporting) $script:attempts++; if($script:attempts -gt 1){throw 'Repeated authentication'}; if(!$Device -and (!$DisableWAM -or $UserPrincipalName -ne 'admin@example.com')) {throw 'Invalid auth options'}; $script:connected=$true }
function Get-ConnectionInformation { if($script:connected){[pscustomobject]@{TenantID='11111111-1111-1111-1111-111111111111';UserPrincipalName='admin@example.com';Attempts=$script:attempts}} }
function Get-Mailbox { param($Identity) [pscustomobject]@{UserPrincipalName=$Identity;PrimarySmtpAddress='alex@example.com';EmailAddresses=@('SMTP:alex@example.com','smtp:alias@example.com');ForwardingSmtpAddress=$null} }
function Get-InboxRule { param($Mailbox,[switch]$IncludeHidden) if(!$IncludeHidden){throw 'Missing hidden rules'} }
function Disconnect-ExchangeOnline { param([switch]$Confirm) $script:connected=$false }
function Get-MessageTraceV2 {
    [CmdletBinding()] param($StartDate,$EndDate,$ResultSize,$RecipientAddress,$SenderAddress,$StartingRecipientAddress,$MessageId)
    if (($EndDate-$StartDate).TotalDays -gt 10 -or $ResultSize -ne 1000 -or (!$RecipientAddress -and !$SenderAddress -and !$MessageId)) { throw 'Invalid trace query' }
}
function Search-UnifiedAuditLog {
    [CmdletBinding()] param($StartDate,$EndDate,$SessionId,$SessionCommand,$ResultSize,$UserIds,$FreeText,$RecordType)
    if (!$SessionId -or $SessionCommand -ne 'ReturnLargeSet' -or $ResultSize -ne 1000 -or (!$UserIds -and !$FreeText)) { throw 'Invalid audit query' }
}
function Get-EXOMailboxPermission { [CmdletBinding()] param($Identity,$ResultSize) if (!$Identity -or $ResultSize -ne 1001) { throw 'Invalid permission query' }; [pscustomobject]@{User='delegate@example.com';AccessRights=@('FullAccess');Deny=$false;IsInherited=$false} }
function Get-EXORecipientPermission { [CmdletBinding()] param($Identity,$ResultSize) if (!$Identity -or $ResultSize -ne 1001) { throw 'Invalid permission query' }; [pscustomobject]@{Trustee='delegate@example.com';AccessRights=@('SendAs');AccessControlType='Allow';IsInherited=$false} }
Export-ModuleMember -Function *
function Get-LanternFakeAttempts { [int]$script:attempts }; Export-ModuleMember -Function *
