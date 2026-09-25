# Fixed read operations only. No server error text is returned to the UI.
function Invoke-LanternActivity {
    param($Request)
    try {
        $rows = @()
        switch ($Request.kind) {
            'resolveAccount' {
                $mailbox = Get-Mailbox -Identity $Request.account -ErrorAction Stop
                $rows = @($mailbox.UserPrincipalName)
            }
            'fullAccess' {
                $rows = @(Get-EXOMailboxPermission -Identity $Request.account -ResultSize 1001 -ErrorAction Stop | ForEach-Object {
                    @{ Trustee=$_.User.ToString(); AccessRights=@($_.AccessRights | ForEach-Object { $_.ToString() }); Deny=$_.Deny; IsInherited=$_.IsInherited }
                })
            }
            'sendAs' {
                $rows = @(Get-EXORecipientPermission -Identity $Request.account -ResultSize 1001 -ErrorAction Stop | ForEach-Object {
                    @{ Trustee=$_.Trustee.ToString(); AccessRights=@($_.AccessRights | ForEach-Object { $_.ToString() }); AccessControlType=$_.AccessControlType.ToString(); IsInherited=$_.IsInherited }
                })
            }
            'sendOnBehalf' {
                $mailbox = Get-Mailbox -Identity $Request.account -ErrorAction Stop
                $rows = @($mailbox.GrantSendOnBehalfTo | Select-Object -First 1001 | ForEach-Object { @{ Trustee=$_.ToString(); AccessRights=@('SendOnBehalf') } })
            }
            'addresses' {
                $mailbox = Get-Mailbox -Identity $Request.account -ErrorAction Stop
                $addresses = @($mailbox.PrimarySmtpAddress.ToString()) + @($mailbox.EmailAddresses | Where-Object { $_ -match '^smtp:' } | ForEach-Object { $_.ToString().Substring(5) })
                return @{ status='ok'; rows=@($addresses | Where-Object { $_ } | Sort-Object -Unique) }
            }
            { $_ -in @('trace','messageTrace') } {
                $start = ([datetimeoffset]$Request.start).UtcDateTime
                $end = ([datetimeoffset]$Request.end).UtcDateTime
                if ($start -ge $end -or ($end-$start).TotalDays -gt 10) { throw 'Invalid period' }
                $parameters = @{StartDate=$start; EndDate=$end; ResultSize=1000; ErrorAction='Stop'}
                if ($Request.kind -eq 'messageTrace') { $parameters.MessageId = $Request.messageId }
                elseif ($Request.direction -eq 'inbound') { $parameters.RecipientAddress = @($Request.addresses) }
                elseif ($Request.direction -eq 'outbound') { $parameters.SenderAddress = @($Request.addresses) }
                else { throw 'Invalid direction' }
                if ($Request.recipient) { $parameters.StartingRecipientAddress = $Request.recipient }
                if ($script:lastTraceRequest) {
                    $delay = 3100 - ([datetime]::UtcNow - $script:lastTraceRequest).TotalMilliseconds
                    if ($delay -gt 0) { Start-Sleep -Milliseconds ([int]$delay) }
                }
                $script:lastTraceRequest = [datetime]::UtcNow
                $rows = @(Get-MessageTraceV2 @parameters | Select-Object Received,SenderAddress,RecipientAddress,Subject,Status,MessageId,MessageTraceId,FromIP,ToIP,Size)
            }
            'audit' {
                $parameters = @{StartDate=(([datetimeoffset]$Request.start).UtcDateTime); EndDate=(([datetimeoffset]$Request.end).UtcDateTime); SessionId=$Request.sessionId; SessionCommand='ReturnLargeSet'; ResultSize=1000; ErrorAction='Stop'}
                # Separate actor and mailbox-owner searches; actor-only queries miss delegate access.
                if ($Request.mode -eq 'actor') { $parameters.UserIds = @($Request.addresses) }
                elseif ($Request.mode -eq 'mailbox') { $parameters.FreeText = $Request.account }
                elseif ($Request.mode -eq 'threat') { $parameters.FreeText = $Request.queryAddress; $parameters.RecordType = 'ThreatIntelligence' }
                else { throw 'Invalid audit scope' }
                $rows = @(Search-UnifiedAuditLog @parameters | Select-Object Identity,AuditData,ResultCount,ResultIndex)
            }
            default { throw 'Unknown operation' }
        }
        return @{status='ok';rows=$rows}
    } catch {
        $status = 'unavailable'
        if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { $status = 'commandUnavailable' }
        elseif ($_.CategoryInfo.Category -in @('PermissionDenied','SecurityError','AuthenticationError')) { $status = 'accessDenied' }
        elseif ($_.Exception.Response.StatusCode -and [int]$_.Exception.Response.StatusCode -eq 429) { $status = 'throttled' }
        return @{status=$status;rows=@()}
    }
}
