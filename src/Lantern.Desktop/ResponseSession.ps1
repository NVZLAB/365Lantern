# Separate process: investigation helpers never receive response commands or write scopes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = $WarningPreference = $InformationPreference = 'SilentlyContinue'
$prepared = $null
$used = $false
$methodPaths = @{
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'='microsoftAuthenticatorMethods'
    '#microsoft.graph.phoneAuthenticationMethod'='phoneMethods'
    '#microsoft.graph.softwareOathAuthenticationMethod'='softwareOathMethods'
    '#microsoft.graph.fido2AuthenticationMethod'='fido2Methods'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'='windowsHelloForBusinessMethods'
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'='temporaryAccessPassMethods'
}
$methodNames = @{
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'='Microsoft Authenticator'
    '#microsoft.graph.phoneAuthenticationMethod'='Phone (SMS / voice)'
    '#microsoft.graph.softwareOathAuthenticationMethod'='Authenticator code (software OATH)'
    '#microsoft.graph.fido2AuthenticationMethod'='Passkey / security key'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'='Windows Hello for Business'
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'='Temporary Access Pass'
    '#microsoft.graph.passwordAuthenticationMethod'='Password — use Reset password'
    '#microsoft.graph.emailAuthenticationMethod'='Recovery email'
}
function Format-ResponseStamp($value) {
    if (!$value) { return '' }
    try { ([datetimeoffset]$value).ToUniversalTime().ToString('O') } catch { '' }
}
function Read-ResponseUser([string]$id) {
    if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { throw 'Invalid identity' }
    $select = '?$select=id,displayName,userPrincipalName,userType,signInSessionsValidFromDateTime'
    if ($script:responseOperation -eq 'password') { $select += ',onPremisesSyncEnabled,lastPasswordChangeDateTime' }
    Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users/' + $id + $select) -OutputType PSObject
}
function Read-ResponseDevices([string]$id) {
    $uri = 'https://graph.microsoft.com/v1.0/users/' + $id + '/registeredDevices?$select=id,deviceId,displayName,operatingSystem,trustType,isManaged,onPremisesSyncEnabled,physicalIds,systemLabels&$top=100'
    $collection = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    if ($collection.'@odata.nextLink' -or $null -eq $collection.value -or @($collection.value).Count -gt 100) { throw 'Incomplete device inventory' }
    foreach ($device in $collection.value) {
        $complete = @('id','deviceId','trustType','isManaged','onPremisesSyncEnabled','physicalIds','systemLabels' | Where-Object { $device.PSObject.Properties.Name -notcontains $_ }).Count -eq 0
        $supported = $complete -and [string]$device.id -match '^[0-9a-fA-F-]{36}$' -and [string]$device.deviceId -match '^[0-9a-fA-F-]{36}$' -and $device.trustType -eq 'Workplace' -and $device.isManaged -eq $false -and $device.onPremisesSyncEnabled -ne $true -and @($device.physicalIds | Where-Object { $_ }).Count -eq 0 -and @($device.systemLabels | Where-Object { $_ }).Count -eq 0
        $snapshot = $device | Select-Object id,deviceId,displayName,operatingSystem,trustType,isManaged,onPremisesSyncEnabled,physicalIds,systemLabels | ConvertTo-Json -Compress -Depth 5
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($snapshot)))
        [pscustomobject]@{id=[string]$device.id;deviceId=[string]$device.deviceId;label=([string]$device.displayName + ' — ' + [string]$device.operatingSystem);supported=[bool]$supported;availability=$(if ($supported) {'Unmanaged Entra registration — review shared-device impact'} else {'Use device management tools: managed, joined, system-managed or incomplete metadata'});snapshot=$hash}
    }
}
function Read-ResponseMethods([string]$id) {
    $collection = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users/' + $id + '/authentication/methods') -OutputType PSObject
    if ($collection.'@odata.nextLink' -or $null -eq $collection.value -or @($collection.value).Count -gt 100) { throw 'Incomplete method inventory' }
    foreach ($method in $collection.value) {
        $type = [string]$method.'@odata.type'
        $path = $methodPaths[$type]
        $label = if ($methodNames[$type]) { $methodNames[$type] } else { $type.Replace('#microsoft.graph.', '') }
        if ($method.displayName) { $label += ' — ' + [string]$method.displayName }
        if ($method.phoneNumber) { $phone = [string]$method.phoneNumber; $label += ' ' + [string]$method.phoneType + ' ending ' + $phone.Substring([Math]::Max(0,$phone.Length-4)) }
        # Compare method metadata before deletion without forwarding raw method properties or secrets.
        $snapshot = $method | Select-Object id,'@odata.type',displayName,phoneNumber,phoneType,deviceTag,createdDateTime,creationDateTime,keyStrength | ConvertTo-Json -Compress
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($snapshot)))
        [pscustomobject]@{id=[string]$method.id; type=[string]$path; label=$label; supported=([bool]$path -and [string]$method.id -match '^[A-Za-z0-9_-]{1,512}$'); snapshot=$hash}
    }
}
try {
    while ($line = [Console]::ReadLine()) {
        $result = @{status='Not performed'}
        $dispatched = $false
        try {
            $request = $line | ConvertFrom-Json
            if ($request.action -eq 'prepare' -and !$prepared -and !$used) {
                $script:responseOperation = if ($request.operation) { [string]$request.operation } else { 'revoke' }
                $writeScope = switch ($script:responseOperation) { 'revoke' { 'User.RevokeSessions.All' } 'password' { 'User-PasswordProfile.ReadWrite.All' } 'method' { 'UserAuthenticationMethod.ReadWrite.All' } 'device' { 'Directory.AccessAsUser.All' } default { throw 'Unsupported action' } }
                if ($request.tenant -notmatch '^[0-9a-fA-F-]{36}$' -or !$request.actor) { throw 'Invalid context' }
                $module = Get-Module -ListAvailable Microsoft.Graph.Authentication | Where-Object Version -ge ([version]'2.36.1') | Sort-Object Version -Descending | Select-Object -First 1
                if (!$module) { throw 'Missing module' }
                Import-Module $module.Path
                Connect-MgGraph -TenantId $request.tenant -Scopes @('User.Read.All',$writeScope) -ContextScope Process -NoWelcome | Out-Null
                Set-MgRequestContext -MaxRetry 0 -ClientTimeout 60 | Out-Null
                $context = Get-MgContext
                if ($context.TenantId -ne $request.tenant -or $context.Account -ne $request.actor -or $context.ContextScope -ne 'Process' -or $context.AuthType -ne 'Delegated' -or $context.Scopes -notcontains $writeScope) { throw 'Context mismatch' }
                $me = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users/' + [uri]::EscapeDataString($context.Account) + '?$select=id') -OutputType PSObject
                $target = Read-ResponseUser $request.targetId
                if ($target.id -ne $request.targetId -or $target.userType -ne 'Member' -or !$me.id -or $target.id -eq $me.id -or !$target.userPrincipalName) { throw 'Unsupported target' }
                if ($script:responseOperation -eq 'password' -and $target.PSObject.Properties.Name -notcontains 'onPremisesSyncEnabled') { $result = @{status='Not performed';reason='SyncStateUnavailable'}; throw 'Unknown authority' }
                if ($script:responseOperation -eq 'password' -and $target.onPremisesSyncEnabled -eq $true) { $result = @{status='Not performed';reason='SyncedAccount'}; throw 'Synced account' }
                $methods = @()
                $devices = @()
                if ($script:responseOperation -eq 'device') { $devices = @(Read-ResponseDevices $target.id) }
                if ($script:responseOperation -eq 'method') { $methods = @(Read-ResponseMethods $target.id) }
                $prepared = @{tenant=$context.TenantId; actor=$context.Account; targetId=$target.id; account=$target.userPrincipalName; operatorId=$me.id; stamp=[datetimeoffset]::UtcNow; operation=$script:responseOperation; methods=$methods; devices=$devices}
                $result = @{status='Prepared'; id=$target.id; account=$target.userPrincipalName; displayName=$target.displayName; userType=$target.userType; operatorId=$me.id; beforeValidFrom=(Format-ResponseStamp $target.signInSessionsValidFromDateTime); beforePasswordChange=(Format-ResponseStamp $target.lastPasswordChangeDateTime); isSynced=($target.onPremisesSyncEnabled -eq $true); preparedUtc=$prepared.stamp.ToString('O'); methods=@($methods | Select-Object id,type,label,supported)}
                $result.devices = @($devices | Select-Object id,deviceId,label,supported,availability)
            } elseif ($request.action -in @('revoke','password','method','device') -and $prepared -and !$used) {
                # A helper accepts only one execution, bound to its own prepared identity.
                $used = $true
                $context = Get-MgContext
                if ($request.action -ne $prepared.operation -or $request.targetId -ne $prepared.targetId -or $request.tenant -ne $prepared.tenant -or $request.actor -ne $prepared.actor -or $request.approved -isnot [bool] -or $request.approved -ne $true -or ([datetimeoffset]::UtcNow - $prepared.stamp).TotalMinutes -gt 5) { throw 'Preview mismatch or expired' }
                if ($context.TenantId -ne $prepared.tenant -or $context.Account -ne $prepared.actor -or $context.ContextScope -ne 'Process' -or $context.AuthType -ne 'Delegated') { throw 'Context changed' }
                $target = Read-ResponseUser $prepared.targetId
                if ($target.id -ne $prepared.targetId -or $target.userPrincipalName -ne $prepared.account -or $target.userType -ne 'Member' -or $target.id -eq $prepared.operatorId) { throw 'Target changed' }
                if ($request.action -eq 'revoke') {
                    $dispatched = $true
                    $reply = Invoke-MgGraphRequest -Method POST -Uri ('https://graph.microsoft.com/v1.0/users/' + $prepared.targetId + '/revokeSignInSessions') -OutputType PSObject
                    if ($reply.value -ne $true) { $result = @{status='Unknown'} }
                    else {
                        $result = @{status='Accepted';afterValidFrom=''}
                        try { $after = Read-ResponseUser $prepared.targetId; if ($after.id -eq $prepared.targetId) { $result.afterValidFrom = Format-ResponseStamp $after.signInSessionsValidFromDateTime } } catch { }
                    }
                } elseif ($request.action -eq 'password') {
                    if ($target.PSObject.Properties.Name -notcontains 'onPremisesSyncEnabled' -or $target.onPremisesSyncEnabled -eq $true -or $request.temporaryPassword -isnot [string] -or $request.temporaryPassword.Length -lt 8 -or $request.temporaryPassword.Length -gt 256) { throw 'Invalid password reset' }
                    $body = @{passwordProfile=@{password=$request.temporaryPassword; forceChangePasswordNextSignIn=$true}} | ConvertTo-Json -Compress
                    $dispatched = $true
                    try {
                        $reply = Invoke-MgGraphRequest -Method PATCH -Uri ('https://graph.microsoft.com/v1.0/users/' + $prepared.targetId) -Body $body -ContentType 'application/json' -OutputType HttpResponseMessage
                        $result = @{status=$(if ([int]$reply.StatusCode -eq 204) {'Accepted'} else {'Unknown'});afterPasswordChange=''}
                        $reply.Dispose()
                    } finally { $body=$null; $request.temporaryPassword=$null; $line=$null }
                    if ($result.status -eq 'Accepted') {
                        try { $after = Read-ResponseUser $prepared.targetId; if ($after.id -eq $prepared.targetId) { $result.afterPasswordChange = Format-ResponseStamp $after.lastPasswordChangeDateTime } } catch { }
                    }
                } elseif ($request.action -eq 'device') {
                    if ($request.deviceImpactApproved -isnot [bool] -or $request.deviceImpactApproved -ne $true) { throw 'Device impact not approved' }
                    $selected = @($prepared.devices | Where-Object { $_.supported -and $_.id -ceq $request.deviceObjectId })
                    if ($selected.Count -ne 1) { throw 'Unapproved device' }
                    $fresh = @(Read-ResponseDevices $prepared.targetId | Where-Object { $_.id -ceq $selected[0].id -and $_.supported })
                    if ($fresh.Count -ne 1 -or $fresh[0].snapshot -cne $selected[0].snapshot) { throw 'Device or association changed' }
                    $dispatched = $true
                    $deviceUri = 'https://graph.microsoft.com/v1.0/devices/' + $selected[0].id
                    $reply = Invoke-MgGraphRequest -Method DELETE -Uri $deviceUri -OutputType HttpResponseMessage
                    $result = @{status=$(if ([int]$reply.StatusCode -eq 204) {'Accepted'} else {'Unknown'});verification=''}
                    $reply.Dispose()
                    if ($result.status -eq 'Accepted') {
                        try { $null = Invoke-MgGraphRequest -Method GET -Uri ($deviceUri + '?$select=id') -OutputType PSObject }
                        catch {
                            $code = 0
                            if ($_.Exception.Response.StatusCode) { $code = [int]$_.Exception.Response.StatusCode }
                            elseif ($_.Exception.StatusCode) { $code = [int]$_.Exception.StatusCode }
                            if ($code -eq 404) { $result.verification='deviceAbsent' }
                        }
                    }
                } else {
                    $selected = @($prepared.methods | Where-Object { $_.supported -and $_.id -ceq $request.methodId -and $_.type -ceq $request.methodType })
                    if ($selected.Count -ne 1) { throw 'Unapproved method' }
                    $fresh = @(Read-ResponseMethods $prepared.targetId | Where-Object { $_.id -ceq $selected[0].id -and $_.type -ceq $selected[0].type })
                    if ($fresh.Count -ne 1 -or $fresh[0].snapshot -cne $selected[0].snapshot) { throw 'Method changed' }
                    $dispatched = $true
                    $reply = Invoke-MgGraphRequest -Method DELETE -Uri ('https://graph.microsoft.com/v1.0/users/' + $prepared.targetId + '/authentication/' + $selected[0].type + '/' + [uri]::EscapeDataString($selected[0].id)) -OutputType HttpResponseMessage
                    $result = @{status=$(if ([int]$reply.StatusCode -eq 204) {'Accepted'} else {'Unknown'});verification=''}
                    $reply.Dispose()
                    if ($result.status -eq 'Accepted') {
                        try {
                            $remaining = @(Read-ResponseMethods $prepared.targetId)
                            if (@($remaining | Where-Object { $_.id -ceq $selected[0].id -and $_.type -ceq $selected[0].type }).Count -eq 0) { $result.verification='methodAbsent' }
                            $result.remainingMethods=$remaining.Count
                        } catch { }
                    }
                }
            }
        } catch {
            if ($dispatched) {
                $status = 0
                if ($_.Exception.Response.StatusCode) { $status = [int]$_.Exception.Response.StatusCode }
                elseif ($_.Exception.StatusCode) { $status = [int]$_.Exception.StatusCode }
                $result = @{status= $(if ($status -in @(400,401,403,404,405,429)) { 'Denied' } else { 'Unknown' })}
            }
            # No raw server errors, credentials or tokens cross the pipe.
        }
        [Console]::WriteLine(('LANTERN:' + (@{ok=$true;result=$result} | ConvertTo-Json -Depth 6 -Compress)))
        $request=$null; $line=$null; $reply=$null
    }
} finally {
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
    $prepared = $null
}
