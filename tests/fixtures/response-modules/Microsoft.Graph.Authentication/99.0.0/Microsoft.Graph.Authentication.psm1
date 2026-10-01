# Synthetic module only. Never shipped in the application payload.
function Connect-MgGraph {
    param($TenantId,$Scopes,$ContextScope,[switch]$NoWelcome)
    if ($ContextScope -ne 'Process' -or (@($Scopes) -join ',') -notin @('User.Read.All,User.RevokeSessions.All','User.Read.All,User-PasswordProfile.ReadWrite.All','User.Read.All,UserAuthenticationMethod.ReadWrite.All','User.Read.All,Directory.AccessAsUser.All')) { throw 'Unexpected response scopes' }
    $script:tenant=$TenantId; $script:scopes=$Scopes; $script:posts=0; $script:reads=0; $script:methodReads=0; $script:deviceReads=0
}
function Set-MgRequestContext { param($MaxRetry,$ClientTimeout) if ($MaxRetry -ne 0 -or $ClientTimeout -ne 60) { throw 'Unsafe retries' } }
function Get-MgContext { [pscustomobject]@{TenantId=$script:tenant; Account='admin@example.com'; ContextScope='Process'; AuthType='Delegated'; Scopes=$script:scopes} }
function Invoke-MgGraphRequest {
    param($Method,$Uri,$OutputType,$Body,$ContentType)
    if ($Method -in @('GET','POST') -and $OutputType -ne 'PSObject') { throw 'Unexpected format' }
    $id='22222222-2222-2222-2222-222222222222'
    $operator='33333333-3333-3333-3333-333333333333'
    if ($Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/users/admin%40example.com?$select=id') { return [pscustomobject]@{id=$operator} }
    if ($Method -eq 'GET' -and $Uri -in @(('https://graph.microsoft.com/v1.0/users/' + $id + '?$select=id,displayName,userPrincipalName,userType,signInSessionsValidFromDateTime'),('https://graph.microsoft.com/v1.0/users/' + $id + '?$select=id,displayName,userPrincipalName,userType,signInSessionsValidFromDateTime,onPremisesSyncEnabled,lastPasswordChangeDateTime'))) {
        $script:reads++
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'missing-sync-state') { return [pscustomobject]@{id=$id;userPrincipalName='test@example.com';userType='Member';displayName='Synthetic Test'} }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'verify-fails' -and $script:posts) { throw 'Verification unavailable' }
        return [pscustomobject]@{id=$(if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'self') {$operator} else {$id}); userPrincipalName=$(if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'changed' -and $script:reads -gt 1) {'changed@example.com'} else {'test@example.com'}); displayName='Synthetic Test'; userType=$(if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'guest') {'Guest'} else {'Member'}); onPremisesSyncEnabled=($env:LANTERN_RESPONSE_TEST_MODE -eq 'synced' -or ($env:LANTERN_RESPONSE_TEST_MODE -eq 'became-synced' -and $script:reads -gt 1)); lastPasswordChangeDateTime=$(if ($script:posts -and $env:LANTERN_RESPONSE_TEST_MODE -ne 'delayed') {'2026-10-01T12:01:00Z'} else {'2026-10-01T12:00:00Z'}); signInSessionsValidFromDateTime=$(if ($script:posts -and $env:LANTERN_RESPONSE_TEST_MODE -ne 'delayed') {'2026-10-01T12:01:00Z'} else {'2026-10-01T12:00:00Z'})}
    }
    if ($Method -eq 'GET' -and $Uri -eq ('https://graph.microsoft.com/v1.0/users/' + $id + '/authentication/methods')) {
        if ($script:scopes -notcontains 'UserAuthenticationMethod.ReadWrite.All') { throw 'Wrong scope' }
        $script:methodReads++
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'verify-fails' -and $script:posts) { throw 'Verification unavailable' }
        $methods = @([pscustomobject]@{id='password-method';'@odata.type'='#microsoft.graph.passwordAuthenticationMethod'})
        if (!$script:posts -or $env:LANTERN_RESPONSE_TEST_MODE -eq 'delayed') { $methods += [pscustomobject]@{id='synthetic-method_1';'@odata.type'='#microsoft.graph.microsoftAuthenticatorAuthenticationMethod';displayName=$(if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'method-changed' -and $script:methodReads -gt 1) {'Changed Phone'} else {'Synthetic Phone'})} }
        return [pscustomobject]@{value=$methods; '@odata.nextLink'=$(if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'partial-methods') {'https://untrusted.example'} else {$null})}
    }
    if ($Method -eq 'PATCH' -and $Uri -eq ('https://graph.microsoft.com/v1.0/users/' + $id)) {
        if ($OutputType -ne 'HttpResponseMessage' -or $ContentType -ne 'application/json' -or $script:scopes -notcontains 'User-PasswordProfile.ReadWrite.All') { throw 'Invalid password protocol' }
        $data = $Body | ConvertFrom-Json
        if (@($data.PSObject.Properties).Count -ne 1 -or @($data.passwordProfile.PSObject.Properties).Count -ne 2 -or $data.passwordProfile.forceChangePasswordNextSignIn -ne $true -or $data.passwordProfile.password -ne 'SYNTHETIC-Password!NeverUse1') { throw 'Wrong password fields' }
        $script:posts++
        if ($script:posts -gt 1) { throw 'Repeated write' }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'deny') { throw [System.Net.Http.HttpRequestException]::new('Denied', $null, [System.Net.HttpStatusCode]::Forbidden) }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'unknown') { throw 'Synthetic connection lost' }
        return [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NoContent)
    }
    if ($Method -eq 'DELETE' -and $Uri -eq ('https://graph.microsoft.com/v1.0/users/' + $id + '/authentication/microsoftAuthenticatorMethods/synthetic-method_1')) {
        if ($OutputType -ne 'HttpResponseMessage' -or $script:scopes -notcontains 'UserAuthenticationMethod.ReadWrite.All') { throw 'Wrong method protocol' }
        $script:posts++
        if ($script:posts -gt 1) { throw 'Repeated write' }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'deny') { throw [System.Net.Http.HttpRequestException]::new('Denied', $null, [System.Net.HttpStatusCode]::Forbidden) }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'unknown') { throw 'Synthetic connection lost' }
        return [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NoContent)
    }
    if ($Method -eq 'POST' -and $Uri -eq ('https://graph.microsoft.com/v1.0/users/' + $id + '/revokeSignInSessions')) {
        $script:posts++
        if ($script:posts -gt 1) { throw 'Repeated write' }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'deny') { throw [System.Net.Http.HttpRequestException]::new('Denied', $null, [System.Net.HttpStatusCode]::Forbidden) }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'unknown') { throw 'Synthetic connection lost' }
        return [pscustomobject]@{value=$true}
    }
    $deviceObject='44444444-4444-4444-4444-444444444444'
    $deviceId='55555555-5555-5555-5555-555555555555'
    if ($Method -eq 'GET' -and $Uri -eq ('https://graph.microsoft.com/v1.0/users/' + $id + '/registeredDevices?$select=id,deviceId,displayName,operatingSystem,trustType,isManaged,onPremisesSyncEnabled,physicalIds,systemLabels&$top=100')) {
        if ($script:scopes -notcontains 'Directory.AccessAsUser.All') { throw 'Wrong device scope' }
        $script:deviceReads++
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'inventory-denied') { throw 'Access denied' }
        $device=[pscustomobject]@{id=$deviceObject;deviceId=$deviceId;displayName='Synthetic laptop';operatingSystem='Windows';trustType='Workplace';isManaged=$false;onPremisesSyncEnabled=$null;physicalIds=@();systemLabels=@()}
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'managed') { $device.isManaged=$true }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'hybrid') { $device.trustType='ServerAd';$device.onPremisesSyncEnabled=$true }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'joined') { $device.trustType='AzureAd' }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'autopilot') { $device.physicalIds=@('[ZTDId]:synthetic') }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'system-managed') { $device.systemLabels=@('AzureResource') }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'missing-device-metadata') { $device.PSObject.Properties.Remove('isManaged') }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'device-changed' -and $script:deviceReads -gt 1) { $device.displayName='Changed laptop' }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'became-managed' -and $script:deviceReads -gt 1) { $device.isManaged=$true }
        $devices=@($device)
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'association-changed' -and $script:deviceReads -gt 1) { $devices=@() }
        return [pscustomobject]@{value=$devices;'@odata.nextLink'=$(if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'partial-devices') {'https://untrusted.example'} else {$null})}
    }
    if ($Method -eq 'DELETE' -and $Uri -eq ('https://graph.microsoft.com/v1.0/devices/' + $deviceObject)) {
        if ($OutputType -ne 'HttpResponseMessage' -or $script:scopes -notcontains 'Directory.AccessAsUser.All' -or $script:deviceReads -ne 2) { throw 'Wrong device protocol' }
        $script:posts++
        if ($script:posts -gt 1) { throw 'Repeated write' }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'deny') { throw [System.Net.Http.HttpRequestException]::new('Denied', $null, [System.Net.HttpStatusCode]::Forbidden) }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'unknown') { throw 'Synthetic connection lost' }
        return [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NoContent)
    }
    if ($Method -eq 'GET' -and $Uri -eq ('https://graph.microsoft.com/v1.0/devices/' + $deviceObject + '?$select=id') -and $script:posts -eq 1) {
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'verify-fails') { throw [System.Net.Http.HttpRequestException]::new('Denied', $null, [System.Net.HttpStatusCode]::Forbidden) }
        if ($env:LANTERN_RESPONSE_TEST_MODE -eq 'delayed') { return [pscustomobject]@{id=$deviceObject} }
        throw [System.Net.Http.HttpRequestException]::new('Absent', $null, [System.Net.HttpStatusCode]::NotFound)
    }
    throw 'Unexpected response endpoint'
}
function Disconnect-MgGraph { }
Export-ModuleMember -Function *
