function Connect-MgGraph { param($TenantId,$Scopes,$ContextScope,[switch]$NoWelcome) if($ContextScope -ne 'Process' -or (@($Scopes) -join ',') -notin @('AuditLog.Read.All,User.Read.All,Device.Read.All','AuditLog.Read.All,User.Read.All,Device.Read.All,Directory.Read.All')) {throw 'Invalid auth options'}; $script:tenant=$TenantId }
function Get-MgContext { [pscustomobject]@{TenantId=$script:tenant;Account='admin@example.com';ContextScope='Process';AuthType='Delegated'} }
function Invoke-MgGraphRequest { param($Method,$Uri,$OutputType) if($Method -ne 'GET') {throw 'Write attempted'}; '{"value":[{"id":"synthetic","userPrincipalName":"alex@example.com"}]}' }
function Disconnect-MgGraph { }
Export-ModuleMember -Function *
