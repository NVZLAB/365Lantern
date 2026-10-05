param([Parameter(Mandatory)][string]$PowerShellRuntime)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$scratch=Join-Path $root ('work/downloaded-helper-'+[guid]::NewGuid().ToString('N'))
New-Item $scratch -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $root 'src/Lantern.Desktop/ModuleSession.ps1'),(Join-Path $root 'src/Lantern.Desktop/ActivityCommands.ps1') $scratch
Set-Content (Join-Path $scratch 'ModuleSession.ps1') -Stream Zone.Identifier -Value "[ZoneTransfer]`nZoneId=3"
function Invoke-Helper([bool]$ProcessOverride) {
    $start=[Diagnostics.ProcessStartInfo]::new($PowerShellRuntime)
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive')){$start.ArgumentList.Add($arg)}
    $start.ArgumentList.Add('-ExecutionPolicy')
    $start.ArgumentList.Add($(if($ProcessOverride){'Bypass'}else{'RemoteSigned'}))
    $start.ArgumentList.Add('-File')
    $start.ArgumentList.Add((Join-Path $scratch 'ModuleSession.ps1'))
    $process=[Diagnostics.Process]::Start($start)
    $process.StandardInput.Close() # No sign-in request, tenant access or credentials.
    $output=$process.StandardOutput.ReadToEndAsync()
    $errors=$process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $code=$process.ExitCode
    $null=$output.GetAwaiter().GetResult(); $null=$errors.GetAwaiter().GetResult()
    $process.Dispose()
    return $code
}
if((Invoke-Helper $false) -eq 0){throw 'Expected downloaded unsigned helper to be blocked under RemoteSigned.'}
if((Invoke-Helper $true) -ne 0){throw 'Process-scoped launch did not fix downloaded helper startup.'}
Write-Output 'PASS: Internet-marked helper blocked before fix and starts after fix; no tenant accessed.'
