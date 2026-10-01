param([switch]$Check)
$ErrorActionPreference = 'Stop'
# Never overwrite or terminate a running investigation to rebuild the app.
$workspacePrefix = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
$runningInstances = @(Get-Process -Name '365Lantern' -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path.StartsWith($workspacePrefix, [StringComparison]::OrdinalIgnoreCase)
})
if ($runningInstances.Count -gt 0) {
    $instanceIds = ($runningInstances | ForEach-Object { $_.Id }) -join ', '
    Write-Warning "365Lantern is already running from this workspace (PID: $instanceIds). Export any evidence you need, close all 365Lantern windows, then run this launcher again. No build was started and your session was left open."
    return
}
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_CLI_HOME = Join-Path $PSScriptRoot 'work/dotnet-home'
$env:PSModulePath = (Join-Path $PSScriptRoot 'work/modules') + [IO.Path]::PathSeparator + $env:PSModulePath
$env:NUGET_PACKAGES = Join-Path $PSScriptRoot 'work/nuget'
$localSdk = Join-Path $PSScriptRoot 'work/toolchain/dotnet/dotnet.exe'
$sdk = if (Test-Path $localSdk) { $localSdk } else { 'dotnet' }
Push-Location $PSScriptRoot
try {
    if ($Check) {
        & $sdk run --project 'tests/Lantern.Checks/Lantern.Checks.csproj' -c Release
        if ($LASTEXITCODE -ne 0) { throw 'Validation failed. Review the check output above.' }
    } else {
        & $sdk build 'src/Lantern.Desktop/Lantern.Desktop.csproj' -c Release --nologo
        if ($LASTEXITCODE -ne 0) { throw 'Build failed. Review the build errors above. The application was not started.' }
        & $sdk run --project 'src/Lantern.Desktop/Lantern.Desktop.csproj' -c Release --no-build
        if ($LASTEXITCODE -ne 0) { throw "365Lantern exited with an application error (exit code $LASTEXITCODE). The build succeeded; reinstalling the SDK is not indicated. See the Windows Application event log for crash details." }
    }
} finally { Pop-Location }
