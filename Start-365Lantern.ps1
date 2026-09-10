param([switch]$Check)
$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_CLI_HOME = Join-Path $PSScriptRoot 'work/dotnet-home'
$env:NUGET_PACKAGES = Join-Path $PSScriptRoot 'work/nuget'
$localSdk = Join-Path $PSScriptRoot 'work/toolchain/dotnet/dotnet.exe'
$sdk = if (Test-Path $localSdk) { $localSdk } else { 'dotnet' }
Push-Location $PSScriptRoot
try {
    if ($Check) {
        & $sdk run --project 'tests/Lantern.Checks/Lantern.Checks.csproj' -c Release
    } else {
        & $sdk run --project 'src/Lantern.Desktop/Lantern.Desktop.csproj' -c Release
    }
    if ($LASTEXITCODE -ne 0) { throw 'Build or execution failed. Install the .NET 10 SDK if it is not available.' }
} finally { Pop-Location }
