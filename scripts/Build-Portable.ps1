param([string]$Dotnet = 'dotnet')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root ('artifacts/portable-' + [guid]::NewGuid().ToString('N'))
$package = Join-Path $build '365Lantern'
New-Item $package -ItemType Directory -Force | Out-Null
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:POWERSHELL_TELEMETRY_OPTOUT = '1'
$env:POWERSHELL_UPDATECHECK = 'Off'
# Inputs are pinned. Only build tooling downloads dependencies; the application never installs them.
$psVersion = '7.6.6'
$moduleVersions = [ordered]@{ 'Microsoft.Graph.Authentication'='2.40.0'; 'ExchangeOnlineManagement'='3.10.1'; 'PowerShellGet'='2.2.5'; 'PackageManagement'='1.4.8.1' }
$assetName = "PowerShell-$psVersion-win-x64.zip"
$release = Invoke-RestMethod "https://api.github.com/repos/PowerShell/PowerShell/releases/tags/v$psVersion" -Headers @{ 'User-Agent'='365Lantern-release-builder' }
$asset = @($release.assets | Where-Object name -eq $assetName)
if ($asset.Count -ne 1 -or $asset[0].digest -notmatch '^sha256:([a-fA-F0-9]{64})$') { throw 'Official PowerShell asset SHA-256 digest unavailable.' }
$expectedHash = $Matches[1]
$zip = Join-Path $build $assetName
Invoke-WebRequest "https://github.com/PowerShell/PowerShell/releases/download/v$psVersion/$assetName" -OutFile $zip
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $expectedHash) { throw 'PowerShell SHA-256 mismatch.' }
$runtime = Join-Path $package 'runtime/powershell'
Expand-Archive -LiteralPath $zip -DestinationPath $runtime
$modules = Join-Path $package 'runtime/modules'
New-Item $modules -ItemType Directory -Force | Out-Null
foreach ($name in $moduleVersions.Keys) { Save-Module -Name $name -RequiredVersion $moduleVersions[$name] -Repository PSGallery -Path $modules -Force -ErrorAction Stop }
& $Dotnet publish (Join-Path $root 'src/Lantern.Desktop/Lantern.Desktop.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:PublishTrimmed=false -p:DebugType=None -p:DebugSymbols=false -o $package
if ($LASTEXITCODE -ne 0) { throw 'Portable publish failed.' }
$version = (Get-Item (Join-Path $package '365Lantern.dll')).VersionInfo.ProductVersion.Split('+')[0]
Copy-Item (Join-Path $root 'LICENSE'),(Join-Path $root 'CHANGELOG.md'),(Join-Path $PSScriptRoot 'PORTABLE-README.txt') -Destination $package
@{ version=$version; platform='win-x64'; powershell=$psVersion; powershellSourceSha256=$expectedHash; modules=$moduleVersions; signing='365Lantern application is unsigned' } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $package 'dependencies.json')
# Validate packaged module discovery without signing in or touching a tenant.
$env:PSModulePath = $modules + [IO.Path]::PathSeparator + (Join-Path $runtime 'Modules')
& (Join-Path $runtime 'pwsh.exe') -NoLogo -NoProfile -NonInteractive -Command 'Import-Module Microsoft.Graph.Authentication -ErrorAction Stop; Import-Module ExchangeOnlineManagement -ErrorAction Stop; Get-Command Connect-MgGraph,Connect-ExchangeOnline,Get-EXOMailboxPermission,Get-EXORecipientPermission,Get-MessageTraceV2,Search-UnifiedAuditLog -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name; if (!(Get-Command Connect-MgGraph) -or !(Get-Command Connect-ExchangeOnline)) { exit 1 }'
if ($LASTEXITCODE -ne 0) { throw 'Packaged module import failed.' }
$smoke = Join-Path $build 'smoke'
$process = Start-Process -FilePath (Join-Path $package '365Lantern.exe') -ArgumentList "--smoke-test `"$smoke`"" -WindowStyle Hidden -PassThru -Wait
if ($process.ExitCode -ne 0 -or !(Test-Path (Join-Path $smoke 'smoke-result.txt'))) { throw 'Packaged app smoke test failed.' }
$files = Get-ChildItem -LiteralPath $package -File -Recurse -Force | ForEach-Object { @{ path=[IO.Path]::GetRelativePath($package,$_.FullName); sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } }
ConvertTo-Json -InputObject @($files) -Depth 3 | Set-Content (Join-Path $package 'package-files.json')
$output = Join-Path $build "365Lantern-$version-win-x64-portable.zip"
[IO.Compression.ZipFile]::CreateFromDirectory($package, $output, [IO.Compression.CompressionLevel]::Optimal, $true)
((Get-FileHash $output -Algorithm SHA256).Hash + '  ' + [IO.Path]::GetFileName($output)) | Set-Content "$output.sha256"
Write-Output "Portable artifact: $output"
