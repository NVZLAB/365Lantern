[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Payload,
    [string]$InnoCompiler='C:/Program Files (x86)/Inno Setup 6/ISCC.exe'
)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$Payload=(Resolve-Path -LiteralPath $Payload).Path
foreach($file in @('365Lantern.exe','365Lantern.dll','dependencies.json','package-files.json','runtime/powershell/pwsh.exe')) {
    if(!(Test-Path -LiteralPath (Join-Path $Payload $file))){throw "Missing packaged dependency: $file"}
}
foreach($entry in (Get-Content (Join-Path $Payload 'package-files.json') -Raw | ConvertFrom-Json)) {
    $path=[IO.Path]::GetFullPath((Join-Path $Payload $entry.path))
    if(!$path.StartsWith($Payload+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Inventory path escaped payload.'}
    if(!(Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.sha256) {throw "Payload inventory mismatch: $($entry.path)"}
}
# Installer and portable edition use the same validated payload, without downloading at install time.
$version=(Get-Item (Join-Path $Payload '365Lantern.dll')).VersionInfo.ProductVersion.Split('+')[0]
if($version -notmatch '^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$'){throw 'Invalid package version.'}
$output=Join-Path $root 'artifacts/installer'
New-Item $output -ItemType Directory -Force | Out-Null
& $InnoCompiler /Qp ("/DPayload=$Payload") ("/DOutput=$output") ("/DVersion=$version") (Join-Path $PSScriptRoot 'Lantern.iss')
if($LASTEXITCODE){throw 'Installer compilation failed.'}
$installer=Join-Path $output "365Lantern-$version-Setup.exe"
((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash+'  '+[IO.Path]::GetFileName($installer)) | Set-Content "$installer.sha256"
Write-Output $installer
