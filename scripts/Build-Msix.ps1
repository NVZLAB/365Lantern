param(
    [Parameter(Mandatory)][string]$PortableDirectory,
    [Parameter(Mandatory)][string]$MakeAppxPath,
    [string]$Publisher = 'CN=365Lantern Prototype'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = (Resolve-Path -LiteralPath $PortableDirectory).Path
$tool = (Resolve-Path -LiteralPath $MakeAppxPath).Path
if ((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') { throw 'MakeAppx must have a valid Authenticode signature.' }
if ($Publisher -notmatch '^CN=') { throw 'Publisher must be the exact signing certificate subject, beginning CN=.' }
# Consume an existing portable payload, never republish or change its executable files.
$inventory = @(Get-Content -LiteralPath (Join-Path $source 'package-files.json') -Raw | ConvertFrom-Json)
$sourcePrefix = [IO.Path]::GetFullPath($source).TrimEnd('\') + '\'
$listed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $inventory) {
    if ([IO.Path]::IsPathRooted($entry.path) -or $entry.path -match '(^|[/\\])\.\.([/\\]|$)' -or $entry.path.Contains(':')) { throw 'Unsafe inventory path.' }
    $path = [IO.Path]::GetFullPath((Join-Path $source $entry.path))
    if (!$path.StartsWith($sourcePrefix,[StringComparison]::OrdinalIgnoreCase) -or !$listed.Add($path)) { throw 'Invalid/duplicate inventory entry.' }
    if (!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.sha256) { throw "Portable payload integrity failure: $($entry.path)" }
}
foreach ($item in Get-ChildItem -LiteralPath $source -Recurse -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Payload links are not permitted.' }
    if (!$item.PSIsContainer -and $item.FullName -ne (Join-Path $source 'package-files.json') -and !$listed.Contains($item.FullName)) { throw "Unlisted payload file: $($item.Name)" }
}
$displayVersion = (Get-Item (Join-Path $source '365Lantern.dll')).VersionInfo.ProductVersion.Split('+')[0]
$match = [regex]::Match($displayVersion,'\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(alpha|beta|rc)\.([1-9][0-9]{0,2}))?\z')
if (!$match.Success) { throw 'MSIX prototype supports stable or alpha.N/beta.N/rc.N versions, N 1..999.' }
$parts = 1..3 | ForEach-Object { [int]$match.Groups[$_].Value }
if (@($parts | Where-Object { $_ -gt 65535 }).Count) { throw 'Version component exceeds MSIX range.' }
$revision = if (!$match.Groups[4].Success) { 4000 } else { @{alpha=1000;beta=2000;rc=3000}[$match.Groups[4].Value] + [int]$match.Groups[5].Value }
$version = "$($parts -join '.').$revision"
$build = Join-Path $root ('artifacts/msix-' + [guid]::NewGuid().ToString('N'))
$payload = Join-Path $build 'payload'
New-Item $payload -ItemType Directory -Force | Out-Null
Get-ChildItem -LiteralPath $source -Force | Copy-Item -Destination $payload -Recurse
# Derive shell assets from our existing icon; no alternative app branding.
Add-Type -AssemblyName System.Drawing
$assets = Join-Path $payload 'PackageAssets'
New-Item $assets -ItemType Directory | Out-Null
$icon = [Drawing.Icon]::new((Join-Path $root 'src/Lantern.Desktop/Assets/Lantern.ico'),256,256)
$bitmap = $icon.ToBitmap()
try {
    foreach ($size in @(44,50,150)) {
        $image = [Drawing.Bitmap]::new($size,$size)
        $graphics = [Drawing.Graphics]::FromImage($image)
        try { $graphics.Clear([Drawing.Color]::Transparent); $graphics.InterpolationMode='HighQualityBicubic'; $graphics.DrawImage($bitmap,0,0,$size,$size); $image.Save((Join-Path $assets "Logo$size.png"),[Drawing.Imaging.ImageFormat]::Png) }
        finally { $graphics.Dispose(); $image.Dispose() }
    }
    # Windows taskbar assets must explicitly opt out of the accent-color backplate.
    foreach ($size in @(16,20,24,30,32,36,40,48,60,64,72,80,96,256)) {
        $image = [Drawing.Bitmap]::new($size,$size)
        $graphics = [Drawing.Graphics]::FromImage($image)
        try {
            $graphics.Clear([Drawing.Color]::Transparent)
            $graphics.InterpolationMode='HighQualityBicubic'
            $graphics.DrawImage($bitmap,0,0,$size,$size)
            foreach ($variant in @('unplated','lightunplated')) {
                $image.Save((Join-Path $assets "Logo44.targetsize-${size}_altform-$variant.png"),[Drawing.Imaging.ImageFormat]::Png)
            }
        } finally { $graphics.Dispose(); $image.Dispose() }
    }
} finally { $bitmap.Dispose(); $icon.Dispose() }
$escapedPublisher = [Security.SecurityElement]::Escape($Publisher)
@"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" IgnorableNamespaces="uap rescap">
  <Identity Name="NVZLAB.365Lantern.Preview" Publisher="$escapedPublisher" Version="$version" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>365Lantern Preview</DisplayName><PublisherDisplayName>365Lantern</PublisherDisplayName><Logo>PackageAssets\Logo50.png</Logo><Description>Read-only Microsoft 365 investigation preview</Description></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0"/></Dependencies>
  <Resources><Resource Language="en-us"/></Resources>
  <Applications><Application Id="Lantern" Executable="365Lantern.exe" EntryPoint="Windows.FullTrustApplication"><uap:VisualElements DisplayName="365Lantern Preview" Description="Microsoft 365 investigation" BackgroundColor="transparent" Square150x150Logo="PackageAssets\Logo150.png" Square44x44Logo="PackageAssets\Logo44.png"/></Application></Applications>
  <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>
"@ | Set-Content -LiteralPath (Join-Path $payload 'AppxManifest.xml') -Encoding utf8
$output = Join-Path $build "365Lantern-$displayVersion-win-x64-unsigned.msix"
& $tool pack /d $payload /p $output /h SHA256
if ($LASTEXITCODE -ne 0) { throw 'MakeAppx validation/pack failed.' }
# Ensure packaging has not mutated any shared portable files.
foreach ($entry in $inventory) { if ((Get-FileHash -LiteralPath (Join-Path $payload $entry.path) -Algorithm SHA256).Hash -ne $entry.sha256) { throw 'Packaged payload differs from portable build.' } }
@{ packageName='NVZLAB.365Lantern.Preview'; publisher=$Publisher; appVersion=$displayVersion; packageVersion=$version; signing='Unsigned; not installable on a normal trusted configuration'; portableInventorySha256=(Get-FileHash -LiteralPath (Join-Path $source 'package-files.json')).Hash; sharedFilesVerified=$inventory.Count } | ConvertTo-Json | Set-Content (Join-Path $build 'package-provenance.json')
((Get-FileHash -LiteralPath $output).Hash + '  ' + [IO.Path]::GetFileName($output)) | Set-Content "$output.sha256"
Write-Output "Unsigned MSIX prototype: $output"
Write-Output 'No application, certificate or trust setting was installed. Sign a copy before deployment testing.'
