param(
    [Parameter(Mandatory)][string]$PackagePath,
    [Parameter(Mandatory)][string]$SignToolPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$TimestampUrl
)
$ErrorActionPreference = 'Stop'
if ($TimestampUrl.Scheme -ne 'https') { throw 'Use an HTTPS RFC3161 timestamp service.' }
$tool = (Resolve-Path -LiteralPath $SignToolPath).Path
if ((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') { throw 'SignTool must have a valid Authenticode signature.' }
$inputPackage = (Resolve-Path -LiteralPath $PackagePath).Path
if ([IO.Path]::GetExtension($inputPackage) -ne '.msix') { throw 'Choose an MSIX package.' }
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
if (!$certificate.HasPrivateKey -or $certificate.NotAfter -lt (Get-Date) -or $certificate.NotBefore -gt (Get-Date)) { throw 'Certificate must be current and have an accessible private key.' }
if ('1.3.6.1.5.5.7.3.3' -notin @($certificate.EnhancedKeyUsageList | ForEach-Object ObjectId)) { throw 'Certificate must explicitly permit code signing.' }
$zip = [IO.Compression.ZipFile]::OpenRead($inputPackage)
try {
    $entry = $zip.GetEntry('AppxManifest.xml')
    if (!$entry) { throw 'Package manifest missing.' }
    $reader = [IO.StreamReader]::new($entry.Open())
    try { [xml]$manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
} finally { $zip.Dispose() }
if ($manifest.Package.Identity.Publisher -cne $certificate.Subject) { throw 'Manifest Publisher must exactly match the certificate subject. Rebuild with the correct Publisher.' }
$output = Join-Path (Split-Path $inputPackage -Parent) (([IO.Path]::GetFileNameWithoutExtension($inputPackage) -replace '-unsigned$','') + '-signed.msix')
if (Test-Path -LiteralPath $output) { throw 'Signed output already exists; refusing to replace it.' }
Copy-Item -LiteralPath $inputPackage -Destination $output
& $tool sign /sha1 $CertificateThumbprint /s My /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 $output
if ($LASTEXITCODE -ne 0) { throw 'Signing failed. Output must not be distributed.' }
& $tool verify /pa /all /v $output
if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed. Output must not be distributed.' }
((Get-FileHash -LiteralPath $output).Hash + '  ' + [IO.Path]::GetFileName($output)) | Set-Content "$output.sha256"
@{ package=[IO.Path]::GetFileName($output); status='Signature verified by SignTool'; subject=$certificate.Subject; certificateThumbprint=$certificate.Thumbprint; timestampService=$TimestampUrl.AbsoluteUri; verifiedUtc=[datetime]::UtcNow.ToString('O') } | ConvertTo-Json | Set-Content "$output.signing.json"
Write-Output "Signed and verified: $output"
