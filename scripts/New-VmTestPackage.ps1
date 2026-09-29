param(
    [Parameter(Mandatory)][string]$PackagePath,
    [Parameter(Mandatory)][string]$SignToolPath
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$inputPackage = (Resolve-Path -LiteralPath $PackagePath).Path
$tool = (Resolve-Path -LiteralPath $SignToolPath).Path
if ((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') { throw 'SignTool signature is not valid.' }
$archive = [IO.Compression.ZipFile]::OpenRead($inputPackage)
try {
    $reader = [IO.StreamReader]::new($archive.GetEntry('AppxManifest.xml').Open())
    try { [xml]$manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
} finally { $archive.Dispose() }
if ($manifest.Package.Identity.Publisher -cne 'CN=365Lantern Prototype' -or $manifest.Package.Identity.Name -ne 'NVZLAB.365Lantern.Preview') { throw 'Only the designated preview package may be test-signed.' }
$output = Join-Path $root ('artifacts/vm-test-' + [guid]::NewGuid().ToString('N'))
New-Item $output -ItemType Directory | Out-Null
# Explicit test operation: creates a private key in the current user's Personal store.
# Never export that key or change any trusted certificate store on this machine.
$cert = New-SelfSignedCertificate -Type Custom -Subject 'CN=365Lantern Prototype' `
    -FriendlyName '365Lantern disposable VM testing only' -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyUsage DigitalSignature `
    -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(90) `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3','2.5.29.19={text}')
$publicCert = Join-Path $output '365Lantern-Test.cer'
Export-Certificate -Cert $cert -FilePath $publicCert -Type CERT | Out-Null
$signed = Join-Path $output '365Lantern-VM-Test.msix'
Copy-Item -LiteralPath $inputPackage -Destination $signed
& $tool sign /sha1 $cert.Thumbprint /s My /fd SHA256 $signed
if ($LASTEXITCODE -ne 0) { throw 'Test signing failed.' }
$signature = Get-AuthenticodeSignature -LiteralPath $signed
if ($signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) { throw 'Signed package certificate does not match the generated test certificate.' }
# Public trust verification is expected to fail here: we deliberately did not trust the test cert.
& $tool verify /pa /all /v $signed *> (Join-Path $output 'host-verification.txt')
$verificationExit = $LASTEXITCODE
@{ purpose='Disposable VM testing only, not public distribution'; subject=$cert.Subject; thumbprint=$cert.Thumbprint; expires=$cert.NotAfter.ToUniversalTime().ToString('O'); privateKeyLocation="CurrentUser/My/$($cert.Thumbprint)"; privateKeyExported=$false; hostTrustModified=$false; hostVerificationExit=$verificationExit; msixSha256=(Get-FileHash $signed).Hash; certificateSha256=(Get-FileHash $publicCert).Hash } | ConvertTo-Json | Set-Content (Join-Path $output 'test-signing.json')
@"
DISPOSABLE VM TEST ONLY — NOT A PUBLIC RELEASE

Copy 365Lantern-VM-Test.msix and 365Lantern-Test.cer to C:\LanternTest inside the VM.
Expected certificate thumbprint: $($cert.Thumbprint)
Certificate expires: $($cert.NotAfter.ToString('yyyy-MM-dd'))

1. Inside the VM only, open PowerShell as administrator:
   `$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new('C:\LanternTest\365Lantern-Test.cer')
   if (`$cert.Thumbprint -ne '$($cert.Thumbprint)') { throw 'Wrong test certificate' }
   Import-Certificate -FilePath 'C:\LanternTest\365Lantern-Test.cer' -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'

2. Close that administrator window. In a normal PowerShell window for the test user:
   Add-AppxPackage -Path 'C:\LanternTest\365Lantern-VM-Test.msix'

3. Launch 365Lantern Preview from Start. Do not install the original unsigned file.
   Windows certificate trust is set up once with admin rights; the app install is per-user.
   No Trusted Root import or Defender/SmartScreen bypass is needed.

4. Cleanup: uninstall 365Lantern Preview through Windows Settings. Then, in an
   administrator PowerShell window inside the VM only:
   Remove-Item -LiteralPath 'Cert:\LocalMachine\TrustedPeople\$($cert.Thumbprint)'
   Or discard the disposable VM/snapshot.

The private signing key remains on the build computer, non-exportable in CurrentUser/My.
Only the public .cer is copied. Retain the test certificate/key for subsequent update tests;
this script creates a new certificate on every run, so do not rerun it to sign updates.
No timestamp was requested; replace/re-sign test packages before the test certificate expires.
Host signature verification may report untrusted root. Trust is intentionally added only in the VM.
Use docs/msix-prototype.md for collection/authentication/update/uninstall acceptance tests.
"@ | Set-Content (Join-Path $output 'VM-INSTRUCTIONS.txt')
Write-Output "Test kit: $output"
Write-Output "Public certificate thumbprint: $($cert.Thumbprint)"
Write-Output "Host verification exit: $verificationExit (untrusted test root expected without host trust)"
# A failed public-trust check is not represented as production signing success.
$global:LASTEXITCODE = 0
