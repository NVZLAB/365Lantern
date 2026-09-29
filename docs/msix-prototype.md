# Per-user packaging and signing prototype

MSIX is the candidate installed distribution; the portable ZIP remains available.
Both use exactly the same published executable, libraries, runtime, modules and
scripts. Build-Msix.ps1 verifies the portable file inventory before copying and
after packing. It adds only the package manifest and shell icons, and records the
source inventory hash in package-provenance.json. No second compilation occurs.

## What this prototype does

- Defines NVZLAB.365Lantern.Preview as a separate preview package identity.
- Registers one application/Start-menu entry. No service, startup entry, scheduled
  task, machine-wide PATH change, driver or elevation capability is declared.
- Runs as a full-trust desktop application with the current user's authority.
  runFullTrust enables our WPF/PowerShell process model; it is not administrator
  elevation and does not make Lantern an AppContainer sandbox.
- Uses bundled dependencies and normal user Microsoft authentication. The package
  directory will be Windows-managed and read-only; module behavior must be tested.
- Leaves update checks manual. No automatic App Installer update feed is configured
  until signing identity, hosting and compatibility are validated.

Packaging is implemented and can be validated without installing it. Actual per-user
installation, updates, rollback, sign-in and removal must still pass the VM gates
below before MSIX is selected for public release. Managed-device policies can block
installation even for a correctly signed package.

## Build the candidate

Build the portable payload first, then use signed Microsoft MakeAppx from Windows
SDK build tools (locally validated with Microsoft.Windows.SDK.BuildTools
10.0.28000.2705 from NuGet). No machine-wide SDK installation is necessary.

```powershell
./scripts/Build-Msix.ps1 `
  -PortableDirectory 'artifacts/portable-<id>/365Lantern' `
  -MakeAppxPath '<SDK>/x64/makeappx.exe' `
  -Publisher 'CN=365Lantern Prototype'
```

The default Publisher is a **placeholder for the unsigned prototype**, not a
verified publisher claim. Before signing, rebuild with the exact certificate
subject, including its full distinguished name. The builder verifies the tool's
Authenticode signature, invokes MakeAppx validation, hashes the result, and never
installs it. The manual packaging workflow produces the ZIP and unsigned MSIX
from one payload; neither is published as a GitHub Release automatically.

## Version mapping

MSIX needs four numeric fields. The first three match the app version; the fourth
is alpha: 1000+N, beta: 2000+N, rc: 3000+N, stable: 4000 (N is 1..999).
Thus 0.1.0-alpha.1 becomes 0.1.0.1001, and 0.1.0 becomes 0.1.0.4000.
Increment the app version for every distributed candidate; do not rebuild and
replace an already distributed package version. This mapping is for direct
distribution, not Microsoft Store submissions. Package name and Publisher define
update continuity; settle the production identity before the first public install.

## Sign without exporting keys

Sign-Msix.ps1 selects a certificate by exact thumbprint from CurrentUser/My. It
requires a current code-signing certificate with an accessible private key, checks
the manifest Publisher, signs a new copy with SHA-256 plus an HTTPS RFC3161 timestamp,
then invokes SignTool verification. It does not accept a PFX password on the command
line, export a key, create certificates, import trust, or pick a certificate silently.

```powershell
./scripts/Sign-Msix.ps1 `
  -PackagePath 'artifacts/msix-<id>/365Lantern-0.1.0-alpha.1-win-x64-unsigned.msix' `
  -SignToolPath '<SDK>/x64/signtool.exe' `
  -CertificateThumbprint '<your code-signing certificate thumbprint>' `
  -TimestampUrl 'https://<your signing providers RFC3161 endpoint>'
```

Production signing and trust verification remain untested. Unsigned MSIX is not a normal end-user installable
release. Public distribution requires a trusted publisher identity. Lab certificates
belong only in an explicitly prepared disposable VM; do not ask users to weaken
security settings or trust an unknown root. Cloud signing can be integrated later
without storing its credentials in the repository.

A successful signing run writes a checksum and signing report. A failed run may
leave an output file: never distribute it without successful verification. Signing
the MSIX protects package contents; it does not Authenticode-sign the separate
portable EXE. The portable payload's dependencies.json correctly continues to call
that EXE unsigned. Separate portable EXE signing is a future release task.

## Clean VM acceptance matrix

For disposable-VM testing, `scripts/New-VmTestPackage.ps1` takes PackagePath and
SignToolPath. It explicitly creates a 90-day non-exportable code-signing key in
CurrentUser/My, signs a copy, and exports only a public CER. It does not change host
trust. Its output folder contains exact VM instructions, the signed MSIX, CER,
certificate thumbprint/hashes, and the host verification log. Add that certificate
to LocalMachine/TrustedPeople only inside the VM, then install as the normal test
user. No production trust claim is made. Do not recreate the certificate between
update tests; retain the original test signing identity. No timestamp is used for
these disposable test packages.

Use a supported Windows x64 VM with a standard user and no development runtimes.
Keep all real tenant evidence outside the test VM until basic tests pass.

1. Verify the package signature/trust and install for the current user using Windows
   App Installer. Confirm no elevation is requested under the intended policy.
2. Launch from Start. Confirm version/icon and offline import/export. Export to a
   user-selected folder outside package storage and verify manifest hashes.
3. Connect to the test tenant in both authentication modes. Confirm browser callback,
   Graph/Exchange sign-in, owned helper processes, module imports and temporary writes
   work from Windows-managed read-only package storage.
4. Exercise collection, optional consent denial, network failure, cancellation and
   session clearing. Confirm helpers exit; inspect actual filesystem/registry writes
   and document Microsoft/OS artifacts rather than claiming zero footprint.
5. Build a higher candidate version with unchanged identity and publisher. Export
   any active case, close Lantern and apply the signed update. Confirm Start launches
   the new version and no duplicate install appears. Do not force active-case shutdown.
6. Test rollback in the disposable VM using a retained trusted prior package and an
   explicit operator procedure; ordinary MSIX updates do not promise automatic
   downgrade support. Prefer a higher-version corrective release for users.
7. Uninstall through Windows Settings. Verify package removal, no orphan helpers or
   scheduled tasks/services, and separately exported evidence still exists. Browser
   sign-in state and tenant consent can remain; uninstallation does not revoke them.

If authentication/module behavior cannot be made reliable within this package model,
retain the identical app payload and evaluate a conventional signed per-user installer.
Do not introduce a privileged service just to make packaging work.

References:
- https://learn.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool
- https://learn.microsoft.com/en-us/windows/msix/package/sign-app-package-using-signtool
- https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes
