# Portable Windows preview

The distribution is a ZIP containing 365Lantern.exe, .NET runtime files, fixed
PowerShell scripts, runtime/powershell, and runtime/modules. Extract it to a new
folder and launch the EXE without administrator elevation. Keep the folder intact.
No installer, machine-wide PATH changes or prerequisite installation is used.
This is a portable folder, not a lone executable. Windows x64 is the initial target.

## Building

From a clean committed checkout, PowerShell 7 with .NET 10 SDK and Save-Module available:

```powershell
./scripts/Build-Portable.ps1
# Or pass -Dotnet with an absolute path to a workspace SDK's dotnet.exe.
```

The script creates a fresh artifacts/portable-GUID directory (it does not delete or
overwrite existing releases), downloads the pinned official PowerShell ZIP, verifies
GitHub's asset SHA-256 digest, saves exact module versions from PSGallery, and publishes
self-contained without trimming or single-file extraction. It preserves dependencies'
licenses/notices. dependencies.json records versions and the PowerShell source hash;
package-files.json records bundled file hashes. sbom.cdx.json inventories declared
NuGet dependencies and all shipped DLL/EXE hashes, and third-party contains supplemental
licenses and exact resolved runtime-package notices. build-provenance.json records the
source commit. A SHA-256 sidecar covers the final ZIP.
These checksums are integrity checks, not signatures or proof of clean source.

Only clean build inputs are packaged: published binaries/scripts, downloaded dependencies,
LICENSE, CHANGELOG, documentation, synthetic sample and portable launch instructions. Tenant evidence and _EXCLUDE are never
copied from the workspace. Verify redistribution notices and dependency licensing before
public release. The app is currently unsigned; organization policies or Windows may block it.

The manual **Portable Windows preview** GitHub Actions workflow runs checks and uploads
a downloadable build artifact. It does not create tags or publish GitHub Releases.
Maintainers review/test the ZIP and attach it and the checksum to a prerelease separately.

## Updates

Checks are explicit sidebar actions. GitHub's public release listing is read without
authentication, with bounded pages/response sizes and timeouts. Drafts and malformed tags
are ignored. Preview builds include prereleases; stable builds exclude them. Semantic
version ordering is used instead of release timestamps. Only the fixed project release
page can be opened, not arbitrary URLs supplied by API data. Nothing is installed or
replaced automatically. No public release is different from a failed/rate-limited check.

Export the current case, close the app, and extract a newer ZIP into a new folder to update.
No application settings or credentials need migration. Retain exported evidence separately.

## Validation and release gate

The builder checks imports using bundled PowerShell/modules, then launches the actual
published EXE for the synthetic UI smoke test. Automated release checks cover prerelease
ordering, stable filtering, invalid tags, empty feeds and HTTP failures. These are local
checks, not proof that every Windows installation is supported.

Before publishing, test the ZIP in a fresh supported Windows x64 VM without .NET SDK,
PowerShell 7 or the Microsoft modules installed. Use a standard user; launch from a path
with spaces, run offline JSON analysis, verify exports, then validate Microsoft sign-in
and live collection with a test tenant. Exercise denied consent, no internet, cancel,
clear session and read-only folders. Confirm helper processes terminate. Record OS/module
versions and all collection gaps. Clean-machine and live bundled-auth validation remain
release gates until performed; the development workstation is not a clean machine.

References:
- https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows
- https://docs.github.com/en/rest/releases/releases#list-releases
