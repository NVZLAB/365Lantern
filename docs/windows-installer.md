# Windows installer

The unsigned alpha installer installs for the current user under
`%LOCALAPPDATA%\Programs\365Lantern`, adds Start menu shortcuts and provides an
uninstaller. It bundles the same application, PowerShell and Microsoft modules as
the portable edition. No administrator elevation, background updater or service
is required. Windows may warn about the unsigned publisher.

If Microsoft sign-in does not appear, select Cancel on the Connect screen, enable
"Use a browser sign-in code", and retry. When a code appears in Lantern, open
the Microsoft sign-in link and enter that code using the intended administrator
account. You do not need to close existing browser windows. Never share a code.
Graph and Exchange require different service tokens, so a separate Exchange
authorization may still appear when collection starts. The validated Exchange
connection is reused; failed authentication is not repeated by subsequent checks.
Reconnect explicitly to retry. Response consent remains separate.

Some tenants prohibit device-code authentication through Conditional Access.
Use the normal sign-in option or an approved custom app registration in those
tenants; Lantern does not bypass tenant policy. Codes are not saved or exported.

Build a validated portable payload with `scripts/Build-Portable.ps1`, then run:

```powershell
./scripts/Build-Installer.ps1 -Payload '<portable build directory>/365Lantern'
```

Inno Setup 6 is required on the build machine only. Outputs are in
`artifacts/installer`, with a SHA-256 checksum alongside the installer.

Downloaded ZIPs can give the bundled PowerShell scripts an Internet-zone marker.
The helper now uses a process-scoped execution-policy override; it does not
modify machine/user policy or override enforced organizational Group Policy.
Regression check (no authentication or tenant requests):

```powershell
./tests/DownloadedHelper.Checks.ps1 -PowerShellRuntime '<payload>/runtime/powershell/pwsh.exe'
```

Before release, test the exact installer as a standard user on a clean Windows 11
VM: install, launch, Microsoft sign-in, read-only collection, synthetic import,
report/evidence export and uninstall. A local candidate built with uncommitted
changes is for testing, not a published release artifact.
