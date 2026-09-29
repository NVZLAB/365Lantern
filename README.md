# 365Lantern

Free, open-source Microsoft 365 compromise investigation for the people defending mail systems.

**Status: unreleased alpha preview.** Native Windows desktop app in C# / WPF on .NET 10. Response actions and the full incident-report workflow are not yet implemented.

## Run

Portable preview packages are built as Windows x64 ZIPs. Extract the entire package
and run `365Lantern.exe`; keep the runtime folder and DLLs beside it. No installer
or separate .NET/PowerShell installation is needed. Public release assets have not
yet been published. See [portable packaging](docs/portable.md).

**Check for updates** in the sidebar contacts GitHub only when clicked. It opens
the release page on request; downloads, extraction and replacement are manual.

### Run from source

On Windows with the .NET 10 SDK:

```powershell
.\Start-365Lantern.ps1
```

Start with **Connect tenant**, then **Investigate**. Review collected evidence in **Findings**. Default authentication uses Microsoft PowerShell modules; a custom app registration is optional. See [tenant setup](docs/test-tenant.md) for prerequisites and permissions. **Offline Investigation** accepts local Entra sign-in JSON without signing in.

Choose System, Light or Dark in the sidebar. The launcher supports a workspace-local SDK at `work/toolchain/dotnet/`; build caches and outputs are ignored. Run automated synthetic checks with `./Start-365Lantern.ps1 -Check`.

## Investigation capabilities

- Single-account and tenant-wide collection with explicit coverage gaps when access is unavailable.
- Interactive and noninteractive user sign-ins, IP/geographic breakdowns, MFA registration and registered-device inventory.
- Exchange rules, forwarding, delegation, mail flow, available Microsoft 365 audits and directory audits.
- Account activity timeline, suspicious-behavior review and related-account evidence searches.
- Optional delegated OAuth grant inventory with additional read consent.
- Explicit ZIP exports containing JSON/CSV findings, timeline and suspicious behavior, raw evidence, summary and integrity hashes.
- Collection stays in application memory until an explicit export; see [privacy boundaries](docs/privacy.md) for browser, module and OS limitations.

Indicators require analyst review. No findings does not establish safety. Noninteractive collection uses Microsoft Graph beta; availability depends on Microsoft's licensing, permissions and retention. Message traces do not prove that a person opened or clicked a message.

## Versions and releases

The shared version is defined in [Directory.Build.props](Directory.Build.props) and shown in the app and evidence exports. The first public preview target is **0.1.0-alpha.1**; no tagged release has been published yet.

See the [changelog](CHANGELOG.md) for user-facing changes and the [release guide](docs/releasing.md) for version numbering, validation and GitHub prereleases.

An [MSIX per-user installation prototype](docs/msix-prototype.md) wraps the same portable
build. Signing and clean-machine installation/authentication tests remain release gates;
the unsigned prototype is not an end-user release.

## Project layout

Please read [contribution guidance](CONTRIBUTING.md) and the [security policy](SECURITY.md)
before opening issues or submitting examples. Never post real tenant evidence or credentials.

- `src/Lantern.Core`: collection, analysis, evidence models and exports.
- `src/Lantern.Desktop`: Windows UI, authentication and fixed read-only PowerShell helpers.
- `tests/Lantern.Checks`: synthetic checks; no tenant access.
- `docs`: setup, privacy, collection limitations and release guidance.
- `design/mockups`: initial interface concepts.

Local reference scripts in `_EXCLUDE/` are ignored by Git and are not executed or imported. MIT licensed. No telemetry, advertising or paid service dependency is built into 365Lantern. Microsoft services have their own licensing and access requirements.
