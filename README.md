# 365Lantern

Open-source Microsoft 365 compromise investigation and incident response, built for the people defending mail systems.

**Status: first development slice, not a production incident-response tool.** Native Windows desktop app in C# / WPF on .NET 10. Original reference scripts in `_EXCLUDE/` are ignored by Git and are not executed or imported.

## Run

On Windows with the .NET 10 SDK:

```powershell
.\Start-365Lantern.ps1
```

Click **Run synthetic demo**. No tenant or network is needed for the demo after dependencies are restored. Choose System, Light or Dark in the sidebar. System is the default and reacts to Windows appearance changes. Theme selection is session-only.

For checks: `./Start-365Lantern.ps1 -Check`. The launcher also supports a workspace-local SDK at `work/toolchain/dotnet/`; build caches and outputs are ignored.

## Implemented

- Desktop navigation and System / Light / Dark palettes, with high-contrast resource handling.
- Clearly labeled synthetic single-account investigation: risky sign-in, forwarding rule, raw evidence and collection coverage.
- Interactive Microsoft sign-in using MSAL's default memory cache; fixed tenant authority; no client secret or persistent cache integration. Successful sign-in opens Overview with the operator account prefilled for review.
- Live Microsoft Graph **interactive sign-in** collection for an exact UPN and bounded time range, pagination, deduplication, cancellation and limited throttling retries.
- Initial findings based only on medium/high Entra risk values. No geographic anomaly scoring or claim that missing risk data means safe.
- Specific guidance for Microsoft's known licensing-denial code; unknown errors remain generic. Failed collections with no evidence display an incomplete-investigation headline.
- Explicit ZIP export containing raw `evidence.json`, readable `summary.txt` and a SHA-256 `manifest.json`.
- Disconnect clears app references, visible results and the MSAL account cache. No response actions exist.

## Still required for milestone 1

- Validate live sign-in/consent/collection against the test tenant, including denied permissions and licensing limitations.
- Implement and validate fresh read-only Exchange collectors for inbox rules and mailbox forwarding. The live UI currently marks these **Not collected**; demo coverage is synthetic only.
- Seed a harmless forwarding-rule scenario in the test tenant with the operator, verify detection and compare the evidence to Microsoft admin portals.
- Add a fuller incident report and export redaction preview. Current export confirmation identifies the scope but does not redact records; the raw Evidence view permits inspection beforehand.
- Expand UI/accessibility and system-theme-change checks on Windows. Screenshots and synthetic UI smoke checks are not a full accessibility review.

Remediation, tenant-wide correlation and PDF reporting are later work. This build never modifies tenant resources. See [test-tenant setup](docs/test-tenant.md), [privacy boundaries](docs/privacy.md) and [development notes](docs/development.md).

## Project layout

- `src/Lantern.Core`: investigation records, demo fixtures, Graph collection, findings and in-memory archive creation.
- `src/Lantern.Desktop`: Windows UI, themes, memory-only authentication and explicit export dialog.
- `tests/Lantern.Checks`: dependency-light executable checks using fake HTTP responses, no tenant access.
- `design/mockups`: initial interface concepts.

MIT licensed. No telemetry, advertising or paid service dependency is built into 365Lantern. Microsoft services have their own licensing and access requirements.
