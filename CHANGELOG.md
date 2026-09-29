# Changelog

User-facing changes are recorded here. Versions follow MAJOR.MINOR.PATCH with
alpha, beta or rc prerelease suffixes. No public tagged release has been published yet.

## Unreleased

Target: **0.1.0-alpha.1** — first public investigation preview.

### Added

- MSIX per-user packaging prototype using the exact portable payload, preview identity,
  shell assets, package-version mapping and file-integrity verification.
- Explicit certificate-store signing script with publisher checks and timestamp/signature
  verification; no certificate creation or machine trust changes.

- Portable Windows x64 ZIP builder with bundled .NET, PowerShell and pinned Microsoft modules,
  file inventory/checksums and manual GitHub Actions artifact packaging.
- User-initiated GitHub release checks with semantic version ordering and preview/stable channels.

- Windows desktop investigation workflow with system, light and dark appearance.
- Default Microsoft-module authentication and optional custom app registration.
- Single-account and tenant-wide investigation with per-source coverage and graceful failures.
- Interactive and noninteractive user sign-ins, account/MFA/device inventory,
  directory audits, Exchange inbox rules, forwarding, mail flow and available unified audits.
- Account activity timeline and suspicious-behavior review with supporting evidence references.
- Persistence review for mailbox delegation, delegated OAuth grants and successful MFA changes.
- Related-account investigation using observed IP, application and message IDs, preserving case evidence.
- Offline Entra sign-in JSON import with download guidance.
- Explicit evidence ZIP export with JSON/CSV findings, suspicious behavior and timeline,
  raw evidence, readable summary and integrity hashes.
- Expanded IP, country and state/region breakdowns with event/outcome counts.
- Animated collection lantern respecting Windows animation settings.
- Shared build version displayed in the app and recorded in evidence exports.

### Fixed

- Launcher detects an existing application instance before rebuilding a locked executable.
- Authentication success and licensing/permission failures have clearer status messages.
- Missing evidence is reported as incomplete coverage rather than a clean investigation.

### Known limitations

- Preview software: live validation of newer collectors is still required.
- Noninteractive user sign-ins use Microsoft Graph beta.
- Service-principal/managed-identity sign-ins, application-only grant inventory,
  and Defender click collection are not implemented.
- Response actions and a full incident-report workflow are not implemented.
- Read availability depends on Microsoft licensing, retention, consent and operator permissions.
- Exports contain sensitive evidence; there is no automatic redaction or encryption.

Earlier development commits are incorporated into this first preview rather than
presented as releases that were never published.
