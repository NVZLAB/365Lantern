# Changelog

User-facing changes are recorded here. Versions follow MAJOR.MINOR.PATCH with
alpha, beta or rc prerelease suffixes. No public tagged release has been published yet.

## Unreleased

Target: **0.1.0-alpha.1** — first public investigation preview.

### Added

- Automatically generated temporary passwords with an ephemeral post-reset handoff window;
  masked by default, with no password in reports or evidence exports.
- Explicitly approved removal of one unmanaged Entra-registered device, with separate
  authorization, identity/metadata rechecks, recovery/shared-device acknowledgment,
  outcome verification and device identification in response records.
- Report navigation starts at the top. Security hardening suggestions now focus on
  monitoring, phishing training, geographic access policies, least privilege and prevention;
  identical unedited suggestions cannot be added twice.

- Separate response actions for cloud-managed password reset (forced change at next
  sign-in) and selected registered MFA/passwordless-method removal, with masked password
  entry, action-specific consent, approval and verification. Passwords are excluded from exports.
- Controlled Response preview: single-account session revocation, separate delegated
  authorization, target preview/confirmation, no automatic write retries, and outcome
  verification with explicit uncertainty. Imported/demo cases and self/guest targets are blocked.
- In-memory response records, executive report summaries and response.json/csv in
  evidence exports, with a warning before discarding unexported response records.

- Incident Report tab with in-memory analyst summaries and attributable per-indicator
  assessments bound to supporting observations; prompts protect unsaved assessment edits.
- Printable, self-contained HTML reports and structured report JSON in the evidence ZIP,
  with a client-facing executive summary; detailed assessments, timeline and evidence stay in the technical exports.

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

- Offline JSON import captures the selected path on the UI thread before reading
  the file asynchronously, preventing a WPF cross-thread crash.
- Launcher distinguishes build failures from application crashes instead of
  suggesting an SDK installation for every nonzero exit.

- Added transparent unplated taskbar assets to MSIX packaging to avoid the Windows
  accent-color background; installed-shell validation remains a checkpoint test.
- Thicker lantern outlines and a larger flame in the sidebar, collection animation
  and multi-resolution application icon.

- Launcher detects an existing application instance before rebuilding a locked executable.
- Authentication success and licensing/permission failures have clearer status messages.
- Missing evidence is reported as incomplete coverage rather than a clean investigation.

### Known limitations

- Preview software: live validation of newer collectors is still required.
- Noninteractive user sign-ins use Microsoft Graph beta.
- Service-principal/managed-identity sign-ins, application-only grant inventory,
  and Defender click collection are not implemented.
- Response supports session revocation, cloud-managed password reset and selected
  authentication-method removal. Password/MFA live test validation is pending.
  Reports are analyst working documents, not
  certified conclusions or tamper-proof chain-of-custody records. Report re-import is not implemented.
- Read availability depends on Microsoft licensing, retention, consent and operator permissions.
- Exports contain sensitive evidence; there is no automatic redaction or encryption.

Earlier development commits are incorporated into this first preview rather than
presented as releases that were never published.

### Pending checkpoint additions
- Editable action blueprint with owner, target date, proposed status and verification prompts.
- Readable application identities for OAuth delegated grants, with bounded cached lookups,
  original IDs, preserved grant records and explicit partial resolution coverage.
