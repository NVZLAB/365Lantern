# Test tenant setup

## Current workflow

Start with **Connect tenant** using the default Microsoft-module authentication workflow described below. A custom registration is an advanced option. Select **Include application-grant inventory** if you want delegated OAuth grant checks; this adds optional Directory.Read.All consent. Then use **Investigate**, review **Findings**, and use **Related accounts** to follow evidence leads. Noninteractive user sign-ins are attempted independently through Graph beta. Mailbox delegation, OAuth snapshots and successful MFA changes are now included; unavailable checks remain coverage gaps. See [persistence and related-account collection](persistence-and-related-accounts.md) for limits and testing details.

The original setup and validation notes below describe earlier milestones; they do not define the current collection scope.

The app starts disconnected. Do not send passwords, access tokens, client secrets or tenant evidence into chat or GitHub issues.

1. In the test tenant's Microsoft Entra app registrations, register a **single-tenant** application for this development build.
2. Under Authentication, add **Mobile and desktop applications** with redirect URI `http://localhost`. This is a public desktop client; do not create a client secret. The prototype uses system-browser interactive authorization, not device-code authentication.
3. Add Microsoft Graph **delegated** `AuditLog.Read.All` permission and grant administrator consent in that test tenant. No write permissions are requested.
4. Use an operator with access to tenant sign-in logs (for example Reports Reader). A Global Administrator can perform the setup, but the app does not require that role for normal investigation.
5. In 365Lantern, choose **Connect tenant**, enter the application ID and directory ID, then sign in. These IDs are not secrets and are not saved by the app.
6. Open Overview, enter the test user's exact UPN, choose a time range, and click **Collect live sign-ins**.
7. Review Collection coverage, the Evidence view and any findings. Export only to a destination appropriate for case evidence. Clear the session when finished.

The v1.0 sign-in endpoint used here returns interactive sign-ins and successful federated sign-ins, not every possible authentication event type. Availability and fields depend on retention, licensing and access. Complete means the selected query finished; it does not assert full historical coverage. A 403 is a collection failure, never a clean result. Exchange coverage remains Not collected in this slice.

MSAL caches tokens in this process only. The system browser may keep its own Microsoft cookies. Clearing this app's session does not sign out the browser, revoke server-side sessions or securely erase operating-system memory artifacts.

References:
- [Microsoft Graph sign-in API, access and coverage](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)
- [MSAL interactive desktop authentication](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/acquiring-tokens-interactively)
- [MSAL default memory cache](https://learn.microsoft.com/en-us/entra/msal/dotnet/how-to/token-cache-serialization)

## Validation so far

Interactive sign-in succeeded in the owner's test tenant on 2026-09-11 after a single-tenant desktop registration and administrator consent for delegated AuditLog.Read.All. The default User.Read permission was removed by the operator. Live sign-in collection returned HTTP 403. The portal showed Entra Free; licensing is a likely cause, but the original build did not inspect the service error code, so the exact cause has not been confirmed.

The updated collector recognizes Microsoft's `Authentication_RequestFromNonPremiumTenantOrB2CTenant` code on HTTP 403 and displays fixed licensing/tenant-eligibility guidance. Other 403 responses remain generic. It does not display or export server error messages, unknown codes or innerError fields. The operator's retry on 2026-09-11 displayed this specific guidance, confirming the known licensing/tenant-eligibility denial. Authentication is validated; successful live sign-in evidence collection remains unvalidated.

Microsoft requires Entra ID P1 or P2 for Graph sign-in log retrieval. No license purchase, trial activation or broader permission grant has been performed. See [Microsoft's licensing-error guidance](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities).

### Local JSON sign-in import

Select **Import JSON…** on Overview; no connection is required. Import accepts a UTF-8 JSON array of Entra sign-in events, or an object with a `value` array. Each event needs `id`, `userPrincipalName`, and `createdDateTime`. Limits: 32 MiB, 100,000 records, depth 64. Empty, malformed and ambiguous records are rejected as a whole; the previous investigation is retained.

All accounts and dates in the file are imported. The live account/time controls do not filter imports. Displayed dates are observed event bounds, not the original export filters. Tenant origin and completeness cannot be verified. Duplicate events are preserved. Missing or hidden risk fields do not establish safety; current analysis only flags explicit medium/high Entra risk values.

The app reads the selected file into memory without copying it, uploading it or storing its path. Explicit evidence export includes the imported events and original input SHA-256/byte count; the original file is not embedded. Keep the source file separately if your case requires it. The hash establishes byte identity, not authenticity. Clear session removes the app's investigation references; it does not remove your downloaded or exported files.

### Direct Exchange collection (preview)

Investigate account now attempts Graph sign-ins and then current Exchange configuration, even when the sign-in API returns a licensing failure. Sign in first, enter the exact mailbox UPN, and select Investigate account. Exchange may request an additional browser consent/sign-in. No tenant writes are implemented.

One-time prerequisites:

1. PowerShell 7 in its standard Windows install location.
2. ExchangeOnlineManagement 3.7.0 or later. For this checkout, run `Save-Module ExchangeOnlineManagement -MinimumVersion 3.7.0 -Repository PSGallery -Path ./work/modules` from the repository directory. The launcher adds this ignored module directory to the process module path.
3. The app registration needs **Office 365 Exchange Online → Delegated permissions → Exchange.Manage** (Manage Exchange configuration), with consent appropriate for the tenant. This is a management permission, not a read-only OAuth scope; this app restricts its implemented operations to Get-Mailbox and Get-InboxRule. Exchange RBAC still determines which mailboxes and commands the operator can access. Do not add Exchange.ManageAsApp or a client secret.
4. The target needs an accessible Exchange Online mailbox. Entra sign-in API premium licensing is a separate prerequisite.

The collector requests hidden inbox rules, and selected current mailbox forwarding properties. It does not retrieve historical rule changes or resolve forwarding recipients to classify external domains. Results are current snapshots, irrespective of the sign-in time range. Failure for one source does not mean the other source was empty.

Current validation: synthetic analysis and response parsing are tested; a live authenticated Exchange run remains required. Existing imported data is replaced when starting a live investigation; export it first if needed.

References: [Connect-ExchangeOnline](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-exchangeonline?view=exchange-ps), [Get-InboxRule](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule?view=exchange-ps).

### Sign-in indicators

Analysis runs on the complete imported file or collected batch, grouped by UPN. Duplicate event IDs per account do not inflate analysis; raw imported duplicates are retained. In addition to medium/high Entra risk, checks flag successful legacy-client categories, success after at least five invalid-credential (50126) failures within 15 minutes, and consecutive successful events with different reported countries within one hour. Missing fields skip dependent checks. MFA interruptions are not treated as incorrect passwords. VPNs, normal client behavior and user mistakes can produce findings; these thresholds are transparent review heuristics, not compromise verdicts or learned baselines.

Offline imports now start from **Offline Investigation**, which includes download instructions and a local file picker. Coverage and exported summaries include observed dates, record counts and unavailable Entra risk assessments. Complete describes request completion, not guaranteed historical coverage.

### Default authentication (September 23)

Connect tenant now defaults to Microsoft-module sign-in. Enter the directory tenant GUID and select Sign in with Microsoft. A Lantern client ID, secret or tenant app registration is not required. The requested tenant must match the returned Graph context. During Investigate account, Exchange may prompt separately; use the same account and tenant. Cross-tenant guest/delegated partner sessions are not supported by this preview's strict identity checks.

Prerequisites: PowerShell 7 in its standard Windows location, Microsoft.Graph.Authentication 2.36.1+ and ExchangeOnlineManagement 3.7+. In the repository, install the Graph dependency with:

```powershell
Save-Module Microsoft.Graph.Authentication -MinimumVersion 2.36.1 -Repository PSGallery -Path ./work/modules
```

The launcher already adds work/modules. Tenant consent policy may require admin approval for Microsoft's application; existing Microsoft application grants are not revoked on exit. Sign-in-log licensing and Exchange RBAC still apply. Advanced: use my own app registration retains the previous flow. Do not delete the test registration until the default path is live-validated.

Validation: synthetic module integration covers process scope, Graph collection, Exchange identity matching, wrong-tenant rejection, cancellation and helper shutdown. Live Graph broker sign-in and Exchange sign-in using the default identities still need operator validation. Module import was checked with Graph Authentication 2.40.0 and ExchangeOnlineManagement 3.10.1.

References: https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands and https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-connectioninformation.

### Tenant scope and account context

Connect tenant is now the launch page. The lookup button opens the requested tenant-lookup website in the browser without transmitting app fields. Findings replaces the old Sign-ins, Mailbox rules and Evidence navigation entries. Export Findings supports JSON (with scope and coverage) and CSV (finding rows only, with spreadsheet formula protection). The full evidence ZIP remains available.

Tenant-wide investigation removes the account restriction from the sign-in query and enumerates directory accounts, including accounts with no sign-ins. Current limits are 50 sign-in pages, 1,000 directory accounts, 10,000 MFA report rows, and 1,000 devices per account; limits are reported as Partial. Exchange snapshots are attempted for enumerated accounts; users without accessible mailboxes produce gaps. This is user-account coverage, not service-principal or managed-identity sign-in coverage. Large tenants should expect longer sequential collection.

Graph delegated scopes now include User.Read.All and Device.Read.All in addition to AuditLog.Read.All. Reconnect and consent as required. Custom registrations need those read permissions configured. MFA method types and isMfaRegistered come from the v1.0 userRegistrationDetails report, which has its own licensing, role, freshness and population limitations. Missing entries are unknown, not proof of missing MFA. We do not claim MFA enforcement. Devices are registered-device relationships, not an Intune inventory or proof that a device signed in. Raw device records are included in the explicit evidence export.

Default Exchange connections are reused during the investigation session and disconnected by Clear session/exit; identity is rechecked before each mailbox query. No tenant write commands were added.

Workflow: Investigate contains launch controls only. Completed live or offline investigations open Findings automatically. Findings contains results and a single Export Findings action that creates a ZIP with findings.json, findings.csv, evidence.json, summary.txt and manifest.json. No separate preview or format selection is required; the on-screen export description identifies the included evidence.

## Activity timeline and mail flow validation

Investigate one test mailbox for the last day first. Findings now includes an account timeline, inbound/outbound trace metadata, directory audit events, and best-effort actor/mailbox unified audit searches. Select a row to inspect original evidence, same-account message-ID links and nearby activity. Normal test messages sent/received in the selected period provide useful known events; allow for Microsoft's ingestion delay.

Review every coverage row. An unavailable trace or audit command should leave other sources usable. A zero-record successful query is different from a failed query. If aliases cannot be resolved, the supplied UPN fallback is explicitly partial. Export Findings includes timeline.json and timeline.csv with the existing evidence/coverage archive. No message body, attachment, response action or automatic evidence save is added. Defender clicks and additional live sign-in types remain explicitly uncollected.

See [activity-timeline.md](activity-timeline.md) for source boundaries, read commands, limits and the best-available-evidence principle.

Suspicious Behavior now appears above the full timeline. The ZIP also contains suspicious.csv and suspicious.json. A separate threat-audit query may be unavailable even when ordinary mailbox audit works; check the Audit threat coverage rows. Suspect-mail access requires a Microsoft phishing/malware verdict and exact same-account message-ID correlation. Reading or clicking is not inferred from delivery alone. See [suspicious-behavior.md](suspicious-behavior.md) for rule thresholds and validation boundaries.
