# Privacy boundaries

Optional response uses a separate process-scoped session with delegated User.Read.All
and only the requested action's write scope: User.RevokeSessions.All,
User-PasswordProfile.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, or the broad Directory.AccessAsUser.All permission for device removal.
Temporary passwords remain transient in memory/stdin and are excluded from journal
and export models; they are not saved, emailed or automatically copied to the clipboard by Lantern. A transient post-reset window permits explicit reveal and manual copying; Windows clipboard history is outside application control.
Explicit per-account and selected-method/device confirmation
is required. The original investigation helper continues to expose only reads.
Response records stay in memory until explicit export; consent and Microsoft audit
events can persist in the tenant. Closing Lantern does not revoke consent. See
[controlled response](controlled-response.md) for outcome semantics and limitations.

The optional **Check for updates** button sends an unauthenticated HTTPS request to
the public GitHub Releases API for NVZLAB/365Lantern. Only a product/version User-Agent
and standard request headers are sent; no tenant data, tokens or investigation state
are attached. GitHub receives the connection's IP address. No startup/background update
requests occur. Opening the release page uses the operator's browser and its own state.

Portable packages carry .NET, PowerShell and Microsoft modules beside the EXE. The app
prefers those dependencies and limits the helper's module search path to bundled modules.
There is no application installer or runtime dependency download. Microsoft modules,
browser authentication and OS logging retain the external-footprint boundaries below.

365Lantern intentionally has no database, telemetry client, background synchronization, persistent token-cache serializer, app-managed diagnostic files, or tenant configuration file. Application code retains investigation objects and authentication state in process memory. It does not promise forensic erasure: Windows paging, process dumps, endpoint tools and browser state are outside this boundary.

The only investigation file write is a user-confirmed evidence export. The archive is assembled in memory, then written to the selected file. Export can contain names, account identifiers, IPs and raw Microsoft event properties. There is no automatic redaction or encryption in this first slice. A destination may be network-backed or cloud-synced at the OS level; the operator chooses where evidence belongs. The app itself does not upload exports.

The system browser and MSAL communicate with Microsoft identity services for sign-in. Graph collectors issue allowlisted GET requests for sign-ins (v1.0 interactive and beta noninteractive), directory audits, account/MFA/device inventory, and delegated OAuth grants. Pagination stays on the collector's allowed endpoint; sign-in pagination cannot switch API versions. HTTP redirects and cookies are disabled for the custom Graph client. No third-party enrichment services are called.

Errors displayed in the app use generic descriptions or HTTP status codes, never authentication responses, bearer tokens or raw exception dumps. Complete, Partial, Failed and Not collected are separate states. Cancellation preserves completed source evidence when available and marks unperformed checks; partial results are not saved automatically. Starting a new investigation clears the prior case; related-account queries append evidence with recorded scope and retain the original tenant/time window. Changing inputs alone does not alter the scope attached to existing results. Disconnect clears visible evidence and releases application session references.

SHA-256 hashes verify the exported bytes against the manifest; they are not a signature, trusted timestamp or complete chain-of-custody system. Build and developer smoke-test files contain code or synthetic fixtures only and are ignored by Git. Runtime/dependency tooling may have its own behavior outside application code.

Exchange preview uses a separate, noninteractive PowerShell process with profiles disabled and a fixed script. The access token and mailbox input are sent through redirected standard input, never command-line arguments, environment variables or an app-created temporary file. Results return through bounded pipes; server errors are discarded. The app does not enable module error reporting or PowerShell telemetry. Disconnect runs on completion; cancellation terminates the owned helper process. Microsoft’s module manages its own runtime/temporary module artifacts; its behavior and enterprise PowerShell logging must be evaluated during live validation. The application cannot promise absence of OS- or administrator-managed logging. Exchange calls use Microsoft's module transport rather than the Graph GET-only client described above.

### Default Microsoft-module authentication

Default sign-in does not create a Lantern application registration. It uses Microsoft.Graph.Authentication with delegated AuditLog.Read.All, User.Read.All and Device.Read.All and ContextScope Process in an owned PowerShell helper. Directory.Read.All is requested only when the optional application-grant inventory checkbox is selected before connection. Graph tokens remain inside the module; the desktop forwards allowlisted read requests and receives evidence only. The helper uses a hidden console for Windows broker compatibility and does not change persistent Graph/WAM options. Windows broker and browser sign-in state can persist outside the process. Process scope does not promise removal of operating-system authentication state.

Exchange uses its normal interactive connection with WAM disabled for that connection, verifies the tenant and operator against Graph before reading, and reuses the connection until Clear session or exit. Clear session closes helper input so module disconnect runs; after a two-second grace period the app terminates the helper if necessary. Cancellation and protocol failures also close the helper. No tenant consent grants or enterprise application entries are automatically removed. Tenant audit records, module runtime artifacts, OS paging and enterprise logging remain outside our no-app-managed-storage boundary.

The previous MSAL/token-pipe description applies only to Advanced custom-registration mode. Default Graph requests use Microsoft's module transport; the app checks the endpoint both before and inside the helper. Module transport behavior is not the same as the custom HttpClient's redirect/cookie policy. No real tenant evidence is included in the module integration fixtures.

Account inventory adds GET requests to /v1.0/users, /v1.0/reports/authenticationMethods/userRegistrationDetails and GUID-scoped /registeredDevices endpoints. Pagination must remain on the originating path. The tenant lookup link opens a browser; the app does not send tenant identifiers to that site. Findings JSON/CSV are additional explicit user-selected writes. Default Exchange sessions are now reused until Clear session/exit, with identity checks per query.

### Activity timeline and mail flow

The account timeline adds the allowlisted Graph directoryAudits endpoint and fixed read commands Get-MessageTraceV2 and Search-UnifiedAuditLog. Mailbox alias resolution is read-only. Collection retains message metadata (including subjects, sender/recipient addresses, IPs and message IDs) and audit records in memory; it does not retrieve message bodies or attachments. The same explicit ZIP export includes timeline JSON/CSV and coverage limitations. Untrusted links remain text. Collection failures do not authorize privilege escalation: independently available sources continue, fallbacks are labeled, and ambiguous failures are not asserted to be licensing diagnoses. See activity-timeline.md for query scope and limits.

Suspicious Behavior adds a bounded ThreatIntelligence audit search per current mailbox address (up to 20). Microsoft verdict metadata stays in memory with existing audit evidence. Correlations use local evidence only; no external geolocation or reputation lookups are sent. Explicit exports now also include suspicious.json and suspicious.csv, with escaped CSV fields and supporting evidence references. Indicator rules and their limitations are documented in suspicious-behavior.md.

## Analyst reports
Report text and indicator assessments stay in the current investigation's memory until
explicit export. HTML/JSON reports and evidence archives include analyst names, notes
and referenced observations and must be treated as sensitive case data. They are not
encrypted or redacted. The HTML report has no external resources or scripts and encodes
supplied text. Browser printing is an operator action. Session clearing, replacement
with a new investigation and application exit discard the in-memory report. No report
re-import or automatic disk persistence is implemented. See incident-reports.md.

Application-name enrichment uses read-only, GUID-scoped service-principal lookups
with a fixed field selection and the existing optional directory permission. Names,
application IDs and publisher labels are retained beside the original grant record;
no credentials are requested or stored. Lookups are cached per collection, capped at
200 requests and stop on access denial or throttling. Unresolved grants remain visible.
Action blueprints only insert editable report text; they do not execute response actions.
