# Test tenant setup

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
