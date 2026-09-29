# Test tenant setup

Use a tenant you are authorized to investigate. Do not put passwords, tokens, tenant
exports or real screenshots in GitHub issues. The app starts disconnected.

## Default connection

1. Open **Connect tenant** and enter the directory tenant ID.
2. Optionally select **Include application-grant inventory** to request Directory.Read.All
   for delegated OAuth grant snapshots. The default Graph scopes are AuditLog.Read.All,
   User.Read.All and Device.Read.All.
3. Select **Sign in with Microsoft**. Graph and Exchange can prompt separately; use the
   same authorized operator and tenant. Default authentication uses Microsoft's modules
   and does not create a Lantern app registration. Consent/enterprise-app entries and
   Microsoft audit records can still remain in the tenant.
4. Open **Investigate**, enter an exact UPN or select tenant-wide scope, and choose dates.
5. Review **Findings**, including all coverage gaps. Export before starting a new case
   or clearing the session. Related-account searches extend the current case instead.

Portable/MSIX builds include PowerShell and modules. Source builds need PowerShell 7
in its standard location and Microsoft.Graph.Authentication 2.36.1+ plus
ExchangeOnlineManagement 3.7+ available to the helper. The source launcher also adds
work/modules to the module path. The tested packaging pins are in scripts/Build-Portable.ps1.
Commands introduced in newer modules can still require a newer version than the baseline.

Graph uses process-scoped authentication. Exchange checks tenant/operator identity
before reads. Clear session closes the owned helper and clears app evidence; it does
not revoke server sessions, remove tenant consent or sign the browser out.

## Advanced custom registration

For operators choosing **Advanced: use my own app registration**:

1. Register a single-tenant public desktop client in the test tenant.
2. Add a Mobile and desktop platform with redirect URI http://localhost. Do not create
   a client secret. Authentication uses the system browser.
3. Configure delegated Microsoft Graph AuditLog.Read.All, User.Read.All and Device.Read.All,
   plus Directory.Read.All only when using optional grant inventory; obtain appropriate consent.
4. Configure **Office 365 Exchange Online**, delegated **Exchange.Manage**, for Exchange
   collection. This is not a Microsoft Graph permission or an application-only permission.
   It is a management scope; Lantern restricts its implemented commands to reads, while
   Exchange RBAC determines the operator's actual access. Do not use Exchange.ManageAsApp.
5. Enter the application/client and directory/tenant IDs in Lantern and sign in.

API scopes do not replace operator roles, licensing or retention requirements. We do not
require Global Administrator for every read; select roles suitable for the desired sources.
Do not broaden permissions automatically to work around ambiguous failures.

## Licensing and collection boundaries

Graph sign-in retrieval requires eligible Entra licensing (Microsoft documents P1/P2).
The known Authentication_RequestFromNonPremiumTenantOrB2CTenant 403 receives specific
eligibility guidance; other denials remain generic. A denied read is a coverage gap,
not a clean investigation. Noninteractive user sign-ins use Graph beta independently
of interactive collection. Service-principal and managed-identity sign-ins are not covered.

MFA inventory is a registration report, not proof of MFA enforcement. Registered devices
are directory relationships, not Intune inventory or proof a device signed in. Mailbox
rules, forwarding and delegation are current snapshots; historical changes come only
from available audit evidence. Mail traces are transport metadata, not proof of opening,
clicking or phishing. No message bodies or attachments are retrieved.

Tenant scope can reach 1,000 directory accounts and other per-source page/record limits.
Incomplete enumeration, denied queries, canceled work and reached limits remain visible.
See [activity timeline](activity-timeline.md), [persistence and related accounts](persistence-and-related-accounts.md)
and [suspicious behavior](suspicious-behavior.md) for precise collection and analysis boundaries.

## Local JSON sign-in import

Select **Offline Investigation** for portal download instructions and a local file picker.
No sign-in is required. Download JSON sign-in logs from Entra's Sign-in logs page, not
Diagnostic settings. This importer accepts a UTF-8 event array or an object with a value
array. Events require id, userPrincipalName and createdDateTime. Limits: 32 MiB, 100,000
records, JSON depth 64. Invalid/ambiguous/empty input is rejected without replacing the case.

All accounts and observed dates in the selected file are analyzed; live UI filters do not
apply. Tenant origin, original export filters and completeness are unverified. Duplicate
raw records are retained, but diagnostic/detection totals deduplicate where documented.
The explicit evidence export includes imported records and the original file hash/size,
not the original file itself. Preserve that source file separately when needed.

## Validate in your tenant

Start with one mailbox and one day. Compare known test sign-ins and normal sent/received
messages against Microsoft portals, allowing for ingestion delay. Review each source's
coverage independently. Confirm cancellation, denied access and no-data cases remain
clearly distinct. Export the case and check timeline/evidence references and manifest hashes.
Do not create forwarding rules or change permissions in production just to test detection.

The owner has reported successful live collection and installation in a clean Windows 11
VM. These observations do not establish comprehensive validation of every collector,
authentication mode, role, license or update path. Bundled MSIX sign-in, update, rollback
and uninstall checks still need recorded acceptance results; see [MSIX testing](msix-prototype.md).

References:
- https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities
- https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands
- https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-exchangeonline
- https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-connectioninformation
