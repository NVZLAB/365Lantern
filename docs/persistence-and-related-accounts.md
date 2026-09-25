# Background sign-ins, persistence and related accounts

An investigation now independently attempts interactive and noninteractive user sign-ins. Background events use Microsoft Graph **beta**, with the explicit nonInteractiveUser filter. Beta is a preview contract that Microsoft can change; failures remain coverage gaps and do not block Exchange reads. Background authentication can reflect token refresh or application activity, not physical user presence. It contributes to diagnostics and risk/legacy-authentication review but is excluded from physical-travel and country-change heuristics. Service-principal and managed-identity sign-ins remain outside this collection.

## Persistence review

Current mailbox Full Access, Send As and Send on Behalf entries are collected independently through fixed Exchange read commands. The Findings persistence table preserves all returned entries. Explicit allowed delegation is flagged for authorization review; self, deny and inherited entries do not independently create suspicious delegation findings. Legitimate delegation is common. Group membership and deny precedence are not resolved into effective access.

The optional **Include application-grant inventory** checkbox requests delegated Directory.Read.All during connection. It is off by default. For an advanced app registration, that permission must also be configured/consented there. The base permissions remain unchanged. A grant read attempted without access produces a gap; it does not silently prompt for broader access. Disconnect/reconnect with the option selected to enable it.

OAuth inventory reads /v1.0/oauth2PermissionGrants: user-specific and tenant-wide delegated grants for a single-account case, or all delegated grants for tenant scope. Sensitive mail/files/directory scopes are review leads, not malicious verdicts. Client/resource identifiers are service-principal object IDs, not application IDs. Application-only app-role assignments are **not** included. Successful authentication-method/security-info changes in existing Entra audit evidence are separately highlighted with the affected account and original evidence reference.

Permission/grant entries are snapshots dated at collection, never historical grant times. Missing permissions, commands, identities, canceled work and page limits are included in coverage. Maximums: 1,000 entries per mailbox permission source; 50 pages per OAuth query and 10,000 grants overall.

## Related-account workflow

From Findings, open **Related accounts**. Select an observed IP address, application ID or message ID. Local matches appear immediately. **Search tenant for this lead** uses the original connected tenant and original date range and appends evidence to the case. IP/app queries search both user sign-in types. Message queries use exact MessageId transport searches in windows of at most ten days, with bounded continuation. No message bodies or attachments are read.

Select an account/address to perform the full investigation for it and merge the results. Exchange attempts to resolve an alias to its mailbox UPN; failure falls back to the supplied address with a coverage warning. Sender/recipient addresses can be external, aliases or unauthenticated sender identities. Shared NAT/VPN addresses and common applications do not establish compromise. Imported and demo cases support local matching only.

Original evidence is retained. Identical observations deduplicate; changed records sharing an ID receive a new observation ID, and new finding references are remapped. Each related query is recorded in Pivots in JSON exports and in summary.txt. The original Account field remains the starting case scope; individual evidence/timeline accounts and query history show its expansion. Related searches cannot change tenants or time windows. New searches stop once the case has at least 200,000 records; the last query/account can exceed that threshold. Export and narrow scope when a limit is reached.

All data stays in the current session until an explicit export. Nothing in this milestone performs response actions. Existing browser/Microsoft-module/OS logging boundaries still apply; see privacy.md.

## Validation

Automated checks cover beta filtering/pagination, background-event interpretation, fixed PowerShell dispatch, independent permission failures, snapshot semantics, grant deduplication, endpoint restrictions, evidence-preserving merges, cross-tenant/time rejection, and related message queries. Synthetic UI smoke tests cover the dialog and read-only demo behavior. Live validation is still needed against Microsoft responses, consent/RBAC, licensing and module versions.

References:

- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-analyze-activity-logs-with-microsoft-graph
- https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailboxpermission
- https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exorecipientpermission
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
