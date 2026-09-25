# Account activity timeline and mail flow

Guiding principle: collect the best available evidence; if a source is unavailable, use a clearly identified fallback and continue independent checks. Never translate missing access or a license limitation into a clean result. Describe confirmed failures precisely; do not guess that an ambiguous denial means a licensing problem.

The Findings timeline combines existing sign-in evidence, Graph directory audits, Exchange message traces, Microsoft 365 unified audits, and current mailbox rules/forwarding snapshots. Filter by account or category, then select a row to inspect source evidence. Exact same-account message-ID links are navigation aids, not proof of causation. Snapshot times mean collection time, not historical change time. Export includes timeline.json and timeline.csv alongside findings, raw evidence, coverage, and hashes.

## Read sources

- Directory audits: GET /v1.0/auditLogs/directoryAudits using existing AuditLog.Read.All. Query the selected dates and retain events matching the account as actor or target (UPN or directory ID); tenant mode retains all returned records. Cap 50 pages. Missing identities can limit matching. No additional permission is silently requested.
- Mail flow: Get-MessageTraceV2 in windows no longer than ten days. Resolve current SMTP aliases with Get-Mailbox; fall back to the supplied UPN if unavailable and mark coverage partial. Inbound and outbound searches fail independently. Continuation uses Received plus StartingRecipientAddress. Deduplicate trace ID and recipient within each direction/account. Cap 100 calls or 50,000 records per direction; stop repeated cursors and mark partial. Requests are spaced at least 3.1 seconds in the persistent helper; throttling retries are bounded.
- Unified audit: Search-UnifiedAuditLog using ReturnLargeSet and a unique session ID per query. Search account/aliases as actors; separately use a mailbox-address text search and retain exact mailbox owner, object or Identity/Mailbox parameter matches. These are best-effort scopes, not exhaustive searches for every possible representation of an account. Preserve AuditData as structured evidence. Deduplicate source IDs across the two queries. Cap 50 pages of 1,000 rows; repeated pages become a partial result. Audit events may include mailbox activity and SharePoint/OneDrive actions where available.
- A tenant scan stops starting new account checks after the accumulated record count reaches 100,000. The last account can exceed this threshold. Narrow the scope when a safety limit is reported.

Default and advanced authentication use fixed read commands. A failed read does not authorize broader access. Read permissions and command availability depend on Exchange/Purview RBAC, module version and Microsoft licensing. ExchangeOnlineManagement must expose Get-MessageTraceV2; install a current supported module if it does not. No response actions are performed.

## Interpretation boundaries

Message traces show transport activity, not whether an email was opened, clicked, or malicious. No message bodies or attachments are fetched. Defender click evidence is explicitly Not collected. User sign-ins include independent interactive and noninteractive queries; service-principal and managed-identity coverage is not implied. See [persistence and related accounts](persistence-and-related-accounts.md) for beta API boundaries and expanded collection. Historical aliases, GUID-only audit targets, retention expiry, audit configuration, ingestion lag, page limits and Microsoft's sampling/completeness behavior can all leave gaps. A successfully completed query is not proof of complete historical coverage.

Coverage is displayed and exported per source/account, including fallback, denied access, command unavailability, throttling, unknown failures and cancellation. Completed activity pages remain in memory after later failures. Cancellation preserves completed sources and completed sign-in pages when available. Exports are explicit operator-selected writes and contain sensitive email metadata, including subjects and addresses. URLs are displayed as text, never activated automatically.

## Validation

Synthetic checks cover independent failures, alias fallback, ten-day partitioning, partial page retention, audit deduplication, actor/target matching, pagination boundaries, timeline ordering, snapshot labeling, exports, and owned-helper command dispatch. Live tenant validation remains required for actual module availability, RBAC, licensing, service pagination, and returned schemas.

Microsoft references:
- https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2
- https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog
- https://learn.microsoft.com/en-us/graph/api/directoryaudit-list
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table
