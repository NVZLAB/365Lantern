# Privacy boundaries

365Lantern intentionally has no database, telemetry client, background synchronization, persistent token-cache serializer, app-managed diagnostic files, or tenant configuration file. Application code retains investigation objects and authentication state in process memory. It does not promise forensic erasure: Windows paging, process dumps, endpoint tools and browser state are outside this boundary.

The only investigation file write is a user-confirmed evidence export. The archive is assembled in memory, then written to the selected file. Export can contain names, account identifiers, IPs and raw Microsoft event properties. There is no automatic redaction or encryption in this first slice. A destination may be network-backed or cloud-synced at the OS level; the operator chooses where evidence belongs. The app itself does not upload exports.

The system browser and MSAL communicate with Microsoft identity services for sign-in. The collector performs GET requests only to `https://graph.microsoft.com/v1.0/auditLogs/signIns`. Pagination URLs are checked against that exact endpoint before attaching authorization. HTTP redirects and cookies are disabled for the Graph client. No third-party enrichment services are called.

Errors displayed in the app use generic descriptions or HTTP status codes, never authentication responses, bearer tokens or raw exception dumps. Complete, Partial, Failed and Not collected are separate states. Cancellation discards in-progress collection. Starting a new collection clears the prior investigation; changing inputs alone does not alter the scope attached to existing results. Disconnect clears visible evidence and releases application session references.

SHA-256 hashes verify the exported bytes against the manifest; they are not a signature, trusted timestamp or complete chain-of-custody system. Build and developer smoke-test files contain code or synthetic fixtures only and are ignored by Git. Runtime/dependency tooling may have its own behavior outside application code.
