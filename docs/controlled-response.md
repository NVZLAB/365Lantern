# Controlled response (preview)

Response supports **Revoke sign-in sessions**, **Reset password**, and **Remove a
registered MFA / passwordless method**, and **Remove an Entra device registration**, for one member account from a live investigation.
Account blocking and mailbox changes remain future milestones. Synthetic and imported investigations
cannot authorize changes. The responding administrator cannot target themselves.

## Test-account walkthrough

1. Close an older app instance and launch the current source build with
   `Start-365Lantern.ps1`. Previously built installers do not contain this milestone.
2. Connect as your test tenant administrator. Investigate the disposable member
   test account. The account inventory must return its directory object ID.
3. Open **Response**, select the test account and action, enter the reason/authorization
   reference, and optionally link an indicator. No finding is required to respond.
4. Select **Prepare selected action**. A separate Microsoft Graph PowerShell
   process requests delegated `User.Read.All` and the selected action's write scope with
   `ContextScope Process`. Sign in as the same administrator in the same tenant.
   Microsoft may require consent. Existing custom-app investigation authentication
   also uses this separate Microsoft-module response session; no write permissions
   are added to the custom app by Lantern.
5. Check the final preview's tenant, account, display name, object ID and operator.
   For password reset, Lantern generates a random 24-character password; regenerate or edit it if needed. After execution, retrieve it from the private handoff window.
   For method removal, select the exact supported registration. Check the approval
   checkbox and click the named action, or **Cancel** without sending a write.
   Preparation can be canceled. Execution cannot be canceled or rolled back locally.
6. Inspect the result, then export the evidence ZIP. The HTML report summarizes
   recorded actions. `response.json/csv` contains the detailed records, alongside
   the original evidence and integrity manifest.

Use only a disposable account initially. Signing that account into a Microsoft app
in a separate browser profile before the test helps observe eventual reauthentication.
A browser remaining open is not proof that revocation failed. Existing access tokens
and application-owned sessions may outlive the request; this is not complete containment.

## Outcomes and evidence

The journal records a unique action ID, action, tenant, target object ID/UPN,
responding administrator and object ID, reason, optional indicator key, request and
completion UTC times, result, verification, and the observed session-validity timestamps.
No password, token or raw server error is retained in the case or exports. A record is created in memory
before dispatch. Preparation failures are **Not performed**; operator cancellation
at the final confirmation sends no write and does not create an execution record.

- **Accepted**: Microsoft reported true for revocation or HTTP 204 for password
  reset/method/device deletion. One follow-up read checks the session-validity or
  password-change timestamp, or absence of the selected method/device. Observed metadata
  is not independent attribution, credential testing, or proof of containment.
- **Accepted; effect not verified**: timestamp unchanged, unavailable, or unreadable.
  Propagation can take minutes. This does not turn an accepted request into failure.
- **Denied**: a known rejection response (including 401/403/429). Verify consent,
  operator role or throttling. No broader permissions are requested automatically.
- **Not performed**: preparation or pre-execution validation failed. No write sent.
- **Unknown**: transport loss, timeout, ambiguous server response or unexpected
  reply after dispatch. The write might have occurred. Check Microsoft before retrying.

Microsoft enforces effective role/permission restrictions when the request is made;
successful preparation is not a guarantee of authorization to execute. The helper
has no generic write endpoint: it binds one allowed action to the prepared GUID,
checks tenant/operator and target identity again, expires previews after five minutes,
and consumes the execution slot before attempting it. Automatic Graph retries are
disabled. Closing the separate response process releases its process-scoped session;
the investigation helper remains unchanged and only exposes read operations.

## Persistence and limitations

Journal data stays in memory until explicit export, just like case evidence. The UI
warns before discarding response records not yet exported to ZIP. Process termination,
power loss or OS failure can still lose the journal. There is no automatic durable
audit log or crash recovery. Microsoft's own audit records should be preserved as
independent evidence. Exported records are not signed or independently attested.

Consent grants, browser/broker sign-in state and Microsoft audit events may remain
outside Lantern. Closing the helper does not revoke tenant consent. No credentials
or case data are intentionally persisted by Lantern outside explicit exports.

References:
- [Session revocation API and limitations](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0)
- [User reads and selected properties](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
- [Microsoft Graph request retry settings](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/set-mgrequestcontext)
- [Password profile updates](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0)
- [Authentication methods API](https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview?view=graph-rest-1.0)
- [Phone deletion restrictions](https://learn.microsoft.com/en-us/graph/api/phoneauthenticationmethod-delete?view=graph-rest-1.0)

Validation: synthetic helper tests cover acceptance, denial, ambiguous results,
verification failure/delay, identity changes, missing approval, self/guest targets and
repeat dispatch. The operator reported successful live session revocation on the
test tenant. Generated-password handoff, method removal and device removal still require live test validation.

## Action boundaries

| Action | Additional delegated permission | Effect |
| --- | --- | --- |
| Revoke sign-ins / refresh tokens | User.RevokeSessions.All | Invalidates refresh tokens and browser session cookies. Does not delete registered MFA methods or promise to end every application-owned session. |
| Reset password | User-PasswordProfile.ReadWrite.All | PATCHes only passwordProfile with the supplied temporary password and forceChangePasswordNextSignIn=true. Synchronized accounts are skipped. Federated accounts may reject the operation; use their authoritative identity provider. |
| Remove Entra device registration | Directory.AccessAsUser.All | Deletes one approved unmanaged Workplace device object; does not wipe or retire a device. |
| Remove registered method | UserAuthenticationMethod.ReadWrite.All | Lists methods for this account, previews exact IDs/types, and deletes one explicitly selected registration. |

There is no separate generic “MFA token” object deleted by the session-revocation API.
Registered authentication methods are a distinct persistence mechanism. Method removal
supports Microsoft Authenticator, phone, software OATH, FIDO2/passkeys, Windows Hello
for Business and Temporary Access Pass registrations exposed by the v1.0 API. Password,
email recovery, hardware OATH and other unsupported methods are not deleted. The list
does not prove every method is exposed. Re-enrollment prompts depend on tenant policy;
method removal does not enforce MFA, revoke sessions, or delete device objects.

Only the method approved in the preview is eligible for deletion. The helper checks
its metadata again before execution. Changed or unknown registrations require a fresh
preview. Each attempt is journaled separately. A phone set as default, dependent phone
registrations, permissions or role restrictions may block deletion; Lantern records
the failure without changing defaults or weakening policies. Review remaining methods
and establish a verified recovery path before removing the user's last usable method.

Temporary passwords are generated using cryptographic randomness (24 characters with
uppercase, lowercase, digits and symbols). Tenant password policy remains authoritative.
The masked value can be regenerated or edited. After Accepted or Unknown outcomes, an
in-memory handoff window offers explicit reveal; Unknown is never represented as success.
Use your approved secure delivery channel. No automatic clipboard use, email delivery or
password inclusion in journal/export models occurs. Manual copying uses the Windows
clipboard, whose persistence/history is outside Lantern's control.

The password passes through stdin to Microsoft, never command arguments, environment
variables or temporary files. Approval controls are cleared on close, the handoff text
is cleared when hidden/closed, and secure copies disposed after handoff. Managed strings,
OS paging/dumps and administrator-controlled logging prevent a guarantee of forensic
memory erasure. Never place a password in free-text reason or report fields.

## Device removal boundary

This preview deletes one **unmanaged Entra-registered (Workplace) device object**, using
its directory object ID, not its deviceId. It does not wipe a computer, retire it from
Intune, remove local registration or remove only one user's relationship. The effect
applies to the tenant device identity for all users. Device name and object ID are
recorded in response exports; the executive report includes its readable name.

This action requests delegated `Directory.AccessAsUser.All` separately, in addition to
`User.Read.All`. Microsoft requires that broad delegated scope and an appropriate role
for device deletion. It is never added to investigation access or requested automatically
as a fallback. Consent can remain in the tenant after the response session closes.

Managed, Entra-joined, hybrid/synchronized, system-labeled and physical-ID-bearing
(including Autopilot) devices are not eligible in this preview. Missing metadata or
incomplete/paged inventories fail closed. Use the authoritative device management tools
for those devices. The confirmation requires the exact object ID and acknowledgment of
recovery-key and shared-device impact. Preserve any needed BitLocker recovery material;
Lantern offers no undo. Recovery options depend on tenant capabilities.

Before execution the helper re-reads the selected account's registeredDevices and checks
the device identity, metadata and eligibility. It sends one DELETE to the approved
/devices/{object-id}, then checks that exact object. Only a follow-up 404 establishes
that it is no longer returned; permission errors or delays leave verification unconfirmed.
A concurrent change after that check remains possible; this API has no transaction
covering the relationship check and deletion. No automatic retry is made.

References:
- [Device deletion permission and API](https://learn.microsoft.com/en-us/graph/api/device-delete?view=graph-rest-1.0)
- [Registered devices API](https://learn.microsoft.com/en-us/graph/api/user-list-registereddevices?view=graph-rest-1.0)
- [Device cleanup considerations](https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices)

For live validation, use a disposable cloud-managed account: test password change and
required next-sign-in reset, register a disposable Authenticator method, remove exactly
that method, and confirm other methods remain. Test each action independently and
export after each attempt. Permission failures must retain the case and an accurate
record; an unknown result must be checked in Microsoft before retrying.
