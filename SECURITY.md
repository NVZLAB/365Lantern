# Security policy

365Lantern is an alpha investigation tool, not a guarantee that an account is safe.
Only the current development line is maintained; there is no supported stable release
or guaranteed response time yet. Findings require analyst review and unavailable sources
must remain explicit collection gaps.

## Reporting a vulnerability

Do not post credentials, tokens, tenant exports, real mailbox content, exploitable
details or private screenshots in public issues or pull requests.

When enabled, use GitHub's **Security → Advisories → Report a vulnerability** for
[this repository](https://github.com/NVZLAB/365Lantern/security/advisories).
If that option is unavailable, open an issue asking only for a private reporting
channel, without disclosing the vulnerability or sensitive data. No alternate private
email address is currently designated. Maintainers must enable and verify private
vulnerability reporting when the repository becomes public.

Include the version/build, affected feature, expected versus observed behavior,
impact, and minimal synthetic reproduction. Test only against systems you are
authorized to assess. Never send a real credential as proof.

## Intended boundaries

- Investigation operations are read-only. Session revocation, password reset and selected
  authentication-method / unmanaged Entra device-registration removal require separate response
  authorization and explicit per-account confirmation. Delegated Microsoft permissions may
  authorize more than Lantern uses; they are not a sandbox against malicious code.
- No app-managed persistent credentials, automatic evidence upload, telemetry or
  unattended response actions. See [privacy boundaries](docs/privacy.md).
- Exports are sensitive and are not automatically encrypted or redacted.
- Self-signed packages/certificates are for disposable test environments only.
- Update checks do not install code. Checksums establish byte integrity, not publisher trust.

Report suspected exposure promptly through a private channel. A leaked credential
must be revoked/rotated; deleting it from a file or rewriting Git history does not
make it safe again.
