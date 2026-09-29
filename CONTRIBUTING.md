# Contributing

365Lantern is MIT-licensed and welcomes fixes, documentation and synthetic test cases.
Read [SECURITY.md](SECURITY.md) before reporting a suspected vulnerability.

- Use synthetic accounts such as alex@example.com and documentation IP addresses.
  Do not attach real tenant evidence, credentials, certificates, exports or screenshots.
- Keep _EXCLUDE, work, artifacts, evidence and signing material out of Git. Review
  staged files before committing. An ignore rule does not protect files already tracked.
- Keep collection separate from detection and presentation. Preserve original evidence
  references, mark missing coverage, and explain alternatives to suspicious indicators.
- Do not add tenant write operations, persistent authentication caches, telemetry,
  automatic updates or new network services without an explicit design discussion.
- Document new API permissions, licenses/roles, failure behavior and data handling.
- Include meaningful synthetic checks for logic changes. Run
  `./Start-365Lantern.ps1 -Check`; build the Windows desktop app and use its documented
  smoke test for UI changes. Do not make automated tests contact a real tenant.
- Update CHANGELOG.md under Unreleased. Do not create release tags or publish assets
  as part of an ordinary pull request.

Describe the problem, final behavior and validation in each pull request. Contributions
must be code/assets you can provide under the project's license; preserve third-party
notices. The production signing identity and public release process remain under review.
