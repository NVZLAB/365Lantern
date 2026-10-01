# Public alpha testing

365Lantern is an experimental investigation and controlled-response tool. Findings
need analyst judgment; no findings does not establish safety. Start with a disposable
tenant/account or the synthetic JSON under tests/fixtures/signins.

## First run

1. Download the Windows x64 portable ZIP and checksum from the matching GitHub
   prerelease. Extract the complete ZIP to a new folder. Run 365Lantern.exe.
2. The alpha is unsigned. Follow your organization's software approval process;
   do not install the project's laboratory signing certificate or disable security
   controls. No installer, local administrator elevation or separately installed
   .NET/PowerShell is required by the portable package.
3. Start with Offline Investigation and synthetic data, then collect a disposable
   account in an authorized test tenant. Verify coverage gaps against available
   licensing/permissions. Read docs/test-tenant.md for the access requirements.
4. Review Findings, edit the executive report and export the evidence ZIP. Keep real
   exports private. Cases and response records are discarded when the session closes.
5. Response actions are experimental and request separate write consent. Use only
   disposable accounts/devices for alpha validation. Review the exact target and
   effect before approving. An Unknown outcome may have taken effect: verify in
   Microsoft before retrying. See docs/controlled-response.md.

## Clean-machine release check

Record the package version and ZIP SHA-256 locally, then test on Windows 11 x64
without the SDK, PowerShell 7 or Graph/Exchange modules installed separately:

- Launch as a standard local user; switch System/Light/Dark themes.
- Import the synthetic sign-in fixture; inspect its repeated-failure finding.
- Sign in, collect a test account, and verify available data and explicit gaps.
- Export/open the HTML report and JSON/CSV ZIP; check that secrets are absent.
- If testing Response, validate each action independently with disposable targets
  and preserve its exported outcome. Device removal has intentionally limited scope.
- Check for updates with preview releases enabled by the alpha build.
- Close, reopen and confirm the case/authentication state was not saved by Lantern.
- Extract a newer package beside the old one for manual updates. To remove the app,
  close it and delete its extracted folder; separately saved exports, browser/broker
  sessions and tenant consent are not removed automatically.

The development-machine smoke test is not a substitute for this clean-machine check.

## Feedback

Use the GitHub bug template for version, workflow and synthetic reproduction details.
Never post real tenant exports, passwords, tokens, mailbox content or private screenshots.
Report vulnerabilities privately through Security → Advisories → Report a vulnerability.

Expected limitations include licensing/retention gaps, API propagation delays,
Microsoft Graph beta noninteractive sign-ins, and heuristic false positives/negatives.
Message traces do not establish whether a person clicked or opened a message.
The report is an analyst assessment, not an independent attestation of compromise.
