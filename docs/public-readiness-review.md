# Public-source readiness review — 2026-09-29

## Recommendation

Suitable for public **alpha source** publication after the pending reviewed changes
are committed/pushed. The owner subsequently authorized replacing personal commit
email metadata with the GitHub noreply address; that rewrite is complete.
Do not present the current unsigned or self-signed installer as a trusted public release.

The repository remains private. This review did not change visibility, rewrite history,
push commits, publish releases, install certificates, or enable paid features.

## Scope and evidence

- Fetched origin refs and tags; reviewed all five reachable commits through bf9be63.
  Only main/origin main was present; no release tags were present.
- Scanned 117 historical text blobs with targeted private-key, token, secret-assignment
  and known tenant-reference patterns, plus the current nonignored source candidate.
  No matches found. No historical _EXCLUDE, work, artifacts, evidence or signing/package
  file paths were found. This covers reachable Git history, not deleted GitHub data,
  inaccessible refs, external backups or forensic recovery of unreachable objects.
- Ran checksum-verified Gitleaks 8.30.1 with redacted reports over full reachable Git
  history, a source-only working-tree copy and all five existing GitHub Actions logs.
  No leaks found. Reports/log copies remain under ignored work/public-review.
- Visually inspected both tracked mockup PNGs: synthetic Northwind/example.com data.
  Added a notice distinguishing design concepts from implemented behavior.
- GitHub had zero issues, pull requests, releases and Actions artifacts. All five
  existing build runs reported success. Downloaded log scans found no secrets.
- NuGet vulnerable-package query including transitive desktop dependencies reported
  none against the configured nuget.org source. This does not audit bundled PowerShell,
  Microsoft modules, native libraries or vulnerabilities absent from that feed.
- MIT license is present for Lantern source. Dependency metadata/notices require a
  separate complete redistribution inventory before public binary release.
- The initial review found a personal author/committer email address in existing
  commits. In an owner-authorized follow-up, all five main-branch commits were rewritten
  and pushed through 2db7805 using the GitHub noreply address. GitHub API verification
  confirmed both email fields for every published commit. File trees, messages, names,
  dates and uncommitted work were preserved. GitHub email privacy and private-email
  push blocking are enabled; local and global Git email settings now use noreply.
  Old clones, recovery history and caches may retain the original metadata.

No secret scan proves the absence of every secret, personal record or vulnerability.
This is a publication-readiness review, not a penetration test or full code audit.

## Changes made during review

- Added SECURITY.md with a private-reporting workflow and safe fallback if GitHub's
  private reporting option is unavailable; no invented contact email or response SLA.
- Added CONTRIBUTING.md requiring synthetic examples and documented privacy boundaries.
- Replaced accumulated/outdated tenant setup notes with current workflow instructions.
  Removed misleading old claims that Exchange collection was absent, the demo button
  remained in the UI, or only risk flags were analyzed.
- Removed conversation-specific assistant-personality notes from development documentation.
- Clarified Exchange session reuse in privacy documentation.
- Added ignore rules for private key/certificate formats, environment variants and
  release archives. Existing local test certificates/packages remain ignored.
- Pinned GitHub Actions to resolved official commit SHAs and bounded job runtime.

## Visibility-transition checklist

1. Review/commit/push the current changes. GitHub main still contains the older committed
   snapshot until that happens. Do not accidentally include local evidence or test packages.
2. Keep the verified GitHub noreply configuration for future commits. Configure it
   on other development computers as well; this machine's settings do not propagate.
3. Make the repository public only on the owner's explicit instruction.
4. Immediately enable GitHub private vulnerability reporting and verify the reporter
   entry point. The endpoint returned 404 while private; this is not proof that a public
   reporting channel is configured. Update SECURITY.md if another private channel is chosen.
5. Configure main-branch protection/rulesets with passing build checks, restricted
   force-push/deletion and a practical review policy. The current protection API returned
   403 with a plan/public-visibility restriction, so protection was not verified.
6. Enable available GitHub secret scanning/push protection and dependency alerts, and
   verify their status. Security-and-analysis data was unavailable in the private-repo
   response; do not assume these protections are active.

## Separate public-binary release gates

- Use an approved free OSS signing provider or Store signing for public MSIX distribution.
  Keep the current test certificate and signed lab kit out of public releases.
- Complete a dependency SBOM/license-notice inventory for the exact bundled versions.
  Module manifest license links and individual files are not a complete legal or supply-chain review.
- The owner reports successful clean Windows 11 VM installation of the self-signed
  prototype. Record bundled authentication, source failures, update, rollback and uninstall
  results before claiming the installed edition is fully validated.
- Build from a clean tagged checkout, publish checksums and limitations, and test update
  discovery against an actual public GitHub prerelease. Public source alone does not
  create release metadata for the update checker.
- Review accessibility, large-tenant performance and source-specific detection limitations
  before describing the project as production-ready or comprehensive compromise detection.
