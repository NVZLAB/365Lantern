# Public alpha preparation — 2026-10-01

The owner authorized public-alpha preparation and publication after review. This
updates the [September source review](public-readiness-review.md); it is not a
penetration test or a claim that every tenant configuration is supported.

## Review evidence

- Gitleaks 8.30.1, previously checksum-verified, found no leaks in all six reachable
  commits, the nonignored source candidate, or all seven existing Actions logs.
  Targeted checks found no known local username or test-tenant references in the
  source candidate and no known test-tenant identifiers in those Actions logs.
- All reachable author/committer email metadata uses the GitHub noreply address.
  No tracked private-reference, evidence, work, artifact, key or certificate paths
  were found. GitHub had no issues, releases or retained Actions artifacts to expose.
- NuGet's vulnerable-package query, including transitive desktop dependencies,
  returned no listed vulnerabilities on 2026-10-01. This query does not cover every
  bundled Microsoft module, native binary or unpublished vulnerability.
- The current feature checks pass (437 checks); the Windows desktop build completes
  without warnings/errors. Synthetic UI checks cover imports, themes, report
  navigation, response confirmation and password handoff. No tenant writes were
  performed by the automated tests.
- Response remains separately authorized and explicitly confirmed. Investigation
  helpers remain read-only. Imported/synthetic cases, self-targeting and guest
  targets cannot initiate response. Ambiguous results are preserved as Unknown;
  writes are not retried automatically. Passwords are excluded from case exports.
- Public issue forms request synthetic reproductions and direct vulnerabilities to
  private reporting. Response is labeled experimental in the UI and testing guide.

## Distribution preparation

The portable builder now requires a clean committed checkout, includes documentation
and a synthetic offline sample, records the source commit, and generates a CycloneDX
1.6 inventory of declared dependencies and all shipped DLL/EXE hashes. The generated
format was validated against the official schema. Exact runtime license/notices and
supplemental upstream module notices are retained. Vendor file versions do not prove
NuGet identity; the inventory does not claim an exhaustive dependency graph or license
analysis for opaque vendor binaries.

The unsigned portable ZIP is the proposed first download. The self-signed MSIX and
laboratory certificate are excluded from public release assets. Checksums identify
bytes, not publisher trust. No public installer is promised in this alpha.

## Remaining release gates

Build and verify the candidate from the committed checkout. Record its commit and
ZIP hash, run the packaged smoke test and check its contents, then complete the
[clean-machine checklist](alpha-testing.md) on the exact ZIP before publishing the
download. Development-machine tests and previous installer tests are not substitutes.
The owner's reported successful tests are useful feedback but do not establish that
this newly packaged ZIP has passed that clean-machine check.

At the visibility transition, enable and verify private vulnerability reporting,
branch protection, available secret scanning/push protection and dependency alerts.
Their actual applied state must be checked through GitHub; configuration files alone
do not prove that these repository features are enabled.

Publish alpha releases as prereleases. An actual public release is required to
validate release discovery against GitHub; a draft is intentionally invisible to the
unauthenticated update checker. Do not claim this integration test passed before it runs.
