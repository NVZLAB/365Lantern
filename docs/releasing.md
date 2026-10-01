# Versioning and releases

## Single source of truth

Edit VersionPrefix and VersionSuffix in Directory.Build.props. All .NET projects
inherit this identity. The title/sidebar and exported summary/manifest read the
compiled assembly metadata; do not hard-code another version in application code.
The SDK may append the source commit to the informational version. This identifies
the source revision, but does not certify that a local working tree was clean.

Current development target: 0.1.0-alpha.2. Public 0.1.0-alpha.1 was released on 2026-10-01. Both remain alpha versions, not a claim of production readiness.

## Numbering

- PATCH: compatible bug fixes, e.g. 0.1.1.
- MINOR: new investigation capabilities or workflows, e.g. 0.2.0.
- MAJOR: incompatible changes after 1.0, e.g. 2.0.0.
- Before 1.0, document breaking changes prominently in a minor release.
- alpha.N: active development; beta.N: feature-complete candidate undergoing validation;
  rc.N: release candidate with only release-blocking fixes expected.
- Increment the prerelease number for each published candidate. Never replace an existing tag or asset.
- Stable releases have an empty VersionSuffix. Git tags use v, e.g. v0.1.0-alpha.1.

Export schemaVersion is separate from the application version. Keep compatible
additions backward compatible; document and version incompatible export changes.
Suspicious-behavior rule versions remain separate so detection changes are traceable.

## Release procedure

1. Finish the intended changes and update CHANGELOG.md under Unreleased.
2. Confirm the shared version. Move the completed entries to a heading such as
   `## [0.1.0-alpha.1] - YYYY-MM-DD` using the actual release date; leave a new Unreleased section.
3. Run the Windows build, automated checks and synthetic UI smoke test. Record which
   collectors have been tested live and retain known licensing/coverage limitations in release notes.
4. Review the files to be shipped. Exclude tenant evidence, credentials, local reference
   scripts, caches and private test artifacts. Publish from a clean committed checkout.
5. Create and push an annotated tag matching the compiled version. Create a GitHub Release
   from that tag, using the changelog entry, and mark alpha/beta/rc releases as prereleases.
6. Attach the tested Windows package with its prerequisites, launch instructions and
   SHA-256 checksum. State signing status accurately. This repository currently has build CI;
   tagging alone does not package or publish a release. Use the manual Portable Windows
   preview workflow or scripts/Build-Portable.ps1; see [portable packaging](portable.md).
7. Advance the version for the next development candidate immediately after release.

Do not mark 1.0 until collection failure handling, evidence integrity, supported tenant
configurations, installation and the promised user workflows have been validated.
Creating this scheme does not create a tag or publish a GitHub Release.
