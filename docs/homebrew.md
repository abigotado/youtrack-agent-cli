# Homebrew readiness

Homebrew installation is **not available** in this implementation slice. The
repository intentionally contains no installable Formula or Cask, no tap
publication workflow, and no release credential. The checked dependency
manifest and its validator are readiness inputs only; they do not produce or
publish a package.

## Why Gate 1A blocks packaging

An ordinary source-built Formula compiles the CLI in Homebrew's build
environment. It cannot, by itself, preserve the designated code-signing
identity and entitlements of the separate native approval helper required by
Gate 1A. Rebuilding or replacing that helper changes the identity on which
receipt signing and Keychain access depend. Ad-hoc signing is not production
evidence, and removing Gatekeeper quarantine is never an acceptable workaround.

Before Homebrew can be enabled, a follow-up architecture decision must choose
and audit the complete macOS delivery shape:

- a signed and notarized application/helper bundle and its update boundary;
- Formula versus Cask, and whether distribution belongs in a private tap;
- immutable release inputs and provenance for the CLI and helper;
- preservation and verification of helper identity and entitlements through
  install, upgrade, rollback, and uninstall;
- behavior when a Homebrew Cellar upgrade changes the executable path; and
- an explicit, credential-safe Keychain ACL migration flow after upgrade.

No installer or post-install hook may silently migrate Keychain authorization.
The operator must run the explicit `auth migrate-keychain --profile NAME --yes`
flow, which rebinds the existing item without printing or returning its secret.
The release gate must prove successful upgrades as well as cancellation,
interruption, binary replacement, helper replacement, and failed migration.

## Missing release provenance

This repository currently has no committed release revision, remote release
source, immutable version tag, source-archive checksum, notarization record, or
operator-controlled signing evidence. Consequently, no correct Formula or Cask
can be materialized from the repository today.

Homebrew may be activated only after Gate 1A passes, the follow-up packaging
decision is accepted, and the fail-closed release-policy guard is deliberately
updated in the same reviewed change. Until then, use a local source build for
development and do not publish or install a Homebrew package.
