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

The [Gate 1A trust-root ADR](gate1a-trust-root.md) now fixes the complete macOS
delivery shape before helper implementation:

- one signed and notarized `YouTrackAgent.app` with its nested helper;
- a Cask or private tap that installs the finished bundle and links its
  contained CLI, never a source Formula that rebuilds the helper;
- the detached exact-artifact descriptor, provisional authorization,
  post-smoke production activation grant, post-grant production-context
  verification evidence, and publication envelope from
  [Gate artifact authorization](gate1a-artifact-authorization.md);
- immutable release inputs and Apple CodeDirectory identities for the CLI and
  helper, independently authorized by the pinned offline root;
- preservation and verification of helper identity and entitlements through
  first install, identical reinstall, rollback refusal, and uninstall;
- explicit prohibition of a second write-capable build until release rollover;
  and
- an explicit, credential-safe Keychain ACL migration flow into the first
  signed app.

No installer or post-install hook may silently migrate Keychain authorization.
The operator must run the explicit `auth migrate-keychain --profile NAME --yes`
flow, which rebinds the existing item without printing or returning its secret.
The first-release gate must prove identical reinstall, cancellation,
interruption, binary replacement, helper replacement, and failed migration.

## Missing release provenance

This repository has committed source and a remote, but it still has no immutable
release tag, signed release archive checksum, notarization record, installed
Developer ID Application identity, offline-root-signed descriptor/Gate
evidence/provisional authorization/activation grant/post-grant verification/
publication envelope, or
operator-controlled signing evidence.
Consequently, no correct Cask can be materialized from the repository today.

Homebrew may be activated only after Gate 1A and live Gate 1B pass and the
fail-closed release-policy guard is deliberately updated in the same reviewed
change. Until then, use a local source build for development and do not publish
or install a Homebrew package.

The future Cask must use the exact outer delivery-archive SHA-256 recorded by
the root-signed publication envelope and may not use `sha256 :no_check`. That
outer archive contains the immutable signed/stapled app payload and the
detached provisional authorization plus production activation grant at the
protocol's fixed archive-root paths.
Installation copies them to the fixed app/support paths without rebuilding,
re-signing, or rewriting any byte sequence. Homebrew's checksum detects a
changed download; the offline-root signature and runtime Security.framework
checks remain the authenticity and execution boundary.

The accepted trust topology permits only the first signed Cask build and an
identical-artifact reinstall. Publishing a later write-capable Cask version is
blocked until a separate release-rollover ADR proves migration/revocation for
approval keys, registry state, YouTrack credentials, and stale access tokens;
package downgrade refusal alone does not stop a side-loaded older signed pair.
