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
The closed Gate 1A case set in
[Gate artifact authorization](gate1a-artifact-authorization.md) proves first
install, identical reinstall, rollback refusal, CLI/helper replacement,
uninstall cleanup, migration cancellation, interruption at durable boundaries,
and partial destination/source failure with a non-secret sentinel. A missing
case or transcript is a Gate failure; these are not informal packaging tests.

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

The future Cask must use a versioned immutable URL and the literal SHA-256 of
the exact outer delivery archive; it may not use `sha256 :no_check`. That
archive contains the immutable signed/stapled app payload, detached provisional
authorization and production activation grant, root-signed publication
envelope, exact post-grant plan, and the complete closed evidence-set tree at
the protocol's fixed archive-root paths. The envelope does not hash its
containing archive; the reviewed Cask pins the archive bytes, while the root
signature binds every security-relevant contained object without a recursive
hash cycle. The closed tree includes, per architecture, the setup-only
enrollment context, empty pre-enrollment inventory, retained revision-1
registry snapshot, case-final evaluations, and final empty-inventory cleanup
proof, including the immutable attributed cleanup-intent/progress and
helper/runner evidence digests. The prepublication helper accepts deletion only
through the exact root-token-bound `stage_cleanup` IPC and reconciles each
byte-equal item under its serialized executor, with one durable acknowledged
marker before the sole delete and no re-delete for an unresolved marker. Session-bound stage
tokens remain historical digests only and are not shipped, so installed or
ordinary production processes receive no such deletion authority.

Installation copies this complete tree to one versioned Caskroom root without
rebuilding, re-signing, fetching auxiliary assets, or rewriting any byte
sequence. Before guarded mutations are enabled, the installed verifier reads
the envelope, plan, evidence-set index, digest-bound install-evidence manifest,
and listed evidence only from that root and fails closed on missing, extra,
linked, escaping, or digest-mismatched files.
It also CMS-validates the embedded helper profile, requires its semantic expiry
to equal descriptor `helper_profile_expires_at`, and requires trusted current
time to be strictly earlier. The same strict cutoff is repeated at helper
launch, confirmation, coordinator acquisition, permit issuance, and immediately
before send; a Cask installed before expiry does not remain write-capable after
it. After expiry, only the exact launchd-managed helper's recovery-only launch
and peer authentication may expose bounded status, trusted-UI fencing, journal
CAS, close reconciliation, and serialized byte-equal active cleanup; ordinary
authority remains denied. Installation also validates that the fixed helper
identifier is registered as one per-user launchd server and that no direct or
second listener mode is present. Homebrew update or reinstall cannot refresh that field without producing a
new signed artifact that starts again at E1.
Homebrew's checksum detects a changed download; the offline-root signature and
runtime Security.framework checks remain the authenticity and execution
boundary.

The accepted trust topology permits only the first signed Cask build and an
identical-artifact reinstall. Publishing a later write-capable Cask version is
blocked until a separate release-rollover ADR proves migration/revocation for
approval keys, registry state, YouTrack credentials, and stale access tokens;
package downgrade refusal alone does not stop a side-loaded older signed pair.
