# Homebrew readiness

Homebrew installation is **not available** in this implementation slice. The
repository intentionally contains no installable Formula or Cask, no tap
publication workflow, and no release credential. The checked dependency
manifest and its validator check dependency closure and offline source builds
only. They are not Formula/Cask, signing, or native Gate proof and do not
produce or publish a package.

## Why Gate 1A blocks packaging

An ordinary source-built Formula compiles the CLI in Homebrew's build
environment. It cannot, by itself, preserve the designated code-signing
identity and entitlements of the separate native approval helper required by
Gate 1A. Rebuilding or replacing that helper changes the identity on which
receipt signing and Keychain access depend. Ad-hoc signing is not production
evidence, and removing Gatekeeper quarantine is never an acceptable workaround.

The [Gate 1A trust-root ADR](gate1a-trust-root.md) now fixes the complete macOS
delivery shape before helper implementation:

- one signed and notarized `YouTrackAgent.app` with its nested helper and
  sealed `Contents/Library/LaunchAgents/io.github.abigotado.youtrack-agent.approval.plist`;
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
The sealed LaunchAgent has fixed label
`io.github.abigotado.youtrack-agent.approval` and `BundleProgram` equal to
`Contents/Library/Helpers/YouTrackAgentApproval.app/Contents/MacOS/YouTrackAgentApproval`,
relative to the outer bundle. Registration with
`SMAppService.agent(plistName:)` requires an explicit operator action and is
subject to macOS approval; Cask installation does not register or launch it.
The helper binds the fixed per-user ordinary AF_UNIX endpoint, and each CLI
connects itself for connection-bound `LOCAL_PEERTOKEN` validation. The job
label and launchd-parent constraint do not establish a global singleton:
ordinary same-UID launchctl and alternate bootstrap contexts remain in scope,
and unique Keychain `active` acquisition supplies cross-process exclusion.
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

Homebrew may be activated only after Gate 1A and live Gate 1B pass, the
non-production pilot and independent security review pass, and the
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
registry snapshot, case-final evaluations, and external whole-host disposal
attestations. The trusted external supervisor destroys each disposable host
after the closed evidence export; smoke disposal precedes activation-grant
signing, and post-grant disposal precedes publication-envelope signing. The
root-bound attestations bind the exact stage/session, evidence index, export
manifest, and supervisor-observed host, without granting runtime authority.
Mutable Keychain, journal, session, credential, and private-key state is never
exported or reused. Live `stage_cleanup`, intent/progress, ACK-ledger deletion
authority, and empty-inventory cleanup proofs are deferred from this release.
Session-bound stage
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
and peer authentication may expose bounded status and exact persistent-reference
cleanup of an already validly closed lease. Unclosed state remains quarantined
with no journal CAS, synthesized close, or deletion, even after reboot or fresh
user presence; ordinary authority remains denied. The
valid closed capacity sentinel is retained when protected history reaches its
bound; neither expiry nor reinstall permits clearing it. See the
[native authority constraints](gate1a-registry-protocol.md). Installation verifies the
sealed LaunchAgent declaration and intended lifecycle but never assumes that
launchd prevents another exact signed helper under the same UID. Homebrew
update or reinstall cannot refresh that field without producing a
new signed artifact that starts again at E1.
Homebrew's checksum detects a changed download; the offline-root signature and
runtime Security.framework checks remain the authenticity and execution
boundary.

The accepted trust topology permits only the first signed Cask build and an
identical-artifact reinstall. Publishing a later write-capable Cask version is
blocked until a separate release-rollover ADR proves migration/revocation for
approval keys, registry state, YouTrack credentials, and stale access tokens;
package downgrade refusal alone does not stop a side-loaded older signed pair.
