# ADR: Gate 1A trust, storage, and package topology

- Status: Accepted for implementation, production identity not enrolled
- Date: 2026-09-03
- Gate 1A result: **NOT PASSED**
- Production approval adapter: `approval.Unsupported`

## Context

The approval protocol verifies a response against an already trusted public
key. A helper response cannot safely choose that key: doing so would turn the
first approval into trust on first use and let a replaced same-user process
enroll itself. A mode-`0600` file is also not an authority boundary against an
agent running as the same user.

The native helper, approval-key registry, code-signing identity, bundle layout,
release-rollover boundary, and future Homebrew artifact therefore form one trust topology.
They must be fixed before native implementation and must fail closed while the
operator-controlled signing identity is unavailable.

## Decision

### Signed bundle and identifiers

The only production distribution unit is one signed and notarized application
bundle named `YouTrackAgent.app`:

```text
YouTrackAgent.app/
  Contents/
    Info.plist
    MacOS/
      youtrack-agent-cli
    Library/Helpers/
      YouTrackAgentApproval.app/
        Contents/Info.plist
        Contents/embedded.provisionprofile
        Contents/MacOS/YouTrackAgentApproval
```

The identifiers are immutable protocol and packaging inputs:

| Code object | Signing identifier |
| --- | --- |
| outer app and CLI authority | `io.github.abigotado.youtrack-agent` |
| approval helper | `io.github.abigotado.youtrack-agent.approval` |
| developer-only Gate runner | `io.github.abigotado.youtrack-agent.gate1a` |

The Gate runner is never embedded in a release, Cask, Formula, archive, or
installed bundle. The CLI path exposed to users is always the executable inside
the installed application bundle. A future Homebrew Cask may install the app
and link that contained executable into Homebrew's binary directory; it may not
rebuild, replace, re-sign, or extract the helper.

The Apple Developer Team ID and positive decimal bundle build number are
required immutable release inputs named `TEAM_ID` and `RELEASE_BUILD`. The
repository has no default or fallback value for either. Empty, wildcard,
non-decimal build, ad-hoc, Apple Development, and locally self-signed inputs
are rejected for production evidence. At the acceptance
date no Developer ID Application identity is installed on the development
machine, so this ADR does not pass Gate 1A.

After substituting the operator-owned `TEAM_ID`, both peers compile and pin the
following Developer ID Application requirements. The exact identifier differs
per peer:

```text
anchor apple generic
and certificate 1[field.1.2.840.113635.100.6.2.6] exists
and certificate leaf[field.1.2.840.113635.100.6.1.13] exists
and certificate leaf[subject.OU] = "${TEAM_ID}"
and identifier "io.github.abigotado.youtrack-agent"
and info[CFBundleVersion] = "${RELEASE_BUILD}"
```

```text
anchor apple generic
and certificate 1[field.1.2.840.113635.100.6.2.6] exists
and certificate leaf[field.1.2.840.113635.100.6.1.13] exists
and certificate leaf[subject.OU] = "${TEAM_ID}"
and identifier "io.github.abigotado.youtrack-agent.approval"
and info[CFBundleVersion] = "${RELEASE_BUILD}"
```

The shipped requirements are compiled from a release manifest containing the
literal Team ID and build number; production code never expands an environment
variable at runtime. This prevents mixed-version peers but not an older matched
CLI/helper pair from trusting itself. Both sides validate the connection-bound
audit token with
`SecCodeCopyGuestWithAttributes` and the pinned opposite requirement before
accepting protocol bytes. They repeat peer validation after enrollment or
rotation and before committing new trust state. PID and filesystem paths are
diagnostic only.

### Entitlements and Keychain namespace

Both signed nested code objects use the hardened runtime, a secure timestamp,
and no `get-task-allow` or runtime exception entitlement. Only the helper's
provisioning profile authorizes this private data-protection Keychain group:

```text
$(AppIdentifierPrefix)io.github.abigotado.youtrack-agent.approval
```

The outer app and CLI have no entitlement for that group and perform no
Keychain query for approval state. Every helper query sets
`kSecUseDataProtectionKeychain=true` and explicitly names the resolved access
group. The following identifiers are fixed:

| Item | Identifier |
| --- | --- |
| Secure Enclave signing key tag prefix | `io.github.abigotado.youtrack-agent.approval.signing.v1/` |
| approval registry service | `io.github.abigotado.youtrack-agent.approval.registry.v1` |
| approval registry account prefix | `revision/` plus a 20-digit decimal revision |

The signing key is helper-owned P-256 Secure Enclave material. Every generation
uses a fresh 128-bit random key ID encoded as 32 lowercase hexadecimal
characters and the exact application tag formed by appending that ID to the
fixed prefix. The logical generation, key ID, full tag, DER SPKI, and
fingerprint are bound into the registry transition. Its private key
is non-exportable and requires `.privateKeyUsage` together with the accepted
fresh-presence policy. A new `LAContext` with zero reuse is bound to the actual
key lookup/sign operation, used once, and invalidated. A separate Gate decision
must record whether the release uses `userPresence` or
`biometryCurrentSet`; there is no silent fallback between them.

The helper enumerates at most 64 keys in only that private tag namespace and
never retrieves a key by a reused tag. A candidate created before a failed or
losing registry transition is an orphan and is never eligible for signing
because no committed transition names it. After exact transition
reconciliation, a separate bounded maintenance pass may delete orphaned or
retired private keys; deletion failure leaves a non-authoritative orphan and is
reported, never treated as transition failure or permission to reuse the key.
Retained public verification keys live in the ledger and do not require old
private keys. Hitting the key-enumeration bound fails closed pending explicit
operator cleanup through trusted helper UI.

The approval-key registry is not a profile file or one mutable item. It is a
bounded append-only ledger in the helper-private data-protection Keychain
group. Each canonical transition contains its schema version, monotonic
revision, predecessor-record SHA-256, active generation, exact DER SPKI, SPKI
SHA-256, trust-manifest SHA-256, status, transition evidence, and retained
verification generations. The
public CLI surface can request an exact active/retained record through one
bounded, peer-authenticated helper operation but cannot address Keychain items
directly. Only the helper's
challenge-bound enrollment, rotation, revocation, and recovery ceremonies may
mutate the record after trusted UI and fresh user presence.

The private group is an authority boundary for key use and registry mutation;
mutual peer validation and a bounded protocol are still required to prevent a
validly signed caller from turning the helper into an arbitrary Keychain
oracle. A same-user process can deny service by interfering with local IPC or
lock files, but cannot acquire the helper's group entitlement. Any entitlement
mismatch, duplicate item, noncanonical record, unexpected revision, rollback,
missing generation, access-group ambiguity, or uncertain Keychain mutation
fails closed.

### Enrollment is a separate authority transition

Ordinary approval can never enroll or replace a key. Enrollment uses a
separate protocol magic/domain and fresh 256-bit challenge, not an approval
frame or approval receipt. It is available only when no valid registry exists
and the operator explicitly starts the enrollment ceremony.

The ceremony is:

1. The CLI validates the connected helper against the pinned helper
   requirement and snapshots the empty registry revision.
2. The helper validates the CLI against the pinned CLI requirement before
   reading the bounded enrollment request.
3. Trusted helper UI displays the release identity, Team ID, generation, SPKI
   fingerprint, and the fact that a new trust root is being created.
4. Fresh user presence authorizes generation or use of the helper-only Secure
   Enclave key.
5. The helper returns generation, exact DER SPKI, fingerprint, challenge
   digest, trust-manifest digest, issuance time, and a self-signature over the
   enrollment domain and all those fields.
6. The CLI revalidates helper identity on the same connection, verifies the
   self-signature with the returned SPKI, checks every binding, then returns an
   exact challenge-bound acceptance message. It has no direct registry-write
   primitive.
7. The helper revalidates the peer and re-reads the exact empty state. It
   creates revision 1 with `SecItemAdd` under account
   `revision/00000000000000000001`; `errSecDuplicateItem` is a conflict.
8. The CLI reads the committed record through the helper's bounded read-only
   operation and compares its exact bytes before reporting success.

Failure or uncertain durability leaves enrollment incomplete. Normal approval
continues to fail closed; it never retries enrollment implicitly.

### Rotation, revocation, and recovery

Rotation is a separate fresh-presence ceremony bound to both the old and new
generations. When the old key remains usable, it signs continuity into the
rotation record; the new key signs acceptance. The next immutable registry
transition commits both signatures and the new active generation.

Old public verification keys remain retained while any unexpired or unresolved
receipt references them. Retention authorizes verification only, never new
approvals. Revocation immediately blocks new approvals from that generation;
already confirmed plans are canceled unless a reviewed policy explicitly
allows their still-valid receipt to proceed. This first implementation chooses
the safer default: rotation or revocation cancels outstanding confirmed plans
and requires fresh preparation and approval.

Key loss has no continuity signature and therefore cannot be rotation.
Recovery is an explicit operator ceremony that displays the loss of
continuity, revalidates the signed bundle, uses fresh user presence, creates a
new generation, revokes all prior generations, and invalidates every existing
confirmed receipt. Recovery never silently reauthorizes a plan. Within the
current signed helper and retained current registry, an older generation
cannot become active without a new recovery ceremony.

This design does not claim cryptographic anti-rollback against an interactive
operator or administrator that installs an older legitimately signed release,
or against an administrator, backup/restore mechanism, or compromised Keychain
service that replaces the ledger with an older complete snapshot. The latter
is undetectable even by the current binary. Team ID and identifier requirements
prove publisher identity, not release or state freshness. Preventing that class
of rollback requires a separately operated monotonic service or an equivalent
external high-water mark and is outside the first release threat model.
Packaging must refuse ordinary downgrade, and Gate 1A must show that an
accidental older-app launch against the retained current registry fails closed;
neither result is described as universal anti-rollback.

### Atomic registry transitions and durable confirmation

The CLI filesystem lock order is:

```text
profile -> policy -> one plan journal
```

Registry transitions do not use a user-owned lock or `SecItemUpdate`. The
helper enumerates only the fixed service and private access group with
match-limit-all, caps the result at 256 revisions, sorts and validates every
canonical account and record, and requires one gap-free hash chain beginning at
revision 1. Missing, duplicate, malformed, forked, out-of-range, or trailing
records fail closed.

To move from revision N to N+1, the helper re-reads that chain, verifies the
expected revision and predecessor digest, then performs exactly one
`SecItemAdd` under account `revision/%020d`. Keychain's unique
service/account/access-group identity makes concurrent candidates contend for
the same new item: one add can win and every different candidate receives
`errSecDuplicateItem`. The helper then reads that exact account and
byte-compares it before reporting success. After an error or crash-ambiguous
add, reconciliation reads once: the exact intended bytes are success, absence
is a failed uncommitted ceremony, and different bytes are a conflict. It never
repeats an add automatically and never mutates or deletes a ledger revision.
Reaching the 256-record bound fails closed pending a separately reviewed ledger
migration; compaction is not implicit.

Confirmation snapshots the profile, policy, and plan revision under that
order, obtains the exact registry revision and key generation through the
helper, then releases all journal locks before
opening trusted UI. After approval it reacquires the same locks, revalidates
every snapshot and the signed receipt, and performs one revision CAS from
`prepared` to `confirmed`. No UI or remote request runs while a journal lock is
held. Any later registry transition invalidates the receipt at the next helper
validation. No remote executor may be activated until Gate 1B selects and
proves the exact ordering between apply and a concurrent rotation or
revocation; Gate 1A does not claim that cross-boundary guarantee.

The journal stores the complete canonical signed receipt and an exact copy of
the verification SPKI, not only a digest. The copy is binding evidence, never a
trust root: restore and apply paths reparse it with protocol bounds and require
it to match an active or retained registry generation before verifying the
signature, receipt hash, registry status, and all plan bindings.
This durable confirmation implementation and the native adapter must exist
before Gate 1A. The dedicated non-writing Gate self-test constructs that
adapter inside the production CLI, but `application.NewDefault` remains wired
to `approval.Unsupported` until the operator Gate is recorded as passed.

### First-release, rollover, rollback, and uninstall

Every release manifest binds the outer/helper identifiers, Team ID,
requirements, entitlements, access-group name, item identifiers, architecture
set, version/build number, hashes of both executables, and the helper's embedded Developer
ID provisioning-profile hash. The profile must authorize the helper App ID,
Team ID, and exact `keychain-access-groups` entitlement. It must be valid for
Developer ID distribution and unexpired at signing and Gate execution. The
nested helper is signed with the profile at
`Contents/embedded.provisionprofile`; the outer bundle is signed afterward.
The exact distribution is notarized and stapled.

The first production release has no supported predecessor and no supported
write-capable in-place upgrade. Exact-build requirements make a current
CLI/helper reject a mixed-version peer. They do not prevent a side-loaded older
matched pair from trusting itself and accessing a stable entitlement group.
Package downgrade refusal is therefore an operational guard, not release
freshness enforcement.

A second write-capable release is prohibited until a separate accepted ADR and
Gate define release rollover for approval keys, registry state, every YouTrack
credential, stale access-token expiry/revocation, side-loaded old binaries, and
crash recovery. A future design may use release-specific entitlement groups and
explicit user-authorized migration or an external monotonic authority; this ADR
does not choose one. Reinstalling the identical first-release artifact is
allowed, but no Cask update may cross to a different build before that rollover
gate passes.

The helper can validate only the complete ledger presented by Keychain;
without an external monotonic authority it cannot detect restoration of an
older complete ledger snapshot, even when the current binary remains installed.
That restoration and execution of a hypothetical older matched signed pair are
explicitly outside the first-release claim. An unsigned, differently signed,
or mixed-build binary/helper replacement breaks peer validation before
approval.

Uninstall removes the application bundle but does not silently delete or
migrate approval keys, registry state, credentials, or journals. Destructive
cleanup is a separate explicit operator action. A Homebrew hook may not grant
new Keychain access or run enrollment.

## Required evidence and activation order

Before Gate 1A can pass, an operator-controlled Developer ID Application
identity must produce an exact hardened-runtime bundle. A black-box Gate
harness must launch and drive the CLI contained in that bundle; it never links
the adapter, injects a peer, changes a requirement, or receives Keychain
entitlements. A dedicated non-writing self-test surface in the same CLI may
exercise the native adapter and test journal while all remote executors remain
disabled. Against that exact artifact, the harness exercises enrollment,
approval, durable journal CAS, cancellation, timeout, process crash, production
peer replacement, rotation, revocation, recovery, identical reinstall, and
accidental package rollback on a supported clean Mac. A separately signed,
never-shipped old-build fixture with the production IDs proves both current
peers reject mixed-build connections; the report also records that a matched
old pair is not prevented by this first-release topology. The fixture is
created only inside the disposable Gate environment, is not notarized or
archived, and is destroyed with that environment. `codesign`, `spctl`,
notarization, stapling,
entitlements, Team ID, architecture, requirement, and embedded-profile
CMS/App ID/Team ID/expiry/entitlement checks all refer to that same artifact.

Registry corruption, fork/gap/duplicate parsing, crash-ambiguous `SecItemAdd`,
orphan-key cleanup, and active-key loss require access that the black-box
harness intentionally lacks. Those cases use a separately built and signed
fixture from the same reviewed commit, with bundle IDs, access group, key tags,
registry service, and peer requirements under the disjoint
`io.github.abigotado.youtrack-agent.gate1a.fixture` namespace. Its helper alone
exposes bounded fault operations, accepts only the Gate runner identity, and
stores data only in the disposable fixture group. Fixture code and
entitlements are compile-time absent from the production target; the fixture
is never embedded, notarized, shipped, installed by Cask, or accepted by a
production requirement. Gate reporting labels exact-artifact and fixture
evidence separately and does not present fixture results as production
artifact execution.

The separate Gate runner identity is diagnostic orchestration only and is
never accepted as the production helper's protocol peer. A Gate run uses a
disposable macOS user or VM and destroys its fixture Keychain state afterward.

Gate 1A enables only the native approval boundary. The REST executor stays
disabled until separate live Gate 1B evidence on a disposable YouTrack 2026.2
project proves exact identity/preconditions, one-shot `issue.create`, and
bounded ambiguous-outcome reconciliation. `issue.update` and `comment.add`
remain subject to their own executor decision.

Public Homebrew distribution is last. The accepted shape is a Cask or private
tap that installs the already signed/notarized app and links its contained CLI.
A source Formula cannot rebuild the helper or establish its production code
identity.

## Consequences

- The project can implement durable confirmation and exercise the native
  adapter through a non-writing Gate self-test without granting remote write
  authority.
- A real Team ID is absent from source and cannot be guessed; an unset release
  configuration fails before signing, enrollment, or approval.
- The first release can be evaluated and installed, but publishing a second
  write-capable build is blocked on an explicit key-and-credential rollover
  design.
- Enrollment, rotation, recovery, approval, and mutation execution are distinct
  authority transitions with distinct domains and journal effects.
- The native bundle is macOS-only. Unsupported platforms and unsigned local
  source builds retain the fail-closed adapter.

## Evidence sources

- Apple: [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- Apple: [`errSecDuplicateItem` and Keychain composite primary keys](https://developer.apple.com/documentation/security/errsecduplicateitem)
- Apple: [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- Apple: [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- Apple: [Generating new cryptographic keys](https://developer.apple.com/documentation/security/generating-new-cryptographic-keys)
- Apple: [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- Apple: [TN3127: Inside Code Signing: Requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
- Apple: [`SecCodeCopyGuestWithAttributes`](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)) and [guest attribute keys](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys)
- Apple XNU: [`LOCAL_PEERTOKEN` in `sys/un.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h)
- Apple: [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- Homebrew: [Cask Cookbook](https://docs.brew.sh/Cask-Cookbook#stanza-binary)

## Rejected alternatives

- approval-time TOFU or a response-selected verification key;
- plaintext, profile, journal, mode-`0600`, environment, or CLI-argument trust
  roots;
- one shared protocol domain for enrollment and approval;
- an agent-visible `--yes`, stdin, PTY, environment, or browser approval path;
- silent key recovery, Keychain migration, or receipt reauthorization;
- path/PID-only peer trust;
- ad-hoc signing as production evidence;
- a source-built Formula or post-install hook that re-signs the helper.
