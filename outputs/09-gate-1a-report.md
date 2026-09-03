# Gate 1A approval-helper evidence report

- Status: **NOT PASSED**
- Date opened: 2026-09-02
- Scope completed by this report: protocol-contract spike only
- Production approval adapter: `approval.Unsupported`

The accepted [trust-root and package-topology ADR](../docs/gate1a-trust-root.md)
freezes the identifiers, Team ID input, Keychain namespace, enrollment,
rotation/recovery, signed layout, and evidence order. It is a design result,
not Gate evidence.

This report is deliberately fail-closed. Protocol code, shared Go/Swift golden
vectors, parser tests, and ad-hoc development builds are preparation evidence;
they do not prove the signed native approval boundary required by Gate 1A.

## Slice 1: protocol contract

| Requirement | Status | Evidence |
| --- | --- | --- |
| Pre-Gate v2 canonical receipt/signature byte contract | Passed for slice 1 only | `docs/gate1a-protocol.md` and `testdata/gate1a` |
| Activation-eligible v3 registry-revision binding | Not implemented | Required v3 delta in `docs/gate1a-protocol.md` |
| Strict bounded Go receipt codec | Passed for slice 1 | `go test -race ./internal/approval` |
| Independent Swift parser/encoder agreement | Passed for slice 1 | 39 tests through `swift test` on macOS |
| Reversible inert rendering of every displayed byte | Passed for slice 1 | all-byte, empty, maximum-size, and round-trip Swift tests |
| Production approval helper used by the CLI | Not implemented | `approval.Unsupported` remains the only adapter |

Completion of this slice must not change this report's overall status from
**NOT PASSED**.

## PR A: native-boundary value contract

The accepted boundary ADR freezes the language-neutral ASCII URL grammar,
canonical 128-bit plan ID, binary frame header and payload union, a signed
CSPRNG challenge digest, closed error codes, strict canonical plan parsing,
and a Go verifier requiring the enrolled generation/SPKI/fingerprint. Shared
fixtures cover all three mutation plan kinds plus URL, identifier, request,
success, and error frames. Existing profile and journal reads retain their
legacy URL grammar; new mutation preparation fails early with
`MUTATION_PROFILE_INCOMPATIBLE` when the selected profile cannot be represented
by the narrower approval protocol.

This remains value-codec evidence plus an offline compatibility guard. There is
no production AF_UNIX I/O, process launch, peer audit-token validation, native
key access, approval UI, helper integration, or confirmation orchestration.
Consequently PR A does not advance the overall Gate result beyond **NOT
PASSED**.

## Required later evidence

### Connection-bound process identity

- Accepted AF_UNIX connections expose `LOCAL_PEERTOKEN` audit tokens.
- Each side validates the connection-bound audit token with
  `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` and its pinned
  designated requirement.
- PID and filesystem-path checks are diagnostic only.
- Replacement, exec, PID reuse, malformed framing, timeout, EOF, and trailing
  data all fail before approval.

### Disposable Secure Enclave and UI spike

- Every signing generation is permanent P-256 Secure Enclave material with a
  fresh random key ID/tag in a helper-only data-protection Keychain access
  group; only a committed active registry transition may select it.
- The item uses `kSecAttrAccessControl`; it does not combine that contract with
  legacy `kSecAttrAccess` ACL configuration.
- One new `LAContext` is bound to the actual private-key sign operation, has no
  authentication reuse window, is used once, and is then invalidated.
- The selected `userPresence` password-fallback or `biometryCurrentSet` policy
  is explicit and tested.
- The separately signed UI displays the complete bounded immutable plan through
  the reversible inert renderer without rich text, links, data detectors,
  clipboard actions, or truncation.
- Cancellation, helper crash, key loss/rotation, unrelated-process access, and
  unsupported hardware fail closed without a receipt or network activity.

This spike requires an explicit operator run before it may create disposable
Keychain or Secure Enclave state.

### Production signing and clean-host gate

- An operator-controlled Developer ID Application identity signs the frozen
  helper bundle with hardened runtime, timestamp, exact entitlements, its
  matching embedded Developer ID provisioning profile, and no
  `get-task-allow`.
- The bundle is notarized and stapled; `codesign`, `spctl`, and stapler checks
  pass against the exact designated requirement, Team ID, and architecture set.
- Clean-machine first install, identical reinstall, accidental package
  rollback, binary/helper replacement, and key rotation cases preserve the
  stated first-release boundary or fail closed. A mixed-build fixture is
  rejected; a matched older pair is recorded as an unsolved rollover case.
- The CLI locally verifies receipt DER signatures against an explicitly
  enrolled public key and stores the full signed receipt only after a
  revision-bound compare-and-swap.

Missing production signing, notarization, Secure Enclave isolation, or
clean-machine evidence is an automatic Gate 1A failure.

Helper-private corruption, key-loss, orphan-cleanup, and ambiguous-Keychain
faults are exercised only by the separately signed Gate fixture defined in the
trust-root ADR. It uses disjoint identifiers, access group, key tags, registry,
and peer requirements and is compile-time absent from the production target.
Reports must distinguish that fixture evidence from black-box execution of the
exact notarized candidate.

## Required candidate product integration

Before Gate 1A runs, a separate reviewed change must add the full signed receipt,
its exact approval-registry revision, and exact verification SPKI to the
journal; revalidate profile/policy/key/revisions after approval; and commit
`prepared -> confirmed` with compare-and-swap. A black-box harness launches the
production CLI from the
exact signed candidate bundle and drives its ordinary `mutation confirm`
entry point; it does not inject an adapter, gain Keychain access, or become an
accepted helper peer. The current repository remains wired to
`approval.Unsupported`, but the unpublished Gate candidate's default factory
must wire the native adapter before signing. Gate success qualifies those exact
hashes; it is not followed by a wiring commit or rebuild. `apply` and
`reconcile` remain disabled until a separate exact Gate 1B candidate proves
their one-shot and ambiguous-outcome behavior on a disposable YouTrack project.
Because that wiring changes executable hashes, the same candidate must rerun
and pass Gate 1A before Gate 1B evidence can qualify it.

## Homebrew decision

Homebrew remains blocked. The trust-root ADR selects a future Cask/private-tap
shape, but this work does not authorize a Formula, Cask, tap, release workflow,
source rebuild of the helper, or package publication. Gate 1A must prove that
the signed and notarized nested helper retains its identity and entitlements
across first install, identical reinstall, rollback refusal, replacement, and
uninstall. Gate 1B must
then prove the live one-shot YouTrack write path. The existing offline module
manifest and checker remain readiness inputs only.

Only the first signed Cask build may follow these gates. A second
write-capable release remains blocked until its separate rollover decision and
evidence cover side-loaded old pairs, approval state, credentials, and stale
access tokens.
