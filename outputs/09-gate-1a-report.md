# Gate 1A approval-helper evidence report

- Status: **NOT PASSED**
- Date opened: 2026-09-02
- Scope completed by this report: protocol-contract spike only
- Production approval adapter: `approval.Unsupported`

This report is deliberately fail-closed. Protocol code, shared Go/Swift golden
vectors, parser tests, and ad-hoc development builds are preparation evidence;
they do not prove the signed native approval boundary required by Gate 1A.

## Slice 1: protocol contract

| Requirement | Status | Evidence |
| --- | --- | --- |
| Versioned canonical receipt/signature byte contract | Passed for slice 1 | `docs/gate1a-protocol.md` and `testdata/gate1a` |
| Strict bounded Go receipt codec | Passed for slice 1 | `go test -race ./internal/approval` |
| Independent Swift parser/encoder agreement | Passed for slice 1 | 16 tests through `swift test` on macOS |
| Reversible inert rendering of every displayed byte | Passed for slice 1 | all-byte, empty, maximum-size, and round-trip Swift tests |
| Production approval helper used by the CLI | Not implemented | `approval.Unsupported` remains the only adapter |

Completion of this slice must not change this report's overall status from
**NOT PASSED**.

## PR A: native-boundary value contract

The accepted boundary ADR freezes the language-neutral ASCII URL grammar,
canonical 128-bit plan ID, binary frame header and payload union, CSPRNG
challenge echo, closed error codes, strict canonical plan parsing, and the Go
success cross-binding verifier. Shared fixtures cover all three mutation plan
kinds plus URL, identifier, request, success, and error frames.

This remains value-codec evidence only. There is no production AF_UNIX I/O,
process launch, peer audit-token validation, native key access, approval UI, or
application wiring. Consequently PR A does not advance the overall Gate result
beyond **NOT PASSED**.

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

- The signing key is permanent P-256 Secure Enclave material in a helper-only
  data-protection Keychain access group.
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
  helper bundle with hardened runtime, timestamp, exact entitlements, and no
  `get-task-allow`.
- The bundle is notarized and stapled; `codesign`, `spctl`, and stapler checks
  pass against the exact designated requirement, Team ID, and architecture set.
- Clean-machine install, upgrade, rollback, binary/helper replacement, key
  rotation, and application-update cases preserve the boundary or fail closed.
- The CLI locally verifies receipt DER signatures against an explicitly
  enrolled public key and stores the full signed receipt only after a
  revision-bound compare-and-swap.

Missing production signing, notarization, Secure Enclave isolation, or
clean-machine evidence is an automatic Gate 1A failure.

## Deferred product integration

Even after Gate 1A passes, a separate reviewed change must add the full signed
receipt to the journal, revalidate profile/policy/revision after approval, and
commit `prepared -> confirmed` with compare-and-swap. `apply` and `reconcile`
remain disabled until their own one-shot and ambiguous-outcome gates pass.

## Homebrew decision

Homebrew remains blocked. This spike does not authorize a Formula, Cask, tap,
release workflow, source rebuild of the helper, or package publication. After
Gate 1A passes, a separate packaging ADR must prove that a signed and notarized
helper retains its identity and entitlements across Cellar path changes,
upgrade, rollback, and uninstall. The existing offline module manifest and
checker remain readiness inputs only.
