# ADR: Gate 1A native approval boundary

- Status: Accepted for PR A contract implementation
- Date: 2026-09-02
- Gate result: **NOT PASSED**
- Production adapter: `approval.Unsupported`

The complementary [trust-root and package-topology
ADR](gate1a-trust-root.md) freezes the production bundle identifiers, nested
layout, Team ID input, Keychain registry, enrollment lifecycle, and clean-host
evidence required to instantiate this protocol. The normative
[registry/ceremony codec](gate1a-registry-protocol.md) and
[exact-artifact authorization](gate1a-artifact-authorization.md) remove the
remaining implementation choices from those authority boundaries.

## Context

YouTrack mutations require evidence that a human reviewed one exact, bounded
plan and was freshly authenticated by macOS. A terminal prompt, `--yes`, an
agent-controlled browser, or an unsigned child process cannot provide that
evidence. LocalAuthentication alone proves an authentication event but does
not bind the reviewed bytes, instance, account, project, preconditions, and
helper key into a durable receipt.

The boundary is exposed to confused-deputy and parser-differential risks: an
agent controls plan content, same-user processes can race or replace endpoints,
URL libraries disagree on normalization, and an ECDSA signature has multiple
encodings unless the wire form is frozen.

## Decision

Go is the canonical plan and receipt authority. The separately signed native
component independently validates the same language-neutral value grammar,
renders every plan byte inertly and reversibly, obtains fresh user presence,
and signs one cross-bound receipt with a non-exportable P-256 key. Neither side
trusts decoded values merely because the other side accepted them.

PR A freezes pure value codecs, shared vectors, the future connection contract,
and one offline application guard for newly prepared mutations. It introduces
no socket, process launch, helper discovery, Keychain, Secure Enclave, UI,
confirmation orchestration, journal transition, or mutation I/O.

### Canonical URL and plan identity

Every approval URL is at most 2,048 ASCII bytes and starts with literal
lowercase `https://`. Its host is either canonical lowercase DNS or canonical
dotted IPv4:

- DNS totals at most 253 bytes; every label is 1..63 bytes, contains only
  `a-z`, `0-9`, and internal hyphens, and has no trailing dot.
- IPv4 has exactly four decimal octets in `0..255`; leading zeroes are forbidden
  except for the value `0`.
- IPv6 is excluded from protocol v2.
- An optional port is decimal `1..65535` without a leading zero. Port `443` is
  omitted.

The path is empty or `/segment(/segment)*`. Segments are nonempty and contain
only RFC 3986 unreserved ASCII, sub-delimiters, `:`, and `@`. A trailing slash,
double slash, `.`/`..` segment, percent encoding, backslash, control/space,
query, fragment, userinfo, or non-ASCII byte fails closed. REST is exactly the
instance URL plus `/api`, still within 2,048 bytes.
`protocolvalue.ValidateApprovalURL` is the shared Go grammar authority;
`endpoint.ValidateApprovalURL` delegates to it for profile-facing callers.

Persisted profiles and journal plans continue to use the legacy service URL
grammar, including explicit `:443` and IPv6, so existing read and export paths
remain compatible. A new `mutation prepare` applies the narrower approval
grammar immediately after its locked profile read. An incompatible profile
fails with `MUTATION_PROFILE_INCOMPATIBLE` before policy, journal, credential,
network, randomness, or export side effects.

Plan IDs are `YTAP-` plus uppercase RFC 4648 Base32 without padding over
exactly 16 bytes. Decode/re-encode equality rejects unused nonzero final bits.
`intent.ValidatePlanID` is shared by preparation, journal lookup, and approval.

### Exact frame contract

One message is exactly one frame; EOF/truncation and every trailing byte fail.
The 16-byte header is:

| Offset | Width | Value |
| ---: | ---: | --- |
| 0 | 8 | raw ASCII `YTAPIPC\x00` |
| 8 | 1 | version `2` |
| 9 | 1 | kind: `1=request`, `2=success`, `3=error` |
| 10 | 2 | reserved big-endian zero |
| 12 | 4 | unsigned big-endian payload length |

The receiver validates the unsigned length against the selected kind before
payload allocation:

- request: 32 raw challenge bytes followed by 1..524,288 exact canonical plan
  bytes; payload is 33..524,320 bytes;
- success: echoed challenge, exact 91-byte P-256 DER SPKI, then 1..4,096
  canonical receipt bytes; payload is 124..4,219 bytes;
- error: exactly the challenge and one code byte, total 33 bytes.

The complete error vocabulary is `1=user_canceled`, `2=request_invalid`,
`3=user_presence_unavailable`, `4=key_unavailable`, `5=signing_failed`,
`6=internal_failure`. There is no error text or extension field.

The CLI creates a fresh opaque 32-byte CSPRNG challenge per request. Both
success and error responses echo it, Go compares it in constant time, and a
success receipt signs its lowercase SHA-256 as `challenge_sha256`.

### Cross-binding acceptance

Go accepts a success only after all of these checks succeed:

1. the challenge equals the outstanding request;
2. response SPKI exactly equals the previously enrolled expected SPKI, has the
   exact P-256 representation, and is on-curve;
3. the receipt strictly parses and byte-for-byte re-encodes canonically;
4. plan ID, SHA-256 of the exact displayed snapshot, profile identity,
   account, project ID/key, schema, request, and expected-state hashes match
   the validated snapshot;
5. receipt generation and fingerprint equal the enrolled key, and the signed
   challenge digest equals SHA-256 of the outstanding challenge;
6. timestamps use whole-second UTC, lifetime is positive and no more than five
   minutes, issue time is no more than 30 seconds in the future, and `now` is
   strictly before expiry;
7. the low-S strict DER ECDSA P-256 signature verifies over the exact
   `approval.SigningBytes` using only the enrolled expected key.

The future native factory uses an exact two-minute receipt lifetime. This is a
minting policy; the five-minute bound remains the verifier safety ceiling.

### Future connection and native key boundary

The later implementation uses helper-owned AF_UNIX connections and binds
identity to the accepted connection's `LOCAL_PEERTOKEN` audit token. Each side
resolves that token with `SecCodeCopyGuestWithAttributes` and checks a pinned
designated requirement. PID and filesystem path are diagnostics, never
authority. Replacement, exec, PID reuse, peer-token failure, timeout, crash,
EOF, malformed frames, and protocol disagreement fail before approval.

This boundary is grounded in Apple's published `LOCAL_PEERTOKEN` definition in
the [XNU `sys/un.h` header](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h),
the Security framework's [guest-attribute keys](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys),
and [`SecCodeCopyGuestWithAttributes`](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)).

The pinned production requirements are exact, not caller-configurable. Their
full Developer ID Application expressions and identifiers are frozen in the
[trust-root ADR](gate1a-trust-root.md#signed-bundle-and-identifiers).
They are only the coarse publisher/build predicate. Exact authority also
requires the offline-root-signed descriptor, provisional authorization, and
matching smoke or production-activation context, plus Security.framework
validity and a match between the running self and connection-bound peer
`kSecCodeInfoUnique` / `kSecCodeInfoCdHashes` values and the authorized
per-architecture set. Both peers exchange and agree on the descriptor digest
and canonical authorization-context digest before display or signing. A
descriptor-only, provisional-only, mixed provisional/grant, or smoke/active
context disagreement fails closed.

`TEAM_ID` and positive decimal `RELEASE_BUILD` are required immutable
operator-supplied build/Gate inputs with no repository defaults. Each peer
requirement pins the other's exact signed `CFBundleVersion` in addition to its
Team ID and identifier. The developer-only Gate runner has exact identifier
`io.github.abigotado.youtrack-agent.gate1a` under a separate Gate policy and
must never ship or be accepted by the production helper. Unset, wildcard,
non-decimal, and ad-hoc inputs fail closed.

The helper-only permanent key is P-256 Secure Enclave material stored through
the data-protection Keychain with `kSecAttrAccessControl`. A new `LAContext`
with zero reuse is present only in the exact signing-key lookup. The returned
`SecKey`, not the context, is used exactly once with `SecKeyCreateSignature`,
which has no context parameter; the context is invalidated on every lookup or
signature outcome. Separate
existence/delete queries carry no context and force authentication UI to fail.
Password-fallback versus `biometryCurrentSet` remains an
explicit operator-reviewed policy. PR A does not create this key or access any
Keychain item.

The key and presence policy follows Apple's first-party guidance for
[protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags),
[`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence),
and the `LAContext`
[`touchIDAuthenticationAllowableReuseDuration`](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration)
control. These sources justify the future design; PR A contains no live use of
those APIs.

The helper-private data-protection Keychain access group is
`$(AppIdentifierPrefix)io.github.abigotado.youtrack-agent.approval`; all item
operations explicitly use `kSecUseDataProtectionKeychain`. The outer app and
CLI are not entitled to that group and obtain bounded registry reads only from
the peer-authenticated helper. Every generation attempt appends a fresh random
128-bit lowercase-hex key ID to the tag prefix
`io.github.abigotado.youtrack-agent.approval.signing.v1/`; the registry binds
the exact tag, generation, SPKI, and fingerprint. The append-only versioned
registry uses service
`io.github.abigotado.youtrack-agent.approval.registry.v1` and immutable accounts
formed as `revision/` plus a 20-digit decimal revision.
The exact event records, proposal/acceptance transcript, final signing views,
state derivation, bounds, and vectors are frozen in the
[registry/ceremony protocol](gate1a-registry-protocol.md); no native
implementation may infer a different codec.
The helper entitlement requires compatible code signing and its own embedded
Developer ID provisioning profile. The helper owns the key and registry; its
ordinary registry-introspection API is read-only and bounded. Only the closed
ceremony and coordinator protocols below may mutate helper-private state or
issue a transport permit. Mutual peer identity and removal of arbitrary
write/enrollment surfaces remain mandatory.

The helper also owns the only write-capable transport permit. Every process
that could apply a mutation or commit a registry revision must acquire the one
fixed Keychain-backed coordinator `active` account through the sole per-user
launchd-managed helper server. One non-reentrant serialized authority executor
owns every coordinator call; its guard spans active acquisition through close
and exact read/delete cleanup, and after restart it spans recovery
classification through cleanup. The Keychain active record remains the
cross-client/restart lock. The
registry peer supplies a canonical intent digest before any ledger/proposal
work; the candidate is validated only after acquisition. The
same authenticated connection is fenced by audit token, runner/session where
applicable, lease ID, coordinator session, descriptor, final context, registry
revision, plan, and journal revision. Apply may receive one exact-request
permit only after durable `confirmed -> in_flight`; the helper retains the
coordinator across the one send/outcome and durable close. Registry ceremonies
use the same coordinator and cannot interleave. Restart never resumes a
permit: pre-permit state closes `failed_before_mutation`, while any post-permit
uncertainty closes ambiguous with no retry. The exact dictionaries, projections,
records, linearization points, and recovery rules live in the registry
protocol and are part of the Gate 1B conformance surface. That closed surface
includes invalid enrollment before ledger read, durable-outcome-before-close,
close-add ambiguity, post-close/pre-delete crash, active-delete ambiguity, and
an ABA schedule that queues acquisition between equality read and delete and
proves zero competing Keychain calls until the executor guard is released,
all driven by exact binary barrier schedules and event traces. Future failures
use the additive JSON v1 commands and distinct future exits 10..13 frozen
there; corruption remains existing exit 1 and no native status creates retry
authority.

Activation-smoke and post-grant sessions are not allowed to assume a registry
already exists. Their first compiled case derives a stage-token-bound setup
context that permits only one exact-artifact revision-1 enrollment after exact
bounded absence probes for the production registry and coordinator services,
signing-key namespace, journal root, and mutable runner state. The retained
generation/SPKI/fingerprint/descriptor/session snapshot binds every later
observation and evidence index. Final cleanup uses UI-fail/no-context queries
and the bounded filesystem probe to prove all five domains empty. It runs only
through the distinct root-token- and snapshot-bound `stage_cleanup` IPC after
the exact attributed records, helper-created tags, Security.framework
dictionaries, and delete order have been retained outside disposable state.
The helper holds the serialized executor, requires coordinator `active`
absent, exact-reads and byte-compares each item before its one delete, and
first requires a durable acknowledged `delete_attempt_started` marker. An
unresolved marker never permits another delete: absence reconciles terminally,
while presence or unknown state quarantines for manual repair.
Unknown/mismatched state is never deleted; expiry or uncertainty destroys the
quarantined disposable user/VM and invalidates the run. Setup and cleanup
contexts cannot sign, permit, send, or cross sessions.
Recovery is a separate trusted-UI handshake: a new exact-code CLI and helper
session validate the descriptor and retained evidence, while old audit-token/
session values are historical only. Its fence can classify/CAS, close, and
read-first clean a byte-equal active record, but cannot sign, acquire, permit,
send, or commit.

The helper validates its CMS profile and requires trusted current time to be
strictly before the descriptor-bound `helper_profile_expires_at` at ordinary launch,
peer acceptance, signing, coordinator acquisition, each registry proposal/final
signature, registry commit, permit issuance, and the last pre-send fence. No
existing connection, cached validation, Gate evidence, or already confirmed
receipt survives that cutoff. Only the exact launchd-managed recovery-only
launch and peer authentication may proceed after expiry, and only for status,
trusted-UI fencing, terminal journal CAS, close reconciliation, and
executor-guarded byte-equal active cleanup; it cannot enter ordinary auth,
sign, acquire, commit, permit, construct transport, or send.

Ordinary approval never enrolls. Enrollment has a distinct challenge and
proposal and activation domains, fresh trusted UI/user presence, peer
verification before and after the response, and an atomic helper-owned registry
commit. Its final key signature covers the live CLI-acceptance digest together
with the complete transition state. Rotation, revocation, recovery, retained
verification keys, downgrade behavior, and the CLI
`profile -> policy -> journal` lock order are defined by the
[trust-root ADR](gate1a-trust-root.md). Confirmation snapshots key revision and
generation before UI and revalidates them afterward.

## Consequences

- Go and Swift consume shared URL, ID, plan, receipt, key, signature, display,
  and frame fixtures; disagreement is a blocking failure.
- The binary format has no ambiguity from JSON envelopes, Unicode, optional
  fields, helper-supplied text, or integer byte order.
- The pure Go validator requires an explicit enrolled key generation, exact
  SPKI, and fingerprint; the response cannot select its own verification key.
- The implemented v2 receipt is pre-Gate evidence only. The signed candidate
  requires the protocol document's v3 registry-revision binding and rejects v2.
- `approval.Unsupported` remains the only production adapter. Gate 1A stays
  **NOT PASSED** until signed/notarized native execution, Secure Enclave
  isolation, peer validation, UI review, and clean-host lifecycle evidence all
  pass.
- Durable confirmation code may be completed while unwired, but remote write
  activation additionally waits for the packaged live Gate 1B integration.
  Gate 1A itself must exercise the ordinary production confirmation entry point
  in the exact signed candidate; a passing artifact is never rebuilt merely to
  change wiring.

## Rejected alternatives

- stdin/PTY/`--yes`: agent-controlled and not bound to immutable displayed
  bytes;
- HTTP callback or localhost service: larger origin, DNS, proxy, and browser
  attack surface;
- PID/path-only helper trust: vulnerable to replacement and PID reuse;
- JSON IPC: unnecessary duplicate-field, number, Unicode, and canonicalization
  surface around an already-canonical plan and receipt;
- arbitrary error strings: untrusted display/log injection surface;
- high-S ECDSA acceptance: permits a second wire representation of one
  signature;
- source-built or ad-hoc helper as Gate evidence: does not prove the production
  designated requirement, entitlements, notarization, or release boundary.
