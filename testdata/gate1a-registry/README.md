# Registry transcript core conformance corpus

**Partial prerequisite evidence only. Production registry implementation remains
blocked.** These test-only vectors do not activate approval, writes, a native
helper, or a release. The [registry protocol](../../docs/gate1a-registry-protocol.md)
is the normative source; this fixture container is not a new authority object.

## Scope

The core covers supplied request, recovery evidence when applicable, unsigned
and signed proposal, acceptance, final body, and stored-record bytes. It retains
domain-prefixed signing inputs, hashes, public SPKIs, signatures, predecessor
records, and explicit expected generation statuses.

The primary scenario is `enroll -> rotate -> revoke -> recover`: revisions 1,
2, 3, and 4. A separate scenario recovers from the active revision-2 state on
the declared missing-key basis. Its revision 3 is an alternative history, not
a fork accepted into the primary ledger. Key uniqueness is enforced within a
history, not across independent fixture scenarios.

Three evidence levels must not be confused:

1. A complete supplied core transcript can establish consistency among its
   canonical bytes, digests, signatures, tuples, times, and resulting state.
2. Stored-record replay verifies signed declarations, predecessor linkage and
   state under the protocol's protected-helper assumptions. Stored records do
   not retain full requests, proposals, acceptances or recovery evidence; their
   digests do not reconstruct those missing objects.
3. Neither test proves actual Keychain absence, trusted user presence, live peer
   authentication, Secure Enclave use, coordinator ownership or quiescence.
   A signed synthetic missing-item declaration is not a native lookup result.

All times are synthetic historical transcript times. Passing these tests cannot
make an expired transcript live or grant a new confirmation/send capability.

## Reproducibility and independent checks

`generate.go` is a build-ignored test-data generator. Its public fixture scalars
and deterministic signing nonces are deliberately unsafe for real signing.
They are not credentials or an enrolled authorization root. Never use them for
production signatures. The generator imports neither registry parsers nor the
test consumers; generated results are not themselves an oracle.

From the repository root:

```sh
go run ./testdata/gate1a-registry/generate.go
go run ./testdata/gate1a-registry/generate.go -check
go test ./internal/approval -run 'TestSharedRegistry'
swift test --package-path native/macos/ApprovalProtocol --filter 'sharedRegistry'
```

Go and Swift independently validate the protocol schemas and recompute exact
signing inputs and digests, using their existing strict P-256 primitives. They
pin the required scenarios and expected states independently of generated
metadata. Domain NUL bytes are preserved in hexadecimal signing-input fields.
The predecessor digest is plain SHA-256 of the exact prior complete record,
not the domain-separated commit-candidate digest.
In each positive manifest, `predecessor_digest` hashes that positive's own
complete record, ready for use as the next record's predecessor value.

The fixture container uses JSON strings for exact embedded object bytes and
has a source-control final LF. Embedded protocol objects have no added LF,
whitespace or escaping. Container arrays and metadata are not protocol fields.

Negatives carry a literal `reason_class` checked identically by both languages:
`canonical_encoding`, `bounds_grammar`, `digest_domain`, `signature`, `temporal`,
`recovery_eligibility`, or `state_transition`. These are test-only categories,
not public CLI errors or exit codes. Negative transcripts must differ from
their named base. Later semantic faults are re-signed and have dependent hashes
recomputed so an earlier accidental signature/digest failure cannot satisfy a
state-transition expectation. Positive manifest comparisons are separate from
negative validation; stale baseline manifest metadata is not a rejection oracle.
All raw caps and canonical/primitive checks run before cryptographic work.
The complete supplied prefix is then validated before the candidate's digest,
signature, temporal, recovery-eligibility and state checks. After prefix
validation, a recovery candidate must supply recovery evidence before candidate
digest checks begin. Only presence is checked at this stage; evidence contents
are checked after signatures and time. Thus missing evidence plus a bad candidate
digest reports `recovery_eligibility`, while an invalid prefix still wins.
A recovery candidate
cannot repair an invalid prefix. Composite faults must not imply a universal
cross-prefix/candidate error priority that the corpus does not test.

OSStatus vectors describe canonical signed-int32 parsing and exact re-encoding,
including numeric absence `-25300`. Their fixture-consistency tests use test-only
reference parsers and independently pinned raw-value sets. There is no production
OSStatus parser here: these tests cannot catch defects in a future implementation
until the vectors are wired to that implementation. They do not classify arbitrary
statuses as success or satisfy the coordinator-result classification requirement.

## Remaining prerequisite inventory

| Surface | Status |
| --- | --- |
| Core transcript bytes, signatures, hashes, history and state | This corpus; synthetic data only |
| OSStatus scalar grammar | Fixture consistency only; no production parser coverage or native status classification |
| Registry intent and intent/request/coordinator binding | Pending; [state derivation](../../docs/gate1a-registry-protocol.md#state-derivation) |
| Commit authorization and ambiguous-result reconciliation | Pending; [commit contract](../../docs/gate1a-registry-protocol.md#commit-and-ambiguous-result-reconciliation) |
| Typed Security.framework dictionaries/results and persistent-reference provenance | Pending; [native projections](../../docs/gate1a-registry-protocol.md#exact-securityframework-dictionaries-and-projections) |
| Coordinator acquisition, exclusion, quiescence, quarantine, cleanup and classification | Pending; [coordinator contract](../../docs/gate1a-registry-protocol.md#helper-owned-apply-authority-coordinator) |
| Native anti-replay/capacity schedules and signed execution evidence | Pending; [conformance requirements](../../docs/gate1a-registry-protocol.md#cross-language-conformance-evidence) |

This directory does **not** satisfy the complete conformance prerequisite.
Production registry codecs/replay, closed authority-evidence verification,
journal v2/durable confirmation, protected native integration, guarded-write
Gates and distribution remain separate work. `approval.Unsupported`, journal
v1, production package dependencies and the CLI contract are unchanged.

## Native signature compatibility regression

On macOS 26.6.2 / Apple Swift 6.3.3, direct CryptoKit verification rejects the
final new-key signature in `recovery-continuity-success` before the intended
`recovery_eligibility` check. The public verifier now handles this observed
representation-dependent incompatibility, and all 121 core negative vectors
reach their expected rejection classes in both consumers.

Standalone verification outside either test consumer reproduced the disagreement:

| Verifier on the same exact message, public key and DER signature | Result |
| --- | --- |
| Go 1.27.1 `ecdsa.VerifyASN1` | Valid |
| Node / OpenSSL 3.0.16 `crypto.verify` | Valid |
| CryptoKit, both message and SHA-256 digest overloads | Invalid |
| Ruby / system LibreSSL 3.3.6 | Verification error |

The domain-prefixed message is 1,855 bytes and its SHA-256 is
`953be2f28a5e846a47fff27d61cc0514fedb34e7888d1536adea8172974c9ec5`.
CryptoKit's decoded signature scalars match the DER bytes, and its public key
matches the synthetic scalar-3 public key. A fresh CryptoKit signature on that
message verifies. These observations localize an interoperability disagreement;
they do not establish a root cause or a general platform vulnerability.

The same CryptoKit key/message accepts the mathematically equivalent `(r, N-s)`
signature. The public verifier first validates the original strict low-S DER,
then verifies it normally. Only a false result permits one verification of an
ephemeral equivalent representation with the same backend, key and message.
Negating the ECDSA verification point preserves its x-coordinate. The twin is
internal only: it is never accepted as a wire `P256Signature`, stored, returned,
or granted authority. If CryptoKit cannot construct only the alternate signature
after the original verification returned false, the result stays false. Original
input/key construction and internal DER invariant errors retain their closed
error behavior and do not trigger another attempt.

The fixed public scalars and nonce deliberately preserve the known valid-signature
regression. Changing the nonce can avoid this input, but does not repair native
verification of the original signature. Sampling other keys/nonces with no
failures does not prove impossibility for all such keys. The compatibility path
has a fixed ceiling of two verifications even on a non-matching signature.

The original fixture and strict expected reason remain intact. Dedicated
public-API tests pin the exact message hash, key and signature, reject high-S
ingress through both parser and verifier, and reject changed message/key/r/s.
They assert correctness rather than requiring the native defect to persist on
future operating systems. No backend fallback, skipped test, or weakened reason
assertion is used. This compatibility correction does not complete the remaining
production prerequisites above.
