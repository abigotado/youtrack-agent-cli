# Gate 1A approval-registry protocol

Status: normative design for Gate 1A; not implemented and not production
enabled. This document freezes the helper-private approval-key ledger and the
four authority ceremonies. It does not make `approval.Unsupported` usable.

The [trust-root ADR](gate1a-trust-root.md) owns the Keychain access group,
service, account naming, peer code requirements, and release boundary. This
document owns every authority-bearing byte stored under that service. The
[artifact-authorization contract](gate1a-artifact-authorization.md) owns the
`artifact_descriptor_sha256` value used below.

## Security properties and non-properties

The registry is a bounded, append-only, event-sourced ledger. A valid ledger
proves an unbroken sequence of locally authorized transitions from enrollment
to the current state. A transition is usable only when its complete canonical
record, predecessor, transcript digests, signatures, and state transition all
validate.

The CLI acceptance is not a CLI signature and is not durable independent
evidence of user intent. It is a digest-bound message on the live IPC
connection after both peers have authenticated the connection-bound audit
token. The helper repeats peer authentication immediately before the one-shot
Keychain add. The final old/new Secure Enclave signatures make the accepted
transcript and resulting state durable.

The ledger does not detect restoration of an older, internally complete
ledger snapshot by an administrator, Keychain compromise, or backup service.
That requires an external monotonic high-water mark and remains outside the
first release.

## Primitive encodings

All authority objects are compact UTF-8 JSON objects. They contain no leading
or trailing bytes and no insignificant whitespace. Fields occur in the exact
order listed in this document. Decoders reject duplicate, missing, unknown, or
out-of-order fields; a non-object top level; alternate number, string, or null
encodings; and trailing data. After validation, the decoder re-encodes the
value and requires byte-for-byte equality with the input.

All string values are printable ASCII and contain no JSON escape. JSON
integers are base-10 digits with no sign and no leading zero, except the value
zero itself. Nullable fields are exactly JSON `null`, never an empty string.
Booleans are exactly `true` or `false`. There are no arrays or nested objects
in an authority object.

The common grammar is:

| Name | Exact encoding |
| --- | --- |
| `schema_version` | JSON integer `1` |
| transition | one of `enroll`, `rotate`, `revoke`, `recover` |
| revision | JSON integer `0..256`; stored records use `1..256` |
| digest | 64 lowercase hexadecimal characters |
| empty predecessor | 64 ASCII `0` characters |
| challenge | unpadded RFC 4648 base64url of exactly 32 bytes; 43 characters; decode/re-encode equality required |
| time | UTC RFC 3339 whole seconds, `YYYY-MM-DDTHH:MM:SSZ` |
| key generation | `YTAG-` followed by a 20-digit positive revision; it equals the revision that introduced the key |
| key ID | 32 lowercase hexadecimal characters encoding 128 random bits |
| key tag | `io.github.abigotado.youtrack-agent.approval.signing.v1/` followed by the key ID |
| SPKI | unpadded base64url of the exact 91-byte P-256 DER SubjectPublicKeyInfo; 122 characters |
| SPKI fingerprint | lowercase SHA-256 of those 91 bytes |
| key status | one of `active`, `retained`, `revoked` |
| signature | unpadded base64url of a strict low-S DER ECDSA P-256 signature; at most 96 characters |

The P-256 SPKI and signature rules are exactly those in
[Gate 1A approval protocol](gate1a-protocol.md#signature-and-public-key).
Every decoded public point must be on P-256. Each `(key_generation, key_id,
key_tag, spki, fingerprint)` tuple is internally consistent and unique across
the whole ledger. No generation, key ID, tag, SPKI, or fingerprint may ever be
reused, including after revocation.

The raw-byte caps are checked before parsing, allocation proportional to input,
base64url decoding, signature verification, or display:

| Object | Maximum bytes |
| --- | ---: |
| request | 2,048 |
| signed proposal | 4,096 |
| acceptance | 2,048 |
| final record body | 4,096 |
| complete stored record | 4,352 |
| commit authorization or reconciliation request | 6,144 |
| one Keychain registry item, including metadata returned by Security.framework | 8,192 |
| complete ledger records | 256 |
| aggregate canonical stored-record bytes | 1,114,112 |
| aggregate bytes returned by the bounded Keychain query | 2,097,152 |

The canonical-record aggregate bound is exactly `256 * 4,352`. More than 256
matching items, an item over its bound, either aggregate over its bound, or
Security.framework returning a value of an unexpected type fails before
sorting or cryptographic work.

## Domains and hashes

Domain strings below are ASCII including the final NUL byte. Concatenation has
no length prefix because the left operand has fixed bytes and the right operand
is one complete canonical JSON object.

| Purpose | Domain |
| --- | --- |
| request digest | `YTA-REGISTRY-REQUEST-V1\0` |
| proposal signature | `YTA-REGISTRY-PROPOSAL-V1\0` |
| proposal digest | `YTA-REGISTRY-PROPOSAL-DIGEST-V1\0` |
| acceptance digest | `YTA-REGISTRY-ACCEPTANCE-V1\0` |
| recovery evidence digest | `YTA-REGISTRY-RECOVERY-EVIDENCE-V1\0` |
| recovery continuity probe | `YTA-REGISTRY-RECOVERY-CONTINUITY-PROBE-V1\0` |
| old-key final signature | `YTA-REGISTRY-RECORD-OLD-V1\0` |
| new-key final signature | `YTA-REGISTRY-RECORD-NEW-V1\0` |
| commit-candidate digest | `YTA-REGISTRY-COMMIT-V1\0` |

`request_sha256`, `proposal_sha256`, `acceptance_sha256`, and
`recovery_evidence_sha256` are lowercase SHA-256 over their respective domain
followed by the complete canonical object. The proposal digest includes its
`proposal_signature`. The record
digest used by commit authorization is SHA-256 over the commit domain followed
by the complete stored record.

`previous_record_sha256` is deliberately different: it is lowercase SHA-256
over the exact complete prior stored-record bytes, with no domain prefix. The
first record uses the empty-predecessor value. No decoded/reconstructed form
may substitute for those exact prior bytes.

## Ceremony request

The CLI produces one request with these fields in order:

1. `schema_version`
2. `message_type`, exactly `registry_request`
3. `transition_kind`
4. `recovery_mode`, null for other transitions or exactly
   `missing_key_item_or_disabled_registry` for recovery
5. `challenge`
6. `expected_registry_revision`
7. `previous_record_sha256`
8. `artifact_descriptor_sha256`
9. `target_generation`
10. `new_generation`
11. `requested_at`
12. `expires_at`

The challenge is freshly generated for every attempt. `expires_at` is strictly
after `requested_at` and at most five minutes later. Both peers reject a
request outside that closed clock window; tolerated clock skew is at most 30
seconds and never extends `expires_at`.

The exact transition-specific values are:

| Transition | Expected revision | Target generation | New generation |
| --- | ---: | --- | --- |
| enrollment | `0` | `null` | generation for revision 1 |
| rotation | current | current active generation | generation for current + 1 |
| revocation | current | current active generation | `null` |
| recovery | current | current active generation, or `null` when no active key exists | generation for current + 1 |

The previous digest is empty only for enrollment. Otherwise it equals the
SHA-256 of the complete current record. The artifact-descriptor digest equals
the currently authorized exact-artifact descriptor and may not change during
a ceremony.

### Recovery eligibility evidence

Recovery never means “the old signature was inconvenient.” It is eligible only
when the complete existing ledger is valid and either it has no active
generation after an explicit revocation, or the exact active private-key item
is absent from the helper-private Keychain namespace.

For an active generation, after trusted UI and fresh user authentication, the
helper performs exactly one `SecItemCopyMatching` for the ledger's exact active
tag, access group, data-protection Keychain, and private-key class. Only
`errSecItemNotFound` (OSStatus `-25300`) establishes absence. If a key reference
is returned, the helper performs exactly one continuity probe signature over
the recovery-continuity-probe domain followed by the exact request bytes, using
the same fresh zero-reuse `LAContext`:

- a valid signature proves continuity is available, ends recovery with
  `RECOVERY_CONTINUITY_AVAILABLE`, discards the probe, and directs the operator
  to rotation or revocation with a new challenge;
- cancellation, authentication failure, interaction-not-allowed, key-use
  failure, transient/unavailable status, malformed result, or any other error
  ends with `RECOVERY_ELIGIBILITY_UNPROVEN`; and
- none of those errors is reclassified as key loss or retried automatically.

If lookup returns any status other than success with one exact key reference or
`errSecItemNotFound`, recovery fails with
`RECOVERY_ELIGIBILITY_UNPROVEN`. A disabled valid ledger performs no key query.

An eligible helper constructs this canonical evidence object:

1. `schema_version`
2. `message_type`, exactly `registry_recovery_evidence`
3. `request_sha256`
4. `challenge_sha256`
5. `registry_revision`
6. `previous_record_sha256`
7. `artifact_descriptor_sha256`
8. `target_generation`
9. `target_key_tag`
10. `eligibility`, `active_key_item_not_found` or `registry_disabled`
11. `key_lookup_result`, exactly `errSecItemNotFound:-25300` for the former or
    `not_attempted:registry_disabled` for the latter
12. `continuity_probe_result`, exactly `not_attempted:no_key` or
    `not_attempted:no_active_generation`, respectively
13. `probed_at`

Active-key fields are exact non-null ledger values for
`active_key_item_not_found` and null for `registry_disabled`. The object is
capped at 2,048 bytes. Its domain-separated digest is inserted into every later
recovery message and the final signed record. It is null for every other
transition. Trusted UI displays the eligibility, target generation/fingerprint
when present, and the fact that recovery revokes all prior generations before
the CLI can accept the proposal.

## Signed proposal

After peer validation, ledger validation, trusted UI, and fresh user presence,
the helper returns a proposal. Its unsigned form contains these fields in
order:

1. `schema_version`
2. `message_type`, exactly `registry_proposal`
3. `transition_kind`
4. `request_sha256`
5. `challenge_sha256`
6. `registry_revision`
7. `previous_record_sha256`
8. `artifact_descriptor_sha256`
9. `recovery_evidence_sha256`
10. `target_generation`
11. `target_key_id`
12. `target_key_tag`
13. `target_spki`
14. `target_fingerprint_sha256`
15. `new_generation`
16. `new_key_id`
17. `new_key_tag`
18. `new_spki`
19. `new_fingerprint_sha256`
20. `proposed_at`
21. `expires_at`
22. `proposal_signer_role`

The signed proposal appends `proposal_signature` as field 23. It signs the
proposal domain followed by the exact unsigned proposal bytes.
`challenge_sha256` is SHA-256 over the decoded 32-byte challenge.

Target fields are all non-null for rotation, revocation, and recovery when an
active target exists, and are all null otherwise. New-key fields are all
non-null for enrollment, rotation, and recovery, and all null for revocation.
Partial tuples are invalid. `recovery_evidence_sha256` is required only for
recovery and must match the exact eligible object above; it is null otherwise.
`registry_revision` is the proposed new revision.
The proposal repeats the request expiry; `proposed_at` is not before
`requested_at` and is before expiry.

For enrollment, rotation, and recovery, `proposal_signer_role` is `new` and
the proposed new key signs. For revocation it is `old` and the current active
key signs. Proposal signing uses a fresh zero-reuse authorization context. A
failed signature attempt ends the ceremony; it is not silently retried.

## CLI acceptance

The CLI revalidates the helper on the same connection, parses the proposal,
checks the request digest, challenge, artifact descriptor, revision,
predecessor, all key
bindings, time window, and proposal signature, and then sends this exact
canonical object:

1. `schema_version`
2. `message_type`, exactly `registry_acceptance`
3. `transition_kind`
4. `request_sha256`
5. `proposal_sha256`
6. `challenge_sha256`
7. `registry_revision`
8. `previous_record_sha256`
9. `artifact_descriptor_sha256`
10. `recovery_evidence_sha256`
11. `target_generation`
12. `new_generation`
13. `accepted_at`
14. `expires_at`
15. `accepted`, exactly `true`

`accepted_at` is not before `proposed_at` and is before expiry. An acceptance
received on another connection, after audit-token identity changes, or after
any reauthentication failure is invalid even if its bytes are otherwise
canonical. It conveys no authority outside that authenticated live transcript.

## Final body and stored record

The helper reauthenticates the live CLI, rereads and validates the entire
ledger, and constructs a final body with these fields in order:

1. `schema_version`
2. `record_type`, exactly `approval_registry_transition`
3. `transition_kind`
4. `registry_revision`
5. `previous_record_sha256`
6. `request_sha256`
7. `proposal_sha256`
8. `acceptance_sha256`
9. `challenge_sha256`
10. `artifact_descriptor_sha256`
11. `recovery_evidence_sha256`
12. `requested_at`
13. `accepted_at`
14. `committed_at`
15. `target_generation`
16. `target_key_id`
17. `target_key_tag`
18. `target_spki`
19. `target_fingerprint_sha256`
20. `target_previous_status`
21. `target_new_status`
22. `new_generation`
23. `new_key_id`
24. `new_key_tag`
25. `new_spki`
26. `new_fingerprint_sha256`
27. `new_status`
28. `revokes_all_prior`

The complete stored record appends these fields:

29. `old_signature`
30. `new_signature`

Each non-null signature covers its role-specific record domain followed by the
exact final-body bytes, so both signatures bind the acceptance digest and
every resulting state field. Signatures are produced once; their exact bytes
are retained through commit and reconciliation.

`recovery_evidence_sha256` is the verified eligibility-object digest for
recovery and null for every other transition. Consequently the new-key recovery
signature durably binds the missing-item or disabled-registry basis, the live
CLI acceptance, and the revoke-all result.

The only legal field combinations are:

| Transition | Target status change | New status | Revoke all prior | Old signature | New signature |
| --- | --- | --- | --- | --- | --- |
| enrollment | all target fields `null` | `active` | `false` | `null` | required |
| rotation | `active` to `retained` | `active` | `false` | required | required |
| revocation | `active` to `revoked` | all new fields `null` | `false` | required | `null` |
| recovery | active target to `revoked`, or all target fields `null` | `active` | `true` | `null` | required |

Enrollment is legal only for an empty ledger. Rotation and revocation require
the target tuple to equal the current active entry. Recovery is legal only
after the exact eligibility procedure succeeds; it may name the current active
tuple for display, but it has no old signature. A returned current key, a
successful continuity probe, or any lookup/auth/sign result other than the
exact eligible states above forbids recovery. A reachable old key must use
rotation or revocation with a fresh challenge.

`committed_at` is not before acceptance and is before expiry. The helper must
not alter a proposal tuple while producing the final record. All inapplicable
fields are literal null.

## State derivation

Consumers always replay all records from revision 1. They never trust a cached
snapshot without replaying and byte-comparing the underlying ledger.

The derived state maps every introduced generation to exactly one status and
holds zero or one active generation:

- enrollment introduces one active generation;
- rotation changes the one active generation to retained and introduces a new
  active generation;
- revocation changes the one active generation to revoked and leaves no active
  generation;
- recovery changes every previously active or retained generation to revoked
  and introduces one new active generation.

Revoked is terminal. Retained keys verify historical receipts only. Only the
single current active generation may authorize a new receipt, and the receipt
must carry the current registry revision. Every transition cancels all
outstanding confirmed plans, including a transition that does not change a
receipt's referenced public key.

A valid ledger has exactly one item for every revision from 1 through its
maximum, no other matching account, an empty predecessor only at revision 1,
and an exact predecessor hash thereafter. Every event must be legal for the
state derived immediately before it. Recovery is never allowed to bypass a
gap, fork, malformed predecessor, bad signature, or invalid prior event.

## Commit and ambiguous-result reconciliation

Before mutation, the helper sends the complete candidate stored-record bytes
to the CLI. The CLI validates them and retains them durably for this ceremony.
It then sends a compact commit authorization with these fields in order:

1. `schema_version`
2. `message_type`, exactly `registry_commit`
3. `transition_kind`
4. `registry_revision`
5. `record_sha256`
6. `authorized_at`
7. `expires_at`

`record_sha256` uses the commit-candidate digest domain. This authorization is
also connection-bound, not a signature. The helper revalidates the peer,
record digest, expiry, exact current chain, expected revision, and predecessor;
then it performs exactly one `SecItemAdd` for account `revision/%020d` in the
fixed service and access group. It never calls `SecItemUpdate`, never retries
the add, and never deletes a registry revision.

After success, error, cancellation, or a crash-ambiguous response, the only
permitted reconciliation is one exact-account read. On a reconnect the CLI
supplies the retained candidate bytes in this canonical object:

1. `schema_version`
2. `message_type`, exactly `registry_reconcile`
3. `transition_kind`
4. `registry_revision`
5. `record_sha256`
6. `record_base64url`

`record_base64url` is unpadded base64url of the complete candidate and is
bounded by the reconciliation-request cap. The helper decodes/re-encodes it,
validates the complete candidate and all signatures against the preceding
ledger, and confirms its commit digest before reading Keychain once.

- exact stored bytes equal to the candidate mean committed success;
- absence means uncommitted failure and the ceremony ends;
- any different bytes, malformed item, duplicate result, or read ambiguity is
  a conflict and fails closed.

No result authorizes generating new signatures, repeating `SecItemAdd`, or
implicitly starting another ceremony. A new operator action must use a fresh
challenge and, if the prior candidate is absent, a new key ID for every
key-creating transition.

## Cross-language conformance evidence

Implementation is blocked until one shared fixture directory contains Go- and
Swift-consumed vectors for each transition. Each positive vector includes
request, signed proposal, acceptance, final body, complete record, every
domain-prefixed signing input, every digest, predecessor chain, DER SPKIs, and
strict low-S signatures. At least one vector must form a multi-event chain
`enroll -> rotate -> revoke -> recover` and derive the exact final state.
Another positive vector covers recovery from an active valid ledger after the
exact `errSecItemNotFound:-25300` result.

Negative vectors must independently cover:

- every raw and aggregate size boundary, revision 0/257, 256/257 records, and
  overlong base64url before allocation;
- missing, duplicate, unknown, reordered, escaped, whitespace-modified, or
  trailing JSON; noncanonical integer, null, time, base64url, DER, SPKI, point,
  low-S, and digest encodings;
- request/proposal/acceptance splice, wrong signature domain or signer role,
  expired transcript, audit-token change, and artifact-descriptor change;
- recovery while active-key lookup succeeds, continuity-probe success, user
  cancellation, authentication failure, interaction-not-allowed,
  unavailable/transient/unknown OSStatus, missing or substituted recovery
  evidence, and recovery over a malformed/forked/gapped ledger;
- partial key tuples, tuple mismatch, reused generation/key ID/tag/SPKI,
  invalid generation-to-revision binding, and proposal-to-record substitution;
- missing revision, gap, duplicate account, fork, predecessor mismatch,
  invalid status transition, second enrollment, rotation/revocation of a
  non-active key, revoked-key resurrection, and recovery over any invalid
  prefix;
- duplicate-item races, exact-winner reconciliation, different-winner
  conflict, absent ambiguous add, read ambiguity, and any attempted automatic
  add retry.

Go and Swift must parse and re-encode every positive byte identically and
reject every negative vector with the same stable reason class. Gate 1A runs
both implementations against the same immutable fixture hashes.

## Evidence

- Apple documents that Keychain duplicate detection uses an item's composite
  primary key in [`errSecDuplicateItem`](https://developer.apple.com/documentation/security/errsecduplicateitem).
- Apple documents private key generation through
  [Generating new cryptographic keys](https://developer.apple.com/documentation/security/generating-new-cryptographic-keys)
  and Secure Enclave protection in
  [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).
- The private access-group boundary follows
  [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps).
