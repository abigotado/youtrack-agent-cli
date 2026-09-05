# Gate 1A approval-registry protocol

Status: normative design for Gate 1A; not implemented and not production
enabled. This document freezes the helper-private approval-key ledger and the
four authority ceremonies plus the distinct release-stage cleanup authority.
It does not make `approval.Unsupported` usable.

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
Booleans are exactly `true` or `false`. Core registry and coordinator authority
objects have no arrays or nested objects. The separately named stage-cleanup
intent, progress, ACK-ledger, and evidence objects are bounded artifact containers and use
only the exact ordered arrays/entries defined in their section; this exception
does not widen any core object.

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
| stage-cleanup IPC request | 1,048,576 |
| stage-cleanup IPC result | 131,072 |
| stage-cleanup context | 4,096 |
| stage-cleanup intent | 262,144 |
| stage-cleanup progress or evidence | 65,536 |
| stage-cleanup delete-attempt or operation-result object | 65,536 |
| stage-cleanup ACK-ledger entry | 8,192 |
| stage-cleanup ACK-ledger container | 131,072 |
| stage-cleanup retained namespace aggregate bytes | 2,097,152 |
| one Keychain registry item, including metadata returned by Security.framework | 8,192 |
| one coordinator active, permit, or closed item, including metadata | 8,192 |
| complete ledger records | 256 |
| aggregate canonical stored-record bytes | 1,114,112 |
| aggregate bytes returned by the bounded Keychain query | 2,097,152 |
| coordinator permit records | 256 |
| coordinator closed records | 256 |

The canonical-record aggregate bound is exactly `256 * 4,352`. More than 256
matching items, an item over its bound, either aggregate over its bound, or
Security.framework returning a value of an unexpected type fails before
sorting or cryptographic work.

## Exact Security.framework dictionaries and projections

Every Keychain call below is constructed by the helper from constants and
already validated canonical values. The CLI never supplies a dictionary key,
class, service, access group, match limit, return flag, synchronizable flag, or
accessibility value. A dictionary with a missing, additional, differently
typed, or differently valued entry is a protocol error before the call. All
CFString-to-data conversions below are exact UTF-8 over the already validated
printable-ASCII value, with no NUL or normalization.

The resolved private access group is the one exact value authorized by the
embedded profile and helper entitlement. `SecAccessControlCreateWithFlags`
uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and exactly
`.privateKeyUsage` plus the separately frozen `userPresence` or
`biometryCurrentSet` choice. No second accessibility or authentication policy
is tried.

The `SecKeyCreateRandomKey` attributes are exactly:

| Key | Value |
| --- | --- |
| `kSecAttrKeyType` | `kSecAttrKeyTypeECSECPrimeRandom` |
| `kSecAttrKeySizeInBits` | CFNumber integer `256` |
| `kSecAttrTokenID` | `kSecAttrTokenIDSecureEnclave` |
| `kSecUseDataProtectionKeychain` | `kCFBooleanTrue` |
| `kSecPrivateKeyAttrs` | the exact nested dictionary below |

The private-key dictionary contains exactly
`kSecAttrIsPermanent=true`, `kSecAttrApplicationTag` as CFData of the complete
key tag, `kSecAttrAccessGroup` as the resolved group, and
`kSecAttrAccessControl` as the successfully created access-control object.
Key creation must return one `SecKey` whose copied public key, 91-byte SPKI,
application tag, key type, size, token, and access group all match the proposal
before it can be used.

Signing and existence are different Keychain operations and never share a
query. An exact signing private-key lookup dictionary contains, in this order
in the protocol projection: `kSecClass=kSecClassKey`,
`kSecAttrKeyType=kSecAttrKeyTypeECSECPrimeRandom`,
`kSecAttrApplicationTag` as the exact tag CFData, `kSecAttrAccessGroup`,
`kSecUseDataProtectionKeychain=true`, `kSecMatchLimit=kSecMatchLimitOne`,
`kSecUseAuthenticationContext` as one newly created `LAContext` whose reuse
duration is zero, `kSecUseAuthenticationUI=kSecUseAuthenticationUIAllow`, and
`kSecReturnRef=true`. The context is an input only to that `SecItemCopyMatching`
lookup; `SecKeyCreateSignature` has no authentication-context parameter. On
successful lookup, the returned `SecKey` is passed to exactly one immediately
following `SecKeyCreateSignature`. The context is never reused for a lookup or
treated as a signing argument and is invalidated after lookup/signature success,
cancellation, or every other failure. Success must project to exactly one
`SecKey`; an array, dictionary, data value, or other CFType is malformed. No
retry, context replacement, or UI-policy fallback is allowed.

The noninteractive private-key existence dictionary contains exactly the same
class, key type, exact application tag, access group, data-protection flag, and
match-one entries, followed by
`kSecUseAuthenticationUI=kSecUseAuthenticationUIFail` and
`kSecReturnRef=true`; it contains no `LAContext`. Success projects to exactly
one typed `SecKey` and proves only presence, never signing authority.
`errSecItemNotFound:-25300` proves absence. Interaction-not-allowed, auth
failure, cancellation, wrong CFType, or every other status is neither presence
nor absence and fails closed. The exact orphan-key delete dictionary below also
includes `kSecUseAuthenticationUIFail` and no `LAContext`, so cleanup cannot
summon or inherit authentication UI. No label, generic tag, account, or caller
predicate is added to either lookup.

The bounded private-key enumeration dictionary contains exactly
`kSecClass=kSecClassKey`, `kSecAttrKeyType=kSecAttrKeyTypeECSECPrimeRandom`,
`kSecAttrAccessGroup`, `kSecUseDataProtectionKeychain=true`,
`kSecMatchLimit=kSecMatchLimitAll`, and `kSecReturnAttributes=true`. Because
Keychain has no trusted prefix-match operator, the helper caps the returned
array at 64 before allocation proportional to its count, then projects each
dictionary to application-tag CFData, key type, integer key size, token ID,
access group, permanent flag, and synchronizable flag. The tag must decode to
the fixed prefix plus one canonical key ID; type, size, token, group, permanent
and synchronizable values must respectively be EC P-256, Secure Enclave, the
resolved group, true, and false. A non-array success, non-dictionary member,
duplicate tag, missing projected value, wrong CFType, unexpected item in this
private group, or result beyond the bound fails closed. Other OS-returned
diagnostic attributes are neither serialized nor used as authority.

Every registry or coordinator value is stored as a generic-password item.
The exact add dictionary contains `kSecClass=kSecClassGenericPassword`,
`kSecAttrService`, `kSecAttrAccount`, `kSecAttrAccessGroup`,
`kSecAttrAccessible=kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
`kSecAttrSynchronizable=false`, `kSecUseDataProtectionKeychain=true`, and
`kSecValueData` as the complete canonical bytes. Registry items use the fixed
registry service and revision account. Coordinator items use the service and
accounts defined below. `SecItemAdd` receives no return flag.

The exact-account read dictionary contains `kSecClassGenericPassword`, exact
service, exact account, resolved access group, `kSecAttrSynchronizable=false`,
`kSecUseDataProtectionKeychain=true`, `kSecMatchLimitOne`,
`kSecReturnAttributes=true`, and `kSecReturnData=true`. Success must be one
dictionary whose projection contains exactly service CFString, account
CFString, access-group CFString, accessibility CFString, synchronizable
CFBoolean, creation/modification CFDates, and value CFData. The first five
must equal the query and fixed policy; both dates must be valid and modification
must not precede creation; value and total projected metadata must respect the
item bound. Authority uses only the exact value bytes. An array, duplicate,
wrong CFType/value, or missing projection field is ambiguous and fails closed.

The bounded service enumeration dictionary is the same except it omits
account and uses `kSecMatchLimitAll`. A success result must be an array of
1..256 dictionaries for the registry or at most one active plus 256 permit and
256 closed dictionaries for the coordinator. The aggregate raw/projection
bound is 2,097,152 bytes. Projection occurs before sorting; accounts are then
validated and sorted by canonical revision or record kind/lease ID. A bare
dictionary for match-all, duplicate account, unknown account, unexpected
value, or `errSecSuccess` with an empty collection is malformed. Only
`errSecItemNotFound` represents an empty service.

The coordinator's final pre-send state probe is exactly three sequential
exact-account reads with the dictionary above: `active` must return bytes equal
to the acquired active record, `permit/<lease-id>` must return bytes equal to
the one permit, and `closed/<lease-id>` must return only
`errSecItemNotFound:-25300`. No match-all query, cached result, combined
predicate, reordered call, or extra read can replace this probe. The helper
then repeats peer audit-token/session and profile-expiry checks without
releasing the coordinator; any mismatch or noncanonical result prevents send.

Registry revision and coordinator permit/closed deletion are forbidden outside
the exact stage-cleanup authority below and have no ordinary-flow dictionary.
The following exact private-key deletion dictionary is usable only in a
disjoint Gate fixture namespace or through the signed smoke/post-grant
stage-cleanup authority. It supplies no ordinary production orphan/retired-key
maintenance operation. Ordinary production retains such keys and reports
unresolved state without deleting them. The dictionary uses only
`kSecClassKey`, EC key type, exact application
tag CFData, key size 256, Secure Enclave token ID, resolved access group, and
the data-protection-Keychain flag plus
`kSecUseAuthenticationUI=kSecUseAuthenticationUIFail`; it contains no
authentication context. Its ambiguous result is reconciled by exactly one
private-key lookup using the exact noninteractive existence dictionary above,
including the same application tag. `errSecItemNotFound:-25300` proves that
deletion completed. `errSecSuccess` is accepted only with exactly one typed
`SecKey`; because the fixed query already contains the exact tag, EC key type,
access group, data-protection flag, and match-one constraint, that result proves
the orphan still exists and returns
`REGISTRY_ORPHAN_KEY_DELETE_AMBIGUOUS` in the disjoint fixture flow without
repeating deletion; signed stage cleanup uses its canonical quarantined result
below. Any other
OSStatus, CFType, count, or projection returns the same stable code with an
internal reason and blocks cleanup.
This reconciliation never uses a generic-password exact-account read. Exact
coordinator-active deletion uses only `kSecClassGenericPassword`, coordinator
service, account `active`, resolved access group,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
`kSecAttrSynchronizable=false`, and the data-protection-Keychain flag. The
helper first exact-reads and byte-compares the intended item; it never issues a
service-wide, class-wide, prefix, match-all, permit, or closed-record delete.
The authority-executor guard is held without interruption from that equality
read through this delete and its one reconciliation read; a competing
acquisition remains queued and performs zero Keychain calls during the
interval. An ambiguous coordinator-active delete is reconciled by one
generic-password exact-account read and is never blindly repeated.
`errSecItemNotFound` proves cleanup completed; equal active bytes return
`APPLY_COORDINATOR_ACTIVE_DELETE_AMBIGUOUS` for trusted read-first recovery;
different well-formed active bytes are a successful stale no-op and are never
deleted; malformed, duplicate, or other status returns
`AUTHORITY_STATE_CORRUPT`. Private-key and coordinator deletion result types
are therefore never interchangeable.

The stage-cleanup generic-password delete dictionary is a separate closed
dictionary accepted only by that authority. In protocol projection order it
contains exactly `kSecClass=kSecClassGenericPassword`, the fixed registry or
coordinator `kSecAttrService`, the exact attributed `kSecAttrAccount`, the
resolved `kSecAttrAccessGroup`,
`kSecAttrAccessible=kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
`kSecAttrSynchronizable=false`, and
`kSecUseDataProtectionKeychain=true`. It contains no value, match limit,
return flag, wildcard, prefix, or caller-selected predicate. Its preceding and
reconciliation read is the exact-account generic-password read above. The
stage-cleanup private-key read is the exact noninteractive UI-fail/no-context
existence query; the helper copies and canonically projects that returned
`SecKey` to tag, type, size, token, access group, DER SPKI, and SPKI fingerprint
for byte comparison. It obtains tag/type/size/token/access-group from the exact
typed `SecKeyCopyAttributes` projection, obtains the public key only through
`SecKeyCopyPublicKey`, requires its external representation to be the canonical
65-byte uncompressed P-256 X9.63 point, wraps it with the fixed 26-byte SPKI
prefix, and hashes the resulting 91 bytes. It never exports private-key bytes
or signs. A null/wrong-typed result, missing/wrong attribute, noncanonical
public point, or API error is quarantine, not absence. Its delete is exactly the orphan-key delete dictionary
above even when the retained setup snapshot marks that session-created
generation active. Neither query may present UI or sign.

`SecItemDelete` returns only `OSStatus`; no CF result is accepted. For either
stage dictionary, each operation begins with its exact read. Not-found advances
without deletion; a different value, malformed/wrong CFType, duplicate,
interaction-required, or other status quarantines. A byte-equal value permits a
physical delete only after the durable `delete_attempt_started` marker and its
exact acknowledgement defined below. Direct `errSecItemNotFound:-25300` from
that one delete is terminal. Success and other statuses use one exact
post-invocation read to establish absence or quarantine, never to authorize a
second delete. Helper/runner restart begins with the exact read and unresolved
marker classification; it never infers completion from an unretained result.

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
| registry intent digest | `YTA-REGISTRY-INTENT-V1\0` |
| old-key final signature | `YTA-REGISTRY-RECORD-OLD-V1\0` |
| new-key final signature | `YTA-REGISTRY-RECORD-NEW-V1\0` |
| commit-candidate digest | `YTA-REGISTRY-COMMIT-V1\0` |
| coordinator active digest | `YTA-APPLY-COORDINATOR-ACTIVE-V1\0` |
| coordinator permit digest | `YTA-APPLY-COORDINATOR-PERMIT-V1\0` |
| coordinator closed digest | `YTA-APPLY-COORDINATOR-CLOSED-V1\0` |
| stage-cleanup request digest | `YTA-STAGE-CLEANUP-REQUEST-V1\0` |
| stage-cleanup intent digest | `YTA-STAGE-CLEANUP-INTENT-V1\0` |
| stage-cleanup progress digest | `YTA-STAGE-CLEANUP-PROGRESS-V1\0` |
| stage-cleanup delete-attempt digest | `YTA-STAGE-CLEANUP-DELETE-ATTEMPT-V1\0` |
| stage-cleanup operation-result digest | `YTA-STAGE-CLEANUP-OPERATION-RESULT-V1\0` |
| stage-cleanup evidence digest | `YTA-STAGE-CLEANUP-EVIDENCE-V1\0` |

`request_sha256`, `proposal_sha256`, `acceptance_sha256`, and
`recovery_evidence_sha256` are lowercase SHA-256 over their respective domain
followed by the complete canonical object. The proposal digest includes its
`proposal_signature`. The record
digest used by commit authorization is SHA-256 over the commit domain followed
by the complete stored record.
The two additional digest domains are `YTA-STAGE-CLEANUP-ACK-ENTRY-V1` and
`YTA-STAGE-CLEANUP-ACK-LEDGER-V1`, each followed by one NUL byte, for a
canonical ACK-ledger entry and container respectively.

Stage-cleanup request, intent, progress, delete-attempt, operation-result, ACK-ledger entry/container, and
evidence digests use their matching domains followed by the complete canonical
object. `operation_result_sha256` specifically means the operation-result
domain followed by the exact canonical operation-result bytes. A setup or cleanup context
digest is instead plain SHA-256 of its exact canonical context bytes, as frozen
by the artifact-authorization protocol; it is not a signing domain.

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
helper performs exactly one noninteractive existence lookup for the ledger's
exact active tag using the UI-fail dictionary above. Only
`errSecItemNotFound` (OSStatus `-25300`) establishes absence. If a typed key
reference is returned, the helper creates a fresh zero-reuse `LAContext`,
performs exactly one signing lookup with the separate UI-allow dictionary, and
uses only that returned key for exactly one `SecKeyCreateSignature`
continuity-probe signature over
the recovery-continuity-probe domain followed by the exact request bytes:

- a valid signature proves continuity is available, ends recovery with
  `RECOVERY_CONTINUITY_AVAILABLE`, discards the probe, and directs the operator
  to rotation or revocation with a new challenge;
- cancellation, authentication failure, interaction-not-allowed, key-use
  failure, transient/unavailable status, malformed result, or any other error
  ends with `RECOVERY_ELIGIBILITY_UNPROVEN`; and
- none of those errors is reclassified as key loss or retried automatically.

If the existence lookup returns any status other than success with one typed
key reference or `errSecItemNotFound`, or the subsequent signing lookup returns
anything other than one typed key under its exact fresh context, recovery fails with
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

Before any registry ledger read, proposal validation, key generation, presence
request, or signing work, the requesting peer constructs one compact canonical
registry intent capped at 1,024 bytes. Its fields are, in order,
`schema_version` integer `1`, `intent_type` exactly `registry_commit`,
`transition_kind`, `artifact_descriptor_sha256`, `ceremony_nonce`,
`requested_at`, and `expires_at`. The transition is exactly `enrollment`,
`rotation`, `revocation`, or `recovery`; the nonce is unpadded base64url of 32
fresh random bytes; expiry is after issue and at most five minutes later. Its
digest is SHA-256 of ASCII `YTA-REGISTRY-INTENT-V1` plus NUL followed by the
exact canonical bytes. This `registry_intent_sha256` is available before the
first mutable authority read and is the only registry-operation payload bound
into coordinator acquisition. It expresses intent, not eligibility or a
candidate winner.

## Helper-owned apply authority coordinator

The production helper is one per-user launchd-managed server. Its launchd job
label is exactly the helper identifier
`io.github.abigotado.youtrack-agent.approval`; launchd is the only component
allowed to start it or bind its fixed service endpoint, and it does not run a
second instance of that label concurrently in the same user bootstrap
namespace. The helper rejects an inherited/listener substitute, a directly
spawned server mode, or a peer that did not connect through that endpoint.
This process topology is part of the signed artifact and Gate evidence, not an
operator convention.

Inside that single server, one non-reentrant serialized authority executor is
the only code allowed to call coordinator Keychain operations. It takes an
in-process executor guard before every active acquisition and retains it across
the complete apply or registry operation through closed reconciliation and
exact-read/delete active cleanup. A recovery operation takes the same guard
before its first coordinator classification read and retains it through its
journal CAS, close reconciliation, exact active read, possible byte-equal
delete, ambiguous-delete reconciliation, and final classification. A queued
competitor cannot call `SecItemAdd`, read coordinator state, replace an item,
or enter another authority path until the guard is released. In particular,
no acquisition can linearize between recovery's byte-equality read and exact
active delete, closing the Keychain read/delete ABA interval.

On helper crash or launchd restart, the old process and its executor cease
before launchd exposes the replacement endpoint. The replacement creates a
fresh executor, acquires its guard, performs bounded startup enumeration, and
enters recovery-only mode for any unresolved active record before accepting or
queuing ordinary authority work. The in-process guard is never treated as
durable state: the fixed Keychain active record remains the cross-client and
cross-restart lock and recovery fence.

All CLI clients therefore serialize registry commits and mutation sends
through one helper-private coordinator service:

```text
io.github.abigotado.youtrack-agent.approval.apply-authority.v1
```

Its only accounts are `active`, `permit/<lease-id>`, and
`closed/<lease-id>`. A lease ID is `YTAL-` followed by uppercase unpadded RFC
4648 Base32 of 16 random bytes; decode/re-encode equality is required. The
fixed `active` account is the crash-durable cross-client mutex: both an apply
attempt and a registry commit must, while holding the authority-executor
guard, successfully create it with one `SecItemAdd` before their first
authority-state read. Every accepted client therefore contends on the same
Keychain primary key rather than an independent process or filesystem lock.
`errSecDuplicateItem` means busy and grants no authority.

The active value is compact canonical JSON capped at 4,096 bytes with fields
in this order: `schema_version`, `record_type` exactly
`apply_coordinator_active`, `lease_id`, `operation_kind` exactly `apply` or
`registry_commit`, `coordinator_session_id`, `cli_audit_token_sha256`,
`artifact_descriptor_sha256`, `authorization_context_sha256`,
`registry_revision`, `plan_id`, `journal_revision`, `registry_intent_sha256`,
`created_at`, and `expires_at`. The session ID is unpadded base64url of 32
fresh random bytes. The CLI digest is required for both operation kinds.
Apply requires the exact context eligible for its closed mode—canonical
`gate_receipt_context_v1` only in the matching authenticated Gate E1/E2
session, the smoke receipt context only in activation smoke, or the grant-bound
final context only in production/post-grant verification—plus registry
revision, plan, and journal revision, and sets registry intent null. Production,
smoke, and post-grant modes reject the Gate context before active acquisition.
Registry commit requires the pre-read
registry-intent digest and sets context, registry revision, plan, and journal
revision null. Its eventual request/proposal/candidate is constructed and
validated later while the lease is held and must repeat the intent's
transition and descriptor; its `challenge` equals the intent's decoded
`ceremony_nonce` bytes re-encoded by the request codec, and its expiry equals
the intent expiry. It never changes
the acquired active bytes. Expiry is at most
ten minutes after creation and never turns an abandoned record into permission
to delete, steal, or reuse it.

An apply permit is compact canonical JSON capped at 4,096 bytes with fields
`schema_version`, `record_type` exactly `apply_coordinator_permit`, `lease_id`,
`active_sha256`, `coordinator_session_id`, `cli_audit_token_sha256`,
`artifact_descriptor_sha256`, `authorization_context_sha256`,
`registry_revision`, `plan_id`, `journal_revision`, `receipt_sha256`,
`mutation_request_sha256`, `issued_at`, and `expires_at`, in that order. It is
stored once under `permit/<lease-id>`. Every field is non-null, repeats the
validated active lease, and binds the exact canonical signed receipt and final
HTTP request bytes. Its expiry equals the active expiry. A permit is evidence
for at most one send on the still-open authenticated coordinator connection;
it is not a bearer token and is never returned as caller-selectable bytes.

A closed value is compact canonical JSON capped at 4,096 bytes with fields
`schema_version`, `record_type` exactly `apply_coordinator_closed`, `lease_id`,
`active_sha256`, `permit_sha256`, `operation_kind`, `terminal_outcome`,
`journal_revision`, `registry_record_sha256`, `closed_at`, `close_mode`,
`recovery_reason`, `recovery_actor_unique`,
`recovery_actor_audit_token_sha256`, and `recovery_helper_session_id`, in that
order. Journal revision is required for apply and null for registry commit;
the registry-record digest has the inverse rule.
Permit digest is null for registry commit and for an apply that provably ended
before any permit existed, and is required exactly when that permit exists.
`terminal_outcome` is exactly `registry_committed`,
`registry_not_committed`, `failed_before_mutation`, `applied`, or `ambiguous`.
`close_mode` is `normal` or `recovery`. A normal close has null recovery fields
and its exact bytes are constructed before the terminal journal CAS. A
recovery close is constructed only after the recovery handshake has installed
the no-sign/no-permit/no-send/no-commit fence; it requires all three recovery
actor fields. `recovery_actor_unique` is the authenticated recovering CLI's
Security.framework unique identifier, its audit-token digest binds that new
connection, and `recovery_helper_session_id` is the fresh helper session that
performed fencing. These are current recovery authority; the active record's
old token and session remain historical evidence only. `recovery_reason` is
null during the uninterrupted path or exactly
`restart_before_permit`, `restart_after_permit`,
`restart_before_registry_commit`, `restart_after_registry_commit`, or
`close_or_delete_ambiguous`. It is stored
once under `closed/<lease-id>`. Permit and closed records are immutable audit
and fencing records and are never deleted in the first release; reaching
either 256-record bound blocks writes and registry ceremonies pending a new
reviewed protocol.

For an apply, the schema-3 receipt, active record, permit, and closed record
form one context chain. The receipt, active, and permit repeat the identical
`authorization_context_sha256`; the permit binds `active_sha256`, and the
closed record binds that same active digest plus the permit digest when a
permit exists. In Gate mode that context digest reconstructs the exact
root-signed E1/E2 token tuple through the journal's closed
`gate_authority_evidence_v1` branch. A changed/missing link, cross-mode context,
or linked object whose bytes reconstruct another Gate token/session is
corruption, never authority.

The active, permit, and closed digests are SHA-256 of their respective domain
followed by their exact canonical bytes. Active, permit, registry-revision, and
each normal-path closed add are one-shot. After their success, error,
cancellation, or ambiguous status, the helper performs at most one
exact-account read: equal bytes mean success, absence means that attempt did
not commit, and different/malformed/duplicate result is a conflict. No permit,
registry-revision, or active acquisition add is retried. A later trusted
recovery is not a blind retry: after fencing it first exact-reads the immutable
closed account and may perform one add only if it is absent, using exact closed
bytes already committed with the terminal journal CAS.

### Apply linearization and fencing

The uninterrupted apply order is exact:

1. The single launchd helper authenticates the connected CLI and checks trusted
   time before the descriptor expiry without reading mutable authority. If
   expired, the CLI CASes `confirmed -> expired` and no active item exists.
   Otherwise it enters the serialized authority executor, takes the executor
   guard, rechecks expiry, and creates the fixed active item. It retains the
   guard through step 6 and active cleanup. This successful add is coordinator
   acquisition, not send authority.
2. While retaining the same authenticated connection and excluding every
   registry commit, it replays the complete ledger, validates the unexpired
   helper profile and applicable live authority/context (the exact root-signed
   Gate token/context in Gate mode or the existing stage/production chain), and checks the receipt,
   project policy, credential binding, preconditions, plan, and journal
   revision. Expiry or another definitive failure after acquisition but before
   permit closes `failed_before_mutation`, burns the receipt, and sends zero
   mutation bytes.
3. The CLI durably compare-and-swaps `confirmed -> in_flight`, storing the
   exact historical registry and authorization evidence. This is the local
   non-replay point; failure closes the lease as `failed_before_mutation`.
4. The helper reauthenticates that same connection, rechecks the unchanged
   ledger/context/profile cutoff and returned `in_flight` revision, then adds
   exactly one permit. The successful or exact-read-reconciled permit add is
   the sole send-authority linearization point.
5. Only the same connection may send the one request whose exact bytes hash to
   `mutation_request_sha256`. The helper keeps the coordinator acquired across
   send and outcome handling, so rotation, revocation, recovery, enrollment,
   and another apply cannot overlap it. There is no second permit, redirect,
   retry, or resend.
6. The CLI constructs the exact `close_mode=normal` closed bytes and durably
   compare-and-swaps them together with `applied`, `failed_before_mutation`, or
   `ambiguous` into journal v2. The helper exact-reads that revision and bytes,
   reads `closed/<lease-id>` first, accepts identical bytes as already
   committed, or performs one identical add only when the read was not found.
   Different/malformed bytes fail closed. Only after an identical durable close
   does it exact-read and clean up `active` under the rules below. Durable
   closed bytes are the close/fencing linearization point; active deletion is
   idempotent cleanup, never proof of closure.

If the normal-path closed add returns ambiguously, its one immediate exact read
maps identical bytes to success, not found to
`APPLY_COORDINATOR_CLOSE_AMBIGUOUS`/exit 11 for trusted recovery, and
different/malformed/other to `AUTHORITY_STATE_CORRUPT`/exit 1. The normal path
does not issue another add or delete active after either failure.

The authenticated coordinator connection carries the lease ID, active digest,
session ID, and expected journal revision on every message. A reconnect,
different audit token, restarted helper session, stale journal revision,
expired lease, or message after close cannot obtain or exercise a permit. The
network executor accepts request bytes only while that original connection is
open and the helper still holds an equal active item with an equal permit and
no closed item. The CLI cannot bypass this check by invoking a transport
directly; write-capable transport construction remains behind this coordinator
capability.

Registry enrollment, rotation, revocation, and recovery use the same active
account with `operation_kind=registry_commit`. The peer first creates the
canonical registry intent and the helper binds its digest into active; only
after the serialized executor guard and a strict pre-acquisition profile-expiry
check may it attempt the active add. At or after expiry it adds nothing. Only
after successful acquisition may the helper read the ledger or validate/build the
request, proposal, or candidate. Under the same lease it rechecks exact peer,
descriptor, intent, ledger, and trusted time strictly before profile expiry
immediately before the proposal signature, again before the final registry
signature, and again before the one revision add. It validates the eventual
candidate against the active intent before commit, reconciles the one revision
add exactly, adds a committed/not-committed closed record, and then performs
read-first active cleanup. No registry revision can linearize between an
apply's in-flight CAS and durable close. If a registry operation acquires
first, its revision and close are visible before a later apply revalidates, so
the old receipt is canceled without a permit.
An initial enrollment is not an exception: even an invalid or duplicate
enrollment attempt must acquire `active` before its first ledger read or
proposal validation. If apply already owns `active`, enrollment returns
`APPLY_COORDINATOR_BUSY`, performs zero ledger reads, key generation, proposal
signing, revision adds, or cleanup deletes, and cannot learn whether the
candidate enrollment would otherwise be valid. Gate 1B proves this ordering
with the deterministic invalid-enrollment contention case.

### Release-stage cleanup authority

`stage_cleanup` is a distinct authenticated IPC operation, not a registry
ceremony, coordinator recovery, ordinary uninstall, or production maintenance
command. The helper accepts it only from the exact Gate runner connection when
all of the following validate together: the complete exact root-signed
`activation_smoke` or `post_grant_verification` token (not only its digest),
that token's `cleanup_authorization=attributed_stage_cleanup_only`, the
canonical stage cleanup context, the descriptor and running code identities,
native architecture, approved capability, runner unique, gate session, and the
retained setup context and post-enrollment registry snapshot. The token must be
currently unexpired and its plan must carry
`stage_cleanup_policy=attributed_stage_cleanup_v1`. A different token type,
session, architecture, capability, runner, descriptor, setup snapshot, or
context is rejected before a Keychain read.
Trusted current time must also be strictly before the descriptor's
`helper_profile_expires_at` at request authentication and immediately before
each item read/delete. These checks instantiate the existing smoke- or
post-grant-observation profile-expiry boundary for every internal cleanup step;
they do not create an expiry grace or recovery exception.

Setup and cleanup contexts are disjoint. The setup context can authorize only
the first exact-artifact enrollment; the cleanup context can authorize only
the bounded attributed deletion protocol in this section. Neither context can
sign a receipt or registry proposal/final record, acquire or replace
coordinator `active`, create or exercise a permit, construct transport, send a
request, cross a runner session, or become ordinary production/recovery
authority. Ordinary production, uninstall, maintenance, and every non-stage
flow continue to forbid registry-revision, permit, closed-record, or active-key
deletion.

Before the first delete, the trusted runner durably writes the exact cleanup
intent and initial progress object to immutable content-addressed storage
outside the disposable journal root, runner mutable-state root, and helper
Keychain namespaces. A cleanup intent is compact canonical JSON capped at
262,144 bytes with fields, in order:

1. `schema_version`, integer `1`
2. `intent_type`, exactly `stage_cleanup`
3. `stage_type`, `activation_smoke` or `post_grant_verification`
4. `stage_token_sha256`
5. `setup_context_sha256`
6. `cleanup_context_sha256`
7. `artifact_descriptor_sha256`
8. `architecture`
9. `approved_capability`
10. `gate_runner_unique`
11. `gate_session_id`
12. `pre_enrollment_inventory_sha256`
13. `pre_enrollment_inventory_base64url`
14. `setup_transcript_manifest_sha256`
15. `setup_transcript_manifest_base64url`
16. `registry_snapshot_sha256`
17. `registry_snapshot_base64url`
18. `generated_key_tags`
19. `expected_registry_records`
20. `expected_coordinator_records`
21. `expected_key_items`
22. `delete_operations`
23. `created_at`
24. `expires_at`

Every base64url value is unpadded encoding of the named exact canonical bytes;
decode/re-encode equality and its adjacent digest are mandatory. The empty
pre-enrollment inventory, setup transcript result manifest, and registry
snapshot must equal the already retained setup evidence. `expires_at` is no
later than the root-signed stage-token expiry. `generated_key_tags` is the
helper-owned creation-order list captured on the authenticated stage session,
contains exactly the setup snapshot's one generation-1 tag, and cannot be
supplied or reordered by the runner. Smoke and post-grant plans contain no
rotation, recovery, or other key creation, so any second tag is unattributed
state and quarantines cleanup.
Before intent construction the helper emits that list in its authenticated
setup transcript and retained snapshot; the runner copies it byte-for-byte,
and the helper compares the intent array to the digest-bound snapshot value and
setup-transcript manifest before the executor guard. A restarted helper
receives and validates those same retained bytes; it never reconstructs the
list from current Keychain state.

`expected_registry_records` is the complete session-created registry set in
ascending numeric revision order and contains exactly the snapshot's revision-1
record. Every entry contains `account`,
`record_sha256`, and `record_base64url`, in that order, and the decoded bytes
must form the valid descriptor-bound chain beginning at revision 1.
`expected_coordinator_records` is the complete session-created audit set in
account byte order and contains entries with `record_kind` exactly `permit` or
`closed`, `account`, `record_sha256`, and `record_base64url`, in that order.
It never contains `active`; every permit has its matching closed record and
every entry binds this descriptor/session and the retained receipt/registry
tuple. `expected_key_items` follows `generated_key_tags` order and contains
`key_tag`, `key_projection_sha256`, and `key_projection_base64url`; each
projection is the exact UI-fail lookup projection defined above and matches its
registry SPKI/fingerprint tuple. These complete exact bytes, not service/name
patterns, are the deletion attribution boundary.
Registry/coordinator `record_sha256` retains that record type's ordinary domain
definition; `key_projection_sha256` is plain SHA-256 of the exact projection.

For `confirm_only`, the coordinator set contains exactly the setup enrollment's
one registry-commit closed record and no permit. For `issue_create`, it also
contains exactly the capability workflow's one apply permit and matching
closed record, for three entries total in account-byte order. Rejected
authority-negative probes create no record. Any other count, kind, lease,
operation, or session is unattributed and fails before deletion.

`delete_operations` is the only allowed operation order. Its entries contain,
in order, `operation_index` starting at zero, `item_kind` exactly
`coordinator_record`, `registry_record`, or `private_key`, `service` nullable
only for a key, `account` nullable only for a key, `key_tag` required only for
a key, `expected_item_sha256`, `exact_read_dictionary_sha256`, and
`exact_delete_dictionary_sha256`. It contains first every attributed
coordinator permit/closed entry in account byte order, then every attributed
registry revision in descending numeric order, then every attributed key in
reverse helper creation order. Each dictionary digest is SHA-256 of the
language-neutral canonical projection of exactly the read/delete dictionary
specified above. The target arrays and operation array must be a one-to-one
mapping: missing, duplicate, extra, reordered, or differently projected entries
invalidate the intent before any delete.
For each operation, `expected_item_sha256` is plain SHA-256 of the exact stored
value bytes or key-projection bytes, independent of the record's domain digest,
so it is the digest used by the pre/post-read equality checks.

Let `N` be the exact intent operation count: `3` for `confirm_only` and `5`
for `issue_create`. Every progress history contains at most `2N+1` records,
including revision zero, because each operation has at most one marker and
one terminal result. Progress revisions are exactly `0..2N`.

Initial progress is retained before deletion with fields, in order,
`schema_version` integer `1`, `progress_type` exactly `stage_cleanup_progress`,
`cleanup_intent_sha256`, `gate_session_id`, `previous_progress_sha256` null,
`progress_revision` integer `0`,
`next_operation_index` integer `0`, `completed_operation_result_sha256s` exact
empty array, `delete_attempt_started_sha256s` exact empty array,
`pending_delete_attempt_sha256` null, `operation_result_sha256s` exact empty
array, `state` exactly `in_progress`, and `updated_at`. State is only
`in_progress`, `delete_pending`, `complete`, or `quarantined`. Before every
physical delete, the runner atomically appends its acknowledged marker digest
to `delete_attempt_started_sha256s`, sets `pending_delete_attempt_sha256`,
increments `progress_revision`, and durably retains the resulting
`delete_pending` progress. After each read/delete/reconciliation result,
the runner atomically appends its digest to `operation_result_sha256s` and
increments `progress_revision`; every successor sets
`previous_progress_sha256` to the exact domain digest of its immediate durable
predecessor. Only `deleted` or `already_absent` also appends
the digest to `completed_operation_result_sha256s` and increments
`next_operation_index`; `reconciled_absent` does the same. `quarantined` leaves
that index unchanged and sets the terminal progress state. Every result clears
`pending_delete_attempt_sha256`. The runner retains the new progress bytes and
acknowledges their digest before another operation. A complete record has
`next_operation_index` equal to the operation count, exactly one completed
result per operation in operation order, and `state` exactly `complete`;
the marker array contains zero or one entry per operation and every entry has
fixed `attempt=1`; operation-result digests remain in operation order. An
unresolved marker is represented only by `state=delete_pending` and the equal
last marker digest in `pending_delete_attempt_sha256`. Missing, forked,
rolled-back, reordered, or
non-prefix progress is unverifiable and quarantines the session.

The IPC request is compact canonical JSON capped at 1,048,576 bytes with fields,
in order, `schema_version` integer `1`, `message_type` exactly `stage_cleanup`,
`stage_type`, `stage_token_sha256`, `stage_token_base64url`,
`setup_context_sha256`, `cleanup_context_sha256`,
`cleanup_context_base64url`, `artifact_descriptor_sha256`, `architecture`,
`approved_capability`, `gate_runner_unique`, `gate_session_id`,
`registry_snapshot_sha256`, `cleanup_intent_sha256`,
`cleanup_intent_base64url`, `cleanup_progress_sha256`,
`cleanup_progress_base64url`, `pending_delete_attempt_base64url`, `cleanup_ack_ledger_sha256`,
`cleanup_ack_ledger_base64url`, `requested_at`, and `expires_at`. The exact token,
cleanup context, intent, progress, and ACK-ledger container bytes must decode, re-encode, hash, and
cross-bind. `pending_delete_attempt_base64url` is null unless supplied progress
is `delete_pending`; in that state it is the exact canonical marker bytes,
capped at 65,536 decoded bytes, and its domain digest must equal progress's
non-null pending marker digest and the ledger head's marker digest. Request
expiry is after issue, at most five minutes later, and no
later than token/intent expiry. The terminal response is capped at
131,072 bytes and contains `schema_version`, `message_type` exactly
`stage_cleanup_result`, `request_sha256`, `cleanup_intent_sha256`,
`final_cleanup_progress_sha256`, `final_cleanup_ack_ledger_sha256`,
`final_cleanup_ack_ledger_entry_count`, `status` exactly `complete` or `quarantined`,
`next_operation_index`, `helper_cleanup_evidence_sha256` and
`helper_cleanup_evidence_base64url` both null unless complete, and `finished_at`,
in that order. The returned evidence bytes must match their digest; `complete`
is the sole status that permits the runner to continue toward a passing final
inventory.

After all immutable inputs validate, the helper enters the one serialized
authority executor and holds its guard through enumeration, every item
read/delete/reconciliation, the final Keychain absence inventory, and result.
Before the first delete and on every resumed request, an exact-account read of
coordinator `active` must return only `errSecItemNotFound:-25300`; stage cleanup
never deletes active and never proceeds around it. The bounded registry,
coordinator, and key enumerations may contain only byte-equal not-yet-completed
attributed intent entries and no unknown, extra, or mismatched entry. An
expected entry may be absent even when its result is not yet in the durable
progress prefix because its delete may have committed before acknowledgement;
only that entry's ordered exact-read operation may classify the absence and
advance progress.
The enrolled registry generation may still be `active`; it is removable here
only because its exact revision/generation/tag/SPKI/fingerprint/descriptor/
session tuple equals the retained setup snapshot and cleanup intent.

Each operation begins with the exact read and complete value- or key-projection
comparison. With no pending marker, not-found completes the operation as
`already_absent` without a delete; exact presence may proceed only through the
marker handshake below; mismatch, malformed/wrong CFType, duplicate,
interaction-required, or other status quarantines before deletion. With a
pending marker, another physical delete is always forbidden: exact absence
completes as `reconciled_absent`, exact byte-equal presence quarantines for
manual repair, and every unknown or mismatched result quarantines. Recovery
therefore classifies an unresolved invocation but never guesses whether it ran
and never repeats it.

Immediately before the sole physical `SecItemDelete`, the helper constructs a
compact canonical marker with fields, in order, `schema_version` integer `1`,
`marker_type` exactly `delete_attempt_started`, `stage_type`,
`stage_token_sha256`, `setup_context_sha256`, `cleanup_context_sha256`,
`artifact_descriptor_sha256`, `architecture`, `approved_capability`,
`gate_runner_unique`, `gate_session_id`, `registry_snapshot_sha256`,
`cleanup_intent_sha256`, `operation_index`, `item_kind`, `target_id`,
`expected_item_sha256`, `exact_delete_dictionary_sha256`, `attempt` integer
`1`, and `started_at`. Its digest uses the stage-cleanup delete-attempt domain.
There is exactly zero or one marker per operation and no value other than
`attempt=1` is valid.

The helper sends a compact canonical message capped at 131,072 bytes with
fields `schema_version` integer `1`, `message_type` exactly
`stage_cleanup_delete_attempt_start`, `cleanup_intent_sha256`,
`prior_progress_sha256`, `operation_index`,
`delete_attempt_started_sha256`, `delete_attempt_started_base64url`,
`delete_pending_progress_sha256`, and
`delete_pending_progress_base64url`, in that order. The proposed progress
appends that marker and enters `delete_pending`. The runner append-only retains
the marker and pending-progress bytes in immutable outside-disposable custody,
publishes and verifies them through the exact durable protocol below, and then
returns an acknowledgement capped at 4,096 bytes with
fields `schema_version` integer `1`, `message_type` exactly
`stage_cleanup_delete_attempt_ack`, `cleanup_intent_sha256`,
`delete_attempt_started_sha256`, `delete_pending_progress_sha256`,
`progress_revision`, `operation_index`, `gate_session_id`, and
`acknowledged_at`, in that order. Only an exact acknowledgement of those durable
bytes permits the helper's one invocation. A lost, early, changed, duplicate,
or unpersisted acknowledgement causes connection close and leaves the marker
pending; it never permits a delete.

After invocation, the helper records a canonical operation result with fields
`schema_version`, `result_type` exactly `stage_cleanup_operation`,
`cleanup_intent_sha256`, `operation_index`,
`delete_attempt_started_sha256` null only when pre-read absence or rejection
prevented invocation, `item_kind`, `target_id`, `expected_item_sha256`,
`pre_read_status`, `pre_read_item_sha256`, `delete_status`,
`post_read_status`, `post_read_item_sha256`, `outcome` exactly `deleted`,
`already_absent`, `reconciled_absent`, or `quarantined`,
`quarantine_reason` null unless outcome is `quarantined`, and `observed_at`, in
that order. Statuses are numeric `OSStatus`; item hashes are over complete
generic-password value or canonical key-projection bytes. Direct
`errSecItemNotFound:-25300` from `SecItemDelete` is terminal
`already_absent`, clears the pending marker, and requires no post-read. Direct
success followed by exact absence records `deleted`; exact presence or an
unverifiable read quarantines with `delete_success_still_present` or
`delete_success_unverifiable`. Every
other delete status requires one exact read: absence records
`reconciled_absent`; exact expected presence records `quarantined` with reason
`delete_result_still_present`; unknown/mismatch records `quarantined` with
reason `delete_result_unverifiable`. Recovery of a pending marker uses reasons
`pending_delete_still_present` or `pending_delete_unverifiable`. Pre-read
rejection uses `pre_delete_read_unverifiable`. No other nullable combination or
reason is valid, and no quarantined outcome permits another delete.

The field shapes are exhaustive. `<marker>` is the one acknowledged marker
digest, `<expected>` is `expected_item_sha256`, `<different>` is a non-equal
digest from an otherwise typed success. `<read-invalid>` means either numeric
`0` with `<different>` for a typed nonmatching item or null for a malformed,
duplicate, wrong-CFType, or unprojectable success, or any numeric status other
than `0` and `-25300` with a null item hash. `<delete-other>` is any numeric
delete status other than `0` and `-25300`. “Advance” means append this result to both result arrays
and increment `next_operation_index`; “quarantine” appends it only to
`operation_result_sha256s`, leaves the index unchanged, and terminalizes
progress.

| Case | Marker | Pre-read status / item hash | Delete status | Post-read status / item hash | Outcome | Reason | Progress |
| --- | --- | --- | --- | --- | --- | --- | --- |
| initial pre-read absence | null | `-25300` / null | null | null / null | `already_absent` | null | advance |
| initial pre-read rejection | null | `<read-invalid>` | null | null / null | `quarantined` | `pre_delete_read_unverifiable` | quarantine |
| direct delete success | `<marker>` | `0` / `<expected>` | `0` | `-25300` / null | `deleted` | null | advance |
| direct delete not-found | `<marker>` | `0` / `<expected>` | `-25300` | null / null | `already_absent` | null | advance |
| direct delete success, exact item still present | `<marker>` | `0` / `<expected>` | `0` | `0` / `<expected>` | `quarantined` | `delete_success_still_present` | quarantine |
| direct delete success, post-read unverifiable | `<marker>` | `0` / `<expected>` | `0` | `<read-invalid>` | `quarantined` | `delete_success_unverifiable` | quarantine |
| ambiguous delete, post-read absence | `<marker>` | `0` / `<expected>` | `<delete-other>` | `-25300` / null | `reconciled_absent` | null | advance |
| ambiguous delete, exact item still present | `<marker>` | `0` / `<expected>` | `<delete-other>` | `0` / `<expected>` | `quarantined` | `delete_result_still_present` | quarantine |
| ambiguous delete, post-read unverifiable | `<marker>` | `0` / `<expected>` | `<delete-other>` | `<read-invalid>` | `quarantined` | `delete_result_unverifiable` | quarantine |
| pending-marker recovery absence | `<marker>` | `-25300` / null | null | null / null | `reconciled_absent` | null | advance |
| pending-marker recovery exact presence | `<marker>` | `0` / `<expected>` | null | null / null | `quarantined` | `pending_delete_still_present` | quarantine |
| pending-marker recovery unverifiable | `<marker>` | `<read-invalid>` | null | null / null | `quarantined` | `pending_delete_unverifiable` | quarantine |

These rows are the complete canonical encoder/decoder state space.

A crash after invocation but before result persistence leaves the durable
pending marker as the authority. Recovery reuses the identical token,
cleanup-context, intent, marker, and unique complete ACK-ledger history defined
below. Delete
success and direct not-found both reconcile only through exact absence and a
terminal `reconciled_absent` result; an ambiguous invocation whose item remains
exactly present quarantines for manual repair. The helper never rebuilds
attribution or dictionaries from mutable state and invokes `SecItemDelete` at
most once per operation across all processes, restarts, and token lifetime.

The initial request opens one full-duplex cleanup exchange and the helper holds
the serialized executor guard until its terminal response or connection loss.
After each operation or pending-marker reconciliation it sends one compact canonical intermediate message capped
at 131,072 bytes with fields, in order, `schema_version` integer `1`,
`message_type` exactly `stage_cleanup_step_result`,
`cleanup_intent_sha256`, `prior_progress_sha256`, `operation_index`,
`operation_result_sha256`, `operation_result_base64url`,
`proposed_progress_sha256`, and `proposed_progress_base64url`. The result and
progress bytes must decode/re-encode, hash, and represent exactly that next
prefix. The runner durably retains both in the immutable outside-disposable
evidence store, then returns an acknowledgement capped at 4,096 bytes with
fields `schema_version` integer `1`, `message_type` exactly
`stage_cleanup_progress_ack`, `cleanup_intent_sha256`,
`proposed_progress_sha256`, `progress_revision`, `next_operation_index`,
`gate_session_id`, and `acknowledged_at`, in that order. The helper verifies the
acknowledged digest and counters and derives the identical next ACK-ledger
entry/container before the next read/delete. A missing,
changed, duplicate, reordered, or early acknowledgement closes the exchange
without another operation. On reconnect, the runner sends a new initial
request containing the unique completely validated ACK-ledger head and its
progress; neither peer
manufactures or rolls back an acknowledgement.

#### Canonical ACK ledger and durable publication

The trusted runner owns one fixed retained namespace at
`stage-cleanup/<cleanup_intent_sha256>/<gate_session_id>/`, relative to its
preopened retained-evidence root outside disposable state. The digest and
43-character canonical session ID are the only variable path components;
they cannot contain a separator. Every directory is same-user, mode `0700`,
opened without following symlinks and checked before use. Before publishing
genesis or any ACK, each newly created path component is exclusively created
with `mkdirat` mode `0700` relative to its checked parent, opened and verified,
then both the new directory and its parent are `fsync`ed. The child is reopened
without following symlinks from that parent and its owner/mode/type/device/inode
must equal the created directory. This proceeds from the retained root outward;
an existing component is accepted only by the same no-follow identity checks,
never replaced. Any creation, directory/parent-fsync, or reopen failure closes
the exchange before an ACK. Durability of a file's immediate directory does
not substitute for durability of its ancestor links.

The trusted runner reuses the repository's persistent OS advisory-lock pattern
for a fixed `stage-cleanup-writer.lock` regular file directly under the retained
root, outside all cleanup namespaces. It opens the same-user mode-`0600`,
single-link file with no-follow and close-on-exec, exclusively creates and
file/parent-fsyncs it if absent, and verifies the reopened identity. It acquires
`flock(LOCK_EX|LOCK_NB)` before namespace creation or inspection and holds that
descriptor and exclusive lock through the whole cleanup exchange and evidence
publication. Contention or lock error performs no cleanup action. This
serializes every trusted runner process using that retained root, including
restarts; the lock file is never unlinked or replaced, and a crashed owner loses
its kernel lock without any stale-PID or timeout-based ownership override. A
new owner revalidates the complete namespace after acquiring the lock.
Cleanup cannot
delete, rename, or reuse the namespace. It contains only the exact intent,
progress, marker, result, and ACK-ledger entry files defined here. Final helper
and complete evidence, transcript manifests, and container snapshots reside
outside this namespace and do not widen its file allowlist.

Each ledger entry is a canonical object capped at 8,192 bytes. Its exact fields
in order are `schema_version` integer `1`, `entry_type` exactly
`stage_cleanup_ack_entry`, `cleanup_intent_sha256`, `gate_session_id`,
`progress_revision`, `previous_entry_sha256`, `prior_progress_sha256`,
`proposed_progress_sha256`, `ack_kind`, `ack_base64url`, `operation_index`,
`delete_attempt_started_sha256`, and `operation_result_sha256`. Digests use the
domains above; ACK bytes are the exact canonical wire ACK, unpadded base64url
encoded, with a decoded cap of 4,096 bytes. The closed nullability rules are:

| Entry | Exact required/null fields |
| --- | --- |
| Genesis, revision `0` | `proposed_progress_sha256` is the retained initial progress digest; `previous_entry_sha256`, `prior_progress_sha256`, `ack_kind`, `ack_base64url`, `operation_index`, and both marker/result digests are all null. There is no fabricated genesis ACK. |
| Marker, revision `1..2N` | predecessor and prior/proposed progress digests are non-null; `ack_kind=stage_cleanup_delete_attempt_ack`; ACK bytes and operation index `0..N-1` are non-null; marker digest is non-null and result digest is null. |
| Result, revision `1..2N` | predecessor and prior/proposed progress digests are non-null; `ack_kind=stage_cleanup_progress_ack`; ACK bytes and operation index `0..N-1` are non-null; result digest is non-null and marker digest is null, even when the result references a prior marker. |

Every entry after genesis advances exactly one progress revision, binds the
immediate preceding entry's domain digest, and sets `prior_progress_sha256` to
that entry's `proposed_progress_sha256`. Intent and session are identical
throughout. Marker ACK fields equal the entry's intent/session/revision,
operation, marker, and proposed progress. Result ACK fields equal the entry's
intent/session/revision and proposed progress, and its `next_operation_index`
equals the referenced result progress. The referenced result's operation index
equals the entry's. The runner validates the complete referenced objects and
the progress transition rules above before publishing the entry. A marker
entry can follow only `in_progress`; a result entry follows `in_progress` for
initial absence/rejection or `delete_pending` for the identical pending marker.
No entry can follow `complete` or `quarantined` progress. There are exactly as
many entries as progress records: `1..2N+1`, thus at most seven for
`confirm_only` or eleven for `issue_create`.

The bounded transport/evidence container has exact fields, in order,
`schema_version` integer `1`, `ledger_type` exactly `stage_cleanup_ack_ledger`,
`cleanup_intent_sha256`, `gate_session_id`, `entries_base64url`, `entry_count`,
and `head_entry_sha256`. The sole array contains exact canonical entry bytes,
each unpadded base64url encoded, in increasing revision order starting at zero;
its length equals `entry_count` and the head digest equals its last entry's
domain digest. The whole container is capped at 131,072 bytes before decoding.
It is reconstructed only from a completely validated namespace, never from a
caller-selected prefix. Its domain digest is `cleanup_ack_ledger_sha256`.

The exact final basenames are `cleanup-intent-<cleanup_intent_sha256>.json`,
`cleanup-progress-<progress_sha256>.json`,
`delete-attempt-<delete_attempt_started_sha256>.json`,
`operation-result-<operation_result_sha256>.json`, and
`ack-entry-<revision4>-<entry_sha256>.json`. `revision4` is the four-digit,
zero-padded decimal revision (`0000` through at most `0010`); the JSON revision
retains the ordinary no-leading-zero grammar. There is one intent, one progress
per entry, at most `N` markers, and at most `N` results: at most `6N+3` final
files (21 or 33), with aggregate capped at 2,097,152 bytes. Per-object caps
apply before parsing; filenames never substitute for content validation.

All these objects use the same durable no-follow publication pattern as the
journal protocol. For each object the
runner opens a fresh same-directory random temporary basename with
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` and mode `0600`, verifies by
`fstat` that it is a same-user regular file with link count one and exact mode,
writes the complete canonical bytes, and `fsync`s the file. It then publishes
to the digest-derived final basename without replacement, using
`renameatx_np(..., RENAME_EXCL)` or the protocol-equivalent collision-safe
`linkat` followed by unlink of the temporary name. An existing final name is
accepted only after the exact reopen verification below proves identical
bytes; a different value is a collision and quarantines. After each final-name
publication/unlink it `fsync`s the containing directory, opens the final entry
relative to that same directory with
`O_RDONLY|O_CLOEXEC|O_NOFOLLOW`, repeats owner/mode/type/link-count and size
checks, reads the exact capped bytes from that one descriptor, repeats
`fstat`, and requires byte-for-byte canonical equality and the expected domain
digest. Initial publication is intent, initial progress, then genesis entry;
all three must be durably reopened before the initial request. For a marker,
the marker is published and verified first, followed by cross-bound
`delete_pending` progress, followed by its ACK entry. For a result, the result
is published and verified first, followed by successor progress, followed by
its ACK entry. The runner constructs the exact ACK before constructing its
entry, and durably reopens that entry before transmitting the ACK. This applies
to every marker ACK and every result ACK, including terminal progress. There
is no separate unstructured ACK file or mutable head pointer.

The pending progress is valid only when it advances the supplied prior valid
prefix by exactly one revision, sets `previous_progress_sha256` to that prior
progress digest, keeps `next_operation_index` and all result
arrays unchanged, appends the one marker digest, sets both
`pending_delete_attempt_sha256` to that digest and `state=delete_pending`, and
matches the marker's stage/token/setup-context/cleanup-context/descriptor/
architecture/capability/runner/session/snapshot/intent/operation/dictionary
fields. The canonical entry is the append-only custody of the exact ACK bytes.
Thus a sent ACK
is durable evidence that both final pair entries existed and cross-bound to the
valid prior prefix; an in-memory or merely written-but-not-reopened pair can
never authorize `SecItemDelete`.

Before an initial/resumed request, the trusted runner enumerates the complete
namespace with the file-count/aggregate bounds above, before selecting a head.
It rejects every extra basename, nested directory, symlink, temporary name,
partial file, duplicate revision (including two different digests), gap,
noncanonical revision/name, bad predecessor, or digest mismatch. It then
requires exactly one genesis and the unique contiguous sequence `0..k`, checks
every entry and all referenced progress/marker/result files through the same
no-follow reopen and canonical-byte checks, validates all transitions, and
requires exact set equality between present final files and this complete
history's references plus intent. Unreferenced progress/marker/result files
are failed partial publication, never candidates to promote. Terminal
successors, a missing reference, cross-intent/session reference, metadata
change, or collision quarantines the whole session. Recovery never picks one
fork, skips a bad file, or silently shortens the history to a valid prefix.
The single head is selected only after these checks, and supplied current
progress must equal its referenced proposed progress.

The runner is trusted to attest that this complete durable store was checked
before opening the authenticated helper request. The helper independently
validates the supplied canonical container, complete entry/ACK chain, exact
intent/session/revision/counter bindings, and head/current-progress equality.
It validates the supplied pending marker bytes on resumed pending progress,
and derives each subsequent entry and container from the exact ACK
it receives and the result/progress it already constructed. It therefore
agrees on the final ledger digest/count without accepting a runner-supplied
final digest as proof. Historical referenced-object filesystem validation is
the trusted runner's responsibility; no untrusted path becomes helper input.
A durable entry whose ACK was not transmitted still counts: recovery resumes
from its progress, consumes its pending marker, and never reissues that
operation's delete. Missing an ACK on a live connection closes the exchange.

There is no digest cycle: the marker binds only the already fixed stage,
intent, and operation; pending progress binds the prior progress and marker;
the ACK binds both final marker and pending-progress digests; the ledger entry
then binds the exact ACK, predecessor entry, and progress references; the
container binds the entries. ACKs never include their own entry/container
digest. Successful
exclusive publication, directory `fsync`, and no-follow reopen/hash comparison
is the storage-model durability boundary. A crash or injected directory-fsync/
reopen failure before the ACK means the helper receives no authority to delete.
Loss after that boundary is not modeled as a normal power-loss outcome; if a
retained ACK entry, object, transcript, or evidence commitment makes a
missing/corrupt suffix detectable, it is local corruption and quarantines
without another delete. A deliberately restored internally complete older
namespace together with all independent commitments is outside this trusted
runner/durable-storage model, as with the registry snapshot rollback
non-property above; this ledger does not claim an external monotonic anchor.

The helper cleanup evidence is compact canonical JSON capped at 65,536 bytes
with fields, in order, `schema_version` integer `1`, `evidence_type` exactly
`stage_cleanup_keychain`, `stage_type`, `stage_token_sha256`,
`setup_context_sha256`, `cleanup_context_sha256`,
`artifact_descriptor_sha256`, `architecture`, `approved_capability`,
`gate_runner_unique`, `gate_session_id`, `pre_enrollment_inventory_sha256`,
`setup_transcript_manifest_sha256`, `registry_snapshot_sha256`,
`cleanup_intent_sha256`, `final_progress_sha256`,
`final_cleanup_ack_ledger_sha256`, `final_cleanup_ack_ledger_entry_count`,
`delete_attempt_started_sha256s`, `operation_result_sha256s`,
`completed_operation_result_sha256s`,
`final_registry_accounts`,
`final_coordinator_accounts`, `final_key_tags`, `started_at`, `finished_at`, and
`result` exactly `pass`. Completed-result digests exactly equal the complete
ordered operation list; operation-result and marker arrays equal the retained
progress history. The final ledger digest/count equal the helper's derived
canonical container and its entry count, which is final progress revision plus
one. The runner must match those fields to its independently reconstructed
complete namespace before accepting helper evidence. Every marker precedes its matching physical delete, has
fixed attempt 1, and occurs at most once; an operation completed from initial
absence has no marker.
The three final arrays are empty and coordinator `active` is
absent. The helper emits these exact bytes only after all attributed Keychain
targets are absent.

After validating that helper evidence, the runner removes the attributed
journal/session filesystem state and emits the complete cleanup evidence to
immutable storage outside disposable state. It contains, in order,
`schema_version` integer `1`, `evidence_type` exactly `stage_cleanup_pass`,
`stage_type`, `stage_token_sha256`, `setup_context_sha256`,
`cleanup_context_sha256`, `artifact_descriptor_sha256`, `architecture`,
`approved_capability`, `gate_runner_unique`, `gate_session_id`,
`pre_enrollment_inventory_sha256`, `setup_transcript_manifest_sha256`,
`registry_snapshot_sha256`, `cleanup_intent_sha256`,
`final_cleanup_progress_sha256`, `final_cleanup_ack_ledger_sha256`,
`final_cleanup_ack_ledger_entry_count`, `helper_cleanup_evidence_sha256`,
`final_empty_inventory_sha256`, `finished_at`, and `result` exactly `pass`.
Only this complete object may be bound by the stage index. Its final inventory
proves registry, coordinator, key, journal, and mutable runner state empty; the
case-final cleanup assertion runs afterward and must match both evidence
objects and their retained bytes.

An unknown or unattributed item, mismatched bytes/projection, unexpected
service/account/tag, active coordinator singleton, malformed/duplicate query
result, changed snapshot, or non-prefix progress causes `quarantined` with zero
further deletion. A token/context/intent or helper profile that expires or
becomes unverifiable during partial cleanup cannot pass or authorize another
delete. The trusted
runner then quarantines and destroys the complete disposable user/VM; all stage
observations, indexes, evidence, contexts, and publication inputs remain
invalid. Mid-cleanup recovery may use only the exact retained bytes and only
while every signature, expiry, peer, session, descriptor, and progress check
still passes.

### Restart and ambiguous recovery

On startup the sole launchd helper takes its fresh authority-executor guard,
enumerates and projects the bounded coordinator service, and establishes
clear or recovery-only mode before exposing ordinary approval, registry, or
apply traffic. An unresolved active item puts that helper session into
recovery-only mode before it accepts a caller. Recovery deliberately does not
require the active record's old audit
token or helper session: those processes may have crashed. Instead the new
helper authenticates a newly connected CLI by the same exact stable code
identity and descriptor bound by the active record, then requires trusted UI
authorization and retained evidence matching every applicable active field.
The old audit-token/session values are checked as historical fields in that
evidence, never as the recovering actor.

The recovery request is compact canonical JSON capped at 16,384 bytes with
fields, in order, `schema_version` integer `1`, `message_type` exactly
`apply_authority_recovery`, `active_sha256`, `artifact_descriptor_sha256`,
`recovery_actor_unique`, `recovery_actor_audit_token_sha256`,
`recovery_helper_session_id`, `journal_record_sha256`,
`registry_intent_sha256`, `registry_candidate_sha256`, `recovery_nonce`,
`requested_at`, and `expires_at`. Apply requires the journal digest and null
registry digests; registry recovery requires the active intent digest and the
retained candidate digest when a candidate had been produced, with journal
null. The actor unique/audit-token identify the newly connected exact CLI; the
helper session is the new 32-byte base64url session; the nonce is 32 fresh
random bytes; expiry is at most five minutes. The helper exact-reads active,
permit, closed, journal/candidate evidence, validates their full hash chain and
descriptor, and reauthenticates the new connection before any state change.

Successful validation installs a recovery-only fence for that active digest.
It can classify retained state, request one journal v2 CAS, persist/reconcile
one exact closed record, and remove only the byte-equal active record. It
cannot sign, acquire a lease, create/exercise a permit, construct or send a
network request, commit a registry revision, generate a key, or resume any old
message. These prohibitions apply even if the retained permit was unused. If
the exact peer/evidence is unavailable, recovery remains blocked. Profile
expiry normally rejects authority, but a recovery request may proceed at or
after `helper_profile_expires_at` solely through this fenced cleanup subset;
expiry can never enable a signature, registry commit, permit, or send.

The helper never edits a CLI journal directly, and no active item permits
resumption of a send:

- an apply-active record with no permit proves that no send authority was
  issued. After byte-validating the journal, recovery records
  `failed_before_mutation`, and asks the CLI to CAS that outcome plus exact
  recovery-closed bytes into journal v2. This terminalizes and burns the
  receipt whether the journal was still `confirmed` or already `in_flight`; it
  never restores either state. A registry-commit active record
  has no permit by definition; recovery instead exact-reads its intended
  revision against the retained intent/candidate, records
  `registry_committed` or `registry_not_committed`, and uses
  `restart_after_registry_commit` for committed or
  `restart_before_registry_commit` for absent;
- active with a permit but no closed record never sends. If the exact retained
  journal already has a durable `applied`, `failed_before_mutation`, or
  `ambiguous` outcome, recovery preserves that outcome byte-for-byte and adds
  the corresponding closed record; a crash after durable outcome cannot
  downgrade it. If no terminal outcome is durable, recovery writes
  `ambiguous`, even when a fixture observed zero network bytes. In both paths
  it uses `restart_after_permit`; normal closed bytes already stored by a
  terminal CAS remain authoritative, otherwise the CLI CAS stores newly
  constructed recovery-closed bytes after fencing;
- active with a matching closed record never resumes work. It only reconciles
  exact active cleanup. A crash after closed add is therefore fenced before
  restart; and
- with no active item, retained permit/closed records are valid audit state
  only when every apply permit has one matching closed record and every apply
  close names its permit; registry closes have no permit. An unmatched permit,
  closed/permit mismatch, multiple active results, unknown account, malformed
  value, missing journal/candidate, or ambiguous Keychain result blocks the
  coordinator for explicit operator investigation. Expiry never authorizes
  reuse, but it does not prevent the exact recovery classification above.

Close recovery is exact-read-first and safely idempotent. When the terminal CAS
already stored normal closed bytes, recovery first exact-reads
`closed/<lease-id>` against those bytes: identical means the normal close had
committed and no recovery close is written; different/malformed/other fails
with `AUTHORITY_STATE_CORRUPT`; not found proves it did not commit. Only after
that not-found result and the recovery fence, the CLI atomically appends exact
`close_mode=recovery` bytes—binding the current recovery actor/helper session
while preserving the same terminal outcome—to journal v2. If no normal bytes
ever existed, that post-fence CAS creates the recovery bytes directly. The
helper then exact-reads against those recovery bytes: identical means already
committed; not found permits one identical add; different/malformed/other is
corruption. An ambiguous recovery add ends with
`APPLY_COORDINATOR_CLOSE_AMBIGUOUS`; a later trusted recovery repeats the
read-first algorithm, not a blind add. It may therefore observe the identical
winner or, if still absent, make one identical attempt. No path changes the
terminal outcome or creates another permit/send.

Active cleanup is also exact-read-first under the continuously held serialized
authority-executor guard. Not found means cleanup complete. Bytes identical to
this recovery request's retained active record permit one exact active delete;
an ambiguous delete ends the command, and a later trusted recovery begins
again with the exact read under a newly held guard. Different well-formed active bytes
belong to a newer lease and are a successful stale no-op: recovery does not
delete, close, or otherwise affect them. Malformed/duplicate/other results are
`AUTHORITY_STATE_CORRUPT`. This permits a repeated cleanup command while never
blindly repeating deletion and never touching a nonmatching lease.

Crash after registry revision commit is reconciled only by the existing exact
revision read, then closed as committed with
`restart_after_registry_commit`. Crash after send but before a journal outcome
remains ambiguous and read-only reconciliation is required. A process exit,
timeout, connection reset, invalid response, stale fence, or cleanup failure
never authorizes a second permit or network retry.

For that Gate 1B read-only remote reconciliation, the exact CLI must still be
operating under the connection-authenticated runner and `gate_session_id`
bound by the retained `gate_receipt_context_v1`; CLI and runner keep their
distinct pinned code identities. It loads the journal's exact descriptor, signed Gate
token, context, receipt, and complete genesis-to-current registry chain,
recomputes every digest, verifies the root signature and historical live-time
checks, derives the receipt key only by full chain replay, and verifies the
active/permit/closed linkage. A token that expired after the recorded permit/
send remains valid historical evidence for those bounded reads, but never for
a new active acquisition, permit, send, or registry commit. A lone terminal
record, retained SPKI without chain derivation, different runner/session, or
cross-mode context fails closed.

### Future authority commands and machine errors

This design intentionally makes an additive command/exit-contract change while
preserving the JSON v1 envelope. It adds exactly two commands:

```text
youtrack-agent-cli --profile NAME mutation authority status
youtrack-agent-cli --profile NAME mutation authority recover
```

Both commands require one explicit, existing `--profile NAME` before helper
contact; missing profile returns the existing `PROFILE_REQUIRED` usage error
and exit 2, and an unknown profile uses the existing not-found contract and
exit 3. Their only accepted inherited flags are `--profile`,
`-o/--output text|json`, the retained hidden `--json` alias, `--timeout`, and
`-v/--verbose` with the existing meanings and conflict rules. They reject
`--yes`, `--dry-run`, `--fields`, and `-o/--output raw` as usage/exit 2;
`status` does not reinterpret dry-run because it is already read-only, and
`recover` never treats dry-run as approval. Neither command defines or accepts
`--plan-id`, a lease ID, `--force`, a cleanup selector, positional arguments,
stdin data, or an environment override; an unknown inherited or local flag is
also usage/exit 2. `status` is bounded and read-only. `recover` operates only on the sole exact unresolved active record,
launches trusted native UI that displays profile, operation kind, lease digest,
terminal classification, and proposed cleanup, and requires fresh user
presence. Cancellation changes nothing. The command can run the recovery-only
handshake above; it can never force-clear, select/delete an arbitrary item, or
contact YouTrack.

A successful JSON `status` response has exactly the JSON v1 success-envelope
top-level fields `ok` equal to true, `v` equal to integer 1, `data`, and
`meta`, in that order. `meta` is required and has
the existing invocation fields `profile`, `instance`, `account_id`, and
`account_login` in that order, copied from the validated non-secret profile;
it contains no count, cursor, authority state, or credential. `data` has these fields in order: `profile`,
`authority_status`, `artifact_descriptor_sha256`,
`helper_profile_expires_at`, `active`, `permit`, `closed`, `journal`, and
`allowed_action`. Status is `clear`, `busy`, `recovery_required`,
`expired_recovery_only`, or `corrupt`; action is respectively `none`, `wait`,
`recover`, `recover`, or `operator`. `active` is null or contains, in order,
`lease_id`, `operation_kind`, `active_sha256`, `created_at`, `expires_at`,
`historical_cli_audit_token_sha256`, and `historical_helper_session_id`.
`permit` is null or contains `permit_sha256`, `mutation_request_sha256`,
`issued_at`, and `expires_at`. `closed` is null or contains `closed_sha256`,
`terminal_outcome`, `close_mode`, and `closed_at`. `journal` is null or
contains `version`, `revision`, `state`, and `record_sha256`. These projections
contain digests and public metadata only—never receipt bytes, request bytes,
credentials, private keys, Keychain values, or untrusted remote content.

A successful JSON `recover` response uses the same required exact invocation
`meta`; `data` fields are `profile`, `recovery_status`, `lease_id`, `terminal_outcome`, `closed_sha256`,
`active_cleanup`, `recovery_actor_unique`, and
`recovery_helper_session_id`, in that order. Recovery status is `recovered`,
`already_closed`, or `stale_active_ignored`; cleanup is `deleted`,
`already_absent`, or `stale_noop`. `terminal_outcome` and `closed_sha256` are
nullable only for `stale_active_ignored`; every other field is non-null. Text
mode is a bounded projection of the same fields. Raw output is unsupported for
both commands.

Every error uses exactly the existing JSON v1 failure shape
`{"ok":false,"v":1,"error":{"code":"CODE","message":"MESSAGE"},"hint":"HINT"}`
with no `data` or `meta`. The following new exit numbers deliberately express
four distinct caller actions; they must be added to the public contract rather
than disguised as existing exit 9:

| Future exit | Name | Caller action |
| ---: | --- | --- |
| 10 | `AUTHORITY_BUSY` | wait, then call authority status |
| 11 | `AUTHORITY_RECOVERY` | obtain trusted presence and call authority recover |
| 12 | `ARTIFACT_EXPIRED` | install a newly authorized artifact; only recovery cleanup remains available |
| 13 | `RECONFIRM_REQUIRED` | prepare a new plan and obtain a new confirmation |

| Future stable `error.code` | Exit | Exact `message` | Exact `hint` |
| --- | ---: | --- | --- |
| `APPLY_COORDINATOR_BUSY` | 10 | `authority coordinator is busy` | `run mutation authority status and wait` |
| `APPLY_COORDINATOR_RECOVERY_REQUIRED` | 11 | `authority recovery is required` | `run mutation authority recover with trusted user presence` |
| `AUTHORITY_RECOVERY_CANCELED` | 11 | `authority recovery was canceled` | `leave state unchanged or rerun mutation authority recover` |
| `APPLY_COORDINATOR_CLOSE_AMBIGUOUS` | 11 | `authority close requires recovery` | `run mutation authority recover; never resend the mutation` |
| `APPLY_COORDINATOR_ACTIVE_DELETE_AMBIGUOUS` | 11 | `authority cleanup requires recovery` | `run mutation authority recover; never resend the mutation` |
| `HELPER_PROFILE_EXPIRED` | 12 | `authorized helper profile has expired` | `install a newly authorized artifact; recovery cleanup only` |
| `APPLY_PRE_PERMIT_ABORTED` | 13 | `mutation stopped before permit issuance` | `prepare a new plan and obtain a new confirmation` |
| `AUTHORITY_STATE_CORRUPT` | 1 | `local authority state is corrupt` | `stop and request operator repair; do not retry or delete state` |
| `REGISTRY_ORPHAN_KEY_DELETE_AMBIGUOUS` (disjoint Gate fixture only) | 1 | `orphan key cleanup is ambiguous` | `stop and request operator repair; do not repeat deletion` |
| `JOURNAL_V1_AUTHORITY_STATE_QUARANTINED` | 1 | `legacy authority journal state is quarantined` | `stop and request operator repair; do not migrate or retry it` |
| `AUTHORITY_RECOVERY_DENIED` | 1 | `authority recovery evidence is invalid` | `stop and request operator repair; do not force clear state` |

No new authority command or reason emits exit 9. The existing contract retains
that number for its already published conflict/stale uses;
`WRITE_OUTCOME_UNKNOWN` may still use it to direct read-only remote
reconciliation. It is not reused for coordinator busy, recovery, profile
expiry, reconfirmation, or cleanup corruption. Unknown new exits are nonzero
and fail closed for older callers; the envelope version remains 1 because its
shape is unchanged.

These commands, exits, and reasons are future contract values and are not
implemented by the current disabled slice. The implementation of record must
add the four exit definitions and one authoritative reason registry to
`internal/errx/contract.go`, extend `errx.Describe()` to expose the exact
code/exit/message/hint mapping, and then extend—not assume—the current
`tools/gencontract` renderer. `go generate` from `internal/errx` must update
both `docs/contract.md` and
`assets/skills/youtrack-agent/reference/contract.md`. The Cobra tree must add
only the two commands above; the existing `tools/gencommands` path must then
update `docs/commands.md` and
`assets/skills/youtrack-agent/reference/commands.md`. The authoritative
`.agents/rules/cli-contract.md` must be updated in that implementation change,
its tracked `.cursor/rules` compatibility mirror must be regenerated through
`.agents/scripts/sync-rules.py`, and both the sync check and the machine-local
provider compiler `--check` gate must pass. The embedded skill's
`SKILL.md` and write-policy reference must be updated to route busy/recovery/
expiry/reconfirm/corruption exactly as above, and the installed Codex/Claude
copies must come only from that regenerated embedded skill. None of those
production, generated-contract, canonical-rule, or tracked mirror files is
changed by this design-only delta.

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

The same fixture directory contains language-neutral serialized projections
for every exact key-generation, signing-key lookup with a fresh zero-reuse
`LAContext` and UI allow, the returned `SecKey` used for exactly one
context-free-API `SecKeyCreateSignature` call followed by context invalidation
on every outcome, noninteractive existence lookup with UI fail and no context,
key-enumeration, registry
add/enumeration/exact-read, disjoint-fixture private-key delete, coordinator add/enumeration/
exact-read/pre-send-probe, and active-delete dictionary above. Positive coordinator vectors
cover apply active records, registry-commit active records bound only to a
pre-read canonical registry intent, later candidate validation under that
lease, one permit, every normal/recovery closed
outcome, uninterrupted apply, registry-first cancellation, apply-first
serialization, restart before permit, restart after permit but before send,
restart after send but before outcome, close-add ambiguity, and active-delete
ambiguity. They also cover the one-per-user launchd helper topology, serialized
authority-executor guard acquisition/release, restart startup classification,
and a competitor queued after byte-equal active read but before delete that
performs zero Keychain operations until guard release and acquires only after
old active is absent. Private-key deletion vectors in the disjoint fixture or
exact signed stage-cleanup authority separately cover delete success,
ambiguous delete followed by typed `SecKey`, ambiguous delete followed by
`errSecItemNotFound`, wrong CFType, multiple results,
and every other OSStatus; coordinator-active deletion vectors separately cover
delete success, equal-byte exact-read ambiguity, not-found reconciliation,
different bytes, malformed projection, and every other OSStatus. Fixture
vectors additionally serialize both signed stage-token variants, the exact
setup snapshot, cleanup context, request, retained intent, every valid progress
prefix, delete-attempt-start/durable-ack and step-result/progress-ack exchange,
same-directory exclusive-`0600` temp writes, canonical file and directory
`fsync`, collision-safe no-replace publication, no-follow reopen/hash checks,
exact registry/coordinator/key read and delete dictionary, projected read
value, every valid nullable operation-result shape, helper evidence, complete
runner evidence, and final empty inventory. Three specific crash vectors stop
after physical invocation but before result persistence: delete success and
direct `errSecItemNotFound` both recover by exact absence into terminal
`reconciled_absent`, while an ambiguous result with the exact item still
present recovers into quarantine/manual repair. Every trace asserts one durable
`delete_attempt_started` marker before invocation and exactly one
`SecItemDelete` call for that operation across restart; every restart replays
the identical intent, marker, and last durable progress bytes and starts with
the same exact read. A separate crash/fault vector interrupts marker or pending-
progress publication at file-fsync, no-replace publication, directory-fsync,
and reopen checkpoints before ACK and proves zero `SecItemDelete` calls. A
detectable ACK-ledger/pair loss or mismatch is a corruption vector that
quarantines without rollback or delete; it is not modeled as successful
directory-fsync durability loss. Additional fixtures encode genesis with its
explicit null ACK fields; all-marker and all-initial-absence successful
histories for both `N=3` and `N=5`; terminal quarantine histories; every exact
entry and container byte/digest; canonical zero-padded filenames; and matching
helper/complete evidence ledger digest/count. Fault vectors interrupt both
ancestor creation at mkdir, child/parent-fsync and no-follow reopen, and both
marker-ACK and result-ACK entry publication at write, file-fsync, exclusive
publish, directory-fsync, and reopen, proving no ACK transmission before
durability. They also stop after entry durability but before ACK transmission
and prove restart adopts that entry without another delete. Concurrent-runner
vectors prove a lock contender performs zero namespace/cleanup operations and
the successor revalidates the entire namespace after a crashed owner exits.
Recovery vectors
reject extra/temp/partial files, duplicates, gaps, forks, bad links, missing or
unreferenced objects, cross-session references, terminal successors, exceeded
count/byte bounds, and a truncated entry suffix with retained object/transcript
evidence; none selects a shorter head. Fixture
manifests name symbolic Security.framework constants and
typed CF values; implementations construct native dictionaries and compare the
bounded projection rather than relying on CFDictionary iteration order. No
literal digest is inserted into this document before the vector generator
emits and both implementations verify it.

Separate negative query vectors delete or substitute
`kSecUseAuthenticationContext`, reuse an `LAContext`, set a nonzero reuse
duration, replace UI allow with fail on signing, add a context or UI allow to
existence/delete, omit UI fail, return a typed key from the wrong query, trigger
unexpected authentication UI, pass any context-like value to the signature
call, reuse the returned signing key for a second signature, or omit context
invalidation on success, cancellation, lookup failure, or signature failure.
Signing vectors require exactly one prompt-capable lookup, one signature made
with only the returned `SecKey`, and one terminal context invalidation;
existence/delete vectors require zero prompt presentation, zero context, and
zero signature.

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
  add retry;
- a missing/additional/wrong-typed dictionary entry, legacy Keychain selection,
  synchronizable item, wrong accessibility/access group/service/account/class,
  match-limit substitution, unexpected return CFType, match-all bare
  dictionary, duplicate/unknown projected account or key tag, over-bound result,
  broad delete, and any registry revision/permit/closed delete outside the
  exact stage-cleanup authority;
- a missing, additional, reordered, cached, match-all, or differently
  projected pre-send probe; active/permit byte mismatch; closed lookup success;
  or any send after a probe failure; and
- two active leases, permit without the exact active/session/audit token,
  permit before `in_flight`, send without or after permit/close, second permit,
  second send, registry commit overlapping apply, active deletion before close,
  stale reconnect/session/journal fence, restart resumption, crash-state
  downgrade, and treating any post-permit uncertainty as retryable;
- a second launchd helper instance/listener, direct helper-server spawn,
  coordinator Keychain access outside the serialized executor, guard release
  before close/read-delete completion, an acquisition call or active
  replacement between equality read and delete, competitor coordinator reads
  before release, or ordinary authority admitted before restart startup
  classification;
- registry active without an intent, candidate digest substituted for intent,
  intent created after a ledger/proposal read, transition/descriptor/nonce/
  expiry disagreement between intent and request, candidate not validated
  under the same lease, or any proposal/final signature/commit at or after
  profile expiry; and
- recovery requiring the crashed audit token/session, recovery with changed
  code identity or descriptor, missing retained evidence, recovery before its
  fence, recovery sign/acquire/permit/send/commit, recovery close missing the
  new actor/session, normal/recovery close substitution, close add without a
  preceding exact read, active delete without exact read/byte equality, or
  deletion of a different well-formed active lease; and
- stage cleanup without the exact root-signed smoke/post-grant token, cleanup
  context, descriptor, native architecture, capability, runner/session, or
  retained setup snapshot; setup/cleanup authority used to sign, acquire,
  permit, send, or cross sessions; absent/mutable intent or progress bytes;
  current-state reconstruction; a wrong, unknown, unattributed, duplicate, or
  reordered expected item, generated-key tag, dictionary, operation, or
  completed prefix; missing/changed/early progress acknowledgement; a delete
  without a preceding durable acknowledged `delete_attempt_started` marker;
  wrong marker stage/token/setup or cleanup context/descriptor/architecture/
  capability/runner/session/snapshot/intent/operation/dictionary, attempt other
  than `1`, multiple markers, marker rollback, same-directory/temp mode or
  no-follow violation, noncanonical write, missing file/directory fsync,
  replacement publication, name collision with different bytes, publication
  or reopen/hash failure, non-cross-bound pair, or acknowledgement before both
  entries and the ACK ledger entry are durably reopened; result ACK transmitted
  before its canonical entry is durable; wrong genesis nullability, ACK kind
  or exact bytes, predecessor/prior/proposed binding, operation/digest union,
  filename revision/digest, entry/container count or head; extra/temp/partial
  namespace member, fork, gap, duplicate, unreferenced object, terminal
  successor, or detectable suffix truncation accepted by shortening history;
  changed final helper/complete-evidence ledger digest or count;
  a second delete after any marker, including an unresolved one; coordinator
  active present; enrolled registry tuple not
  equal to the retained active generation; missing pre-read or byte comparison;
  mismatch followed by deletion; unresolved-marker absence not terminalized as
  `reconciled_absent`; unresolved-marker exact presence not quarantined for
  manual repair; blind delete retry after ambiguity; restart
  with changed bytes; stage-token/intent or helper-profile expiry, or other
  unverifiability after partial cleanup, treated
  as pass; incomplete final inventory; or any such delete from an ordinary
  production or non-stage flow (disjoint Gate fixture deletion remains limited
  to fixture identities). Ordinary orphan/retired-key maintenance attempts
  must perform zero delete calls.

Go and Swift must parse and re-encode every positive byte identically and
reject every negative vector with the same stable reason class. Gate 1A runs
both implementations against the same immutable fixture hashes.

## Evidence

- Apple defines the dictionary-driven Keychain operations
  [`SecItemAdd`](https://developer.apple.com/documentation/security/secitemadd(_:_:)),
  [`SecItemCopyMatching`](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)),
  and
  [`SecItemDelete`](https://developer.apple.com/documentation/security/secitemdelete(_:)),
  together with the explicit
  [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain)
  selector. This protocol narrows those general APIs to the exact dictionaries
  and bounded projections above.
- Apple documents that Keychain duplicate detection uses an item's composite
  primary key in [`errSecDuplicateItem`](https://developer.apple.com/documentation/security/errsecduplicateitem).
- Apple documents private key generation through
  [Generating new cryptographic keys](https://developer.apple.com/documentation/security/generating-new-cryptographic-keys)
  and Secure Enclave protection in
  [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).
- The private access-group boundary follows
  [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps).
