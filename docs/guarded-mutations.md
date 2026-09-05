# Guarded mutation contract

The CLI supports typed `issue.create`, `issue.update`, and `comment.add`
operations. It exposes no arbitrary REST method/path, deletion, administration,
attachment, bulk, or workflow-command escape hatch.

Current implementation state: offline `prepare`/`export` and local `status` are enabled.
`confirm`, `apply`, and `reconcile` fail closed with
`USER_PRESENCE_UNAVAILABLE` (or `RECONCILER_DISABLED` for an eligible future
record) until Gate 1A proves the separately signed native helper and the
selected executor passes its compatibility gate. There is no terminal,
environment, stdin, PTY, or `--yes` approval fallback.

## Lifecycle

1. Narrow read helpers capture the exact issue, project, field schema, immutable
   IDs, and expected-state hashes.
2. `mutation prepare --offline` validates the request and exact project
   allowlist using only non-secret local metadata and supplied snapshots. It
   allocates the plan ID before canonicalization and hashing.
   A failed `--out` export does not delete the authoritative journal record;
   `mutation export --plan-id ... --out ...` creates a new exclusive `0600`
   copy without network or credential access.
3. `mutation confirm` displays one immutable in-memory plan and mints a
   short-lived signed receipt only after trusted OS user presence. Piped stdin,
   environment variables, `--yes`, PTY input, and agent-controlled UI are not
   approval channels.

The native helper protocol has two distinct byte sequences. It displays the
exact bytes returned by `intent.ApprovalDisplayBytes`, stores their SHA-256 as
`receipt.plan_sha256`, then signs the exact unsigned-receipt JSON returned by
`approval.SigningBytes`. The signature therefore covers the displayed-plan
hash together with receipt ID, nonce, TTL, approval-registry revision, active
key generation/fingerprint, account, project, schema, request, expected-state,
and SHA-256 of the fresh IPC challenge. A cross-language golden vector pins the
unsigned-receipt encoding. The [Gate 1A protocol](gate1a-protocol.md) records
the implemented pre-Gate v2 contract and the mandatory activation-eligible v3
registry-revision and authorization-context delta; neither constitutes a
trusted helper or a passed Gate 1A.
The activation boundary also requires the exact event-ledger codec in
[Gate 1A registry and ceremony protocol](gate1a-registry-protocol.md) and a
capability-specific, offline-root-signed provisional authorization plus
post-smoke production activation grant from
[Gate artifact authorization](gate1a-artifact-authorization.md).
Before provisional authorization exists, the same schema-3 receipt field is
exercised only inside an authenticated Gate 1A/Gate 1B E1/E2 session. It then
contains the digest of canonical `gate_receipt_context_v1`, which binds the
exact root-signed Gate token, Gate ID, descriptor, plan, target/prerequisite
null rules, architecture, runner/session, and capability. This is controlled
Gate authority, not production activation; production, smoke, and post-grant
paths reject the Gate context type.
4. `mutation apply` validates the receipt signature, expiry, nonce, plan/payload
   and schema hashes, current identity, project policy, and preconditions. It
   additionally requires the signed registry revision, generation, exact SPKI,
   fingerprint, artifact descriptor, authorization-context digest, and
   authorized capability to equal the current active registry, the authority
   eligible for this closed mode, and running exact code identities through
   `confirmed -> in_flight`. Production/post-grant uses the exact signed
   provisional authorization, activation grant, and final context; Gate 1B
   uses the exact unexpired E1/E2 token, Gate context, authenticated runner/session,
   and complete registry chain; activation smoke uses its existing signed
   provisional/smoke-token and smoke-context branch. The journal atomically
   persists the matching complete `authority_evidence` branch and its exact
   canonical bytes/digests with the receipt before this transition. Branches
   are mutually exclusive and cannot supply missing fields for one another.
   Before reading mutable authority it enters the sole launchd-managed
   helper's serialized authority executor, takes its guard, and acquires the
   helper-owned fixed-active Keychain coordinator also used by every
   enrollment/rotation/revocation/recovery commit. The guard remains held
   through close and exact-read/delete cleanup. While holding that guard and
   coordinator, the helper revalidates the complete
   registry, the applicable context, and trusted current time strictly before the
   descriptor's `helper_profile_expires_at`. Only after the durable
   `confirmed -> in_flight` CAS may it create one permit bound to the exact
   request bytes. It holds the coordinator through that one send, durable
   outcome, and durable close; permit creation is the send linearization point
   and closed-record creation is the fencing/close linearization point.
   Retained public keys and historical authorization contexts verify audit and
   reconciliation evidence only. Any intervening registry or activation
   transition cancels confirmation rather than authorizing apply. A crash
   before permit is `failed_before_mutation`; a crash or uncertainty at
   or after permit is ambiguous and never retried. Expiry observed before
   coordinator acquisition transitions `confirmed -> expired`; expiry after
   acquisition while no permit exists burns the receipt and closes
   `failed_before_mutation` with zero dispatch. The final pre-send fence
   repeats the profile-expiry, active-item, permit, connection, audit-token,
   session, journal-revision, registry, and context checks. An eligible plan
   sends at most one mutating request and performs bounded verification.
   Gate 1B proves this with exact two-party barrier schedules covering
   rotate/revoke/recovery, invalid enrollment, every pre/post-permit crash,
   durable-outcome-before-close, close-add ambiguity, post-close crash, and
   active-delete ambiguity plus an explicit acquisition-between-equality-read-
   and-delete ABA attempt that remains queued with zero Keychain calls until
   guard release. The future authority command contract assigns distinct exits
   10..13 to wait, trusted recovery, artifact replacement, and reconfirmation;
   corruption/operator escalation uses existing exit 1 and the new authority surface never emits
   exit 9, while remote-uncertain reconciliation may retain it.
   None is retry permission.
5. `mutation reconcile` is read-only. Once a plan is `in_flight`, it validates
   the persisted historical receipt, exact authority sidecars, root signatures,
   descriptor/grant hash chain, context, and capability but does not require
   that authority to remain active. It may establish a unique applied result;
   otherwise it records `operator_resolution_required`. In the controlled Gate
   1B path, the equivalent validation uses the retained signed Gate token,
   canonical Gate context, and complete registry chain under the still-
   authenticated matching Gate runner session. Token expiry after the recorded
   live boundary does not erase that historical chain, but it cannot authorize
   another confirmation, permit, or send.

When execution is enabled, normal terminal states are `reconciled`, `failed_before_mutation`, and
`operator_resolution_required`. A timeout, reset, malformed/truncated response,
proxy failure after send, or any failure at or after permit issuance is
ambiguous and never authorizes replay. Merely reaching `in_flight` is not that
boundary: a provable crash/failure after its CAS but before permit is
`failed_before_mutation` and requires a new confirmation.

## Future journal record v2 and migration

The current implementation writes journal record version 1. Native authority
work must first introduce strict record version 2; no v1 record can enter the
coordinator. A canonical v2 record contains these fields in order: `version`
exactly `2`, `revision`, `state`, `plan`, `receipt`, `authority_evidence`,
`coordinator_evidence`, `mutation_attempts`, `outcome`, `evidence`,
`legacy_v1_record_sha256`, `created_at`, and `updated_at`. Nullable fields are
present as null rather than omitted. Existing plan, receipt, outcome, and
evidence values retain their bounded codecs. `authority_evidence` is null only
for `prepared` and v2 `canceled`/`expired` records reached before authority
acquisition; otherwise it is exactly one closed branch. `production`,
`post_grant_verification`, and `activation_smoke` retain their existing
descriptor/provisional/stage-token-or-grant/context/registry evidence. `gate`
is the bounded canonical `gate_authority_evidence_v1` object from the artifact-
authorization protocol: it retains exact descriptor, root-signed E1/E2 token,
Gate receipt-context, and complete genesis-to-current registry-chain bytes plus
every digest needed to reconstruct the receipt verification key. It contains
no provisional authorization, smoke token, activation grant, final-production
context, or production authority. A lone final registry record or unchecked
retained SPKI cannot satisfy this branch.

`coordinator_evidence` is null before acquisition or one compact canonical
object with fields `schema_version` integer `1`, `lease_id`,
`active_bytes_base64url`, `active_sha256`, `permit_bytes_base64url`,
`permit_sha256`, `normal_closed_bytes_base64url`, `normal_closed_sha256`,
`recovery_closed_bytes_base64url`, `recovery_closed_sha256`,
`recovery_actor_unique`, `recovery_actor_audit_token_sha256`,
`recovery_helper_session_id`, and `last_fenced_at`, in that order. Byte fields
are unpadded base64url of exact secret-free canonical coordinator objects.
Permit fields are both null before permit; normal-closed fields are both null
until the normal terminal CAS; recovery-closed fields and all recovery actor/
session fields are all null or all non-null and may become non-null only after
the recovery-only fence. The normal terminal CAS writes outcome and exact
normal closed bytes in the same fsync/rename transaction. If recovery later
proves that normal close absent, a second post-fence CAS may append recovery
closed bytes that preserve the outcome and bind the recovery actor/session;
both pairs then remain as history, but only the recovery digest may be added.
Close recovery never reconstructs different bytes from decoded fields.

Migration reads a v1 record under its existing per-plan lock with no-follow,
size, owner, mode, canonical decode, and revision checks. Only `prepared` with
`mutation_attempts == 0`, no receipt, no outcome, and no evidence may migrate:
that is the sole safe state actually producible by the currently shipped
fail-closed command path. It copies the plan, sets receipt, authority,
coordinator, outcome, and evidence null, sets
`legacy_v1_record_sha256` to SHA-256 of the exact v1 bytes, increments revision
once, and preserves state/timestamps except for `updated_at`. It writes a
same-directory exclusive `0600` temporary file, fsyncs it, atomically renames
over the v1 path, fsyncs the directory, then rereads and byte-compares v2 before
returning success. Any failure before rename leaves v1 intact; failure after an
uncertain rename requires exact reread and never a second write.

A valid v1 record in any other state is always rejected with
`JOURNAL_V1_AUTHORITY_STATE_QUARANTINED`, including `canceled`, `expired`,
`confirmed`, `in_flight`, every valid `failed_before_mutation` record, and
`applied`, `ambiguous`, `reconciled`, `operator_resolution_required`,
`resolved_applied`, or `resolved_not_applied`. In particular, the v1 schema
requires `failed_before_mutation` to retain a receipt, one mutation attempt,
and a matching outcome; it is not a zero-attempt local terminal and never
migrates. The source record remains byte-for-byte unchanged. Under the plan lock the CLI
atomically writes a separate exclusive `0600` sibling at exact filename
`<plan-id>.v1-quarantine.json` using the same temp-file/fsync/rename/directory-
fsync protocol. The marker contains only
`schema_version`, `record_sha256`, `state`, `reason` exactly
`unsafe_v1_authority_state`, and `detected_at`; if marker creation is ambiguous
or fails, the in-memory quarantine still blocks all operations. Status may
report its digest, but neither authority recovery nor another migration can
consume it. The current `approval.Unsupported` boundary means no legitimate
current supported command path could have created any valid v1 state beyond
`prepared`; every unexpected non-prepared record remains evidence, never
authority or a migration candidate.

## Executor boundary

The proposed REST executor has a disclosed project-move TOCTOU interval between policy
validation and mutation. A strict project-bound profile requires a custom
YouTrack MCP executor that validates and consumes the external receipt, checks
the current project and nonce, and mutates within one server transaction.
