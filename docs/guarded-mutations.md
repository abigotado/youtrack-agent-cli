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
4. `mutation apply` validates the receipt signature, expiry, nonce, plan/payload
   and schema hashes, current identity, project policy, and preconditions. It
   additionally requires the signed registry revision, generation, exact SPKI,
   fingerprint, artifact descriptor, authorization-context digest, and
   authorized capability to equal the current active registry, active grant,
   and running exact code identities through `confirmed -> in_flight`. The
   journal atomically persists the exact canonical descriptor, signed
   provisional authorization, signed activation grant, derived context, and
   their digests with the receipt before this transition.
   Retained public keys and historical authorization contexts verify audit and
   reconciliation evidence only. Any intervening registry or activation
   transition cancels confirmation rather than authorizing apply. An eligible
   plan records `in_flight`, sends at most one mutating request, and performs
   bounded verification.
5. `mutation reconcile` is read-only. Once a plan is `in_flight`, it validates
   the persisted historical receipt, exact authority sidecars, root signatures,
   descriptor/grant hash chain, context, and capability but does not require
   that authority to remain active. It may establish a unique applied result;
   otherwise it records `operator_resolution_required`.

When execution is enabled, normal terminal states are `reconciled`, `failed-before-mutation`, and
`operator_resolution_required`. A timeout, reset, malformed/truncated response,
proxy failure after send, or process failure after `in_flight` is ambiguous and
never authorizes replay.

## Executor boundary

The proposed REST executor has a disclosed project-move TOCTOU interval between policy
validation and mutation. A strict project-bound profile requires a custom
YouTrack MCP executor that validates and consumes the external receipt, checks
the current project and nonce, and mutates within one server transaction.
