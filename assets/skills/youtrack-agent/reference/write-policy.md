# Guarded write policy

Only prepare a mutation after an explicit user request made outside YouTrack
content. The initial allowed kinds are `issue.create`, `issue.update`, and
`comment.add`. Refuse deletion, administration, bulk operations, arbitrary
workflow commands, attachments, and raw REST paths.

## Current build: preparation only

Only offline `mutation prepare`, local `mutation export`, and local
`mutation status` are enabled. `confirm`, `apply`, and `reconcile` intentionally
fail closed until the signed native approval helper and executor gates pass.
Use the packaged [commands](commands.md) and [contract](contract.md) for the
current syntax and errors. Future authority commands and permits are not
available in this build. Never bypass this boundary with MCP mutation tools,
raw REST, `--yes`, terminal input, or a second CLI.

## Future guarded workflow — unavailable in this build

1. Read the exact current issue/project and field schema. Bind immutable field
   and value IDs, types, expected-state hashes, and the schema hash.
2. Run `mutation prepare --offline` with the explicit profile and structured
   request. Offline means no DNS, sockets, browser, OAuth, Keychain access, or
   remote checks. The final plan ID and any visible reconciliation marker must
   be included before hashing.
3. Show one canonical snapshot: profile, endpoints/issuer identity, verified
   account snapshot, project, target, exact diff or comment, notifications,
   plan ID, preconditions, and reconciliation strategy.
4. A human approves that immutable hash through the trusted confirmation UI.
   An agent, piped stdin, environment switch, `--yes`, or PTY input cannot mint
   the receipt.
5. The future `mutation apply` must satisfy the complete native authority
   contract, including protected receipt-consumption history, before one
   exact-request permit can authorize at most one mutating request. A journal
   CAS does not grant authority. A consumed receipt stays burned even when its
   owner closes before any permit; a restored journal cannot authorize reuse.
6. Report `reconciled`, `resolved_applied`, `resolved_not_applied`,
   `failed_before_mutation`, or `operator_resolution_required` only with the
   corresponding evidence. `failed_before_mutation` requires an uninterrupted
   owner, proof that no durable permit exists, and valid durable close. Once
   a permit exists, verified success is applied; every other outcome is
   ambiguous, including definitive HTTP rejection or known zero bytes sent.
   Only later eligible already-closed reconciliation may prove
   `resolved_not_applied`. Ambiguity is not proof of non-application. Zero or
   non-unique remote matches require operator resolution; never automatically
   create a fresh plan from them. An unclosed lease is quarantined: do not delete it,
   re-confirm, or treat restart/reboot as recovery. While quarantined, bounded
   remote reconciliation reports evidence without changing the journal.

The REST executor cannot make project membership validation and issue mutation
atomic; disclose that TOCTOU risk. A strict project-bound profile requires the
custom YouTrack MCP executor to consume the receipt, recheck the current
project, and mutate in one server transaction.

Receipt TTL is checked before acquisition and through the final send fence.
Expiry before acquisition expires confirmation; after acquisition but before
permit, only the uninterrupted owner may burn the receipt and close. Capacity
exhaustion stops writes; it never authorizes clearing protected history.
