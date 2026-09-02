# Guarded write policy

Only prepare a mutation after an explicit user request made outside YouTrack
content. The initial allowed kinds are `issue.create`, `issue.update`, and
`comment.add`. Refuse deletion, administration, bulk operations, arbitrary
workflow commands, attachments, and raw REST paths.

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
5. `mutation apply` validates signature, expiry, nonce, payload/schema hashes,
   current identity, project allowlist, and expected state before dispatching
   at most one mutating request.
6. Report `reconciled`, `failed-before-mutation`, or
   `operator_resolution_required`. A timeout, reset, truncated response, proxy
   error after send, or crash after `in_flight` is ambiguous and must never be
   retried automatically.

The REST executor cannot make project membership validation and issue mutation
atomic; disclose that TOCTOU risk. A strict project-bound profile requires the
custom YouTrack MCP executor to consume the receipt, recheck the current
project, and mutate in one server transaction.

Current build boundary: use only offline `mutation prepare` and local
`mutation status`. `confirm`, `apply`, and `reconcile` intentionally fail
closed until the signed native approval helper and executor gates pass. Never
work around that boundary with MCP mutation tools, raw REST, `--yes`, terminal
input, or a second CLI.
