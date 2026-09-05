# Implementation decision: align with the existing CLI harness without weakening write approval

- Status: Accepted and implemented through the fail-closed first slice
- Date: 2026-09-02
- Target module: `github.com/abigotado/youtrack-agent-cli`
- Target binary: `youtrack-agent-cli`
- Target Agent Skill: `youtrack-agent`

## Reuse baseline

Use the clean `confluence-cli` `main` revision `fea3152` as the canonical source for the provider-neutral harness, JSON v1 envelope, panic recovery, bounded output, direct Security.framework Keychain adapter, atomic registries, lockfiles, embedded skill installer, generated command/contract documentation, and CI. Distribution remains explicitly disabled until Gate 1A passes with the frozen trust/package topology and an audited signed and notarized macOS package; the inherited portable archive and Homebrew paths are not safe defaults for this credential-bearing CLI. Homebrew dependency metadata and validation may be prepared before that gate, but an installable Formula/Cask and every tap publication path remain forbidden.

Use the current `jira-cli` feature branch only as a reviewed source for issue/project modeling, exact project policy, and centralized one-shot HTTP request policy. Do not copy the dirty `trello-cli` worktree.

The official YouTrack Remote MCP remains the routine read plane. Its URL must carry the exact positive `tools=` list, while the host independently restricts the same six names. The bare endpoint is not classified read-only because official YouTrack documentation simultaneously claims predefined tools are read-only and lists mutating tools.

## Gate 1A: approval feasibility before remote writes

`LocalAuthentication` can prove a local authentication event, but its short reason string cannot prove that the operator reviewed the complete canonical plan. The existing CLI `--confirm-intent ... --yes` flow is therefore not reused as authority for YouTrack mutations.

Before implementing an enabled `mutation confirm` or `mutation apply`, a macOS feasibility spike must demonstrate all of the following on a supported Mac:

1. A separately signed native helper displays the complete bounded canonical snapshot from one immutable in-memory byte buffer.
2. Only after a fresh LocalAuthentication success, the helper stores the digest of exactly those displayed bytes in `receipt.plan_sha256` and signs the deterministic unsigned receipt from `approval.SigningBytes`, including the exact current approval-registry revision/active key and SHA-256 of the fresh IPC challenge; authentication reuse is disabled.
3. The on-device P-256 private key is non-exportable, has a documented tag and public-key fingerprint, and cannot be used by an unrelated same-user process.
4. Cancellation, timeout, helper crash, binary replacement, key rotation,
   mixed-build peers, and identical reinstall fail closed or preserve the
   first-release boundary. A second write-capable release is blocked on a
   separate rollover design.
5. The CLI verifies the helper code identity, enrolled key, receipt signature,
   signed request challenge, plan digest, TTL, nonce, profile identity, and key
   generation. Exact code identity means Security.framework validity plus the
   offline-root-authorized per-architecture `kSecCodeInfoUnique` /
   `kSecCodeInfoCdHashes` set, not Team ID/build alone.
6. First-install, identical-reinstall, and rollback-refusal paths preserve the
   required code-signing identity and entitlements. Development or ad-hoc
   signing is not accepted as production evidence.

The [registry/ceremony protocol](../docs/gate1a-registry-protocol.md) freezes
every authority-bearing transition byte. The
[artifact-authorization protocol](../docs/gate1a-artifact-authorization.md)
freezes the pinned Ed25519 root, exact descriptor, per-architecture
runner/session-bound E1 and E2 full Gate evidence sets, post-E2 provisional
authorization, pre-grant deny-only smoke, production activation grant, and a
separate per-architecture verification of the real grant-bound production
context before publication. A Gate token or provisional authorization is never
production authority.

## Homebrew activation gate

An ordinary source-built Homebrew Formula cannot establish or preserve the
separately signed native helper's designated requirement and entitlements.
Homebrew therefore remains unavailable before Gate 1A even though the
non-writing CLI surface can be built locally.

The accepted [trust-root topology](../docs/gate1a-trust-root.md) now chooses one
signed/notarized `YouTrackAgent.app` delivered later by Cask or private tap.
Homebrew may link the contained CLI but may not build, replace, extract, or
re-sign the helper. Gate 1A must prove immutable CLI/helper provenance and that
first install, identical reinstall, rollback refusal, and replacement preserve
identity or fail closed. The future Cask pins the exact outer archive SHA-256
and installs the detached descriptor, provisional authorization, activation
grant, root-signed publication envelope, exact post-grant plan, and complete
evidence tree at their fixed support paths. It never fetches verification
assets after extraction and never uses `sha256 :no_check`. The root envelope
binds the security-relevant contents while the Cask separately pins its
containing archive without a recursive hash. It does not authorize a second
write-capable build.

Both activation-smoke capability plans and both post-grant plans are now
setup-first and cleanup-last. A stage token plus derived setup-only context may
perform exactly one revision-1 exact-artifact enrollment after canonical empty
registry/coordinator/key/journal/session inventories pass. The retained
generation/SPKI/fingerprint/descriptor/session snapshot binds every later
observation, per-architecture index, and complete evidence set. Operation
observations carry empty assertion IDs; only the separate case-final runner
evaluation may emit the ordered aggregate after all transcripts exist. Every
failure runs bounded cleanup, and an unproved cleanup destroys the quarantined
disposable user/VM while invalidating all session output.

Gate 1B independently enrolls its fresh E1/E2 host in the first compiled case.
Its retained baseline snapshot records enrollment provenance through later
observations and evidence sets; planned registry transitions retain their own
successor evidence. Gate 1B does not acquire release-stage cleanup authority.

Cleanup itself is a distinct root-token-bound `stage_cleanup` IPC authority,
not a consequence of the setup context or ordinary maintenance. Its immutable
pre-delete intent binds the empty pre-inventory, setup transcript/snapshot,
helper-created key order, complete attributed record/key bytes, exact
Security.framework dictionaries, and operation order. Under the serialized
executor the helper requires coordinator active absent, exact-reads and
byte-compares each item, and durably acknowledges a fixed-attempt marker before
its sole delete only after the marker and cross-bound `delete_pending` progress
are exclusively published, file/directory-fsynced, and exactly reopened.
Genesis and every progress ACK are retained in one bounded hash-linked ledger.
Recovery validates its full namespace, references, and unique contiguous chain;
missing, extra, partial, or forked history quarantines without shortening it.
Restart with an unresolved marker terminalizes exact absence
or quarantines presence/unknown state without another delete. Unknown or expired partial state is quarantined
and the disposable environment is destroyed; it is never broadly deleted.

The same gate must test the first Cask install path against the application-
bound Keychain ACL. Install hooks must not silently reauthorize credentials;
the only permitted initial migration is the operator-invoked
`auth migrate-keychain --profile NAME --yes` flow, with cancellation and
partial failure covered. The repository now has committed source and a remote,
but no immutable release tag, signed archive checksum, installed Developer ID
Application identity, pinned-root provisional/activation authority, or
notarization evidence, so it cannot provide release
provenance for an active Cask.

A later write-capable Cask version is prohibited until a separate rollover ADR
and Gate cover side-loaded older matched pairs, approval keys and registry,
credential migration, and stale access-token expiry or revocation.

If Gate 1A cannot be proven without access to an operator-controlled signing identity, the first coherent release includes profile/auth/inspect, the Remote MCP skill/configuration, offline prepare/export/status, and the complete fail-closed journal schema. `confirm` and `apply` return `USER_PRESENCE_UNAVAILABLE`; no PTY, stdin, environment, Keychain-password, or `--yes` fallback exists.

## Compile-time dependency DAG

```text
cmd/youtrack-agent-cli -> cli
cli -> {application, output, errx}

application -> {profile, auth, oauth, writepolicy, intent, mutation,
                approval, journal, skills, youtrack, restexec, reconcile}

mutation -> {intent, errx}
intent -> {endpoint, protocolvalue}
restexec -> {mutation, youtrack, errx}
reconcile -> {mutation, youtrack, errx}
approval -> {intent, protocolvalue, errx}
journal -> {intent, lockfile, errx}
auth -> {profile, lockfile, errx}
oauth -> {endpoint, errx}
youtrack -> {endpoint, errx}
writepolicy -> {profile, lockfile, errx}
profile -> {endpoint, lockfile, errx}
skills -> {assets, lockfile, errx}
output -> errx
endpoint -> protocolvalue
protocolvalue -> standard library only
lockfile -> errx
errx -> standard library only
```

`application` is the only orchestration owner. `cli` parses and renders only. `mutation` owns consumer-defined interfaces whose concrete implementations are injected by `application`:

- `Executor`: preflight plus exactly one typed execute operation;
- `Reconciler`: bounded read-only evidence collection;
- `Approver`: invoke the display/sign boundary for one exact canonical snapshot, with no receipt-verification or journal access;
- `Journal`: compare-and-swap transitions under one transaction API;
- `CredentialProvider` and `PolicyChecker`: minimum operations needed by the application service.

The combined `approval.DecodeAndValidateIPCResponse` decoder is the sole response-acceptance path: it binds both response arms to the request challenge and binds a success to the exact snapshot, registry revision, and active enrolled signing key before exposing a verified receipt. The interfaces contain at most one to three methods. `internal/youtrack` is a fixed-origin transport/model boundary and imports neither profile nor auth. `internal/cli` does not import `net/http`. Architecture tests enumerate allowed internal edges and fail on every unlisted dependency.

## Journal transaction and lock contract

All durable mutation operations use one journal transaction API with revision-based compare-and-swap. When multiple locks are needed, the global order is profile, policy, then one plan/receipt journal lock. Subsets preserve that order. No remote request or approval UI runs while the journal file lock is held.

Native authority requires canonical journal record version 2, including exact authority evidence plus raw canonical active/permit/normal-close or recovery-close bytes. The normal terminal CAS persists exact normal closed bytes with the outcome; post-fence recovery may instead persist actor/session-bound recovery closed bytes. A strict atomic migration admits only a valid v1 `prepared` record with zero attempts, no receipt, no outcome, and no evidence—the only safe state actually producible by the shipped fail-closed path. Every other valid v1 state, explicitly including `canceled`, `expired`, and `failed_before_mutation`, is retained unchanged and quarantined with `JOURNAL_V1_AUTHORITY_STATE_QUARANTINED`; a valid v1 `failed_before_mutation` has a receipt, one attempt, and an outcome and is never treated as local zero-attempt state. The current `approval.Unsupported` boundary means no v1 authority state can be legitimate current authority.

`prepare` acquires profile, policy, and journal locks, commits the authoritative canonical plan as `prepared`, then exports a 0600 copy. Export failure does not erase or duplicate the journal record.

`confirm` has two phases. It first snapshots the prepared plan under profile/policy/journal locks and releases all locks. The native helper displays that one immutable snapshot, hashes those exact bytes into the receipt, and signs the deterministic unsigned receipt together with the current registry revision, active key identity, and applicable mode-bound authorization-context digest. The service reacquires the locks in the same order, revalidates unchanged identity, policy, plan hash, state, journal revision, registry revision, active key, descriptor and the complete applicable authority branch and derived context. It then atomically stores the receipt, exact canonical authority objects/context and all digests, and moves to `confirmed`. Concurrent confirmation loses the compare-and-swap and cannot mint a second usable receipt.

`apply` holds the profile and policy locks while it validates the bound credential and remote preconditions. Historical verification with retained key or authority bytes is audit evidence only. Apply authority requires the signed receipt's registry revision and generation/SPKI/fingerprint to equal the current active registry entry and its context digest to equal the currently valid mode-bound authority set. Any intervening registry or activation transition cancels a confirmed plan. One launchd-managed helper server owns one serialized authority executor; before its first mutable authority read, apply enters that executor, takes its guard, and acquires the helper-owned fixed-active Keychain coordinator also required by every registry commit. It retains the guard and crash-durable Keychain lease across exact revalidation, the journal `confirmed -> in_flight` CAS, one exact-request permit, one send/outcome, durable close, and guarded exact-read/delete cleanup. Registry-first closes before later apply revalidation and cancels the stale receipt; apply-first excludes all registry commits through durable close. Crash before permit is `failed_before_mutation`. Crash or uncertainty at/after permit is ambiguous and never retried. Audit-token, helper-session, lease, journal-revision, registry, context, and expiry fences are repeated immediately before send.

`reconcile` snapshots an eligible state, revision, receipt, SPKI, and exact historical descriptor, applicable authority branch, context, and complete registry-chain bytes, fully verifies their pinned-root signatures, hashes, capability, and receipt binding without requiring the context to remain active, performs bounded reads without the journal lock, then compare-and-swaps the evidence and next state. Repeated reconciliation is read-only and idempotent. Terminal states return their existing record without additional network activity unless the operator explicitly requests a fresh evidence collection.

Coordinator recovery authenticates a new exact-code CLI and fresh helper session against the stable descriptor and retained evidence; the crashed audit token/session are historical only. After trusted UI it enters a recovery-only fence under the new helper's serialized authority-executor guard that can classify/CAS, persist an actor/session-bound close, and read-first remove only byte-equal active state. The guard remains held across equality read, delete, and ambiguity reconciliation, so a queued acquisition performs no Keychain operation and cannot replace active in that ABA interval. Identical closed is complete, absent allows one identical add, and different fails; active absent is complete, byte-equal allows one delete, and a different well-formed newer lease is a stale no-op. Even after profile expiry only exact launchd recovery-only launch/peer auth is admitted, and this path is cleanup-only: status, trusted-UI fencing, journal CAS, close reconciliation, and guarded byte-equal active cleanup; it cannot enter ordinary auth, sign, acquire, permit, send, or commit.

## Complete state table

The applicable authority set is mutually exclusive by mode: production and
post-grant use provisional authorization plus activation grant and final context;
Gate 1A/1B use their unexpired E1/E2 token, Gate context, authenticated runner/session,
and full registry chain (Gate 1A remains confirmation-only); activation smoke uses its closed provisional/smoke
branch. Confirmation and apply require live authority. Historical validation
reconstructs the retained branch; Gate reconciliation remains confined to its
authenticated runner/session and cannot create a new permit or send.

| From | Event | To | Recovery semantics |
|---|---|---|---|
| none | valid offline prepare committed | `prepared` | Export can be repeated from the journal; no network or credential was used. |
| `prepared` | trusted helper receipt and active authority set committed | `confirmed` | Exactly one receipt/key generation plus the exact canonical descriptor, complete applicable authority branch, derived context, registry chain, and all digests are retained. |
| `prepared` | operator cancellation or expiry | `canceled` / `expired` | Terminal; create a new plan. |
| `confirmed` | coordinator acquired; receipt and unchanged active authority set consumed before permit | `in_flight` | Durable non-replay point; no send authority exists until the one exact-request permit is added. |
| `confirmed` | helper/CLI crashes after coordinator acquisition but before the CAS | `failed_before_mutation` | Recovery proves no permit, burns the receipt, durably closes/fences the lease, and never sends. |
| `in_flight` | crash or definitive failure before permit | `failed_before_mutation` | Terminal after a durable coordinator close; zero mutation dispatch and no retry. |
| `in_flight` | exact permit added | remains `in_flight` | Sole send-authority linearization; every later uncertainty is ambiguous and non-replayable. |
| `confirmed` | operator cancellation before coordinator acquisition | `canceled` | Terminal; no mutation attempt. |
| `confirmed` | trusted time reaches descriptor `helper_profile_expires_at` before coordinator acquisition | `expired` | Absolute cutoff; Gate/install evidence and cached helper sessions do not extend it. |
| `confirmed` | approval registry revision or active generation changed | `canceled` | Retained keys may verify history but never authorize apply. |
| `confirmed` | descriptor, applicable authority token/grant, or context changed | `canceled` | Historical bytes remain audit evidence but never authorize apply. |
| `confirmed` / `in_flight` | trusted time reaches descriptor `helper_profile_expires_at` after coordinator acquisition while no permit exists | `failed_before_mutation` | Recovery burns the receipt, durably closes the lease, sends zero mutation bytes, and requires a newly authorized artifact before a new plan. |
| `in_flight` | definitive rejection proving no mutation | `failed_before_mutation` | Terminal; a new plan is required. |
| `in_flight` | verified success recorded | `applied` | Non-replayable; proceed to bounded verification. |
| `in_flight` | timeout, reset, unexpected/invalid response, or uncertain send | `ambiguous` | Never retry; reconcile. |
| `in_flight` | process crash or local journal failure after permit | remains `in_flight` / `ambiguous` | Restart never resumes send; it durably closes/fences the lease and requires reconciliation. |
| `applied` | exact bounded verification matches | `reconciled` | Terminal known-applied. |
| `applied` | verification cannot establish unique state | `operator_resolution_required` | No automatic retry. |
| `ambiguous` | bounded evidence uniquely proves application | `reconciled` | Terminal known-applied. |
| `ambiguous` | bounded evidence proves definitive non-application | `resolved_not_applied` | Terminal; only a new plan may write. |
| `ambiguous` | zero/non-unique/unsupported evidence | `operator_resolution_required` | No automatic retry. |
| `operator_resolution_required` | explicit local operator resolution with evidence digest | `resolved_applied` / `resolved_not_applied` | Terminal audit record; this action never contacts YouTrack. |

A verified remote success followed by stdout failure or journal-finalization failure emits `WRITE_APPLIED_LOCAL_FAILURE` with do-not-retry guidance. The durable record may remain `in_flight`; restart still treats it as non-replayable, adds/validates the ambiguous closed lease without resending, and requires reconciliation. Gate 1B's closed contract includes apply-first and registry-first rotate/revoke/recovery orderings, invalid-enrollment contention before ledger read, crash before permit, crash after permit before send, crash after send before outcome, crash after durable outcome before close, close-add ambiguity, crash after close before active deletion, active-delete ambiguity, restart fencing, durable close-before-active-delete, and a dedicated ABA schedule that queues a competing acquisition between active equality-read and delete and proves zero competing Keychain calls until executor-guard release. Exact Security.framework dictionary/result-projection vectors, content-addressed binary barrier schedules, and exact event traces prove true two-party ordering without sleeps.

The future authority contract retains JSON v1 while deliberately adding commands `mutation authority status` and `mutation authority recover` plus distinct exits 10..13 for wait, trusted recovery, artifact replacement, and reconfirmation; corruption and operator escalation use existing exit 1. Both require an explicit profile, include invocation identity in required success `meta`, reject plan/lease/force selectors, `--yes`, `--dry-run`, `--fields`, and raw output, and recovery requires trusted UI and never contacts YouTrack. The new authority surface never emits exit 9, while remote-uncertain reconciliation may retain it. These additions are not implemented in the current disabled slice; the later implementation must extend `.agents/rules/cli-contract.md`, `internal/errx`, generators, generated command/contract references, the tracked Cursor mirror through the rule sync, and embedded skill routing together, then pass sync/compiler gates.

## First implementation slice

1. Scaffold the canonical harness and machine contract.
2. Add the portable embedded skill and safe installer.
3. Implement endpoint/profile/project-policy schemas and architecture tests.
4. Implement Keychain-bound public-client OAuth Authorization Code + PKCE and permanent-token fallback.
5. Implement bounded exact REST inspection and offline intent preparation.
6. Implement the journal state machine and fail-closed approval interfaces.
7. Implement durable two-phase confirmation and its native adapter behind
   dependency injection while the current repository remains disabled.
8. Build an unpublished signed/notarized/stapled candidate whose default
   production factory wires confirmation. Create and retain its exact app-only
   archive, freeze its descriptor, then run complete Gate 1A
   E1 and clean-reset E2 on every declared architecture, then issue the
   confirm-only provisional authorization and pass its ordinary-command
   black-box smoke set. Issue the production activation grant only afterward,
   then verify the exact grant-bound production context through the ordinary
   commands on every architecture under deny-only runner restrictions. Failed
   evidence quarantines the unpublished candidate and grant. No post-Gate
   wiring or rebuild occurs.
9. Implement the typed one-shot `issue.create` engine and reconciliation behind
   the disabled executor boundary together with the helper-owned coordinator,
   exact Security.framework dictionary/projection codecs, permit/closed
   fencing, strict helper-profile expiry checks, and crash recovery that never
   resumes a send.
10. Build an unpublished exact candidate whose ordinary production factory
    wires only `issue.create`, repeat the two-pass Gate 1A sequence against its
    new descriptor, then run two-pass live Gate 1B on a disposable YouTrack
    2026.2 project, including the closed apply/registry ordering and every
    pre/post-permit crash/restart case. Only after E2 issue provisional authorization and run the
    exact per-architecture loopback-preflight/hard-deny dispatch smoke; only a
    complete passing smoke evidence set permits the production activation grant.
    The real grant-bound context then passes the separate per-architecture
    ordinary-command verification before publication. There is no post-Gate
    activation edit.
11. Keep `issue.update` and `comment.add` disabled until their separate
    REST-TOCTOU acceptance or strict custom-MCP transaction decision.
12. Run contract, security, primary, and independent adversarial review gates
    before packaging.

The REST executor is always labeled `rest-best-effort`. Strict atomic project enforcement remains a later custom YouTrack MCP executor because a local REST preflight cannot close the concurrent issue-move race.
