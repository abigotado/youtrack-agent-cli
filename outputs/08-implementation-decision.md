# Implementation decision: align with the existing CLI harness without weakening write approval

- Status: Accepted and implemented through the fail-closed first slice
- Date: 2026-09-02
- Target module: `github.com/abigotado/youtrack-agent-cli`
- Target binary: `youtrack-agent-cli`
- Target Agent Skill: `youtrack-agent`

## Reuse baseline

Use the clean `confluence-cli` `main` revision `fea3152` as the canonical source for the provider-neutral harness, JSON v1 envelope, panic recovery, bounded output, direct Security.framework Keychain adapter, atomic registries, lockfiles, embedded skill installer, generated command/contract documentation, and CI. Distribution remains explicitly disabled until Gate 1A defines an audited signed and notarized macOS package; the inherited portable archive and Homebrew paths are not safe defaults for this credential-bearing CLI. Homebrew dependency metadata and validation may be prepared before that gate, but an installable Formula/Cask and every tap publication path remain forbidden.

Use the current `jira-cli` feature branch only as a reviewed source for issue/project modeling, exact project policy, and centralized one-shot HTTP request policy. Do not copy the dirty `trello-cli` worktree.

The official YouTrack Remote MCP remains the routine read plane. Its URL must carry the exact positive `tools=` list, while the host independently restricts the same six names. The bare endpoint is not classified read-only because official YouTrack documentation simultaneously claims predefined tools are read-only and lists mutating tools.

## Gate 1A: approval feasibility before remote writes

`LocalAuthentication` can prove a local authentication event, but its short reason string cannot prove that the operator reviewed the complete canonical plan. The existing CLI `--confirm-intent ... --yes` flow is therefore not reused as authority for YouTrack mutations.

Before implementing an enabled `mutation confirm` or `mutation apply`, a macOS feasibility spike must demonstrate all of the following on a supported Mac:

1. A separately signed native helper displays the complete bounded canonical snapshot from one immutable in-memory byte buffer.
2. Only after a fresh LocalAuthentication success, the helper stores the digest of exactly those displayed bytes in `receipt.plan_sha256` and signs the deterministic unsigned receipt from `approval.SigningBytes`; authentication reuse is disabled.
3. The on-device P-256 private key is non-exportable, has a documented tag and public-key fingerprint, and cannot be used by an unrelated same-user process.
4. Cancellation, timeout, helper crash, binary replacement, key rotation, and application upgrade fail closed.
5. The CLI verifies the helper code identity, receipt signature, plan digest, TTL, nonce, profile identity, and key generation.
6. Packaging and update paths preserve the required code-signing identity and entitlements. Development or ad-hoc signing is not accepted as production evidence.

## Homebrew activation gate

An ordinary source-built Homebrew Formula cannot establish or preserve the
separately signed native helper's designated requirement and entitlements.
Homebrew therefore remains unavailable before Gate 1A even though the
non-writing CLI surface can be built locally.

After Gate 1A, a separate accepted architecture decision must choose among a
signed/notarized bundle delivered by Formula, Cask, or a private tap. It must
define immutable CLI and helper provenance, signing and notarization evidence,
tap ownership, update and rollback behavior, and whether Homebrew may build any
component from source. The gate must prove that upgrades preserve helper
identity and fail closed when they do not.

The same gate must test Homebrew Cellar path changes against the application-
bound Keychain ACL. Upgrade hooks must not silently reauthorize credentials;
the only permitted migration is the operator-invoked
`auth migrate-keychain --profile NAME --yes` flow, with cancellation and
partial failure covered. At this decision's acceptance date the repository has
no commit, remote, immutable release tag, source archive checksum, signing
identity, or notarization evidence, so it cannot provide release provenance for
an active Formula or Cask.

If Gate 1A cannot be proven without access to an operator-controlled signing identity, the first coherent release includes profile/auth/inspect, the Remote MCP skill/configuration, offline prepare/export/status, and the complete fail-closed journal schema. `confirm` and `apply` return `USER_PRESENCE_UNAVAILABLE`; no PTY, stdin, environment, Keychain-password, or `--yes` fallback exists.

## Compile-time dependency DAG

```text
cmd/youtrack-agent-cli -> cli
cli -> {application, output, errx}

application -> {profile, auth, oauth, writepolicy, intent, mutation,
                approval, journal, skills, youtrack, restexec, reconcile}

mutation -> {intent, errx}
restexec -> {mutation, youtrack, errx}
reconcile -> {mutation, youtrack, errx}
approval -> {intent, errx}
journal -> {intent, lockfile, errx}
auth -> {profile, lockfile, errx}
oauth -> {endpoint, errx}
youtrack -> {endpoint, errx}
writepolicy -> {profile, lockfile, errx}
profile -> {endpoint, lockfile, errx}
skills -> {assets, lockfile, errx}
output -> errx
endpoint -> errx
lockfile -> errx
errx -> standard library only
```

`application` is the only orchestration owner. `cli` parses and renders only. `mutation` owns consumer-defined interfaces whose concrete implementations are injected by `application`:

- `Executor`: preflight plus exactly one typed execute operation;
- `Reconciler`: bounded read-only evidence collection;
- `Approver`: display/sign or verify a receipt, with no journal access;
- `Journal`: compare-and-swap transitions under one transaction API;
- `CredentialProvider` and `PolicyChecker`: minimum operations needed by the application service.

The interfaces contain at most one to three methods. `internal/youtrack` is a fixed-origin transport/model boundary and imports neither profile nor auth. `internal/cli` does not import `net/http`. Architecture tests enumerate allowed internal edges and fail on every unlisted dependency.

## Journal transaction and lock contract

All durable mutation operations use one journal transaction API with revision-based compare-and-swap. When multiple locks are needed, the global order is profile, policy, then one plan/receipt journal lock. Subsets preserve that order. No remote request or approval UI runs while the journal file lock is held.

`prepare` acquires profile, policy, and journal locks, commits the authoritative canonical plan as `prepared`, then exports a 0600 copy. Export failure does not erase or duplicate the journal record.

`confirm` has two phases. It first snapshots the prepared plan under profile/policy/journal locks and releases all locks. The native helper displays that one immutable snapshot, hashes those exact bytes into the receipt, and signs the deterministic unsigned receipt. The service reacquires the locks in the same order, revalidates unchanged identity, policy, plan hash, state, and revision, then atomically stores the receipt and moves to `confirmed`. Concurrent confirmation loses the compare-and-swap and cannot mint a second usable receipt.

`apply` holds the profile and policy locks while it validates the bound credential and remote preconditions. It briefly acquires the journal lock to atomically consume the receipt and persist `in_flight`, releases the journal lock, sends at most one mutation while retaining the outer identity/policy locks, then reacquires the journal lock to record the outcome. Once `in_flight` is durable, the nonce is never reusable and the state never returns to `confirmed`.

`reconcile` snapshots an eligible state and revision, performs bounded reads without the journal lock, then compare-and-swaps the evidence and next state. Repeated reconciliation is read-only and idempotent. Terminal states return their existing record without additional network activity unless the operator explicitly requests a fresh evidence collection.

## Complete state table

| From | Event | To | Recovery semantics |
|---|---|---|---|
| none | valid offline prepare committed | `prepared` | Export can be repeated from the journal; no network or credential was used. |
| `prepared` | trusted helper receipt committed | `confirmed` | Exactly one receipt/key generation is retained. |
| `prepared` | operator cancellation or expiry | `canceled` / `expired` | Terminal; create a new plan. |
| `confirmed` | receipt consumed before dispatch | `in_flight` | Durable non-replay point. |
| `confirmed` | operator cancellation or expiry before consumption | `canceled` / `expired` | Terminal; no mutation attempt. |
| `in_flight` | definitive rejection proving no mutation | `failed_before_mutation` | Terminal; a new plan is required. |
| `in_flight` | verified success recorded | `applied` | Non-replayable; proceed to bounded verification. |
| `in_flight` | timeout, reset, unexpected/invalid response, or uncertain send | `ambiguous` | Never retry; reconcile. |
| `in_flight` | process crash or local journal failure | remains `in_flight` | On restart it is interpreted as ambiguous and is never replayable. |
| `applied` | exact bounded verification matches | `reconciled` | Terminal known-applied. |
| `applied` | verification cannot establish unique state | `operator_resolution_required` | No automatic retry. |
| `ambiguous` | bounded evidence uniquely proves application | `reconciled` | Terminal known-applied. |
| `ambiguous` | bounded evidence proves definitive non-application | `resolved_not_applied` | Terminal; only a new plan may write. |
| `ambiguous` | zero/non-unique/unsupported evidence | `operator_resolution_required` | No automatic retry. |
| `operator_resolution_required` | explicit local operator resolution with evidence digest | `resolved_applied` / `resolved_not_applied` | Terminal audit record; this action never contacts YouTrack. |

A verified remote success followed by stdout failure or journal-finalization failure emits `WRITE_APPLIED_LOCAL_FAILURE` with do-not-retry guidance. The durable record may remain `in_flight`; restart still treats it as non-replayable and requires reconciliation.

## First implementation slice

1. Scaffold the canonical harness and machine contract.
2. Add the portable embedded skill and safe installer.
3. Implement endpoint/profile/project-policy schemas and architecture tests.
4. Implement Keychain-bound public-client OAuth Authorization Code + PKCE and permanent-token fallback.
5. Implement bounded exact REST inspection and offline intent preparation.
6. Implement the journal state machine and fail-closed approval interfaces.
7. Run Gate 1A. Enable `confirm/apply` only after it passes; otherwise ship them disabled with a typed error.
8. Add the REST executor in order: update, create, then comment only after its compatibility gate.
9. Run contract, security, primary, and independent adversarial review gates before packaging.

The REST executor is always labeled `rest-best-effort`. Strict atomic project enforcement remains a later custom YouTrack MCP executor because a local REST preflight cannot close the concurrent issue-move race.
