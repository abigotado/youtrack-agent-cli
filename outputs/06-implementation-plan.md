# Implementation plan and decision gates

Status: In progress; existing phases 2-4 reach the fail-closed Gate 1A
boundary, while the native coordinator, profile-expiry enforcement, Gates, and
writes described below are not implemented

## Accepted remaining order

The trust and activation dependencies are now fixed:

1. Freeze the signed bundle, Team ID parameter, peer requirements,
   data-protection Keychain namespace, enrollment/rotation/recovery, and package
   topology in `docs/gate1a-trust-root.md`, with complete normative codecs in
   `docs/gate1a-registry-protocol.md` and
   `docs/gate1a-artifact-authorization.md`.
2. Implement full durable receipt verification and two-phase confirmation behind
   dependency injection while the current repository remains
   `approval.Unsupported`.
   Bind E1/E2 receipts to their canonical Gate context and retained signed-token
   authority branch so the unpublished candidate can exercise the same v3
   receipt protocol before provisional authorization exists. Reject Gate
   contexts from production, smoke, and post-grant authority paths.
3. Implement the signed native helper, OS-protected approval-key registry,
   bounded Go client, and non-distributed operator runner. Keep the fresh-
   `LAContext` UI-allow signing lookup separate from UI-fail/no-context
   existence and delete queries; use only the returned `SecKey` for one
   `SecKeyCreateSignature` call, invalidate the context on every outcome, and
   freeze disjoint vectors for those boundaries.
4. Produce one unpublished signed/notarized/stapled artifact with the ordinary
   production confirmation path wired; create and retain its exact app-only
   payload archive, then bind that archive and the exact Apple code identities
   in the descriptor before E1; pass complete runner/session-bound E1
   and clean-reset E2 Gate 1A evidence sets on every declared architecture,
   including the closed first-install/reinstall/rollback/replacement/uninstall
   set, Keychain-migration cancellation/interruption/partial-failure set, and
   all 100 profile-expiry boundary vectors;
   only then issue the confirm-only provisional authorization, pass its
   network-disabled ordinary-command smoke set. Begin each smoke/post-grant
   capability plan with the token/context-limited exact-artifact revision-1
   enrollment from a canonical empty five-domain inventory, bind its retained
   registry snapshot to every later observation/index/set, end with a proved-
   empty cleanup, and accept assertions only in a case-final runner evaluation
   after all operation/transcript results. Then issue the production
   activation grant. Run the grant-bound ordinary-command verification on every
   architecture under its deny-only runner token; failed evidence quarantines
   the unpublished grant and candidate.
5. Implement canonical fingerprints, typed `issue.create`, bounded
   reconciliation, and the sole launchd-managed helper's serialized
   apply-authority executor plus fixed-active cross-client Keychain coordinator
   while the current repository apply remains disabled. The executor guard
   spans every acquisition and exact read/delete cleanup interval. Freeze the
   exact Keychain dictionaries/projections and active/permit/closed records;
   add canonical journal v2 with strict atomic prepared-only v1 migration and
   quarantine; add only `mutation authority status` and trusted-UI
   `mutation authority recover`; update `.agents/rules/cli-contract.md`, extend
   the authoritative `internal/errx` reason/exit registry and both
   contract/command reference generators, regenerate the tracked
   `.cursor/rules` mirror through `.agents/scripts/sync-rules.py`, and pass the
   rule-sync and machine-local provider-compiler checks;
   require `confirmed -> in_flight` before the sole request-bound permit and
   durable close before releasing registry serialization.
6. Produce an unpublished exact candidate with ordinary `issue.create` apply
   wired, rerun the two-pass Gate 1A sequence for its new descriptor, then run
   the closed 26-case two-pass live Gate 1B on a disposable YouTrack 2026.2
   project. Each fresh E1/E2 host starts with the compiled token-bound enrollment
   case and retains its baseline registry snapshot in observations, index, and
   evidence set. Later transition evidence records the planned registry changes;
   the baseline remains enrollment provenance. The suite includes
   Remote MCP/OAuth host tests, both apply-first and registry-first
   rotation/revocation/recovery orderings, invalid-enrollment contention before
   ledger read, crash before permit, crash after permit before send, crash after
   send before outcome, crash after durable outcome before close, close-add
   ambiguity, crash after close before active deletion, active-delete ambiguity,
   acquisition attempted between active equality read and delete with zero
   competing Keychain work before executor-guard release, restart
   fencing/durable close, exact binary barrier/trace assertions, exact
   authority status/recover envelopes/exits, and v1-to-v2 migration/quarantine.
   Issue only the `issue.create` provisional authorization
   after E2, run the exact per-architecture network-isolated dispatch-boundary
   smoke under the same setup-first/snapshot-bound/cleanup-last case contract,
   and issue the production activation grant only after that complete
   evidence set passes. Run the grant-bound per-architecture ordinary-command
   verification and quarantine any failure. Implement final deletion only as
   the distinct signed `stage_cleanup` IPC: retain its complete attributed
   intent/progress outside disposable state before the first delete, serialize
   exact-read/byte-compare/delete in the sole helper executor, and require the
   durable acknowledged fixed-attempt marker before invocation. Recovery of an
   unresolved marker may only terminalize exact absence or quarantine; it must
   never re-delete. Publish both marker and cross-bound `delete_pending`
   progress from same-directory exclusive `0600` no-follow temps with canonical
   write/file fsync, collision-safe no-replace publication, directory fsync,
   and exact no-follow reopen before ACK. Destroy/quarantine rather than touch
   unknown state.
7. Sign the root publication envelope over the exact post-grant plan and
   complete evidence set, then reuse the retained app-only payload to build one
   outer delivery archive containing the app, authority objects, envelope,
   plan, and closed evidence tree without changing app bytes;
   keep update/comment disabled or require the strict custom-MCP transaction
   gate.
8. Publish those exact signed artifacts and an audited SHA-pinned Cask/private
   tap last.

Gate 1A cannot pass before durable confirmation exists in the candidate's
ordinary production entry point. The unpublished candidate is the object under
test; failure discards it, while PASS qualifies its exact descriptor/code
identities without a
post-Gate code change. Neither Gate token nor provisional authorization is
production authority. The offline root signs a capability-specific provisional
authorization only after E2; a separate content-addressed black-box smoke set
must exercise that deny-only branch on every declared architecture before the
root signs a production activation grant. The exact grant-bound production
context must then pass a separate per-architecture ordinary-command
verification in the trusted disposable pre-publication environment; only the
later publication envelope binds that evidence. Packaging the envelope and
bound evidence in an archive whose checksum is pinned by the Cask avoids a
recursive hash cycle. Gate 1B
applies the same rule to the first remote mutation.

## Gate 0 — operator architecture decision

This gate was approved for local repository and implementation work. Installing
a YouTrack app, configuring a live instance, or enabling mutations still
requires the remaining explicit decisions:

- approve/revise ADR-001;
- choose executor assurance: REST with accepted issue-move TOCTOU residual risk, or custom MCP for strict atomic project policy;
- keep `issue.create` as the selected Stage A mutation and decide separately
  whether update/comment may accept REST TOCTOU or require strict custom MCP;
- decide receipt-marker policy;
- state whether simultaneous same-instance multi-account MCP use is mandatory;
- state whether Server with external Hub must be supported in the first MVP;
- identify the first non-production YouTrack instance and test accounts for later validation.

Deliverable at this gate: this design packet only.

## Phase 1 — executable specifications and compatibility spikes

After Gate 0 approval:

1. Freeze profile, plan, receipt, journal, and result JSON schemas.
2. Define canonicalization rules and golden vectors for payload/expected-state hashes.
3. Test Codex and Claude Code against a non-production YouTrack 2026.2 instance:
   - positive `tools=` filtering;
   - exact discovered tool set;
   - protocol-level negative call to hidden `update_issue` with a guaranteed nonexistent target, requiring rejection before domain validation;
   - output-schema behavior;
   - OAuth Authorization Code + PKCE;
   - preregistered client callbacks;
   - CIMD with Codex when enabled;
   - two accounts on the same endpoint;
   - identity persistence after restart.
4. Verify Cloud and one Server/base-path URL shape; if external Hub is in scope, separately verify pinned service/MCP/REST/OAuth origins and redirect policy.
5. Record observed behavior and version numbers; revise the ADR if any safety assumption fails.

Exit criteria:

- bare endpoint demonstrably exposes the documented mutation surface or is otherwise treated as unsafe without relying on the test result;
- allowlisted endpoint returns exactly the six tools;
- hidden mutation calls are rejected, or strict read-only is supplied by host runtime enforcement/read-only YouTrack permissions;
- account identity is stable and distinguishable;
- no token appears in config/log/process arguments;
- same-instance multi-account strategy is selected from observed client behavior.

## Phase 2 — provider-neutral skill package

1. Create the canonical `youtrack-agent` skill folder.
2. Keep `SKILL.md` concise and route detailed modes into the four proposed references.
3. Add no networked script and no credential setup script.
4. Validate the skill structure with the Codex skill validator.
5. Symlink the same test package into isolated Codex and Claude Code configuration homes.
6. Run behavioral evals for profile selection, bounded search, exact reads, injection handling, and MCP-write refusal.

Exit criteria:

- identical source folder works in both hosts;
- no host-specific frontmatter is required for core behavior;
- injection corpus causes no command, URL fetch, profile change, or mutation;
- an advertised write tool is refused and diagnosed as configuration drift.

## Phase 3 — CLI foundation and authentication

1. Choose a memory-safe implementation language and a minimal dependency set.
2. Implement non-secret profile parsing with separately pinned YouTrack service URL, MCP URL, REST base, OAuth issuer/endpoints, and allowed redirect origins.
3. Implement OS secret-store abstraction:
   - macOS Keychain first;
   - explicit unsupported result on other systems until adapters exist;
   - no plaintext fallback.
4. Implement OAuth Authorization Code + PKCE with strict state/callback validation and refresh handling.
5. Add permanent-token import only through trusted interactive input into Keychain.
6. Implement `auth whoami` against `/api/users/me?fields=id,login,email` and bind the result to the profile.
7. Implement strict redaction and structured diagnostics.

Security review gate:

- independent review of OAuth, callback listener, Keychain access control, redaction, redirect policy, TLS/custom-CA handling, and dependency supply chain.

Exit criteria:

- credentials never reach stdout/stderr, argv, profile files, crash dumps under normal configuration, or model-visible output;
- profile/account/origin mismatch fails closed;
- logout removes only the selected profile credential.

## Phase 4 — offline plan, confirmation, and journal

1. Implement strict per-operation schemas and canonical JSON.
2. Allocate `plan_id` during prepare and include it in the final marker/body before canonicalization and hashing.
3. Implement `prepare --offline` under a test that denies all network syscalls.
4. Implement human-readable plan rendering with golden tests.
5. Generate a signing key whose use is protected by OS user-presence policy (macOS Keychain/Secure Enclave + LocalAuthentication for the first adapter).
6. Implement a trusted approval UI that loads, displays, and signs one immutable in-memory snapshot, outside agent-controlled terminal input, with no noninteractive bypass.
7. Implement short-lived signed receipts and atomic nonce journal states.
8. Implement the helper-owned coordinator shared by apply and every registry
   commit: fixed active-account acquisition, exact-request permit after
   `in_flight`, same-connection fences, durable closed record, narrow active
   cleanup, and restart recovery that never resumes a send.
9. Bind the CMS-validated helper profile expiry into the descriptor and enforce
   the strict cutoff at Gate/publication/install/runtime and twice around
   permit/send.
10. Add crash-consistency tests at every journal, active, permit, send,
    outcome, close, and cleanup boundary.

Exit criteria:

- any one-bit payload/profile/precondition change invalidates the receipt;
- receipt replay is rejected;
- expired receipt is rejected;
- any display-to-sign file change is irrelevant because the UI signs the already displayed immutable bytes;
- the agent cannot mint a receipt through piped input, PTY injection, or a normal tool call;
- offline preparation succeeds with networking disabled and never reads a credential.

## Phase 5 — schemas and Stage A executor operations

Implement in risk order:

1. Project custom-field schema snapshot and immutable field/value ID resolution.
2. `issue.create` — project ID is part of the mutation, but ambiguous-create reconciliation is harder.
3. `issue.update` — strongest exact before/after state reconciliation, but REST mode has project-move TOCTOU.
4. `comment.add` — exact target, but the documented comments collection lacks author/time filtering and ordering guarantees.

For each operation:

- add minimal executor request/response schemas and minimal REST `fields` where REST is selected;
- disable mutation retries;
- bind project ID+key, field/value IDs/types, and schema hash into the plan;
- enforce project policy according to the selected executor assurance level;
- verify expected state before send;
- acquire the helper coordinator, persist `in_flight`, issue one permit for the
  exact request, send one mutation, persist outcome and durable close, then
  release active;
- reconcile exact touched state;
- inject failures before send, during send, after server commit, and before journal commit;
- require a fresh plan after any state mismatch.

REST executor acceptance additionally requires:

- an explicit operator record accepting the issue-move race for update/comment or a scope limited to operations where the project ID is part of the mutation;
- no claim that the local preflight is atomic with the POST;
- comment reconciliation to remain unresolved unless an instance-tested bounded ordering/window algorithm or activity query proves a unique marker match.

Custom MCP executor acceptance additionally requires:

- Low-level Admin approval for a non-production app install;
- server-side signature/schema/account/project validation;
- current-project check, nonce consumption, and mutation in one transaction;
- a compatibility test confirming transaction rollback on any policy/receipt failure;
- explicit `customToolPackages=` exposure and no predefined mutation tools.

The YouTrack REST API requires explicit `fields` to return more than entity IDs and uses `$top`/`$skip` for collection pagination. Keep reconciliation queries bounded and field-minimal. See [Fields Syntax](https://www.jetbrains.com/help/youtrack/devportal/api-fields-syntax.html) and [Pagination](https://www.jetbrains.com/help/youtrack/devportal/api-concept-pagination.html).

Exit criteria:

- recorded mutation count is never greater than one per receipt under fault injection;
- ambiguous response never triggers retry;
- update reconciliation distinguishes touched-field success from unrelated concurrent changes;
- create/comment reconciliation returns `operator_resolution_required` rather than guessing when evidence is non-unique;
- strict profiles demonstrate that a concurrent project move cannot escape the allowlist.

## Phase 6 — host integration and end-to-end validation

1. Configure non-production read-oriented MCP profiles with positive endpoint allowlists and a host runtime allowlist/read-only identity.
2. Add Codex client-side `enabled_tools` as defense in depth.
3. Configure Claude Code user-scoped Remote MCP and exact permission behavior.
4. Exercise the same acceptance suite in both hosts.
5. Verify no issue content can invoke CLI writes without explicit user intent and a human receipt.
6. Verify profile and account labels appear in every result and plan.

Exit criteria:

- all read and write safety scenarios pass in both clients;
- the installer/host gate detects tool drift, hidden-call behavior, and identity mismatch;
- observed network traces show only pinned service/OAuth origins and at most one mutating request.

## Phase 7 — pilot and operational hardening

1. Pilot with one non-production instance, two accounts, and one allowlisted project.
2. Add signed release artifacts, SBOM, dependency pinning, and reproducible-build targets.
3. Define token/receipt signing-key rotation and journal backup/retention.
4. Document incident response for leaked credentials and unresolved ambiguous writes.
5. Add telemetry that contains only non-secret IDs, state transitions, timings, and status codes.
6. Run an independent security review and threat-model update before production use.
7. Publish only the first write-capable build; keep any second build blocked
   until its release-rollover ADR and Gate cover old signed pairs, approval
   state, credentials, and stale tokens.

## Phase 8 — custom MCP app RFC or hardening

If Gate 0 selects strict atomic project policy, this phase moves before production use (and may move before the REST pilot). Otherwise, after the CLI pilot evaluate whether centralized server-side policy justifies a YouTrack app. The RFC must answer:

- how a human receipt is minted outside the model and verified server-side;
- how project allowlists are administered and audited;
- how global tool availability is constrained;
- how each instance receives upgrades and rollback;
- how the app prevents replay and reconciles ambiguous client responses;
- whether it can reuse the same operation/receipt schemas as the CLI.

Do not copy built-in mutation scripts and call them “guarded” without these controls.

## Validation matrix

| Area | Minimum validation |
|---|---|
| MCP surface | Exact `tools/list` snapshot plus injected-extra-tool failure |
| Hidden MCP call | Direct disallowed `tools/call` negative test on disposable non-production target |
| Search bounds | Limit default/max, no automatic second page, minimal fields |
| Identity | Wrong user, expired auth, two accounts, restart persistence |
| Injection | Markdown/HTML/code/link/tool-instruction corpus from issue and comment fields |
| Profile policy | Wrong service/MCP/REST/OAuth endpoint, external Hub, redirect, wrong project ID/key, renamed/moved project |
| Offline plan | Network denied, credential store denied, deterministic hash |
| Receipt | Tamper, expiry, replay, wrong profile/account/project/payload/schema/precondition, display-to-sign swap |
| Mutation | Pre-send failure, server rejection, timeout before/after commit, process crash |
| Reconciliation | Unique success, zero match, multiple match, unspecified comment order, unrelated concurrent update |
| Local authority | Single launchd helper; serialized guard; acquisition-between-read/delete ABA denial; exact status/recover JSON + invocation meta/flags/exits; prepared-only v1 migration and all-other-state quarantine |
| Release stages | Exact setup-first 5/6/6/6 case lists; distinct token-bound `stage_cleanup`; immutable attributed intent/progress; exact read/compare; no-follow temp + file/directory fsync + exclusive publish + reopen-verified marker/pending-progress pair before ACK and sole delete; partial-pair/pre-ACK fault quarantine with zero delete; unresolved-marker absence terminalization and present/unknown quarantine with zero re-delete; exhaustive operation-result shapes/domain; final empty inventory and case-final assertions |
| Secrets | Config/argv/log/error/crash-output scan |
| Portability | Same skill scenarios in Codex and Claude Code |

## Initial effort order

The shortest safe path from the current repository is:

```text
trust/storage/package topology
  -> exact registry codec + pinned artifact-authorization root
  -> durable confirmation, injected and unwired
  -> native helper + protected key registry + operator runner
  -> exact Keychain dictionaries/projections + apply-authority coordinator
  -> signed/stapled candidate + retained app-only archive
  -> descriptor with production confirm wiring and archive digest
  -> complete per-architecture Gate 1A E1 + clean-reset E2 evidence sets
  -> confirm-only provisional authorization + black-box smoke evidence set
  -> confirm-only production activation grant
  -> per-architecture post-grant production-context verification
  -> fingerprints + disabled issue.create engine
  -> new exact descriptor with production issue.create wiring
  -> per-architecture two-pass Gate 1A rerun + live YouTrack Gate 1B sets
  -> Gate 1B apply/registry ordering + permit/crash/restart/ABA fencing cases
  -> issue.create provisional authorization + dispatch-boundary smoke set
  -> issue.create production activation grant
  -> per-architecture post-grant production-context verification
  -> update/comment risk decision or strict custom MCP
  -> publication envelope + complete verification tree inside a SHA-pinned
     Cask archive/private tap
```

The custom YouTrack app is outside the critical path only when the operator explicitly accepts the REST executor's project-move TOCTOU residual risk. It is on the critical path for strict atomic project allowlisting.
