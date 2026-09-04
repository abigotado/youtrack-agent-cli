# Gate 1A exact-artifact authorization

Status: normative design for Gate 1A; authority key not enrolled, no Gate token
issued, and no production artifact authorized. `approval.Unsupported` remains
the only production adapter.

Developer ID identity, Team ID, bundle identifiers, and build number establish
publisher and release identity, but they do not distinguish a Gate-tested
binary from a separately rebuilt binary with the same semantic identity. This
contract adds an independent, exact-artifact authorization layer without
placing a self-referential manifest inside the signed app bundle.

## Root of authorization

There is exactly one first-release artifact-authorization root:

- algorithm: Ed25519 as specified by RFC 8032, pure mode, with 32-byte public
  keys and 64-byte signatures;
- key ID: `YTAAK-` followed by lowercase SHA-256 of the exact 32 public-key
  bytes;
- verifier input: one literal key ID and one literal unpadded base64url public
  key compiled into the CLI, helper, Gate runner, and publication verifier;
- custody: the private key is generated and held in an operator-controlled
  offline or hardware-backed signing environment, never exported to a
  developer workstation, CI runner, release archive, Gate fixture, or app;
- use: the signing environment accepts only an already canonical object,
  displays its domain and SHA-256, and emits one signature after explicit
  operator approval. It does not build, edit, test, upload, or install code.

No fallback key, key search, certificate-chain substitution, online key
discovery, environment override, or trust-on-first-use path exists. There is no
root-key rollover in the first write-capable release. Loss, compromise, or any
requested root change blocks production authorization and requires a separate
rollover ADR and a new full Gate. The repository currently contains no
operator root public key; Gate tooling must fail closed until one literal key
and its derived key ID are committed and independently verified. Test keys use
a disjoint `test-only` domain and can never satisfy these domains.

The clean Gate host, its signed runner, and the operator supervising the run
are trusted release inputs. Content addressing makes collected evidence
tamper-evident after capture; it does not prove that a compromised runner or OS
executed a test honestly. The offline signer must require an operator-observed
clean/reverted host and review the complete evidence set, but its signature
does not remove this trust assumption. Compromise or suspected compromise of
the Gate host/runner invalidates the run and all derived E1/E2 evidence.

## Canonical signed objects

All objects are compact UTF-8 JSON with fields in the exact listed order, no
leading/trailing bytes, and no insignificant whitespace. Decoders reject a
non-object top level, missing, duplicate, unknown, or reordered fields,
alternate escaping or number encoding, and trailing data. They re-encode and
require byte equality. Strings are printable ASCII without JSON escapes.
Digests are 64 lowercase hexadecimal characters. Signatures are unpadded
base64url of exactly 64 bytes and are decode/re-encode checked.

Signed bytes are the ASCII domain including its final NUL byte followed by the
complete canonical unsigned object. The signed object appends `signature` as
its final field. Each signed object is capped before parsing or allocation:

| Object | Domain | Maximum bytes |
| --- | --- | ---: |
| E1 Gate token | `YTA-GATE-E1-V1\0` | 4,096 |
| E2 Gate token | `YTA-GATE-E2-V1\0` | 4,096 |
| production authorization | `YTA-PRODUCTION-AUTHORIZATION-V1\0` | 8,192 |
| activation-smoke token | `YTA-ACTIVATION-SMOKE-V1\0` | 4,096 |
| publication envelope | `YTA-PUBLICATION-ENVELOPE-V1\0` | 8,192 |

The descriptor is not itself root-signed. Its exact SHA-256 is the subject of
each signed token or authorization. It is capped at 16,384 bytes and its digest
is SHA-256 over the exact raw canonical descriptor JSON, with no domain prefix.
This permits multiple Gate stages to bind the identical descriptor without
changing signed code.

Unless a field below defines a narrower grammar, every time is exactly UTC
RFC 3339 at whole-second precision (`YYYY-MM-DDTHH:MM:SSZ`), every digest is 64
lowercase hexadecimal characters, and every nullable value is literal JSON
`null`. `authority_key_id` is exactly `YTAAK-` followed by 64 lowercase
hexadecimal characters and must equal the pinned public-key digest.
`gate_runner_unique` is exactly 40 lowercase hexadecimal characters encoding
the 20-byte `kSecCodeInfoUnique` value. `gate_session_id` is canonical unpadded
base64url of exactly 32 bytes (43 characters). Gate plans and target objects
are each capped at 65,536 bytes; their identifiers are SHA-256 of their exact
canonical bytes. An evidence index contains 1..256 observations and references
at most 1,024 regular files, each at most 8 MiB and at most 256 MiB in
aggregate. All counts and byte caps are checked before proportional allocation
or file reads.

The Gate 1B target object is compact canonical JSON capped at 4,096 bytes with
these fields in order: `schema_version` integer `1`, `target_type` exactly
`disposable_youtrack_2026_2`, `service_url`, `rest_url`, `oauth_issuer_url`,
`account_id`, `project_id`, `project_key`, `target_nonce`, and `expires_at`.
URLs use the approval URL grammar; REST is the exact service URL plus `/api`;
the OAuth issuer is the separately pinned HTTPS origin accepted by the Gate
plan. Identifiers use the mutation-plan grammar, and `target_nonce` is
canonical unpadded base64url of 32 random bytes. The target contains no token or
secret. `gate_target_sha256` is SHA-256 of those exact bytes.

## Exact artifact descriptor

The descriptor fields are:

1. `schema_version`, integer `1`
2. `descriptor_type`, exactly `youtrack_agent_exact_artifact`
3. `product_version`, canonical SemVer without build metadata, at most 64 bytes
4. `release_build`, positive decimal string with no leading zero, at most 18 bytes
5. `team_id`, exactly 10 uppercase ASCII letters or digits
6. `outer_identifier`, exactly `io.github.abigotado.youtrack-agent`
7. `helper_identifier`, exactly `io.github.abigotado.youtrack-agent.approval`
8. `minimum_macos`, `major.minor` decimal, at most 16 bytes
9. `architectures`, a JSON array in exact order `arm64`, then `x86_64`, omitting an architecture only when the release does not contain it
10. `code_slices`, ordered JSON array described below
11. `outer_entitlements_sha256`
12. `helper_entitlements_sha256`
13. `helper_profile_sha256`
14. `outer_designated_requirement_sha256`
15. `helper_designated_requirement_sha256`
16. `app_payload_archive_sha256`
17. `notary_submission_id`, canonical lowercase UUID
18. `notary_log_sha256`
19. `stapled_ticket_evidence_sha256`
20. `created_at`, UTC RFC 3339 whole seconds

The structured arrays have no extension points. `architectures` has the order
above. `code_slices` entries are ordered first by role `outer`, `helper`, then
by the descriptor architecture order. Every entry has these fields in order:

1. `role`, `outer` or `helper`
2. `architecture`, `arm64` or `x86_64`
3. `identifier`, the exact matching identifier above
4. `team_id`
5. `release_build`
6. `executable_sha256`
7. `ksec_code_info_unique`, lowercase hex of the exact
   `kSecCodeInfoUnique` bytes returned for that architecture
8. `cdhashes`, an array ordered by ascending Security.framework digest
   algorithm number

Each `cdhashes` entry contains `digest_algorithm` as a JSON integer in
`1..255` and `value` as exactly 40 lowercase hexadecimal characters encoding
the 20-byte cdhash, in that order. Each role/architecture pair occurs exactly
once, so `code_slices` has exactly twice the declared architecture count; each
`cdhashes` array has `1..8` entries. The array contains every value
returned by `kSecCodeInfoCdHashes` paired positionally with
`kSecCodeInfoDigestAlgorithms`; duplicates, omissions, empty arrays, or an
unknown/unrepresentable algorithm fail descriptor creation. No implementation
parses Mach-O or CodeDirectory structures directly to invent these values.

For a universal binary the release tool asks Security.framework for each
declared architecture and records each architecture-specific result. At
runtime, each peer obtains the connection-bound guest from the audit token,
validates its Developer ID requirement, selects the running architecture, and
requires `kSecCodeInfoUnique` and the complete ordered cdhash set to equal the
descriptor entry. Both peers separately verify their own static signed code
against the same descriptor before accepting the connection. They exchange
and compare the descriptor SHA-256 inside the authenticated handshake; any
missing entry, differing digest, mixed descriptor, unsupported architecture,
or Security.framework ambiguity fails closed.

The semantic identifier, Team ID, build, entitlements, provisioning profile,
and designated-requirement hashes are defense-in-depth evidence and Gate
diagnostics. The Security.framework unique identifiers and cdhash sets are the
runtime exact-code authority. Executable and archive SHA-256 values bind
publication and offline reproduction; they do not replace runtime code-signing
validation.

The descriptor is created only after signing nested code first, signing the
outer app last, notarization, ticket stapling, and final signature validation.
Adding a descriptor inside the app afterward would change its resource seal.
It therefore remains detached.

## Detached layout and race-free reads

The app-only payload archive contains exactly one top-level
`YouTrackAgent.app/` and excludes every descriptor, token, authorization,
publication envelope, Gate runner, and Gate fixture. The archive format is a
release-packaging choice, not an authority codec. `app_payload_archive_sha256`
is SHA-256 of the exact opaque archive file bytes produced for the candidate;
the file is capped at 1 GiB and retained as evidence. Verifiers never attempt
to reconstruct those bytes from an extracted app.

A production delivery archive contains:

```text
YouTrackAgent.app/
authorization/artifact-descriptor.json
authorization/production-authorization.json
```

The descriptor and authorization are outside the signed app and outside the
app-only payload archive. The publication envelope is a separate release asset
and is never placed in either archive. The outer archive is likewise an opaque
release file capped at 1 GiB; its SHA-256 covers its exact downloaded bytes.
Thus no object contains a hash of bytes that recursively contain that object.

Archive hashes are pre-extraction publication/download evidence only. They are
verified against the retained release assets and, for the outer archive, by the
Cask before extraction. They are not runtime authority and are not recomputed
from an installed tree. Before packaging, the release verifier validates the
app-only archive and the app selected for the outer archive against the same
descriptor, Developer ID signatures, all-architecture code identities,
profile, notarization, and staple evidence. After extraction, installation and
runtime validation use those signed-code checks plus the exact root-signed
sidecar bytes. The code signature's sealed resources, not a home-grown tree
manifest or archive reconstruction, protect the installed app contents.

For a direct installation, the app and its sibling `authorization/` directory
remain under one installation root. For Homebrew, both remain in the same
versioned Caskroom root and `binary` links only the executable inside the app.
The CLI resolves its executable symlink to the signed app, ascends to that
single versioned root, and accepts no authorization directory outside it.

Every detached file is opened with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW` from an
already opened installation-root directory. Each path component is opened
relative to its parent file descriptor; `..`, empty components, symlinks, hard
links with link count other than one, non-regular files, group/world-writable
files, and owner mismatch are rejected. The verifier applies the raw size cap
to `fstat`, reads to EOF from that one descriptor, repeats `fstat`, and rejects
device/inode, size, mode, owner, or modification-time change. It never validates
one path and reopens another. Gate-only files use the same procedure in a
runner-created mode-`0700` session directory.

Detached files are untrusted until their canonical bytes and root signature
validate. A same-user attacker may replace or replay files, but cannot make a
different code digest satisfy a valid signed authorization.

## E1 Gate authorization

E1 permits only the exact descriptor to execute one named Gate suite. Its
unsigned fields are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `gate_e1`
3. `gate_id`, exactly `gate1a` or `gate1b`
4. `authority_key_id`
5. `descriptor_sha256`
6. `gate_plan_sha256`
7. `gate_target_sha256`, null for Gate 1A and the exact disposable
   instance/account/project policy digest for Gate 1B
8. `gate_runner_unique`
9. `gate_session_id`
10. `allowed_capability`, `confirm_only` for Gate 1A or `issue_create_gate`
    for Gate 1B
11. `allowed_network`, `none` for Gate 1A or `exact_gate_target` for Gate 1B
12. `issued_at`
13. `expires_at`

`gate_runner_unique` is lowercase hex of the signed Gate runner's
Security.framework unique identifier. `gate_session_id` is unpadded base64url
of 32 random bytes. E1 validity is at most 30 minutes.

The candidate accepts E1 only over an inherited, already connected local Gate
session descriptor. It validates the runner's connection-bound audit token,
exact runner identifier, Developer ID requirement, unique identifier, and a
challenge response bound to the session ID. A token copied to another process
or session is unusable. E1 cannot be loaded from the production authorization
path and is never shipped.

Under a Gate 1A E1 token, the complete clean-host Gate 1A suite runs against
the normal CLI confirmation command and real signed helper/Keychain boundary;
network creation is denied by the process sandbox. A Gate 1B E1 token is issued
only for a candidate that has already completed the two-pass Gate 1A sequence;
it permits the ordinary one-shot `issue.create` path only against the exact
disposable target named by `gate_target_sha256`. Every other capability or
origin fails closed. A pass records the descriptor, Gate ID, token, plan and
target digests, fixture hashes, OS/architecture, times, and result in immutable
evidence.

## E2 Gate authorization

E2 exists only after a complete E1 pass for the same descriptor, Gate ID, plan,
target, and capability. It permits a clean-reset repetition of that complete
suite solely inside one new Gate runner session. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `gate_e2`
3. `gate_id`, exactly `gate1a` or `gate1b`
4. `authority_key_id`
5. `descriptor_sha256`
6. `gate_plan_sha256`
7. `gate_target_sha256`, with the same null/non-null rule as E1
8. `e1_evidence_sha256`
9. `gate_runner_unique`
10. `gate_session_id`
11. `allowed_capability`, exactly the matching E1 capability
12. `allowed_network`, exactly the matching E1 network policy
13. `issued_at`
14. `expires_at`

E2 has the same 30-minute maximum and runner/session checks as E1. The run
starts from another clean host or freshly reverted snapshot and repeats every
ordered observation in the same content-addressed Gate plan. Gate 1A remains
network-free. Gate 1B again permits only the exact disposable target, performs
its real one-shot write/reconciliation cases, and must start from a fresh
project fixture. It records the E2 token, prior E1 evidence, descriptor, full
rerun evidence, network transcript, and target reset. A partial, cached, or
smoke-only second pass is invalid.

E1/E2 are capabilities of a signed runner session, not production feature
flags. A Gate 1B token can exist only after the same descriptor's Gate 1A E1
and E2 evidence validate. Production authorization rejects all Gate token types
and domains. The release binary contains no environment switch that converts a
Gate token into production authority.

## Gate evidence codec

Each Gate run writes immutable content-addressed files and one compact
canonical evidence index. The index is capped at 65,536 bytes. Its fields are:

1. `schema_version`, integer `1`
2. `evidence_type`, exactly `gate_e1_pass` or `gate_e2_pass`
3. `gate_id`, exactly `gate1a` or `gate1b`
4. `descriptor_sha256`
5. `gate_token_sha256`
6. `gate_plan_sha256`
7. `gate_target_sha256`, null for Gate 1A and required for Gate 1B
8. `allowed_capability`, matching the Gate token
9. `prior_e1_evidence_sha256`, null for E1 and required for E2
10. `prerequisite_gate1a_e2_sha256`, null for Gate 1A and required for Gate 1B
11. `gate_runner_unique`
12. `gate_session_id`
13. `macos_product_build_version`, printable ASCII, at most 32 bytes
14. `architecture`, `arm64` or `x86_64`
15. `fixture_set_sha256`
16. `started_at`
17. `finished_at`
18. `result`, exactly `pass`
19. `observations`, an ordered JSON array

Observation order is the order frozen by the Gate plan. Each entry contains
`name`, `command_sha256`, `stdout_sha256`, `stderr_sha256`, `exit_code`,
`transcript_sha256`, and `assertion_sha256`, in that order. Names are printable
ASCII of 1..128 bytes; digests use the common grammar; exit codes are JSON
integers `0..255`. Secret-bearing output is a Gate failure and is never made
acceptable merely by hashing it.

Gate 1A observations include every approval-protocol, code-identity, Keychain,
UI-presence, fail-closed, restart, and clean-host test. Gate 1B observations
include its ordinary CLI live-write, ordering, fault, and reconciliation cases.
E2 contains the complete repeated observation set for its Gate ID. Missing,
duplicated, reordered, or additional observations are a failure against the
content-addressed Gate plan.

An evidence digest is lowercase SHA-256 over the exact canonical index bytes.
Every referenced transcript/assertion/file is separately published by its
digest; before signing E2 or production authorization, the offline ceremony
verifies the entire closed set and recomputes the index. A detached index with
a missing or mismatched referenced file is invalid even if its own digest is
correct.

## Final production authorization

Only after E2 passes may the offline root sign a production authorization.
Its unsigned fields are:

1. `schema_version`, integer `1`
2. `authorization_type`, exactly `first_release_production`
3. `authority_key_id`
4. `descriptor_sha256`
5. `gate1a_e1_evidence_sha256`
6. `gate1a_e2_evidence_sha256`
7. `gate1a_plan_sha256`
8. `gate1b_e1_evidence_sha256`, null for a confirmation-only artifact
9. `gate1b_e2_evidence_sha256`, null for a confirmation-only artifact
10. `gate1b_plan_sha256`, null for a confirmation-only artifact
11. `app_payload_archive_sha256`, exactly the descriptor value
12. `approved_capability`, exactly `confirm_only` or `issue_create`
13. `minimum_registry_schema`, integer `1`
14. `minimum_receipt_schema`, integer `3`
15. `issued_at`
16. `release_not_before`

The authorization has no implicit wildcard and authorizes only the one
descriptor. A `confirm_only` authorization requires all three Gate 1B fields to
be null and can never authorize apply. An `issue_create` authorization requires
all three Gate 1B fields, whose evidence must name the same descriptor and a
valid prerequisite Gate 1A E2 digest. It never authorizes `issue.update`,
`comment.add`, or an arbitrary operation. `release_not_before` is UTC RFC 3339
whole seconds and is not before `issued_at`. The verifier requires the root key
ID, signature, descriptor/payload digests, schemas, and exact capability. It
then performs all static, runtime, peer, and registry-descriptor checks before
a confirmation or apply. There is no offline bypass when authorization is
absent or invalid.

The capability matrix is closed:

| Authorization value | `mutation confirm` | `mutation apply` for `issue.create` | Apply for `issue.update` / `comment.add` / other |
| --- | --- | --- | --- |
| `confirm_only` | allowed | denied before preflight | denied before preflight |
| `issue_create` | allowed | allowed only for a confirmed plan whose canonical operation kind is exactly `issue.create` | denied before preflight |

The Gate-only `confirm_only` capability has the same command meaning but is
runner/session-bound. Gate-only `issue_create_gate` includes confirmation and
apply only for canonical `issue.create`, only against `gate_target_sha256`, and
never grants update, comment, arbitrary REST, or production use. There is no
set union, implied wildcard, prefix matching, or caller-selected capability.

Signing final authorization changes no executable, bundle, payload archive,
or descriptor byte. A code rebuild, re-sign, re-notarization, restaple,
entitlement/profile change, or archive repack produces a different descriptor
and must start again at E1.

### Mandatory production-authorization smoke

The production authorization is signed only after all evidence above exists.
Before publication, a final root-signed activation-smoke token binds its exact
digest, descriptor, capability, Gate runner identity, fresh 32-byte session ID,
and a 30-minute expiry. This token can only further restrict an already valid
production authorization; it cannot grant a capability or substitute for one.
It is never shipped. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `activation_smoke`
3. `authority_key_id`
4. `descriptor_sha256`
5. `production_authorization_sha256`
6. `approved_capability`, exactly matching the production authorization
7. `gate_runner_unique`
8. `gate_session_id`, unpadded base64url of 32 random bytes
9. `loopback_origin`, null for `confirm_only` or exact
   `http://127.0.0.1:<port>` for `issue_create`
10. `dispatch_deny_code`, null for `confirm_only` or exactly
    `GATE_PRODUCTION_MUTATION_DISPATCH_DENIED` for `issue_create`
11. `issued_at`
12. `expires_at`, no more than 30 minutes after issue

For `confirm_only`, a clean network-disabled host drives the ordinary
`mutation confirm` entry point successfully and proves every `mutation apply`
path remains disabled. For `issue_create`, the harness first prepares a real
issue-create plan, then invokes exactly:

```text
youtrack-agent-cli --profile work mutation apply --plan-id <issue-create-plan-id>
```

Only an instrumented loopback read-only fixture is reachable. The harness
asserts the exact expected preflight reads. After authorization and preflight,
the activation-smoke restriction stops the ordinary executor at the final
mutating dispatch boundary with
`GATE_PRODUCTION_MUTATION_DISPATCH_DENIED`; the harness requires that exact
post-authorization result and zero mutating request-line, header, or body bytes.
Argument parsing, authorization, capability, journal, or preflight failure can
never count as the expected result. Tampered authorization, wrong descriptor or
running code, `issue.update`, and `comment.add` must fail before dispatch.

The activation-smoke branch and shared canonical positive/negative vectors are
part of the exact artifact's Gate plan. Because the smoke token is
runner/session-bound, domain-separated, offline-root-signed, and deny-only, it
cannot activate a production write or make a Gate token usable in production.

The smoke produces one canonical evidence object, capped at 16,384 bytes, with
these fields in order: `schema_version`, `evidence_type` exactly
`activation_smoke_pass`, `descriptor_sha256`,
`production_authorization_sha256`, `smoke_token_sha256`,
`approved_capability`, `gate_runner_unique`, `gate_session_id`,
`command_sha256`, `preflight_transcript_sha256` (null for `confirm_only`),
`dispatch_assertion_sha256` (null for `confirm_only`), `stdout_sha256`,
`stderr_sha256`, `exit_code`, `started_at`, `finished_at`, and `result` exactly
`pass`. Its evidence digest is SHA-256 of those exact canonical bytes.

## Publication envelope

After final authorization, release packaging creates the outer delivery
archive without changing its three contained inputs. The separate publication
envelope has these unsigned fields:

1. `schema_version`, integer `1`
2. `envelope_type`, exactly `youtrack_agent_publication`
3. `authority_key_id`
4. `product_version`
5. `release_build`
6. `git_commit_oid`, `sha1:` followed by the exact 40-character lowercase hexadecimal commit object ID used by the first release repository
7. `descriptor_sha256`
8. `production_authorization_sha256`
9. `activation_smoke_evidence_sha256`
10. `app_payload_archive_sha256`
11. `delivery_archive_sha256`
12. `delivery_archive_size`, positive JSON integer, maximum 1,073,741,824
13. `homebrew_cask_sha256`, exactly equal to `delivery_archive_sha256`
14. `published_at`, UTC RFC 3339 whole seconds

The release pipeline verifies all contained hashes and signatures, signs this
envelope offline, uploads the delivery archive, production authorization,
descriptor, envelope, and Gate evidence as distinct assets to a draft GitHub
release, verifies remote asset digests, and only then publishes an immutable
release. A mutable release, replaceable asset, moved tag, or mismatched remote
digest is not eligible for the Cask.

The Cask uses the literal delivery-archive SHA-256, never `:no_check`, installs
the complete signed app plus detached authorization directory without
re-signing or rebuilding, and links the contained CLI. Installation validation
must verify the root-signed publication envelope, production authorization,
descriptor, archive hash, Developer ID signatures, notarization, and exact app
code identities before guarded mutations are enabled. It never reconstructs an
archive hash from the installed tree. Homebrew's checksum is a useful
download-integrity check, but it is not a substitute for root authorization or
runtime peer verification.

## Cross-language conformance evidence

Implementation is blocked until one language-neutral fixture set is consumed
by the Go release/publication verifier and the Swift native verifier. Positive
vectors contain exact unsigned bytes, domain-prefixed signing bytes, signed
bytes, SHA-256 values, Ed25519 public key/signature, and parsed values for:

- one universal artifact descriptor and one single-architecture descriptor;
- Gate 1A and Gate 1B E1/E2 tokens plus both evidence-index variants;
- `confirm_only` and `issue_create` production authorizations;
- both activation-smoke token/evidence variants; and
- the publication envelope, app-payload archive, and outer delivery archive.

Both implementations must parse, validate, re-encode, hash, and verify every
positive vector identically. The fixture set evaluates every row of the
capability matrix against confirm and each supported apply operation, including
Gate target/session restrictions. The closed negative set independently covers:

- every object and field size boundary; missing, duplicate, unknown, reordered,
  escaped, whitespace-modified, noncanonical integer/null/base64url, and
  trailing JSON;
- wrong root key ID, public key, signature, domain, object type, descriptor, or
  payload digest, including cross-domain signature substitution;
- absent, duplicate, reordered, unsupported, or mismatched architecture,
  code-slice, digest-algorithm, `kSecCodeInfoUnique`, cdhash, Team ID,
  identifier, build, entitlement, profile, notarization, or staple evidence;
- sidecar traversal, symlink, hard link, wrong owner/mode/type, oversize,
  truncation, inode/metadata change, mixed descriptor, and reopen races;
- wrong Gate runner, connection audit token, session, nonce, expiry, Gate ID,
  plan, target, capability, or network policy, plus E1/E2 replay and evidence
  predecessor mismatch;
- Gate-token use on the production path, missing Gate 1A prerequisite for Gate
  1B, null/non-null Gate 1B evidence errors, capability widening, and
  `issue.update` / `comment.add` substitution; and
- app-payload, production-authorization, activation-smoke, delivery-archive,
  publication-envelope, remote-asset, and Homebrew checksum mismatch.

Every negative vector has one stable fail-closed reason class. Gate plans pin
the complete fixture-set digest; adding, removing, or changing a vector
invalidates prior E1/E2 evidence.

## Gate and release invariants

- The Gate plan is itself content-addressed. Any test, runner, fixture,
  entitlement expectation, or command change produces a new `gate_plan_sha256`
  and invalidates E1/E2 evidence.
- Gate 1A uses the normal confirmation command. Gate 1B uses the normal issue
  creation apply command against only its disposable target. The later
  production-authorization smoke uses that same command through exact loopback
  reads and the unique pre-write dispatch denial. Test-only command surfaces
  cannot substitute for either path.
- E1, E2, final authorization, and publication all bind one descriptor digest.
  A same-build rebuild has different Security.framework unique identifiers or
  hashes and cannot inherit evidence.
- The helper and CLI must agree on the descriptor digest before any authority
  protocol bytes. The approval registry records that same digest as
  `artifact_descriptor_sha256`; any mismatch or artifact change invalidates the
  ceremony or receipt.
- Gate evidence cannot authorize production. Only the later, separately
  domain-separated production authorization can do so.
- No production artifact is activated by this document. The root key, signed
  binaries, notarization evidence, clean-host E1/E2 passes, final authorization,
  publication envelope, and immutable release must all exist and validate.

## Evidence

- Apple defines [`kSecCodeInfoUnique`](https://developer.apple.com/documentation/security/kseccodeinfounique)
  as a binary identifier tied to a specific version of signed code and
  [`kSecCodeInfoCdHashes`](https://developer.apple.com/documentation/security/kseccodeinfocdhashes)
  as the unique identifiers for every digest algorithm in the signature.
- Apple recommends Code Signing Services rather than parsing signature internals
  in [TN3127: Inside Code Signing: Requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
  and documents architecture-specific signatures and sealed resources in
  [TN3126: Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes).
- Apple exposes [`kSecCodeAttributeArchitecture`](https://developer.apple.com/documentation/security/kseccodeattributearchitecture)
  for architecture selection and requires
  [`kSecCSCheckAllArchitectures`](https://developer.apple.com/documentation/security/kseccscheckallarchitectures)
  when validating universal code.
- Apple's code-signing guide explains that nested code is signed first and its
  signature is sealed by the outer bundle in
  [Code Signing Tasks](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html).
- Homebrew requires a downloaded Cask artifact SHA-256 and documents the `app`
  and `binary` artifacts in the
  [Cask Cookbook](https://docs.brew.sh/Cask-Cookbook).
- GitHub documents that
  [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
  lock release tags and assets and generate a cryptographically verifiable
  release attestation over the tag, commit, and assets.
