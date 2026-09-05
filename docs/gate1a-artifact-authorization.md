# Gate 1A exact-artifact authorization

Status: **NOT ACTIVATED**. The authority key is not enrolled, no Gate token is
issued, and no production artifact is activated. `approval.Unsupported`
remains the only production adapter. Gate 1A and Gate 1B are **NOT PASSED**.

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
| provisional production authorization | `YTA-PROVISIONAL-PRODUCTION-AUTHORIZATION-V1\0` | 8,192 |
| activation-smoke token | `YTA-ACTIVATION-SMOKE-V1\0` | 4,096 |
| production activation grant | `YTA-PRODUCTION-ACTIVATION-GRANT-V1\0` | 8,192 |
| post-grant verification token | `YTA-POST-GRANT-VERIFICATION-V1\0` | 4,096 |
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
base64url of exactly 32 bytes (43 characters). Gate plans are capped at their
object-specific limits below and target objects at 4,096 bytes; their
identifiers are SHA-256 of their exact canonical bytes. An evidence index
contains 1..256 observations and references
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
11. `outer_peer_requirement_source_sha256`
12. `helper_peer_requirement_source_sha256`
13. `helper_profile_raw_sha256`
14. `helper_profile_expires_at`, UTC RFC 3339 whole seconds copied from the
    verified profile semantic object
15. `helper_profile_signer_policy_sha256`
16. `helper_profile_cms_evidence_sha256`
17. `outer_code_validation_evidence_sha256`
18. `helper_code_validation_evidence_sha256`
19. `app_payload_archive_sha256`
20. `notary_evidence_sha256`
21. `staple_evidence_sha256`
22. `created_at`, UTC RFC 3339 whole seconds

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
9. `entitlements_semantic_sha256`
10. `actual_designated_requirement_data_sha256`

The launchd job label is not an additional caller-selected descriptor field:
it is the protocol constant equal to `helper_identifier`. Static validation
requires the signed app's packaged service declaration to register exactly one
per-user launchd job for that label and one fixed endpoint, with no alternate
server mode, second label/listener, or directly spawnable server entry. Runtime
evidence binds the one launchd-owned helper PID and endpoint to the descriptor's
helper code slice before authority traffic.

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
peer requirements, and actual designated requirements are defense-in-depth
evidence and Gate diagnostics. The Security.framework unique identifiers and
cdhash sets are the runtime exact-code authority. Executable and archive
SHA-256 values bind publication and offline reproduction; they do not replace
runtime code-signing validation.

The descriptor is created only after signing nested code first, signing the
outer app last, notarization, ticket stapling, and final signature validation.
Adding a descriptor inside the app afterward would change its resource seal.
It therefore remains detached.

`helper_profile_expires_at` must equal the profile-semantic `expires_at`
recovered from the CMS-validated embedded profile. There is no grace period,
clock-skew extension, cached-success window, or online refresh. Descriptor
creation, each E1/E2/smoke/post-grant token issuance and observation, activation
grant signing, publication-envelope signing, remote publication verification,
installation validation, helper launch, peer authentication, confirmation,
coordinator acquisition, registry proposal signing, registry final signing,
registry commit, permit issuance, and the final pre-send fence all
require their trusted current UTC instant to be strictly earlier than
this value. A stage that begins before expiry but reaches any listed boundary
at or after expiry fails closed; prior Gate evidence cannot authorize a later
expired install or apply. Replacing the profile changes signed code and starts
again from the app-only archive and descriptor at E1.
Trusted current time is sampled from the host realtime clock at each boundary,
compared as an instant before truncation or display formatting, and is never
accepted from argv, environment, plan, profile, server response, cached prior
check, or Gate fixture. An unavailable or unrepresentable clock result fails
the current operation; administrator/OS clock rollback or compromise remains
outside this local verifier's claim.

The conformance fixture set names the following complete boundary IDs; this is
a closed list for the profile-expiry claim:

| Boundary ID | `.just-before` | `.equal` | `.after` | `.expiry-between-checks` | Side effect forbidden by each denial |
| --- | --- | --- | --- | --- | --- |
| `profile-expiry.descriptor-create` | accept | deny | deny | deny after CMS parse | descriptor canonicalization/signing input acceptance |
| `profile-expiry.gate-e1-token-issue` | accept | deny | deny | deny after descriptor acceptance | E1 token signature |
| `profile-expiry.gate-e1-observation` | accept | deny | deny | deny after token acceptance | next Gate observation |
| `profile-expiry.gate-e2-token-issue` | accept | deny | deny | deny after E1 evidence validation | E2 token signature |
| `profile-expiry.gate-e2-observation` | accept | deny | deny | deny after token acceptance | next Gate observation |
| `profile-expiry.smoke-token-issue` | accept | deny | deny | deny after provisional validation | smoke token signature |
| `profile-expiry.smoke-observation` | accept | deny | deny | deny after token acceptance | next smoke observation |
| `profile-expiry.post-grant-token-issue` | accept | deny | deny | deny after activation-grant validation | post-grant token signature |
| `profile-expiry.post-grant-observation` | accept | deny | deny | deny after token acceptance | next post-grant observation |
| `profile-expiry.activation-grant-sign` | accept | deny | deny | deny after smoke evidence validation | activation-grant signature |
| `profile-expiry.publication-envelope-sign` | accept | deny | deny | deny after post-grant evidence validation | publication-envelope signature |
| `profile-expiry.publication-remote-verify` | accept | deny | deny | deny after envelope validation | release eligibility/publication continuation |
| `profile-expiry.installation-validate` | accept | deny | deny | deny after archive authentication | installation acceptance or link creation |
| `profile-expiry.helper-launch` | accept | deny | deny | deny after installation validation | helper session establishment |
| `profile-expiry.peer-authenticate` | accept | deny | deny | deny after helper launch | peer session authentication or authority read |
| `profile-expiry.mutation-confirm` | accept | deny | deny | deny after peer authentication | user-presence request or signed receipt |
| `profile-expiry.coordinator-acquire` | accept | deny | deny | deny after confirmation validation | coordinator active add |
| `profile-expiry.registry-proposal-sign` | accept | deny | deny | deny after leased ledger/candidate validation | proposal signing lookup or signature |
| `profile-expiry.registry-final-sign` | accept | deny | deny | deny after accepted proposal validation | final registry signing lookup or signature |
| `profile-expiry.registry-commit` | accept | deny | deny | deny after final signature validation | registry revision add |
| `profile-expiry.coordinator-permit` | accept | deny | deny | deny after `in_flight` CAS | permit add |
| `profile-expiry.mutation-pre-send` | accept | deny | deny | deny after permit add | socket creation or mutating request byte |

Every boundary ID has four mandatory vectors, with no sampled-time tolerance:
`.just-before` supplies a trusted instant exactly one nanosecond before expiry
and must accept that boundary; `.equal` supplies the expiry instant and must
reject with reason `HELPER_PROFILE_EXPIRED`; `.after` supplies one nanosecond
after expiry and must reject with the same reason; `.expiry-between-checks`
lets the immediately preceding named check complete one nanosecond before
expiry, then samples this boundary exactly at expiry and must reject before the
side effect in the table. For descriptor creation, the preceding check is CMS
profile parsing. For E1 issue it is descriptor acceptance. The final peer-auth
vector specifically proves a helper launched just before expiry cannot
authenticate a peer at equality. The coordinator-permit and mutation-pre-send
vectors prove that an acquired lease and existing permit respectively cannot
extend authority. The registry-sign/commit vectors prove the same under a
registry lease after proposal construction. All 88 vector IDs are the boundary
ID plus one of those four
suffixes, and the fixture manifest must contain exactly that Cartesian product.
Missing, duplicate, differently rounded, reordered, cached-time, or
caller-controlled-time variants fail both language implementations and every
Gate plan that relies on the expiry claim.

The only post-expiry runtime exception is a recovery-only launch of the exact
launchd-managed helper and recovery-only authentication of the exact CLI. It
is accepted only to perform bounded startup/status classification under the
serialized authority-executor fence. If no unresolved active record exists,
it returns bounded `authority_status=clear` with the expired profile field and
closes without another operation.
Trusted recovery proceeds only when classification finds one unresolved active
record for the same descriptor and retained evidence. That session may perform
only `mutation authority status`, trusted-UI recovery
authorization, terminal journal v2 CAS, exact-read-first closed-record
reconciliation, and executor-guarded byte-equal active cleanup. It cannot
enter an ordinary helper session, confirmation, registry ceremony,
coordinator acquisition, signing lookup, permit, transport construction, or
send. The ordinary `profile-expiry.helper-launch` and
`profile-expiry.peer-authenticate` vectors therefore still deny at equality;
separate recovery negatives prove that an expired session is accepted only in
this cleanup subset and is closed after classification/cleanup.

### Code, entitlement, profile, notary, and staple evidence

The two peer-requirement sources are the exact UTF-8 bytes compiled from the
literal Team ID, identifier, and build requirements in the trust-root ADR.
They end with exactly one LF, contain no CR or NUL, are at most 4,096 bytes,
and are hashed without normalization. The outer source describes the
requirement the helper applies to the CLI; the helper source describes the
requirement the CLI applies to the helper. These hashes do not claim to be the
code objects' designated requirements.

For every role/architecture slice, the release verifier asks
`SecCodeCopySigningInformation` for both `kSecCodeInfoEntitlementsDict` and
the raw `kSecCodeInfoEntitlements` value. Dictionary absence is represented by
an empty dictionary only when the raw value is also absent. Raw-present with a
missing dictionary, dictionary-present with missing raw bytes, parse failure,
or disagreement between their complete semantic values fails closed. The
complete returned dictionary is
converted to compact semantic JSON with recursively sorted ASCII keys; values
may only be boolean, signed 64-bit integer, printable-ASCII string, an array in
the Security.framework order, or another dictionary under the same rules.
Depth is at most 8, each collection has at most 64 members, and canonical bytes
are at most 16,384. Duplicate/non-ASCII keys, data/date/real values, unknown
entitlement keys, or a value outside the exact release allowlist fails closed.
The outer allowlist is empty. The helper allowlist is exactly
`com.apple.application-identifier`, `com.apple.developer.team-identifier`,
`com.apple.security.get-task-allow`, and `keychain-access-groups`;
`com.apple.security.get-task-allow` must be absent or false, and the other
values must equal the fixed Team ID, helper identifier, and one private access
group. Hashing only a selected entitlement subset is forbidden.

Each code-validation evidence object is compact canonical JSON capped at
32,768 bytes with these fields in order: `schema_version` integer `1`,
`evidence_type` exactly `code_validation`, `role`, `architectures`,
`peer_requirement_source_sha256`, `actual_designated_requirements`,
`certificate_chain`, `code_signing_policy_oid`,
`sec_static_code_check_flags`, `sec_static_code_check_status`, and
`validated_at`. `actual_designated_requirements` has one entry per declared
architecture, in descriptor order, containing `architecture` and
`requirement_data_sha256`; the bytes come from
`SecCodeCopyDesignatedRequirement`/`SecRequirementCopyData` and must match the
slice field. `certificate_chain` is the complete leaf-first
`kSecCodeInfoCertificates` array returned with `kSecCSSigningInformation`;
each entry contains its zero-based `position` and SHA-256 of the exact DER
certificate. `code_signing_policy_oid` is the exact UTF-8
value of `kSecPolicyAppleCodeSigning`; the policy is created only with
`SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, null)`. Flags are
the array `kSecCSStrictValidate`, then `kSecCSCheckAllArchitectures`, with no
other entry, and status is exactly the numeric `errSecSuccess` value.

`SecStaticCodeCheckValidityWithErrors` against the compiled peer requirement,
with all architectures and without `kSecCSSkipResourceDirectory`, is the
accept/reject authority. The evidence wrapper and hashes are not substitutes
for that call. The verifier separately validates that every actual designated
requirement is present, canonical Security.framework requirement data and that
the static code satisfies it; this self-designation check cannot substitute
for the stricter peer requirement.

The checked-in first-release profile-signer policy is compact canonical JSON
capped at 32,768 bytes with fields `schema_version` integer `1`, `policy_type`
exactly `apple_developer_id_profile_signer_first_release`, `signer_count`
integer `1`, and `chain`, in that order. `chain` is the exact leaf-to-root
certificate array. Each entry contains, in order, `position`,
`certificate_der_sha256`, `subject_der_sha256`, `issuer_der_sha256`,
`spki_sha256`, `basic_constraints_ca`, `basic_constraints_path_length`,
`key_usage_bits`, `extended_key_usage_oids`, `certificate_policy_oids`,
`subject_key_identifier`, `authority_key_identifier`, `not_before`, and
`not_after`. OID arrays are nonempty sorted canonical dotted-decimal strings;
identifiers are lowercase hex or null; the path length is a nonnegative integer
or null; key usage is the exact nonnegative bit mask. Every value is literal,
not a pattern or caller input. `helper_profile_signer_policy_sha256` is SHA-256
of those exact checked-in bytes and is compiled into both release verifiers.
The current repository has no enrolled first-release policy; its absence fails
closed. Any future certificate, extension, OID, key identifier, or chain change
requires a protocol revision and new Gate, not a policy-file replacement.

`helper_profile_raw_sha256` covers the exact raw
`Contents/embedded.provisionprofile` bytes. Profile CMS evidence is compact
canonical JSON capped at 32,768 bytes with fields in this order:
`schema_version`, `evidence_type` exactly `provisioning_profile_cms`,
`profile_raw_sha256`, `profile_signer_policy_sha256`, `cms_content_sha256`,
`cms_signer_status`,
`cms_certificate_verification_status`, `cms_chain`,
`cms_all_certificates_sha256`, `code_signing_policy_oid`,
`profile_semantic_sha256`, and `validated_at`. The profile is capped at 1 MiB
and the exact call order is
`CMSDecoderCreate`, one `CMSDecoderUpdateMessage` covering all raw bytes,
`CMSDecoderFinalizeMessage`, `CMSDecoderGetNumSigners`,
`CMSDecoderCopyContent`, `CMSDecoderCopyAllCerts`, then
`CMSDecoderCopySignerStatus` for signer index zero with the code-signing policy
and trust evaluation enabled, followed by `SecTrustCopyCertificateChain` on
the returned trust. Exactly one signer and one encapsulated content value must
exist. Every call must succeed; signer status and certificate verification
status must be exactly `kCMSSignerValid` and numeric `errSecSuccess`.
`CMSDecoderCopyAllCerts` must return 1..32 certificates. Each certificate is
exported once with `SecCertificateCopyData`; every DER value is nonempty and
the aggregate DER size is at most 1 MiB. The complete multiset, including
duplicate DER values, is sorted first by the 32 raw digest bytes of
`SHA-256(DER)` and then by the raw DER bytes as a deterministic tie-breaker.
The `cms_all_certificates_sha256` preimage is the ASCII domain
`YTA-CMS-ALL-CERTIFICATES-V1\0`, followed by the certificate count as one
unsigned 32-bit big-endian integer, followed for each sorted multiset entry by
its DER length as one unsigned 32-bit big-endian integer and then its exact DER
bytes. Its value is SHA-256 of that complete byte sequence. No separator,
certificate digest, JSON encoding, deduplication, or platform array order is
part of the preimage. `cms_chain` is the complete
leaf-to-root evaluated chain; each entry carries every field of the checked-in
policy entry and must equal it exactly. Unknown critical extensions, omitted
extension semantics, extra/unordered certificates, policy-digest mismatch, or
time outside any certificate validity interval fails closed. The policy OID
must equal the code-validation evidence. The decoded
plist is the source of a compact profile-semantic object capped at 16,384 bytes
with fields `schema_version` integer `1`, `semantic_type` exactly
`developer_id_profile`, `application_identifier`, `team_identifiers`,
`expires_at`, and `entitlements`, in that order. `team_identifiers` is a
nonempty sorted unique array of 10-character Team IDs. The expiry is converted
from the plist date to UTC whole-second RFC 3339 without rounding.
`entitlements` permits exactly `com.apple.application-identifier`,
`com.apple.developer.team-identifier`, `get-task-allow`, and
`keychain-access-groups`; an unknown entitlement is rejected. Those values,
Team ID, App ID, and expiry must match the descriptor and helper semantic
entitlements. The exact CMS content hash, rather than selected reserialized
metadata, preserves every other Apple-issued profile field.

A typed path token used by release or Gate argv templates is compact canonical
JSON capped at 1,024 bytes with fields `schema_version` integer `1`,
`token_type` exactly `path_argument`, `source`, `fixture_id`,
`content_sha256`, `expected_type`, and `access`, in that order. `source` is
exactly `submitted_artifact_path`, `candidate_app_path`, `gate_profile_path`,
`gate_session_path`, or `fixture_path`. `expected_type` is `regular_file`,
`signed_app_bundle`, or `directory`; access is exactly `read_only`.
`fixture_id` is non-null only for the two fixture-backed sources.
`content_sha256` is required for a submitted artifact or fixture and null for
the signed bundle/session directory, whose descriptor or session identity is
already bound. Source/type/null combinations are closed and compiled into the
consumer. Resolution starts from the already opened trusted root, uses the
one-descriptor path rules above, and substitutes exactly one native path argv
element; no serialized absolute path, environment expansion, tilde, or caller
component is accepted.

Each Apple command-line dependency has one compact canonical tool-capture
object capped at 16,384 bytes. Its fields are `schema_version` integer `1`,
`capture_type` exactly `apple_tool`, `tool_name`, `find_argv`,
`find_exit_code`, `find_stdout_sha256`, `find_stderr_sha256`, `resolved_path`,
`executable_sha256`, `version_probe_argv`, `version_probe_exit_code`,
`version_probe_stdout_sha256`, `version_probe_stderr_sha256`, `version_source`,
`owner_version_argv`, `owner_version_exit_code`,
`owner_version_stdout_sha256`, `owner_version_stderr_sha256`, and `captured_at`,
in that order. All referenced stdout/stderr files are retained exact bytes and
pass secret scanning. Find and owner-version exit codes, when non-null, are
zero. No version-output string is parsed into authority semantics.
A zero version probe requires `version_source` exactly `native_version` and all
four owner-version fields null. A nonzero probe is permitted only for the two
explicit fallback mappings below; every other combination is invalid.

For `notarytool` and `stapler`, `find_argv` is exactly
`/usr/bin/xcrun`, `--find`, then the tool name, and `version_probe_argv` is
exactly `/usr/bin/xcrun`, the tool name, `--version`. `resolved_path` is the sole
printable-ASCII absolute path emitted by `--find`; stdout must be exactly that
path plus LF, stderr must be empty, and `executable_sha256` hashes the regular
file at that resolved path through the same already-opened-descriptor rules.
For `notarytool`, `version_source` is `native_version`, the probe exit is zero,
and all four `owner_version_*` fields are null. For `stapler`, the exact probe
is still executed and all of its bytes and actual `0..255` exit code are
retained. When that captured executable does not support the option,
`version_source` is `xcode_build_fallback`; the nonzero exit and exact usage
output must match the checked-in expected digests for that executable hash,
and `owner_version_argv` is exactly `/usr/bin/xcrun`, `xcodebuild`, `-version`.
An arbitrary failed probe is never treated as a fallback.

The active developer directory is frozen for the ceremony, and xcrun
resolution is repeated after the final tool invocation; any changed path,
executable hash, or output fails the wrapper. For `spctl`, all four `find_*`
fields are null, `resolved_path` is exactly `/usr/sbin/spctl`,
`executable_sha256` hashes that path through an opened descriptor, and
`version_probe_argv` is exactly `/usr/sbin/spctl`, `--version`. If that exact
binary does not support the option, `version_source` is
`macos_build_fallback`; the same pinned-nonzero-probe rule applies and
`owner_version_argv` is exactly `/usr/bin/sw_vers` with no argument. Its exact
output must contain one each of the product name, product version, and build
version keys and match the separately recorded Gate macOS build. An alternate
PATH lookup, shell alias, relative executable, unrecognized failed probe,
failed fallback, or unretained output is invalid.

Notary evidence is one compact canonical wrapper capped at 32,768 bytes with
these fields in order: `schema_version` integer `1`, `evidence_type` exactly
`apple_notary`, `submission_id`, `submitted_artifact_sha256`,
`notarytool_capture_sha256`, `notary_output_schema_sha256`, `submit_argv`, `submit_exit_code`,
`submit_stdout_sha256`, `submit_stderr_sha256`, `log_argv`, `log_exit_code`,
`log_stdout_sha256`, `log_stderr_sha256`, `retained_log_sha256`,
`parsed_submit_id`, `parsed_log_id`, `status` exactly `Accepted`, and
`completed_at`. Both exit codes are exactly zero; all four output files are
retained by digest and must pass secret scanning.

`submit_argv` is exactly `/usr/bin/xcrun`, `notarytool`, `submit`, a typed
`submitted_artifact_path` token carrying `submitted_artifact_sha256`,
`--keychain-profile`, `youtrack-agent-release`, `--wait`, `--output-format`,
`json`. `log_argv` is exactly `/usr/bin/xcrun`, `notarytool`, `log`, a typed
`submission_id` token, `--keychain-profile`, `youtrack-agent-release`,
`--output-format`, `json`. These arrays are direct-process argv values, not
shell text; the typed values are substituted as one argument. The credential
profile name is public, but its Keychain value is never read into evidence.
The submission-ID token is compact canonical JSON with fields `schema_version`
integer `1`, `token_type` exactly `dynamic_scalar`, and `source` exactly
`submission_id`, in that order; it resolves only to the canonical UUID already
present in the wrapper.
The submit JSON and log JSON are strictly parsed under their checked-in,
version-pinned observed-input schema;
their UUID values must both equal `submission_id`, the submit status must be
`Accepted`, and the submitted artifact must pass the same one-descriptor hash
and metadata checks immediately before and after the subprocess.
`notary_output_schema_sha256` is a literal compiled digest of a canonical
manifest containing `schema_version` integer `1`, `schema_type` exactly
`observed_notarytool_json`, `notarytool_capture_sha256`,
`submit_shape_sha256`, and `log_shape_sha256`, in that order. It is a local
allowlist for output observed from the captured tool build, not a claim that
Apple documents or guarantees a stable JSON schema. An unknown field or shape
change fails closed and requires reviewed new observed fixtures, a new literal
digest, and a protocol revision. `retained_log_sha256` exactly equals
`log_stdout_sha256`. A successful exit without those semantic matches is a
failure.

Staple evidence is a non-circular compact wrapper capped at 32,768 bytes with
these fields in order: `schema_version` integer `1`, `evidence_type` exactly
`apple_staple`, `notary_evidence_sha256`, `stapler_capture_sha256`,
`spctl_capture_sha256`, `staple_argv`,
`staple_exit_code`, `staple_stdout_sha256`, `staple_stderr_sha256`,
`validate_argv`, `validate_exit_code`, `validate_stdout_sha256`,
`validate_stderr_sha256`, `spctl_argv`, `spctl_exit_code`,
`spctl_stdout_sha256`, `spctl_stderr_sha256`, `post_staple_code_identities`,
`sec_static_code_check_status`, and `validated_at`. All exit codes and the
Security.framework status are exactly zero; every output is retained by digest
and passes secret scanning.

The three direct argv arrays are exactly `/usr/bin/xcrun`, `stapler`,
`staple`, typed `candidate_app_path`; `/usr/bin/xcrun`, `stapler`, `validate`,
the same typed path; and `/usr/sbin/spctl`, `--assess`, `--type`, `exec`,
`--verbose=4`, the same typed path. No extra flag or alternate executable is
accepted. Stapler validation and `spctl` assessment succeed only by exit code
zero. Their stdout/stderr remain opaque observed evidence: the verifier does
not parse an `accepted` word, source label, app name, or other undocumented
text. The typed path and the subsequent Security.framework validation bind
both invocations to the candidate app. The wrapper contains no descriptor,
authorization, or archive digest; its only predecessor is the already final
notary-evidence digest. The final app is then revalidated through
Security.framework and becomes the app placed in the app-only archive.
`post_staple_code_identities` is an array with exactly one entry for every
descriptor role/architecture pair in descriptor order. Each entry contains
`role`, `architecture`, `ksec_code_info_unique`, and the complete `cdhashes`
array, in that order, and exactly equals the corresponding descriptor slice.
A singular outer identity, native-architecture-only result, missing slice, or
aggregate hash without the canonical array is invalid. This ordering prevents
a descriptor/evidence/archive hash cycle.

## Detached layout and race-free reads

The app-only payload archive contains exactly one top-level
`YouTrackAgent.app/` and excludes every descriptor, token, authorization,
publication envelope, Gate runner, and Gate fixture. The archive format is a
release-packaging choice, not an authority codec. `app_payload_archive_sha256`
is SHA-256 of the exact opaque archive file bytes produced for the candidate;
the file is capped at 1 GiB and retained as evidence. Verifiers never attempt
to reconstruct those bytes from an extracted app.
It is produced exactly once from the final stapled and revalidated app, and its
opaque bytes and digest are retained before the descriptor is canonicalized
and before any E1 token can be issued. No later Gate, smoke, grant, post-grant
verification, or publication step rebuilds or repacks it. After E1 begins, the
only archive created later is the outer delivery archive. The publication
envelope is signed first and then included in that archive at its fixed path.

A production delivery archive contains:

```text
YouTrackAgent.app/
authorization/artifact-descriptor.json
authorization/provisional-production-authorization.json
authorization/production-activation-grant.json
authorization/publication-envelope.json
authorization/post-grant-verification-plan.json
authorization/post-grant-verification-evidence-set/index.json
authorization/post-grant-verification-evidence-set/install-files.json
authorization/post-grant-verification-evidence-set/files/...
```

The descriptor, provisional authorization, and activation grant are outside
the signed app and outside the app-only payload archive. The publication
envelope, exact post-grant plan, canonical complete evidence-set index,
canonical install-evidence manifest, and every file listed by that manifest
are also outside the app-only payload archive but inside the outer delivery
archive at the literal paths above. The `files/` tree is the install-evidence
manifest's closed, relative-path namespace; missing, extra,
duplicate, absolute, dot-segment, symlink, hard-link, or escaping entries fail
closed. The outer archive is an opaque release file capped at 1 GiB and the
Cask pins the SHA-256 of its exact downloaded bytes. The envelope deliberately
does not contain the delivery-archive hash, so including the envelope and its
verification assets creates no recursive hash cycle.

Archive hashes are pre-extraction publication/download evidence only. The
app-only archive hash is verified against the descriptor and retained release
asset; the outer archive hash is a literal Cask checksum verified before
extraction. Neither is runtime authority and neither is recomputed from an
installed tree. Before packaging, the release verifier validates the
app-only archive and the app selected for the outer archive against the same
descriptor, Developer ID signatures, all-architecture code identities,
profile, notarization, and staple evidence. After extraction, installation and
runtime validation use those signed-code checks plus the exact root-signed
sidecar bytes and the envelope-bound post-grant verification assets available
under the same installation root. The code signature's sealed resources, not
a home-grown tree manifest or archive reconstruction, protect the installed
app contents.

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

## Canonical Gate, smoke, and post-grant plans

A Gate plan is data, never a script. Gate 1A and Gate 1B plans are each capped
at 65,536 bytes; activation-smoke and post-grant-verification plans are each
capped at 32,768 bytes. Their
compact canonical fields are, in order:

1. `schema_version`, integer `1`
2. `plan_type`, exactly `gate1a`, `gate1b`, `activation_smoke`, or
   `post_grant_verification`
3. `descriptor_sha256`
4. `approved_capability`, `confirm_only` for Gate 1A; `issue_create_gate` for
   Gate 1B; and `confirm_only` or `issue_create` for smoke and post-grant
   verification
5. `architectures`, exactly the descriptor array
6. `fixture_set_sha256`
7. `fixture_executable_manifest_sha256`, required for Gate 1A and null for
   Gate 1B, activation smoke, and post-grant verification
8. `assertion_set_sha256`
9. `transcript_set_sha256`
10. `command_contract_manifest_sha256`
11. `allowed_network`, exactly `none` for Gate 1A and confirm-only smoke or
    post-grant verification, `exact_gate_target` for Gate 1B, or
    `loopback_read_only` for issue-create smoke or post-grant verification
12. `sandbox_policy`, exactly `gate1a_deny_v1`, `gate1b_target_v1`,
    `smoke_confirm_deny_v1`, `smoke_issue_loopback_v1`,
    `post_grant_confirm_deny_v1`, or `post_grant_issue_loopback_v1`, matching
    plan type and capability
13. `reset_policy`, exactly `fresh_reverted_host_per_architecture_stage_v1`
14. `minimum_macos_product_build_version`, printable ASCII of 1..32 bytes
15. `architecture_execution_matrix`, the closed array described below
16. `gate_target_sha256`, null except for Gate 1B
17. `provisional_context_sha256`, null except for activation smoke
18. `authorization_context_sha256`, null except for post-grant verification
19. `stage_setup_policy`, null for Gate 1A/Gate 1B or exactly
    `first_exact_artifact_enrollment_v1` for activation smoke and post-grant
    verification
20. `stage_cleanup_policy`, null for Gate 1A/Gate 1B or exactly
    `attributed_stage_cleanup_v1` for activation smoke and post-grant
    verification
21. `cases`, an ordered array

`gate_plan_sha256` always means SHA-256 of these complete exact plan bytes,
including when `plan_type` is `activation_smoke`. No `smoke_plan_sha256` field
or alternate digest exists. The same field and definition apply when plan type
is `post_grant_verification`.

The architecture execution matrix has exactly one entry per descriptor
architecture in descriptor order. Each entry has `architecture`,
`required_native_host` equal to that architecture, `translation_allowed`
exactly false, `fresh_token` exactly true, `fresh_runner_session` exactly true,
and `clean_reset_before_run` exactly true, in that order. The observed macOS
product build and the minimum both match
`^[0-9]{2}[A-Z][0-9]{1,5}[a-z]?$`. Comparison parses numeric major, ASCII train
letter, numeric build, then optional seed suffix; an absent suffix sorts after
any suffix for the same first three components. The observed tuple must be at
least the minimum and is recorded byte-for-byte in evidence. A run under
Rosetta, on an undeclared slice, with a reused token/session/host state, or
missing one matrix row fails the whole evidence set.

The six sandbox policies are compiled constants, not file paths. They deny
undeclared subprocesses and filesystem access outside the mode-0700 Gate root.
For an `exact_artifact` case they permit only the descriptor-pinned CLI/helper
and the runner/verifier named by its command contract. The sole exception is
the compiled mixed-build rejection substeps of
`gate1a.artifact.runtime-peer-validation`, which may launch the manifest-pinned
`negative_peer_fixture` only as an adversarial connection input. It has no
Keychain, registry, helper, or positive-protocol authority and must be rejected
before protocol bytes. For a
`disjoint_fixture` case they deny execution of the production CLI/helper and
permit only the command-contract-declared `fixture_cli`/`fixture_helper` whose
active slice exactly matches the fixture-executable manifest, plus the same
runner/verifier supervisors. No fixture identity is accepted on an
`exact_artifact` case except the negative peer's bounded adversarial launch,
which is never an accepted protocol peer; no production identity is accepted
on a `disjoint_fixture` case.

Every policy permits only the ordinary helper-owned or runner-preopened
`AF_UNIX` `SOCK_SEQPACKET` IPC descriptor. For `exact_artifact`, its only
socket-address components relative to the already opened mode-0700 session
root are exactly `ipc` and `approval.sock`; for `disjoint_fixture` they are
exactly `fixture-ipc` and `approval.sock`. The matching helper or runner creates
and connects it before sandbox entry and passes the connected descriptor. The
receiver validates the connection-bound audit token and exact peer requirement
before any protocol byte, including Team ID, identifier, build, active-slice
unique/cdhash set, descriptor or fixture-manifest digest, and the stage's Gate
or authorization context. Cross-namespace descriptors and callers creating,
binding, connecting, or redirecting an additional Unix socket are rejected.
The negative peer receives only a runner-preopened descriptor under
`negative-peer-ipc` and `approval.sock`; it cannot address either ordinary or
fixture registry state and the candidate must close it on audit-token/build
rejection.
Gate 1A and confirm-only smoke deny `AF_INET`,
`AF_INET6`, and every other socket family/type. `gate1b_target_v1` permits only
the exact target origin and methods required by its declared workflows.
`smoke_issue_loopback_v1` permits only its token's IPv4 loopback origin and
read-only `GET`/`HEAD`; the mutation dispatcher remains a pre-socket hard deny.
The two post-grant policies have the same network restrictions as their smoke
counterparts but require the real grant-bound final authorization context and
the post-grant token's distinct dispatch-denial code.
For either stage policy, `stage_setup_policy` grants no ambient registry
authority: it is usable only by the first compiled setup case, only with the
stage token and derived setup context, and only to create revision 1 from the
proved empty disposable inventory described below. Rotation, recovery,
revocation, a second enrollment, receipt signing, and mutation dispatch are
outside that setup authority.
`stage_cleanup_policy` is likewise not ambient deletion authority. It permits
only the distinct `stage_cleanup` IPC protocol over the exact retained cleanup
intent and cleanup context; ordinary production and non-stage processes retain
the no-delete rule.
An inherited non-IPC descriptor, alternate Unix path, missing audit-token
check, IPv6/hostname loopback, datagram/raw socket, or undeclared socket attempt
is a Gate failure. Any policy change requires a protocol revision, not a new
caller value.

### Fixture, executable, assertion, and transcript manifests

The fixture, assertion, and transcript sets are compact canonical JSON, each
capped at 65,536 bytes with 1..256 entries and no extensions. A fixture-set manifest has fields
`schema_version` integer `1`, `manifest_type` exactly `fixture_set`, and
`entries`, in that order. Each entry has `fixture_id`, `fixture_kind`,
`content_sha256`, `size`, and `mode`, in that order. Kind is exactly
`canonical_json`, `binary_blob`, `profile_root_archive`, or `expected_output`;
size is `1..8,388,608`; mode is exactly `read_only`. Directory fixtures are
deterministic archives, never caller-supplied paths.

The Gate 1A fixture-executable manifest is a separate compact canonical JSON
object capped at 32,768 bytes. Its fields are `schema_version` integer `1`,
`manifest_type` exactly `fixture_executables`, `descriptor_sha256`,
`fixture_namespace` exactly
`io.github.abigotado.youtrack-agent.gate1a.fixture`, `fixture_set_sha256`,
`architectures`, `fixture_code_slices`, and
`negative_peer_code_slices`, in that order. `architectures` exactly equals the
descriptor array. `fixture_code_slices` is ordered
first by role `fixture_cli`, `fixture_helper`, then by architecture in
descriptor order, with exactly one entry for every pair. Each entry contains,
in order, `role`, `architecture`, `identifier`, `team_id`, `build`,
`executable_sha256`, `ksec_code_info_unique`, `cdhashes`,
`entitlements_semantic_sha256`,
`actual_designated_requirement_data_sha256`, and
`code_validation_evidence_sha256`. `cdhashes` uses the exact descriptor-slice
codec. Identifiers are exactly
`io.github.abigotado.youtrack-agent.gate1a.fixture` and
`io.github.abigotado.youtrack-agent.gate1a.fixture.approval` for their matching
roles. Every other value is obtained and validated by the same per-architecture
Security.framework procedure and grammar as a descriptor code slice.
The resolved fixture access-group suffix is exactly the namespace plus
`.approval`; the key-tag prefix is the namespace plus
`.approval.signing.v1/`; the registry service is the namespace plus
`.approval.registry.v1`; and its peer requirements name only the two fixture
identifiers above. No test, temporary, or caller-selected namespace alias is
accepted.

`negative_peer_code_slices` is ordered by `peer_component` `outer`, `helper`,
then descriptor architecture, with exactly one entry for every pair. Each
entry has `role` exactly `negative_peer_fixture`, then `peer_component`,
`architecture`, `identifier`, `team_id`, `build`, `executable_sha256`,
`ksec_code_info_unique`, `cdhashes`, `entitlements_semantic_sha256`,
`actual_designated_requirement_data_sha256`, and
`code_validation_evidence_sha256`, in that order. Identifier and Team ID equal
the matching production descriptor values, but `build` is one literal positive
decimal build strictly older than `release_build` and is identical in every
negative-peer slice. Its exact signed per-architecture identities and hashes
are manifest data, never a wildcard or semantic-only match.

The disjoint fixture slices must differ from the artifact descriptor in both
identifiers and every role/architecture `ksec_code_info_unique` and
`executable_sha256`. The negative-peer slices deliberately retain production
identifiers but must differ in build, unique identifier, executable hash, and
cdhashes. The negative peer is a separately signed, never-shipped old pair: it
is not notarized, stapled, archived, installed, or accepted as authority, and
is destroyed with the disposable Gate environment. It proves only that the
current exact artifact rejects a mixed-build connection; it does not claim
that this first-release topology prevents a separately run matched old pair.
The manifest is content-addressed by the plan and signed indirectly
by the Gate token; it is never a production descriptor, publication input, or
runtime authority. The checked-in Gate 1A command contract fixes its exact
manifest digest. A missing slice, uncompiled manifest, or fixture binary not
equal to its active signed slice fails before execution. A production
identifier on a disjoint fixture role, or a nonproduction identifier on a
negative-peer component, also fails.

An assertion-set manifest has fields `schema_version` integer `1`,
`manifest_type` exactly `assertion_set`, and `entries`. Each entry has
`assertion_id`, `evaluator`, and `expected_sha256`, in that order. Evaluator is
exactly `json_envelope`, `exit_code`, `filesystem_state`, `keychain_state`,
`code_identity`, `network_transcript`, `byte_equality`, `ui_observation`, or
`cleanup_state`, or `concurrency_trace`; its expected object is one canonical
fixture in the fixture set. The verifier, not the plan, implements these
evaluators.

A transcript-set manifest has fields `schema_version` integer `1`,
`manifest_type` exactly `transcript_set`, and `entries`. Each entry has
`transcript_id`, `transcript_kind`, `maximum_bytes`, and `redaction_policy`, in
that order. Kind is exactly `stdout`, `stderr`, `ipc`, `network`, `ui`, or
`security_framework`, or `concurrency_trace`; maximum is `1..8,388,608`;
redaction policy is exactly `reject_secret_then_hash`. A detected credential,
token, private key, or unredacted secret fails the run instead of being
replaced.

A command-contract manifest is compact canonical JSON capped at 131,072 bytes.
Its fields are `schema_version` integer `1`, `manifest_type` exactly
`command_contract`, `plan_type`, `approved_capability`,
`fixture_executable_manifest_sha256`, `entries`, and `case_evaluations`, in
that order. The fixture digest follows the same required/null rule as the plan.
Entries are in the
normative case/step order below and contain, in order, `case_id`,
`evidence_scope`, `step_id`, `executable_role`, `executable_component`, `argv`,
`working_directory`, `environment`, `stdin`, `timeout_seconds`, `fixture_ids`,
`assertion_ids`, and `transcript_ids`.
`argv` and `transcript_ids` are nonempty; `assertion_ids` is the exact empty
array on every operation entry. `environment` is the required empty array;
`fixture_ids` may be empty where the compiled contract needs no fixture. The
`argv` field is the exact typed template later resolved by the runner. The
entry fixes each operation's executable, argv template, timeout, and complete
ordered ID lists; a plan never supplies or overrides different values.

`case_evaluations` has exactly one entry per case in normative case order.
The six manifests therefore contain exactly 23, 25, 5, 6, 6, and 6
case-evaluation entries for Gate 1A, Gate 1B, smoke confirm, smoke issue-create,
post-grant confirm, and post-grant issue-create respectively.
Each contains, in order, `case_id`, `observation_id` equal to the case ID plus
`/final-evaluation`, `executable_role` and `executable_component` both exactly
`gate_runner`, `assertion_ids`, and `transcript_ids`. Its `assertion_ids` are
the complete ordered IDs obtained from that case row's suffixes. Its
`transcript_ids` are exactly the final evaluator's derived `stdout` then
`stderr` IDs. This is not a candidate subprocess command: it binds the
already authenticated runner's mandatory case-final evaluation after every
operation observation and transcript result exists. A plan case contains
`case_id`, `evidence_scope`, `steps`, and `final_evaluation`, in that order;
the last field is rebuilt from this manifest entry.

The release verifier contains exactly six checked-in literal digests named
`GATE1A_COMMAND_CONTRACT_SHA256`, `GATE1B_COMMAND_CONTRACT_SHA256`,
`SMOKE_CONFIRM_COMMAND_CONTRACT_SHA256`, and
`SMOKE_ISSUE_CREATE_COMMAND_CONTRACT_SHA256`,
`POST_GRANT_CONFIRM_COMMAND_CONTRACT_SHA256`, and
`POST_GRANT_ISSUE_CREATE_COMMAND_CONTRACT_SHA256`. Each is SHA-256 of one complete
manifest whose plan type/capability matches its name. The corresponding plan
field must equal that literal, its fixture-executable field must equal the
manifest field, and its `cases` array must byte-for-byte equal the canonical
case tree rebuilt from all operation and case-evaluation manifest entries,
including scope. A missing literal/manifest,
unregistered digest, empty step, changed command field, or validly hashed but
uncompiled manifest fails before token acceptance. Changing a contract requires
a protocol revision and new Gate.

All IDs match `^[a-z0-9][a-z0-9._-]{0,127}$` and are globally unique by
manifest type. Only set-like fixture, assertion, and transcript manifest entry
arrays are sorted by increasing unsigned UTF-8 ID bytes and must already be in
that order on input. Order-bearing arrays are never sorted: command-contract
entries and `case_evaluations`, plan `cases`, case `steps`, step `argv`,
case-final `assertion_ids`, `transcript_ids`, observations, evidence scopes,
and concurrency trace events must occur in the exact normative order declared
below. A producer cannot use
map iteration or byte sorting to replace that order. A set digest is SHA-256
over the exact canonical bytes of the explicitly set-like manifest. The plan
validator loads each manifest by digest, rejects missing/extra entries, and
requires every operation and final-evaluation reference to resolve with the
declared kind and evaluator.
An unreferenced manifest entry or a referenced ID absent from the plan is
invalid.

There are no optional fields, user extensions, ignored metadata, default
steps, or wildcard case IDs. `evidence_scope` is exactly `exact_artifact` or
`disjoint_fixture`. The compiled mapping assigns exactly these five cases to
`disjoint_fixture`: `gate1a.registry.corruption-deny`,
`gate1a.registry.fork-gap-duplicate-deny`,
`gate1a.registry.crash-ambiguous-secitemadd`,
`gate1a.registry.orphan-cleanup`, and
`gate1a.registry.active-key-loss`. Every other Gate 1A case, including ordinary
`gate1a.registry.enroll-rotate-revoke-recover`, every Gate 1B case, and every
activation-smoke and post-grant-verification case is `exact_artifact`. No caller or plan generator can
change this mapping. The
exact Gate 1A case order is:

1. `gate1a.artifact.static-validation`
2. `gate1a.artifact.runtime-peer-validation`
3. `gate1a.protocol.positive-vectors`
4. `gate1a.protocol.negative-vectors`
5. `gate1a.registry.enroll-rotate-revoke-recover`
6. `gate1a.registry.corruption-deny`
7. `gate1a.registry.fork-gap-duplicate-deny`
8. `gate1a.registry.crash-ambiguous-secitemadd`
9. `gate1a.registry.orphan-cleanup`
10. `gate1a.registry.active-key-loss`
11. `gate1a.confirm.ordinary-success`
12. `gate1a.confirm.cancel-and-expire`
13. `gate1a.confirm.restart-and-replay-deny`
14. `gate1a.confirm.untrusted-display`
15. `gate1a.network.hard-deny`
16. `gate1a.authority.fail-closed-matrix`
17. `gate1a.install.first-install-validation`
18. `gate1a.install.identical-reinstall`
19. `gate1a.install.rollback-and-replacement-deny`
20. `gate1a.install.uninstall-cleanup`
21. `gate1a.migration.cancel`
22. `gate1a.migration.interruption`
23. `gate1a.migration.partial-failure`

This closed Gate 1A list contains exactly 23 cases; the compiled case table
below must contain the same IDs once each in this exact order.

The exact Gate 1B case order is:

1. `gate1b.issue-create.prepare-confirm-apply-success`
2. `gate1b.issue-create.expected-state-conflict`
3. `gate1b.issue-create.timeout-reconcile-created`
4. `gate1b.issue-create.timeout-reconcile-absent`
5. `gate1b.issue-create.timeout-reconcile-conflict`
6. `gate1b.issue-create.one-shot-no-retry`
7. `gate1b.coordinator.apply-vs-rotate-linearization`
8. `gate1b.coordinator.apply-vs-revoke-linearization`
9. `gate1b.coordinator.apply-vs-recovery-linearization`
10. `gate1b.coordinator.invalid-enrollment-contention`
11. `gate1b.coordinator.crash-before-permit`
12. `gate1b.coordinator.crash-after-permit-before-send`
13. `gate1b.coordinator.crash-after-send-before-outcome`
14. `gate1b.coordinator.crash-after-durable-outcome-before-closed-add`
15. `gate1b.coordinator.closed-add-ambiguity`
16. `gate1b.coordinator.crash-after-closed-before-active-delete`
17. `gate1b.coordinator.active-delete-ambiguity`
18. `gate1b.coordinator.active-cleanup-aba-deny`
19. `gate1b.coordinator.restart-fence-and-close-recovery`
20. `gate1b.authority.status-recover-contract`
21. `gate1b.journal.v1-v2-migration-and-quarantine`
22. `gate1b.capability.update-comment-other-deny`
23. `gate1b.target.origin-account-project-deny`
24. `gate1b.receipt.context-and-replay-deny`
25. `gate1b.authority.fail-closed-matrix`

This closed Gate 1B list contains exactly 25 cases; the compiled case table
below must contain the same IDs once each in this exact order.

For activation smoke, `confirm_only` has exactly these cases:

1. `smoke.confirm.setup-exact-artifact-enrollment`
2. `smoke.confirm.prepare-confirm-success`
3. `smoke.confirm.apply-all-deny`
4. `smoke.confirm.receipt-context-ineligible`
5. `smoke.confirm.authority-negatives`

`issue_create` smoke has exactly these cases:

1. `smoke.issue-create.setup-exact-artifact-enrollment`
2. `smoke.issue-create.prepare-confirm-apply-dispatch-deny`
3. `smoke.issue-create.zero-mutating-bytes`
4. `smoke.issue-create.update-comment-other-deny`
5. `smoke.issue-create.receipt-context-ineligible`
6. `smoke.issue-create.authority-negatives`

Post-grant verification for `confirm_only` has exactly these cases:

1. `post-grant.confirm.setup-exact-artifact-enrollment`
2. `post-grant.confirm.prepare-confirm-success`
3. `post-grant.confirm.apply-all-deny`
4. `post-grant.confirm.receipt-terminal-replay-deny`
5. `post-grant.confirm.authority-negatives`
6. `post-grant.confirm.cleanup`

Post-grant verification for `issue_create` has exactly these cases:

1. `post-grant.issue-create.setup-exact-artifact-enrollment`
2. `post-grant.issue-create.prepare-confirm-apply-dispatch-deny`
3. `post-grant.issue-create.zero-mutating-bytes`
4. `post-grant.issue-create.receipt-terminal-replay-deny`
5. `post-grant.issue-create.authority-negatives`
6. `post-grant.issue-create.cleanup`

The four stage lists therefore contain exactly 5, 6, 6, and 6 cases in the
order shown. Each first case is the only setup-authorized case; each last case
contains or is the final cleanup and final empty-inventory proof.

The verifier compiles the following closed case contracts. Operation step IDs
and case-final assertion suffixes occur in the shown order; a suffix forms the
assertion ID by directly appending it to the case ID. Every operation records
`stdout` and `stderr`; the last column adds required transcript kinds. The
tables do not abbreviate assertion timing: every listed suffix belongs only to
the separate `/final-evaluation` observation, never to an operation
observation.

| Gate 1A case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `gate1a.artifact.static-validation` | `validate` | `.primary`, `.all-architectures`, `.launchd-single-helper-server` | `security_framework` |
| `gate1a.artifact.runtime-peer-validation` | `launch`, `handshake`, `launch-negative-outer`, `reject-negative-outer`, `launch-negative-helper`, `reject-negative-helper` | `.primary`, `.mixed-cli-peer-deny`, `.mixed-helper-peer-deny`, `.negative-peer-no-authority` | `ipc`, `security_framework` |
| `gate1a.protocol.positive-vectors` | `verify` | `.primary` | `ipc` |
| `gate1a.protocol.negative-vectors` | `verify` | `.primary`, `.all-negatives-rejected` | `ipc` |
| `gate1a.registry.enroll-rotate-revoke-recover` | `enroll`, `rotate`, `revoke`, `recover` | `.primary`, `.final-state`, `.coordinator-serialized`, `.all-leases-closed` | `ipc`, `ui`, `security_framework` |
| `gate1a.registry.corruption-deny` | `seed`, `corrupt`, `parse-deny` | `.primary`, `.no-transition` | `ipc`, `security_framework` |
| `gate1a.registry.fork-gap-duplicate-deny` | `seed`, `parse-fork`, `parse-gap`, `parse-duplicate` | `.primary`, `.all-malformed-denied` | `ipc`, `security_framework` |
| `gate1a.registry.crash-ambiguous-secitemadd` | `seed`, `arm-crash`, `secitemadd`, `reconcile` | `.primary`, `.one-shot`, `.ambiguous-reconciled` | `ipc`, `security_framework` |
| `gate1a.registry.orphan-cleanup` | `seed-orphan`, `cleanup`, `verify` | `.primary`, `.only-orphan-removed`, `.delete-ambiguity-code-exit1` | `ipc`, `security_framework` |
| `gate1a.registry.active-key-loss` | `seed`, `remove-active`, `recover`, `verify` | `.primary`, `.recovery-required`, `.final-state` | `ipc`, `ui`, `security_framework` |
| `gate1a.confirm.ordinary-success` | `prepare`, `confirm` | `.primary`, `.receipt-context` | `ipc`, `ui` |
| `gate1a.confirm.cancel-and-expire` | `prepare`, `cancel`, `expire` | `.primary`, `.no-confirmed-plan` | `ipc`, `ui` |
| `gate1a.confirm.restart-and-replay-deny` | `prepare`, `confirm`, `restart`, `replay` | `.primary`, `.replay-denied` | `ipc`, `ui` |
| `gate1a.confirm.untrusted-display` | `prepare`, `confirm` | `.primary`, `.bytes-inert` | `ipc`, `ui` |
| `gate1a.network.hard-deny` | `confirm`, `audit` | `.primary`, `.zero-network-bytes` | `network`, `ipc`, `ui` |
| `gate1a.authority.fail-closed-matrix` | `verify-matrix` | `.primary`, `.all-negatives-rejected`, `.profile-expiry-code-exit12` | `ipc`, `security_framework` |
| `gate1a.install.first-install-validation` | `stage`, `install`, `validate`, `launch` | `.primary`, `.exact-tree`, `.profile-valid`, `.ordinary-launch` | `ipc`, `security_framework` |
| `gate1a.install.identical-reinstall` | `install`, `reinstall-identical`, `validate`, `launch` | `.primary`, `.byte-identical`, `.keychain-preserved`, `.ordinary-launch` | `ipc`, `security_framework` |
| `gate1a.install.rollback-and-replacement-deny` | `install`, `attempt-rollback`, `replace-cli`, `replace-helper`, `validate-denials` | `.primary`, `.rollback-denied`, `.cli-replacement-denied`, `.helper-replacement-denied`, `.zero-authority` | `ipc`, `security_framework` |
| `gate1a.install.uninstall-cleanup` | `install`, `seed-gate-state`, `uninstall`, `audit` | `.primary`, `.app-removed`, `.no-silent-keychain-delete`, `.no-post-uninstall-authority` | `ipc`, `security_framework` |
| `gate1a.migration.cancel` | `seed-legacy-sentinel`, `start-migration`, `cancel-presence`, `verify-source`, `verify-destination-absent` | `.primary`, `.source-intact`, `.destination-absent`, `.no-secret-transcript` | `ipc`, `ui`, `security_framework` |
| `gate1a.migration.interruption` | `seed-legacy-sentinel`, `start-migration`, `interrupt-before-commit`, `restart`, `reconcile`, `verify` | `.primary`, `.source-intact-or-exact-destination`, `.no-duplicate`, `.no-secret-transcript` | `ipc`, `ui`, `security_framework` |
| `gate1a.migration.partial-failure` | `seed-legacy-sentinel`, `arm-destination-write-failure`, `migrate`, `reconcile`, `verify` | `.primary`, `.source-intact`, `.partial-destination-ineligible`, `.no-secret-transcript` | `ipc`, `ui`, `security_framework` |

The seven install/migration cases above are a closed Gate 1A set, not examples.
They run on the clean-reset exact-artifact host in E1 and E2 and use the same
descriptor-bound archive retained before descriptor creation. First install
must reproduce the descriptor's installation tree and profile expiry;
identical reinstall must leave the exact code bytes and every preexisting
Keychain item unchanged. Rollback and either-component replacement must fail
peer/artifact validation before authority access. Uninstall must remove the app
and link while leaving approval, credential, registry, coordinator, and journal
state untouched and unusable until an equal authorized artifact is installed.

Migration uses a Gate-owned non-secret sentinel value generated from a fixed
fixture, never a real credential. It drives the ordinary existing
`auth migrate-keychain --profile gate-migration --yes` command through direct
spawn; `--yes` authorizes only this explicit Gate fixture and is not an
installer hook. Cancellation occurs at the native user-presence prompt before
any destination commit. Interruption terminates the process after destination
staging but before source deletion/commit. Partial failure injects exactly one
destination `SecItemAdd` failure through the authenticated Gate fixture
boundary. In all three cases the source remains intact unless an exact,
readable, byte-equal destination has durably committed; partial destination
state is ineligible, never selected as a credential, and is reconciled without
repeating an ambiguous add. Transcripts contain only item identifiers,
OSStatus/reason classes, digests, and bounded projections—not `kSecValueData`
or the sentinel bytes. Cancellation, interruption at every durable boundary,
source-read failure, destination-add success/error/ambiguity, exact-winner,
different-winner, source-delete success/error/ambiguity, restart, and cleanup
partial failure are mandatory schedule fixtures for these cases. Missing any
one is a Gate failure.

| Gate 1B case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `gate1b.issue-create.prepare-confirm-apply-success` | `prepare`, `confirm`, `apply` | `.primary`, `.one-created-issue` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.expected-state-conflict` | `prepare`, `confirm`, `mutate-fixture`, `apply` | `.primary`, `.zero-create` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.timeout-reconcile-created` | `prepare`, `confirm`, `apply-timeout`, `reconcile` | `.primary`, `.one-created-issue` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.timeout-reconcile-absent` | `prepare`, `confirm`, `apply-timeout`, `reconcile` | `.primary`, `.zero-create` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.timeout-reconcile-conflict` | `prepare`, `confirm`, `apply-timeout`, `reconcile` | `.primary`, `.conflict-closed` | `network`, `ipc`, `ui` |
| `gate1b.issue-create.one-shot-no-retry` | `prepare`, `confirm`, `apply`, `audit` | `.primary`, `.one-mutation-dispatch` | `network`, `ipc`, `ui` |
| `gate1b.coordinator.apply-vs-rotate-linearization` | `apply-first`, `rotate-after-close`, `reset`, `rotate-first`, `apply-after-rotation` | `.primary`, `.pre-read-registry-intent-bound`, `.candidate-validated-under-lease`, `.apply-first-serialized`, `.rotation-first-cancels`, `.zero-overlap` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.apply-vs-revoke-linearization` | `apply-first`, `revoke-after-close`, `reset`, `revoke-first`, `apply-after-revocation` | `.primary`, `.pre-read-registry-intent-bound`, `.candidate-validated-under-lease`, `.apply-first-serialized`, `.revocation-first-cancels`, `.zero-overlap` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.apply-vs-recovery-linearization` | `apply-first`, `recover-after-close`, `reset`, `recover-first`, `apply-after-recovery` | `.primary`, `.pre-read-registry-intent-bound`, `.candidate-validated-under-lease`, `.apply-first-serialized`, `.recovery-first-cancels`, `.zero-overlap` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.invalid-enrollment-contention` | `acquire-apply`, `attempt-enrollment`, `verify-busy-before-ledger-read`, `close-apply` | `.primary`, `.one-losing-active-add`, `.busy-before-enrollment-validation`, `.zero-later-authority-read-or-write`, `.closed-and-fenced`, `.busy-code-exit10` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-before-permit` | `prepare`, `confirm`, `acquire`, `crash-before-in-flight`, `recover-before-in-flight`, `reset`, `prepare-again`, `confirm-again`, `acquire-again`, `mark-in-flight`, `crash-before-permit`, `recover-after-in-flight`, `audit` | `.primary`, `.both-pre-permit-states-failed_before_mutation`, `.both-receipts-burned`, `.zero-mutation-dispatch`, `.closed-and-fenced`, `.pre-permit-code-exit13` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-permit-before-send` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `crash`, `recover`, `reconcile`, `audit` | `.primary`, `.ambiguous-no-retry`, `.zero-mutation-dispatch`, `.closed-and-fenced` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-send-before-outcome` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `send`, `crash`, `recover`, `reconcile`, `audit` | `.primary`, `.ambiguous-no-retry`, `.at-most-one-created-issue`, `.closed-and-fenced` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-durable-outcome-before-closed-add` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `send`, `record-outcome-and-normal-close-bytes`, `crash`, `recover-close`, `audit` | `.primary`, `.outcome-and-normal-close-atomic`, `.new-recovery-actor-bound`, `.no-retry`, `.closed-and-fenced`, `.at-most-one-created-issue` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.closed-add-ambiguity` | `run-equal-winner`, `reset`, `run-not-found-then-recover`, `reset-again`, `run-conflicting-winner`, `audit` | `.primary`, `.read-first`, `.equal-reconciled-success`, `.not-found-code-exit11-then-one-identical-add`, `.conflict-code-exit1`, `.no-blind-add`, `.no-resend` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.crash-after-closed-before-active-delete` | `prepare`, `confirm`, `acquire`, `mark-in-flight`, `permit`, `send`, `record-outcome`, `add-closed`, `crash`, `recover-delete`, `audit` | `.primary`, `.closed-fence-survives`, `.no-resend`, `.single-active-delete`, `.at-most-one-created-issue` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.active-delete-ambiguity` | `run-not-found`, `reset`, `run-equal-active-then-recover`, `reset-again`, `run-different-active`, `reset-third`, `run-malformed-active`, `audit` | `.primary`, `.read-first`, `.not-found-reconciled-success`, `.equal-code-exit11-then-one-matching-delete`, `.different-active-stale-noop`, `.malformed-code-exit1`, `.no-blind-delete`, `.closed-fence-survives`, `.no-resend` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.active-cleanup-aba-deny` | `seed-closed-active`, `start-recovery`, `pause-after-equal-read`, `attempt-competing-acquisition`, `delete-active`, `release-guard`, `acquire-competitor`, `close-competitor`, `audit` | `.primary`, `.single-launchd-helper`, `.executor-guard-held`, `.competitor-zero-keychain-before-release`, `.no-aba-replacement`, `.post-release-acquisition`, `.fixed-active-lock` | `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.coordinator.restart-fence-and-close-recovery` | `acquire`, `restart`, `stale-permit`, `recover-close`, `reacquire`, `close`, `audit` | `.primary`, `.new-actor-authenticated`, `.old-token-session-historical`, `.stale-session-denied`, `.single-active`, `.recovery-close-binds-actor-session`, `.durable-close-before-delete`, `.no-retry`, `.recovery-code-exit11` | `network`, `ipc`, `ui`, `security_framework`, `concurrency_trace` |
| `gate1b.authority.status-recover-contract` | `status-clear`, `status-expired-clear`, `seed-unresolved`, `status-recovery`, `reject-flags`, `recover-cancel`, `recover-confirm`, `seed-expired-unresolved`, `recover-expired-cleanup`, `status-after` | `.primary`, `.required-invocation-meta`, `.exact-json-v1-shapes`, `.exact-exits-10-through-13-and-corruption-exit1`, `.explicit-profile`, `.closed-inherited-flags`, `.no-plan-id-or-force-clear`, `.expired-clear-status-closes`, `.cancel-no-change`, `.fresh-presence`, `.new-actor-session-bound`, `.expired-recovery-only`, `.recovery-only-capabilities`, `.zero-network-bytes` | `network`, `ipc`, `ui`, `security_framework` |
| `gate1b.journal.v1-v2-migration-and-quarantine` | `seed-v1-prepared`, `migrate-prepared`, `seed-v1-canceled`, `quarantine-canceled`, `seed-v1-expired`, `quarantine-expired`, `seed-v1-failed_before_mutation`, `quarantine-failed_before_mutation`, `seed-v1-confirmed`, `quarantine-confirmed`, `seed-v1-in-flight`, `quarantine-in-flight`, `seed-v1-remote-state`, `quarantine-remote-state`, `interrupt-before-rename`, `interrupt-after-rename`, `audit` | `.primary`, `.exact-v2-schema`, `.prepared-only-migration-atomic`, `.all-other-valid-v1-byte-preserved`, `.failed_before_mutation-quarantined`, `.quarantine-code-exit1`, `.ambiguous-write-readback`, `.no-authority-from-v1` | `ipc` |
| `gate1b.capability.update-comment-other-deny` | `prepare-negatives`, `apply-negatives` | `.primary`, `.zero-mutation-dispatch` | `network`, `ipc` |
| `gate1b.target.origin-account-project-deny` | `prepare-negatives`, `apply-negatives` | `.primary`, `.zero-target-bytes` | `network`, `ipc` |
| `gate1b.receipt.context-and-replay-deny` | `prepare`, `confirm`, `copy-context`, `replay` | `.primary`, `.zero-mutation-dispatch` | `network`, `ipc`, `ui` |
| `gate1b.authority.fail-closed-matrix` | `verify-matrix` | `.primary`, `.all-negatives-rejected` | `network`, `ipc`, `security_framework` |

| Confirm smoke case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `smoke.confirm.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `smoke.confirm.prepare-confirm-success` | `prepare`, `confirm` | `.primary`, `.smoke-context` | `ipc`, `ui` |
| `smoke.confirm.apply-all-deny` | `apply-negatives` | `.primary`, `.zero-network-bytes` | `network`, `ipc` |
| `smoke.confirm.receipt-context-ineligible` | `consume`, `copy-context`, `replay` | `.primary`, `.terminal-state`, `.ordinary-context-denied` | `ipc` |
| `smoke.confirm.authority-negatives` | `verify-matrix`, `derive-cleanup-context`, `retain-cleanup-intent`, `stage-cleanup`, `verify-cleanup` | `.primary`, `.all-negatives-rejected`, `.cleanup-intent-retained`, `.stage-cleanup-authority`, `.delete-attempt-marked-before-invocation`, `.unresolved-attempt-no-redelete`, `.attributed-deletes-only`, `.cleanup-complete`, `.final-inventory-empty` | `ipc`, `security_framework` |

| Issue-create smoke case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `smoke.issue-create.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `smoke.issue-create.prepare-confirm-apply-dispatch-deny` | `prepare`, `confirm`, `apply` | `.primary`, `.dispatch-deny-code` | `network`, `ipc`, `ui` |
| `smoke.issue-create.zero-mutating-bytes` | `audit` | `.primary`, `.zero-mutation-bytes` | `network` |
| `smoke.issue-create.update-comment-other-deny` | `prepare-negatives`, `apply-negatives` | `.primary`, `.zero-mutation-dispatch` | `network`, `ipc` |
| `smoke.issue-create.receipt-context-ineligible` | `terminalize`, `copy-context`, `replay` | `.primary`, `.terminal-state`, `.ordinary-context-denied` | `network`, `ipc` |
| `smoke.issue-create.authority-negatives` | `verify-matrix`, `derive-cleanup-context`, `retain-cleanup-intent`, `stage-cleanup`, `verify-cleanup` | `.primary`, `.all-negatives-rejected`, `.cleanup-intent-retained`, `.stage-cleanup-authority`, `.delete-attempt-marked-before-invocation`, `.unresolved-attempt-no-redelete`, `.attributed-deletes-only`, `.cleanup-complete`, `.final-inventory-empty` | `network`, `ipc`, `security_framework` |

| Post-grant confirm case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `post-grant.confirm.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `post-grant.confirm.prepare-confirm-success` | `prepare`, `confirm` | `.primary`, `.final-production-context` | `ipc`, `ui` |
| `post-grant.confirm.apply-all-deny` | `apply-negatives` | `.primary`, `.zero-network-bytes` | `network`, `ipc` |
| `post-grant.confirm.receipt-terminal-replay-deny` | `consume`, `replay` | `.primary`, `.terminal-state`, `.replay-denied` | `ipc`, `security_framework` |
| `post-grant.confirm.authority-negatives` | `verify-matrix` | `.primary`, `.all-negatives-rejected` | `ipc`, `security_framework` |
| `post-grant.confirm.cleanup` | `derive-cleanup-context`, `retain-cleanup-intent`, `stage-cleanup`, `verify-cleanup` | `.primary`, `.cleanup-intent-retained`, `.stage-cleanup-authority`, `.delete-attempt-marked-before-invocation`, `.unresolved-attempt-no-redelete`, `.attributed-deletes-only`, `.cleanup-complete`, `.final-inventory-empty` | `ipc`, `security_framework` |

| Post-grant issue-create case | Exact operation step IDs | Case-final assertion suffixes | Additional transcripts |
| --- | --- | --- | --- |
| `post-grant.issue-create.setup-exact-artifact-enrollment` | `pre-enrollment-inventory`, `enroll`, `snapshot` | `.primary`, `.pre-enrollment-empty`, `.setup-only-authority`, `.registry-snapshot` | `ipc`, `ui`, `security_framework` |
| `post-grant.issue-create.prepare-confirm-apply-dispatch-deny` | `prepare`, `confirm`, `apply` | `.primary`, `.final-production-context`, `.dispatch-deny-code` | `network`, `ipc`, `ui` |
| `post-grant.issue-create.zero-mutating-bytes` | `audit` | `.primary`, `.zero-mutation-bytes` | `network` |
| `post-grant.issue-create.receipt-terminal-replay-deny` | `consume`, `replay` | `.primary`, `.terminal-state`, `.replay-denied` | `network`, `ipc`, `security_framework` |
| `post-grant.issue-create.authority-negatives` | `verify-matrix` | `.primary`, `.all-negatives-rejected` | `network`, `ipc`, `security_framework` |
| `post-grant.issue-create.cleanup` | `derive-cleanup-context`, `retain-cleanup-intent`, `stage-cleanup`, `verify-cleanup` | `.primary`, `.cleanup-intent-retained`, `.stage-cleanup-authority`, `.delete-attempt-marked-before-invocation`, `.unresolved-attempt-no-redelete`, `.attributed-deletes-only`, `.cleanup-complete`, `.final-inventory-empty` | `network`, `ipc`, `security_framework` |

For each step and transcript kind, the transcript ID is the case ID, one dot,
the step ID, one dot, and the kind. Every operation step's `assertion_ids` is
exactly `[]`; its `transcript_ids` equals `stdout`, `stderr`, then the additional
kinds in table order. The case-final evaluation's assertion IDs are the full
IDs derived from that row, and its two transcript IDs use step component
`final-evaluation` and kinds `stdout`, then `stderr`. A case with an empty
operation-step list, an empty case-final assertion list, a changed operation,
evaluation, assertion, or transcript order, or an ID not compiled from this
table is rejected before execution.

Each case object contains only `case_id`, `evidence_scope`, `steps`, and
`final_evaluation`, in that order. Steps are ordered operations and
contain these fields in order: `step_id`, `executable_role`,
`executable_component`, `argv`, `working_directory`, `environment`, `stdin`,
`timeout_seconds`, `fixture_ids`,
`assertion_ids`, and `transcript_ids`. `executable_role` is exactly `cli`,
`helper`, `fixture_cli`, `fixture_helper`, `negative_peer_fixture`,
`gate_runner`, or `release_verifier`; it resolves to the descriptor-, fixture-
manifest-, or Gate-plan-pinned executable and is never an argv value. The two
disjoint fixture roles are valid only in the five compiled
`disjoint_fixture` cases; `cli` and `helper` are valid only in
`exact_artifact` cases. `negative_peer_fixture` is valid only for
`launch-negative-outer` and `launch-negative-helper` in
`gate1a.artifact.runtime-peer-validation`; their corresponding reject steps
run the exact current peer or runner and must prove zero authority or registry
access. `executable_component` is exactly `outer`, `helper`, `fixture_cli`,
`fixture_helper`, `gate_runner`, or `release_verifier`; `cli` maps to `outer`
and every other ordinary role maps to its same-named component;
for `negative_peer_fixture` it selects exactly `outer` or `helper` and matches
the step name. `working_directory`
is always null, `environment` is always an empty array, and `stdin` is exactly
`closed`. `timeout_seconds` is an integer `1..300`. Fixture, assertion, and
transcript IDs are 1..128 printable ASCII bytes, explicitly declared in their
respective manifests, unique in their array, and never pathnames supplied by a
caller.

`final_evaluation` contains exactly the fields frozen by the command-contract
`case_evaluations` entry. The runner may create it only after every operation
has terminated and every declared stdout, stderr, and additional transcript
result has been retained by digest. Its canonical stdout is a bounded
case-evaluation aggregate with fields `schema_version` integer `1`, `case_id`,
`ordered_operation_observation_ids`, `ordered_transcript_results_sha256`,
`ordered_exit_codes`, `assertion_results_sha256`, and `result` exactly `pass`,
in that order; stderr is exactly zero bytes. The three ordered arrays match the
operation-step and per-step transcript order without sorting. Case assertions
evaluate only retained operation, transcript, and state inputs; they never
depend on the final aggregate bytes, its stdout digest, or the final observation
digest. The runner first evaluates those assertions, records their manifest,
then emits the aggregate containing that manifest digest and finally the
case-final observation. A crash, timeout, missing transcript, or failed
assertion produces no passing final observation and therefore no passing case
or evidence index.

`argv` has 1..64 entries and at most 16,384 decoded bytes. Every entry is one
closed typed object using one exact schema:

| Kind | Fields in exact order | Constraint |
| --- | --- | --- |
| literal | `source`, `value` | source exactly `literal`; printable ASCII value |
| path | `schema_version`, `token_type`, `source`, `fixture_id`, `content_sha256`, `expected_type`, `access` | the complete typed path-token codec defined above |
| Gate target | `source` | exactly `gate_target_service_url`; Gate 1B only |
| prior output | `source`, `step_id`, `output_field` | source exactly `step_output`; earlier step; output exactly `plan_id` or `receipt_id` |

No other source or output field exists. Dynamic values are produced by the
same runner after schema validation, never interpolated into a shell string,
and substituted as one argv element. Execution uses direct process spawning
with the declared argv, closed stdin, empty environment, no shell, no current-
directory inheritance, and an independent hard timeout. The runner rejects an
undeclared file access, transcript, assertion, network origin, or subprocess.

### Deterministic two-party coordinator schedules

Every Gate 1B coordinator case uses a content-addressed schedule fixture; no
sleep, scheduler luck, polling race, shell, environment variable, inherited
working directory, or caller-selected event may determine its ordering. The
runner creates two unidirectional anonymous pipes per child before direct
spawn, maps only the child release-read end to file descriptor 3 and its
arrival-write end to descriptor 4 with `posix_spawn_file_actions`, closes every
other inherited descriptor, and retains the complementary ends. These four
ends are the only extra descriptors admitted by the sandbox for such a step.
The exact artifact recognizes them only over the already authenticated Gate 1B
runner session bound by E1/E2; an ordinary production invocation, Gate 1A,
smoke, or post-grant token cannot enter a barrier. A crash phase directly
spawns a recovery child only after the crashed child has exited; there are
never more than two live candidate children in one phase.

Each pipe message is exactly 16 bytes: bytes 0..7 are ASCII `YTABARR` followed
by NUL; byte 8 is version `0x01`; byte 9 is kind `0x01` for runner release or
`0x02` for child arrival; byte 10 is actor `0x01` apply, `0x02` registry, or
`0x03` recovery; byte 11 is the event code below; bytes 12..15 are the unsigned
big-endian sequence number starting at one. No short frame, trailing byte,
unknown value, repeated/out-of-order sequence, arrival before release, or
arrival with fields unequal to its release is accepted. The runner releases
one event and waits for that exact arrival within the step timeout before
releasing the next. For `process.crash`, arrival means the child reached the
declared crash boundary; the runner then sends `SIGKILL` to that exact PID and
requires `waitpid` to report that signal before releasing `recovery.start`.

| Code | Event | Required durable observation after arrival |
| ---: | --- | --- |
| `0x01` | `apply.acquire` | exact apply active exists; no permit or close exists |
| `0x02` | `coordinator.acquire-busy` | exactly one losing active `SecItemAdd` returns duplicate/`APPLY_COORDINATOR_BUSY`; zero later ledger/key/journal/permit/closed read or state write follows |
| `0x03` | `apply.in-flight` | journal is durably `in_flight`; no permit exists |
| `0x04` | `apply.permit` | exactly one equal permit exists |
| `0x05` | `apply.send` | exactly one mutating request begins; no second dispatch exists |
| `0x06` | `apply.outcome` | one terminal/non-replayable journal outcome is durable |
| `0x07` | `coordinator.close` | exactly one equal closed record exists |
| `0x08` | `coordinator.delete-active` | active is absent after the one delete or is classified ambiguous |
| `0x09` | `registry.acquire` | exact registry-commit active binds pre-read `registry_intent_sha256`; zero ledger/proposal work preceded it |
| `0x0a` | `registry.commit` | candidate matches that intent under the same lease and exactly one revision winner or deterministic absence exists |
| `0x0b` | `registry.close` | exact registry closed record exists |
| `0x0c` | `registry.delete-active` | active is absent after the one delete |
| `0x0d` | `apply.cancel-stale` | no permit/send; journal and lease are terminal before close |
| `0x0e` | `enrollment.busy-before-ledger` | invalid enrollment loses acquisition before ledger validation or mutation |
| `0x0f` | `process.crash` | selected child reached the boundary; runner then proves its `SIGKILL` exit |
| `0x10` | `recovery.start` | new CLI audit token/helper session pass exact code-identity, descriptor, retained-evidence, trusted-UI, and recovery-fence checks; old token/session are historical; zero sign/acquire/permit/send/commit |
| `0x11` | `coordinator.close-ambiguous-return` | one close add occurred; exact read classifies equal, absent, or conflict |
| `0x12` | `coordinator.delete-ambiguous-return` | one active delete occurred; exact read classifies not-found, equal, or conflict |
| `0x13` | `stale.send-probe` | recovery actor presents the stale permit/session tuple and receives a pre-network denial |
| `0x14` | `helper.restart` | old exact helper connection is invalidated; a newly authenticated exact helper has a different session ID and zero send |
| `0x15` | `coordinator.stale-active-noop` | active contains a different well-formed newer lease; recovery succeeds without delete, close, permit, or send |
| `0x16` | `coordinator.active-equality-read` | under the held authority-executor guard, exact active bytes equal the retained recovery bytes and no delete has begun |
| `0x17` | `coordinator.acquisition-guard-blocked` | a competing authenticated acquisition request is queued between equality read and delete; it performs zero `SecItemAdd`, coordinator reads, or state changes |
| `0x18` | `authority.guard-release` | byte-equal active cleanup and its reconciliation are complete, old active is absent, recovery close is durable, and the executor guard is released exactly once |

The event registry contains exactly 24 codes, `0x01` through `0x18`, without
aliases or extension slots in this protocol version.

`A`, `R`, and `H` below mean actor bytes apply, registry, and recovery. Every
arrow is one release/arrival pair in the shown order. Rotate, revoke, and
recovery use the same two schedules with the transition fixed by their case ID:

The `reset` and `reset-again` steps in multi-phase ambiguity cases are runner-
controlled reversions to the case's clean disposable VM snapshot after every
actor exits. They are not candidate commands, do not delete a production
Keychain item, reuse no receipt/lease/target data, and revalidate the same
descriptor and artifact before the next direct spawn.

| Case/phase | Exact released event sequence |
| --- | --- |
| apply-first rotate/revoke/recovery | `A:apply.acquire -> R:coordinator.acquire-busy -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close -> A:coordinator.delete-active -> R:registry.acquire -> R:registry.commit -> R:registry.close -> R:registry.delete-active` |
| registry-first rotate/revoke/recovery | `R:registry.acquire -> A:coordinator.acquire-busy -> R:registry.commit -> R:registry.close -> R:registry.delete-active -> A:apply.acquire -> A:apply.cancel-stale -> A:coordinator.close -> A:coordinator.delete-active` |
| invalid enrollment contention | `A:apply.acquire -> R:enrollment.busy-before-ledger -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close -> A:coordinator.delete-active` |
| crash while confirmed after acquire | `A:apply.acquire -> A:process.crash -> H:recovery.start -> H:coordinator.close -> H:coordinator.delete-active` |
| crash while in-flight before permit | `A:apply.acquire -> A:apply.in-flight -> A:process.crash -> H:recovery.start -> H:coordinator.close -> H:coordinator.delete-active` |
| crash after permit before send | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:process.crash -> H:recovery.start -> H:apply.outcome -> H:coordinator.close -> H:coordinator.delete-active` |
| crash after send before outcome | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:process.crash -> H:recovery.start -> H:apply.outcome -> H:coordinator.close -> H:coordinator.delete-active` |
| crash after durable outcome before closed add | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:process.crash -> H:recovery.start -> H:coordinator.close -> H:coordinator.delete-active` |
| closed-add ambiguity / equal winner | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close-ambiguous-return -> A:coordinator.delete-active` |
| closed-add ambiguity / not found | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close-ambiguous-return -> H:recovery.start -> H:coordinator.close -> H:coordinator.delete-active` |
| closed-add ambiguity / conflicting winner | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close-ambiguous-return -> H:recovery.start` |
| crash after closed before active delete | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close -> A:process.crash -> H:recovery.start -> H:coordinator.delete-active` |
| active-delete ambiguity / not found | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close -> A:coordinator.delete-ambiguous-return` |
| active-delete ambiguity / equal active | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close -> A:coordinator.delete-ambiguous-return -> H:recovery.start -> H:coordinator.delete-active` |
| active-delete ambiguity / different active | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close -> A:coordinator.delete-ambiguous-return -> H:recovery.start -> H:coordinator.stale-active-noop` |
| active-delete ambiguity / malformed active | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:apply.send -> A:apply.outcome -> A:coordinator.close -> A:coordinator.delete-ambiguous-return -> H:recovery.start` |
| active-cleanup ABA denial | `H:recovery.start -> H:coordinator.active-equality-read -> R:coordinator.acquisition-guard-blocked -> H:coordinator.delete-active -> H:authority.guard-release -> R:registry.acquire -> R:registry.commit -> R:registry.close -> R:registry.delete-active` |
| restart fence and close recovery | `A:apply.acquire -> A:apply.in-flight -> A:apply.permit -> A:helper.restart -> H:recovery.start -> H:apply.outcome -> H:coordinator.close -> H:coordinator.delete-active -> H:stale.send-probe` |

This schedule table contains exactly 18 phases. Each Gate 1B coordinator case
selects only its named phase or phases; an extra, missing, or reordered phase
invalidates the plan digest.

The schedule fixture is a compact canonical object capped at 32,768 bytes with
fields, in order, `schema_version`, `schedule_type` exactly
`gate1b_coordinator`, `case_id`, `phase_id`, `actors`, and `events`; every event
contains `sequence`, `actor`, `event_code`, and `expected_state_sha256` in that
order. `actors` is order-bearing by direct-spawn ordinal and every entry
contains `actor`, `spawn_sequence`, `executable_role`, `executable_component`,
`code_slice_sha256`, and `expected_termination` exactly `exit_zero`,
`exit_nonzero`, or `crash_signal`; it names exactly the children required by
the phase and no supervisor shell. Apply, registry, and recovery actors are
separately direct-spawned outer-CLI processes; they connect to the same already
validated exact helper. `code_slice_sha256` is SHA-256 of the matching compact
canonical descriptor code-slice object. It is one ordinary fixture entry and its bytes are therefore covered by
the Gate fixture-set digest; no digest is invented in this document. The
runner emits one compact canonical `concurrency_trace` transcript with fields
`schema_version`, `case_id`, `phase_id`, `schedule_fixture_sha256`,
`runner_session_id`, `actor_processes`, and ordered `events`.
`actor_processes` exactly equals the schedule's actor order. Each entry has
`actor`, `spawn_sequence`, positive `pid`, connection-bound
`audit_token_sha256`, `executable_sha256`, `ksec_code_info_unique`,
`started_monotonic_ns`, `termination_kind`, and `exit_status` in that order;
code identity must equal the schedule/descriptor and each actor's events must
come from that one authenticated process. Each trace event contains
`sequence`, `actor`, `event_code`, `release_monotonic_ns`,
`arrival_monotonic_ns`, `pre_state_sha256`, `post_state_sha256`,
`mutating_request_count`, and `mutating_request_sha256` in that order. Time is
diagnostic only; the exact frame order and state hashes are authoritative.
For comparison, the verifier projects every trace event to `sequence`,
`actor`, `event_code`, and `expected_state_sha256` (the trace
`post_state_sha256`) in that order; that canonical projected array must equal
the schedule's `events` bytes exactly. Assertions also require every pre-state
to equal the preceding post-state within a phase, the mutating count to remain zero before
`apply.send` and never exceed one, no registry commit between `apply.in-flight`
and `coordinator.close`, and no event from a crashed/stale actor except the
explicit recovery-side stale-session rejection probe. The process assertion also requires exactly
the scheduled child count, direct parent PID equal to the runner, no
intermediate process, one unique PID/audit token per spawn ordinal, and the
scheduled termination classification. Missing, extra, reordered, duplicated,
or unacknowledged events or processes fail the case.

For `active-cleanup ABA denial`, the registry child sends its authenticated
acquisition request only after the recovery child has acknowledged
`coordinator.active-equality-read`. The single helper's Gate-only executor
instrumentation acknowledges `coordinator.acquisition-guard-blocked` when that
request is queued behind the still-held guard, before any acquisition
Keychain call. The runner then releases recovery's delete and guard-release
events; only after the exact guard-release arrival may the queued registry
request execute its one active add. The trace must show the old active digest
until delete, absence at guard release, the new active digest only afterward,
one helper PID throughout, and zero `SecItemAdd` or coordinator read from the
competitor between the equality read and guard release. A replacement active,
a second helper PID/listener, or an acquisition event before release fails the
case.

`helper.restart` is available only to the authenticated Gate 1B schedule. The
apply child requests the exact helper's compiled terminate-at-boundary action,
observes its XPC invalidation, and acknowledges only after the old helper PID
has exited and launchd reports no running instance for the per-user job label.
The runner then asks launchd to activate the normal signed helper service
through its fixed service endpoint—never a shell, direct server spawn, second
listener, or substitute binary—and the
recovery child's authentication records the new PID, audit-token digest, code
identity, and coordinator session in the IPC/Security.framework transcripts.
The old and new code identities must equal the descriptor, while PID and
session must differ; the new helper's serialized authority executor completes
startup classification under its guard before ordinary work; no permit/send
capability or in-process guard crosses that restart.

The positive issue-create workflow contains three distinct ordered steps:
`prepare`, `confirm`, then `apply`. `confirm` obtains `plan_id` only from the
validated prepare envelope; `apply` obtains that same `plan_id` and the
confirmed `receipt_id` only from validated earlier envelopes. Combining,
omitting, reordering, or replacing a step is a failure. Smoke uses the same
three-step workflow, but its apply step is expected to reach the unique
pre-write dispatch denial rather than a remote mutation.
Post-grant `issue_create` verification also uses those exact three ordinary
steps with real grant-bound authority, but the session token forces its own
pre-socket dispatch denial after read-only loopback preflight.

For every operation step the plan implies exactly one observation ID formed by
the case ID, one slash, and the step ID, followed by the mandatory case ID plus
`/final-evaluation` observation. Evidence observations must equal that complete
derived list byte-for-byte and in order—no missing, duplicate, reordered, early,
or additional entry. The observation scope must equal its case scope. Every
operation observation carries exact `assertion_ids=[]`; only the final
evaluation carries the case row's ordered assertion IDs. The recorded
`command_sha256` covers a compact canonical execution context containing that
scope, executable role and component, the resolved executable's exact canonical descriptor
slice, disjoint-fixture slice, or negative-peer slice digest, resolved argv
array, null working
directory, empty environment, closed stdin, timeout, fixture hashes, assertion
IDs, and transcript IDs. Recording merely a display string or a shell command
is invalid. For a final evaluation, `command_sha256` instead covers its
canonical evaluation context: case ID/scope, pinned runner identity, every
prior operation observation ID and result-manifest digest in order, and the
compiled final assertion/transcript IDs. It cannot be computed before the last
operation result exists.

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
8. `prerequisite_gate1a_e2_evidence_set_sha256`, null for Gate 1A and the
   complete Gate 1A E2 set for Gate 1B
9. `architecture`, exactly one architecture declared by the descriptor
10. `gate_runner_unique`
11. `gate_session_id`
12. `allowed_capability`, `confirm_only` for Gate 1A or `issue_create_gate`
    for Gate 1B
13. `allowed_network`, `none` for Gate 1A or `exact_gate_target` for Gate 1B
14. `issued_at`
15. `expires_at`

`gate_runner_unique` is lowercase hex of the signed Gate runner's
Security.framework unique identifier. `gate_session_id` is unpadded base64url
of 32 random bytes. E1 validity is at most 30 minutes.

The candidate accepts E1 only over an inherited, already connected local Gate
session descriptor. It validates the runner's connection-bound audit token,
exact runner identifier, Developer ID requirement, unique identifier, and a
challenge response bound to the session ID. A token copied to another process
or session is unusable. E1 cannot be loaded from either production sidecar
path and is never shipped.

Under a Gate 1A E1 token, every `exact_artifact` case runs against the normal
CLI confirmation command and real signed helper/Keychain boundary; this
includes ordinary enroll, rotate, revoke, and recover. The five destructive
registry corruption, malformed-ledger, ambiguous-add, orphan-cleanup, and
active-key-loss cases instead run only the
manifest-pinned disjoint fixture pair in its disjoint Keychain service,
filesystem root, and IPC namespace; they never execute or modify production
registry state. The old-build negative peer may appear only in the exact
runtime mixed-build rejection substeps and must gain no authority. Network
creation is denied by the process sandbox. A Gate 1B E1 token is issued
only for a candidate that has already completed the two-pass Gate 1A sequence;
it permits the ordinary one-shot `issue.create` path only against the exact
disposable target named by `gate_target_sha256`. Every other capability or
origin fails closed. A pass records the descriptor, Gate ID, token, plan and
target digests, fixture hashes and executable manifest, per-observation scope
and executable identity, OS/architecture, times, and result in immutable
evidence.

One distinct E1 token and fresh runner session is required for every declared
architecture. A token is invalid on a different architecture, and passing one
slice cannot stand in for another.

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
9. `prerequisite_gate1a_e2_evidence_set_sha256`, exactly matching E1
10. `architecture`, exactly matching its E1 evidence index
11. `gate_runner_unique`
12. `gate_session_id`
13. `allowed_capability`, exactly the matching E1 capability
14. `allowed_network`, exactly the matching E1 network policy
15. `issued_at`
16. `expires_at`

E2 has the same 30-minute maximum and runner/session checks as E1. The run
starts from another clean host or freshly reverted snapshot and repeats every
ordered observation in the same content-addressed Gate plan, including the
exact artifact/fixture scope partition and a fresh disjoint fixture namespace.
Gate 1A remains network-free. Gate 1B again permits only the exact disposable target, performs
its real one-shot write/reconciliation cases, and must start from a fresh
project fixture. It records the E2 token, prior E1 evidence, descriptor, full
rerun evidence, network transcript, and target reset. A partial, cached, or
smoke-only second pass is invalid.

Every declared architecture receives its own E2 token after that
architecture's E1 pass, with a new random session ID and a freshly reset host
or snapshot. E1 and E2 session IDs must differ across all Gate IDs,
architectures, and stages.

E1/E2 are capabilities of a signed runner session, not production feature
flags. A Gate 1B token can exist only after the same descriptor's Gate 1A E1
and E2 evidence validate. The ordinary provisional/grant path rejects all Gate
token types and domains. The release binary contains no environment switch
that converts a Gate token into production authority.

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
10. `prerequisite_gate1a_e2_evidence_set_sha256`, null for Gate 1A and required for Gate 1B
11. `gate_runner_unique`
12. `gate_session_id`
13. `macos_product_build_version`, printable ASCII, at most 32 bytes
14. `architecture`, `arm64` or `x86_64`
15. `fixture_set_sha256`
16. `fixture_executable_manifest_sha256`, the Gate 1A plan value or null for
    Gate 1B
17. `evidence_scopes`, exactly the ordered unique case scopes in the plan
18. `started_at`
19. `finished_at`
20. `result`, exactly `pass`
21. `observations`, an ordered JSON array

Observation order is the order frozen by the Gate plan. Each entry contains
`observation_id`, `evidence_scope`, `executable_role`, `executable_component`,
`executable_identity_sha256`, `command_sha256`, `stdout_sha256`,
`stderr_sha256`, `exit_code`, `registry_snapshot_sha256`, `assertion_ids`,
`assertion_results_sha256`, and `transcript_results_sha256`, in that order.
`registry_snapshot_sha256` is null for Gate 1A/Gate 1B and for activation-
smoke/post-grant setup operations before snapshot creation. It equals the exact
retained post-enrollment snapshot for the setup `snapshot` operation, its
final evaluation, and every later stage observation. Scope and role exactly
match the compiled case, step, or case-final evaluation.
`executable_identity_sha256` hashes the complete exact
descriptor code-slice entry (`cli` maps to `outer`, `helper` to `helper`),
fixture-executable slice for `fixture_cli`/`fixture_helper`, negative-peer slice
selected by `executable_component` for `negative_peer_fixture`, or the separately pinned runner or verifier
identity object for a supervisor. A negative-peer identity can occur only in
its compiled rejection observation and never satisfies an exact-artifact
positive identity assertion.
Observation IDs are printable ASCII of 1..128 bytes; digests use the common
grammar; exit codes are JSON integers `0..255`. Secret-bearing output is a Gate
failure and is never made acceptable merely by hashing it.

An assertion-result manifest is compact canonical JSON capped at 32,768 bytes
with fields `schema_version` integer `1`, `manifest_type` exactly
`assertion_results`, `observation_id`, and `entries`, in that order. Each entry
has `assertion_id`, `evaluator`, `expected_sha256`, `actual_sha256`, and
`result` exactly `pass`, in that order. For an operation observation, `entries`
and the observation's `assertion_ids` are both exact empty arrays. For a
case-final evaluation they exactly equal the row's compiled assertion order
and the evaluator/expected digest in the assertion-set manifest. No operation
may claim an assertion pass before the case-final aggregate exists.

A transcript-result manifest has the same cap and fields `schema_version`,
`manifest_type` exactly `transcript_results`, `observation_id`, and `entries`.
Each entry has `transcript_id`, `transcript_kind`, `content_sha256`,
`byte_count`, `redaction_result` exactly `no_secret_detected`, and `result`
exactly `captured`, in that order. Entries exactly equal the compiled
`transcript_ids` order and kind; byte count is within the transcript-set cap and
the retained content file matches its digest.

The final evaluator's stdout is the exact case-evaluation aggregate defined
above. Its assertion-result manifest is created only after every ordered
operation transcript-result manifest has been loaded and matched to the
aggregate; its own transcript-result manifest then captures the final stdout
and empty stderr. This makes assertion suffixes case-final, not aliases for an
arbitrarily early operation result.

The two observation fields hash the exact respective result-manifest bytes.
The runner and offline verifier both require one-to-one equality: every
required ID occurs once, no unrequired ID occurs, all expected and actual
objects are retained by digest, and every result has the required success
literal. The observation's direct stdout/stderr digests must equal the content
digests of its exact stdout/stderr transcript entries. An aggregate success
bit, unordered map, missing result manifest, or
digest referring to a different observation is invalid. In particular, a
nonempty operation `assertion_ids`, an assertion result on a non-final
observation, an evaluation emitted before the final operation transcript, or a
missing/reordered final evaluation invalidates the run; there is no pass bit
that can substitute for it.

Gate 1A observations include every approval-protocol, code-identity, Keychain,
UI-presence, fail-closed, restart, and clean-host test. Gate 1B observations
include its ordinary CLI live-write, helper-owned coordinator, apply-versus-
registry linearization, lease fencing, every pre/post-permit crash boundary,
one-shot send, fault, and reconciliation cases.
E2 contains the complete repeated observation set for its Gate ID. Missing,
duplicated, reordered, or additional observations are a failure against the
content-addressed Gate plan.

An evidence digest is lowercase SHA-256 over the exact canonical index bytes.
Every referenced transcript/assertion/file is separately published by its
digest; before signing E2, provisional authorization, or activation grant, the
offline ceremony verifies the entire closed set and recomputes the index. A
detached index with a missing or mismatched referenced file is invalid even if
its own digest is correct.

Passing indexes are collected into one canonical evidence-set manifest,
capped at 16,384 bytes. Its fields are `schema_version` integer `1`,
`evidence_set_type` exactly `gate_e1`, `gate_e2`, or `activation_smoke`,
`gate_id` exactly `gate1a`, `gate1b`, or `activation_smoke`,
`descriptor_sha256`, `gate_plan_sha256`, `gate_target_sha256`,
`provisional_context_sha256`, `fixture_executable_manifest_sha256`,
`evidence_scopes`, `architectures`, `indexes`, `registry_snapshots`, and
`result` exactly `pass`, in that order. Gate sets use null provisional context,
smoke uses null Gate target, and `registry_snapshots` is null for Gate sets.
The fixture-executable digest is required only for Gate 1A. Gate 1A
scope order is exactly `exact_artifact`, then `disjoint_fixture`; Gate 1B and
smoke contain only `exact_artifact`. `architectures` exactly equals the
descriptor array.
For Gate sets, `indexes` has one entry per architecture in that same order,
with fields `architecture`, `evidence_index_sha256`, `gate_token_sha256`, and
`gate_session_id` in order. For activation smoke, each entry appends
`setup_context_sha256`, `pre_enrollment_inventory_sha256`,
`registry_snapshot_sha256`, `cleanup_context_sha256`,
`cleanup_intent_sha256`, `final_cleanup_progress_sha256`,
`helper_cleanup_evidence_sha256`, `stage_cleanup_evidence_sha256`,
`cleanup_evidence_sha256`, and `final_empty_inventory_sha256`, in that order.
Its non-null
`registry_snapshots` array has one entry per descriptor architecture, in that
order, with fields `architecture` and `registry_snapshot_sha256`; it must
exactly project the matching index entries. Every tuple must match its
canonical index, root-signed token, and retained setup/cleanup evidence. All
token and session IDs are unique across all sets.

An evidence-set digest is SHA-256 over the exact manifest bytes. A Gate stage
passes only as the complete set; no per-architecture index, subset, combined
session, or architecture copied from another descriptor may satisfy a later
token or authorization.

## Provisional production authorization and pre-grant context

Only after complete E1 and E2 evidence sets exist for every declared
architecture may the offline root sign a provisional production
authorization. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `authorization_type`, exactly `provisional_first_release_production`
3. `authority_key_id`
4. `descriptor_sha256`
5. `gate1a_e1_evidence_set_sha256`
6. `gate1a_e2_evidence_set_sha256`
7. `gate1a_plan_sha256`
8. `gate1a_evidence_scopes`, exactly `exact_artifact`, then
   `disjoint_fixture`
9. `gate1b_e1_evidence_set_sha256`, null for a confirmation-only artifact
10. `gate1b_e2_evidence_set_sha256`, null for a confirmation-only artifact
11. `gate1b_plan_sha256`, null for a confirmation-only artifact
12. `gate1b_evidence_scopes`, null for a confirmation-only artifact or the
    one-element array `exact_artifact`
13. `app_payload_archive_sha256`, exactly the descriptor value
14. `approved_capability`, exactly `confirm_only` or `issue_create`
15. `minimum_registry_schema`, integer `1`
16. `minimum_receipt_schema`, integer `3`
17. `issued_at`
18. `smoke_not_before`

This object is deliberately non-activating. Ordinary `mutation confirm` and
every `mutation apply` fail with `PRODUCTION_ACTIVATION_REQUIRED` when only the
provisional authorization is present. It is accepted solely as an input to a
valid activation-smoke token in a matching Gate runner session. No timestamp,
command flag, environment value, or network state promotes it.
`smoke_not_before` is not before `issued_at`; a smoke token issued earlier is
invalid.

A `confirm_only` provisional authorization requires all Gate 1B fields to be
null. An `issue_create` authorization requires all four Gate 1B fields and
complete Gate 1B sets whose indexes each name a valid Gate 1A prerequisite for
the same architecture. Gate 1A's two scope values and Gate 1B's exact-artifact
scope are mandatory and must equal their plans, indexes, and final evidence
sets. The disjoint registry fixture therefore contributes required
corruption, fork/gap/duplicate, ambiguous-add, orphan-cleanup, and active-key-
loss evidence without ever being represented as execution of the production
artifact. Ordinary enroll/rotate/revoke/recover evidence remains exact-
artifact execution. Other operations are never implied.

The provisional context is a compact canonical unsigned object capped at
8,192 bytes. Its fields are `schema_version` integer `1`, `context_type`
exactly `provisional_first_release`, `authority_key_id`, `descriptor_sha256`,
`provisional_authorization_sha256`, `gate1a_e1_evidence_set_sha256`,
`gate1a_e2_evidence_set_sha256`, `gate1a_plan_sha256`,
`gate1a_evidence_scopes`,
`gate1b_e1_evidence_set_sha256`, `gate1b_e2_evidence_set_sha256`,
`gate1b_plan_sha256`, `gate1b_evidence_scopes`,
`app_payload_archive_sha256`, `approved_capability`,
`minimum_registry_schema`, and `minimum_receipt_schema`, in that order. Its
digest is SHA-256 over the exact canonical bytes, with no domain prefix. Every
value must exactly equal the provisional authorization and descriptor. There
are no nullable values beyond the capability-specific four-field Gate 1B
group.
`provisional_context_sha256` names this digest. It is a smoke input only and is
not the context accepted by ordinary peers or production receipts.

### Stage-only first exact-artifact enrollment

Every activation-smoke and post-grant capability plan begins with its compiled
`setup-exact-artifact-enrollment` case on a newly created disposable macOS user
or VM. The stage token contains `setup_authorization` exactly
`first_exact_artifact_enrollment_only`. After validating that token, the exact
runner and artifact derive a compact canonical setup context capped at 4,096
bytes with fields, in order, `schema_version` integer `1`, `context_type`
exactly `stage_first_exact_artifact_enrollment`, `stage_type` exactly
`activation_smoke` or `post_grant_verification`, `descriptor_sha256`,
`stage_token_sha256`, `architecture`, `approved_capability`,
`gate_runner_unique`, `gate_session_id`, and `setup_authorization` exactly
`first_exact_artifact_enrollment_only`. `setup_context_sha256` is SHA-256 of
those exact bytes. This context is accepted only for the first case's one
revision-1 enrollment ceremony. It cannot authorize rotation, recovery,
revocation, another enrollment, plan preparation, receipt signing,
confirmation, apply, coordinator permit, or network access. The ordinary smoke
receipt context or final production context, not this setup context, controls
all later workflow authority.

After the retained setup snapshot exists, the runner and exact artifact derive
a second compact canonical context capped at 4,096 bytes with fields, in order,
`schema_version` integer `1`, `context_type` exactly
`stage_attributed_cleanup`, `stage_type`, `descriptor_sha256`,
`stage_token_sha256`, `setup_context_sha256`, `registry_snapshot_sha256`,
`architecture`, `approved_capability`, `gate_runner_unique`, `gate_session_id`,
and `cleanup_authorization` exactly `attributed_stage_cleanup_only`.
`cleanup_context_sha256` is plain SHA-256 of those exact bytes. It is accepted
only by the final case's distinct `stage_cleanup` IPC operation and only while
the root-signed stage token remains valid. Neither setup nor cleanup context can
sign a registry/receipt, acquire or exercise a permit, send, cross a session,
or substitute for smoke receipt/final production authority.

Before any registry, coordinator, signing-key, journal, plan, receipt, socket,
or loopback state is created, the first case emits a compact canonical
pre-enrollment inventory capped at 8,192 bytes. Its fields are, in order,
`schema_version` integer `1`, `evidence_type` exactly
`stage_pre_enrollment_empty_inventory`, `stage_type`, `descriptor_sha256`,
`architecture`, `gate_runner_unique`, `gate_session_id`, `registry_service`,
`registry_accounts`, `coordinator_service`, `coordinator_accounts`,
`signing_key_tag_prefix`, `signing_key_tags`, `journal_root_inventory_sha256`,
`runner_session_state_sha256`, `observed_at`, and `result` exactly `empty`.
The two services and tag prefix are the fixed production values from the
registry protocol. All three account/tag arrays are exact empty arrays.
`journal_root_inventory_sha256` hashes a compact canonical empty regular-file
inventory, and `runner_session_state_sha256` hashes a compact canonical object
whose `plans`, `receipts`, `sockets`, `loopback_accounts`, and
`temporary_sidecars` arrays, in that order, are all empty. The already
authenticated immutable stage token and its setup context are held outside
this mutable disposable inventory. Bounded exact Keychain enumeration, an
already opened no-follow journal-root descriptor, and runner-owned state
enumeration must all independently prove emptiness; not-found is accepted only
where the exact Security.framework contract declares it.

The single setup enrollment must commit revision 1/generation 1 and durably
close and remove its coordinator active record before its `snapshot` operation
emits a compact canonical post-enrollment registry snapshot capped at 16,384
bytes. Its fields are, in order, `schema_version` integer `1`, `evidence_type`
exactly `stage_post_enrollment_registry_snapshot`, `stage_type`,
`descriptor_sha256`, `stage_token_sha256`, `setup_context_sha256`,
`pre_enrollment_inventory_sha256`, `architecture`, `gate_runner_unique`,
`gate_session_id`, `registry_service`, `registry_revision` integer `1`,
`registry_record_sha256`, `generation` integer `1`, `signing_key_tag`,
`signing_key_spki_der_b64u`, `signing_key_fingerprint_sha256`,
`setup_transcript_manifest_sha256`, `generated_key_tags`,
`coordinator_closed_sha256`, and `created_at`. `generated_key_tags` is the
helper-owned creation-order array and contains exactly the snapshot tag at this
boundary. The revision record, generation,
SPKI, fingerprint, descriptor, architecture, runner unique, and session must
equal the enrolled exact artifact and token. `registry_snapshot_sha256` is
SHA-256 of these exact bytes. The snapshot operation, setup final evaluation,
every later observation, the per-architecture evidence index, and its
evidence-set entry all carry this same digest; no later enumeration may silently
substitute current registry state for it.

The pre-enrollment inventory, setup context, registry snapshot, every result
they reference, and failure evidence are written to immutable
content-addressed storage outside the disposable user/session root and outside
the disposable Keychain namespace before the runner advances. The runner may
read them only by preopened digest-bound handles. The final cleanup emits the
same inventory schema with `evidence_type` exactly
`stage_final_empty_inventory`; every account/tag array and both mutable-state
inventories must again be empty. Its digest is `final_empty_inventory_sha256`.
Cleanup passes only when this final inventory is byte-equivalent to the initial
empty state after ignoring the two evidence-type/timestamp fields and when the
recorded registry revision/key and all later journal/session state have been
removed. Before its first deletion, the runner must retain the cleanup context,
canonical intent, and initial progress bytes required by the registry
protocol's [release-stage cleanup authority](gate1a-registry-protocol.md#release-stage-cleanup-authority).

Every stage failure or timeout runs one bounded cleanup decision from the last
retained inventory and append-only evidence. Attributed deletion is attempted
only when the valid setup snapshot, cleanup context, intent, initial progress,
and unexpired token already exist; it then uses only `stage_cleanup`. A failure
before that complete authority exists performs read-only five-domain probes.
If they are not canonically empty—including enrollment committed but snapshot
not retained—the trusted runner quarantines and destroys the entire disposable
user/VM without a per-item delete. If even the pre-enrollment inventory was not
retained, the same probes run and any incomplete result is uncertain. If a
valid stage cleanup or read-only probe proves the final empty inventory, the
failed run and all candidate outputs are still invalid. Otherwise destruction
is mandatory; no best-effort delete can qualify the run. Failure, cleanup
uncertainty, missing retained evidence, or destruction uncertainty invalidates
every observation, index, evidence set, token-derived context, and publication
input from that session.

## Mandatory activation smoke

For each declared architecture, the offline root signs a distinct smoke token
with a fresh runner session. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `activation_smoke`
3. `authority_key_id`
4. `descriptor_sha256`
5. `provisional_authorization_sha256`
6. `provisional_context_sha256`
7. `gate_plan_sha256`
8. `architecture`
9. `approved_capability`, exactly matching the provisional authorization
10. `gate_runner_unique`
11. `gate_session_id`
12. `setup_authorization`, exactly
    `first_exact_artifact_enrollment_only`
13. `cleanup_authorization`, exactly `attributed_stage_cleanup_only`
14. `loopback_origin`, null for `confirm_only` or `http://127.0.0.1:` followed
    by one canonical decimal port in `1..65535` for `issue_create`
15. `dispatch_deny_code`, null for `confirm_only` or exactly
    `GATE_PRODUCTION_MUTATION_DISPATCH_DENIED` for `issue_create`
16. `issued_at`
17. `expires_at`, no more than 30 minutes after issue

The smoke plan's descriptor, capability, architecture set, and provisional
context must match the token and provisional authorization; the plan must begin
with the capability-specific setup case and carry
`stage_setup_policy=first_exact_artifact_enrollment_v1` and
`stage_cleanup_policy=attributed_stage_cleanup_v1`. Smoke tokens and
sessions are unique across architectures and every E1/E2 session. The token
uses its setup and cleanup fields only through the separately derived setup
and cleanup contexts. Outside the first setup case and final cleanup case it
only restricts provisional authority inside its authenticated runner session.
It cannot activate ordinary use and is never shipped.

Both smoke workflows first run their exact-artifact setup case, retain the
proved-empty pre-inventory and revision-1 registry snapshot, and bind that
snapshot into every later observation. For `confirm_only`, the hard-coded
smoke workflow then prepares and confirms through the ordinary commands on a
clean network-disabled host and proves all apply operations remain disabled.
For `issue_create`, it then uses the hard-coded `prepare -> confirm -> apply`
issue-create workflow. Only the exact
instrumented loopback read-only fixture is reachable. The harness verifies the
ordered preflight reads, then requires the ordinary executor to reach
`GATE_PRODUCTION_MUTATION_DISPATCH_DENIED` at the final transport boundary
before opening or writing a mutating request. No mutating request-line, header,
or body byte may reach a socket. An earlier parse, authority, journal,
capability, or preflight failure cannot satisfy this case.

The smoke token derives a disposable canonical receipt-context object capped
at 4,096 bytes. Its fields are `schema_version` integer `1`, `context_type`
exactly `activation_smoke`, `descriptor_sha256`,
`provisional_authorization_sha256`, `provisional_context_sha256`,
`smoke_token_sha256`, `architecture`, `approved_capability`, and
`gate_session_id`, in that order. Its digest is SHA-256 over those exact bytes.
Every smoke-created plan and schema-v3 receipt carries that value, never the
different `first_release_production` context digest. Smoke uses a runner-created
mode-0700 profile/journal root, a loopback-only account, and no production credential.
The journal atomically stores a stage-tagged historical authority set with the
receipt: `stage_type` exactly `activation_smoke`, the exact descriptor, signed
provisional authorization, signed smoke token, canonical provisional context,
canonical smoke receipt context, and every digest. It contains no activation
grant. For `confirm_only`, the compiled `consume` step moves `confirmed` to the
runner-only terminal state `activation_smoke_consumed` after all apply denials.
For `issue_create`, ordinary apply first persists `in_flight`; after the exact
pre-socket dispatch denial and zero-mutation evidence, `terminalize` moves it
to `activation_smoke_consumed`. That state cannot be reconciled, applied,
confirmed, or returned to an earlier state; replay must return
`RECEIPT_ALREADY_CONSUMED` without UI, preflight, or network access. After
evidence capture the runner deletes that root through its bounded cleanup path.
Copied, retained, or cleanup-failed smoke receipts remain
context-ineligible under the later activation grant and cannot be reconciled
or applied in an ordinary profile.

The terminal transition emits a compact canonical evidence object capped at
8,192 bytes with fields `schema_version` integer `1`, `evidence_type` exactly
`activation_smoke_terminal_journal`, `descriptor_sha256`,
`provisional_authorization_sha256`, `smoke_token_sha256`,
`smoke_receipt_context_sha256`, `architecture`, `gate_session_id`, `plan_id`,
`registry_snapshot_sha256`, `receipt_id`, `receipt_sha256`, `prior_state`, `terminal_state` exactly
`activation_smoke_consumed`, `journal_revision`, and `transitioned_at`, in
that order. `prior_state` is `confirmed` for `confirm_only` and `in_flight` for
`issue_create`. The evidence and replay-denial observation are mandatory; a
smoke `in_flight` record is never eligible for ordinary reconciliation.

The last smoke case performs bounded cleanup and then `verify-cleanup`; no
operation follows it except its case-final evaluation. It emits a compact
canonical object capped at 8,192 bytes with fields, in order,
`schema_version` integer `1`, `evidence_type` exactly
`activation_smoke_cleanup`, `descriptor_sha256`, `smoke_token_sha256`,
`architecture`, `gate_session_id`, `registry_snapshot_sha256`,
`cleanup_context_sha256`, `cleanup_intent_sha256`,
`final_cleanup_progress_sha256`, `helper_cleanup_evidence_sha256`,
`stage_cleanup_evidence_sha256`,
`terminal_journal_evidence_sha256`, `pre_enrollment_inventory_sha256`,
`removed_registry_record_sha256`, `removed_signing_key_tags`,
`journal_cleanup_sha256`, `final_empty_inventory_sha256`, `finished_at`, and
`result` exactly `pass`. The removed record and single key tag exactly equal
the retained setup snapshot. The five cleanup digests resolve to the immutable
context, intent, completed prefix, and helper/runner evidence objects defined
by the registry protocol; each repeats the same token, context, snapshot, and
session bindings. UI-fail exact reads prove the registry,
coordinator, and signing-key namespace absent; the no-follow filesystem probe
proves the journal/session root empty. A copied sidecar, plan, receipt, socket,
loopback account, registry item, coordinator item, key, or journal file makes
the final inventory nonempty and invalidates the complete smoke set.

Each architecture produces a canonical smoke evidence index capped at 65,536
bytes with these fields in order: `schema_version` integer `1`, `evidence_type`
exactly `activation_smoke_pass`, `gate_id` exactly `activation_smoke`,
`descriptor_sha256`, `gate_token_sha256`, `gate_plan_sha256`,
`gate_target_sha256` null, `allowed_capability`,
`prior_e1_evidence_sha256` null,
`prerequisite_gate1a_e2_evidence_set_sha256` null,
`gate_runner_unique`, `gate_session_id`, `macos_product_build_version`,
`architecture`, `fixture_set_sha256`, `fixture_executable_manifest_sha256`
null, `evidence_scopes` exactly the one-element array `exact_artifact`,
`started_at`, `finished_at`, `result` exactly `pass`,
`provisional_authorization_sha256`,
`provisional_context_sha256`, `setup_context_sha256`,
`pre_enrollment_inventory_sha256`, `registry_snapshot_sha256`,
`smoke_receipt_context_sha256`, `terminal_journal_evidence_sha256`,
`cleanup_context_sha256`, `cleanup_intent_sha256`,
`final_cleanup_progress_sha256`, `helper_cleanup_evidence_sha256`,
`stage_cleanup_evidence_sha256`,
`cleanup_evidence_sha256`, `final_empty_inventory_sha256`, and `observations`.
Observations exactly equal the capability-specific smoke plan, including
the first setup case, case-final evaluations, authority-negative,
receipt-context, cleanup, ordered preflight, dispatch-deny, and zero-mutating-
byte assertions. The setup `snapshot` observation and every observation after
it carry the index's exact `registry_snapshot_sha256`. The cleanup and final
inventory digests resolve to the retained objects above. The per-architecture
indexes form the canonical `activation_smoke` evidence-set manifest defined
above.

## Production activation grant

Only after the complete smoke evidence set passes may the offline root sign a
production activation grant. Its unsigned fields are:

1. `schema_version`, integer `1`
2. `grant_type`, exactly `first_release_production_activation`
3. `authority_key_id`
4. `descriptor_sha256`
5. `provisional_authorization_sha256`
6. `provisional_context_sha256`
7. `gate1a_e1_evidence_set_sha256`
8. `gate1a_e2_evidence_set_sha256`
9. `gate1a_plan_sha256`
10. `gate1a_evidence_scopes`
11. `gate1b_e1_evidence_set_sha256`
12. `gate1b_e2_evidence_set_sha256`
13. `gate1b_plan_sha256`
14. `gate1b_evidence_scopes`
15. `activation_smoke_gate_plan_sha256`
16. `activation_smoke_evidence_set_sha256`
17. `approved_capability`
18. `minimum_registry_schema`, integer `1`
19. `minimum_receipt_schema`, integer `3`
20. `activated_at`
21. `release_not_before`

All fields match the descriptor, provisional authorization, provisional
context, Gate sets/plans, scopes, and smoke set/plan. The Gate 1B evidence
digests, plan, and scope field follow the
same exact null rule for `confirm_only`; the smoke values are never null. The
grant never contains or signs the final authorization-context digest, avoiding
a circular hash.
`activation_smoke_gate_plan_sha256` must exactly equal `gate_plan_sha256` in
every smoke token, smoke evidence index, and the smoke evidence-set manifest;
there is no second smoke-plan digest or alias.
`release_not_before` is not before `activated_at`; runtime denies authority
before it.

After the complete signed grant bytes exist, both peers derive the final
production authorization context as compact canonical JSON capped at 4,096
bytes. Its fields are `schema_version` integer `1`, `context_type` exactly
`first_release_production`, `authority_key_id`, `descriptor_sha256`,
`provisional_authorization_sha256`, `production_activation_grant_sha256`,
`approved_capability`, `minimum_registry_schema`, and
`minimum_receipt_schema`, in that order. Every value must equal the descriptor,
provisional authorization, and grant. `authorization_context_sha256` is
SHA-256 over those exact bytes, with no domain prefix.

Runtime production authority requires both signed sidecars, valid under their
distinct domains, and exact agreement with the derived final context. Each
peer independently derives and exchanges that digest before any authority
protocol bytes. Two different grants necessarily produce different final
contexts and cannot be silently mixed. The provisional authorization or grant
alone, a mismatched pair, or any missing evidence/context binding denies
confirmation and apply before profile or network access.

Receipt schema 3 adds `authorization_context_sha256` immediately after
`registry_revision` to the unsigned and signed receipt contract. Because v3 is
not implemented or shipped, this is part of its required pre-Gate delta rather
than a new schema version. Production confirmation and apply require it to
equal the final production authorization-context digest. The distinct smoke
context and every earlier schema are ineligible. This delta must be frozen in
the approval-protocol vectors before Gate begins.

The closed capability matrix is:

| Matching provisional + grant | `mutation confirm` | `mutation apply` for `issue.create` | Apply for `issue.update` / `comment.add` / other |
| --- | --- | --- | --- |
| provisional only | denied before profile access | denied before profile access | denied before profile access |
| grant only | denied before profile access | denied before profile access | denied before profile access |
| mismatched pair/context/evidence | denied before profile access | denied before profile access | denied before profile access |
| peers select different valid grants/final contexts | denied before protocol bytes | denied before protocol bytes | denied before protocol bytes |
| `confirm_only` | allowed with production context | denied before preflight | denied before preflight |
| `issue_create` | allowed with production context | allowed only for a confirmed schema-3 receipt and canonical `issue.create` plan in the same context | denied before preflight |

There is no set union, prefix match, implied wildcard, caller-selected
capability, or Gate-token substitution. Signing provisional authorization,
smoke tokens, and the activation grant changes no executable, bundle, payload
archive, or descriptor byte. Any rebuild, re-sign, re-notarization, restaple,
entitlement/profile change, or archive repack starts again at E1.

## Mandatory post-grant production-path verification

The activation grant is not eligible for packaging or publication until the
exact artifact has completed a separate post-grant verification on every
declared architecture. This stage exists because activation-smoke evidence is
created before the grant exists and therefore cannot test the grant parser,
the final authorization-context derivation, or schema-3 receipts that bind
that final context.

After the grant and final context exist, the offline root signs one distinct
post-grant verification token per declared architecture. Its unsigned fields
are:

1. `schema_version`, integer `1`
2. `token_type`, exactly `post_grant_verification`
3. `authority_key_id`
4. `descriptor_sha256`
5. `provisional_authorization_sha256`
6. `production_activation_grant_sha256`
7. `authorization_context_sha256`
8. `gate_plan_sha256`
9. `architecture`
10. `approved_capability`, exactly matching the grant
11. `gate_runner_unique`
12. `gate_session_id`
13. `setup_authorization`, exactly
    `first_exact_artifact_enrollment_only`
14. `cleanup_authorization`, exactly `attributed_stage_cleanup_only`
15. `loopback_origin`, null for `confirm_only` or `http://127.0.0.1:` followed
    by one canonical decimal port in `1..65535` for `issue_create`
16. `dispatch_deny_code`, null for `confirm_only` or exactly
    `POST_GRANT_PRODUCTION_MUTATION_DISPATCH_DENIED` for `issue_create`
17. `issued_at`
18. `expires_at`, no more than 30 minutes after issue

The signer recomputes all four authority digests from the exact descriptor,
signed provisional authorization, signed activation grant, and derived final
context before signing. The post-grant plan's descriptor, capability,
architecture set, and `authorization_context_sha256` must match the token and
authority pair; the plan begins with the matching setup case and carries
`stage_setup_policy=first_exact_artifact_enrollment_v1` plus
`stage_cleanup_policy=attributed_stage_cleanup_v1`. Tokens and sessions
are fresh and globally distinct from every
E1, E2, and activation-smoke token/session. The candidate accepts the token
only through the same runner-identity, audit-token, native-architecture,
challenge-response, expiry, and mode-0700 session checks as E1. It is never
installed, shipped, or accepted by an ordinary process outside that exact
authenticated session. Its setup and cleanup fields are accepted only through
their separately derived contexts in the first and final cases; neither can
substitute for the grant-bound final production context used by the intervening
workflow.

The runner stages the real detached descriptor, provisional authorization,
and activation grant beside the real signed app under the ordinary installation
layout. It first derives the setup-only context, proves the canonical empty
inventory, performs the one exact-artifact revision-1 enrollment, and retains
the resulting registry snapshot outside disposable state. The CLI and helper
then load that exact authority pair through the ordinary production
validator, independently derive and exchange the final
`authorization_context_sha256`, and use the ordinary production
approval-registry, Secure Enclave/Keychain, and schema-3 receipt codecs against
runner-provisioned state on the clean Gate host. A test root, fixture
executable, provisional context, smoke context, alternate sidecar loader,
synthetic receipt, or prevalidated authority object cannot satisfy a positive
post-grant observation. Every receipt minted in this stage carries the actual
final production context; the runner token restricts where it can be used but
does not replace or alter that context. The setup snapshot observation, its
case-final evaluation, and every later operation/final observation carry the
retained `registry_snapshot_sha256`.

The `confirm_only` plan runs the compiled ordinary `prepare -> confirm`
workflow, proves that the resulting schema-3 receipt names the final context,
and proves every apply operation is denied before preflight or network access.
The `issue_create` plan runs the compiled ordinary
`prepare -> confirm -> apply` workflow. Apply performs only the declared
read-only IPv4-loopback preflight, durably consumes the receipt, and then must
return `POST_GRANT_PRODUCTION_MUTATION_DISPATCH_DENIED` at the final dispatcher
before any mutating request-line, header, or body byte is opened or written.
An earlier validation, authority, journal, preflight, or capability failure
does not satisfy the positive dispatch-denial assertion. Update, comment, and
every other capability remain denied before preflight.

### Non-replayable journal and cleanup evidence

Post-grant verification uses a runner-created mode-0700 profile and journal
root and no production credential. It introduces one compiled, runner-only
terminal transition named `post_grant_verification_consumed`; that transition
is not exposed by the ordinary CLI, skill, environment, or caller-selected
configuration. For `confirm_only`, the compiled `consume` step atomically
changes the positive receipt from `confirmed` to that terminal state after all
apply-denial observations pass. For `issue_create`, ordinary apply first makes
the durable `confirmed -> in_flight` transition, and only after the exact
post-grant dispatch-denial result is captured does the runner atomically change
`in_flight` to the same terminal state. Neither path can return to `prepared`
or `confirmed`. The receipt ID, nonce, plan ID, and journal revision are burned
even if later evidence collection or cleanup fails.

The terminal transition produces one compact canonical journal evidence object
capped at 8,192 bytes. Its fields are, in order: `schema_version` integer `1`,
`evidence_type` exactly `post_grant_terminal_journal`, `descriptor_sha256`,
`provisional_authorization_sha256`, `production_activation_grant_sha256`,
`authorization_context_sha256`, `architecture`, `gate_session_id`, `plan_id`,
`registry_snapshot_sha256`, `receipt_id`, `receipt_sha256`, `nonce_sha256`, `prior_state`,
`terminal_state` exactly `post_grant_verification_consumed`,
`journal_revision`, `transition_reason`, and `transitioned_at`.
`prior_state` is exactly `confirmed` for `confirm_only` and `in_flight` for
`issue_create`; `transition_reason` is respectively
`confirm_only_verification_complete` or
`post_grant_dispatch_denied_before_mutation`. IDs and revisions use the
ordinary schema-3 journal grammar. The hashes cover the exact canonical signed
receipt and its 32-byte nonce. The journal CAS and a repeated ordinary
confirm/apply attempt must both prove the terminal record and return the stable
`RECEIPT_ALREADY_CONSUMED` reason without UI, preflight, or network access.

Cleanup runs only after the terminal record, its replay-denial observations,
and every authority-negative observation have been retained by digest. It is
the final case and final state-changing action for the post-grant session; no
step may restage a plan, receipt, socket, copied sidecar, or Keychain object
after its final probe. Its compact canonical evidence object is capped
at 8,192 bytes and contains, in order: `schema_version` integer `1`,
`evidence_type` exactly `post_grant_cleanup`, `descriptor_sha256`,
`production_activation_grant_sha256`, `architecture`, `gate_session_id`,
`setup_context_sha256`, `pre_enrollment_inventory_sha256`,
`registry_snapshot_sha256`, `terminal_journal_evidence_sha256`,
`cleanup_context_sha256`, `cleanup_intent_sha256`,
`final_cleanup_progress_sha256`, `helper_cleanup_evidence_sha256`,
`stage_cleanup_evidence_sha256`,
`pre_cleanup_inventory_sha256`, `removed_inventory_sha256`,
`keychain_cleanup_evidence_sha256`, `post_cleanup_probe_sha256`,
`final_empty_inventory_sha256`, `finished_at`, and `result` exactly `pass`. The
three filesystem inventory/probe digests name canonical
fixture objects enumerating every regular file by session-root-relative
component, mode, size, and content digest; symlinks, hard links, non-regular
entries, traversal, and files outside the already opened session root fail
cleanup. The removed inventory must exactly equal the pre-cleanup inventory,
and the post-cleanup probe must prove that no plan, receipt, journal, loopback
account, socket, or copied authority sidecar remains beneath that root. Cleanup
does not delete or alter the immutable evidence files retained outside the
disposable root. The final empty inventory additionally proves the exact
registry service, coordinator service, signing-key namespace, journal root,
and mutable runner-session state are empty and matches the setup contract's
initial inventory comparison rule.

The five stage-cleanup digests resolve to the immutable context, intent,
completed progress, helper evidence, and complete runner evidence defined by
the registry protocol. Their token, descriptor, snapshot, architecture,
capability, runner, and session values must equal this cleanup object. They are
the sole authority and reconciliation record for Keychain deletion; the
filesystem inventory fields neither widen nor reconstruct that authority.

The Keychain cleanup digest names a compact canonical object capped at 8,192
bytes with fields `schema_version` integer `1`, `evidence_type` exactly
`post_grant_keychain_cleanup`, `descriptor_sha256`, `architecture`,
`gate_session_id`, `registry_snapshot_sha256`, `registry_service`,
`registry_accounts`, `coordinator_service`, `coordinator_accounts`, `key_tags`,
`registry_lookup_statuses`, `coordinator_lookup_statuses`,
`key_lookup_statuses`, `checked_at`, and `result` exactly `pass`, in that order.
Services, accounts, and tags are the exact bounded values produced by the
approval-registry/coordinator protocols during this session;
`key_tags` are sorted bytewise and contain every created tag exactly once.
The account arrays contain every created account once in canonical byte order;
each corresponding status array has one entry in the same order with its
`account` then `status` fields, and status exactly numeric
`errSecItemNotFound` (`-25300`).
`key_lookup_statuses` has one entry per tag in the same order with fields
`key_tag` and `status` exactly `-25300`. Any successful lookup, authentication
cancel, transient/unknown status, unbounded enumeration, or extra matching
item fails cleanup and quarantines the candidate.
This object is a final absence projection of the completed
`stage_cleanup_keychain` evidence, not an independent deletion instruction.

Each architecture emits a compact canonical post-grant evidence index capped
at 65,536 bytes with these fields in exact order:

1. `schema_version`, integer `1`
2. `evidence_type`, exactly `post_grant_verification_pass`
3. `gate_id`, exactly `post_grant_verification`
4. `descriptor_sha256`
5. `post_grant_verification_token_sha256`
6. `gate_plan_sha256`
7. `allowed_capability`
8. `provisional_authorization_sha256`
9. `production_activation_grant_sha256`
10. `authorization_context_sha256`
11. `setup_context_sha256`
12. `pre_enrollment_inventory_sha256`
13. `registry_snapshot_sha256`
14. `gate_runner_unique`
15. `gate_session_id`
16. `macos_product_build_version`
17. `architecture`
18. `fixture_set_sha256`
19. `fixture_executable_manifest_sha256`, null
20. `evidence_scopes`, exactly the one-element array `exact_artifact`
21. `started_at`
22. `finished_at`
23. `result`, exactly `pass`
24. `terminal_journal_evidence_sha256`
25. `cleanup_context_sha256`
26. `cleanup_intent_sha256`
27. `final_cleanup_progress_sha256`
28. `helper_cleanup_evidence_sha256`
29. `stage_cleanup_evidence_sha256`
30. `cleanup_evidence_sha256`
31. `final_empty_inventory_sha256`
32. `observations`

The observations exactly equal the capability-specific post-grant plan and use
the Gate evidence observation/result codecs. They begin with exact-artifact
setup and its case-final evaluation; the setup snapshot observation and every
later observation bind the index's retained `registry_snapshot_sha256`. They
include ordinary authority loading, both-peer final-context equality, schema-3 receipt parsing and
signature validation, capability denials, terminal CAS, ordinary replay
denial, cleanup, runner/session negatives, and, for `issue_create`, the exact
read-only loopback transcript, unique dispatch code, and zero mutating bytes.
The index digest is SHA-256 of those exact bytes. Its setup, pre-inventory,
snapshot, terminal, cleanup, and final-inventory digests must resolve to the
objects above and agree with their observation result manifests.

The per-architecture indexes form one complete compact canonical evidence-set
manifest capped at 16,384 bytes. Its fields are, in order: `schema_version`
integer `1`, `evidence_set_type` exactly `post_grant_verification`, `gate_id`
exactly `post_grant_verification`, `descriptor_sha256`,
`provisional_authorization_sha256`, `production_activation_grant_sha256`,
`authorization_context_sha256`, `gate_plan_sha256`, `approved_capability`,
`fixture_set_sha256`, `evidence_scopes` exactly the one-element array
`exact_artifact`, `architectures`, `indexes`, `registry_snapshots`,
`install_evidence_manifest_sha256`, and `result` exactly `pass`.
`architectures` exactly equals the descriptor array. `indexes` has one entry
per architecture in that order, with fields `architecture`,
`evidence_index_sha256`, `post_grant_verification_token_sha256`,
`gate_session_id`, `setup_context_sha256`,
`pre_enrollment_inventory_sha256`, `registry_snapshot_sha256`,
`terminal_journal_evidence_sha256`, `cleanup_context_sha256`,
`cleanup_intent_sha256`, `final_cleanup_progress_sha256`,
`helper_cleanup_evidence_sha256`, `stage_cleanup_evidence_sha256`,
`cleanup_evidence_sha256`, and
`final_empty_inventory_sha256`, in that order. `registry_snapshots` contains
one entry per descriptor architecture, in that order, with fields
`architecture` and `registry_snapshot_sha256`, and exactly projects the index
entries. Every value must equal its token, plan, index, authority pair,
context, and retained file.

`install_evidence_manifest_sha256` is SHA-256 of the exact compact canonical
`install-files.json` bytes. That separate object is capped at 2,097,152 bytes
and has fields in exact order: `schema_version` integer `1`, `manifest_type`
exactly `post_grant_install_evidence`, `descriptor_sha256`,
`authorization_context_sha256`, `gate_plan_sha256`, and `files`. Its three
digests exactly equal the complete evidence-set manifest. `files` is the
complete inventory for the archive's
`authorization/post-grant-verification-evidence-set/files/` tree. It is sorted
by the raw ASCII bytes of `path` and contains one entry for every regular file
under that directory, with fields `path`, `size`, and `sha256` in that order.
Across all architectures it contains 1..1,024 entries and names at most 256
MiB of aggregate file bytes; these are independent whole-manifest caps, not
per-index allowances. The counts and aggregate size are checked before any
proportional allocation or file read.
`path` is 1..1,024 printable ASCII bytes without JSON escapes and is a relative
path of slash-separated components. Each component is 1..128 bytes and uses
only ASCII letters, digits, dot, underscore, or hyphen; dot, dot-dot, empty,
backslash, leading-slash, trailing-slash, duplicate, and ASCII-case-fold-
colliding paths are invalid. `size` is a
non-negative JSON integer no greater than the file-type cap, and `sha256` is
the digest of the exact file bytes. The list includes every per-architecture
evidence index and every referenced fixture, transcript, assertion, result
manifest, setup context, pre-enrollment inventory, registry snapshot, terminal
record, cleanup object, final empty inventory, and inventory/probe object. Neither
manifest is self-listed: the fixed `index.json` path is authenticated by the
publication envelope's `post_grant_verification_evidence_set_sha256`, and the
fixed `install-files.json` path is authenticated by the evidence-set
manifest's `install_evidence_manifest_sha256`. A missing, additional,
reordered, mismatched, linked, escaping, or secret-bearing file fails the
entire set. `post_grant_verification_evidence_set_sha256` is SHA-256 of the
exact compact evidence-set manifest bytes. The envelope therefore
authenticates the compact evidence-set manifest, which authenticates the
install-evidence manifest, which authenticates every evidence file's installed
path, size, digest, ordering, and multiplicity without exceeding the compact
object's 16,384-byte cap.

Post-grant verification token bytes are deliberately absent from the install-
evidence manifest and from the delivery archive. Before publication,
the Gate and release verifiers validate each root signature, token/session
binding, and expiry and then record its exact digest in both the
per-architecture index and evidence-set manifest. At installation time that
matching digest is an envelope-authenticated historical cross-reference, not
a request to reconstruct or revalidate an expired session token. The installer
must not fetch token bytes. This preserves the rule that a session-bound token
is never installed, shipped, or accepted outside its authenticated Gate
session while still making token substitution in retained evidence detectable.

Until that complete set passes, the app-only archive, canonical descriptor,
provisional authorization, and activation grant remain in trusted
prepublication custody on the clean Gate/release hosts. They must not be put in
a delivery archive, draft release, Cask, ordinary installation root, shared
artifact store, or developer workstation. This custody is a release-process
trust assumption, not a cryptographic revocation mechanism. Any post-grant
failure, timeout, missing architecture, cleanup failure, or evidence mismatch
quarantines the descriptor, provisional authorization, grant, tokens, and all
derived artifacts; no publication envelope is signed, no quarantined object is
later reused, and a retry starts from a newly built, signed, notarized, stapled,
archived, and described artifact at E1. The failed evidence is retained only in
the access-controlled release incident record.

## Publication envelope

After the complete post-grant verification set passes, the offline root signs
the publication envelope. It has these unsigned fields:

1. `schema_version`, integer `1`
2. `envelope_type`, exactly `youtrack_agent_publication`
3. `authority_key_id`
4. `product_version`
5. `release_build`
6. `git_commit_oid`, `sha1:` followed by the exact 40-character lowercase hexadecimal commit object ID used by the first release repository
7. `descriptor_sha256`
8. `provisional_authorization_sha256`
9. `authorization_context_sha256`
10. `production_activation_grant_sha256`
11. `activation_smoke_evidence_set_sha256`
12. `post_grant_verification_gate_plan_sha256`
13. `post_grant_verification_evidence_set_sha256`
14. `app_payload_archive_sha256`
15. `published_at`, UTC RFC 3339 whole seconds

The two post-grant fields must equal the plan and complete evidence set whose
descriptor, authority pair, final context, capability, architecture order, and
fixture set equal this envelope and its other authority fields. The release
pipeline verifies all contained hashes and signatures, then creates the outer
delivery archive exactly once from the app, descriptor, provisional
authorization, activation grant, signed envelope, exact post-grant plan, and
complete closed evidence-set tree shown above. It records the archive's exact
byte length and SHA-256 in the release record and as literal `url` and `sha256`
values in the reviewed Cask. It uploads that archive plus the descriptor,
authority objects, envelope, Gate/smoke/post-grant plans, Gate 1A fixture-
executable manifest, and complete evidence sets as distinct audit assets to a
draft GitHub release, verifies every remote digest, and only then publishes an
immutable release. The Cask URL names that immutable version/tag and exact
archive filename; it may not use a latest, redirect-selected, mutable, or
replaceable asset. A moved tag, remote digest mismatch, or Cask/archive
checksum mismatch is not eligible for installation.

The Cask uses the literal outer-delivery-archive SHA-256, never `:no_check`,
installs the complete signed app and detached `authorization/` tree without
re-signing, rebuilding, fetching, or rewriting any byte, and links the
contained CLI. Installation validation reads the root-signed publication
envelope, exact post-grant plan, evidence-set index, install-evidence manifest,
and every file listed by that manifest only from their fixed paths under that
same versioned installation root. It must verify the envelope signature,
matching provisional
authorization and
activation grant, authorization context, descriptor, post-grant plan and
complete evidence-set binding, Developer ID signatures, notarization, and
exact app code identities before guarded mutations are enabled. Missing or
extra evidence, a path/link violation, or any digest mismatch disables guarded
mutations. It never reconstructs an archive hash from the installed tree or
retrieves verification material after extraction. Homebrew's checksum is a
download-integrity check, not a substitute for root authorization or runtime
peer verification.

## Cross-language conformance evidence

Implementation is blocked until one language-neutral fixture set is consumed
by the Go release/publication verifier and the Swift native verifier. Positive
vectors contain exact unsigned bytes, domain-prefixed signing bytes, signed
bytes, SHA-256 values, Ed25519 public key/signature, and parsed values for:

- one universal artifact descriptor and one single-architecture descriptor;
- exact Gate 1A, Gate 1B, both capability-specific smoke plans, and both
  capability-specific post-grant plans, including every typed argv source,
  scope mapping, canonical operation execution context, empty operation
  assertion array, case-final evaluation contract, and ordered final aggregate;
- the complete Gate 1A fixture-executable manifest with both disjoint fixture
  roles, both negative-peer components, and every architecture-specific signed
  identity/code slice;
- Gate 1A and Gate 1B per-architecture E1/E2 tokens, evidence indexes, and
  complete evidence-set manifests;
- every exact Security.framework key/registry/coordinator dictionary
  projection, coordinator active/permit/closed record, apply-first and
  registry-first linearization, and pre/post-permit restart outcome;
- code/entitlement, profile CMS, certificate-chain/policy, notary, and
  non-circular staple evidence wrappers, including exact tool find/version
  captures, retained output digests, and CMS-certificate multiset framing with
  duplicate DER values and digest-sort ties;
- `confirm_only` and `issue_create` provisional authorizations, provisional
  contexts, final grant-bound production contexts, smoke receipt contexts,
  both stage-only setup and cleanup contexts, canonical empty pre-enrollment/
  final inventories, post-enrollment registry snapshots, cleanup intents and
  progress prefixes, acknowledged `delete_attempt_started` markers,
  same-directory exclusive-`0600` canonical marker/pending-progress
  publication with file/directory fsync and no-follow reopen/hash evidence,
  the dedicated operation-result digest domain and every exhaustive nullable
  field-shape row,
  helper/runner stage-cleanup evidence, and the three post-invocation/
  pre-result-persistence crash outcomes: success and direct-not-found
  reconciled by exact absence, plus ambiguous exact presence quarantined
  without another delete;
- both per-architecture activation-smoke token/index variants, complete smoke
  evidence sets and cleanup objects, production activation grants, both per-architecture
  post-grant token/index variants, terminal-journal and cleanup objects, and
  complete post-grant evidence sets plus their separately digest-bound install-
  evidence manifests with multi-component ASCII paths; and
- the publication envelope, app-payload archive, and outer delivery archive.

Both implementations must parse, validate, re-encode, hash, and verify every
positive vector identically. The fixture set evaluates every row of the
capability matrix against confirm and each supported apply operation, including
Gate target/session/architecture restrictions. It runs every hard-coded plan
case and requires exact ordered observation equality. The closed negative set
independently covers:

- every object and field size boundary; missing, duplicate, unknown, reordered,
  escaped, whitespace-modified, noncanonical integer/null/base64url, and
  trailing JSON;
- wrong root key ID, public key, signature, domain, object type, descriptor, or
  payload digest, including cross-domain signature substitution;
- absent, duplicate, reordered, unsupported, or mismatched architecture,
  code-slice, digest-algorithm, `kSecCodeInfoUnique`, cdhash, Team ID,
  identifier, build, complete semantic entitlement, peer-requirement source,
  actual designated requirement, certificate chain/policy,
  `SecStaticCodeCheckValidity` result, profile raw/CMS sequence, notarization,
  or staple evidence;
- descriptor/profile expiry mismatch and the exact 88-vector Cartesian product
  of all 22 named profile-expiry boundaries with just-before, equality, after,
  and expiry-between-checks variants—including peer authentication—and exact
  no-side-effect assertions;
- raw-entitlement-present/dictionary-absent, dictionary-present/raw-absent,
  raw/dictionary semantic disagreement, unknown entitlement, and both values
  absent for a helper that requires its fixed entitlements;
- CMS certificate count/aggregate overflow, empty DER, changed count/length
  framing, digest-only or JSON preimage, array-order dependence, duplicate DER
  removal, wrong digest/DER sort order, and trailing certificate bytes;
- sidecar traversal, symlink, hard link, wrong owner/mode/type, oversize,
  truncation, inode/metadata change, mixed descriptor, and reopen races;
- wrong Gate runner, connection audit token, session, nonce, expiry, Gate ID,
  architecture, plan, target, capability, or network policy, plus
  E1/E2/smoke/post-grant replay, session reuse, evidence predecessor mismatch,
  missing architecture, and incomplete evidence set;
- unknown/reordered Gate case, step, typed argv source, fixture, assertion, or
  transcript; shell/cwd/env/stdin inheritance; prepare/confirm/apply reorder;
  dynamic-value injection; observation omission/addition/reorder; and command-
  context digest mismatch;
- missing, early, duplicate, or reordered case-final evaluation; nonempty
  `assertion_ids` or an assertion result on any operation observation; empty or
  reordered final assertion IDs; final evaluation before all operation and
  transcript-result digests exist; changed ordered aggregate; or a case/evidence
  pass without its final evaluation;
- changed/missing evidence scope; production-role execution in a disjoint
  case; fixture-role execution in an exact-artifact case; fixture identifier,
  manifest, architecture, unique identifier, executable hash, cdhash, or code-
  validation mismatch; cross-namespace IPC; and fixture evidence mislabeled as
  production execution;
- ordinary lifecycle mislabeled as fixture evidence; any destructive case
  outside the exact five-case disjoint mapping; alternate fixture namespace;
  negative-peer missing/changed component, production identifier, older build,
  architecture, or signed digest; negative-peer use outside the mixed-build
  rejection steps; or any negative-peer helper, Keychain, registry, positive-
  assertion, or protocol authority;
- an empty or modified compiled command contract; assertion/transcript result
  omission, duplication, reorder, wrong expected/actual digest, false success,
  aggregate-only result, and result-manifest/observation substitution;
- alternate or caller-created Unix IPC, wrong peer path/audit token,
  non-preopened `AF_UNIX`, `AF_INET`/`AF_INET6` under a deny policy, IPv6 or
  hostname loopback during smoke, datagram/raw socket, and undeclared socket
  family/type;
- Gate-token use on the production path, missing Gate 1A prerequisite for Gate
  1B, null/non-null Gate 1B evidence errors, capability widening, and
  `issue.update` / `comment.add` substitution;
- missing, reordered, or additional Gate 1B coordinator cases/steps,
  schedule fixture, barrier release/arrival, or concurrency-trace event;
  sleep/timing-based orchestration; apply/registry or enrollment overlap; two
  launchd helper instances/listeners; direct helper-server spawn; authority
  Keychain access outside the single serialized executor; acquisition before
  its guard or between active equality-read and delete; competitor Keychain
  work before guard release; active ABA replacement; two active leases; permit before `in_flight`; send without or after a permit;
  second permit/send; registry-first stale receipt; stale session/audit-token/
  journal fence; durable-outcome downgrade; repeated ambiguous close add or
  active delete; active deletion before durable close; restart resume; and any
  post-permit automatic retry;
- authority status/recover without explicit profile or required invocation
  `meta`; any plan/lease/force selector, positional input, `--yes`, `--dry-run`,
  `--fields`, raw output, stdin/environment override, or changed accepted-flag
  semantics; authority corruption mapped anywhere but exit 1; and any future
  authority exit outside 10 through 13;
- migration of any valid v1 state other than `prepared`, especially
  `failed_before_mutation`; mutation/deletion of quarantined source bytes;
  missing quarantine marker attempt; or treating current fail-closed code as
  proof that an unrepresentable v1 authority state is safe;
- provisional-only or grant-only use, mismatched provisional/grant/context,
  two valid grants for one provisional context, peer disagreement on grant or
  final context, smoke-plan or post-grant-plan substitution, smoke receipt
  copied into a production context, post-grant receipt using a provisional or
  synthetic context, wrong post-grant token/grant/context/runner/architecture,
  missing terminal CAS or cleanup evidence, receipt replay after terminal
  consumption, and pre-dispatch/late-dispatch false positives;
- missing/non-first setup case; setup token/context absent, mismatched, or used
  for any action except the one initial exact-artifact enrollment; nonempty
  pre-enrollment registry service, coordinator service, signing-key namespace,
  journal root, or mutable runner-session inventory; enrollment other than
  revision 1/generation 1; setup snapshot with wrong revision, generation,
  SPKI, fingerprint, descriptor, architecture, runner, or session; any later
  observation/index/evidence-set entry with a missing or different snapshot;
  retained setup evidence placed inside disposable state; or a second setup,
  rotation, recovery, revocation, receipt signature, permit, or network action
  under setup authority;
- missing, expired, unsigned, cross-stage, cross-architecture, cross-capability,
  cross-runner, or cross-session cleanup authority; cleanup-context/token/
  descriptor/setup-snapshot disagreement; a setup or cleanup context used to
  sign a receipt or registry record, acquire a coordinator active record,
  create a permit, send, or cross sessions; missing or mutable retained cleanup
  intent/progress; reconstruction from current mutable state; incomplete,
  reordered, duplicated, or extra expected records, key tags, delete
  dictionaries, or delete operations; active coordinator singleton during
  cleanup; a registry tuple other than the retained active generation;
  deletion without the exact UI-fail pre-read and byte comparison; unknown,
  unattributed, malformed, or byte-mismatched state; deletion outside the
  completed prefix; a physical delete without its durable append-only
  stage/token/context/operation-bound marker and acknowledgement; any marker
  whose attempt is not exactly 1; duplicate/rolled-back marker state;
  missing/partial/non-cross-bound marker and `delete_pending` progress pair;
  temp-mode/no-follow/canonical-write/file-fsync/no-replace-publication/
  directory-fsync/reopen/hash failure; ACK before both entries and its retained
  transcript ledger entry are durable; rollback to a prior progress prefix;
  delete after any pre-ACK publication crash/failure;
  operation result under the wrong digest domain or outside the exhaustive
  pre-read/delete/post-read/pending-marker field-shape table;
  delete after an unresolved marker; unresolved-marker absence not terminally
  reconciled, exact presence not quarantined for manual repair, or unknown/
  mismatch followed by deletion; restart with different intent/marker/progress
  bytes; or stage deletion attempted by an ordinary production or non-stage
  process;
- missing/changed `xcrun --find` output, executable hash, version argv, version
  exit/output digest, active-developer-directory resolution, or wrapper tool-
  capture digest; undocumented `notarytool` JSON shape substitution; and
  `spctl` text accepted despite a nonzero exit;
- app-payload, provisional-authorization, activation-smoke evidence set,
  activation-grant, post-grant plan/evidence set, delivery-archive,
  publication-envelope, remote-asset, and Homebrew checksum mismatch; and
- missing, additional, duplicate, reordered, ASCII-case-fold-colliding, or
  digest/size/path-mismatched install-evidence entries; wrong install-manifest
  context or digest; non-ASCII, escaped, empty-component, dot-segment,
  backslash, or overlong paths; unlisted files; a shipped or post-install-
  fetched post-grant token; and treating a retained token digest as an install-
  time authority object; and
- cleanup before authority-negative observations, any object restaged after
  the final cleanup probe, a final inventory that does not prove all five
  setup inventory domains empty, a final probe that omits such restaged state,
  failure without bounded cleanup, cleanup token/context expiry or
  unverifiability during partial cleanup, a nonempty or mismatched attributed
  remainder, cleanup failure without whole disposable user/VM quarantine and
  destruction, or reuse of any invalidated failure output; and
- app-only archive creation or replacement after descriptor canonicalization
  or E1 issuance, quarantined grant reuse, publication before every native
  architecture passes post-grant verification, and a publication envelope
  missing either post-grant digest.

Every negative vector has one stable fail-closed reason class. Gate plans pin
the complete fixture-set digest; adding, removing, or changing a vector
invalidates prior E1/E2 evidence.

## Gate and release invariants

- Gate, smoke, and post-grant plans are closed, canonical, and
  content-addressed. Any case, workflow step, runner, typed argv source,
  fixture, assertion, transcript, entitlement expectation, or command change
  produces a new plan digest and invalidates its tokens and evidence sets.
- Gate 1A exact-artifact cases use the normal confirmation and registry
  lifecycle commands; its five destructive corruption/malformed-ledger/
  ambiguous-add/orphan-cleanup/active-key-loss cases use only the separately
  identified fixture pair and cannot stand in for product execution. Gate 1B
  uses the normal issue creation apply command against only its disposable target. The later
  activation smoke uses that same ordered prepare/confirm/apply workflow
  through exact loopback reads and the unique pre-write dispatch denial. After
  the grant is signed, post-grant verification repeats the ordinary workflow
  with the real sidecar pair, final production context, and schema-3 receipts,
  then irrevocably terminalizes those disposable receipts. Test-only command
  surfaces cannot substitute for either path.
- Every activation-smoke and post-grant capability plan begins with exactly one
  setup-only exact-artifact enrollment from a canonical empty five-domain
  inventory. Its retained revision-1/generation-1 registry snapshot binds
  every later observation and both index layers. Final cleanup proves the same
  five domains empty; any failure invalidates all session output and either
  proves bounded cleanup or destroys the quarantined disposable user/VM.
- Their final deletion is available only to the distinct root-token-bound
  `stage_cleanup` IPC authority. Before its first delete, the trusted runner
  retains the complete attributed cleanup intent and empty pre-inventory,
  setup transcript/snapshot, helper-created key list, expected-record bytes,
  exact dictionaries, and delete order outside disposable state. Recovery
  reuses only those bytes. Every physical delete is preceded by one durable,
  acknowledged, append-only `delete_attempt_started` marker with fixed attempt
  1. The marker and cross-bound `delete_pending` progress are each published
  from same-directory exclusive `0600` no-follow temps through canonical
  file-fsync, collision-safe no-replace publication, directory-fsync, and
  no-follow exact reopen before the retained ACK may be sent. An intact
  unresolved pair can reconcile exact absence; exact presence or unknown state
  quarantines. A detectably missing/partial pair also quarantines. Neither path
  rolls back or permits another delete. Every step otherwise
  remains exact-read/byte-compare/delete under the serialized executor. Unknown
  state is never deleted, and an expired or unverifiable partial cleanup can
  only invalidate and destroy/quarantine the disposable environment.
- Assertion suffixes are case-final. Operation observations carry empty
  assertion IDs; only a separate final runner evaluation may aggregate and
  pass them after all ordered operation/transcript results exist. Without that
  observation the case and containing evidence set cannot pass.
- E1, E2, provisional authorization, provisional context, smoke, activation
  grant, final production context, post-grant verification, and publication
  all bind one descriptor digest and complete per-architecture evidence sets with their exact
  artifact/fixture scope partition. The fixture manifest is Gate evidence only
  and is never promoted into production runtime authority. The final context also
  binds the exact grant bytes, so different valid grants cannot share peer or
  receipt authority. A same-build rebuild has different Security.framework
  unique identifiers or hashes and cannot inherit evidence.
- The helper and CLI must agree on the descriptor digest before any authority
  protocol bytes. The approval registry records that same digest as
  `artifact_descriptor_sha256`; any mismatch or artifact change invalidates the
  ceremony or receipt.
- One launchd-managed helper server and its single serialized authority
  executor mediate every coordinator operation. The executor guard spans each
  active acquisition and the complete exact-read/delete cleanup interval;
  Keychain `active` remains the durable cross-client/restart lock. A competing
  acquisition cannot replace active between equality read and delete, and a
  helper restart cannot expose ordinary work before guarded recovery
  classification.
- Gate evidence, a provisional authorization, and smoke evidence cannot
  authorize ordinary production. Only a matching, separately domain-separated
  activation grant plus its provisional authorization can do so.
- The app-only payload archive is produced and retained once from the final
  stapled app before descriptor canonicalization and before E1 issuance. No
  Gate, smoke, grant, post-grant, delivery, or publication step may recreate or
  replace it while preserving the descriptor digest.
- A valid activation grant is necessary but not sufficient for publication.
  Every native architecture must pass the grant-bound post-grant plan, reach a
  terminal non-replayable journal state, and complete bounded cleanup; the
  root-signed publication envelope must bind that exact plan and complete set.
  Failure quarantines the entire candidate and cannot be repaired by rerunning
  only the missing case or by reusing the grant.
- The embedded helper profile expiry is an absolute write cutoff bound by the
  descriptor. Gate or publication evidence created earlier never waives a
  current expiry check, and apply checks it again under the helper coordinator
  immediately before the sole permit and immediately before the sole send.
- No production artifact is activated by this document. The root key, signed
  binaries, complete semantic signing evidence, notarization evidence,
  per-architecture clean-host E1/E2 passes, provisional authorization,
  per-architecture smoke pass, activation grant, per-architecture post-grant
  verification and cleanup, publication envelope, and immutable release must
  all exist and validate.

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
- Apple exposes the complete signed entitlement dictionary through
  [`kSecCodeInfoEntitlementsDict`](https://developer.apple.com/documentation/security/kseccodeinfoentitlementsdict)
  and documents
  [`SecCodeCopySigningInformation`](https://developer.apple.com/documentation/security/seccodecopysigninginformation%28_%3A_%3A_%3A%29),
  [`SecCodeCopyDesignatedRequirement`](https://developer.apple.com/documentation/security/seccodecopydesignatedrequirement%28_%3A_%3A_%3A%29),
  and
  [`SecRequirementCopyData`](https://developer.apple.com/documentation/security/secrequirementcopydata%28_%3A_%3A_%3A%29).
  The static-code validity authority is
  [`SecStaticCodeCheckValidityWithErrors`](https://developer.apple.com/documentation/security/secstaticcodecheckvaliditywitherrors(_:_:_:_:)).
- Apple's [Cryptographic Message Syntax Services](https://developer.apple.com/documentation/security/cryptographic-message-syntax-services)
  enumerate the public decoder sequence beginning with
  [`CMSDecoderCreate`](https://developer.apple.com/documentation/security/1392600-cmsdecodercreate)
  and covering update, finalize, content, signer, certificate, and signer-status
  calls used for the profile. Apple separately documents
  [`SecPolicyCreateWithProperties`](https://developer.apple.com/documentation/security/secpolicycreatewithproperties%28_%3A_%3A%29),
  [`SecTrustCopyCertificateChain`](https://developer.apple.com/documentation/security/sectrustcopycertificatechain%28_%3A%29),
  [`SecCertificateCopyData`](https://developer.apple.com/documentation/security/seccertificatecopydata%28_%3A%29),
  and
  [`SecCertificateCopyValues`](https://developer.apple.com/documentation/security/seccertificatecopyvalues%28_%3A_%3A_%3A%29).
  These APIs provide the chain and exact DER/property inputs; the checked-in
  first-release policy remains this protocol's stricter local allowlist.
  Apple's
  [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
  explains the App ID and entitlement allowlist carried by a profile.
- Apple's code-signing guide explains that nested code is signed first and its
  signature is sealed by the outer bundle in
  [Code Signing Tasks](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html).
- Apple's
  [notarization workflow](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
  identifies `notarytool` and `stapler` as the command-line upload and ticket
  tools, while
  [Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
  documents manual submission and stapling. Apple's Xcode help gives the exact
  [`xcrun stapler validate` ticket check](https://help.apple.com/xcode/mac/current/en.lproj/dev88332a81e.html).
  Apple also shows `stapler staple` and recommends clean-machine distribution testing in
  [Packaging Mac software for distribution](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution).
- Apple documents `spctl --assess --type exec` as a system-policy assessment in
  [Resolving common notarization issues](https://developer.apple.com/documentation/security/resolving-common-notarization-issues)
  and documents exit-status assessment behavior in
  [Code Signing Tasks](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW25).
  Neither source is treated as a stable schema for verbose `spctl` text, so the
  protocol retains that output without parsing it.
- Homebrew requires a downloaded Cask artifact SHA-256 and documents the `app`
  and `binary` artifacts in the
  [Cask Cookbook](https://docs.brew.sh/Cask-Cookbook).
- GitHub documents that
  [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
  lock release tags and assets and generate a cryptographically verifiable
  release attestation over the tag, commit, and assets.
