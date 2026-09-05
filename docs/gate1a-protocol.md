# Gate 1A approval protocol (pre-Gate v2)

Status: frozen cross-language data contract for the feasibility spike. Gate 1A
itself is **not passed**. `approval.Unsupported` remains the only production
adapter, and this document does not enable confirmation, apply, release, or
Homebrew installation.

The accepted trust-root ADR found that v2 lacks the approval-registry revision
needed to invalidate receipts after rotation, revocation, or recovery. V2
remains evidence for the completed feasibility spike but is not eligible for a
signed Gate candidate. The next implementation must apply the exact v3 delta
below before any native adapter is wired.

## Required schema v3 delta

Schema v3 retains every v2 limit and encoding rule and makes only these signed
contract changes:

- `schema_version` is exactly `3`;
- `registry_revision` is inserted immediately after `challenge_sha256` in both
  unsigned and signed canonical JSON;
- `registry_revision` is a JSON integer in `1..256`, matching the bounded
  append-only helper ledger, with no alternate string or floating encoding;
- `authorization_context_sha256` is inserted immediately after
  `registry_revision` in both unsigned and signed canonical JSON. It is the
  lowercase SHA-256 of the exact canonical authorization-context object
  defined by the artifact-authorization protocol: canonical
  `gate_receipt_context_v1` during an authenticated Gate 1A/Gate 1B E1/E2
  session, smoke receipt context during activation smoke, or grant-bound final
  context during production/post-grant verification;
- `key_generation` is exactly `YTAG-` followed by the 20-digit decimal ledger
  revision that introduced the key (`00000000000000000001` through
  `00000000000000000256`), replacing the broader pre-Gate v2 label grammar;
- the signature, receipt digest, IPC success response, Go/Swift parsers, and
  golden vectors bind that added field;
- candidate decoders reject schema v2 rather than inferring a revision or
  authorization context.

All ordinal field references below describe the implemented v2 spike. The v3
implementation inserts `registry_revision` at position 5 and
`authorization_context_sha256` at position 6, shifting subsequent fields by
two.

The native trust boundary, canonical URL/plan-ID grammar, and exact future IPC
frame are specified in [Gate 1A native approval boundary](gate1a-native-boundary.md).
The registry generation and transition authority are specified by the
[Gate 1A registry and ceremony protocol](gate1a-registry-protocol.md), and
`registry_revision` and `authorization_context_sha256` are accepted only with
the descriptor and exact root-signed Gate token/context, provisional/smoke
pair, or provisional/activation pair authorized by
[Gate artifact authorization](gate1a-artifact-authorization.md). The Gate
branch exists before provisional authorization and is accepted only through
the matching authenticated Gate runner session; production, smoke, and
post-grant modes reject it.
Both authenticated peers agree on that context digest before the helper may
display or sign. Confirmation and the `confirmed -> in_flight` transition
require the same currently active context. Once a request is `in_flight`,
read-only reconciliation verifies the persisted historical context and receipt
but does not require that context to remain active. Before `in_flight`, the
journal atomically retains one closed stage-tagged authority set. An E1/E2
`gate` set contains the exact descriptor, exact root-signed Gate token,
canonical `gate_receipt_context_v1`, complete bounded genesis-to-current
registry chain, receipt, and digests; it contains no provisional authorization,
smoke token, activation grant, or production authority. An `activation_smoke`
set contains the exact descriptor, signed provisional
authorization, signed smoke token, provisional context, smoke receipt context,
receipt, and digests; it contains no activation grant and a pre-socket hard
denial is terminalized as `activation_smoke_consumed`, never reconciled. A
`production` or `post_grant_verification` set instead contains the exact
descriptor, signed provisional authorization, signed activation grant, final
grant-bound context, receipt, and digests. Historical verification rebuilds
the matching pinned-root signature/hash chain and replays the complete retained
registry chain to derive the verification key; a receipt digest, lone terminal
record, or caller-selected SPKI is not sufficient, and fields from different
stage types cannot be mixed. Live Gate confirmation/acquisition/permit/send
requires an unexpired E1/E2 token and the same authenticated runner session.
After `in_flight`, later token expiry does not invalidate historical evidence,
but Gate 1B may use it only for bounded read-only reconciliation in that still-
authenticated session; it cannot authorize a new permit or send.

Schema v3 apply receipts are consumed only through the helper-owned apply-authority
coordinator defined by the registry protocol. The receipt's revision, active
generation, applicable authorization context, exact request digest, plan ID,
journal revision, and
connected CLI audit token are copied into the active/permit chain. The durable
`confirmed -> in_flight` CAS precedes the sole permit; the permit precedes the
sole send; the helper excludes every registry commit until a durable closed
record exists. Crash before permit is `failed_before_mutation`. Any uncertainty
at or after permit is ambiguous, non-replayable, and read-only reconcile only.
Neither a receipt signature nor an `in_flight` state alone authorizes network
I/O. The helper also requires trusted current time strictly before the
descriptor's `helper_profile_expires_at` at confirmation, coordinator
acquisition, permit issuance, and immediately before send.
The registry protocol's future command/exit contract preserves the JSON v1
envelope but deliberately adds exits 10..13 for wait, trusted recovery,
artifact replacement, and reconfirmation; corruption/operator escalation uses
existing exit 1. The future
authority surface never emits exit 9; remote-uncertain reconciliation may
retain it. The four additive exits do not exist in the current disabled
production slice and never authorize retry.

## Authority and limits

Go remains the authority for mutation-plan validation and canonical receipt
semantics. A native implementation must independently enforce this exact
schema before displaying or signing anything. Every numeric length is checked
before allocating, copying, decoding, or rendering the corresponding input.

| Value | Maximum |
| --- | ---: |
| Immutable approval display | 524,288 bytes (512 KiB) |
| Canonical signed receipt JSON | 4,096 bytes |
| Canonical unsigned signing JSON | 3,072 bytes |
| `key_generation` UTF-8/ASCII bytes | 64 bytes |
| DER ECDSA P-256 signature | 72 bytes |
| Unpadded base64url signature text | 96 ASCII bytes |

The display is non-empty and contains the exact bytes returned by
`intent.ApprovalDisplayBytes`. The renderer must represent every byte
reversibly. It must not interpret Markdown, HTML, URLs, terminal escapes, or
other embedded content as active UI.

`intent.MaxCanonicalPlanBytes` owns and enforces the 512 KiB ceiling for every
produced and validated plan; approval code references that invariant rather
than maintaining a second limit. The budget covers the 64 KiB request domain
after the worst-case sixfold `encoding/json` HTML escaping plus the separately
bounded profile, URL, account, policy, and expected-state metadata. Tests keep
escape-heavy maximum plans for every supported mutation kind below the bound.

The frozen escaped renderer emits printable ASCII bytes `0x20...0x7e` unchanged
except that a backslash is emitted as `\\`. Every other byte is emitted as
uppercase `\xHH`. Its decoder accepts only this representation and recovers the
exact original byte sequence. The helper shows both the inert payload and this
escaped representation together with the payload digest.

This slice deliberately does not define an IPC transport, process lifecycle,
or helper discovery mechanism. Those security-sensitive contracts require a
separate reviewed decision; no implementation may infer one from these data
fixtures.

Likewise, neither the release-stage setup context nor its distinct cleanup
context is a receipt-signing context. The later `stage_cleanup` IPC authority
is defined only by the registry and artifact-authorization protocols and is
accepted solely with its exact root-signed smoke/post-grant token, retained
setup snapshot, and immutable attributed cleanup intent. It cannot sign this
receipt (or schema v3), acquire a permit, send, or cross sessions; no field in
this receipt grants deletion authority.

## Identifiers and time

`receipt_id` and `nonce` respectively use the literal prefixes `YTAR-` and
`YTAN-`, followed by the uppercase RFC 4648 Base32 encoding of exactly 16
bytes, without padding. The encoded payload is exactly 26 characters. A parser
must decode and re-encode it and require byte-for-byte equality, which also
rejects a non-canonical final symbol.

`issued_at` and `expires_at` are exactly UTC RFC 3339 at whole-second
precision: `YYYY-MM-DDTHH:MM:SSZ`. Offsets and fractional seconds are rejected.
Expiry is strictly after issue time, and the interval is no longer than five
minutes.

`key_generation` matches
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. Plan, account, project, project-key, and
digest strings retain the canonical constraints of the mutation plan and
project policy. Every SHA-256 value is 64 lowercase hexadecimal characters.

## JSON encodings

The unsigned bytes signed by the helper are compact UTF-8 JSON with these
fields in this exact order:

1. `schema_version`
2. `receipt_id`
3. `nonce`
4. `challenge_sha256`
5. `plan_id`
6. `plan_sha256`
7. `profile_identity_sha256`
8. `account_id`
9. `project_id`
10. `project_key`
11. `schema_sha256`
12. `request_sha256`
13. `expected_sha256`
14. `issued_at`
15. `expires_at`
16. `key_generation`
17. `key_fingerprint_sha256`

`approval.SigningBytes` is the sole Go encoder for that representation. The
`challenge_sha256` is lowercase SHA-256 over the exact 32-byte request
challenge, so an outer-frame challenge splice invalidates the signed receipt.
The signed receipt returned by `approval.ReceiptBytes` appends `signature` as
field 18. `approval.ReceiptDigestSHA256` is lowercase SHA-256 hex over those
complete signed receipt bytes, including the signature text.

`approval.ParseReceiptBytes` accepts only that canonical signed encoding. It
rejects a non-object top level, absent, duplicate, or unknown fields, alternate
field order/escaping/whitespace, malformed values, and all trailing data.

## Signature and public key

Signatures use ECDSA with NIST P-256 and SHA-256. The wire signature is one
strict ASN.1 DER `SEQUENCE` of two minimally encoded positive `INTEGER` values
`r` and `s`, with `1 <= r < P-256.N` and
`1 <= s <= floor(P-256.N/2)`. The low-S rule gives each mathematical ECDSA
signature one receipt encoding. A future helper must normalize signer output
with `s = min(s, N-s)` before base64url encoding and calculating the full
receipt digest. There are no trailing bytes. Receipt JSON carries those DER
bytes as RFC 4648 base64url without `=` padding. Parsers decode and re-encode
both DER and base64url and require exact equality.

The public-key interchange form is exactly the 65-byte uncompressed ANSI X9.63
point `0x04 || X || Y`, and the point must lie on P-256. Its DER SubjectPublicKeyInfo
form is exactly the following 26-byte prefix followed by that X9.63 point:

```text
3059301306072a8648ce3d020106082a8648ce3d030107034200
```

The resulting SPKI is exactly 91 bytes. `key_fingerprint_sha256` is lowercase
SHA-256 hex over those exact 91 DER bytes.

## Fixtures

Language-neutral vectors live under `testdata/gate1a/`. Text fixture files end
with one LF for source-control portability; the JSON values referenced by the
protocol are the file contents without that final fixture LF. Hex files encode
the named binary value in lowercase without separators, again followed by one
fixture LF.

The display vector pairs `display.hex` with `display.escaped.txt` and its
SHA-256 digest. The signature vector intentionally uses `r=1, s=2` to pin DER
and base64url codecs; it is not a signature over `signing.json`.
