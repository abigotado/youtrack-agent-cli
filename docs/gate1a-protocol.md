# Gate 1A approval protocol v2

Status: frozen cross-language data contract for the feasibility spike. Gate 1A
itself is **not passed**. `approval.Unsupported` remains the only production
adapter, and this document does not enable confirmation, apply, release, or
Homebrew installation.

The native trust boundary, canonical URL/plan-ID grammar, and exact future IPC
frame are specified in [Gate 1A native approval boundary](gate1a-native-boundary.md).

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
