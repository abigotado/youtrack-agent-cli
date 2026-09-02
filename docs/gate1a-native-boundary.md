# ADR: Gate 1A native approval boundary

- Status: Accepted for PR A contract implementation
- Date: 2026-09-02
- Gate result: **NOT PASSED**
- Production adapter: `approval.Unsupported`

## Context

YouTrack mutations require evidence that a human reviewed one exact, bounded
plan and was freshly authenticated by macOS. A terminal prompt, `--yes`, an
agent-controlled browser, or an unsigned child process cannot provide that
evidence. LocalAuthentication alone proves an authentication event but does
not bind the reviewed bytes, instance, account, project, preconditions, and
helper key into a durable receipt.

The boundary is exposed to confused-deputy and parser-differential risks: an
agent controls plan content, same-user processes can race or replace endpoints,
URL libraries disagree on normalization, and an ECDSA signature has multiple
encodings unless the wire form is frozen.

## Decision

Go is the canonical plan and receipt authority. The separately signed native
component independently validates the same language-neutral value grammar,
renders every plan byte inertly and reversibly, obtains fresh user presence,
and signs one cross-bound receipt with a non-exportable P-256 key. Neither side
trusts decoded values merely because the other side accepted them.

PR A freezes only pure value codecs, shared vectors, and the future connection
contract. It introduces no socket, process launch, helper discovery, Keychain,
Secure Enclave, UI, application-service, journal-transition, or mutation I/O.

### Canonical URL and plan identity

Every approval URL is at most 2,048 ASCII bytes and starts with literal
lowercase `https://`. Its host is either canonical lowercase DNS or canonical
dotted IPv4:

- DNS totals at most 253 bytes; every label is 1..63 bytes, contains only
  `a-z`, `0-9`, and internal hyphens, and has no trailing dot.
- IPv4 has exactly four decimal octets in `0..255`; leading zeroes are forbidden
  except for the value `0`.
- IPv6 is excluded from protocol v1.
- An optional port is decimal `1..65535` without a leading zero. Port `443` is
  omitted.

The path is empty or `/segment(/segment)*`. Segments are nonempty and contain
only RFC 3986 unreserved ASCII, sub-delimiters, `:`, and `@`. A trailing slash,
double slash, `.`/`..` segment, percent encoding, backslash, control/space,
query, fragment, userinfo, or non-ASCII byte fails closed. REST is exactly the
instance URL plus `/api`, still within 2,048 bytes. `endpoint.ValidateApprovalURL`
is the shared Go validator.

Plan IDs are `YTAP-` plus uppercase RFC 4648 Base32 without padding over
exactly 16 bytes. Decode/re-encode equality rejects unused nonzero final bits.
`intent.ValidatePlanID` is shared by preparation, journal lookup, and approval.

### Exact frame contract

One message is exactly one frame; EOF/truncation and every trailing byte fail.
The 16-byte header is:

| Offset | Width | Value |
| ---: | ---: | --- |
| 0 | 8 | raw ASCII `YTAPIPC\x00` |
| 8 | 1 | version `1` |
| 9 | 1 | kind: `1=request`, `2=success`, `3=error` |
| 10 | 2 | reserved big-endian zero |
| 12 | 4 | unsigned big-endian payload length |

The receiver validates the unsigned length against the selected kind before
payload allocation:

- request: 32 raw challenge bytes followed by 1..524,288 exact canonical plan
  bytes; payload is 33..524,320 bytes;
- success: echoed challenge, exact 91-byte P-256 DER SPKI, then 1..4,096
  canonical receipt bytes; payload is 124..4,219 bytes;
- error: exactly the challenge and one code byte, total 33 bytes.

The complete error vocabulary is `1=user_canceled`, `2=request_invalid`,
`3=user_presence_unavailable`, `4=key_unavailable`, `5=signing_failed`,
`6=internal_failure`. There is no error text or extension field.

The CLI creates a fresh opaque 32-byte CSPRNG challenge per request. Both
success and error responses echo it, and Go compares it in constant time.

### Cross-binding acceptance

Go accepts a success only after all of these checks succeed:

1. the challenge equals the outstanding request;
2. SPKI has the exact P-256 representation and is on-curve;
3. the receipt strictly parses and byte-for-byte re-encodes canonically;
4. plan ID, SHA-256 of the exact displayed snapshot, profile identity,
   account, project ID/key, schema, request, and expected-state hashes match
   the validated snapshot;
5. receipt fingerprint equals SHA-256 of the response SPKI;
6. timestamps use whole-second UTC, lifetime is positive and no more than five
   minutes, issue time is no more than 30 seconds in the future, and `now` is
   strictly before expiry;
7. the low-S strict DER ECDSA P-256 signature verifies over the exact
   `approval.SigningBytes` using the response SPKI.

The future native factory uses an exact two-minute receipt lifetime. This is a
minting policy; the five-minute bound remains the verifier safety ceiling.

### Future connection and native key boundary

The later implementation uses helper-owned AF_UNIX connections and binds
identity to the accepted connection's `LOCAL_PEERTOKEN` audit token. Each side
resolves that token with `SecCodeCopyGuestWithAttributes` and checks a pinned
designated requirement. PID and filesystem path are diagnostics, never
authority. Replacement, exec, PID reuse, peer-token failure, timeout, crash,
EOF, malformed frames, and protocol disagreement fail before approval.

This boundary is grounded in Apple's published `LOCAL_PEERTOKEN` definition in
the [XNU `sys/un.h` header](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h),
the Security framework's [guest-attribute keys](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys),
and [`SecCodeCopyGuestWithAttributes`](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)).

The helper-only permanent key is P-256 Secure Enclave material stored through
the data-protection Keychain with `kSecAttrAccessControl`. A new `LAContext`
with zero reuse is bound to the actual private-key signing operation, used
once, and invalidated. Password-fallback versus `biometryCurrentSet` remains an
explicit operator-reviewed policy. PR A does not create this key or access any
Keychain item.

The key and presence policy follows Apple's first-party guidance for
[protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags),
[`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence),
and the `LAContext`
[`touchIDAuthenticationAllowableReuseDuration`](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration)
control. These sources justify the future design; PR A contains no live use of
those APIs.

## Consequences

- Go and Swift consume shared URL, ID, plan, receipt, key, signature, display,
  and frame fixtures; disagreement is a blocking failure.
- The binary format has no ambiguity from JSON envelopes, Unicode, optional
  fields, helper-supplied text, or integer byte order.
- The returned SPKI is cryptographically checked but is not yet enrollment
  authority. Production integration must pin the expected key generation and
  enrolled SPKI/designated requirement before enabling confirmation.
- `approval.Unsupported` remains the only production adapter. Gate 1A stays
  **NOT PASSED** until signed/notarized native execution, Secure Enclave
  isolation, peer validation, UI review, and clean-host lifecycle evidence all
  pass.

## Rejected alternatives

- stdin/PTY/`--yes`: agent-controlled and not bound to immutable displayed
  bytes;
- HTTP callback or localhost service: larger origin, DNS, proxy, and browser
  attack surface;
- PID/path-only helper trust: vulnerable to replacement and PID reuse;
- JSON IPC: unnecessary duplicate-field, number, Unicode, and canonicalization
  surface around an already-canonical plan and receipt;
- arbitrary error strings: untrusted display/log injection surface;
- high-S ECDSA acceptance: permits a second wire representation of one
  signature;
- source-built or ad-hoc helper as Gate evidence: does not prove the production
  designated requirement, entitlements, notarization, or upgrade boundary.
