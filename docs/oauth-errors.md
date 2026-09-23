# OAuth token error recovery

The standard macOS CLI reports these codes in the v1 JSON error envelope for
authorization-code token exchange. The codes and exits below first appear in
`v0.2.0`; a merged source change does not reach Homebrew until its tagged
release is pinned by a merged tap update.

| `error.code` | Exit | Recovery |
| --- | ---: | --- |
| `OAUTH_TOKEN_ENDPOINT_UNAVAILABLE` | 6 | Back off, then restart `auth login` to obtain a fresh authorization code. Never replay the token POST with the old code. Includes transport failures and HTTP 408/429/5xx. |
| `OAUTH_TOKEN_TRANSPORT_REJECTED` | 5 | Check the configured endpoint, DNS name, and TLS trust. Includes invalid certificate trust, missing DNS name, and scheme mismatch. Do not retry unchanged. |
| `OAUTH_TOKEN_REQUEST_REJECTED` | 5 | Check the public OAuth-client registration and profile, then start a new login. Includes other HTTP 4xx responses. |
| `OAUTH_TOKEN_RESPONSE_INVALID` | 5 | Check token-response compatibility, then start a fresh interactive login for a new authorization code. Never replay the previous token POST. Includes malformed or oversized HTTP 200 and unexpected 1xx or non-200 2xx responses. |
| `OAUTH_TOKEN_REDIRECT_REFUSED` | 5 | Check the pinned token endpoint. Redirects are never followed. |
| `OAUTH_TOKEN_REQUEST_INTERRUPTED` | 5 | Cancellation or deadline expiry after an authorization-code token request was attempted, or any error while reading an HTTP 200 token response. Start a fresh login; do not replay the token POST. |
| `OAUTH_TOKEN_EXCHANGE_FAILED` | 5 | Correct invalid local exchange input, or start a new login after a refresh request failure, local binding rejection, or persistence uncertainty. This published code remains the refresh fallback in `v0.2.0`. |

Before `v0.2.0`, all of these failures used
`OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5. This is a deliberate breaking
machine-recovery change while the JSON envelope shape remains `v:1`.

These OAuth errors do not include `error.retry_after`. For
`OAUTH_TOKEN_ENDPOINT_UNAVAILABLE`, the caller applies its own bounded backoff
before starting a fresh login; the CLI does not forward the server's
`Retry-After` header or authorize replay of the old token request.

Cancellation or deadline expiry detected before either token request is attempted
keeps the normal `CANCELED` or `TIMEOUT` recovery. Once an attempt begins, the
client cannot prove whether the server consumed it. An interrupted authorization-
code exchange therefore requires a fresh login, without retrying its token POST.
An HTTP 200 response with a body-read failure is also non-retryable: the server
may already have consumed the authorization code, regardless of the local read
error. The CLI exposes only a fixed error category and HTTP 200, never the
underlying read error.
Likewise, a malformed or oversized HTTP 200 response—or an unexpected 1xx or
non-200 2xx response—does not prove the authorization code remains usable.
`OAUTH_TOKEN_RESPONSE_INVALID` always requires a fresh interactive login and
new code after checking compatibility; it never authorizes replaying the old
token POST, even if the client configuration is changed.

After a refresh attempt, all failures retain the legacy non-retryable
`OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5 recovery, including DNS and TLS failures
that may in fact have occurred before dispatch and local failure after a
successful refresh response. A local binding rejection happens before Save,
so the old credential remains unchanged. A Save failure leaves the persisted
credential state unknown. This intentionally coarse
classification preserves the published refresh contract until a durable
cross-process fence can establish safe retry semantics. Refresh-token rotation
makes a lost or malformed response ambiguous:
the server may have consumed the old token even when this CLI cannot save the
new one. This release does not have a durable cross-process refresh fence.
The CLI does not repeat refresh within the same invocation. A failed token
request leaves the old credential in place. A later auth-dependent invocation, including
`auth status --check` or an authenticated read, may automatically send that
old refresh token again. Agents must avoid further auth-dependent commands
after a failed refresh and direct the operator to a fresh interactive login.
If the old credential remains present, the operator must explicitly approve
its replacement (`auth login --profile NAME --yes`); agents must not add
`--yes` automatically. The CLI's machine hints never prescribe an unattended
confirmation flag.

After a successful refresh response, local failures have fixed, actionable
diagnostics while retaining the same auth/5 code. A binding mismatch directs
the operator to inspect the local profile/credential binding; invalid token
validation directs them to local token validation and OAuth client
configuration. Other pre-Save validation failures direct them to inspect the
local binding check. None of these paths called Save, so the old credential
remains. Save failures keep persistence *uncertain*: the public hint identifies
one fixed local repair area—interactive Keychain access, an operator-approved
ACL migration, canceled Keychain authorization, an interrupted or timed-out
save, Keychain availability and permissions, or an unclassified local store
failure—without exposing the raw error or OSStatus. In every case the agent
stops auth-dependent commands and refresh retries. Only after the local issue
is addressed should an operator start a fresh interactive login and explicitly
approve replacement if required.

A future refresh-recovery change must first add a durable fence and test it
across separate CLI invocations.

Only fixed categories and numeric HTTP statuses are exposed. Server response
bodies, OAuth codes, PKCE verifiers, tokens, URLs returned by the server, and
raw transport errors never appear in the public error.
