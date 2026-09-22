# OAuth token error recovery

The standard macOS CLI reports these codes in the v1 JSON error envelope for
authorization-code token exchange. The codes and exits below first appear in
`v0.2.0`; a merged source change does not reach Homebrew until its tagged
release is pinned by a merged tap update.

| `error.code` | Exit | Recovery |
| --- | ---: | --- |
| `OAUTH_TOKEN_ENDPOINT_UNAVAILABLE` | 6 | Back off, then restart `auth login` to obtain a fresh authorization code. Never replay the token POST with the old code. Includes network interruption, HTTP 408/429/5xx, and interrupted HTTP 200 bodies. |
| `OAUTH_TOKEN_TRANSPORT_REJECTED` | 5 | Check the configured endpoint, DNS name, and TLS trust. Includes invalid certificate trust, missing DNS name, and scheme mismatch. Do not retry unchanged. |
| `OAUTH_TOKEN_REQUEST_REJECTED` | 5 | Check the public OAuth-client registration and profile, then start a new login. Includes other HTTP 4xx responses. |
| `OAUTH_TOKEN_RESPONSE_INVALID` | 5 | Report a token-response compatibility problem. Includes malformed HTTP 200 and unexpected 1xx or non-200 2xx responses. Do not retry unchanged. |
| `OAUTH_TOKEN_REDIRECT_REFUSED` | 5 | Check the pinned token endpoint. Redirects are never followed. |
| `OAUTH_TOKEN_EXCHANGE_FAILED` | 5 | Correct invalid local exchange input, or start a new login after a refresh request failure with possible dispatch. This published code remains the refresh fallback in `v0.2.0`. |

Before `v0.2.0`, all of these failures used
`OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5. This is a deliberate breaking
machine-recovery change while the JSON envelope shape remains `v:1`.

These OAuth errors do not include `error.retry_after`. For
`OAUTH_TOKEN_ENDPOINT_UNAVAILABLE`, the caller applies its own bounded backoff
before starting a fresh login; the CLI does not forward the server's
`Retry-After` header or authorize replay of the old token request.

Cancellation detected before a refresh request is sent keeps the normal
`CANCELED` recovery. Refresh-token rotation makes a lost or malformed response ambiguous:
the server may have consumed the old token even when this CLI cannot save the
new one. This release does not have a durable cross-process refresh fence.
Agents must not automatically repeat a failed refresh; a fresh interactive
login is the recovery path. A future refresh-recovery change must first add
that fence and test it across separate CLI invocations.

Only fixed categories and numeric HTTP statuses are exposed. Server response
bodies, OAuth codes, PKCE verifiers, tokens, URLs returned by the server, and
raw transport errors never appear in the public error.
