# Homebrew

## Standard macOS Formula

The standard macOS distribution channel for the existing CLI is a source-built
Formula in the maintained tap. A merged source change reaches Homebrew only
after its own release tag and a merged tap update; check `version` before
relying on newly documented behavior:

```bash
brew install abigotado/tap/youtrack-agent-cli
youtrack-agent-cli version -o json
```

Like the Jira, Slack, and Confluence CLI Formulae, this Formula pins a
checksummed immutable source release and has Homebrew build it locally with Go
and `CGO_ENABLED=1`. The resulting binary links the native macOS
Security.framework Keychain backend. This is a Formula, not a downloaded
binary Cask: it does not require an Apple Developer membership, Developer ID
signing, notarization, or an installer that removes Gatekeeper quarantine.

The Formula carries the standard CLI, including explicit-profile OAuth,
Keychain credential storage, REST reads, local journal operations, and the
Agent Skill installer. The Linux portable Remote-MCP-only release is unchanged:
it remains credential-free and does not gain a macOS archive from this Formula.

The release sequence is deliberately simple: merge the source change, create
the immutable source tag, then open the tap PR that pins that exact archive and
its SHA-256. A Formula update never builds from a mutable branch.

### OAuth error-code transition in v0.2.0

The `v0.2.0` standard CLI changes the machine recovery classification for
authorization-code token exchange failures. The JSON envelope remains `v:1`,
but callers that branch on the published `OAUTH_TOKEN_EXCHANGE_FAILED` code
must handle these cases explicitly. The published Formula may still be an
earlier version; check `version` before relying on these v0.2.0 codes.
Previously all of the following failures exited with 5:

| Token failure | `error.code` in v0.2.0 | Exit |
| --- | --- | --- |
| Transport failure, HTTP 408/429/5xx, or interrupted HTTP 200 body other than cancellation/deadline | `OAUTH_TOKEN_ENDPOINT_UNAVAILABLE` | 6 (bounded backoff, then restart login with a fresh code) |
| Invalid TLS trust, missing DNS name, or scheme mismatch | `OAUTH_TOKEN_TRANSPORT_REJECTED` | 5 (check endpoint and trust) |
| Other HTTP 4xx rejection | `OAUTH_TOKEN_REQUEST_REJECTED` | 5 (auth) |
| Malformed HTTP 200, unexpected 1xx, or non-200 2xx | `OAUTH_TOKEN_RESPONSE_INVALID` | 5 (auth) |
| HTTP 3xx redirect | `OAUTH_TOKEN_REDIRECT_REFUSED` | 5 (auth) |
| Cancellation or deadline after authorization-code token request attempt begins | `OAUTH_TOKEN_REQUEST_INTERRUPTED` | 5 (fresh login; never replay the POST) |
| Refresh request failure, post-refresh persistence uncertainty, or invalid local exchange input | `OAUTH_TOKEN_EXCHANGE_FAILED` | 5 (auth) |

Refresh request failures after an attempt begins keep the published
`OAUTH_TOKEN_EXCHANGE_FAILED` / exit 5 recovery in this release, including
DNS/TLS failures even if they occurred before wire dispatch. A cancellation or
deadline detected before an attempt remains a normal `CANCELED` or `TIMEOUT`.
The post-attempt category is conservative because dispatch cannot always be
established. Agents must not trigger another refresh after an ambiguous result:
the server may have rotated the old token before the response was lost.
A durable refresh fence across CLI processes is required before changing that
behavior; this release does not provide one. The CLI makes no repeat attempt
within the same invocation. A failed token request leaves the old credential
in place; after a local save error, the persisted credential state is unknown.
A later auth-dependent invocation, including `auth status --check` or a read,
may automatically retry the old token. Agents should avoid those commands after
failure and start a fresh interactive login instead.
If the old credential remains present, replacement requires explicit
operator approval (`auth login --profile NAME --yes`); agents must not add
`--yes` automatically. The exchange-specific
failure codes are also listed in the
[machine-error reference](oauth-errors.md).

Only the fixed category and numeric HTTP status appear in an error. The token
endpoint response, OAuth code, verifier, and tokens remain private. Do not
retry a rejected or invalid-response request unchanged. A failed first login
stores no new credential; restarting login starts a fresh browser authorization.

### Authentication and upgrades

Create or select a named profile, then use the normal browser OAuth flow:

```bash
youtrack-agent-cli auth login --profile work -o json
youtrack-agent-cli auth status --profile work --check -o json
```

Homebrew never reads, copies, deletes, or automatically migrates a credential.
After a Formula Cellar upgrade, macOS may require an existing Keychain item's
ACL to be explicitly rebound to the current executable. Only when the CLI
reports that condition, run:

```bash
youtrack-agent-cli auth migrate-keychain --profile work --yes -o json
```

That command operates on exactly one selected profile and does not expose its
secret. It is deliberately an operator action, never a post-install hook.

## Guarded-write boundary

The Formula does not activate guarded YouTrack writes. `mutation prepare`
remains a network-free local planning operation, while `mutation confirm`,
`mutation apply`, and `mutation reconcile` fail closed until Gate 1A and Gate
1B have passed and a separately authorized write-capable release exists. Do
not use raw REST or MCP mutation tools as a workaround.

Formula support therefore does not claim a signed native approval helper,
confirmation receipt, or mutation authority. The existing dependency manifest
and `tools/homebrewcheck` provide a dependency-closure and network-free
standard-CLI CGO build rehearsal. They do not validate a Homebrew Formula and
are not proof of native Gate readiness. Formula validation happens in the tap
PR against the pinned release: `brew audit`, a source install, and `brew test`
must all pass there.

## Separate future Cask channels

The [macOS identity-only ADR](macos-identity-readonly-adr.md) describes a
separate, optional, not-yet-activated signed identity Cask. It is not a
precondition for the Formula and is not a write path.

A future Gate 1A write-capable Cask is also a separate proposed channel. It
would carry a completed signed/notarized application and native approval helper
without rebuilding either artifact. Its prerequisites remain the Gate 1A and
Gate 1B evidence, independent review, release-policy update, and the artifact
authorization requirements in [the trust-root topology](gate1a-trust-root.md),
[exact-artifact authorization](gate1a-artifact-authorization.md), and the
[mutation lifecycle](guarded-mutations.md). Neither Cask is required to
install, authenticate with, or use the standard Formula today.
