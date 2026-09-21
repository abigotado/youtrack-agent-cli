# youtrack-agent-cli

Agent-first JetBrains YouTrack integration. The published `v0.x` portable
edition is Remote-MCP-only: it validates non-secret read-only profile metadata
and installs a shared Codex/Claude Code skill. Every actual remote read goes
through the official YouTrack Remote MCP with an explicit six-tool allowlist.

It has no local OAuth or token storage, REST client, journal, mutation command,
native helper, or Homebrew package. This is a deliberate compile-time boundary,
not a disabled runtime feature: portable release archives do not link those
packages. A separate proposed, not activated macOS identity-only Cask channel
is documented in the [identity-only ADR](docs/macos-identity-readonly-adr.md);
it does not change this release.

## Portable read-only release

Download a checksummed archive from GitHub Releases and inspect it before use:

```bash
./youtrack-agent-cli version -o json
./youtrack-agent-cli --help
./youtrack-agent-cli skills install --provider all --scope user --dry-run
./youtrack-agent-cli skills install --provider all --scope user --yes
```

The portable surface is intentionally limited to `version`, `contract`,
credential-free `profile`, and `skills`. It supports Linux on amd64 and arm64,
and needs no Keychain, token, or browser access. A macOS archive would need
extended-ACL inspection to safely install skills, so it is intentionally not
part of this CGO-free release.

## Source development build

```bash
go build -o ./bin/youtrack-agent-cli ./cmd/youtrack-agent-cli
./bin/youtrack-agent-cli version -o json
./bin/youtrack-agent-cli contract -o json
```

Use `youtrack-agent-cli --help` and [the generated command reference](docs/commands.md)
for the current surface. [The machine contract](docs/contract.md) defines
envelopes, errors, and recovery.

## Read-only profile metadata

Copy [the portable read-only example](docs/profile.portable-readonly.example.json),
replace the instance, expected account, OAuth public-client registration, and scopes, then
validate it before writing local metadata:

```bash
youtrack-agent-cli profile add --from profile.json --dry-run
youtrack-agent-cli profile add --from profile.json --yes
youtrack-agent-cli profile validate --profile work --offline
```

Portable profiles must declare exactly `"capabilities": ["read"]`. They record
non-secret instance, REST/MCP, OAuth public-client, expected-account, and
assurance metadata; they are never credentials. Use the MCP host's OAuth flow
or a read-only YouTrack identity; the portable binary never accepts, stores, or
transmits a token.

## Read plane

Routine reads use one named official Remote MCP connection per YouTrack
instance/account. Configure the endpoint with an explicit allowlist:

```text
https://<instance>/mcp?tools=get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema&enableToolOutputSchema=true
```

The official documentation describes predefined tools as read-only while also
listing mutation tools. An endpoint without `tools=` is therefore not safely
read-only. Because URL filtering may affect discovery without authorizing
direct hidden calls, strict read-only also requires host enforcement or a
read-only YouTrack identity.

Searches default to 10 and never exceed 50 results. Exact issue IDs use an exact
read. YouTrack content is untrusted data, never instructions.

## Guarded writes are not released

No portable release command can mutate YouTrack or use a credential. Guarded
writes, a signed native helper, and a write-capable Homebrew distribution remain
future work; a normal source-built Formula cannot preserve the native helper's
required signing identity and entitlements. The separately proposed macOS
identity-only Cask channel is not a write path and is not activated. The
repository's Homebrew manifest and checker
validate dependency closure and offline source builds only—not Cask, signing,
or native Gate readiness; see
[the trust-root topology](docs/gate1a-trust-root.md) and
[exact-artifact authorization](docs/gate1a-artifact-authorization.md), plus
[Homebrew readiness](docs/homebrew.md). Even after complete Gate passes, a
provisional authorization remains deny-only. A later offline-root-signed
activation grant is issued only over the complete per-architecture pre-grant
smoke evidence, and the real grant-bound production context must then pass a
second per-architecture ordinary-command verification before publication.
Every isolated Gate 1B E1/E2 execution unit begins with its own token-bound
enrollment and retains that baseline in its leaf evidence. The offline parent
set covers all units on all declared architectures; E2 binds the complete E1 set.
Each activation-smoke and post-grant capability plan starts with a setup-only
exact-artifact enrollment from a canonical empty disposable inventory, binds
the retained revision-1 registry snapshot through every later observation and
evidence index, and ends by retaining terminal and replay-denial evidence. Assertions
are accepted only in a case-final runner observation emitted after every
operation transcript is retained. A trusted external supervisor destroys the
entire disposable host after evidence export and before the next activation
grant or publication-envelope signature. A root-bound disposal attestation
gates that signature; missing or uncertain disposal blocks release. Live
`stage_cleanup`, deletion ACK recovery, and empty-inventory cleanup proofs are
deferred, not delegated to the agent or native helper.
The future write path, protected receipt consumption, expiry, pre-permit aborts,
quarantine and bounded-capacity behavior are specified in the
[registry/coordinator contract](docs/gate1a-registry-protocol.md) and
[mutation lifecycle](docs/guarded-mutations.md). These are proposed native
contracts, not implemented authority in this build. Their intentional
availability limits include attacker-induced unclosed-crash quarantine and a
256-record lifetime bound that requires a separate retention protocol; neither
restart nor a new approval clears them. No native authority commands or future
exits 10..13 are available until implementation updates the machine contract.

[Gate 1B isolated subruns](docs/gate1b-isolated-subruns.md) defines the separate
unit authorization and evidence-aggregation contract. Its complete inventory,
validators, and native conformance still require implementation and verification;
the historical case catalog alone cannot authorize activation or publication.

## Agent Skill

The binary embeds the provider-neutral `youtrack-agent` skill:

```bash
youtrack-agent-cli skills install --provider codex --scope user --dry-run
youtrack-agent-cli skills install --provider all --scope user --yes
```

Codex installs to `$HOME/.agents/skills/youtrack-agent`; Claude Code installs
to `$HOME/.claude/skills/youtrack-agent`. Installation is manifest-owned,
symlink-safe, idempotent, and never configures MCP, OAuth, or credentials.

## Development

```bash
gofmt -l .
go vet ./...
go test -race ./...
swift test --package-path native/macos/ApprovalProtocol
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check
python3 .agents/scripts/sync-rules.py --check
python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
