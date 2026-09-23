# youtrack-agent-cli

Agent-first JetBrains YouTrack integration with two deliberately separate
distribution channels:

- The published `v0.x` **portable read-only** edition is Linux-only and
  Remote-MCP-only. It validates non-secret read-only profile metadata and
  installs a shared Codex/Claude Code skill. Every remote read goes through the
  official YouTrack Remote MCP with an explicit six-tool allowlist.
- The **standard macOS edition** is being prepared as a source-built Homebrew
  Formula. Once published, Homebrew will compile the standard CLI locally with
  `CGO_ENABLED=1`, so OAuth credentials remain in the native
  Security.framework Keychain. This channel needs neither an Apple Developer
  membership nor a signed/notarized application bundle.

The portable archive has no local OAuth or token storage, REST client,
journal, mutation command, native helper, or Homebrew package. That is a
compile-time boundary, not a disabled runtime feature. It does not constrain
the separate standard Formula edition.

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

## macOS Homebrew Formula

The planned standard macOS distribution channel is a source-built Formula in
the maintained tap. The command below is for use after publication, not an
indication that the Formula is already available. A merged source change
reaches Homebrew only after its own release tag and a merged tap update; check
`version` before relying on newly documented behavior:

```bash
brew install abigotado/tap/youtrack-agent-cli
youtrack-agent-cli version -o json
```

Once published, the Formula will pin a checksummed source release and build it
locally with Go, CGO, and the macOS Security.framework; it does not download
an unsigned executable, remove Gatekeeper quarantine, or need Apple Developer
signing or notarization. It includes the standard explicit-profile OAuth and Keychain
commands:

```bash
youtrack-agent-cli auth login --profile work -o json
youtrack-agent-cli auth status --profile work --check -o json
```

The installer never reads, copies, or migrates credentials. After a Formula
Cellar upgrade, an existing credential may require an explicit ACL rebind:

```bash
youtrack-agent-cli auth migrate-keychain --profile work --yes -o json
```

Run that command only for the named profile when the CLI reports that its
existing Keychain item needs migration. It does not print the credential.
See [Homebrew](docs/homebrew.md) for support boundaries and the future Cask
channels.

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

The macOS Formula enables the standard CLI's OAuth, Keychain, REST, journal,
and network-free `mutation prepare` surfaces. It does **not** make guarded
writes available: `mutation confirm`, `mutation apply`, and
`mutation reconcile` fail closed until Gate 1A and Gate 1B have passed and a
separately authorized write-capable channel is released. This applies equally
to source builds and the Formula; no agent may bypass it through MCP or raw
REST.

The signed identity-only Cask and the Gate 1A write-capable Cask remain
separate proposed future channels. They have different trust requirements from
the Formula and are not prerequisites for installing or using the standard
macOS CLI. See [Homebrew](docs/homebrew.md), [the trust-root topology](docs/gate1a-trust-root.md),
and [the mutation lifecycle](docs/guarded-mutations.md).

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
