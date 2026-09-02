# youtrack-agent-cli

Agent-first JetBrains YouTrack integration: official Remote MCP for bounded
reads, plus a local Go CLI for explicit profiles and guarded one-shot writes.

The CLI is not a generic REST client. It emits a versioned JSON v1 envelope,
keeps credentials in the OS secret store, requires a named profile for every
remote operation, and treats ambiguous mutation outcomes as reconciliation
work rather than permission to retry.

## Build and inspect

```bash
go build -o ./bin/youtrack-agent-cli ./cmd/youtrack-agent-cli
./bin/youtrack-agent-cli version -o json
./bin/youtrack-agent-cli contract -o json
```

Use `youtrack-agent-cli --help` and [the generated command reference](docs/commands.md)
for the current surface. [The machine contract](docs/contract.md) defines
envelopes, errors, and recovery.

## Profile bootstrap

Copy [the non-secret profile example](docs/profile.example.json), replace the
instance, expected account, OAuth public-client registration, and scopes, then
validate it before writing local metadata:

```bash
youtrack-agent-cli profile add --from profile.json --dry-run
youtrack-agent-cli profile add --from profile.json --yes
youtrack-agent-cli auth login --profile work
youtrack-agent-cli auth status --profile work --check
```

For permanent-token fallback, run `auth import-token --interactive` in a trusted
human terminal. Pipe, heredoc, file, argv, and environment input are refused so
the token cannot enter an agent transcript, shell history, or profile file.
Existing Keychain records created by an older build must be rebound explicitly
with `auth migrate-keychain --profile work --yes`; migration never prints or
returns the credential.

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

## Guarded writes

The initial write kinds are `issue.create`, `issue.update`, and `comment.add`.
They follow four separate steps:

```bash
youtrack-agent-cli mutation prepare --offline --profile work --kind issue.update --project 0-1:APP --request-stdin --expected-state snapshot.json --schema-sha256 SHA256 --out plan.json
youtrack-agent-cli mutation status --plan-id YTAP_PLAN_ID
youtrack-agent-cli mutation export --plan-id YTAP_PLAN_ID --out recovered-plan.json
youtrack-agent-cli mutation confirm --plan-id YTAP_PLAN_ID
youtrack-agent-cli mutation apply --profile work --plan-id YTAP_PLAN_ID
youtrack-agent-cli mutation reconcile --profile work --plan-id YTAP_PLAN_ID
```

`prepare --offline` performs no network, OAuth, browser, or secret-store access.
`confirm` requires trusted OS user presence and has no noninteractive bypass.
In this first fail-closed slice, `confirm`, `apply`, and `reconcile` remain
disabled until the signed native helper and executor pass their gates. No
terminal or `--yes` fallback exists. See [guarded mutations](docs/guarded-mutations.md).

Binary distribution, including Homebrew, is intentionally disabled until Gate
1A and a signed, notarized, audited macOS package are available. A normal
source-built Formula cannot preserve the native approval helper's required
signing identity and entitlements. Linux/Windows and unsigned portable archives
are not a supported credential-bearing release path. The repository's Homebrew
manifest and checker are readiness inputs, not an installable Formula; see
[Homebrew readiness](docs/homebrew.md).

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
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check
python3 .agents/scripts/sync-rules.py --check
python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
