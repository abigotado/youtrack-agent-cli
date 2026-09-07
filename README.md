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
The future write path uses a helper-private fixed-active Keychain coordinator
as its cross-process mutex. LaunchAgent registration manages lifecycle, not
singleton security; another same-user helper remains in the threat model.
Registry commits cannot overlap an apply, and apply must durably
enter `in_flight`, obtain one exact-request permit, send at most once, and
irreversibly quiesce every send/sign/commit capability before durably closing.
Only a valid already-closed lease may be cleaned up, using its exact Keychain
persistent reference so a stale cleanup cannot delete a replacement lease.
An unclosed lease stays quarantined even after restart, reboot, expiry, or
user confirmation. This deliberately sacrifices availability after a crash;
bounded remote reconciliation reports findings without changing its journal.
The descriptor-bound helper
profile expiry is a strict Gate, publication, installation, and pre-send
cutoff. The closed evidence contract includes exact install/reinstall and
Keychain-migration failure cases plus deterministic two-party coordinator
schedules through close/delete ambiguity and active-cleanup ABA denial. Future coordinator/profile failures
add stable JSON v1 `error.code` values and distinct future exits 10..13 while
corruption remains existing exit 1;
the only recovery commands will be `mutation authority status` and trusted-UI
`mutation authority recover`, neither with a plan ID or force-clear option.
None of this is enabled in the current build.

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
