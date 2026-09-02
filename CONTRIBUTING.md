# Contributing

`youtrack-agent-cli` is a Go binary whose public interface is primarily consumed
by agents. Preserve the JSON v1 envelope, stable exit codes, explicit profile
selection, bounded operations, and one-shot mutation semantics.

Read `AGENTS.md` and the matching `.agents/rules/` files before editing. Keep
package dependencies directed toward `internal/errx`; commands wire behavior but
do not issue HTTP directly. Test HTTP with `httptest`, credentials with a fake
store, and filesystem behavior with `t.TempDir()`.

Generated command and contract references are updated with:

```bash
go generate ./...
```

The source Agent Skill lives only under `assets/skills/youtrack-agent/`.
Installation tests must never touch the developer's home directory.

Before review, run:

```bash
gofmt -l .
go vet ./...
go test -race ./...
python3 ~/.agents/compiler.py --source .agents --root . --scope project --check
python3 .agents/scripts/sync-rules.py --check
python3 -m unittest discover -s .agents/tests -p 'test_*.py'
```

Do not commit `.claude/`, `.codex/`, credentials, generated build output, or
account-specific MCP configuration. Never broaden the fixed REST/MCP surface
through an arbitrary method/path escape hatch.
