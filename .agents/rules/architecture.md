# Architecture

`youtrack-agent-cli` is a single Go binary built for machine callers.

## Package direction

- `cmd/youtrack-agent-cli`: process entry, panic recovery, exit delivery only.
- `internal/cli`: Cobra wiring and output selection; never imports `net/http`.
- `internal/application`: operation orchestration and one-shot write lifecycle.
- `internal/profile`, `internal/auth`, `internal/writepolicy`: non-secret profile,
  credential boundary, and exact project policy respectively.
- `internal/youtrack`: fixed-origin YouTrack reads/writes; never imports auth or
  profile storage.
- `internal/skills`: manifest-owned Codex/Claude skill installation only.
- `internal/output`: compact renderers and JSON v1 envelope.
- `internal/errx`: dependency-free typed error contract.

Dependencies point from CLI/orchestration toward domain boundaries and finally
`errx`; never introduce a storage/client cycle. Every I/O function accepts
`context.Context` first. Remote pagination contributes only an opaque cursor;
the client rebuilds a fixed-origin, fixed-operation URL.

## Streams and mutations

In JSON mode stdout contains exactly one envelope. Logs, warnings, and prompts
use stderr. Text, raw, and explicit help are caller-selected exceptions.

Every network operation names a profile. Reads are bounded. Mutation preparation
is network-free, approval requires trusted user presence, and apply dispatches at
most one mutating request. An ambiguous result is reconciled by bounded reads and
is never replayed automatically.
