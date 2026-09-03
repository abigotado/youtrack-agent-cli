# MVP command and tool surface

Status: Accepted; fail-closed first-slice surface implemented

## Remote MCP read surface

The MVP exposes exactly these official tools through each read profile:

```text
get_current_user
search_issues
get_issue
get_issue_comments
get_project
get_issue_fields_schema
```

No custom MCP tool and no predefined mutation tool is part of the MVP.

## `youtrack-agent-cli` principles

- It is not a general REST client and has no arbitrary method/path command.
- It accepts structured JSON over stdin or an explicitly named file, never large bodies as shell arguments.
- Every network operation requires `--profile`; there is no mutable global “current profile”.
- Machine output is versioned JSON on stdout; diagnostics go to stderr with secrets redacted.
- Exit codes distinguish policy denial, precondition failure, transport ambiguity, and reconciliation failure.
- Mutation HTTP retries are disabled.

## Profile and authentication commands

```text
youtrack-agent-cli profile list
youtrack-agent-cli profile show --profile <name>
youtrack-agent-cli profile validate --profile <name> --offline
youtrack-agent-cli profile add --from <non-secret-profile.json>
youtrack-agent-cli auth login --profile <name>
youtrack-agent-cli auth status --profile <name>
youtrack-agent-cli auth whoami --profile <name>
youtrack-agent-cli auth logout --profile <name>
```

`profile add` writes only non-secret configuration. `auth login` uses Authorization Code + PKCE where supported and writes refresh/permanent tokens only to the OS secret store. No command returns token material.

## Read helpers used by the write protocol

Routine agent reads stay on Remote MCP. The CLI still needs narrow REST reads for policy and reconciliation:

```text
youtrack-agent-cli inspect issue --profile <name> --id <ID>
youtrack-agent-cli inspect project --profile <name> --project <ID-or-key>
youtrack-agent-cli inspect schema --profile <name> --project <ID-or-key> --limit <1-100> --offset <n>
youtrack-agent-cli mutation status --plan-id <YTAP-ID>
```

There is no unbounded CLI search in the initial surface. A bounded internal search primitive exists only for reconciliation. For comments, the documented collection has `$top`/`$skip` but no author/time filter or ordering guarantee, so the CLI must not claim that such filters are server-enforced. It may use a preflight `commentsCount` plus a compatibility-tested bounded window; without a proven ordering/window algorithm or an activity endpoint, the result remains `operator_resolution_required`.

## Mutation protocol commands

```text
youtrack-agent-cli mutation prepare \
  --offline \
  --profile <name> \
  --kind <operation> \
  --project <immutable-ID:key> \
  --request-stdin \
  --expected-state <snapshot-or-hash> \
  --schema-sha256 <digest> \
  --out <plan.json>

youtrack-agent-cli mutation confirm \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation apply \
  --profile <name> \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation reconcile \
  --profile <name> \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation status \
  --plan-id <YTAP-ID>

youtrack-agent-cli mutation export \
  --plan-id <YTAP-ID> \
  --out <new-plan.json>
```

The implemented first slice enables only `prepare`, `export`, and `status`. `confirm`,
`apply`, and `reconcile` are present as stable fail-closed commands while Gate
1A and the executor compatibility gate remain open.

### `prepare --offline`

Guarantees zero DNS, socket, browser, or OAuth activity. It:

- loads only the non-secret profile and supplied snapshot/hash;
- validates operation schema and project allowlist;
- allocates `plan_id` and inserts it into the final audit marker/body before hashing;
- canonicalizes the request;
- calculates hashes;
- renders a human plan;
- chooses a reconciliation strategy;
- writes an unsigned plan.

It cannot claim that credentials, permissions, or current server state are valid.

### `confirm`

Launches a trusted approval UI that loads canonical plan bytes once and displays that immutable in-memory snapshot. Only after OS-verified user presence, the helper stores the displayed-byte SHA-256 in `plan_sha256` and signs the deterministic unsigned receipt that binds that digest to SHA-256 of the fresh IPC challenge, receipt ID, nonce, TTL, key identity, account, project, schema, request, and preconditions. It must not re-read a mutable plan file after display. A normal pseudo-terminal prompt is not sufficient when the agent host can inject input. The macOS MVP should bind the signing key to Keychain/Secure Enclave access control and LocalAuthentication, or use a genuinely out-of-band approval service. There is no `--yes`, environment override, piped stdin approval, or model-callable noninteractive mode. If no trustworthy presence adapter is available, `confirm` fails closed and guarded writes remain disabled.

### `apply`

Validates receipt signature/TTL/nonce, plan ID, payload/schema hashes, resolves the exact current target/project/account, checks the expected-state fingerprint, atomically marks the intent `in_flight`, sends at most one mutation request through the configured executor, and reconciles with reads.

### `reconcile`

Never mutates. It re-runs only the method-specific bounded evidence checks and records `reconciled` or `operator_resolution_required`.

## MVP operation kinds

### Stage A — recommended first release

| Kind | REST mutation | Preconditions | Reconciliation |
|---|---|---|---|
| `issue.create` | REST `POST /api/issues` or custom executor | Allowlisted project ID+key is part of payload; required fields resolved to IDs/types; schema hash; plan marker | Exact returned ID on normal success; on ambiguity, bounded project/author/time/marker/content-hash search |
| `issue.update` | REST `POST /api/issues/{issueID}` or custom executor | Exact issue; field/value IDs and schema hash; expected touched-state hashes | Exact issue read; compare touched fields and receipt/audit evidence; REST mode carries issue-move TOCTOU risk |
| `comment.add` | REST `POST /api/issues/{issueID}/comments` or custom executor | Exact issue; explicit visibility; plan marker | Exact comment ID on normal success; ambiguous REST result is conclusive only with a tested bounded retrieval algorithm |

The official API documents create/update issue and add-comment operations, explicit response `fields`, and per-operation permissions. See [Issues](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues.html), [Operations with Specific Issue](https://www.jetbrains.com/help/youtrack/devportal/operations-api-issues.html), and [Issue Comments](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues-issueID-comments.html).

### Stage B — after Stage A is proven

| Kind | Why deferred |
|---|---|
| `tags.change` | Bundle/name ambiguity and add/remove semantics need dedicated preconditions |
| `issues.link` | Link direction/type and duplicate-link reconciliation need focused tests |
| `work.log` | Time-zone, work type, attributes, and payroll/reporting impact |
| `assignee.change` | Can be represented through `issue.update`, but merits a clearer human plan |

### Not in the initial guarded-write MVP

- Article create/update.
- Attachment upload/delete.
- Issue/comment delete.
- Project/user/group administration.
- Arbitrary workflow commands.
- Silent notification suppression.
- Bulk mutations.

## Request schemas

Illustrative schema shapes, not implementation code:

```json
{
  "kind": "issue.update",
  "profile": "youtrack_acme_alice_write",
  "issue": "APP-123",
  "project": { "id": "0-12", "key": "APP" },
  "set": {
    "summary": "New summary",
    "customFields": [
      {
        "fieldId": "92-3",
        "displayName": "State",
        "type": "StateIssueCustomField",
        "valueId": "69-2",
        "displayValue": "In Progress"
      }
    ]
  },
  "expected": {
    "summarySha256": "...",
    "customFieldsSha256": "...",
    "schemaSha256": "..."
  },
  "planId": "YTAP-...",
  "notifications": "normal"
}
```

Visibility is explicit for create/comment operations. Omission means the CLI refuses when the operation could accidentally broaden visibility; it does not infer visibility from surrounding chat or issue text.

## Receipt marker policy

Reliable create/comment reconciliation benefits from a stable marker. Recommended order:

1. Dedicated organization-configured custom field or app-owned property, if available later.
2. A short visible audit footer such as `Agent plan: YTAP-<plan_id>` when the operator approves this policy.
3. Marker-free matching only when explicitly configured, with the understanding that an ambiguous timeout may require manual inspection and cannot be safely retried.

`plan_id` is allocated during offline prepare, so the marker is already in the canonical body shown to the human and covered by the receipt signature. Do not add or change a marker after confirmation. Do not assume Markdown comments are invisible or preserved in a canonical form without an instance compatibility test.

## One-shot and reconciliation rules

- Preflight GETs and postflight GETs are allowed; “one-shot” means exactly one mutating request.
- A definitive HTTP validation/auth/policy failure before server acceptance is `failed-before-mutation`.
- A success response containing the created/updated entity is followed by exact verification.
- Timeout, connection reset, invalid/truncated response, proxy 5xx after send, or process crash after `in_flight` is `ambiguous`.
- The CLI never resends the mutation for the same receipt.
- A unique reconciliation match changes state to `reconciled`.
- Zero or multiple plausible matches after an ambiguous result is `operator_resolution_required`; it is not automatically considered failure.

## Versioned machine response

```json
{
  "schemaVersion": 1,
  "profile": "youtrack_acme_alice_write",
  "instance": "https://acme.youtrack.cloud",
  "account": { "id": "1-2", "login": "alice" },
  "receiptId": "YTAR-...",
  "operation": "issue.update",
  "target": "APP-123",
  "mutationAttempts": 1,
  "state": "reconciled",
  "evidence": { "issueId": "APP-123", "touchedFieldsMatch": true }
}
```

Error responses use the same envelope and never include authorization headers, OAuth codes/verifiers, tokens, full request bodies, or full untrusted server responses.

## Deferred custom MCP equivalent

If a YouTrack app executor is approved, its smallest coherent surface would be:

```text
<prefix>_get_write_policy          # read-only
<prefix>_preview_mutation          # read-only server validation, not the offline dry-run
<prefix>_apply_confirmed_mutation  # verifies an externally minted receipt, then one mutation
<prefix>_reconcile_mutation        # read-only
```

This does not replace the local/offline planner or human approval channel: a server-side preview is already a network operation, and a model-accessible pair of “preview then apply” tools does not prove human confirmation. The custom app becomes the strict executor only if it verifies the same external receipt/schema hashes, checks the issue's current project, consumes the nonce, and applies the mutation in one YouTrack transaction. JetBrains documents transaction atomicity for requests that apply issue changes; verifying this behavior for a custom MCP action is an implementation compatibility gate, not an assumption. See [Transactions](https://www.jetbrains.com/help/youtrack/devportal/workflow-transactions.html).
