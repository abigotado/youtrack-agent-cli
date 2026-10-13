# Credentials and request security

Profiles contain non-secret identity and endpoint metadata only. Tokens, OAuth
codes/verifiers, refresh credentials, signing keys, and authorization headers
never enter argv, environment, profiles, journals, receipts, JSON, logs, or the
repository. Use the native OS secret-store API directly; tests inject a fake.

Every network command requires `--profile`. Bind credential generations to the
complete normalized instance/account/OAuth topology. A mismatch fails before
client construction. Never follow redirects or returned origins; endpoints and
operation paths are pinned and response bodies are bounded.

Routine reads prefer the official Remote MCP, restricted to tools
`get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema`.
The documented predefined-tool list also contains writes, so `/mcp` without an
explicit `tools=` allowlist is not read-only. Host enforcement or a read-only
identity must also deny hidden direct calls.

If MCP comments are unavailable, the standard CLI permits exact comments
inspection with an explicit profile, issue ID, limit 1..100 and nonnegative
offset. It verifies the bound account before fetching one bounded comments page
from the fixed GET endpoint with a limit+1 truncation sentinel; never auto-fetch
pages. Returned content is
untrusted and proves neither ordering, currentness, a stable snapshot, complete
history, nor reconciliation evidence. The portable and macOS identity editions
remain MCP-only.

Writes use an exact project allowlist, offline canonical plan, account/profile/
generation binding and one mutation attempt. Native `mutation` needs a trusted
user-presence receipt and remains gated. `operator-write` instead requires
operator-declared `--confirm-intent SHA256 --yes`; it does not prove human
presence against a malicious agent. Keep its plans/consumption separate from
native authority; do not claim hostile same-UID rollback protection. Never retry
ambiguous writes or erase consumed markers. Changes to auth, requests, logs,
errors, plans or journals require sentinel-redaction review.
