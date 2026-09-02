# Profile contract

A profile selects exactly one normalized YouTrack origin, one expected account,
one OAuth issuer/end-point set, one credential generation, one executor mode,
and one exact project allowlist. Profile files contain no tokens, authorization
codes, PKCE verifiers, or refresh credentials.

Name the profile on every network command. If none was supplied, list only
non-secret profile labels and ask the user to choose; do not contact YouTrack.
Before presenting remote data, verify the current account and show the profile,
instance, and account together.

OAuth endpoints may be hosted by an external Hub. Pin and validate the service
origin, MCP/REST origins, issuer, authorization endpoint, and token endpoint as
separate values. Redirects, endpoint discovery, and returned URLs must never
move credentials to an unpinned origin.

Credentials belong in the OS secret store and never in chat, command arguments,
environment variables, profile files, logs, receipts, or repository files. Do
not inspect or print secret-store values.
