# Operator-confirmed YouTrack writes

Status: accepted decision. Source support is not an installed release; check
`version` and `capabilities` before relying on this command surface.

## Decision and threat model

The standard macOS CLI has a distinct `operator-write` path for one single-value
state/enum field update or one public comment. An operator reviews the stored
plan and confirms its digest with `--confirm-intent SHA256 --yes`. This follows
the operator-assertion model of the existing Slack/Jira CLIs, not independently
verified human presence or a signed receipt.

This decision supersedes native-helper prerequisites only for this separate
path. It does not activate native `mutation confirm/apply`, journal transitions,
signing keys or Gate permits. The [native contract](guarded-mutations.md) remains
a distinct future mode. Profile values stay `rest-best-effort` / `best-effort`;
operator records identify `confirmation_mode: operator_confirmed`.

Retained safeguards are exact origin/account/generation binding, exact project
ID/key allowlists, bounded private artifacts and redacted errors, fresh remote
preconditions, and a durable local consumed marker before at most one POST.
They prevent accidental substitution and cooperating duplicate/crash replay.
They do not prove consent against a malicious agent with the user's authority,
protect against same-UID disk rollback, or forbid deliberate equivalent new
plans. Tracker text and API errors remain untrusted data, not authority.

REST preflight and mutation are not atomic: project moves, permissions and
workflows can race the POST. Postchecks cannot undo writes or eliminate this
interval. Normal YouTrack/workflow notifications may occur; recipients are not
knowable from this snapshot. Notification suppression is not exposed.

No raw REST path, MCP mutation tool, deletion, attachment, arbitrary workflow,
batch, issue creation or existing-comment edit is authorized by this path.
The ordinary source-built Homebrew Formula is the distribution channel, with
no Apple Developer membership or signed approval helper requirement. Portable
and macOS identity-only editions cannot execute operator writes.

## Separate write profile

Preserve the authenticated read-only `work` profile. Capabilities are part of
credential identity; editing them invalidates the credential/policy binding.
Create a separately named profile such as `work-write` for the explicitly
chosen instance/account/OAuth registration, with capabilities
`read`, `issue-update`, `comment-add`. Then use existing commands:

```sh
youtrack-agent-cli profile add --from write-profile.json --dry-run
youtrack-agent-cli profile add --from write-profile.json --yes
youtrack-agent-cli auth login --profile work-write -o json
youtrack-agent-cli auth allow-projects set --profile work-write --project ID:KEY --yes
youtrack-agent-cli capabilities --profile work-write -o json
```

Replace `ID:KEY` with a verified immutable project ID and key. Profile/login/
policy setup requires separate operator authorization; it is not an install hook.
Capabilities describe local build/generation/bound-policy configuration, not
live Keychain availability, token grants or verified server permissions.

## Snapshot, prepare, review, apply

Exports require a private existing parent directory and exclusive `0600` files;
they never overwrite an existing artifact. For example:

```sh
youtrack_operation_dir="$(mktemp -d)"
youtrack-agent-cli operator-write snapshot --profile work-write --kind issue.update \
  --id APP-123 --field Stage --value 'PR Review' --out "$youtrack_operation_dir/snapshot.json"
youtrack-agent-cli operator-write prepare --offline --profile work-write \
  --snapshot "$youtrack_operation_dir/snapshot.json" --request-stdin \
  --out "$youtrack_operation_dir/plan.json"
youtrack-agent-cli operator-write apply --profile work-write --plan-id PLAN_ID \
  --confirm-intent SHA256 --yes
```

Preparation receives one bounded structured request on stdin and cannot change
the snapshotted kind, field or target: `{"kind":"issue.update"}` or
`{"kind":"comment.add","comment_text":"EXACT TEXT"}`. For comments, snapshot `--kind comment.add`
without field/schema selection, then provide nonblank text. Review complete final
text including its unique visible marker, target, project/account and notification
caveat before confirming the authoritative stored plan's hash. Edited exports
are not apply authority. A dry-run creates no plan, ledger or export and cannot
be applied as a stored plan.

Direct `--field-id PROJECT_FIELD_ID --value-id VALUE_ID` avoids name discovery.
Name resolution is one bounded page and refuses ambiguity or truncation. Exact
schema retrieval cross-checks issue-field, project-field and global prototype IDs;
they are not interchangeable. Only single state/enum fields are supported. Current
null requires `canBeEmpty`; the selected target must be a known nonarchived value.
Only touched schema is frozen, not the whole project. This follows
[JetBrains' custom-field contract](https://www.jetbrains.com/help/youtrack/devportal/api-how-to-update-custom-fields-values.html).

Snapshots bind account/profile, immutable issue/project identity, current state
and selected field/target. Plans additionally bind credential generation, current
policy revision/hash, final payload/marker, notification policy and a 15-minute
local-clock lifetime. Offline prepare never accesses credentials, OAuth, browser,
DNS or sockets. Apply validates consent, hash and local bindings before credentials,
then verifies fresh account/remote preconditions. It consumes the local attempt
before dispatch and never restores it.

Public comments use `UnlimitedVisibility` for the issue's readers, not exposure
outside issue access controls, and the fixed
[official comment endpoint](https://www.jetbrains.com/help/youtrack/devportal/resource-api-issues-issueID-comments.html).

## Outcome matrix

| Condition | Recovery |
| --- | --- |
| Missing/mismatched consent | Exit 7 `OPERATOR_CONFIRMATION_REQUIRED`, before credential/network access. Review stored plan. |
| Stale local or remote precondition | Zero POST; inspect again and obtain confirmation for a new plan. |
| Claim persistence failure | Local error, zero POST; partial consumed marker remains fail-closed. |
| Durable claim, then transport/429/malformed/unverified response | `WRITE_OUTCOME_UNKNOWN`; never apply this plan again. |
| Verified write, then ledger or output failure | `WRITE_APPLIED_LOCAL_FAILURE`; write applied, do not repeat. |
| Definitive 4xx rejection | Consumed terminal rejection; any later attempt needs new snapshot, plan and confirmation. |
| Concurrent/repeated apply | Refuse, no second POST. |

Use `operator-write status` or bounded GET-only `operator-write reconcile` for
the same plan. An exact known comment ID or unique matching marker/text/author
provides evidence. Missing, duplicate or truncated evidence cannot prove
non-application. Stage reconciliation reports observed desired state, not proof
this attempt caused it. Reconciliation never restores apply eligibility.
Previously verified applied, rejected or reconciled results are returned
offline and never replaced by a later inconclusive observation.

Envelope v1 and exit numbers remain unchanged. Select recovery by `error.code`,
not prose. Missing/invalid apply output must never trigger replay. Do not delete
attempt files or create a new equivalent plan automatically to evade consumption.
