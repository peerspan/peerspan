# Capabilities slice 3: resource bounds and the `gh` source

Status: **Proposed — owner decisions pending.** Nothing here is settled until the owner decides the items under [Owner decisions needed](#owner-decisions-needed). The design is the recommendation; each open choice is listed there with its alternatives.

This is item D of roadmap milestone 10, slice 3. The other items of the slice are designed separately: (A) remote MCP servers and OAuth, (B) approval of each call, and (C) sharing with one agent. [Interactions](#interactions-with-a-b-and-c) lists where they touch this one.

It builds on the [capabilities contract](capabilities-contract.md) (slices 1 and 2), [credentials for shared tools](tool-credentials.md), and the CLI experience (`docs-internal`, `docs/cli-spec.md`). Where this proposal says "today", it means that contract as implemented at `84a36d0`.

## Summary

- **Bounds are per capability, set at `capability create`, and stored only on the serving host.** They never go into policy v2, so the policy format, its test vector, and coordinators are unchanged, and repository names never reach coordination.
- **A bound is a list of allowed argument values.** `--bound repo=acme/api` lets a call through only when its `repo` argument is `acme/api`. Several `--bound` flags are alternatives. One flag can pin several arguments together (`--bound owner=acme,repo=api`).
- **The receiving host enforces it**, at submission and again before start, by checking the call's input. A call outside the bound is refused with 403 `out_of_bounds` and never runs.
- **Peerspan only bounds what it can check.** Every selected operation must declare each bound argument in its input schema, or `capability create` refuses. The review lists, per operation, the other arguments Peerspan does not check, and still states the credential's full reach.
- **`gh` is the first non-MCP source.** Peerspan ships a fixed set of GitHub operations (issues, pull requests, repository, checks) backed by the GitHub CLI. Each takes a required `repo`, so a repository bound covers every `gh` operation completely.
- **The `gh` adapter is a built-in MCP server inside the `peerspan` binary.** The daemon starts it as it starts any stdio source, so instances, calls, cancellation, records, and logs work unchanged. It runs `gh` with an argument vector, never a shell, with `--json` output, time and size limits, and an empty working directory.
- **The `gh` token is captured at discovery**, as `${VAR}` values are today, and its reach (account, host, token type, scopes) is stated in `sources`, the review, and `shares`.

## Part 1: resource bounds

### What a bound is

A bound restricts the values of named top-level arguments of a capability's tool operations. It is stored in the capability record's `bounds` field, which slice 1 reserved and always set to `{}`.

```json
"bounds": {
  "arguments": [
    {"repo": "acme/api"},
    {"repo": "acme/web"}
  ]
}
```

- **`arguments`** is a list of 1 to 16 **combinations**. Each combination maps 1 to 4 argument names to one string value each.
- **A call passes** when, for at least one combination, every argument it names is present at the top level of the call's `input`, is a string, and matches that value.
- **Matching** is exact byte equality, except where the source type defines a matcher for an argument name. The `gh` source defines one for `repo` ([below](#bounds-on-gh)).
- **`{}`** still means no bound. A record without `bounds` reads as `{}`.
- **Argument names** match `[A-Za-z_][A-Za-z0-9_]{0,63}`. Values are 1 to 256 bytes of UTF-8 without control characters.
- **Combinations, not independent lists.** The GitHub MCP server names a repository with two arguments, `owner` and `repo`. Two flags `--bound owner=acme,repo=api --bound owner=beta,repo=web` allow `acme/api` and `beta/web`, but not `acme/web`. Independent value lists for `owner` and `repo` would allow it.
- **Resources are not bounded by arguments.** The `read` operation is already bounded by the capability's selected `resources`. A bound applies to tool operations only, and the review says so when `--resources all` is combined with a bound.

### Where it is set

| CLI | Change |
| --- | --- |
| `capability create NAME --from SOURCE … [--bound KEY=VALUE[,KEY=VALUE…]]…` | `--bound` may repeat; each one is a combination. `POST /v1/capabilities` gains `bounds`, absent or `{arguments: [...]}`. |
| guided `share --with PRINCIPAL [… --bound …]` | At a terminal, after operations and resources, it asks `Limit which repositories? Enter OWNER/REPO, several separated by spaces, or leave empty for no limit: ` for a `gh` source, and `Limit by argument values? Enter KEY=VALUE[,KEY=VALUE] combinations separated by spaces, or leave empty for no limit: ` for an MCP source. Without a terminal, `--bound` is a flag like the others. |

- **Checks at create.** Each operation in `operations` must declare every argument named in any combination as a top-level property of type `string` in its snapshot input schema. Otherwise 400 with code `bound_unenforceable` and the text `Operation OPERATION has no string argument KEY, so Peerspan cannot check this bound for it. Leave the operation out, or narrow the credential instead (--env-file).`
- **A required argument is not needed.** A call that omits a bound argument does not match, so it is refused. Peerspan never fills in a value ([decision 6](#owner-decisions-needed)).
- **Records stay immutable.** As today, an identical repeat of `capability create` returns 200 and a different record under the same name returns 409. Changing a bound means `capability remove` and `capability create` again ([decision 13](#owner-decisions-needed)).
- **One capability per scope.** To give Alice `acme/api` and Bob `acme/web`, the owner creates two capabilities. Bounds do not vary by recipient ([decision 1](#owner-decisions-needed)).

### Enforcement

Authorization step 2, [The capability](capabilities-contract.md#authorization), gains a final check: when the capability has a bound and the operation is not `read`, the input must pass it. Otherwise the receiver answers:

```
403 {"code": "out_of_bounds", "error": TEXT, "bounds": {"arguments": [...]}}
```

- **TEXT**, exactly: `This capability is limited to calls where ALLOWED. The call has GOT. Nothing was run.`
  - `ALLOWED` lists the combinations joined by ` or `, each as `KEY is VALUE` joined by ` and `: `repo is acme/api or repo is acme/web`.
  - `GOT` lists the bound argument names in the order of the first combination, each as `KEY "VALUE"`, or `no KEY` when absent, or `a non-string KEY`: `repo "acme/infra"`.
- **Final.** 403 is already a final `rejected` submission outcome for `call`, and a refusal that persisted nothing for agent tools, so the call never runs and the agent sees the "never ran" note.
- **Recheck before start.** The recheck repeats it, so a capability removed and recreated with a narrower bound while a call is queued rejects that call with `authorization lapsed before start`.
- **Sources for the person's own machines** have no bounds. The implicit capability `AGENT/SERVER` is unchanged.
- **Budget.** Refused calls are not counted, as for every refusal before acceptance.

### What bounds cannot do

A bound checks only the arguments it names. The review and `shares` say this plainly rather than implying more:
- **Free-form arguments.** A tool that takes SQL, a search query, a URL, a GraphQL document, or a shell command can reach other resources through that argument. Peerspan does not parse it. The GitHub MCP server's `search_issues`, for example, takes `query`, and `repo:other/repo` inside it is not checked.
- **Tools without the argument** cannot be selected under a bound at all (the 400 above).
- **Unchecked arguments are listed.** For each selected operation, the review lists its other top-level string properties, and any property of another type, as `not checked by Peerspan`. This is mechanical, from the schema, with no guessing about which names are dangerous.
- **Names, not identities.** A bound names a repository by name. If `acme/api` is deleted and a different repository is later created with that name, the bound covers the new one.
- **The server's own behavior.** A tool may ignore the argument or follow redirects. Only the provider enforces a narrower credential, which remains the way to bound free-form tools ([tool credentials](tool-credentials.md#narrowing-what-a-credential-can-reach), option 1). A capability can have both.

### How it is shown

**The review**, printed by `share` before confirmation, gains a bounds block after the resources, and a revised reach statement. For a `gh` capability with a bound:

```
Bounds:    repo is acme/api
           Every gh operation names its repository in repo, so Peerspan checks every call.
Reach:     alice can use these operations only where repo is acme/api; Peerspan refuses
           other calls. The credential reaches more: the gh account bob on github.com
           (token scopes: repo, read:org, workflow) can read and change every repository
           bob can.
```

For an MCP capability with a bound:

```
Bounds:    owner is acme and repo is api
           Not checked by Peerspan: search_issues: query, sort; list_issues: labels, state.
Reach:     alice can use these operations only where owner is acme and repo is api;
           Peerspan refuses other calls. Arguments Peerspan does not check can still reach
           anything the credentials they run with on this host can reach.
```

Without a bound, the reach statement is today's, followed by `No resource bound.` For a `gh` source the credential sentence is the [stated reach](#credential-reach) instead of the generic one.

- **`shares`** shows each capability's bounds and reach line, in text and as `bounds` and `reach` in `--json`.
- **`capability list` and `show`** show `bounds` from the record, no longer always `{}`.
- **`discover`, `GET /peer/v1/capabilities`, and `list_capabilities`** gain `bounds` on each entry: `{}` or the record's `bounds`. Recipients see the allowed values, which travel only on the peer path to principals already authorized ([decision 4](#owner-decisions-needed)).
- **Input schemas in listings** are narrowed to match, so callers and agents fill arguments correctly. When every combination names the same single argument and no value uses a source matcher's wildcard, that property becomes `{"type": "string", "enum": [VALUES]}`; otherwise its description gains `Limited by the owner: ALLOWED.` The snapshot itself is unchanged.

## Part 2: the `gh` source

### What changes in the source model

Today a source is an MCP server from an attached agent's harness configuration, addressed `AGENT/SERVER`. This slice adds **built-in sources**: adapters Peerspan ships and detects on the host, not tied to any agent.

- **Address.** A built-in source is addressed `builtin/NAME`, for example `builtin/gh`. `builtin` is reserved in the agent position: `attach --name builtin` is refused with exit 1 from this slice on ([decision 8](#owner-decisions-needed)). On a host where an agent named `builtin` already exists with an MCP server of the same name as an adapter, the adapter source is listed with `shareable: false` and reason `name`.
- **Raw-source addresses** follow: `PERSON/builtin/gh` or `HOST_ID/builtin/gh` for the person's own trusted machines that the host is open to. Nothing else about raw sources changes.
- **The capability record** keeps `source: {agent, server}`, with `agent` `builtin` and `server` the adapter source name, so every path keyed by agent and server keeps working. `--from gh` resolves when exactly one source named `gh` exists, as today.
- **The general mechanism is internal.** Each binary has a small registry of built-in adapters, each with: a source name scheme, detection run in the CLI, a fixed tool list, an executor, an optional reach check, and optional argument matchers for bounds. Slice 3 registers only `gh`. Third-party adapters are not a plugin mechanism: anyone can already ship an MCP server, which is a source today ([decision 16](#owner-decisions-needed)).

### Discovery

Built-in discovery runs in the CLI, where the user's `PATH` and `gh` login are, at every `attach` and at `sources refresh` without `--agent`. `sources refresh --builtin` runs only built-in discovery. The CLI sends the result with a new local route:

| CLI | Local API | Behavior |
| --- | --- | --- |
| (from `attach` and `sources refresh`) | `PUT /v1/builtin-sources` with `{sources, values}` | Replaces the built-in source definitions and values in one transaction, then snapshots each shareable one, as the agent route does. `values` maps `NAME` to `{"env.GH_TOKEN": TOKEN}`. |
| `sources [--json]` | `GET /v1/sources` | The response gains `builtin: [SERVER]` beside `agents`, each `SERVER` as today plus `adapter`, `account`, `host`, and `reach`. |

**Steps, for `gh`:**
1. **Find it.** Look up `gh` on the CLI's `PATH`. If it is absent, nothing is listed, and `sources` prints one hint line: `GitHub CLI (gh) not found on PATH; install gh 2.81.0 or later and run peerspan sources refresh to use it as a source.`
2. **Version.** Run `gh --version` and parse `gh version X.Y.Z`. Below 2.81.0, the first release with `gh auth status --json` ([cli/cli#11544](https://github.com/cli/cli/pull/11544), released in [v2.81.0](https://github.com/cli/cli/releases/tag/v2.81.0)), the source is listed with `shareable: false` and reason `version` ([decision 14](#owner-decisions-needed)).
3. **Accounts.** Run `gh auth status --json hosts`. Its output is `{"hosts": {HOST: [{state, active, host, login, tokenSource, gitProtocol}]}}`; with `--json` it exits 0 even when an account has problems (`gh auth status --help`). Only `github.com` accounts are used in this slice ([decision 9](#owner-decisions-needed)).
4. **One source per account.** The active `github.com` account is source `gh`. Each other `github.com` account is `gh-LOGIN`, with `LOGIN` lowercased and characters outside the server-name pattern replaced by `-`. An account whose `state` is not `success` is listed with `shareable: false` and reason `not_authenticated`.
5. **Capture the token.** For each shareable account, run `gh auth token --hostname github.com --user LOGIN`. The token goes only into `values`, which the daemon stores in `tool_values` as today ([decision 10](#owner-decisions-needed)).
6. **Record the executable.** The definition stores the absolute path of `gh` found in step 1, because the daemon's `PATH` may differ.

The CLI runs each command with a 10-second timeout, `GH_PROMPT_DISABLED=1`, and `GH_NO_UPDATE_NOTIFIER=1`, and never logs its output. A `GH_TOKEN` or `GITHUB_TOKEN` in the CLI's environment makes `gh` report that token as an extra account with `tokenSource` `GH_TOKEN`; such an entry is ignored, because it lives only in that shell.

**The definition** sent in `sources`:

```json
{
  "name": "gh",
  "adapter": "gh",
  "command": "/usr/bin/gh",
  "version": "2.102.0",
  "host": "github.com",
  "account": "bob",
  "env": {"GH_TOKEN": {"source": "captured"}},
  "disabled": false
}
```

Reasons for `shareable: false`, in precedence order: `name`, `version`, `not_authenticated`, `missing_env` (no token captured).

### Snapshot and credential reach

**Snapshot.** The daemon snapshots a built-in source exactly as an MCP source: it starts the built-in server, sends `initialize`, and calls `tools/list`. The tool list is fixed by the Peerspan release, so it always matches the [operation set](#operations). Snapshot failures and `snapshot_error` behave as today.

**Reach.** During the same snapshot, the daemon runs, with the instance's environment, `gh api --include --hostname github.com user`:
- the login from the body;
- the token type from the token's prefix: `gho_` (OAuth, as `gh auth login` creates), `ghp_` (classic personal token), `github_pat_` (fine-grained personal token), `ghu_` or `ghs_` (GitHub App);
- the scopes from the `X-OAuth-Scopes` response header, which GitHub sends for OAuth and classic tokens and not for fine-grained ones.

It stores `reach: {account, host, token_type, scopes, checked_at, error}`, never the token. A capability with its own credential (`--env-file` with a `GH_TOKEN` line) gets its own reach from its own snapshot.

<a id="credential-reach"></a>**The reach sentence**, used in `sources`, the review, and `shares`:

| Token | Sentence |
| --- | --- |
| scopes include `repo` | `The gh account LOGIN on HOST (token scopes: SCOPES) can read and change every repository LOGIN can, public and private.` |
| scopes include `public_repo` but not `repo` | `The gh account LOGIN on HOST (token scopes: SCOPES) can read public repositories and change public repositories LOGIN can.` |
| OAuth or classic, neither scope | `The gh account LOGIN on HOST (token scopes: SCOPES or none) can read public repositories only.` |
| fine-grained, App, or unknown type | `The gh account LOGIN on HOST uses a token that states no scopes, so Peerspan cannot tell which repositories it reaches. Assume every repository it was granted.` |
| the check failed | `Peerspan could not check the reach of the gh account LOGIN on HOST (ERROR). Assume everything the account can reach.` |

This meets the CLI experience's requirement that reach be stated accurately, and that output say so when it cannot be determined rather than claim a narrower scope.

### Operations

The `gh` adapter defines these operations. Names follow the `gh` command (`gh issue list` becomes `issue_list`; [decision 11](#owner-decisions-needed)). Every operation requires `repo`.

| Operation | Marks | `gh` command (argv, no shell) | Result |
| --- | --- | --- | --- |
| `issue_list` | read-only | `issue list --repo=R --state=S --limit=N [--label=L]… [--assignee=A] [--author=A] [--milestone=M] --json=F` | `{issues: [...]}` |
| `issue_view` | read-only | `issue view N --repo=R [--comments] --json=F` | `{issue: {...}}` |
| `pr_list` | read-only | `pr list --repo=R --state=S --limit=N [--base=B] [--head=H] [--label=L]… [--author=A] [--draft] --json=F` | `{pull_requests: [...]}` |
| `pr_view` | read-only | `pr view N --repo=R [--comments] --json=F` | `{pull_request: {...}}` |
| `pr_diff` | read-only | `pr diff N --repo=R --color=never [--name-only]` | `{diff: TEXT}` or `{files: [PATH, ...]}` |
| `pr_checks` | read-only | `pr checks N --repo=R --json=F` | `{checks: [...]}` |
| `repo_view` | read-only | `repo view R --json=F` | `{repository: {...}}` |
| `issue_create` | can change things | `issue create --repo=R --title=T --body-file=- [--label=L]… [--assignee=A]…` | `{url, number}` |
| `issue_comment` | can change things | `issue comment N --repo=R --body-file=-` | `{url}` |
| `pr_comment` | can change things | `pr comment N --repo=R --body-file=-` | `{url}` |

**JSON fields `F`**, fixed per operation (all valid in gh 2.81.0 and later, from each command's `JSON FIELDS` help):
- `issue_list`: `number,title,state,author,labels,assignees,milestone,createdAt,updatedAt,url`
- `issue_view`: `number,title,state,stateReason,body,author,labels,assignees,milestone,createdAt,updatedAt,closedAt,url`, plus `comments` with `comments: true`
- `pr_list`: `number,title,state,isDraft,author,baseRefName,headRefName,labels,createdAt,updatedAt,url`
- `pr_view`: `number,title,state,isDraft,body,author,baseRefName,headRefName,mergeable,reviewDecision,additions,deletions,changedFiles,files,labels,createdAt,updatedAt,mergedAt,url`, plus `comments,reviews` with `comments: true`
- `pr_checks`: `name,state,bucket,workflow,link,startedAt,completedAt`
- `repo_view`: `nameWithOwner,description,url,visibility,isArchived,defaultBranchRef,homepageUrl,primaryLanguage,stargazerCount,forkCount,pushedAt,updatedAt`

Callers cannot choose fields, so the result shape is fixed and documented, and `--jq` and `--template` are never passed.

**Input schemas**, each with `additionalProperties: false`:

| Property | Schema | Used by |
| --- | --- | --- |
| `repo` | string, pattern `^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`, not ending in `/.` or `/..`; required | all |
| `number` | integer, 1 to 2^31 − 1; required | `*_view`, `pr_diff`, `pr_checks`, `*_comment` |
| `state` | `issue_list`: enum `open`, `closed`, `all`; `pr_list`: enum `open`, `closed`, `merged`, `all`; default `open` | lists |
| `limit` | integer, 1 to 100, default 30 | lists |
| `label` | array of 0 to 10 strings | lists, `issue_create` |
| `assignee`, `author`, `milestone`, `base`, `head` | string | lists, as the table shows |
| `assignee` (create) | array of 0 to 10 strings | `issue_create` |
| `draft` | boolean | `pr_list` |
| `comments`, `name_only` | boolean, default false | views, `pr_diff` |
| `title` | string, 1 to 256 bytes; required | `issue_create` |
| `body` | string, 0 to 65,536 bytes; required for comments, optional for `issue_create` | writes |

Every string other than `body` is 1 to 256 bytes with no control characters. `repo` has no `HOST/` prefix, and `number` is only an integer: `gh issue view`, `pr view`, and `pr diff` also accept a URL or branch in that position, and a URL would name another repository than `--repo`.

**Annotations.** Read-only operations have `readOnlyHint: true`. Writes have `readOnlyHint: false`, `destructiveHint: false`, and `idempotentHint: false`. Unlike a third-party server's hints, these are Peerspan's own, so the `(can change things)` marks are accurate for this source.

**Left out of this slice**: free-form search (`--search` on lists, `gh search`), closing, editing, merging, reviewing, labels on existing items, workflow runs, releases, and `gh api`. `issue_list --search` is left out because GitHub search ORs repeated `repo:` qualifiers, so a query could escape a repository bound ([decision 12](#owner-decisions-needed)).

### Executing a call

The built-in server is the hidden subcommand `peerspan builtin-source gh`, started by the daemon from its own executable as a stdio MCP server. The definition's `command` path for `gh` is passed to it. For each `tools/call` it:
1. **Validates** the arguments against the operation's schema. A failure is a tool result with `isError: true` and the text `Invalid arguments for OPERATION: DETAIL`, and runs nothing.
2. **Builds argv** from the table. Every value is passed as `--flag=value`, so a value starting with `-` can never become a flag, and positional values are only decimal integers or the validated `repo`. Body text goes to standard input through `--body-file=-`, never argv.
3. **Runs** `gh` directly (`exec`, no shell) with:
   - working directory `STATE/builtin/gh/work`, empty and mode 0700, so `gh` never infers a repository from a git checkout;
   - environment only: `PATH` and `HOME` from the daemon; `GH_TOKEN` from the instance environment (stored value, then the environment file filtered to `GH_TOKEN`, then a capability's `env_file`, as for any source); `GH_HOST=github.com`; `GH_CONFIG_DIR=STATE/builtin/gh/config` (empty, 0700), so the user's aliases, extensions, and stored accounts are not used; `GH_PROMPT_DISABLED=1`, `GH_NO_UPDATE_NOTIFIER=1`, `GH_NO_EXTENSION_UPDATE_NOTIFIER=1`, `GH_SPINNER_DISABLED=1`, `NO_COLOR=1`, `GH_PAGER=cat`, and `GH_TELEMETRY=0` ([decision 15](#owner-decisions-needed)).
   - a timeout of 120 seconds, or the call's deadline if sooner;
   - standard output read up to 1,000,000 bytes, and standard error up to 64 KiB.
4. **Returns** a `CallToolResult` with one text item, the result object as JSON. List and view results wrap `gh`'s parsed JSON; `pr_diff` returns its text; writes parse the URL `gh` prints on standard output and take `number` from its last path segment.

**Errors.** Unless stated otherwise, each is an `isError: true` result, so the call is `failed` with `tool_error`, as for MCP:
- exit 4, which `gh` uses when authentication is required (`gh help exit-codes`): a **JSON-RPC error**, not a tool result, with code `-32001` and the message `gh is not authenticated for github.com. The owner runs gh auth login, then peerspan sources refresh.` The call is `failed` with `jsonrpc_error`. Today both daemons set `auth_error_at` only for JSON-RPC errors whose message matches the authentication pattern (`auth`, `401`, `403`, or `token`), and this message does, so status item 14 reports it with no daemon change. An `isError` tool result would not.
- exit 1: text `gh failed: STDERR`, with the last 2,048 bytes of standard error. Exit 1 from `pr_checks` with valid JSON on standard output, which `gh` uses when checks failed, is a success. So is exit 8, which `gh pr checks` documents as "checks pending".
- standard output over the limit: the process is killed, and the server answers with a JSON-RPC error with code `-32002` and the message `gh output exceeded 1000000 bytes.` Today a JSON-RPC error becomes `jsonrpc_error`; `result_too_large` comes only from the transport seeing an oversized response. So both daemons gain one rule: for a source whose `agent` is `builtin`, a JSON-RPC error with code `-32002` makes the call `failed` with `result_too_large`, and no result is stored, as for an oversized MCP result. This is the only change to the call runner. [Decision 12](#owner-decisions-needed) covers truncating diffs instead.
- timeout: the process is killed (`SIGTERM`, then `SIGKILL` after 2 seconds), and the text is `gh did not finish within N seconds.`
- output that does not parse: text `gh returned output Peerspan could not read.`

**Cancellation.** On `notifications/cancelled` the server kills that call's `gh` process the same way. The daemon already makes such a call `uncertain`, so a write that may have reached GitHub is never repeated.

**Concurrency, idle stop, logs, and records** are today's, since the daemon sees an ordinary stdio instance; the `-32002` rule above is the one addition. The server's standard error log is `STATE/tool-logs/builtin/gh.log`. It records each operation, its exit code, and timing, never arguments, bodies, results, or the token.

### Bounds on `gh`

`gh` defines a matcher for its `repo` argument:
- **Case-insensitive**, because GitHub owner and repository names are.
- **`OWNER/*`** matches every repository of `OWNER` ([decision 5](#owner-decisions-needed)). No other wildcard is accepted, and `--bound` refuses one with 400.
- **Host fixed.** The source's host is fixed by `GH_HOST`, and `repo` cannot carry a host, so a bound can only mean repositories on that host.

Because every `gh` operation requires `repo` and nothing else names a repository, a `repo` bound covers every operation completely, and the review says so. At `capability create`, the CLI runs `repo_view` on each exact bound repository with the capability's credential, and prints `warning: REPO is not visible to this credential` when it fails, without refusing ([decision 17](#owner-decisions-needed)).

Example:

```text
Bob$ peerspan capability create api-issues --from gh \
       --operations issue_list,issue_view,issue_comment --bound repo=acme/api
Bob$ peerspan share api-issues --with alice
Alice$ peerspan call bob/api-issues issue_list --repo acme/api
Alice$ peerspan call bob/api-issues issue_list --repo acme/infra
  rejected: This capability is limited to calls where repo is acme/api. The call has repo "acme/infra". Nothing was run.
```

## Storage and compatibility

- **Database version 19** adds `builtin_sources (name TEXT PRIMARY KEY, record TEXT NOT NULL)`. Values reuse `tool_values` with `agent_id` `builtin`; that table has no foreign key to `agents`. Capability records gain only the populated `bounds`. Items A and C may need schema changes too, so the slice should land one migration ([interactions](#interactions-with-a-b-and-c)).
- **Policy v2 is unchanged**, with no new lines and no new test vector, and coordinators need no upgrade.
- **Peer compatibility.** A caller older than this slice ignores `bounds` in listings and sees `out_of_bounds` as an ordinary 403. A receiver older than this slice has no bounds and no `builtin` sources, so nothing it serves changes.
- **`PUT /v1/agents/{id}/tool-servers`** is unchanged. Built-in sources use their own route.

## Interactions with A, B, and C

- **A, remote MCP servers and OAuth.** Remote sources are MCP sources, so argument bounds apply to them unchanged. An OAuth consent screen that lets the owner choose repositories is provider-enforced narrowing, like a narrower token, and its scopes should feed the same reach statement. A and D both add source kinds (`remote`, `builtin`) to the `sources` listing and `shareable` reasons, and both add tables, so their listing fields and migration should be agreed together.
- **B, approval of each call.** The bounds check should come before any approval request, so the owner is never asked about a call that would be refused anyway, and the approval prompt can show that the call is within the bound. The `gh` adapter's read-only marks are Peerspan's own, so a rule such as "approve only operations that can change things" is accurate for `gh`, unlike for third-party hints. Time waiting for approval counts against the same deadline as the `gh` process timeout.
- **C, sharing with one agent.** Bounds belong to the capability, so they apply equally to a person, group, or single-agent principal. An owner who wants a narrower bound for one agent creates a second capability. If C introduces local per-share settings, per-share bounds could later live there, but this proposal does not need them.

## Implementation size

Rough estimates of implementation code. Following the repository's testing policy, no unit or integration tests are budgeted by default; verification is the independent conformance and live acceptance work below.

| Part | Go | Rust |
| --- | --- | --- |
| Bounds: parse, store, check at submit and recheck, listing schema narrowing, review and `shares` text, guided prompts | ~450 lines | ~500 lines |
| Built-in source framework: CLI discovery, `PUT /v1/builtin-sources`, storage, addressing, `sources` output, migration | ~500 lines | ~550 lines |
| `gh` adapter: built-in MCP server, schemas, argv building, execution limits, errors, reach check | ~750 lines | ~800 lines |

- **Shared Node adapter:** the daemon adds `bounds` to each `GET /adapter/v1/capabilities` entry, and the adapter returns that object as it is. Only the `list_capabilities` description gains a sentence saying that `bounds` lists the allowed argument values (a few lines).
- **Conformance:** about 1,000 lines in `conformance/capabilities.py`, written by an independent author, using a fake `gh` script on `PATH` that records argv, environment variable names, working directory, and standard input, returns canned `--json` output, and can exit 1, 4, or 8, sleep, ignore signals, and print oversized output. It covers discovery and every reason, token capture appearing only in `tool_values`, each operation's argv and result, argument injection attempts (`-` prefixes, URLs as numbers, `HOST/` in `repo`), limits and timeouts, cancellation, bounds for `gh` and for the fixture MCP server (combinations, `bound_unenforceable`, `out_of_bounds` text, recheck, listings, review text), and migration from 18 to 19.
- **Live acceptance:** one run against a real test repository with a real `gh`, through all three harnesses, extending `conformance/live_capability_agents.py`: a bounded `gh` capability lists issues in the bound repository, and a call for another repository is refused with the `out_of_bounds` text.

## Owner decisions needed

1. **Where bounds live.**
   - Options: (a) per capability, set at create, local only; (b) per share, in a local table keyed by network, capability, and principal; (c) per share, in policy v2 as a new capability-rule line.
   - Recommendation: (a). It needs no policy change, keeps repository names away from coordination, and one capability per scope is easy to explain. (c) puts argument values in front of the coordinator and changes the format again.
2. **How MCP tools are bounded.**
   - Options: (a) generic argument combinations checked against the snapshot schema; (b) no MCP bounds in this slice, `gh` only; (c) Peerspan-shipped profiles for popular MCP servers, such as GitHub's `owner` and `repo`.
   - Recommendation: (a). It works for any server with structured arguments and is honest about what it checks. Profiles (c) can be added later as source matchers, but identifying which server a definition is takes guessing.
3. **Operations whose schema does not declare the bound argument.**
   - Options: (a) refuse at create with `bound_unenforceable`; (b) allow them and mark them unbounded in the review.
   - Recommendation: (a). A bounded capability with unbounded operations would be misread as bounded.
4. **Showing bounds to recipients.**
   - Options: (a) show `bounds` in `discover` and `list_capabilities`, and narrow input schemas; (b) hide them, so callers learn only from refusals.
   - Recommendation: (a). Callers and agents need the allowed values to make valid calls, and the values go only to authorized principals on the peer path.
5. **Wildcards in `gh` repository bounds.**
   - Options: (a) exact names plus `OWNER/*`; (b) exact names only; (c) general glob patterns.
   - Recommendation: (a). "Everything in our organization" is common, and `OWNER/*` is easy to state and check. General globs make the review harder to read.
6. **A call that omits a bound argument.**
   - Options: (a) refuse it with `out_of_bounds`; (b) fill in the value when the bound allows exactly one.
   - Recommendation: (a). Peerspan never changes a call's input, and the narrowed schema already tells callers what to send.
7. **How the `gh` adapter runs.**
   - Options: (a) a built-in stdio MCP server subcommand in each binary, run through the existing instance machinery; (b) a separate executor inside each daemon with its own call path; (c) one shared implementation in the Node adapter.
   - Recommendation: (a). Calls, cancellation, uncertainty, concurrency, and logs need no new code, apart from mapping one JSON-RPC error code to `result_too_large`. (c) would make sources depend on Node.
8. **The built-in source address.**
   - Options: (a) `builtin/NAME`, with `builtin` refused as a new agent name; (b) a separate address form, such as `@gh`, which every address parser must learn; (c) a bare `gh`, which collides with MCP servers named `gh`.
   - Recommendation: (a). It fits every existing parser and record that uses `AGENT/SERVER`.
9. **Which `gh` accounts become sources.**
   - Options: (a) every `github.com` account, `gh` for the active one and `gh-LOGIN` for others; (b) the active `github.com` account only; (c) every account on every host, including GitHub Enterprise.
   - Recommendation: (a). People with work and personal accounts need to pick one. Enterprise hosts need `GH_ENTERPRISE_TOKEN` and host-qualified names, so they can follow later.
10. **Where the `gh` token comes from at call time.**
    - Options: (a) captured at discovery with `gh auth token` and stored in `tool_values`; (b) `gh` reads the user's own store (keyring or `hosts.yml`) at call time.
    - Recommendation: (a). It matches the decision for `${VAR}` values, and works when the daemon cannot reach the desktop keyring. The cost is the same as today: after `gh auth refresh` or a new login, the owner runs `peerspan sources refresh`, and status item 14 says so.
11. **The operation set and names.**
    - Options: (a) the ten operations above, named after the `gh` command (`issue_list`); (b) read-only operations only in this slice; (c) a larger set including close, merge, review, and workflow runs.
    - Recommendation: (a). It covers the CLI experience's issue example and common pull-request reading, and three low-risk writes that the review marks. Merges and closes deserve per-call approval (B) first.
12. **Free-form search and large diffs.**
    - Options for search: (a) left out; (b) allowed, refusing queries with `repo:`, `org:`, `user:`, or `owner:` qualifiers. Options for diffs over 1,000,000 bytes: (a) fail with `result_too_large`; (b) truncate with `truncated: true` in the result.
    - Recommendation: (a) for both. Search filtering is easy to get wrong, and failing matches every other source; `name_only` gives a usable fallback.
13. **Changing a bound.**
    - Options: (a) remove and create again; (b) a new `capability update` that re-signs nothing but changes the record.
    - Recommendation: (a) for this slice. Records are immutable today, and an update command needs its own rules for running and queued calls.
14. **The minimum `gh` version.**
    - Options: (a) 2.81.0, for `gh auth status --json`; (b) an older version, parsing the text output of `gh auth status`.
    - Recommendation: (a). The text output is not a stable interface, and 2.81.0 is a year old.
15. **Telemetry when Peerspan runs `gh`.**
    - Options: (a) set `GH_TELEMETRY=0`; (b) leave `gh`'s default. The private `GH_CONFIG_DIR` means the user's own `gh` setting does not apply either way.
    - Recommendation: (a). Calls made for a peer should not report usage on the owner's behalf without being asked.
16. **How general the source-type mechanism is.**
    - Options: (a) an internal registry of built-in adapters, with `gh` the only one now; (b) a public plugin interface for third-party adapters.
    - Recommendation: (a). A third-party adapter can already be an MCP server, which is a source today. A plugin interface would add a second way to do the same thing.
17. **Checking `gh` bound repositories at create.**
    - Options: (a) warn when a bound repository is not visible to the credential; (b) refuse; (c) no check.
    - Recommendation: (a). A typo is caught early, but a repository the credential cannot see yet, or a network failure, does not block setup.
