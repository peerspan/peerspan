# Remote MCP servers and OAuth (capabilities slice 3, item A)

Status: **Accepted on 2026-10-25.** The owner accepted every recommendation under [Owner decisions needed](#owner-decisions-needed), recorded as [decision 16](capabilities-contract.md#owner-decisions) in the capabilities contract. The recommended design below is the design for item A; it is not yet implemented, and its contract section is added when it is.

Milestone 10, slice 3 has four parts, proposed separately: (A) remote MCP servers and OAuth, this document; (B) approval of each call; (C) sharing with one agent; (D) optional resource bounds and non-MCP sources such as a `gh` adapter. This document builds on the [capabilities contract](capabilities-contract.md) (slices 1 and 2) and the [credentials analysis](tool-credentials.md#remote-servers-with-oauth). It does not change policy v2, the peer routes, or the agent tools.

## The problem today

- Discovery already finds URL-based servers: Claude Code `type: "http"` or `"sse"`, Codex `url`, OpenCode `type: "remote"`. They are normalized to `transport: "remote"` with `url`, and listed with `shareable: false` and reason `remote` (Go `sources_store.go`, Rust `sources.rs`).
- The daemon's MCP client speaks stdio only (Go `mcp_client.go`, Rust `mcp.rs`).
- Discovery drops the remote server's `headers`, so a server authenticated by a static token in a header loses its credential.
- A server that uses OAuth has its token in the harness's own store. The daemon cannot use it. Reading it was rejected in [tool credentials](tool-credentials.md#remote-servers-with-oauth): the storage is undocumented, and the token was issued to another application.
- The Rust host has no HTTPS client for the public web. Its TLS is pinned to peers and the coordinator (`peer.rs`). The Go host has `net/http` and the system roots.

## Goals

1. An owner can create and share a capability built on a remote MCP server, and callers use it exactly as a stdio capability: same peer routes, call states, agent tools, and records.
2. Three ways a remote server gets its credential, chosen per source:
   - **none**: a public server;
   - **headers**: static headers from the harness configuration, with `${VAR}` values captured at `attach` as `env` values are today;
   - **oauth**: Peerspan is its own OAuth client, signs in once per source, and keeps its own tokens in host state.
3. Works on a machine without a browser (a server reached over SSH).
4. Tokens never leave the host, never enter policy, listings, logs, activity, or anything sent to peers.

**Non-goals:** using the harness's stored tokens; a Peerspan-hosted OAuth broker that holds tokens; signing in to a provider on behalf of another person; MCP sampling, elicitation, or other server-to-client requests; streaming results.

## External facts this depends on

- **MCP authorization** (revision [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), unchanged in substance in [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration.md)):
  - Clients MUST use Protected Resource Metadata ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)) to find the authorization server: the `resource_metadata` parameter of a 401 `WWW-Authenticate` header, else `/.well-known/oauth-protected-resource/PATH`, then `/.well-known/oauth-protected-resource`.
  - Clients MUST support both RFC 8414 and OpenID Connect discovery for authorization server metadata, trying the listed well-known paths in order.
  - Clients MUST use PKCE with `S256`, and MUST refuse to proceed when the metadata has no `code_challenge_methods_supported`.
  - Clients MUST send the `resource` parameter ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)), the server's canonical URI, in both the authorization and token requests.
  - Tokens go only in `Authorization: Bearer`, never in the query string. Redirect URIs MUST be `localhost` or HTTPS. Clients SHOULD use and check `state`.
  - Registration, in priority order: pre-registered client; Client ID Metadata Documents (CIMD, a client ID that is an HTTPS URL of a JSON document) when the server advertises `client_id_metadata_document_supported`; Dynamic Client Registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591), DCR) when it advertises `registration_endpoint`; else ask the user. In 2026-07-28, DCR is marked deprecated in favor of CIMD but kept for compatibility, clients registering with DCR MUST send `application_type` (`native` for CLIs), and persisted client credentials MUST be keyed by the authorization server's `issuer` and not reused with another one.
  - Scope selection: the `scope` in the 401 challenge, else all of `scopes_supported` from the resource metadata, else none. A 403 `insufficient_scope` calls for step-up sign-in.
  - Authorization servers MUST rotate refresh tokens for public clients.
- **Transports** ([2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)): Streamable HTTP is one endpoint taking `POST` per JSON-RPC message, with `Accept: application/json, text/event-stream`. The answer is JSON or an SSE stream. A server may set `MCP-Session-Id` on the `initialize` response, which the client then sends on every request. A 404 on a session means start a new one. `DELETE` ends a session. The client sends `MCP-Protocol-Version` on later requests. The old HTTP+SSE transport (2024-11-05) is deprecated; a client detects it when `POST initialize` returns 400, 404, or 405, and then opens `GET` for an `endpoint` event. The [2026-07-28 revision](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) drops the connection-scoped `initialize` session and defines how clients fall back to servers of the initialization era.
- **Harness configuration of remote servers:**
  - Claude Code ([docs](https://code.claude.com/docs/en/mcp)): `type` (`http`, alias `streamable-http`; `sse` deprecated), `url`, `headers`, `headersHelper` (a shell command printing headers), and `oauth` with `clientId`, `callbackPort`, `authServerMetadataUrl`, `scopes`. The client secret is not in the file. `${VAR}` expands in `url` and `headers`.
  - Codex ([docs](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)): `url`, `bearer_token_env_var`, `http_headers`, `env_http_headers` (header to variable name), `scopes`, `oauth.callback_port`, and the global `mcp_oauth_callback_port`.
  - OpenCode ([docs](https://opencode.ai/docs/mcp-servers/)): `type: "remote"`, `url`, `headers`, `oauth` (`clientId`, `clientSecret`, `scope`) or `oauth: false`, with `{env:VAR}` substitution. Tokens go to `~/.local/share/opencode/mcp-auth.json`.
- **Providers** (third-party reports, October 2026; to be rechecked in live acceptance):

  | Provider | Endpoint | Registration | Static token |
  | --- | --- | --- | --- |
  | GitHub | `https://api.githubcopilot.com/mcp` | No DCR ([host integration guide](https://glama.ai/mcp/servers/@github/github-mcp-server/blob/bf6467855c13d3b8f5cf72f8dfd9c86f8336b20b/docs/host-integration.md), [Claude Code report](https://claudeissues.com/issue/3433-claude-code-cannot-connect-to-githubs-remote-mcp-server-using-oauth-authenticati)); a pre-registered OAuth app works | PAT as `Authorization: Bearer` header |
  | Linear | `https://mcp.linear.app/mcp` | DCR ([LiteLLM](https://docs.litellm.ai/docs/mcp_servers/linear)) | — |
  | Notion | `https://mcp.notion.com/mcp` | DCR, PKCE ([Notion guide](https://developers.notion.com/guides/mcp/build-mcp-client)) | — |
  | Atlassian | `https://mcp.atlassian.com/v1/mcp` | DCR; manually created apps reported refused ([Speakeasy](https://www.speakeasy.com/docs/ai-control-plane/guides/atlassian), [ROVO-870](https://jira.atlassian.com/browse/ROVO-870)) | API token, if an admin enables it ([Arcade](https://docs.arcade.dev/operate/governance/remote-mcp-servers/atlassian)) |
  | Sentry | `https://mcp.sentry.dev/mcp` | DCR ([Nango](https://nango.dev/docs/api-integrations/sentry-mcp)); a report suggests CIMD ([issue](https://claudeissues.com/issue/81643-sentry-mcp-oauth-fails-with-invalid-redirect-uri-cimd-client-id-flow-not-port-re)) | — |

  So DCR plus a pre-registered fallback plus static headers covers all five today. CIMD covers some and is where the specification is heading.

## Recommended design in one paragraph

Discovery keeps remote servers, now with their headers. The daemon gains a Streamable HTTP MCP client, used for snapshots and calls exactly where it uses stdio today. A source whose server answers `initialize` with a 401 Bearer challenge is listed as needing sign-in (reason `login`). The owner runs `peerspan sources login AGENT/SERVER` on the serving host. The daemon discovers the authorization server, registers Peerspan as a client (DCR, or a client ID the owner gives), and builds a PKCE authorization URL. The CLI opens it in a browser, or prints it on a headless machine, and receives the redirect on a loopback port, or has the owner paste the final URL. The daemon exchanges the code, stores the tokens in host state beside `tool_values`, snapshots the source, and refreshes the token as needed. Capabilities, sharing, calls, and agent tools are unchanged above the transport. `sources logout` deletes the tokens and revokes them where the provider supports it.

## Discovery changes

### Definition shape

A remote server definition adds `remote` and `headers`; `env`, `command`, and `args` stay empty for it.

```json
{
  "name": "linear",
  "transport": "remote",
  "command": null,
  "args": [],
  "env": {},
  "url": "https://mcp.linear.app/mcp",
  "remote": {"protocol": "http", "oauth": {"client_id": null, "scopes": null, "callback_port": null}},
  "headers": {"Authorization": {"source": "captured"}},
  "source": "claude-code:user"
}
```

- **`remote.protocol`** is `http` (Streamable HTTP) or `sse` (the deprecated HTTP+SSE), from Claude Code `type`. Codex and OpenCode give no type, so they read as `http`.
- **`remote.oauth`** holds only public hints from the harness: Claude Code `oauth.clientId`, `oauth.scopes`, `oauth.callbackPort`; Codex `scopes`, `oauth.callback_port`; OpenCode `oauth.clientId`, `oauth.scope`. An OpenCode `oauth: false` sets `remote.oauth` to null, and the source is never offered sign-in. Client secrets are never read from harness files (OpenCode `oauth.clientSecret` included); see `--client-secret-file` below.
- **`headers`** maps each header name to `{source}` exactly as `env` does: `literal`, `captured`, or `missing` with `variables`. Values go only in the `values` payload, as `headers.NAME`. A `url` containing a reference is resolved and sent as `values.url`.
- **Per harness:**
  - Claude Code: `headers`, with `${VAR}` and `${VAR:-D}` resolved as today. `headersHelper` is not run by discovery or the daemon; a server that has one is listed with `shareable: false` and reason `headers_helper` (see decision 9).
  - Codex: `http_headers` are literals; each `env_http_headers` entry and `bearer_token_env_var` (as `Authorization: Bearer VALUE`) is `captured` from the CLI's environment, or `missing` naming the variable.
  - OpenCode: `headers`, with `{env:VAR}` resolved the same way as `${VAR}`.
- **The environment file** applies to headers as it does to `env`: when a header value referenced `${NAME}`, a `NAME=` line in `$XDG_CONFIG_HOME/peerspan/env` overrides the captured value. The daemon records which variables each header used, as `headers.NAME.variables`, so it can substitute.

### Shareable and reasons

The reason `remote` is retired. Reasons, in precedence order, become: `name`, `disabled`, `insecure_url`, `sse`, `headers_helper`, `missing_env`, `login`.
- **`insecure_url`**: the URL is not `https`, and its host is not `localhost`, `127.0.0.1`, or `[::1]`.
- **`sse`**: `remote.protocol` is `sse`, while the deprecated transport is unsupported (decision 4).
- **`login`**: the server asked for OAuth sign-in and this host has no usable token for it (below). It is the only reason that `sources login` clears.

### How the daemon learns a server needs sign-in

At snapshot, the daemon sends `initialize` with the definition's headers and no token.
- **2xx:** auth mode `none` or `headers`, by whether there are headers. Snapshot as today.
- **401 with `WWW-Authenticate: Bearer`, and no `Authorization` header configured:** auth mode `oauth`. The daemon stores the challenge's `resource_metadata` and `scope`. Without a usable token, the source gets reason `login`, and the snapshot is skipped without a `snapshot_error`.
- **401 with an `Authorization` header configured:** `snapshot_error` `unauthorized`. The configured token is wrong or stale. The daemon does not start OAuth over a configured header.
- **Other failures:** `snapshot_error` as today, with the HTTP status in the message.

## Signing in

### Commands

| CLI | Local API | Behavior |
| --- | --- | --- |
| `sources login SOURCE [--scopes "A B"] [--client-id ID] [--client-secret-file PATH] [--port N] [--no-browser] [--account LABEL]` | `POST /v1/sources/{agent_id}/{server}/login`, then `POST /v1/oauth/logins/{login_id}/complete` | Signs Peerspan in to the source's server, as below. `SOURCE` is `AGENT/SERVER`, or `SERVER` when one agent has it. |
| `sources logout SOURCE [--yes]` | `POST /v1/sources/{agent_id}/{server}/logout` | Revokes and deletes this host's tokens for the source. When capabilities are built on it, it first lists them and asks (`y` at a terminal, or `--yes`), because their calls will fail with `auth_required` until the next login. Shares are kept. |
| `capability login NAME [same flags]` / `capability logout NAME` | the same routes with `{capability: NAME}` | Only if decision 6 adopts separate sign-ins per capability. |

The guided `share --with` runs the same sign-in inline at a terminal when the chosen source has reason `login`, before the review.

### The flow

1. **Start (daemon).** `POST …/login` with `{capability, scopes, client_id, client_secret, redirect_port, account}`. The daemon:
   1. sends `initialize` without a token to get the challenge, or reuses the stored one;
   2. fetches the protected resource metadata, picks the first entry of `authorization_servers`, and fetches its metadata, trying the RFC 8414 and OpenID Connect paths in the specification's order;
   3. refuses unless `code_challenge_methods_supported` contains `S256`;
   4. gets a client: the `--client-id` given; else a stored registration for this issuer; else the harness hint `remote.oauth.client_id`; else CIMD when supported and decision 2 enables it; else DCR at `registration_endpoint`; else refuses;
   5. creates `state` (32 random bytes, hex) and a PKCE verifier (32 random bytes, base64url), and builds the authorization URL with `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `resource` (the canonical URL: lowercase scheme and host, no fragment, no trailing `/`), and `scope` when chosen;
   6. keeps `{login_id, state, verifier, client, issuer, redirect_uri, scopes}` **in memory only**, for 10 minutes;
   7. returns `{login_id, authorization_url, redirect_uri, expires_at}`.
2. **Approve (person, browser).** The CLI starts a listener on `127.0.0.1:PORT` (the port from `redirect_uri`), then opens the URL with `xdg-open` or `open`. With `--no-browser`, or when it sees `SSH_CONNECTION`, or no `DISPLAY`/`WAYLAND_DISPLAY` on Linux, it prints the URL instead:

   ```text
   Open this link in a browser on any machine and approve Peerspan:
     https://mcp.linear.app/authorize?...
   If the browser then shows a page that cannot be reached, copy the full address
   from its address bar and paste it here:
   ```

   It waits for whichever comes first: a request to the listener, or a pasted line. The listener answers the browser with a short page saying the sign-in is complete and the tab can be closed.
3. **Finish (daemon).** The CLI posts `{callback_url}` to `…/complete`. The daemon checks `state`, reads `code` (or `error`), and posts the token request with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`, and `resource`. It stores the result (below), snapshots the source with the token, and returns the source object.
4. **Output.** `{source, issuer, scopes, account, expires_at, registration}`. The readable line names the provider's host and the granted scopes.

The PKCE verifier and the token never pass through the CLI. Only the redirect URL does, and its code is useless without the verifier.

### Registration details

- **Redirect URI.** `http://127.0.0.1:PORT/callback`. `PORT` is `--port`, else the harness `callback_port` hint, else a free port picked at first sign-in and stored with the registration, so later sign-ins reuse the registered URI. If that port is busy later, the CLI uses paste mode with the same URI: the browser's failed redirect still carries the code.
- **DCR request:** `{client_name, redirect_uris: [URI], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", application_type: "native"}`. A registration that returns a `client_secret` is kept and used as `client_secret_post` or `client_secret_basic`, as returned.
- **`client_name`.** Proposed `Peerspan (HOST_LABEL)`, so the provider's list of connected apps shows which machine holds the token (decision 3).
- **One registration per issuer per host**, reused by every source and capability using that issuer. A changed issuer for a source means a new registration, as the 2026-07-28 revision requires.
- **Pre-registered clients.** `--client-id` with an optional `--client-secret-file` (mode 0600 or stricter, read once, stored with the registration). This is the GitHub path when headers are not used.

### Refusal texts

| Case | Exit 1 with |
| --- | --- |
| Source not found | `No source SOURCE on this host. Run peerspan sources.` |
| Source has no OAuth challenge | `SOURCE did not ask for a sign-in, so there is nothing to sign in to.` |
| `remote.oauth` is null (OpenCode `oauth: false`) | `SOURCE has OAuth turned off in its harness configuration.` |
| No `S256` | `The authorization server for SOURCE (ISSUER) does not advertise PKCE, so Peerspan will not sign in to it.` |
| No way to register | `The authorization server for SOURCE (ISSUER) does not let Peerspan register itself. Register an OAuth app with the provider, with redirect URI http://127.0.0.1:PORT/callback, then run: peerspan sources login SOURCE --client-id ID [--client-secret-file PATH]` |
| `state` mismatch, or the 10 minutes passed | `This sign-in link is no longer valid. Run peerspan sources login SOURCE again.` |
| `error` in the redirect | `The provider refused the sign-in: ERROR (DESCRIPTION).` |
| Token request refused | `The provider refused to issue a token: ERROR (DESCRIPTION).` |
| No terminal and no `--no-browser` | `sources login needs a terminal, or --no-browser to print the link and read the pasted address from stdin.` |

## Tokens

### What is stored

Each sign-in is one **OAuth credential**, keyed by `(agent_id, server, capability)`, where `capability` is `""` for the source's own sign-in.

```json
{
  "issuer": "https://mcp.linear.app",
  "resource": "https://mcp.linear.app/mcp",
  "registration": "dcr",
  "client_key": "https://mcp.linear.app|127.0.0.1:53682",
  "access_token": "…",
  "refresh_token": "…",
  "token_type": "Bearer",
  "expires_at": "RFC3339 or null",
  "scope": "read write",
  "account": "owner@work (owner's label)",
  "obtained_at": "RFC3339",
  "refreshed_at": "RFC3339 or null",
  "state": "ok"
}
```

- `state` is `ok`, `refresh_failed` (the last refresh failed in a way that may recover, such as a network error), or `login_required` (refused with `invalid_grant`, revoked, or 401 after a refresh).
- Client registrations are stored separately, keyed by issuer and redirect URI: `{issuer, client_id, client_secret, registration_access_token, redirect_uri, method, created_at}`.
- `GET /v1/sources` and `capability show` gain `auth: {mode, state, issuer, scope, account, registration, obtained_at, expires_at}`. Secret fields never appear in any response, log, or activity.

### Storage at rest

Recommended: the same protection as `tool_values` today. Tokens live in the host database in the 0700 state directory, read by the daemon running as the owner's user, never copied elsewhere. Encryption alternatives are decision 7. Whatever is chosen, the refresh token is the most valuable secret on the host after the person and host keys, and `status` should never print it.

### Use and refresh

- **Every request** to the MCP endpoint carries `Authorization: Bearer ACCESS`, and only requests to the MCP URL's origin. HTTP redirects from the MCP endpoint are not followed. A token is never sent to a server other than its `resource`.
- **Refresh before use.** Before `initialize` or a call, when `expires_at` is within 60 seconds, the daemon refreshes with `grant_type=refresh_token`, `refresh_token`, `client_id`, and `resource`.
- **One refresh at a time.** Refreshes for one credential are serialized, and the new refresh token is stored in the same transaction as the new access token, before it is used. Authorization servers rotate refresh tokens for public clients, so two concurrent refreshes would invalidate each other.
- **401 during a session.** The daemon refreshes once and retries only `initialize`, `tools/list`, and `resources/list`. For `tools/call` and `resources/read`, a 401 makes the call `failed` with `auth_required`, and the next call refreshes first. The call is not sent again, which keeps the rule that a call is never sent twice (decision 8).
- **403 `insufficient_scope`.** The call is `failed` with `insufficient_scope`. Status item 14 names the scopes the server asked for, with the command `peerspan sources login SOURCE --scopes "…"`. There is no automatic step-up, because it needs a person.
- **Refresh refused** (`invalid_grant`, `invalid_client`): the credential becomes `login_required`, the source gets reason `login`, and calls fail with `auth_required` without being sent.

### Which account

The token belongs to whoever approved in the browser, at whatever provider account that browser was signed in to. MCP gives the client no standard way to learn which account that was. So Peerspan:
- records the issuer, the granted scope, and the owner's own `--account LABEL`, defaulting to empty;
- shows them in `sources`, `capability show`, `shares`, and the share review;
- states in the review that the person cannot see which account approved, when no label was given.

The account is the owner's, never a caller's. Signing in for another person is a non-goal.

### Revocation and removal

- **`sources logout`** posts the refresh token, then the access token, to the authorization server's `revocation_endpoint` ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)) when the metadata has one, then deletes the credential. Without an endpoint, or when revocation fails, it deletes anyway and prints: `ISSUER has no revocation endpoint Peerspan could use. To revoke access there, remove "Peerspan (HOST_LABEL)" from the connected apps of your account.` Output: `{source, revoked: true|false, deleted: true}`.
- **The source disappears** from configuration (a `PUT` that drops it): the credential is revoked and deleted with the definition, values, and snapshot, as slice 1 does for values.
- **The URL changes:** the old credential's `resource` no longer matches, so it is revoked and deleted, and the source gets reason `login`.
- **At the provider:** the owner revokes Peerspan in the provider's settings. The next refresh or call gets `invalid_grant` or 401, and the source moves to `login_required`.
- **Unshare** does not touch tokens. It only stops new calls, as today.

## Running remote servers

The slice 1 instance rules carry over with these meanings:

| Slice 1 rule | For a remote server |
| --- | --- |
| Instance | One MCP session: an HTTP client, the negotiated version, and `MCP-Session-Id` if the server set one. One per source, or per capability with its own credential (decision 6). |
| Starting | `POST initialize`, then `notifications/initialized`, within 30 seconds. Failure gives `server_start_failed`. Three failures in 10 minutes fail queued calls, as today. |
| Concurrency | At most 4 calls at once per instance. |
| Idle stop | After 10 minutes without calls, `DELETE` with the session ID (405 is fine), and the instance is dropped. |
| stderr log | `STATE/tool-logs/AGENT_ID/SERVER.log` records HTTP status, session changes, refreshes, and errors, never headers or tokens. |

- **Requests.** Each JSON-RPC message is a `POST` with `Content-Type: application/json`, `Accept: application/json, text/event-stream`, the headers from the definition, `Authorization` for OAuth, `MCP-Protocol-Version` after `initialize`, and `MCP-Session-Id` once set. A JSON reply is read whole. An SSE reply is read until the event holding the response to this request; other events on it are logged and dropped, and a server-to-client request on it gets a JSON-RPC error `-32601`.
- **Protocol version.** The client offers `2025-06-18` as today, and accepts `2025-03-26`, `2025-06-18`, or `2025-11-25` from the server. The 2026-07-28 session-less form is later work.
- **Session lost.** A 404 to a request carrying `MCP-Session-Id` ends the instance. A call whose request got that 404 was refused, so it is `failed` with `server_exited` and was not run. Queued calls start a new instance.
- **Cancel and deadline.** Peerspan posts `notifications/cancelled` with the request ID on the same session, and abandons the response stream. The call becomes `uncertain`, as for stdio.
- **Lost response.** A connection that drops after the request was sent, before its response, makes the call `uncertain` with the new error `connection_lost`. It is never sent again.
- **HTTP errors.** 401 gives `auth_required`, 403 `insufficient_scope` (when the challenge says so) or `http_error`, and any other non-2xx answer to a call gives `http_error`. These are `failed`: the server answered without running the call. A 5xx is `uncertain` with `http_error`, because a server error after the call started cannot be told apart from one before (decision 8).
- **Result size.** As today: over 1,048,576 bytes is `failed` with `result_too_large`. The HTTP body read stops at 2 MiB.
- **Timeouts.** Connect 10 seconds. A call has no read timeout of its own beyond its deadline.
- **Proxies.** Neither host honors `HTTPS_PROXY` in this slice; Go turns off `ProxyFromEnvironment` to match Rust (decision 10).
- **TLS.** The system trust store in both hosts. Rust adds a root store (decision 10).

**New call errors.** `failed` gains `auth_required`, `insufficient_scope`, and `http_error`; `uncertain` gains `connection_lost` and `http_error`. The agent tools pass `error` through unchanged, so no adapter change is needed, but the call view's `note` texts already cover these states.

## Capabilities on remote sources

- `capability create --from AGENT/SERVER` accepts a remote source once it is `shareable`. Operations and resources come from its snapshot as today.
- **Credential context.** `--arg` is refused with 400 `--arg applies only to stdio sources`. `--env-file` supplies values for the variables the definition's headers reference, overriding captured values (the narrower-credential case for header tokens, such as a fine-grained GitHub PAT for one capability). Its own OAuth sign-in is decision 6.
- **The review** adds a line for remote sources:
  - headers: `Credential: the token in the Authorization header of AGENT/SERVER (from claude-code:user).`
  - OAuth: `Credential: Peerspan's own sign-in to ISSUER_HOST, scopes SCOPE, account LABEL (or: account not labelled; Peerspan cannot see which account approved), signed in on DATE.`

  The reach sentence is unchanged.
- **Raw sources** for the person's own machines (open list) cover remote sources too, on the serving host's token.
- **`unavailable`.** Each capability is judged by the credential it actually uses. A capability that uses the source's sign-in becomes unavailable when the source is in `login`. A capability with its own sign-in (decision 6) is judged only by that sign-in, so it keeps working while the source's sign-in has lapsed or been logged out, and becomes unavailable when its own lapses. Either case uses a new marker, `unavailable: ["auth"]` (not `source`, because the source still exists). Calls are refused at the receiver with 409 `{code: "unavailable", error: "the capability's sign-in has lapsed on its host"}`, before anything is persisted. A caller then knows not to wait, and the owner sees item 14.

## Status

Attention item 14, `capability_failing`, gains:
- a source with reason `login` that has capabilities using its sign-in: command `peerspan sources login AGENT/SERVER`; a capability whose own sign-in lapsed: `peerspan capability login NAME`;
- a credential in `refresh_failed` for more than 1 hour, or in `login_required`: same command;
- an `insufficient_scope` in the last 24 hours: command `peerspan sources login AGENT/SERVER --scopes "SCOPES"`;
- a `snapshot_error` `unauthorized` on a headers source: command `peerspan sources refresh --agent AGENT` after updating the token.

`capabilities` in status gains `remote_sources` and `signed_in`.

## Persistence

The next free database version (19 is taken by machine linking; B, C, and D may also need one, so one slice 3 migration is suggested) adds:

```sql
CREATE TABLE oauth_clients (issuer TEXT NOT NULL, redirect_uri TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(issuer, redirect_uri));
CREATE TABLE oauth_credentials (agent_id TEXT NOT NULL, server TEXT NOT NULL, capability TEXT NOT NULL DEFAULT '', record TEXT NOT NULL, PRIMARY KEY(agent_id, server, capability));
```

- `tool_servers.record` gains `remote`, `headers`, and the stored challenge `{resource_metadata, scope}`. `tool_values` gains `headers.NAME` and `url` fields. Existing records read as before.
- Migration creates the tables and rewrites nothing. Remote sources from earlier discovery keep reason `remote` until the next `sources refresh`, which recomputes it.
- **New activity kinds:** `sources.login` and `sources.logout` (subject `AGENT_ID/SERVER` or `…@CAPABILITY`), `sources.token_refresh_failed`. Never with token values.

## Security notes

- **Who can trigger use of the token.** Only callers the owner shared a capability with, or the owner's trusted and opened machines, through the existing authorization. The token's reach is the provider account's reach within the granted scope, and the review says so.
- **Callers never see tokens.** Results are the server's JSON-RPC results; Peerspan strips nothing from them, so a server that echoes a token would leak it. This is the same trust in the server as for stdio.
- **The URL is the owner's.** Callers cannot choose where the daemon connects, so there is no request forgery through calls. The daemon still refuses non-HTTPS URLs except loopback, and never follows redirects with a token.
- **Authorization-server metadata** is fetched only over HTTPS, except loopback for tests, and the `issuer` in it must match the URL it was derived from (RFC 8414 section 3.3).
- **Loopback redirect.** Another local process could bind the port first and receive the code. PKCE makes that code useless to it, and `state` is checked.
- **Coordinator.** Learns nothing new: no names, URLs, or tokens enter policy or coordination.

## Interactions with items B, C, and D

- **B, approval of each call.** OAuth-backed write tools are the main use for approval. The approval prompt should show the credential line from the review (issuer, scope, account). A call waiting for approval can outlast a token: the refresh happens when the call starts, and a lapsed sign-in fails it with `auth_required` after approval, not before. Approval must sit before `running`, so `connection_lost` stays meaningful.
- **C, sharing with one agent.** No interaction beyond the review line: an agent principal reaches the owner's provider account exactly as a person principal does. `call --from-agent` behaves the same for remote capabilities.
- **D, resource bounds and other source types.**
  - Bounds that check arguments run before the HTTP request, so they apply unchanged to remote tools.
  - Some providers can bound reach at the consent screen (Notion's page picker, GitHub App repository selection). A per-capability sign-in (decision 6) lets that act as a provider-enforced bound; D may want to describe it in the review.
  - A `gh` adapter would take its credential from `gh auth token` or `GH_TOKEN`, not OAuth. The `auth.mode` field here (`none`, `headers`, `oauth`) should become a general credential kind that D extends, for example with `cli`.
  - D's `bounds` field and this document's `auth` field are separate parts of the capability record and do not conflict.

## Implementation size (estimate)

| Part | Work | Size |
| --- | --- | --- |
| Go host | Discovery of headers and hints; Streamable HTTP client behind the existing instance interface; OAuth discovery, DCR, PKCE, token exchange, refresh, revocation; store, migration, local API, CLI (`sources login` and `logout`, review lines, status) | ~2,500–3,000 lines with unit tests |
| Rust host | The same, plus an HTTPS client with a public root store on the existing hyper and rustls stack | ~3,000–3,500 lines |
| Shared adapter | None required; the new `error` values pass through. Optional wording in tool descriptions | ~0–20 lines |
| Conformance | A fixture Streamable HTTP MCP server and fixture authorization server in Python, on loopback HTTP: resource metadata in both discovery forms, RFC 8414 and OIDC metadata, DCR on and off, PKCE on and off, `resource` checking, short-lived tokens, refresh rotation, `invalid_grant`, `insufficient_scope`, revocation, session 404, dropped connections, SSE replies. Conformance drives the authorization URL itself (auto-approve) and posts the redirect, covering both the listener and paste paths. Cases across all four Go/Rust pairings | ~900 lines of fixtures, ~1,200 lines of cases |
| Live acceptance | One DCR provider by OAuth and GitHub by header PAT, owner call and agent call, then `sources logout` and the next call failing `auth_required` | ~250 lines plus test accounts (decision 11) |

## Owner decisions needed

1. **Credential modes in slice 3.** Options: (a) OAuth only; (b) OAuth plus static headers from harness configuration; (c) (b) plus public servers with no auth. **Recommend (c).** Headers are how GitHub's remote server works without DCR, and public servers cost nothing extra.
2. **Client registration methods.** Options: (a) DCR plus `--client-id`; (b) (a) plus CIMD, with a client metadata document Peerspan hosts at a fixed HTTPS URL; (c) CIMD first, DCR fallback. **Recommend (a) now, (b) once Peerspan has a public domain.** CIMD needs a stable HTTPS URL, and the public domain is not settled; DCR covers Linear, Notion, Atlassian, and Sentry today. The specification now deprecates DCR, so CIMD should follow soon.
3. **Client name shown at providers.** Options: (a) `Peerspan`; (b) `Peerspan (HOST_LABEL)`; (c) set by the owner at sign-in. **Recommend (b).** It tells the person which machine to revoke at the provider; the cost is sending the host label to the provider. With CIMD it is fixed per document, so it becomes `Peerspan`.
4. **The deprecated HTTP+SSE transport.** Options: (a) not supported, reason `sse`; (b) supported when the harness says `sse` or when `POST initialize` returns 400, 404, or 405. **Recommend (a).** The providers above serve Streamable HTTP; (b) adds a second client for a deprecated transport. Revisit if live testing finds a needed SSE-only server.
5. **Headless sign-in.** Options: (a) loopback listener plus pasting the final URL; (b) (a) plus completing a headless host's sign-in from another trusted machine of the same person, over a new peer route; (c) OAuth device flow (RFC 8628) where offered. **Recommend (a).** It works over SSH with nothing new; (b) needs a new peer route and trust rule, and (c) is not part of MCP authorization and few MCP servers offer it.
6. **Separate sign-ins per capability.** Options: (a) one sign-in per source, shared by its capabilities; (b) a capability may have its own sign-in (`capability login NAME`), with its own instance, like `--env-file` today. **Recommend (b).** It is the OAuth form of the narrower credential: another account, fewer scopes, or a narrower consent-screen choice. It adds one key column and two commands.
7. **Tokens at rest.** Options: (a) plain in the host database, as `tool_values`; (b) encrypted with a key in a separate 0600 file in the state directory; (c) the OS keychain where present (macOS Keychain, Secret Service), else (a). **Recommend (a) for slice 3**, with (c) considered with macOS support. (b) protects only against copies of the database alone, such as backups; (c) fails on headless Linux without a session bus, which is a main case.
8. **Calls after an HTTP error.** Options: (a) never resend a call; 401 and 4xx are `failed`, 5xx and dropped connections `uncertain`; (b) after a 401, refresh and resend once, since the server refused before running it; (c) treat 5xx as `failed`. **Recommend (a).** It keeps "never sent twice" exact; proactive refresh makes 401 rare.
9. **Claude Code `headersHelper`.** Options: (a) not shareable, reason `headers_helper`; (b) run the helper in the CLI at discovery and capture its output as literal headers; (c) run it in the daemon before each instance starts. **Recommend (a).** (b) captures a token that may be short-lived, and (c) runs an arbitrary owner command for every peer's call, which is the same reach as stdio servers but invisible in the review.
10. **HTTP client environment.** (i) TLS roots: (a) system store (Go default; Rust adds `rustls-native-certs`); (b) bundled Mozilla roots (`webpki-roots`) in Rust. (ii) Proxies: (a) ignore `HTTPS_PROXY` in both; (b) honor it in both. **Recommend system roots and ignoring proxies** for slice 3. System roots honor corporate CAs the same way in Go and Rust; proxy support can come when someone needs it, and must be identical in both hosts.
11. **Live acceptance providers.** Options: Linear, Notion, Atlassian, or Sentry for OAuth with DCR; GitHub with a PAT header for headers. **Recommend Linear (DCR) and GitHub (PAT header)**, both with a free test account. It needs the owner to provide the accounts.
12. **A lapsed sign-in at the receiver.** Options: (a) a new `unavailable` marker `auth`, refused at submission with 409 `unavailable`; (b) accept calls and fail them at start with `auth_required`. **Recommend (a).** A caller learns at once, nothing is persisted, and it matches how a missing source is handled.

## Sources

- MCP authorization: [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization); client registration in [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration.md).
- MCP transports: [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports); [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports).
- [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html), [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591), [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), [CIMD draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document).
- Harness configuration: [Claude Code](https://code.claude.com/docs/en/mcp), [Codex](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [OpenCode](https://opencode.ai/docs/mcp-servers/).
- Providers: as linked in the table above.
