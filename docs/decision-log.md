# Owner decision log

The owner's decisions about Peerspan's design, in one place, with the options each choice was made from. It is a record for auditing and reviewing the codebase. The owner makes the decisions; this log only records them, and the contract or proposal it links to stays the specification.

## How to use it

- **One entry per decision.** Each entry has a stable ID, which never changes or gets reused. Cite it in reviews, commits, and other documents ("per CONV-9").
- **What an entry records:** its date and area; the question; every option that was proposed; the choice; the reason given; the proposal it came from and the contract section that specifies it; and, when known, the PR that recorded it and the PRs that implement it. An entry's heading states the question, as the source titles it. Entries in a group share the fields given under the group's heading.
- **Wording is copied, not paraphrased.** Options and reasons are quoted from the source document as written. When the source records no options, the entry says "options not recorded"; it never reconstructs them. When options survive only in git history, the entry names the commit.
- **IDs** are `AREA-N`. Where the source numbers its decisions, `N` is the source's number (CAP-15 is decision 15 of the capabilities contract; CAP-16B.3 is decision 3 of the slice 3 item B proposal). Where it does not, entries are numbered here in the source's order.
- **Superseded decisions stay.** A later decision that replaces an earlier one gets its own entry and names the one it replaces; the earlier entry is not deleted.
- **Maintained going forward.** Every new owner decision adds an entry here in the same PR that records it in a contract or proposal. Implementing PRs add their number to the entry.

Areas: `ACC` access model, `ROAD` roadmap, `PI` person identity, `QR` QUIC and relays, `COORD` coordination, `DEL` delegation, `LAUNCH` launch readiness, `HC` hosted coordinator, `LIVE` live delivery, `RT` remote tools, `CRED` tool credentials, `CAP` capabilities, `GS` guided setup, `ML` machine linking, `CONV` conversations.

Contents:
- [Full entries](#full-entries), with options:
  - [CAP-16: capabilities slice 3](#cap-16-capabilities-slice-3-2026-10-25) (2026-10-25)
  - [CONV: conversations](#conv-conversations-2026-10-25) (2026-10-25)
  - [LIVE-5: protocol_version from every adapter](#live-5-protocol_version-from-every-adapter-2026-10-25) (2026-10-25)
  - [LAUNCH-34: the `attach --no-start` sign-in check](#launch-34-the-attach---no-start-sign-in-check-2026-10-24) (2026-10-24)
  - [CAP-15: call timing](#cap-15-call-timing-2026-10-23) (2026-10-23)
- [Index of earlier decisions](#index-of-earlier-decisions)

## Full entries

### DEC-EP1: unambiguous numeric endpoints (2026-10-26)

- **Authority:** selected within the delegated DEC-01 through DEC-07 stream.
- **Chosen:** "refuse ambiguous numeric-address aliases so endpoint
  interpretation does not depend on a platform's legacy IPv4 resolver."
- **Discarded:** "interpret every numeric label sequence as DNS"; "special-case
  only exactly four dotted numeric labels while accepting other legacy numeric forms."
- **Source:** [endpoint grammar](decentralized-bootstrap-contract.md).
- **Boundary:** exact TLS key pins remain mandatory; endpoint parsing grants no authority.

### DEC-RT1: explicit retention selections before signing (2026-10-26)

- **Authority:** selected within the delegated DEC-01 through DEC-07 stream.
- **Chosen:** "refuse a known ineffective retention selection before local
  signing, while preserving independent key rotation verification."
- **Discarded:** "advertise unusable selections as preserved"; "invalidate a
  correctly signed root rotation because its child cannot be kept"; "infer a
  new child grant from the list."
- **Source:** [typed signing-intent authority](decentralized-verification-contract.md#action-or-typed-signing-intent-authority).
- **Reason:** the caller's reviewed kept-grant selection must be independently
  usable at its fixed transition time; signed root verification remains separate.

### DEC-SF1: observe additive migration rollback (2026-10-26)

- **Authority:** selected within the delegated DEC-01 through DEC-07 stream.
- **Chosen:** "an explicit immediate startup failure point makes the required
  transaction boundary observable without guessing internal SQL timing."
- **Discarded:** "treating preflight refusal as post-DDL rollback evidence";
  "waiting on a durable barrier while holding the opening writer lock";
  "relying on sleep/kill timing or filesystem exhaustion to guess which migration ran."
- **Source:** [schema migration rollback control](decentralized-verification-contract.md#schema-migration-rollback-control).
- **Boundary:** explicit test-mode opt-in, no waiting/partial commit or remote
  control; normal startup without the flag and current23 opening are unaffected.

### DEC-RP1: network-root provider host (2026-10-26)

- **Authority:** selected within the delegated DEC-01 through DEC-07 stream.
- **Chosen:** "use the absent-host marker consistently" in the public root
  provider summary; its root state and scope8 stay explicit.
- **Discarded:** "show the daemon's local writer as a bound root host".
- **Reason:** that would "mix transport placement with the root's authority
  identity". The private intent still pins its actual local writer.
- **Source:** [public provider views](decentralized-runtime-contract.md#2-public-network-and-provider-views).

### DEC-RC1: exact retention proof closure (2026-10-26)

- **Authority:** selected by the delegated coordinator-free workstream; this
  records an agent decision within DEC-01 through DEC-07, not a new owner reply.
- **Chosen:** "include every signed retention reference in the manifest's
  transitive statement closure."
- **Reason:** "This keeps portable validation deterministic and requires the
  same original evidence on both implementations."
- **Discarded:** "omit all retention references"; "include only finite retainers
  while skipping root retention"; "choose only apparently relevant retained
  children". The reasons and concrete verification cases are in the source.
- **Source:** [retention-closure clarification](decentralized-bootstrap-contract.md#retention-closure-clarification-2026-10-26).
- **Boundary:** proof completeness does not change admission or effective scopes;
  existing aggregate quotas can refuse an oversized exact closure. Ordinary
  statement closure includes exact resolution/restriction references; operation
  and migration-origin composite proofs keep their separate verification rules.

### CAP-16: capabilities slice 3 (2026-10-25)

- **Date:** 2026-10-25.
- **Area:** capabilities, roadmap milestone 10, slice 3.
- **Decision:** slice 3 covers four items, each designed in its own proposal. The owner accepted every recommendation in each proposal's "Owner decisions needed" list, so each proposal's recommended design is the design for its item.
- **Recorded in:** [decision 16](capabilities-contract.md#owner-decisions) of the capabilities contract ([PR #77](https://github.com/peerspan/peerspan-internal/pull/77)), and each proposal's status line.
- **Contract section:** each item's section in the capabilities contract, added when it was implemented, following its proposal.
- **Implementing PRs:** item B [#78](https://github.com/peerspan/peerspan-internal/pull/78) (merged), item C [#79](https://github.com/peerspan/peerspan-internal/pull/79) (merged), item D [#80](https://github.com/peerspan/peerspan-internal/pull/80) (merged), item A [#86](https://github.com/peerspan/peerspan-internal/pull/86).

Every entry below was decided by accepting the proposal's recommendation, quoted under "Chosen".

#### CAP-16A: remote MCP servers and OAuth

- **Source:** [capabilities-slice3-remote-proposal.md, Owner decisions needed](capabilities-slice3-remote-proposal.md#owner-decisions-needed), decisions 1–12 (proposal [PR #74](https://github.com/peerspan/peerspan-internal/pull/74)).
- **Contract section:** [Remote MCP servers and OAuth (slice 3)](capabilities-contract.md#remote-mcp-servers-and-oauth-slice-3).
- **Implemented in:** [PR #86](https://github.com/peerspan/peerspan-internal/pull/86).

##### CAP-16A.1. Credential modes in slice 3

- **Options:** (a) OAuth only; (b) OAuth plus static headers from harness configuration; (c) (b) plus public servers with no auth.
- **Chosen (the recommendation):** Recommend (c).
- **Reason given:** Headers are how GitHub's remote server works without DCR, and public servers cost nothing extra.

##### CAP-16A.2. Client registration methods

- **Options:** (a) DCR plus `--client-id`; (b) (a) plus CIMD, with a client metadata document Peerspan hosts at a fixed HTTPS URL; (c) CIMD first, DCR fallback.
- **Chosen (the recommendation):** Recommend (a) now, (b) once Peerspan has a public domain.
- **Reason given:** CIMD needs a stable HTTPS URL, and the public domain is not settled; DCR covers Linear, Notion, Atlassian, and Sentry today. The specification now deprecates DCR, so CIMD should follow soon.

##### CAP-16A.3. Client name shown at providers

- **Options:** (a) `Peerspan`; (b) `Peerspan (HOST_LABEL)`; (c) set by the owner at sign-in.
- **Chosen (the recommendation):** Recommend (b).
- **Reason given:** It tells the person which machine to revoke at the provider; the cost is sending the host label to the provider. With CIMD it is fixed per document, so it becomes `Peerspan`.

##### CAP-16A.4. The deprecated HTTP+SSE transport

- **Options:** (a) not supported, reason `sse`; (b) supported when the harness says `sse` or when `POST initialize` returns 400, 404, or 405.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** The providers above serve Streamable HTTP; (b) adds a second client for a deprecated transport. Revisit if live testing finds a needed SSE-only server.

##### CAP-16A.5. Headless sign-in

- **Options:** (a) loopback listener plus pasting the final URL; (b) (a) plus completing a headless host's sign-in from another trusted machine of the same person, over a new peer route; (c) OAuth device flow (RFC 8628) where offered.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** It works over SSH with nothing new; (b) needs a new peer route and trust rule, and (c) is not part of MCP authorization and few MCP servers offer it.

##### CAP-16A.6. Separate sign-ins per capability

- **Options:** (a) one sign-in per source, shared by its capabilities; (b) a capability may have its own sign-in (`capability login NAME`), with its own instance, like `--env-file` today.
- **Chosen (the recommendation):** Recommend (b).
- **Reason given:** It is the OAuth form of the narrower credential: another account, fewer scopes, or a narrower consent-screen choice. It adds one key column and two commands.

##### CAP-16A.7. Tokens at rest

- **Options:** (a) plain in the host database, as `tool_values`; (b) encrypted with a key in a separate 0600 file in the state directory; (c) the OS keychain where present (macOS Keychain, Secret Service), else (a).
- **Chosen (the recommendation):** Recommend (a) for slice 3, with (c) considered with macOS support.
- **Reason given:** (b) protects only against copies of the database alone, such as backups; (c) fails on headless Linux without a session bus, which is a main case.

##### CAP-16A.8. Calls after an HTTP error

- **Options:** (a) never resend a call; 401 and 4xx are `failed`, 5xx and dropped connections `uncertain`; (b) after a 401, refresh and resend once, since the server refused before running it; (c) treat 5xx as `failed`.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** It keeps "never sent twice" exact; proactive refresh makes 401 rare.

##### CAP-16A.9. Claude Code `headersHelper`

- **Options:** (a) not shareable, reason `headers_helper`; (b) run the helper in the CLI at discovery and capture its output as literal headers; (c) run it in the daemon before each instance starts.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** (b) captures a token that may be short-lived, and (c) runs an arbitrary owner command for every peer's call, which is the same reach as stdio servers but invisible in the review.

##### CAP-16A.10. HTTP client environment

- **Options:** (i) TLS roots: (a) system store (Go default; Rust adds `rustls-native-certs`); (b) bundled Mozilla roots (`webpki-roots`) in Rust. (ii) Proxies: (a) ignore `HTTPS_PROXY` in both; (b) honor it in both.
- **Chosen (the recommendation):** Recommend system roots and ignoring proxies for slice 3.
- **Reason given:** System roots honor corporate CAs the same way in Go and Rust; proxy support can come when someone needs it, and must be identical in both hosts.

##### CAP-16A.11. Live acceptance providers

- **Options:** Linear, Notion, Atlassian, or Sentry for OAuth with DCR; GitHub with a PAT header for headers.
- **Chosen (the recommendation):** Recommend Linear (DCR) and GitHub (PAT header), both with a free test account.
- **Reason given:** It needs the owner to provide the accounts.

##### CAP-16A.12. A lapsed sign-in at the receiver

- **Options:** (a) a new `unavailable` marker `auth`, refused at submission with 409 `unavailable`; (b) accept calls and fail them at start with `auth_required`.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** A caller learns at once, nothing is persisted, and it matches how a missing source is handled.

##### CAP-16A.add1. A remote server with no sign-in in the share review

- **Date:** 2026-10-25, the owner's addition to item A after accepting it.
- **Question:** what the share review says about a remote server that asks for no sign-in (allowed by CAP-16A.1, option (c)).
- **Options:** not offered as a choice; the owner added the requirement.
- **Decision:** keep no-sign-in servers. The share review states plainly that such a server asks for no sign-in and serves anyone who can reach it, and that sharing extends that reach to the recipients through this host. The proposed review line: `Credential: none. AGENT/SERVER (URL_HOST) asks for no sign-in, so it serves anyone who can reach it. Sharing it lets the people you share with use the selected operations through this host, including when the server is only reachable from here (a local, home, VPN, or company network).`
- **Reason given:** not recorded beyond the line itself: a server reachable only from the owner's network becomes reachable to recipients through the owner's host.
- **Source:** [PR #81](https://github.com/peerspan/peerspan-internal/pull/81), merged on 2026-10-25 as `5d6467a`. It adds the line to the [proposal's review section](capabilities-slice3-remote-proposal.md#capabilities-on-remote-sources) and notes it in decision 16.

##### CAP-16A, settled by the implementer (not owner decisions)

These points were left open by the proposal and were settled by the implementer in [PR #86](https://github.com/peerspan/peerspan-internal/pull/86), choosing what fits the proposal best. They are not owner decisions; the owner may revisit them. Each is specified in the contract section above.

- **CAP-16A.impl1. Database version.** 22, the next after per-call approval's 20 and resource bounds' 21. A version 22 binary migrates databases at versions 0 to 21 and refuses anything above 22.
- **CAP-16A.impl2. How headers are captured and overridden.** A `captured` header entry lists its `variables`; the CLI sends the resolved value as `headers.NAME` and the configured text as `header_templates.NAME` (a template may hold configured text, so it is a value, not part of the definition). The environment file, and a capability's `env_file` before it, override a header only when they define every variable it references; otherwise the captured value stands. The URL is never overridden. Codex `env_http_headers` and `bearer_token_env_var` become the templates `${VAR}` and `Bearer ${VAR}`; OpenCode `{env:VAR}` is rewritten as `${VAR}`.
- **CAP-16A.impl3. Definition shape.** `remote` carries `headers_helper` so the daemon can give the reason; `remote` and `headers` are optional so a CLI that predates this slice still works. A source whose harness turned OAuth off answers a 401 challenge with `snapshot_error` `unauthorized`, never `login`, since it is never offered sign-in.
- **CAP-16A.impl4. The sign-in flow's details.** The sign-in always probes the server afresh rather than reusing a stored challenge; scopes are chosen from `--scopes`, then the harness hint, then the challenge, then `scopes_supported`; the protected resource metadata is tried at the challenge URL, the path-inserted URL, then the root; the redirect port reuses the newest registration for the issuer; a pending sign-in is removed at its first completion attempt; `login_id` is `login_` and 16 random bytes in hex.
- **CAP-16A.impl5. Refusals beyond the proposal's table.** `not_usable` (a definition reason applies), `unreachable` (the probe could not connect), `oauth_metadata`, `registration_failed`, and `no_code`, with HTTP statuses and codes for every refusal, and the CLI's `--client-secret-file` checks.
- **CAP-16A.impl6. Client authentication.** A DCR answer with a secret uses its `token_endpoint_auth_method`, defaulting to `client_secret_basic`; a `--client-id` secret uses `client_secret_post` unless the metadata lists only `client_secret_basic`. `HOST_LABEL` in `Peerspan (HOST_LABEL)` is the machine's host name up to its first dot.
- **CAP-16A.impl7. The credential record.** It adds `client`, `token_endpoint`, `revocation_endpoint`, and `refresh_failed_at` to the proposal's fields so refresh and revocation need no new discovery; `account` is null when no label is given. A replaced credential, and credentials removed by a dropped source, a changed URL, or `capability remove`, are revoked in the background, best effort.
- **CAP-16A.impl8. Per-capability sign-out.** `capability logout` keeps the capability on its own sign-in, so it becomes `unavailable` with `auth` until the next `capability login`, rather than falling back to the source's sign-in, which may reach more.
- **CAP-16A.impl9. Call outcomes the proposal left open.** A connection that cannot be made means nothing was sent: `failed` with `server_exited`. A 3xx is `failed` `http_error`. A body over 2 MiB is `failed` `result_too_large` with `result_bytes` null. A start refused for its credential fails the waiting calls with `auth_required` and does not count toward the start-failure limit; a queued call whose capability's sign-in has lapsed fails with `auth_required` at the recheck instead of `rejected`; a raw source that needs a sign-in is refused with the same 409 as a capability.
- **CAP-16A.impl10. Status.** `signed_in` counts the credentials that are not `login_required`. Item 14 picks one command per subject: a lapsed sign-in first, then a recent `insufficient_scope`, then the existing causes; a capability with its own sign-in has its own item with `peerspan capability login NAME`.
- **CAP-16A.impl11. Texts the proposal did not give.** The review's `Credential:` lines for headers (one or several, with the `env_file` note), for a capability's own sign-in, for a lapsed sign-in, and for a server not reached yet; the `shares` credential line; the `sources` `url:` and `auth:` lines; the CLI's browser-mode line, busy-port line, listener pages, success line, sign-out question and messages.
- **CAP-16A.impl12. The guided share.** It may choose a source that needs a sign-in; at a terminal it signs in right after the source is chosen, before the operations; without one it refuses with nothing created.
- **CAP-16A.impl13. Clarifications from conformance.** A URL with an unresolved reference is `missing_env` and is not judged for `insecure_url`; the loopback host comparison is case-insensitive; `sources login SERVER` held by several agents exits 1 listing the qualified names; a `ping` on an event stream is answered with a JSON-RPC response; a JSON `null` for `remote` or `headers` reads as absent; a remote record stored before this slice lists `remote` with the http default; both hosts open one connection per remote request; in browser mode the CLI waits up to 5 seconds for the opener before printing the link.
- **CAP-16A.impl14. Found in review.** A sign-in whose source was dropped or changed URL, or whose capability was removed, while it was pending is refused as `login_expired` and its tokens are revoked; each session takes tokens only for its own resource; a refresh is stored only while the credential is still the one refreshed, and a credential becomes `login_required` only while it holds the refused token; every exchange with an OAuth endpoint is bounded at 30 seconds, and a session's closing `DELETE` at 5.

#### CAP-16B: approval of each call

- **Source:** [capabilities-slice3-approval-proposal.md, Owner decisions needed](capabilities-slice3-approval-proposal.md#owner-decisions-needed), decisions 1–12 (proposal [PR #72](https://github.com/peerspan/peerspan-internal/pull/72)).
- **Contract section:** [Per-call approval (slice 3)](capabilities-contract.md#per-call-approval-slice-3), and the input deletion schedule under the slice 1 Records section of the capabilities contract.
- **Implemented in:** [PR #78](https://github.com/peerspan/peerspan-internal/pull/78).

##### CAP-16B.1. Where the requirement lives

- **Options:**
  - (a) On the capability record, host-local, unsigned, not visible to coordination.
  - (b) As a fourth bound in the policy's capability rule (`none`, `changing`, or `all`), signed and visible to coordination; no per-operation list, since the policy never names operations.
  - (c) Both: the policy flag as a floor the person sets everywhere, the record for operation lists.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** It only narrows, needs no signing or format break, applies offline at once, and can name operations; a policy flag can only be per capability anyway.

##### CAP-16B.2. Where the person approves

- **Options:**
  - (a) Only on the serving host, through its local CLI.
  - (b) Also from any of the person's trusted machines, through a new peer route authorized by self access.
  - (c) Also from a future dashboard.
- **Chosen (the recommendation):** Recommend (a) for this slice, (b) as a follow-up.
- **Reason given:** (b) makes approval authority follow `trusted_hosts`, which any holder of the person key can grant itself; that deserves its own review.

##### CAP-16B.3. How strong the approval act is

- **Options:**
  - (a) A terminal prompt; `approve` refuses without a terminal and has no `--yes`.
  - (b) Like `share`: a prompt, or `--yes` without a terminal.
  - (c) A person-key signature over `(sender, call_id, input_sha256)`, through ssh-agent.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** It keeps the person's agent from approving through its shell by accident, without key prompts for every call. (c) stops only processes that cannot reach the ssh-agent, and the agent usually can.

##### CAP-16B.4. Which calls are covered

- **Options:**
  - (a) Policy calls per the requirement; self calls with an agent origin too unless `agent_self` is false; self calls without origin never.
  - (b) Policy calls only; everything under self access is exempt.
  - (c) Every call, including the person's own CLI from trusted machines.
- **Chosen (the recommendation):** Recommend (a), with `agent_self` true by default.
- **Reason given:** The person's own agent on another machine using write tools is a main reason to want approval; the person typing at their own CLI is not.

##### CAP-16B.5. How the caller sees it on the wire

- **Options:**
  - (a) `state` stays `queued`, with a new `approval` object; callers derive `awaiting_approval` locally.
  - (b) A new wire state `awaiting_approval`, with an upgrade gate: the receiver uses it only for callers that announce support, for example with a request field.
  - (c) A new wire state for everyone.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** (c) breaks every v18 caller, whose validation rejects unknown states, so their calls never resolve. (b) works but adds a negotiation for no gain over (a).

##### CAP-16B.6. Whether to notify the person's agent session

- **Options:**
  - (a) A notice event to the capability's source agent, as specified.
  - (b) To every attached agent session on the serving host.
  - (c) No agent notice in this slice; status and activity only.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** The person is most often in an agent session; the source agent is the natural one and avoids spamming every session.

##### CAP-16B.7. What the notice and listing show of the input

- **Options:**
  - (a) The notice carries no input; the CLI shows it.
  - (b) The notice carries an escaped preview.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** Input is caller-written text; in the owner's agent context it becomes a channel for a caller to instruct the owner's agent.

##### CAP-16B.8. Remembering approvals

- **Options:**
  - (a) Each approval covers one call only.
  - (b) `approve --for 30m` also approves later calls from the same caller to the same operation for a window.
  - (c) `approve --same-input` approves later calls with an identical input hash.
- **Chosen (the recommendation):** Recommend (a) now; consider (b) after real use.
- **Reason given:** (b) and (c) turn approval back into short standing permission, which needs its own review of scope and revocation.

##### CAP-16B.9. Per recipient

- **Options:**
  - (a) The requirement applies to every recipient of the capability.
  - (b) The record also holds `approval_exempt: [principals]`, recipients who never need approval.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** Two capabilities on the same source, one with approval, already serve "trusted Bob, approved Carol" without new syntax; (b) can follow C's principal forms later.

##### CAP-16B.10. How long a call may wait

- **Options:**
  - (a) Until the call's deadline, at most 15 minutes, as for every call.
  - (b) Raise the deadline limit for calls to operations that need approval, for example to 24 hours.
- **Chosen (the recommendation):** Recommend (a) for this slice.
- **Reason given:** (b) changes the receiver's deadline check, which older receivers enforce with 400, and the caller's daemon does not know before submitting whether approval is needed except from the advisory listing. The design notes approval "fails while the owner is away"; (a) accepts that, and the caller sees `approval_timeout` clearly.

##### CAP-16B.11. Default for new capabilities

- **Options:**
  - (a) `none` unless chosen; the guided share asks when write tools are selected, defaulting to yes at the prompt.
  - (b) `changing` by default everywhere.
  - (c) `none`, with no prompt.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** It keeps existing scripts and records unchanged while steering the interactive path, where write tools are chosen, toward approval.

##### CAP-16B.12. Pending limit per caller

- **Options:**
  - (a) 20 pending approvals per rule identity and caller, fixed.
  - (b) A per-rule or per-capability setting.
- **Chosen (the recommendation):** Recommend (a).
- **Reason given:** It stops one caller from flooding the owner's list; `max_calls_per_hour` already bounds volume.

##### CAP-16B, settled by the implementer (not owner decisions)

These points were left open by the proposal and were settled by the implementer in [PR #78](https://github.com/peerspan/peerspan-internal/pull/78), choosing what fits the proposal best. They are not owner decisions; the owner may revisit them. Each is specified in the contract section above.

- **CAP-16B.impl1. Database version.** 20, the next after machine linking's version 19 (PRs #63 and #68, which merged while this PR was open). A version 20 binary migrates databases at versions 0 to 19 and refuses anything above 20.
- **CAP-16B.impl2. The status attention item.** Item 18, `call_approval_pending`, after item 17: one item while any approval is pending, with the pending count as subject and `peerspan approvals` as command.
- **CAP-16B.impl3. Bare call IDs.** `approve`, `deny`, and `approvals show` accept a bare call ID, resolved through `GET /v1/approvals/{call_id}`: 409 `ambiguous` with sorted `candidates` when several senders used that call ID, 404 when none.
- **CAP-16B.impl4. `capability approval` without a flag.** With neither `--agent-self` nor `--no-agent-self`, the current `agent_self` is kept; `PUT /v1/capabilities/{name}/approval` treats an absent `agent_self` the same way.
- **CAP-16B.impl5. The input preview.** The input encoded as the call view encodes a result (so Go and Rust agree byte for byte), cut to at most 512 bytes on a UTF-8 character boundary, then U+007F and U+0080 to U+009F written as `\u` and four lowercase hex digits (the encoding already escapes characters below U+0020); `input_bytes` is the full length.
- **CAP-16B.impl6. The listing's per-operation `approval`.** Advisory, and computed as if the call carries an `origin`: true when the operation is covered and the entry has a `policy` via entry or `agent_self` is true. The receiver decides at acceptance.
- **CAP-16B.impl7. `share NAME --approval`.** Refused with exit 1 before anything is signed (also `--no-agent-self-approval`); `share` of an existing capability never changes its requirement. Only `capability create` and the guided share take the flags.
- **CAP-16B.impl8. `deny` with an approval ID.** `deny` treats its argument as an approval ID exactly when it has one of the two ID forms (`call_` plus 32 lowercase hex digits, or `SENDER_HOST_ID/CALL_ID`); anything else is the access `deny PRINCIPAL`. `--reason` with a non-ID, and `--agent` or `--network` with an ID, are refused with exit 1 before any request.
- **CAP-16B.impl9. Held status requests after a decision.** When the caller's daemon stores an approval that is no longer pending for a call that is not final, a new 60-second window of held status requests begins, as at acceptance, so an approved call's result also arrives at once rather than after backoff polling.
- **CAP-16B.impl10. When inputs are deleted.** The receiver deletes the inputs and results of calls final for more than 7 days within 60 seconds of starting, and at least every 10 minutes after that.

#### CAP-16C: sharing with one agent

- **Source:** [capabilities-slice3-agent-shares-proposal.md, Owner decisions needed](capabilities-slice3-agent-shares-proposal.md#owner-decisions-needed), decisions 1–15 (proposal [PR #73](https://github.com/peerspan/peerspan-internal/pull/73)).
- **Contract section:** [Sharing with one agent (slice 3)](capabilities-contract.md#sharing-with-one-agent-slice-3), and agent addresses in `allow`/`deny` under [Principals and sizes](launch-contract.md#principals-and-sizes).
- **Implemented in:** [PR #79](https://github.com/peerspan/peerspan-internal/pull/79).

##### CAP-16C.1. How Bob's host finds Alice's agent ID

- **Options:**
  - (a) A new peer route that answers one exact name or ID to any member of the network, with the directory as fallback for older hosts.
  - (b) The directory only. It works only when Alice already lets Bob's host reach that agent, which is usually not the case.
  - (c) No lookup. Alice reads `agent:HOST_ID/AGENT_ID` from `peerspan agents` and sends it to Bob.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It is the only option where `--with alice/claude-laptop` works in the common case, and it discloses only that an exact name exists.

##### CAP-16C.2. What the stored principal names

- **Options:**
  - (a) Host ID and agent ID, the existing `agent:` form; the share does not follow the agent to another machine.
  - (b) A new form naming the person and the agent name (for example `agent-name:PERSON_ID/NAME`), which follows moves. The sending host would have to assert the agent's name in `origin`, the format and test vector change, and names would start to authorize.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It keeps "nothing authorizes by name" and needs no format change. Moves are rare, and re-sharing is one command.

##### CAP-16C.3. A host unbound from the person it was shared as

- **Options:**
  - (a) Keep milestone 6 matching (host and agent only). `shares` shows `unbound`, or labels the agent with the host's new person.
  - (b) Add the person to the principal (for example `agent:HOST_ID/AGENT_ID@PERSON_ID`), so the share stops when the host's person changes. This is a format change.
  - (c) Keep the format, store the person at `share` time on the sharing host, and add a status attention item when the host's person differs.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Unbinding is rare, signed, and deliberate, and `shares` makes it visible. (b) is the safe choice if the owner sees this as a real risk.

##### CAP-16C.4. A bare `--with` value containing one `/`

- **Options:**
  - (a) It is always an agent address. A person label with `/` is given as `person:LABEL`.
  - (b) Try a person label first, then an agent address.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** One reading, matching capability addresses. (b) makes the meaning depend on who exists.

##### CAP-16C.5. Sharing with the owner's own agents

- **Options:**
  - (a) Allowed for agents on the owner's other hosts, with a note when that host is trusted; refused with `local` for agents on this host.
  - (b) Refused for all of the owner's own agents, since self access covers trusted machines.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It is how one agent on an untrusted machine gets one capability.

##### CAP-16C.6. How `shares` labels agent recipients

- **Options:**
  - (a) A live lookup by agent ID when `shares` runs (up to 5 seconds), showing gone agents.
  - (b) Store the name at `share` time in a new table (a schema bump); fast and offline, but stale and present only on the host that shared.
  - (c) Show IDs, with only the person taken from the network map.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** No schema change, and it shows when an agent is gone. Names never change, so a lookup is accurate.

##### CAP-16C.7. One match while some of the person's hosts did not answer

- **Options:**
  - (a) Go ahead, and list the unanswered hosts in the review.
  - (b) Refuse until every host answers.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Names are unique per person, `attach` already works this way, and an offline laptop should not block sharing.

##### CAP-16C.8. Which agents `call --from-agent` may act as

- **Options:**
  - (a) Any agent registered on this host.
  - (b) Only agents with an `attach` profile.
  - (c) Only agents whose credential has `calls`.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It matches `message send --from-agent`; the owner already controls every local agent, and the receiver cannot tell the difference.

##### CAP-16C.9. Whether the agent sees calls made as it

- **Options:**
  - (a) No: owner's records only.
  - (b) Yes: visible to `call_status` and `pending_work`, with a `call_update` event.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** The owner made the call and follows it; injecting it into a live session would confuse the agent.

##### CAP-16C.10. `--from-agent` with a source address

- **Options:**
  - (a) Refused, since agents cannot call sources.
  - (b) Allowed, carrying the origin.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** `--from-agent` should show exactly what the agent can do.

##### CAP-16C.11. The recipient's default `discover`

- **Options:**
  - (a) List agent-only shares with `for_agents`, and refuse `call` without the flag with an `agent_only` error that names the flag.
  - (b) Keep them hidden; only `discover --from-agent` shows them.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Alice can see what her agents were given, and the error tells her how to use it.

##### CAP-16C.12. `--from-session`

- **Options:**
  - (a) Accept it, as `message send` does.
  - (b) Omit it.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It is cheap, keeps parity, and lets an owner reproduce an adapter call exactly.

##### CAP-16C.13. How `--from-agent` names the agent

- **Options:**
  - (a) An agent ID or a local agent name.
  - (b) An ID only, as `send --from-agent` takes today.
- **Chosen (the recommendation):** Recommendation: (a), and accept names in `send`/`task --from-agent` too, later or in this slice.
- **Reason given:** (none beyond the recommendation)

##### CAP-16C.14. `allow` and `deny` (message and task access)

- **Options:**
  - (a) Accept `PERSON/AGENT` and `HOST_ID/AGENT` with the same resolver, in this slice.
  - (b) Leave them at `agent:HOST/AGENT` for now.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** The resolver is shared, and one recipient syntax everywhere is easier to explain. It adds `launch_onboarding.py` cases.

##### CAP-16C.15. Principals for agents that are gone

- **Options:**
  - (a) Show them in `shares` with their state, and never remove them automatically.
  - (b) Remove them at the next policy edit.
  - (c) Add a status attention item.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** An unanswered host may come back, and silent removal by a signing tool is surprising. `shares` already shows the state and the `unshare` command.

##### CAP-16C, settled by the implementer (not owner decisions)

These points were left open or contradictory in the proposal and were settled by the implementer in [PR #79](https://github.com/peerspan/peerspan-internal/pull/79), choosing what fits the proposal best. They are not owner decisions; the owner may revisit them. Each is specified in the contract section above.

- **CAP-16C.impl1. A session of another agent in `call --from-session`.** The proposal said both "checked as for `message send`" (404) and "a session of another agent is 400". Settled: 404, as for `message send`.
- **CAP-16C.impl2. Refusal codes of `GET /v1/agent-lookup`.** `invalid` (400), `local` (400), `unknown_person` (404), `unknown_host` (404), `ambiguous` (409), `unknown` (404). The CLI syncs the network once on `unknown_person` or `unknown_host`, as `allow` does for person labels.
- **CAP-16C.impl3. A host that predates the lookup route, with no matching directory entry.** It is listed in `unanswered` with the error `unsupported`, rather than counted as answering "no agent".
- **CAP-16C.impl4. How `shares` triggers the live lookup.** `GET /v1/capabilities` and `GET /v1/capabilities/{name}` take `?lookup=true`; `shares`, `capability list`, and `capability show` use it. Without it, the daemon uses its in-memory cache, and an agent not looked up since the daemon started reads `unanswered`.
- **CAP-16C.impl5. Which recipients carry `agent_state`.** Only `agent:` recipients; other recipients keep exactly `{network_id, principal, label}`.
- **CAP-16C.impl6. Where `for_agents` appears in `discover`.** Only on agent-only capabilities, which keep all their `via` entries. Capabilities the owner can call keep only their `from_agent: null` entries, as in slice 2.
- **CAP-16C.impl7. `discover --from-agent` with PERSON or `--network`.** Accepted, narrowing as in `discover`; with neither, the output equals the agent's `list_capabilities`.
- **CAP-16C.impl8. Which principals the `unshare` fallback lists for `PERSON/AGENT`.** Those on hosts bound to the person and on every host no longer in the network, since a revoked host's binding leaves with it.
- **CAP-16C.impl9. The `shares --json` layout.** Not shared (Go and Rust already differ); each agent recipient object in it is exactly `{network_id, principal, label, agent_state, unshare}`, and the printed `unshare` command (in `shares` and in `unshare`'s note) uses `HOST_ID/AGENT_NAME` for a found agent, never the person's label, so it is unambiguous and shell-safe, and otherwise the raw principal.
- **CAP-16C.impl10. Review wording.** The exact recipient, `Not checked:`, agent paragraph, and trusted-own-agent lines, including a wording for a host bound to no person; and dropping the unreachable "name shared by two agents" case from Verification (names are unique within a host), keeping its refusal as defensive behavior.

#### CAP-16D: resource bounds and the `gh` source

- **Source:** [capabilities-slice3-bounds-sources-proposal.md, Owner decisions needed](capabilities-slice3-bounds-sources-proposal.md#owner-decisions-needed), decisions 1–17 (proposal [PR #75](https://github.com/peerspan/peerspan-internal/pull/75)).
- **Contract section:** [Resource bounds and the `gh` source](capabilities-contract.md#resource-bounds-and-the-gh-source-slice-3).
- **Implemented in:** [PR #80](https://github.com/peerspan/peerspan-internal/pull/80).

##### CAP-16D.1. Where bounds live

- **Options:** (a) per capability, set at create, local only; (b) per share, in a local table keyed by network, capability, and principal; (c) per share, in policy v2 as a new capability-rule line.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It needs no policy change, keeps repository names away from coordination, and one capability per scope is easy to explain. (c) puts argument values in front of the coordinator and changes the format again.

##### CAP-16D.2. How MCP tools are bounded

- **Options:** (a) generic argument combinations checked against the snapshot schema; (b) no MCP bounds in this slice, `gh` only; (c) Peerspan-shipped profiles for popular MCP servers, such as GitHub's `owner` and `repo`.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It works for any server with structured arguments and is honest about what it checks. Profiles (c) can be added later as source matchers, but identifying which server a definition is takes guessing.

##### CAP-16D.3. Operations whose schema does not declare the bound argument

- **Options:** (a) refuse at create with `bound_unenforceable`; (b) allow them and mark them unbounded in the review.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** A bounded capability with unbounded operations would be misread as bounded.

##### CAP-16D.4. Showing bounds to recipients

- **Options:** (a) show `bounds` in `discover` and `list_capabilities`, and narrow input schemas; (b) hide them, so callers learn only from refusals.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Callers and agents need the allowed values to make valid calls, and the values go only to authorized principals on the peer path.

##### CAP-16D.5. Wildcards in `gh` repository bounds

- **Options:** (a) exact names plus `OWNER/*`; (b) exact names only; (c) general glob patterns.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** "Everything in our organization" is common, and `OWNER/*` is easy to state and check. General globs make the review harder to read.

##### CAP-16D.6. A call that omits a bound argument

- **Options:** (a) refuse it with `out_of_bounds`; (b) fill in the value when the bound allows exactly one.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Peerspan never changes a call's input, and the narrowed schema already tells callers what to send.

##### CAP-16D.7. How the `gh` adapter runs

- **Options:** (a) a built-in stdio MCP server subcommand in each binary, run through the existing instance machinery; (b) a separate executor inside each daemon with its own call path; (c) one shared implementation in the Node adapter.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Calls, cancellation, uncertainty, concurrency, and logs need no new code, apart from mapping one JSON-RPC error code to `result_too_large`. (c) would make sources depend on Node.

##### CAP-16D.8. The built-in source address

- **Options:** (a) `builtin/NAME`, with `builtin` refused as a new agent name; (b) a separate address form, such as `@gh`, which every address parser must learn; (c) a bare `gh`, which collides with MCP servers named `gh`.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It fits every existing parser and record that uses `AGENT/SERVER`.

##### CAP-16D.9. Which `gh` accounts become sources

- **Options:** (a) every `github.com` account, `gh` for the active one and `gh-LOGIN` for others; (b) the active `github.com` account only; (c) every account on every host, including GitHub Enterprise.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** People with work and personal accounts need to pick one. Enterprise hosts need `GH_ENTERPRISE_TOKEN` and host-qualified names, so they can follow later.

##### CAP-16D.10. Where the `gh` token comes from at call time

- **Options:** (a) captured at discovery with `gh auth token` and stored in `tool_values`; (b) `gh` reads the user's own store (keyring or `hosts.yml`) at call time.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It matches the decision for `${VAR}` values, and works when the daemon cannot reach the desktop keyring. The cost is the same as today: after `gh auth refresh` or a new login, the owner runs `peerspan sources refresh`, and status item 14 says so.

##### CAP-16D.11. The operation set and names

- **Options:** (a) the ten operations above, named after the `gh` command (`issue_list`); (b) read-only operations only in this slice; (c) a larger set including close, merge, review, and workflow runs.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It covers the CLI experience's issue example and common pull-request reading, and three low-risk writes that the review marks. Merges and closes deserve per-call approval (B) first.

##### CAP-16D.12. Free-form search and large diffs

- **Options:** Options for search: (a) left out; (b) allowed, refusing queries with `repo:`, `org:`, `user:`, or `owner:` qualifiers. Options for diffs over 1,000,000 bytes: (a) fail with `result_too_large`; (b) truncate with `truncated: true` in the result.
- **Chosen (the recommendation):** Recommendation: (a) for both.
- **Reason given:** Search filtering is easy to get wrong, and failing matches every other source; `name_only` gives a usable fallback.

##### CAP-16D.13. Changing a bound

- **Options:** (a) remove and create again; (b) a new `capability update` that re-signs nothing but changes the record.
- **Chosen (the recommendation):** Recommendation: (a) for this slice.
- **Reason given:** Records are immutable today, and an update command needs its own rules for running and queued calls.

##### CAP-16D.14. The minimum `gh` version

- **Options:** (a) 2.81.0, for `gh auth status --json`; (b) an older version, parsing the text output of `gh auth status`.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** The text output is not a stable interface, and 2.81.0 is a year old.

##### CAP-16D.15. Telemetry when Peerspan runs `gh`

- **Options:** (a) set `GH_TELEMETRY=0`; (b) leave `gh`'s default. The private `GH_CONFIG_DIR` means the user's own `gh` setting does not apply either way.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Calls made for a peer should not report usage on the owner's behalf without being asked.

##### CAP-16D.16. How general the source-type mechanism is

- **Options:** (a) an internal registry of built-in adapters, with `gh` the only one now; (b) a public plugin interface for third-party adapters.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** A third-party adapter can already be an MCP server, which is a source today. A plugin interface would add a second way to do the same thing.

##### CAP-16D.17. Checking `gh` bound repositories at create

- **Options:** (a) warn when a bound repository is not visible to the credential; (b) refuse; (c) no check.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** A typo is caught early, but a repository the credential cannot see yet, or a network failure, does not block setup.

##### CAP-16D, settled by the implementer (not owner decisions)

These points were left open by the proposal and were settled by the implementer in [PR #80](https://github.com/peerspan/peerspan-internal/pull/80), choosing what fits the proposal best. They are not owner decisions; the owner may revisit them. Each is specified in the contract section above.

- **CAP-16D.impl1. Discovery's edge cases.** When `gh` is too old, its version cannot be read, or no usable `github.com` account is found, discovery sends one definition `gh` with `account` null and `authenticated` false, so `sources` shows why. Definitions carry an `authenticated` field, which the proposal's example lacks, so the daemon can give `not_authenticated`. When no account is active, the first is `gh`. The discovery commands run without `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, and `GITHUB_ENTERPRISE_TOKEN` in their environment, besides ignoring `GH_TOKEN` entries.
- **CAP-16D.impl2. The bound warning runs in the daemon.** The proposal says the CLI runs `repo_view`; only the daemon holds the credential, so it runs the check after creating the capability and returns `warnings` in the `POST /v1/capabilities` response, which the CLI prints.
- **CAP-16D.impl3. The reach check's details.** A 10-second timeout; the error texts; the `token_type` names `oauth`, `classic`, `fine_grained`, `app`, and `unknown`; and a "not checked yet" sentence before the first check. The capability view gains `credential_reach`.
- **CAP-16D.impl4. Bounds details.** A bound on a capability without tool operations is refused; `gh` `repo` bound values must be `OWNER/REPO` or `OWNER/*`; entries within a combination are ordered by name in the texts; the `out_of_bounds` text's `GOT` lists every bound name, in order of first appearance.
- **CAP-16D.impl5. The review and `shares` wording.** The review keeps its existing line layout rather than the proposal's aligned columns. The bounded `gh` reach statement says "The credential reaches more than the bound." before the reach sentence, the no-bound statements end with "No resource bound.", and `shares` uses `Recipients` in place of the principal.
- **CAP-16D.impl6. Execution details.** `--arg` is refused for a built-in source. The call's deadline is enforced by the daemon's existing cancellation rather than passed to the server. Texts the proposal did not give: `gh could not be started.` and `gh failed with exit status N.` (empty standard error); an unknown tool is JSON-RPC `-32602`. Result text copies `gh`'s JSON output byte for byte, and each invalid UTF-8 byte becomes one U+FFFD.
- **CAP-16D.impl7. Output shapes.** `attach`'s `sources` gains `builtin`, and `sources refresh` adds one element for built-in discovery.
- **CAP-16D.impl8. Database version.** 21, the next after machine linking's version 19 and per-call approval's version 20 (PRs #63, #68, and #78, which merged while this PR was open). A version 21 binary migrates databases at versions 0 to 20 and refuses anything above 21.
- **CAP-16D.impl9. Clarifications from conformance.** An out-of-bounds refusal through agent tools is a `rejected` call view with the refusal's text and the never-ran note, as slice 2 gives any refused submission; the `sources` line names the discovered account and version, `unknown` when null; a 200 repeat of `capability create` has `warnings` `[]`; a recheck between `capability remove` and `capability create` rejects every queued call of the capability.
- **CAP-16D.impl10. Approval on a built-in source.** A capability on `builtin/NAME` may require per-call approval; since there is no source agent, no approval notice is created and the call waits for `peerspan approvals` only (found in review).

### CONV: conversations (2026-10-25)

- **Date:** 2026-10-25.
- **Area:** conversations, launch-plan track 3. On 2026-10-16 the owner tabled the track to follow the interface track; on 2026-10-25 the owner chose to start it, designed for the CLI and the agents' Peerspan tools, with a later UI addable without protocol changes.
- **Decision:** the owner accepted every recommendation in the proposal's "Owner decisions needed" list (21 decisions), so the proposal's recommended design is the design for conversations.
- **Source:** [conversations-proposal.md, Owner decisions needed](conversations-proposal.md#owner-decisions-needed) (proposal [PR #76](https://github.com/peerspan/peerspan-internal/pull/76)).
- **Recorded in:** this log and the proposal's status line ([PR #82](https://github.com/peerspan/peerspan-internal/pull/82)).
- **Contract section:** none yet; added when conversations are implemented. Not yet a roadmap milestone.
- **Implementing PRs:** none yet.

Every entry below was decided by accepting the proposal's recommendation, quoted under "Chosen".

#### CONV-1. Which permission authorizes a post

- **Options:**
  - (a) `message.append`, unchanged: whoever may message an agent may talk to it in a conversation.
  - (b) A new policy action `conversation.post`, separate from messages.
  - (c) A new action that `message.append` implies, so owners can later grant conversations without messages.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** A post is a message with context; (b) and (c) change the policy format, test vectors, and coordinators for a distinction no one has asked for yet.

#### CONV-2. Whether being in a conversation lets participants reach each other

- **Options:**
  - (a) No: each recipient's policy governs every author; unreachable pairs are shown and their posts refused for that target.
  - (b) Yes: an authorized invite implies permission from every participant.
  - (c) Opt-in: an owner rule letting "participants of conversations my agent is in" post to it.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** (b) lets one person introduce strangers to someone else's agent, against the owner-decides model; (c) can come later.

#### CONV-3. Who orders membership changes

- **Options:**
  - (a) The creator's host, as home, for the conversation's life.
  - (b) Any participant's host, with a merged roster (add and remove sets) and no single authority.
  - (c) (a), with handing home to another participant later.
- **Chosen (the recommendation):** Recommendation: (a) now, (c) later.
- **Reason given:** One authority makes adds and removes simple and auditable; posting does not depend on it.

#### CONV-4. Who may add and remove participants

- **Options:**
  - (a) The creator only.
  - (b) Any participant may add; only the creator removes.
  - (c) Any participant may add or remove.
- **Chosen (the recommendation):** Recommendation: (a) in slice 1.
- **Reason given:** It keeps "who brought this person in" obvious; (b) can follow once rosters are seen in use.

#### CONV-5. Whether an agent must accept being added

- **Options:**
  - (a) No: an invite that passes the agent owner's `message.append` check joins it, and it can leave.
  - (b) The agent accepts with a tool before posts arrive.
  - (c) The agent's owner accepts.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** The owner already allowed this sender to message the agent; an extra model turn adds cost, not control.

#### CONV-6. How people take part

- **Options:**
  - (a) A person takes part from one bound host, after an explicit `join`, and receives posts from any joined participant not blocked.
  - (b) As (a), but posts to a person also need a policy rule naming the author.
  - (c) People can read and post, but cannot be invited; only agents are participants in slice 1.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Joining is the person's own consent, and they can leave or block; policy rules today name agents, not people.

#### CONV-7. Who may invite a person

- **Options:**
  - (a) Any member host of a shared network that is not blocked, held as pending, at most 20 per sender, expiring after 7 days.
  - (b) Only principals the person lists in a new local allow list.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** An invite carries only a title and note, and nothing reaches the person until they join.

#### CONV-8. What a late joiner sees

- **Options:**
  - (a) Posts from when they joined, plus the inviter's note.
  - (b) Earlier posts, each served by its author's host only if that author's owner allows history for late joiners (a setting per conversation or per host).
  - (c) All earlier posts, by default.
- **Chosen (the recommendation):** Recommendation: (a) in slice 1, (b) in slice 2.
- **Reason given:** Earlier posts were written for the earlier participants; (c) would share them without their authors' consent.

#### CONV-9. How posts are ordered

- **Options:**
  - (a) Lamport clock plus per-author `seq`, display order `(clock, author, seq)`.
  - (b) Vector clocks, showing concurrency explicitly.
  - (c) Each host's arrival order.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Same order on every host once complete, replies after what they answer, and a fixed-size field; (b) grows with participants for little visible gain.

#### CONV-10. What a receiving session gets each turn

- **Options:**
  - (a) The new post with a header, and a window (10 posts, 16 KiB) only on the first event and on catch-up.
  - (b) A window with every event.
  - (c) The new post only, always.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** The session already holds earlier events in its context; repeating them each turn costs tokens, while (c) leaves a new session lost.

#### CONV-11. How to bound back-and-forth between agents

- **Options:**
  - (a) 60 posts per author per conversation per hour, `addressed_to`, and "you need not answer every post" guidance; not counted against `max_sends_per_hour`.
  - (b) As (a), and also counted against `max_sends_per_hour`.
  - (c) Turn-taking: one post per author until someone else posts.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It stops runaway loops without throttling a busy legitimate conversation; (c) breaks multi-step work.

#### CONV-12. Messages and replies

- **Options:**
  - (a) Keep both unchanged beside conversations; no migration.
  - (b) Reimplement messages as two-participant conversations and migrate records.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** One-shot ask-and-answer stays useful and tested; migration risks working behavior for no user gain.

#### CONV-13. Tasks

- **Options:**
  - (a) Slice 1: an optional, informational `about` task link. Slice 2: a task thread between submitter and receiver, authorized by the task itself.
  - (b) Task threads in slice 1.
  - (c) No link between conversations and tasks.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Threads need their own authorization rule (like replies to accepted work), which deserves its own review.

#### CONV-14. How long posts are kept

- **Options:**
  - (a) Until the owner runs `conversation forget`.
  - (b) Pruned automatically, for example 90 days after the last post.
- **Chosen (the recommendation):** Recommendation: (a) for now, matching messages, which have no deletion; revisit with the UI.
- **Reason given:** (none beyond the recommendation)

#### CONV-15. Which agents get the conversation tools

- **Options:**
  - (a) Sessions with directory access (every `attach` session), refusing otherwise with `no_directory`.
  - (b) A new `attach --conversations` opt-in, like `--calls`.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Conversations use the same addressing and authorization as `send --to`; a second prompt adds friction without new reach.

#### CONV-16. Telling an author about undelivered posts

- **Options:**
  - (a) One `conversation_undelivered` event per final failure.
  - (b) Nothing; failures show only in views and `conversation_history`.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** An agent should know a participant missed its post; successes stay silent.

#### CONV-17. How long the author's host keeps pushing

- **Options:**
  - (a) 24 hours, then the recipient fetches on sync.
  - (b) 1 hour, as agent sends.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** Conversations last longer than one request, and sync covers anything later.

#### CONV-18. Participants on the same host

- **Options:**
  - (a) Allowed: a post to a local participant is delivered locally, under self access.
  - (b) Refused with `local`, as sends by address are.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** A person with Claude Code and Codex on one laptop is the simplest useful conversation, and nothing crosses a trust boundary.

#### CONV-19. Closing

- **Options:**
  - (a) The creator can close; a closed conversation is read-only.
  - (b) No close; only leaving.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It gives the design's "close" operation and a clear end for agents.

#### CONV-20. Command names

- **Options:**
  - (a) `peerspan conversations` and `peerspan conversation start|show|say|watch|add|remove|join|decline|leave|close|read|forget`, in the root help beside `send` and `task`.
  - (b) Shorter top-level verbs, such as `peerspan talk` and `peerspan say`.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** It matches `capability` and `calls`, and stays clear as subcommands grow.

#### CONV-21. First slice scope

- **Options:**
  - (a) Agents and people together, as in [Slices](conversations-proposal.md#slices).
  - (b) Agents only first; people from the CLI in the next slice.
- **Chosen (the recommendation):** Recommendation: (a).
- **Reason given:** The CLI is the only human surface today, and people in the conversation are the multiplayer case worth proving first.

### LIVE-5: protocol_version from every adapter (2026-10-25)

- **Date:** 2026-10-25.
- **Area:** live delivery, adapters (Claude Code, Codex, OpenCode).
- **Background:** the capability live test ([PR #54](https://github.com/peerspan/peerspan-internal/pull/54)) found the adapter connection's `protocol_version` was `2025-11-25` for Claude Code but null for the Codex and OpenCode sidecars, and the contract did not say whether they must report it.
- **Decision:** first, Codex and OpenCode integrations must report a version, as Claude Code does. The owner then chose among the options in LIVE-5.1 to LIVE-5.4, taking the recommendation in each case.
- **Source:** [live-delivery-proposal.md, Decisions](live-delivery-proposal.md#decisions), "Settled with the owner on 2026-10-25". The repo records only the chosen options; the alternatives below are recorded here from the owner's decision.
- **Contract section:** [live delivery contract, Doctor](live-delivery-contract.md#doctor) (`mcp_protocol`).
- **Recorded and implemented in:** [PR #66](https://github.com/peerspan/peerspan-internal/pull/66).

#### LIVE-5.1. The value OpenCode reports

- **Options:**
  - O1: `opencode-plugin-<server version>` in `protocol_version`.
  - O2: a fixed `opencode-plugin`.
  - O3: a separate new field, keeping `protocol_version` MCP-only (needs a migration).
- **Chosen:** O1, the recommendation. As recorded: "OpenCode: it has no MCP session with Peerspan, so it reports `opencode-plugin-VERSION`, the server version from `GET /global/health`, rather than a separate field."

#### LIVE-5.2. How Codex attributes the value, and when it reports it

- **Options:**
  - C2: `mcp.mjs` sends `protocol_version` with each `POST /tool`, accepted only from the selected thread.
  - C1: report at MCP initialize through a new tool-socket route, which is not attributable to a thread.
- **Chosen:** C2, the recommendation. As recorded: "Codex: `mcp.mjs` sends its negotiated MCP revision with each `POST /tool`. The sidecar accepts it only from calls whose `_meta.threadId` is the selected thread."

#### LIVE-5.3. A value that arrives late

- **Options:**
  - R1: the adapter reconnects as soon as the value changes, before its next daemon request.
  - R2: wait for the 5-second renewal.
- **Chosen:** R1, the recommendation. As recorded: "Reporting: the adapter connects again as soon as the value changes, before its next daemon request." PR #66 adds: "so the daemon has it before `POST /adapter/v1/ready`."

#### LIVE-5.4. What doctor checks

- **Options:**
  - Scope the `2026-07-28` failure to Claude Code only; a missing value is not a doctor failure.
  - Also fail a verified agent that never reported a version.
- **Chosen:** the first, the recommendation. As recorded: "Doctor: the `2026-07-28` failure applies to the Claude Code harness (`claude-code`) only, and a missing value is not a failure."

### LAUNCH-34: the attach --no-start sign-in check (2026-10-24)

- **Date:** 2026-10-24/25, while fixing the capability live test.
- **Area:** launch, `attach`; the capability live test (`conformance/live_capability_agents.py`).
- **Question:** `attach claude --no-start` runs Claude Code's readiness checks, which require a sign-in. The live test's pretend person, Bob, had a temporary HOME with no Claude login, so setup failed before any harness ran. Should attach keep requiring a sign-in with `--no-start`?
- **Options:**
  - (a) Keep: attach checks that Claude Code is signed in even with `--no-start`, and the live test gives its pretend person a login.
  - (b) Loosen: with `--no-start`, a missing sign-in is only a warning.
- **Chosen:** (a). The live test links the operator's Claude login (`~/.claude/.credentials.json`) into Bob's HOME; Bob never starts Claude Code.
- **Reason given:** not recorded in the repo.
- **Source:** [PR #54](https://github.com/peerspan/peerspan-internal/pull/54) description and commit `5853778`, and the comments in `conformance/live_capability_agents.py`. The options are recorded here from the owner's decision; the repo records only the outcome.
- **Contract section:** none; `attach` behavior is unchanged. See [Attach launches](launch-contract.md#attach-launches) for `attach`.
- **Implemented in:** [PR #54](https://github.com/peerspan/peerspan-internal/pull/54).

### CAP-15: call timing (2026-10-23)

- **Date:** 2026-10-23.
- **Area:** capabilities, agent capability tools (slice 2).
- **Question:** how `call_capability` learns a call's result, and how long it may wait. Before this decision the tool waited up to `wait` seconds (default 30, at most 60), and the adapter and the caller's daemon checked status once a second for a call's first 60 seconds.
- **Options:**
  - Results: the owner chose "option 1", held requests instead of 1-second polling. The other options are not preserved in the repo.
  - Limit: the owner chose "option A", a fixed 15-second wait limit as one daemon constant, configurable in a release. The other options are not preserved in the repo.
  - Searched: the contract's history (`git log -p -S` on `docs/capabilities-contract.md`, from `564768b` "Record decision 15: a 15-second call wait and held status requests") and the PR #42 description. Both record only the chosen design.
- **Chosen,** as the contract records it:
  - "**Wait limit.** `call_capability` returns within 15 seconds of being called, everything included, and answers `queued` or `running` when the call has not finished; the result then arrives as a `call_update` event. An agent may ask for less, never more. The limit is one constant in the daemon, changed in a release; the adapter and the tool description do not repeat it. An owner setting for it may be added later."
  - "**Results without polling.** The caller's daemon holds a status request open at the serving host (`GET /peer/v1/calls/{id}?wait=10`), and the adapter's call request is held open at the daemon, so a result arrives as soon as it exists instead of on a once-a-second check. A push from the serving host to the caller may be added later; hosts that predate the held request are polled every second as before."
- **Possible later:** an owner setting for the limit, and a push from the serving host to the caller.
- **Reason given:** not recorded beyond the decision text ("so a result arrives as soon as it exists instead of on a once-a-second check").
- **Source and contract section:** [capabilities contract, decision 15](capabilities-contract.md#owner-decisions); specified under [Adapter routes](capabilities-contract.md#adapter-routes) ("Results without polling", "The wait limit"). It supersedes the waiting parts of CAP-13 and CAP-14.
- **Recorded and implemented in:** [PR #42](https://github.com/peerspan/peerspan-internal/pull/42) (contract, adapter, Go, Rust, and the agent tools suite).

## Index of earlier decisions

Owner decisions recorded across the docs before this log, oldest first within each area. Each row gives the decision in one line; the linked section is the record. "Options" quotes the options where a source records them, including earlier versions of a proposal in git history; otherwise it says "options not recorded".

Not included: the [peer messaging proposal](peer-messaging-proposal.md#decisions-still-to-validate)'s "Decisions still to validate" and the [connectivity evaluation](connectivity-evaluation.md#admission-and-the-current-decision), which record open questions and an engineering evaluation, not owner decisions; and the `mesh-new` system design and `docs-internal` documents, which are outside this repository.

### Roadmap and access model

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| ROAD-1 | 2026-10-05 | The production roadmap's working sequence of milestones. | Options not recorded here; the decisions behind it are in the `mesh-new` system design under "Enrollment and reachability decisions". | [Roadmap, status](production-roadmap.md) |
| ROAD-2 | 2026-10-07 | Order: milestone 6 (delegation), then 2c (direct propagation), then 7 (launch readiness). | Options not recorded. | [Roadmap](production-roadmap.md) |
| ACC-1 | 2026-10-06 | Membership, ownership, and access are separate: administrators decide which hosts belong, whoever runs a host owns it and its agents, and only an agent's owner decides access to it. Membership and administration grant no access. Network-wide guardrails remain a future decision. | Options not recorded. | [Access model](access-model.md) |

### Person identity (milestone 2b)

Settled on 2026-10-06; the decisions replace the original recommendations where they differ. The original proposal (`9e0267a`) listed a recommendation and alternatives for seven of the ten questions.

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| PI-1 | 2026-10-06 | Person keys are `ssh-ed25519` only, signed in OpenSSH `SSHSIG` format through `ssh-agent`; `--person-key PATH` falls back to a key file. Hardware security keys out of scope. | At `9e0267a`, "Where person keys live": recommended "CLI-held key file outside host state; `ssh-agent` signing as a follow-up"; alternatives "Held by one designated host daemon; hardware keys from the start". The decision made `ssh-agent` primary. | [Decisions](person-identity-proposal.md#decisions) |
| PI-2 | 2026-10-06 | Administrators admit hosts, as today; persons are an optional layer they also admit. | At `9e0267a`: recommended "Persons, who then bind their own hosts"; alternative "Keep admitting hosts, with persons optional on top". The decision took the alternative. | [Decisions](person-identity-proposal.md#decisions) |
| PI-3 | 2026-10-06 | Join flows, for persons and hosts alike: a one-time invite token, or an administrator admitting a public key directly, plus a non-secret network descriptor. | Options not recorded. | [Decisions](person-identity-proposal.md#decisions) |
| PI-4 | 2026-10-06 | Host binding is valid with the person's signature and the host's own submission; no administrator step. | Options not recorded. | [Decisions](person-identity-proposal.md#decisions) |
| PI-5 | 2026-10-06 | A root rotation re-signs person admissions; person removal and host unbinding are signed, sticky, and permanent. | Options not recorded. | [Decisions](person-identity-proposal.md#decisions) |
| PI-6 | 2026-10-06 | Groups are defined and versioned by administrators; owners choose whether to grant to a group or to named persons. | At `9e0267a`: recommended "Administrator-defined, versioned; owners choose whether to grant to groups"; alternative "Owner-defined groups only (no administrator influence on access at all, more toil)". | [Decisions](person-identity-proposal.md#decisions) |
| PI-7 | 2026-10-06 | Policy validity is chosen by the owner per policy, 1–90 days, default 7, re-signed automatically while the key is available. | At `9e0267a`: recommended "7 days, re-signed automatically while the person key is available"; alternatives "Longer (more outage tolerance, slower withdrawal); no expiry (rely on local revocation only)". | [Decisions](person-identity-proposal.md#decisions) |
| PI-8 | 2026-10-06 | Disconnected use needs `allow_disconnected` on a policy rule and ends at `valid_until`; manual host grants unchanged. | At `9e0267a`: recommended "Bounded by `valid_until`"; alternative "Allow manual host grants to keep longer disconnected validity, as today". | [Decisions](person-identity-proposal.md#decisions) |
| PI-9 | 2026-10-06 | A request names the policy owner and version; the receiver checks its newest verified copy. | At `9e0267a`: recommended "Request names policy owner and version"; alternative "Keep `grant_id`, with policies materialized into local grants on each host". | [Decisions](person-identity-proposal.md#decisions) |
| PI-10 | 2026-10-06 | The root key is kept offline after delegation, used only to delegate or revoke administrators and to rotate. | At `9e0267a`: recommended "kept offline, used only to delegate administrators and rotate"; alternative "Stays on the creator's host, as today". | [Decisions](person-identity-proposal.md#decisions) |

### QUIC and relays (milestones 3 and 4)

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| QR-1 | 2026-10-06 | The peer transport moves to QUIC before relays are built. | For the relay carrier: "a TCP splice of the existing peer TLS (recommended) or moving the peer transport to QUIC now. The decision was to move to QUIC now." The proposal's table also lists "WireGuard as the only transport" as the alternative. | [How this design was reached](quic-relay-proposal.md#how-this-design-was-reached), [Decisions to settle](quic-relay-proposal.md#decisions-to-settle) |
| QR-2 | 2026-10-06 | The relay runs inside `peerspan-coord`. | Options not recorded. | [Status](quic-relay-proposal.md) |
| QR-3 | 2026-10-06 | Only network members may use the relay. | Options not recorded. | [Status](quic-relay-proposal.md) |

The proposal's other rows (application protocol over QUIC, relay carrier, cutover, coordinator API, dependencies) list a recommendation and an alternative, but the proposal does not record an owner decision on them.

### Coordination

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| COORD-1 | 2026-10-07 | Delegated administrators do everything except govern the root; only the root delegates or removes administrators and rotates. | Options not recorded. | [Administrators and groups](coordination-contract.md#administrators-and-groups) |
| COORD-2 | 2026-10-07 | Removing an administrator keeps what they admitted, unless the removal says otherwise. | Options not recorded. | [Administrators and groups](coordination-contract.md#administrators-and-groups) |
| COORD-3 | 2026-10-07 | The root can go offline by rotating to an SSH key. | Options not recorded. | [Administrators and groups](coordination-contract.md#administrators-and-groups) |
| COORD-4 | 2026-10-07 | `network create` makes the creator's person the first administrator. | Options not recorded. | [Administrators and groups](coordination-contract.md#administrators-and-groups) |
| COORD-5 | 2026-10-07 | A request is authorized by a manual grant or by the target agent owner's policy; a host-local block list overrides both. | Options not recorded. | [Owner access policy](coordination-contract.md#owner-access-policy) |
| COORD-6 | 2026-10-07 | Daemons renew policies by asking the owner's `ssh-agent`, and never hold the key (except a CLI-generated key). | Options not recorded. | [Owner access policy](coordination-contract.md#owner-access-policy) |
| COORD-7 | 2026-10-07 | Every member sees every policy. | Options not recorded. | [Owner access policy](coordination-contract.md#owner-access-policy) |
| COORD-8 | 2026-10-07 | An owner's hosts also pass policies to each other directly (roadmap 2c). | Options not recorded. | [Owner access policy](coordination-contract.md#owner-access-policy) |
| COORD-9 | 2026-10-08 | Only the owner's own hosts receive policies directly, by push plus periodic sync; block lists stay host-local. | Options not recorded. | [Direct propagation](coordination-contract.md#direct-propagation) |
| COORD-10 | 2026-10-18 | A policy edit that loses to a concurrent one is kept by its host and re-applied on top of the winner; the coordinator is not involved. See also CAP-11. | Options not recorded. | [Concurrent edits](coordination-contract.md#concurrent-edits) |

### Delegation (milestone 6)

Settled on 2026-10-07. The original proposal (`8174492`) listed a recommendation and alternatives for each.

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| DEL-1 | 2026-10-07 | The final receiver checks originator and sender. | At `8174492`: recommended "Originator and sender"; alternatives "Originator only, with the sender as a conduit. Sender only, with the chain merely informational." | [Decisions](delegation-proposal.md#decisions) |
| DEL-2 | 2026-10-07 | Host-asserted agent origin now; agent keys come with isolated runtimes. | At `8174492`: recommended as decided; alternative "Per-agent keys now, which adds little under one OS account". | [Decisions](delegation-proposal.md#decisions) |
| DEL-3 | 2026-10-07 | Only where the receiving owner's rule includes `task.delegate`, and the incoming link allows further delegation. | At `8174492`: recommended as decided; alternative "Any authorized recipient may delegate within the chain". | [Decisions](delegation-proposal.md#decisions), [chain contract](delegation-chain-contract.md#who-may-delegate-decision-3) |
| DEL-4 | 2026-10-07 | Maximum chain depth: 3 hops past the originator. | At `8174492`: recommended as decided; alternatives "Configurable per rule; unlimited, bounded by expiry". | [Decisions](delegation-proposal.md#decisions) |
| DEL-5 | 2026-10-07 | Chain format: Peerspan's own minimal line-encoded links with Ed25519 host signatures. | At `8174492`: recommended "Own minimal line-encoded links"; alternative "Biscuit tokens (a Datalog policy language, plus a library dependency in each language)". | [Decisions](delegation-proposal.md#decisions) |
| DEL-6 | 2026-10-07 | Cancellation propagates downstream best-effort; each hop reports the outcome. | At `8174492`: recommended as decided; alternative "Cancellation only at the immediate receiver". | [Decisions](delegation-proposal.md#decisions), [chain contract](delegation-chain-contract.md#cancellation-decision-6) |
| DEL-7 | 2026-10-07 | Text input and results up to 64 KiB, plus input and result artifacts (pulled by hash, 100 MiB each, 1 GiB per task, 10 GiB per host, kept 7 days), off unless a rule sets `max_artifact_bytes`. | At `8174492`: recommended "Bounded text results (64 KiB) first; artifacts and streaming later"; alternative "Large results and artifacts in milestone 6". The decision included artifacts in milestone 6. | [Decisions](delegation-proposal.md#decisions) |
| DEL-8 | 2026-10-07 | Milestone 6 scope: agent origin, tasks with artifacts, delegation chains, and live acceptance; tools and conversations later. | At `8174492`: recommended "Tasks and chains; tools and conversations later on the same envelope"; alternative "Include remote tools now". | [Decisions](delegation-proposal.md#decisions) |

### Launch readiness (milestone 7)

The proposal's numbered references (1) to (5) point to its own sections; the proposal records no alternatives for them.

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| LAUNCH-1 | 2026-10-08 | Onboarding targets a small team (3 to 10); the same commands cover solo and pair use. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-2 | 2026-10-08 | A hosted default coordinator built into the CLI, overridable for self-hosting. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-3 | 2026-10-08 | The daemon is installed as a user service; foreground `run` stays. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-4 | 2026-10-08 | Low-level commands stay, hidden behind `help advanced`. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-5 | 2026-10-08 | Addressing through a directory derived from authorization, with `person/agent` names; explicit routes stay as an advanced option. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-6 | 2026-10-08 | Expiries optional everywhere, with defaults; sessions renew while live, reversing the quick start's no-renewal rule. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-7 | 2026-10-08 | Name `peerspan` (originally `capsule`), with `peerspan-host` as an alias. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-8 | 2026-10-08 | `attach` registers the agent if needed. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-9 | 2026-10-08 | `allow` defaults to messages and tasks; files and delegation are opt-in. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-10 | 2026-10-08 | `allow` without `--agent` covers all of the owner's agents through `*`. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-11 | 2026-10-08 | Self access: everything, up to 1 GiB of artifacts, with no policy. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-12 | 2026-10-08 | Hosted limits: modest caps as configurable `peerspan-coord` flags, returning 429. | Options not recorded. | [Decisions](launch-proposal.md#decisions) |
| LAUNCH-13 | 2026-10-09 | Agent names are unique per person across their hosts; `attach` picks a suffixed name when the default is taken rather than failing. | Options not recorded. | [Decisions](launch-proposal.md#decisions), [Slice 4](launch-contract.md#slice-4-directory-and-addressing) |
| LAUNCH-14 | 2026-10-09 | `attach` sessions may reach any agent in the directory, at most 100 sends and delegations per hour by default. | Options not recorded. | [Decisions](launch-proposal.md#decisions), [Slice 4](launch-contract.md#slice-4-directory-and-addressing) |
| LAUNCH-15 | 2026-10-09 | The directory shows whether an agent has a connected session. | Options not recorded. | [Decisions](launch-proposal.md#decisions), [Slice 4](launch-contract.md#slice-4-directory-and-addressing) |
| LAUNCH-16 | 2026-10-08 | Builds take the hosted coordinator from build-time variables until the hosted instance exists. | Options not recorded. | [Slice 2](launch-contract.md#slice-2-service-and-coordinator) |
| LAUNCH-17 | 2026-10-08 | `install` always enables systemd lingering on Linux. | The proposal's first version left open "Whether `install` should offer to enable systemd lingering"; options not otherwise recorded. | [Slice 2](launch-contract.md#slice-2-service-and-coordinator) |
| LAUNCH-18 | 2026-10-08 | The installed daemon listens for peers on UDP port 7401 on all interfaces by default. | Options not recorded. | [Slice 2](launch-contract.md#slice-2-service-and-coordinator) |
| LAUNCH-19 | 2026-10-09 | `network create` and `join` generate a person key when none is found. | Revised the same day from "failing without one"; options not otherwise recorded. | [Slice 3](launch-contract.md#slice-3-team-onboarding) |
| LAUNCH-20 | 2026-10-09 | `allow` sets a principal's access for an agent scope, rather than adding to it. | Options not recorded beyond "rather than adding to it". | [Slice 3](launch-contract.md#slice-3-team-onboarding) |
| LAUNCH-21 | 2026-10-09 | Self access works while out of sync with coordination. | Options not recorded. | [Slice 3](launch-contract.md#slice-3-team-onboarding) |
| LAUNCH-22 | 2026-10-09 | `deny` without `--agent` removes the principal from every rule. | Options not recorded. | [Slice 3](launch-contract.md#slice-3-team-onboarding) |
| LAUNCH-23 | 2026-10-09 | Each machine in the scripted acceptance run is a temporary Linux user on one host, with a real systemd user service. | Options not recorded. | [Slice 5](launch-contract.md#slice-5-acceptance) |
| LAUNCH-24 | 2026-10-09 | The scripted run executes exactly the commands the quick start documents, and fails if any other step is needed. | Options not recorded. | [Slice 5](launch-contract.md#slice-5-acceptance) |
| LAUNCH-25 | 2026-10-09 | The live run has three Claude Code sessions use the directory and a two-link delegation, with no routes. | Options not recorded. | [Slice 5](launch-contract.md#slice-5-acceptance) |
| LAUNCH-26 | 2026-10-09 | The live run uses the operator's existing Claude Code login for all three sessions, with each person's Peerspan state isolated. | Options not recorded. | [Slice 5](launch-contract.md#slice-5-acceptance) |
| LAUNCH-27 | 2026-10-09 | `attach` launches the session itself. | Options not recorded. | [Slice 5](launch-contract.md#slice-5-acceptance) |
| LAUNCH-28 | 2026-10-09 | The coordinator pushes change notifications, so hosts learn of joins and policies at once rather than at the next 30-second sync. | Options not recorded; decided after the first acceptance runs failed on that latency. | [Slice 5](launch-contract.md#slice-5-acceptance) |
| LAUNCH-29 | 2026-10-09 | An agent's delegation by address may allow onward hops, opt-in per task. | Options not recorded. | [Slice 5](launch-contract.md#slice-5-acceptance) |
| LAUNCH-30 | 2026-10-14 | A host's directory learns of another host's session connecting or disconnecting when it happens, not at the next 5-minute refresh. | See LAUNCH-33. | [Slice 6](launch-contract.md#slice-6-presence-notifications) |
| LAUNCH-31 | 2026-10-14 | The host whose presence changed announces it through the coordinator relay, so hosts without `--peer-listen` are told too. | Options not recorded. | [Slice 6](launch-contract.md#slice-6-presence-notifications) |
| LAUNCH-32 | 2026-10-14 | The announcement is only a signal: receivers refresh that one host through the existing peer route, and the coordinator carries no agent names, sessions, or authorizations. | Options not recorded. | [Slice 6](launch-contract.md#slice-6-presence-notifications) |
| LAUNCH-33 | 2026-10-14 | Presence by announcement, not by timed refresh. | "a timed refresh of stale entries was rejected in favour of this." | [Slice 6](launch-contract.md#slice-6-presence-notifications) |
| LAUNCH-34 | 2026-10-24 | `attach --no-start` keeps checking that Claude Code is signed in. | Full entry above. | [LAUNCH-34](#launch-34-the-attach---no-start-sign-in-check-2026-10-24) |

### Hosted coordinator (milestone 8)

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| HC-1 | 2026-10-09 | Cerebral Systems runs one `peerspan-coord` on one cloud VM with a static address, as a systemd service. | Options not recorded. | [Decisions](hosted-coordinator-proposal.md#decisions) |
| HC-2 | 2026-10-09 | A coordinator move is part of this milestone. | Options not recorded. | [Decisions](hosted-coordinator-proposal.md#decisions) |
| HC-3 | 2026-10-09 | Key custody: on disk in the database, continuous encrypted backups, and an offline encrypted copy held by the owner, with a tested restore. | Options not recorded. | [Decisions](hosted-coordinator-proposal.md#decisions) |
| HC-4 | 2026-10-09 | A loopback health and metrics endpoint, and structured logs without payloads or keys. | Options not recorded. | [Decisions](hosted-coordinator-proposal.md#decisions) |
| HC-5 | 2026-10-10 | Move authority: both. The operator's coordinator-signed successor moves every hosted network; a move signed by the network root or a delegated administrator moves one network and always takes precedence. | Options not recorded beyond the answer "both". | [Decisions](hosted-coordinator-proposal.md#decisions) |
| HC-6 | 2026-10-10 | Repair: any member host re-submits signed statements a coordinator lacks, with no administrator needed. | Options not recorded. | [Decisions](hosted-coordinator-proposal.md#decisions) |
| HC-7 | 2026-10-10 | Launch: Hetzner Cloud; a DNS name the owner provides; a runbook plus an install script over SSH, no infrastructure as code yet; the owner runs every outward-facing step with their own credentials; port 443 for TCP and UDP. | Options not recorded. | [Slice 4](hosted-coordinator-contract.md#slice-4-launch) |
| HC-8 | 2026-10-11 | The install script also supports Ubuntu 24.04, uses ufw when active, and takes `--no-firewall`, so the coordinator can share a VM. | Options not recorded. | [Slice 4](hosted-coordinator-contract.md#slice-4-launch) |

### Live delivery (milestone 9)

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| LIVE-1 | 2026-10-10 | Readiness: a handshake at launch, costing one brief model turn. | Alternative named: "heuristics alone". | [Decisions](live-delivery-proposal.md#decisions) |
| LIVE-2 | 2026-10-10 | Orphans: the same agent's new session adopts running tasks. | Options not recorded. | [Decisions](live-delivery-proposal.md#decisions) |
| LIVE-3 | 2026-10-10 | Redelivery: work the model provably never saw goes to the next session. | Options not recorded. | [Decisions](live-delivery-proposal.md#decisions) |
| LIVE-4 | 2026-10-10 | Deadline: agent sends wait 1 hour, as CLI sends and delegations do. | Options not recorded. | [Decisions](live-delivery-proposal.md#decisions) |
| LIVE-5 | 2026-10-25 | Codex and OpenCode adapters report `protocol_version`. | Full entry above. | [LIVE-5](#live-5-protocol_version-from-every-adapter-2026-10-25) |

### Remote tools and credentials (milestone 10, before the capability model)

Settled on 2026-10-16 for the MCP-specific proposal. The shareable-capability model (RT-12) supersedes RT-10 and CRED-2 and CRED-4; the entries stay as history. The proposal's first version (`c796a56`) listed "Open decisions" with a proposed answer and an alternative; they are quoted where they match.

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| RT-1 | 2026-10-16 | Discovery, not registration: servers come from the harness configuration; the only explicit step is sharing. | At `c796a56`, "What a capability is": "Host-registered MCP servers (proposed), or also session tools from the start." The decision dropped registration. | [Decisions](remote-tools-proposal.md#decisions) |
| RT-2 | 2026-10-16 | Read-only by default without a narrower credential, with the reach stated. | See CRED-4. | [Decisions](remote-tools-proposal.md#decisions) |
| RT-3 | 2026-10-16 | `${VAR}` secrets are captured at `attach`. | "A per-user environment file is the alternative." | [Decisions](remote-tools-proposal.md#decisions) |
| RT-4 | 2026-10-16 | The first time a server is shared, `allow` shows the credential's reach and the owner confirms it once. | See CRED-4. | [Decisions](remote-tools-proposal.md#decisions) |
| RT-5 | 2026-10-16 | Policy v2 is a clean break, with coordinators upgraded first. | At `c796a56`: "Policy v2 as a clean break (proposed), or a separate capability policy statement." | [Decisions](remote-tools-proposal.md#decisions) |
| RT-6 | 2026-10-16 | Self access covers tools only from hosts the person marks trusted, listed in the signed policy; `join` and `network create` ask, defaulting to no. Replaces the proposed `allow self --tools` opt-in. | At `c796a56`, "Self access": "Excluded from capabilities unless allowed (proposed), or covered like everything else." | [Decisions](remote-tools-proposal.md#decisions) |
| RT-7 | 2026-10-16 | Calls are persisted and asynchronous only. | At `c796a56`: "Persisted asynchronous calls with a 60-second wait in the MCP tool (proposed), or a synchronous route for short calls as well." | [Decisions](remote-tools-proposal.md#decisions) |
| RT-8 | 2026-10-16 | Server, profile, and tool names in policy being visible to coordination is accepted for now. | At `c796a56`: "Accept this, or hash the names in signed rules." | [Decisions](remote-tools-proposal.md#decisions) |
| RT-9 | 2026-10-16 | Default budget: 100 calls per hour per caller and rule. | At `c796a56`: "For example, 100 calls per hour per caller and capability, like the session send cap." | [Decisions](remote-tools-proposal.md#decisions) |
| RT-10 | 2026-10-16 | One thing to share: the server. Superseded by RT-12. | Options not recorded. | [Decisions](remote-tools-proposal.md#decisions) |
| RT-11 | 2026-10-16 | The environment file is scoped to each server: a server receives only the variables its own definition names. | Options not recorded. | [Decisions](remote-tools-proposal.md#decisions) |
| RT-12 | 2026-10-16 | The public unit is the shareable capability: one coherent use case with defined operations or resources and stated credential reach, backed by an MCP server or a bounded CLI operation; a resource restriction is optional. | Options not recorded; it replaced whole-server sharing (RT-10). | [Status](remote-tools-proposal.md), [capabilities contract](capabilities-contract.md) |
| CRED-1 | 2026-10-16 | Shared servers are discovered from harness configuration at `attach`; they start unshared. | Options not recorded. | [Decisions](tool-credentials.md#decisions) |
| CRED-2 | 2026-10-16 | Without a narrower credential a share covers read-only tools; write tools need a narrower credential or approval of each call. Replaced under the capability model. | The analysis lists five ways to narrow a share, under [Narrowing what a credential can reach](tool-credentials.md#narrowing-what-a-credential-can-reach): "A narrower credential for each share, enforced by the provider (primary)", "Argument rules, enforced by Peerspan (secondary)", "Profiles for popular servers (convenience)", "Approval of each call (fallback)", "Isolated runtimes (later)". | [Decisions](tool-credentials.md#decisions) |
| CRED-3 | 2026-10-16 | `${VAR}` secrets are captured at `attach`; a per-user environment file is an alternative whose values take precedence. | Options as stated in the decision. | [Decisions](tool-credentials.md#decisions) |
| CRED-4 | 2026-10-16 | The first time a server is shared, `allow` states the credential's reach and the owner confirms it once. Replaced under the capability model by a review at every share (CAP-4). | At `95e4eaf`, "Is read-only too permissive as a default?": "share nothing until tools are named, even read-only ones; require a narrower credential before any write tool, with no approval route; require the owner to confirm the stated reach once per server." The last was chosen. | [Decisions](tool-credentials.md#decisions) |
| CRED-5 | 2026-10-16, extended 2026-10-17 | Trust is per machine; on 2026-10-17 extended to raw sources behind the serving machine's local open list (CAP-6). | Options not recorded. | [Decisions](tool-credentials.md#decisions) |

### Capabilities (milestone 10, slices 1 and 2)

The first contract version (`fbd2b7c`) listed decisions 1 to 9 as "Owner review points", each with a single proposed answer and no alternatives.

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| CAP-0.1 | 2026-10-16 | Sources are discovered from harness configuration, never registered. | Options not recorded. | [Contract, overview](capabilities-contract.md) |
| CAP-0.2 | 2026-10-16 | The unit people share is a named capability, created explicitly or through the guided share. | Options not recorded. | [Contract, overview](capabilities-contract.md) |
| CAP-0.3 | 2026-10-16 | `${VAR}` values are captured at `attach`; a per-user environment file overrides them, filtered to the names each definition uses. | Options not recorded. | [Contract, overview](capabilities-contract.md) |
| CAP-0.4 | 2026-10-16 | The policy makes a clean break to `peerspan-policy-v2`; capability names in policy are visible to coordination. | Options not recorded. | [Contract, overview](capabilities-contract.md) |
| CAP-0.5 | 2026-10-16 | Calls are persisted and asynchronous only. | Options not recorded. | [Contract, overview](capabilities-contract.md) |
| CAP-0.6 | 2026-10-16 | Self access covers capabilities only from hosts the person has marked trusted, per network. | Options not recorded. | [Contract, overview](capabilities-contract.md) |
| CAP-1 | 2026-10-17 | An MCP tool operation keeps the tool's name; resources are read through one `read` operation. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-2 | 2026-10-17 | Write tools may be selected; the review marks them `(can change things)`; a narrower credential is optional. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-3 | 2026-10-17, revised 2026-10-18 | Each capability rule names its serving host; revised so names are claimed in the person's policy at creation. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-4 | 2026-10-17 | Every `share` shows the review and asks for confirmation; `--yes` skips it. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-5 | 2026-10-17 | `capability remove` also withdraws the capability's shares, signing every affected policy before deleting the record. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-6 | 2026-10-17 | Trusted machines may call raw sources, gated also by the serving machine's local open list; sources are never shared with others. | At `fbd2b7c` the proposed answer was "Self access covers capabilities only, never raw sources"; the owner decided otherwise. No other options recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-7 | 2026-10-17 | `--KEY VALUE` options fill top-level scalar input properties; `call`'s own flags win on a clash. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-8 | 2026-10-17 | After `unshare`, running calls finish and queued ones are refused at start. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-9 | 2026-10-17 | `agent register --capability` is renamed `--label`, with `--capability` kept as an alias. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-10 | 2026-10-18 | Capability names are claimed in the person's signed policy at creation; creating a capability needs the person key. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-11 | 2026-10-18 | Concurrent policy edits are re-applied; a withdrawal wins over a concurrent addition. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-12 | 2026-10-19 | A name no policy binds that the person has on several hosts is 409 `ambiguous` with candidates, not 404. | Options as stated: 409 `ambiguous`, "not 404". | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-13 | 2026-10-19 | Agent capability tools (slice 2): four generic tools, opt-in per agent at `attach`, `max_calls_per_hour` default 100, self access, waiting (superseded by CAP-15), 64 KiB inline results, uncertain-call guidance. | Options not recorded, except "four generic MCP tools ... rather than one MCP tool per remote operation". | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-14 | 2026-10-20 | Slice 2 details: re-attaching, optional `call_id`, tools always listed, calls followed across sessions; waiting superseded by CAP-15. | Options not recorded. | [Owner decisions](capabilities-contract.md#owner-decisions) |
| CAP-15 | 2026-10-23 | Call timing: a 15-second wait limit and held status requests. | Full entry above. | [CAP-15](#cap-15-call-timing-2026-10-23) |
| CAP-16 | 2026-10-25 | Slice 3: every recommendation of the four proposals accepted. | Full entries above. | [CAP-16](#cap-16-capabilities-slice-3-2026-10-25) |

### Guided setup and machine linking

| ID | Date | Decision | Options | Source |
| --- | --- | --- | --- | --- |
| GS-1 | 2026-10-23 | Prioritize guided setup (`peerspan up`) and defer release repository variables; the proposal was accepted in [PR #38](https://github.com/peerspan/peerspan-internal/pull/38). | Options not recorded. | [Guided setup, status](guided-setup-proposal.md) |
| ML-1 | 2026-10-23 | UP-06a, delegated signing and pairing primitives, accepted in [PR #41](https://github.com/peerspan/peerspan-internal/pull/41). | Options not recorded in this repository; the UP-05 design is in `docs-internal`. | [Machine linking contract, status](machine-linking-contract.md) |
| ML-2 | 2026-10-23 | UP-06b, transactions, persistence and recovery, accepted in [PR #43](https://github.com/peerspan/peerspan-internal/pull/43). | Options not recorded. | [Machine linking transactions, status](machine-linking-transactions.md) |

## Coordinator-free preparation clarifications (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation:

- **Cold selection:** verify an existing owner's exact current binding and issuer
  closure for preparation, without adopting it as authority. Preserve the
  separately specified new-original possession-only offer and its reviewed pins.
  This permits first contact while retaining binding/current checks. Discarded:
  unbound person-only shortcuts for existing owners, fabricated prior/second
  import, unrelated same-pass admission, and selection as final consent/adoption.
- **Current retainer proofs:** retain the manifest's exact literal forward DS
  closure; additionally pin known required current retainer/issuer/consent proofs
  in proof_ids. This includes the evidence needed for current scope intersection
  without changing the signed reference graph. Discarded: reverse successor
  discovery in the literal DS closure, omitted current authority evidence,
  proof pins as authority, and rewriting a manifest for later learned evidence.
- **Imported resolvers:** a multi-predecessor statement omitting those IDs from
  resolves is invalid before admission. Apply the same explicit fork relation
  to imported proofs and local preparation. Discarded: a high sequence silently
  healing a fork, admission before validation, or an empty repair diagnostic for
  this complete but malformed typed relationship.
- **Atomic application outcome:** preflight bounded resource capacity, then fix
  the actual guarded decision time/root and generate the bounded host outcome
  signature/optional terminal frame inside the final application transaction.
  Commit outcome, public state/provider/event and secret retirement together.
  This preserves the final current-authority decision and immutable local
  receipt. Discarded: presealed earlier applied_at presented as a later commit,
  a separate prematurely durable outcome, or extending this exception to the
  earlier requester/approver consent/signature/encryption phases.

## Coordinator-free role-specific preapproval (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation: an approved owner
intent may preapprove its own dependency-ready finalization under the exact
reviewed terms, with actual current original-owner authority or device scope4
and scope2 for a new/changed binding. Preapproval of administrator work separately
requires the exact selected path's current scope8/admin authority. Later signing
revalidates the role and current path. This aligns the bootstrap summary with the
runtime's separate owner-finalization and administrator paragraphs. Discarded:
requiring admin8 merely to finish an owner's own bounded approval, letting
owner preapproval stand in for an actual administrator, widened terms or an
alternate signer on resume, and any implicit requester final consent.

## Coordinator-free new-person requested-scope default (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation: the CLI proposes
scopes7 for an unadmitted new original person. Its possession-only preview still
truthfully reports scopes0, and later finalization must use the exact approved
mask under its actual current path. Existing admitted owners keep the default15
capped by their actual path; explicit administrator scope8 requires its actual
grant. This gives the new-person flow a usable bounded default without treating
someone else's administrator approval as the new owner's own admin authority.
Discarded: default0 inferred from possession-only metadata, nominal default15
that assumes a future admin grant, silently widening a reviewed mask after P/H
arrives, and using possession consent as a normal selected signing provider.

## Coordinator-free durable ceremony consent (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation: persist approved
exact typed intent before generating signatures, persist exact signatures and
packet before encryption, then persist exact sealed frames before publication.
Add requester selection/requester_commit intent kinds and their fixed private
packet templates, two pending intent references, and a requester-only owned-key
selector that supplies possession signatures but no network authority. Existing
stage APIs and independent default-no consents stay unchanged. The new frame
barrier observes actual committed bytes, outside writer locks. This makes the
bootstrap's existing durable order expressible and independently crashable in
both implementations. Discarded: calling one atomic approve/sign/seal transaction
three durable boundaries, a generic requester signing provider, reconstructing
consent from an incoming packet, exposing owned requester signing slots, changing
templates on resume, or silently repairing unshipped older pending shapes.

## Coordinator-free legacy status and restriction classification (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation: retain the exact
existing NetworkStatus response fields for a legacy network and add explicit
mode legacy_history and migration_required true. Reads stay local and preserve
historical nullable fields without claiming present coordinator authority.
Discarded: a fabricated DEC NETWORK_VIEW, silently dropping the legacy network,
or using last-sync as a new authority credential.

Inherited migration bans come from verified applicable legacy restrictions and
endorsed admitted history, preserving previously admitted sticky stable-key
bans. Complete evidence omitting a required ban is forbidden; genuinely missing
exact evidence is proof_required. Discarded: treating every restrictive catalog
object as active, forgetting admitted bans after a withdrawal, and conflating a
complete invalid prepared choice with a missing proof.

## Coordinator-free migration possession selectors (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation: use the existing
private host selector only for an exact owned unbound proposal-bound membership
signature and its separate exact acknowledgment. The first uses a dedicated
owner-local typed partial-host-lease handoff: the real root issuer signature is
fixed first, then the actual target host reviews and signs its own role. Only
the complete body enters public prepared evidence. The later acknowledgment
requires a different approval and the complete fixed prepared hash; it alone
fences the legacy network. Owned acknowledgments pin their exact prepared device
lease and actual retained device seed, plus their actual host signature. These
private possession selectors create no ordinary provider/issuer authority.

This makes unbound migration possible without inventing a person/device or
using the root as another host's consent. It also avoids requiring an already
active new context merely to approve that context's migration. Discarded:
arbitrary host signing, a generic unsigned-object catalog/import route, mixing
partial signatures into public catalogs, copying host/device/original keys,
reusing membership approval as acknowledgment, manufacturing current provider
authority for staged keys, and new schema/tables for these bounded typed intents.
The dedicated route adds one explicit reviewed local step; all-known-host/root
consent, original-person approvals, fixed finite ceilings and final adoption
checks remain mandatory.

## Coordinator-free known-source serialization compatibility (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation: compare strictly
decoded descriptor/source-state fields and exact legacy catalog proof-body
tuples when independently reconstructed LOCAL state is checked against a frozen
proposal. Preserve all original endorsed source/descriptor bytes, declared
hashes, signatures, nonce, key and consent. This allows Go/Rust reopening to
survive harmless JSON wrapper order/escaping differences without changing any
authority fact. Actual local root/feature/history must independently verify;
the existing all-known-host/restriction/floor/operation coverage rules remain.

Discarded: treating local JSON serialization as a new authority pin, normalizing
signed proof bodies or proposed source bytes, replacing declared hashes,
ignoring historical coordinator pins, floating-point maxima, dropping new
proof aliases or omitted local facts, and recreating/re-signing a proposal to
hide a representation difference. The exception is compatibility of local
representations only; it does not create semantic signed-object hashes.


## Coordinator-free exact migration evidence carrier (2026-10-26)

Selected within the owner's DEC-01 through DEC-07 delegation: encode every
exact public migration component as canonical standard Base64 in one shared
owner-local/peer/file evidence carrier. Preserve original decoded proposal,
source/state/prepared catalogs, ordered ACKs and commit across ordinary JSON
clients and Go/Rust handoff. Keep all signed hashes, complete-M schema, existing
records and consent/fence/adoption checks. This resolves the independent
contract-only author's observed specification gap: reserializing an inline
catalog object could otherwise change the bytes bound by prepared_catalog_sha256.
No runtime failure or successful interoperability is claimed by this decision.

Discarded: an implicit JSON canonicalization scheme, semantic replacement of
an exact prepared hash, requiring clients to preserve raw nested JSON slices,
fixing only the catalog while other original proof bytes remain exposed to
reserialization, redundant inline-plus-Base64 copies, copying private keys, and
new persistence schema. Standard JSON tools may transform the outer carrier;
the bounded decoded public components retain their exact original bytes.

## Coordinator-free inherited device-ban preparation (2026-10-27)

Selected within the owner's DEC-01 through DEC-07 delegation: expose one typed
copy-only original-person preparation route for the exact required inherited
device bans. Independently derive targets/provenance from the approved source,
fix a durable reviewed migration intent and original SSHSIG slots, and put only
completed copies into prepared evidence. The root's existing preparation can
copy required person/host bans but never signs an owner's device ban. Reuse the
inert shared person head and bounded existing records/signature submission.
This makes the already selected source-preservation rule achievable through
normal native/API setup without hand-authoring signed proofs or activating
pending authority. No runtime result is claimed by this contract decision.

Discarded: dropping inherited denies, root/device substitution, arbitrary new
targets, copied original keys, ordinary action through a staged person, generic
unsigned import/signing, a second schema/intent kind, and manual proof authoring
as the required setup path. All exact source, original/all-host consent,
complete prepared verification and acknowledgment/fence/adoption rules remain.
The exact copy set may be signed throughout the unchanged proposal window,
with current root/person/source rechecks and no renewed issued_at; this avoids
stranding a unique approved intent after300 seconds. Its review includes every
source maximum. The selected original person may differ from the local writer's
roster person, but only that exact original key can sign. Discarded: an extra
300-second expiration for these copies, timestamp refresh, person-filtered
maxima and requiring the writer to own another person's original key.

## Coordinator-free current views and stable linking defaults (2026-10-27)

Selected within the owner's DEC-01 through DEC-07 delegation, following concrete
native workflow failures: add pure v2 person-admission and current-policy reads
from the same guarded verified snapshot as product authorization. Return exact
current P labels and original signed policy bytes; never fabricate legacy
PolicyView signatures or obtain authority from planning heads. This lets native
agents/access/name resolution work without weakening the intentional legacy
parser guard. Discarded: passing DEC records through the old parser, changing
v1 response shapes, using an unsigned effective body as signed legacy evidence,
mutating policy-edit state just to read it or treating a display as authority.

For omitted native owner-approval expiry, select signed request.created_at+7d
capped by actual finite ancestors. This preserves an unchanged preview's exact
terms across a later approval while staying within every actual issuance
ceiling. Discarded: recomputing now+7d on every invocation, an unsigned-preview
read/persistence exception, extending finite ancestors or silently replacing
already reviewed terms. Explicit deadlines remain exact.

Native link admit explicitly recommends network_root by default and displays
that choice before default-no approval; explicit auto remains available for
the current selected administrator/device with its actual earlier ceiling.
Discarded: automatic root fallback, presenting auto as the root, ignoring a
shorter admin lease or silently narrowing a previously fixed owner offer.
These CLI defaults do not change daemon auto-selection or issuer powers.

## Coordinator-free acknowledgment preview boundary (2026-10-27)

Selected within the owner's DEC-01 through DEC-07 delegation: an ACK preview
may fix only the exact unapproved private typed intent/template, its local
reference and named monotonic clock. Approval, signature, public acknowledgment,
fence and adoption remain separate. A read-only implementation also qualifies.
This clarifies the existing typed-preparation boundary after an independent
case incorrectly required all database rows to be unchanged. The first failed
assertion stays recorded; there was no observed approval, signature or fence.

Discarded: treating an unsigned private intent as acknowledgment, weakening the
explicitly pure identity/H/device-ban previews, permitting unrelated row/secret
changes or silently rewriting the fixed template. Corrected independent checks
must name and inspect the only permitted changes; this is no general mutation
waiver or runtime-success claim.
