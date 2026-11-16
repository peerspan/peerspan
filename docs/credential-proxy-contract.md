# Credential proxy contract

A runtime agent's model API key is given to its microVM today: the runtime reads the key file
and guest init writes it to `/run/secrets`, where the harness, which runs as root in the guest,
reads it into its environment. The agent can therefore read the key and send it anywhere its
network reaches. A **credential proxy** keeps the key out of the VM. The harness talks plain
HTTP to a port on the guest's loopback, the runtime carries each connection to a host socket,
and a confined process on the host checks the request, adds the key, and forwards it to the
model provider over TLS. The guest holds only a token that is useless outside its run.

The decisions are RUN-23 to RUN-34 in the
[decision log](decision-log.md#run-23-to-run-34-a-credential-proxy-for-runtime-agents-model-keys-2026-11-16),
made from the internal design draft `docs/credential-proxy.md` in docs-internal. This contract
extends the [runtime agent contract](runtime-agent-contract.md) and the
[runtime task contract](runtime-task-contract.md). Where it doesn't say otherwise, those
contracts apply. It changes nothing for senders.

Not in this contract:
- credentials other than the harness's model key: GitHub, package registries, remote MCP
  (RUN-30: Peerspan's MCP tools reaching the VM come first, then header injection only for
  package registries and git over HTTPS);
- how a hosted machine holds a customer's key and how the customer sets it (RUN-31: an
  encrypted disk with the operator's access disclosed, a narrowed key at the vendor, and SSH for
  the pilot; operations, not this contract);
- a key used for work on another owner's runtime (RUN-32: the proxy runs where the key lives);
- a one-command entry point outside runtime agents (RUN-34, later);
- the rule that requires `proxy` (below, [Modes](#modes)), which comes with the change that
  makes `proxy` the default.

## What must hold

| # | Property |
| --- | --- |
| P1 | The key's bytes are never in the guest: not in its memory, disk, environment, arguments, workspace, branch or history. |
| P2 | What the guest holds works only through its own run's socket, and only while the run lives. |
| P3 | Every proxied request is bound to one run, and attributed to its task and agent. |
| P4 | Requests go only to the harness's provider, and only to the paths below. Anything else is refused, never passed on without the key. |
| P5 | A run's model use is bounded: connections, request size, requests, bytes and, when the profile sets it, output tokens. |
| P6 | Clearing or replacing the credential takes effect at the next request; the run ending or being cancelled stops new requests at once. |
| P7 | The key is never logged, and never in a response, task record, event, activity or output. |

These protect the key from the guest, not from whoever is root on the host. They do not stop an
agent with `internet` from sending the work itself elsewhere, which is the network level's job.

## Runtime: host ports

A run can reach services on the host through ports on its own loopback (RUN-24). The runtime
does not read what crosses them.

`GET /v1/runtime` gains `host_ports`, true when the runtime supports them. `POST /v1/runs` gains
the optional `host_ports`, null by default, or an array of 1 to 4 entries `{port, socket}`:

| Field | Rules |
| --- | --- |
| `port` | 1 to 65,535: a TCP port on the guest's `127.0.0.1`. Distinct within the run, and not the run's `link` port. |
| `socket` | An absolute path of at most 107 bytes to a Unix stream socket on the host. |

A run naming well-formed `host_ports` on a runtime that reports `host_ports` false is 422
`unavailable`; a malformed entry is 400 `invalid` naming `host_ports`, on any runtime.

While the run is `running`, a TCP connection the guest opens to `127.0.0.1:PORT` is carried to
the entry's `socket` as one ordered byte stream each way. Guest init listens on each port before
the command starts, and opens one vsock stream to the host per connection, on a vsock port of
the run's own that the VMM maps to a Unix socket in the run's private directory, as for a linked
run. The runtime connects to `socket` for each guest connection and splices the two:
- **Who it connects to.** It connects as root, so it checks the listener: the connection's peer
  credentials (`SO_PEERCRED`) must name the runtime's client user (`serve --client-uid`, or root
  when that is unset). A connection to any other listener is closed at once, as is one that
  cannot be made. The guest's connection is then closed; the harness sees a reset and may retry.
- **Bounds.** At most 64 connections are open at once per entry; a guest connection beyond that
  is closed at once. There is no byte bound in the runtime: the service bounds its own use.
- **Its end.** When the run exits, every connection of every entry is closed.

`host_ports` works with every `network` level, `none` included, and gives the guest nothing
else: no other port and no address beyond loopback. With `host_ports`, the runtime task
contract's guarantee "the guest has no network" holds for `network` `none` except for these
ports, as for a linked run's port.

A runtime with `host_ports` is a new runtime release. Runtime tasks from peers never set it.

## The proxy

### The process

The proxy is its own program, `peerspan-credential-proxy`, shipped in the host archive beside
`peerspan-host` (RUN-23, RUN-34). The host daemon starts it when it starts, and restarts it if it
exits. It is never started by hand, has no listening socket of its own, and serves only runs the
daemon gives it.
- **What it receives.** The daemon talks to it over one Unix socket pair. For each proxied run,
  the daemon passes it the run's listening socket (bound by the daemon at
  `STATE/rp/HEX.sock`, where HEX is the first 32 hex digits of the run ID, mode 0600), the
  harness, the run's token, its bounds and the key. It passes a new key, or the credential's
  removal, the moment the owner sets or clears it, before answering the owner's request. When
  the task ends, the daemon tells the proxy, which closes the run's listener and connections,
  and the daemon removes the socket.
- **Confinement.** Before it reads anything from the daemon, the proxy:
  - runs as the user `peerspan-proxy` when the daemon runs as root, and never as root: without
    that user it does not start, and proxied tasks stay queued as below. When the daemon is not
    root, the proxy runs as the daemon's user;
  - sets `no_new_privs`, makes itself non-dumpable (so a process of the same user can neither
    trace it nor read its memory), and turns off core dumps;
  - drops every file system access except reading the resolver configuration and the system's
    trusted roots, with Landlock where the kernel has it;
  - installs a seccomp allow-list of the system calls it needs.

  It holds keys only in memory, locked against swapping, and zeroes them when they are replaced
  or removed.
- **Restarts.** When the daemon stops, the proxy exits. Proxied connections are reset; the run
  goes on, as runs survive daemon restarts today, and new connections fail until the daemon is
  back and has given the proxy the runs again. When the proxy exits on its own, the daemon
  restarts it and gives it every proxied run still dispatched.

### Requests

The proxy speaks HTTP/1.1 to the guest and HTTP/1.1 or HTTP/2 over TLS to the provider. Each
harness has one provider entry, fixed in the host release and not configurable by the guest or
the owner:

| Harness | Upstream | Allowed | Guest headers removed | Added |
| --- | --- | --- | --- | --- |
| `claude` | `https://api.anthropic.com` | `POST /v1/messages` and `POST /v1/messages/count_tokens`, each with any query; `HEAD /api/hello`, answered by the proxy itself with 200 and no body | `x-api-key`, `authorization` | `x-api-key: KEY` |
| `codex` | `https://api.openai.com` | `POST /v1/responses` with no query; `GET /v1/responses` as a WebSocket upgrade (RUN-29) | `authorization`, `openai-organization`, `openai-project`, `chatgpt-account-id` | `authorization: Bearer KEY` |

For every request:
- **The token.** The guest sends the run's token where the harness would send a key: in
  `x-api-key` for `claude`, and as `authorization: Bearer TOKEN` for `codex`. The proxy compares
  it in constant time. A missing or wrong token is 401 and nothing is sent upstream.
- **Anything not allowed** is 403, with a JSON error in the provider's shape naming the method
  and path, and nothing is sent upstream.
- **Headers.** Hop-by-hop headers, the headers named in `connection`, and
  `proxy-authorization` are dropped, and `host` becomes the upstream's. Every other header and
  the body pass unchanged, in both directions. The proxy never changes the model, the prompt or
  the body: the owner's key is used as the owner set it, so the provider bills the key's owner.
- **The key** is looked up for every request, including a request over an upstream connection
  that is already open. A request after the credential was cleared is 401
  `the agent has no credential`. An upstream connection opened with a key that has since been
  replaced or cleared is closed, not reused.
- **Redirects** from upstream are passed back to the guest, never followed, so the key is only
  ever sent to the upstream host.
- **Upstream TLS** is checked against the system's trusted roots. No proxy from the environment
  applies to the upstream.
- **Streaming.** Bodies stream both ways as they arrive, with no buffering, so server-sent
  events reach the harness as the provider sends them.
- **Timeouts.** Connecting upstream times out after 30 seconds (502). A connection with no byte
  either way for 10 minutes is closed. There is no other time limit beyond the run's.

**Codex's WebSocket** (RUN-29). An upgrade request `GET /v1/responses` is checked as above,
with the token in its `authorization` header. The proxy removes `sec-websocket-extensions`, so no
compression is negotiated, adds the key, and sends the upgrade upstream. Once the provider
answers 101, the proxy carries the frames both ways unchanged until either side closes. It reads
the frames to count requests and usage (below) and never changes them. Any other upgrade is 403.

After the 101 there is no HTTP status to answer with, so a refusal on an open WebSocket is a
close. When a client message would pass a bound (below), or arrives after the credential was
cleared or replaced, the proxy does not forward it. It sends the guest a close frame with code
1008 and the refusal's message as the reason (for example
`model request limit reached for this run`), closes the upstream connection, and carries nothing
more either way. The harness then opens a new connection or falls back to HTTP, where the same
refusal is answered with its status.

### Bounds

| Bound | Value | On reaching it |
| --- | --- | --- |
| Open connections from the guest | 16 per run | A new connection is closed at once |
| Request body | 32 MiB | 413, provider-shaped, `request too large for this run` |
| Requests over the run | 5,000 | 403 `model request limit reached for this run` |
| Bytes each way over the run | 1 GiB | The run's connections are closed; later requests are 403 `model byte limit reached for this run` |
| Output tokens over the run | The profile's `max_output_tokens`, or none | Once usage reaches it, later requests are 403 `model token limit reached for this run` |

A request is an HTTP request, or a client message of type `response.create` on a WebSocket. A
bound that ends model access answers 403 or 413, never 429 or a 5xx, so the harness fails
instead of retrying until the run's timeout. Passing a bound never ends the run: the harness
decides what to do without the model.

### Failures

| Case | The guest sees |
| --- | --- |
| Upstream unreachable, its name unresolved, or its TLS refused | 502, provider-shaped |
| The credential cleared, or never set | 401 `the agent has no credential` |
| The proxy or the daemon restarting | The connection reset, or closed by the runtime |
| A bound reached | As above |
| The task ended or cancelled | Its connections closed; new ones closed by the runtime, since the socket is gone |

Every error the proxy makes itself is a JSON body in the provider's error shape:
`{"type": "error", "error": {"type": "TYPE", "message": "MESSAGE"}}` for `claude`, and
`{"error": {"type": "TYPE", "message": "MESSAGE"}}` for `codex`.

### Logs and usage

The proxy writes one line per request to the daemon's log: the run ID, task ID, agent ID, method,
path, status, duration and bytes each way. Never a header, a body, the key or the token.

**Usage** (RUN-27). The proxy reads, without changing them, the usage fields of the provider's
responses: for `claude`, the `usage` of the `message_start` and `message_delta` events or of a
non-streamed message; for `codex`, the `usage` of `response.completed` over SSE or WebSocket, or
the top-level `usage` of a non-streamed response. When the profile sets `max_output_tokens`, a
successful response whose usage the proxy cannot read ends model access for the run as if the
bound were reached, so no request mode passes the cap uncounted.
It sums them per run as `{requests, input_tokens, output_tokens, cache_read_tokens,
cache_write_tokens}`, and the daemon stores the sums with the received task. Usage is the
owner's: it is never sent to the sender, in an event, a status record or the output.

## Host: the profile's credential mode

The launch profile gains two fields:

| Field | Rules | Default |
| --- | --- | --- |
| `credential_mode` | `secret`: the key is given to the VM at `/run/secrets`, as today. `proxy`: the key stays on the host and the run reaches it through the proxy. | `secret` |
| `max_output_tokens` | Null, or 1 to 1,000,000,000: the output tokens a run of the profile may use through the proxy. Only with `credential_mode` `proxy`. | null |

CLI: `agent runtime set AGENT ... [--credential-mode secret|proxy] [--max-output-tokens N]`. A
field outside these rules is 400 `invalid` naming it. A `proxy` profile needs a runtime that
reports `host_ports` true (otherwise 409 `runtime_unavailable`). A returned profile always has
`credential_mode`, and has `max_output_tokens` only when it is set. `network` keeps its default,
`internet`, for both modes (RUN-33): the proxy is not a network policy, and agents install
packages. An owner may choose `none`, which leaves the agent only its model.

### Modes

`secret` stays the default until the live check below passes with both harnesses. The change
that makes `proxy` the default will also make it required whenever the key's owner is not the
work's: a task from another person, a peerbox run with an agent, a hosted machine, and another
owner's runtime (RUN-26). `secret` will then be allowed only for an owner's own tasks on their
own machine. That change is a contract amendment of its own.

### The run of a proxied profile

At the start, the host checks the task as before, then also that the proxy is up
(`the credential proxy is not running`, a recoverable failure that leaves the task queued). It
draws the run's **token**, `psp_run_` and 32 random lowercase hex digits (RUN-25), binds the
run's socket, gives the run to the proxy, and only then dispatches. The `POST /v1/runs` body
differs from a `secret` profile's in three fields:
- no `secrets`;
- `env` `{"PEERSPAN_RUN_TOKEN": TOKEN}`;
- `host_ports` `[{"port": 4100, "socket": "STATE/rp/HEX.sock"}]`.

The token is not a secret: it is stored in the dispatch body, and a resend after a restart
reuses it, with the same socket. The daemon gives every dispatched proxied run back to the
proxy when it starts. When the task ends, however it ends, the daemon removes the run from the
proxy and the socket from disk.

**The harness command** of a proxied run replaces the key steps of the scripts in the runtime
agent contract:
- **Claude:** step 3 sets `ANTHROPIC_BASE_URL` to `http://127.0.0.1:4100` and
  `ANTHROPIC_API_KEY` to `$PEERSPAN_RUN_TOKEN`, instead of reading `/run/secrets`. Steps 1, 2 and
  4 are unchanged.
- **Codex:** step 2 writes `$CODEX_HOME/config.toml` instead of setting `CODEX_API_KEY`:

  ```toml
  model_provider = "peerspan"

  [model_providers.peerspan]
  name = "Peerspan"
  base_url = "http://127.0.0.1:4100/v1"
  wire_api = "responses"
  env_key = "PEERSPAN_RUN_TOKEN"
  supports_websockets = true

  [analytics]
  enabled = false
  ```

  Codex ignores these settings in a repository's own `.codex/config.toml`, so the workspace
  cannot point it elsewhere. Steps 1, 3 and 4 are unchanged.

The scripts' exact text is fixed by the host release, as before.

### Usage for the owner

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `agent runtime usage AGENT [--json]` | `GET /v1/agents/{agent_id}/runtime/usage` | `{agent_id, tasks: [...]}`: the agent's last 100 proxied tasks, newest first, each `{task_id, sender_host_id, started_at, ended_at, usage}`, with `ended_at` null while it runs and `usage` as summed so far. 404 `not_found` for an agent without a profile. |

## Persistence

The host schema version increments by one: the next free version on `main` when the
implementing PR merges. The received task record of a runtime agent's task gains `usage` (null
for a `secret` run) and, for a proxied run, the token inside its stored dispatch body.
Profiles gain their fields in `runtime-agents.json`. Older binaries reject the new version. No
new activity kind: `runtime.agent_set` covers the new fields.

## Verification

- **Runtime:** `scripts/check-serve.py` cases: a run with `network` `none` reaches a host socket
  through `127.0.0.1:PORT` and nothing else; a listener of another user is refused; more than
  64 connections; the connections closed when the run exits; 422 and 400 as above.
- **Host:** the `runtime_agents` suite, written from this contract by an author who does not read
  `src/`, `tests/` or `integrations/` (DEC-OWN6, DEC-OWN9), gains cases for the profile fields,
  the run body of a proxied profile, and the proxy. The fake runtime gains `host_ports`: it
  records the request, and with `harness` set it acts as the agent by connecting to the given
  socket and sending the requests its prompt names. In a debug build, and only on the harness's
  test clock, the daemon honors `PEERSPAN_TEST_PROXY_UPSTREAM`, a URL that replaces both
  upstreams, so the suite can run a fake provider that records every header it receives. The
  cases include:
  - the run request of a `proxy` profile holds no byte of the key, while the fake provider
    receives the key and not the token;
  - a guest's own `x-api-key` or `authorization` is replaced, never passed on;
  - another path, method or upgrade is 403, and a wrong token 401, with nothing sent upstream;
  - the credential cleared during a run makes the next request 401, and a new key is used from
    the next request on;
  - a streamed response arrives event by event;
  - Codex's WebSocket carries frames both ways and its usage is counted; a message past a bound,
    or after the credential was cleared, is not forwarded, and the guest gets close code 1008
    with the refusal's message;
  - each bound, with its status;
  - usage as the fake provider reported it, streamed and not, for the owner and never in the
    sender's events; with `max_output_tokens` set, a successful response without readable usage
    ends model access;
  - after the task ends, its socket is gone and a held connection is closed;
  - the key and the token in no event, output, activity or log line.
- **Live, on KVM with real harnesses and real keys.** A Claude agent and a Codex agent with
  `credential_mode` `proxy` and `network` `none` each finish the small story 2 task. For each:
  - while the run waits before tearing down, a check-only runtime command scans the guest's
    memory for the key's bytes, base64 and URL encoding, finding none, and finds the token,
    which shows the scan works;
  - a step in the same VM after the harness finds the key in no process's environment or
    arguments, and nowhere under `/run`, `/root`, `/tmp` or `/workspace`;
  - the branch, the output, the run's logs and the daemon's log hold no key.

  It is recorded in docs-internal `runtime.md`. Passing it for both harnesses is the condition
  for making `proxy` the default.
