# PeerFS cross-host pull (PF-3)

Status: proposed contract for owner review, following the [delivery plan](peerfs-host-contract.md)
(PF-3), the [local contract](peerfs-local-contract.md) (PF-1) and the
[read contract](peerfs-read-contract.md) (PF-2). Decisions PF-07 to PF-11 in the
[decision log](decision-log.md).

## 1. Scope

A reader host B brings a branch that a serving host S shares with it (PF-2) into one of B's own
host-backed PeerFS spaces, L, as the tracking reference `<S's host ID>/<branch>`. Every object is
checked against its identity and kind, every commit's signature is checked against a key B's host
recognizes, and the reference is written last, only when the whole history is present. A pull is
started by B's owner (`fs pull`), or by one of B's agents the owner allowed to pull into L
(`fs_pull`). It is read-only towards S: nothing is written there.

Not here: pushing, forking or committing on S (PF-5); a pull that narrows by path; mounting the
pulled branch (`peerfs ws` already works on the tracking reference once it exists); automatic or
scheduled pulls.

## 2. How a pull runs (PF-07)

B's host does not re-implement PeerFS's pull. For one pull it serves, on a private local socket,
the three calls a PeerFS pull makes of its source, answering them from S's PF-2 peer routes, and
asks L's provider to pull from that socket:

1. **Checks before anything is fetched:** L has a `registered` PF-1 binding on B in network N,
   its pinned directory is unchanged and its provider passes activation's identity check; the
   caller may pull into L (section 5); S's discovery (`GET /peer/v1/fs/branches?network=N`) lists
   `(space, branch)` for B; and no other pull of that `(L, S, space, branch)` is running (409).
2. **The head is selected once:** B asks S's `head` route, citing the policy discovery returned.
   That commit is the pull's target; a later move of S's branch does not change it.
3. **The proxy:** B creates a directory, mode 0700, in its private state directory, and in it a
   socket, mode 0600, owned by B's account, that serves exactly:
   - `GET /v1/space`: `{path, host, objects, key}` with `path` the text `peerspan:S/SPACE`, `host`
     S's host ID, `objects` 0 and `key` S's public key;
   - `GET /v1/branches`: `[{name: BRANCH, head: TARGET}]`, only the pulled branch at its target;
   - `POST /v1/objects/fetch` with `{ids}` (at most 256): forwarded to S's `objects` route,
     citing the same policy. S returns only the leading objects that fit its 16 MiB answer, while
     PeerFS's pull needs every requested object in one answer, so the proxy asks S again for those
     not yet returned until it holds all of them, then answers with one batch of them all in the
     order asked. Objects are passed through as S sent them; checking them is PeerFS's.
   Every other request is 404. The socket is removed when the pull ends, however it ends.
4. **L's provider pulls** with its existing `POST /v1/pull` from the proxy socket. PeerFS checks
   each object's identity and kind, stores children before what refers to them so its store stays
   closed, checks each commit's signature through its key check (section 3), and writes the
   tracking reference `<S's host ID>/<branch>` last.
5. **The answer:** `{peer, space, branch, into, tracking, head, objects, bytes}`, with the number
   of objects and bytes fetched in this pull.

The proxy accepts connections only from L's provider: it checks each connection's peer
credentials (`SO_PEERCRED`) are B's account, as activation checks the provider's.

## 3. Verifying what arrives

L is a host-backed space (PF-1), so its provider checks every pulled commit's signature with
`host-keys/check` against L's binding's network context. A commit authored by S verifies when S's
key is S's own (its host ID is its key's hash) and L's context retains S's admission, which holds
because S and B share N. A commit authored by a third host verifies only when L's context
retains that host's admission too; otherwise the pull fails. Recognition is identity history,
not current access (PF-1, section 6).

So **L must be in the network of the share**: the command and the tool refuse a destination whose
binding is in another network (PF-08). Objects and signatures that fail any check fail the pull.

## 4. Bounds and interruption (PF-11)

- **Bytes.** The proxy counts the bytes of S's `objects` answers. Once the count exceeds the
  pull's byte bound, the proxy contacts S no more and answers the fetch 507, and the pull fails
  with `too_large`; so a pull fetches at most its bound plus one S answer (16 MiB). The bound is
  1 GiB by default; `fs pull --max-bytes N` sets it for the owner, and an agent's grant sets its
  own (section 5).
- **Large objects.** An object larger than an `objects` answer cannot be pulled: S answers 503
  (PF-06), and the pull fails with `unavailable`.
- **No partial reference.** A pull that fails, for any reason, writes no tracking reference.
  PeerFS stores blobs as they are checked and holds trees and commits until the whole history is
  present, so a failed pull leaves only unreferenced blobs in L, which PeerFS's garbage
  collection may drop.
- **Resuming.** Running the same pull again does not fetch the blobs L already holds; it fetches
  the trees and commits again. Each run re-checks everything in section 2 and selects S's head
  afresh, so a withdrawn share, a lapsed membership or a changed binding refuses the next run.
  A refusal mid-pull (S answering 404 or 503) fails the pull there. S checks each fetch against
  its branch's current head, so a pull whose target the branch no longer reaches (the branch was
  reset or removed) fails with 404, and a rerun pulls the new head.
- **Time.** A pull has no overall time bound; its bytes are bounded, and each S request has
  PF-2's bounds. The owner command shows progress, and an agent's tool call returns when the pull
  ends.
- **Cancellation.** Interrupting `fs pull`, or the agent's tool call being cancelled, ends the
  pull: B stops contacting S and removes the proxy socket, PeerFS's pull fails, and nothing is
  referenced. An interrupted pull is never reported as complete or as an empty pull.
- **One at a time.** At most one pull per `(L, S, space, branch)` runs at once; another is 409.

## 5. Who may pull (PF-09, PF-10)

**The owner** runs `fs pull`; that run is B's consent.

**An agent** pulls through the MCP tool `fs_pull` only into a space its owner allowed it:

| Command | Does |
| --- | --- |
| `fs allow-pull AGENT --space LOCAL_SPACE [--max-bytes N]` | Lets `AGENT` pull any branch shared with this host into `LOCAL_SPACE`, each pull bounded to `N` bytes (default 1 GiB). Replaces an existing grant for the pair. |
| `fs deny-pull AGENT --space LOCAL_SPACE` | Withdraws it. A pull already running finishes; the next is refused. |
| `fs pull-grants [--json]` | The grants. |

Grants are stored only on this host, as `fs-pull-grants.json` (mode 0600) in the state directory,
never in signed policy, so holding the person key does not let another machine allow an agent
here. A grant names a registered agent of this host and a space with a binding on this host; the
binding must still be `registered` when the agent pulls. At most 256 grants.

The tool `fs_pull` takes `{peer, space, branch, into}` and returns section 2's answer or an error
with the codes of section 6. It is offered to an agent only while the agent has at least one
grant, and refused (403 `forbidden`) for a destination it has no grant for. An agent's pull is
recorded as the activity `fs.pulled`, with the agent, `(peer, space, branch)`, `into`, the
target head and the byte count; the owner's too.

## 6. Commands and errors

`fs pull --peer HOST --space SPACE --branch BRANCH --into LOCAL_SPACE [--network ID]
[--max-bytes N] [--json]`. `--network` is optional when L's binding names the network.

| Status / code | Meaning |
| --- | --- |
| 400 `invalid` | Malformed arguments or IDs |
| 403 `forbidden` | An agent without a grant for that destination |
| 404 `not_found` | S does not share that branch with B in N, or no such local space |
| 409 `conflict` | L's binding not registered, in another network, or its directory changed; another pull of the same branch into L running |
| 502 `remote` | S's answer was malformed, or an object or signature failed its check |
| 503 `unavailable` | S unreachable, S's space not serving, or L's provider unavailable |
| 507 `too_large` | The pull's byte bound reached |

## 7. Verification

A separate author writes one compact suite from this contract (second tier, under 120 s), with
genuine hosts in a shared network and fake PeerFS providers on both sides where real ones are
not needed, plus one installed check with real PeerFS (below):

- **Pull:** a shared branch arrives in L as `<S>/<branch>` at the head selected at the start, with
  every object S's head reaches and no others; a second pull fetches nothing new; after S's
  branch moves, a pull brings the new head.
- **Proxy:** only the three calls are served; a fetch whose objects S returns over several answers
  is answered with all of them in one batch; the socket and its directory are private and
  removed after success, failure and interruption; a connection from another account is refused.
- **Refusals:** an unshared branch, a destination in another network, a prepared or released
  destination, a changed destination directory, a destination provider down, and a concurrent
  pull of the same branch, each with its status; nothing written.
- **Verification failures:** a corrupted object, a wrong kind, a commit whose signature does not
  verify, and a commit by a host L's context does not recognize each fail the pull with no
  tracking reference.
- **Bounds and resumption:** a pull stopped by its byte bound writes no reference and, rerun with a
  larger bound, completes without fetching the blobs already held; an object larger than one
  answer fails the pull with 503; a withdrawal mid-pull fails it there; S stopping mid-pull
  fails it, and a rerun completes.
- **Agents:** a granted agent pulls with its own bound; an agent without a grant, or after
  `deny-pull`, is refused; the tool is offered only with a grant; `fs.pulled` is recorded.

**Installed acceptance** (manual, as for runtime agents): on the two machines of
`docs-internal` `runtime.md`, a host-backed space on the server shares `main` with the laptop's
host, and the laptop pulls it into its own space and opens it with `peerfs ws`. A run interrupted
by stopping the server's host resumes and completes.

## Decisions and discarded options

- PF-07: B's host serves a per-pull proxy of PeerFS's three source calls and lets L's provider
  pull. Discarded: the host importing objects itself, which re-implements the pull's ordering,
  resumption and reference rules.
- PF-08: the destination is an existing registered space of B's in the share's network.
  Discarded: a new mirror space per remote space, prepared and activated on first pull.
- PF-09: the owner and B's agents may pull. Discarded: the owner command only.
- PF-10: an agent pulls only into spaces its owner allowed it, by a local grant. Discarded:
  approving each pull; letting any of the owner's agents pull anywhere.
- PF-11: each pull has a byte bound, 1 GiB by default. Discarded: no limit.
- Contract choices within them: the head is selected once per pull; the bound counts S's answer
  bytes and is enforced at the proxy; grants live in a local file, not the database, so PF-3 adds
  no schema version; the proxy collects S's partial answers into the one batch PeerFS expects; a
  failed pull leaves fetched blobs for garbage collection, not a reference.
