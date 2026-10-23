# Setup baseline before `peerspan up`

This records the implemented quick start at `3c774c0402fd1eb43cb905d4cb03ee9655cbc3da`
before adding guided setup. The [compact result](results/setup-baseline.json)
retains the environment, bundle provenance and checksums, counted commands and
their available timings, and each acceptance check's outcome. Verbose fixture
message, policy, and task payloads are omitted from that summary.

## What was exercised

The existing `conformance/launch_acceptance.py` built both native Linux amd64
bundles, verified their checksums, and followed the current quick start in seven
configurations: solo Go and Rust, pair Go and Rust, and team Go, Rust and mixed.
Each simulated machine was a fresh Linux user with its own home, Peerspan state,
systemd user service, project, and person-key files. A local coordinator was
built into the bundles as their default. All seven paths passed; cleanup left no
temporary users, homes, linger entries, or processes.

The fixture agent performs the real adapter handshake and readiness response.
The checks verify status, agent discovery, accepted messages, and delivery of
tasks to the receiving adapter under the expected self or owner-policy access.
They do not establish model execution, task completion, or the quality of a
result. No live coding-agent login was used in this run.

This is a scripted baseline on one Linux host. It does not measure a new user's
understanding, transport between separate machines, public or private release
downloads, macOS, or the current hosted staging coordinator. The real-machine
user observation remains an open part of UP-01 in the
[guided setup proposal](guided-setup-proposal.md#task-queue).

## Counted steps

| Path | Machines | Installer commands | Other CLI commands | Private-key copy | Total |
| --- | --- | --- | --- | --- | --- |
| One person | 2 | 2 | 5 | 1 | 8 |
| Two people | 2 | 2 | 7 | 0 | 9 |
| Three people | 3 | 3 | 11 | 0 | 14 |

The counts match in both host implementations. The mixed team path has the same
counts as the other team paths. Each `attach` is one command, even though it
keeps running as the launched integration.

For the same-person path, the first machine installs, creates a network, issues
an invite for its own person label, and attaches the agent. The second installs,
receives the person's private key and public-key file, joins using the invite,
and attaches. Other-person paths also need the owner's `allow` commands.

Preparation supplies Node, the fixture agent, a running systemd user manager,
the bundle and checksum, the installer, a project directory, and a `PATH` that
already contains `~/.local/bin`. Archive acquisition, authentication for private
GitHub downloads, prerequisite installation, shell configuration, and changing
directories are not counted. Invite handoffs are represented by substituting a
token from one command's output into another command; the harness does not time a
person transferring it.

## Runtime measurements

The result records wall time for synchronous counted commands. It records
`attach` as a background launch, without a duration, and the private-key copy as
an outcome without a duration. Their timings must not be treated as zero or
included in a claim about total setup time. Packaging, preparation, end-to-end
checks, and cleanup are also outside those command timings.

| Run | Timed commands | Recorded synchronous seconds | Steps without a duration |
| --- | --- | --- | --- |
| solo-go | 5 | 5.32 | 3 |
| solo-rust | 5 | 5.18 | 3 |
| pair-go | 7 | 5.35 | 2 |
| pair-rust | 7 | 5.40 | 2 |
| team-go | 11 | 8.16 | 3 |
| team-rust | 11 | 8.39 | 3 |
| team-mixed | 11 | 8.90 | 3 |

These measurements describe prepared local execution. A fresh-machine user run
must separately time prerequisite setup, downloads, reading and answering
prompts, invite and identity handoffs, channel approval, and the first useful
completed task.

## Friction the guided flow should address

| Existing step or outcome | Change to verify |
| --- | --- |
| Service installation, enrollment and attachment are separate operations | One `up` flow identifies what already succeeded and performs only the missing stages. |
| Invite handoff requires an administrator to run another command | First milestone accepts the current invite and explains how to obtain it; approved same-person linking follows. |
| Same-person second machine needs the same person key | Explain the prerequisite accurately in the first milestone; the later identity design removes private-key copying. |
| Host membership and person binding can have different outcomes | Inspect the structured binding outcome; stop before attachment if identity is incomplete. This case comes from the current onboarding contract and code, not an observed failure in the successful baseline runs. |
| Attachment preparation precedes actual delivery readiness | Show prepared or starting until the integration supplies its existing readiness evidence. |
| Prerequisite and integration details span multiple guides | Present missing requirements and the recovery action in the guided flow. |
| Some setup work is hidden in acceptance preparation | Observe it on separate fresh machines and keep it in the measured user journey. |

## Repeat the baseline

On Linux with the prerequisites listed by the runner, from a clean checkout of
the revision above:

```sh
python3.12 conformance/launch_acceptance.py --output /tmp/setup-baseline.json
```

The runner requires root and systemd user services; it creates and removes
temporary users and their services. Its default coordinator is local. The
`--coordinator` and `--coordinator-key` options select a deployed coordinator for
a distinct run; record that result separately.
