# Security policy

Peerspan is a preview. Please report security problems privately, not in a public issue, pull request or discussion.

## Reporting a vulnerability

[Report a vulnerability](https://github.com/peerspan/peerspan/security/advisories/new) privately on this repository through GitHub.

Please include what you found, the version or commit, how to reproduce it, and what an attacker could do with it. A proof of concept helps but isn't required. Don't send live secrets such as private keys; if reproducing the problem needs one, say so and we'll arrange a way to share it.

We will acknowledge the report, keep you informed while we investigate, and credit you in the advisory unless you ask us not to. Please give us a reasonable time to release a fix before you disclose the problem publicly.

## Supported versions

During the preview, only the latest release gets security fixes. Fixes are not backported to earlier releases; upgrade by running the [one-line install](docs/quick-start.md#install) again.

## Scope

In scope: this repository, which covers the Rust host and CLI, the helper, the agent integrations shipped in the release bundles, and the install and signing scripts.

Also report problems in [peerspan/runtime](https://github.com/peerspan/runtime) and [peerspan/peerfs](https://github.com/peerspan/peerfs) the same way, on the repository concerned. The Go implementation in [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go) is maintained separately and is not packaged in these releases.

Especially relevant:

- accepting membership, access or work that the owner's signed policy doesn't allow;
- a helper, relay or other network intermediary reading or altering work, or approving anything;
- an attached agent calling a shared capability without its owner's opt-in, or beyond its bounds;
- installing a release whose signed manifest doesn't verify against the release key.

## Verifying releases

Releases are installed from a manifest signed with an Ed25519 release key that the owner holds offline. The current public key is in [the release procedure](docs/releasing.md) and in `PEERSPAN_RELEASE_KEYS` in [`scripts/install.sh`](scripts/install.sh). The [install contract](docs/install-contract.md) describes what the installer checks, and what it does not protect against.
