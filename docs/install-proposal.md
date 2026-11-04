# One-line install from peerspan.dev

Status: **Accepted on 2026-11-04.** The owner accepted all five recommendations ([INST-1 to INST-5](decision-log.md#inst-1-to-inst-5-one-line-install-2026-11-04)). The [install contract](install-contract.md) specifies the behavior. Nothing is implemented yet.

## The problem

The promoted launch sends people from [peerspan.dev](https://peerspan.dev) to an install. Today that install ([quick start](quick-start.md#install), [release procedure](releasing.md#publish-the-preview)) asks a new user to:

1. install GitHub CLI and run `gh auth login`, although the repository and its releases are public ([DEC-OWN7](decision-log.md#dec-own7-publish-the-repository-2026-10-28));
2. know the current version number;
3. download two files, check one against the other, and run the installer with three arguments.

Step 1 is a leftover from the private repository. The [v0.1.0 public install smoke record](https://github.com/peerspan/peerspan/releases/download/v0.1.0/public-install-smoke-v0.1.0.json) already shows that unauthenticated HTTPS downloads of the release assets work. `gh` is used in exactly one place, `gh release download` in `scripts/install-release.sh`.

The checksum also only detects corruption. It is downloaded from the same place as the archive, so anyone who can replace one can replace both. The installer says so itself. That's acceptable for a preview whose users read the release page. It isn't acceptable for a promoted `curl | bash`.

## Goals and non-goals

**Goals:**
- One command on the website: `curl -fsSL https://peerspan.dev/install | bash`, which installs the latest release for this machine's architecture and starts the user service.
- Pinning a version is equally short: `curl -fsSL https://peerspan.dev/install | bash -s -- --version 0.2.0`.
- No GitHub account, no `gh`, no root, and no new tools beyond those the bundle already needs: Bash, `tar`, `flock`, Node.js 22, plus `curl` or `wget`.
- Every downloaded archive is checked against a manifest signed with a key that is not stored on GitHub.
- Running the same command again upgrades in place, as rerunning `install-release.sh` does today.
- `scripts/install-release.sh --from DIRECTORY` stays the offline path, unchanged.

**Non-goals:**
- macOS, Windows, package managers (Homebrew, apt), and system-wide or root installs.
- Installing Node.js for the user (see [Risks](#risks)).
- Self-update from the CLI (`peerspan upgrade`). Rerunning the one-liner is the upgrade path.
- Installing the optional helper. It keeps its own archive and [operator guide](decentralized-helper-contract.md).
- Changing what `install-release.sh` does once it has a verified archive: the layout, the launcher link, refusing to replace unrelated commands, `peerspan install`, and rollback of the service all stay as they are.

## Design

### Pieces

| Piece | Where it lives | New or changed |
| --- | --- | --- |
| `scripts/install.sh`, the bootstrap | this repository; a copy is served by the website at `/install` | new |
| `release.json`, the manifest | an asset of every release | new |
| `release.json.sig`, its Ed25519 signature | an asset of every release, added at publication | new |
| `scripts/sign-release.sh` | this repository; run by the key holder | new |
| `scripts/install-release.sh` | this repository and every release | `--from-github` uses HTTPS instead of `gh` |
| Draft Linux release workflow | `.github/workflows/linux-release.yml` | writes `release.json` |

### The manifest

The draft workflow writes `release.json` next to the other ten assets:

```json
{
  "format": 1,
  "name": "peerspan",
  "version": "0.2.0",
  "source_revision": "<40-hex commit>",
  "assets": {
    "peerspan-0.2.0-linux-amd64-rust.tar.gz": "<sha256>",
    "peerspan-0.2.0-linux-arm64-rust.tar.gz": "<sha256>",
    "peerspan-helper-0.2.0-linux-amd64.tar.gz": "<sha256>",
    "peerspan-helper-0.2.0-linux-arm64.tar.gz": "<sha256>",
    "install-release.sh": "<sha256>"
  }
}
```

The workflow already checks each archive's `RELEASE.json` against the version, architecture and commit, so the manifest only restates facts the draft job has verified. Its file name has no version in it, so `releases/latest/download/release.json` always names the newest release.

### Signing

The signature is a detached Ed25519 signature over the exact bytes of `release.json`, base64-encoded. Node's built-in `crypto.verify` checks it, so verification needs nothing the bundle doesn't already require.

The release procedure gains one step between qualification and publication. The key holder:
1. downloads the draft's `release.json` and every asset it lists;
2. runs `scripts/sign-release.sh`, which checks every listed digest and every archive's `RELEASE.json` before signing, then prints the signature;
3. uploads `release.json.sig` to the draft and publishes it.

What gets signed is the candidate that passed qualification. A release without `release.json.sig` can't be installed through the bootstrap, so a draft published by mistake, or an asset swapped afterwards, fails closed.

The bootstrap pins a list of public keys, normally one. Rotating the key means adding the new key to the list in a bootstrap update before the first release signed with it, and removing the old one later. The public key is also printed in `docs/releasing.md` and on the website, for people who verify by hand.

### The bootstrap

`scripts/install.sh` is short, readable and self-contained. Its whole body sits inside a function that runs on the last line, so a download cut off halfway executes nothing. In order, it:

1. checks Linux, the architecture (amd64 or arm64), Bash, `tar`, `flock`, Node.js 22 or later, and `curl` or `wget`. When something is missing it names it, says how to get it, and stops before downloading anything;
2. downloads `release.json` and `release.json.sig` from `https://github.com/peerspan/peerspan/releases/latest/download/`, or from `.../releases/download/vVERSION/` with `--version`;
3. verifies the signature against the pinned keys, then checks the manifest's `format`, its `name`, its `version` (which must equal `--version` when given), and that it lists this architecture's host archive and `install-release.sh`;
4. downloads those two files into a new private temporary directory and checks both against the signed digests. It doesn't download the archive's `.sha256`. Instead it writes that file itself from the signed digest, for the unchanged archive installer (the manifest lists no `.sha256` files);
5. runs the downloaded `install-release.sh VERSION --from DIR`, passing through `--no-service`, and prints its output. The archive installer checks the `.sha256` file and `RELEASE.json` as it does today;
6. removes the temporary directory on every exit path.

Before the first download it prints one line saying what it is about to do (version, architecture, destination). It never uses `sudo`, never edits shell profiles, and doesn't write outside the temporary directory until step 5. If `~/.local/bin` isn't on `PATH`, the archive installer's existing message covers it.

Downloads use `curl --proto '=https' --tlsv1.2 -fsSL` or `wget --https-only -q`. They follow GitHub's redirects to its asset host and fail on any HTTP error.

### Serving it from peerspan.dev

The website repository holds a copy of `scripts/install.sh` from a tagged release, served at `/install` as `text/plain`. Each release that changes the bootstrap updates that copy as part of publication. Because the bootstrap finds the latest version by itself, an ordinary release needs no website change.

### `install-release.sh --from-github`

`--from-github OWNER/REPO` keeps its meaning, but downloads over HTTPS with `curl` or `wget` from `https://github.com/OWNER/REPO/releases/download/vVERSION/`. `gh` is no longer required or used. When `release.json` and `release.json.sig` are present beside the archive, it verifies them as the bootstrap does. This keeps the documented manual path working for people who want to read the installer before running it.

## What this protects against, and what it doesn't

- **Protects against:** a changed or corrupted archive or installer in a GitHub release, a release published without the signing step, and an older signed manifest served as `--version` for a different version. Replacing assets on GitHub alone is not enough to install unsigned code.
- **Doesn't protect against:** someone who controls what `peerspan.dev/install` serves. `curl | bash` trusts the website's TLS and its deployment. The pinned key moves trust off GitHub's asset storage; it doesn't make the bootstrap self-authenticating. People who want more can download `install.sh`, read it, and compare its key with the one in this repository and the release notes.
- **Doesn't protect against:** compromise of the signing key. That is why the key isn't in CI (decision 2).
- **Doesn't protect against downgrades:** an attacker who controls `releases/latest` could serve an older, correctly signed release. The manifest's version is shown before installing. Refusing versions older than the installed one is a possible follow-up, not part of this proposal.

## Risks

- **Node.js 22 is the largest remaining hurdle.** Ubuntu 22.04 and 24.04 and Debian 12 ship older Node in their default repositories. The bootstrap stops with a clear message and a link. Bundling a Node runtime in the archive would remove this hurdle, but it's a packaging change and would add roughly 30 MB to each compressed archive. I suggest deciding it separately, based on early launch feedback.
- **`releases/latest` skips prereleases.** The launch release has to be published as a full release, not a prerelease. Release notes and the README can still say "preview."
- **v0.1.0 has no manifest,** so the bootstrap can't install it. That is intended: the first release built with this procedure is the first one the website installs.

## Verification sketch

A separate author writes these cases from this proposal's contract section, once accepted, without reading the implementation. They form a new slim suite, `install`, which serves fixture releases from a local HTTPS server. It uses a bootstrap copy whose base URL and pinned key are rewritten for the test key, and fixture archives with the real bundle layout, installed with `--no-service`. It is expected to take under 60 seconds and about 400 lines, so it fits the per-push budget ([DEC-OWN14](decision-log.md#dec-own14-to-dec-own17-a-budget-for-the-conformance-suites-2026-11-03)).

- The latest release installs, and so does a pinned `--version`. The launcher points at the verified release and the archive matches the signed digest.
- With no `gh` on `PATH`, installs succeed using `curl` only and using `wget` only.
- Install is refused, and no file is written outside the temporary directory, when any of these happen:
  - the signature is missing, malformed, or made with an unpinned key;
  - the manifest is changed by one byte;
  - an archive or `install-release.sh` doesn't match its digest;
  - the manifest's version differs from `--version`;
  - this architecture is missing from the manifest;
  - a download is cut off.
- Missing Node.js, Node.js older than 22, a missing `tar` or `flock`, having neither `curl` nor `wget`, an unsupported architecture, or a non-Linux system each stop the bootstrap before any download, with a message naming the problem.
- A truncated bootstrap script executes nothing.
- Running the bootstrap again with a newer release upgrades. With the same release it changes nothing but the output.
- `install-release.sh --from-github` succeeds without `gh` and rejects a bad `release.json.sig` when one is present. `--from` behaves as before.

Live checks for release qualification, added to the [roadmap](production-roadmap.md#release-qualification): the real one-liner from `peerspan.dev` on clean Debian 12, Ubuntu 22.04 and Ubuntu 24.04 machines with no `gh` installed, on amd64 and arm64, followed by the quick start.

## Owner decisions needed

All five were accepted as recommended on 2026-11-04 and are recorded as INST-1 to INST-5 in the [decision log](decision-log.md#inst-1-to-inst-5-one-line-install-2026-11-04).

1. **Signing scheme.** (a) An Ed25519 signature over `release.json`, verified with Node's built-in crypto against a pinned key. (b) Sigstore keyless signing from the release workflow. Users would need `cosign` or a downloaded verifier, which brings back the extra tool this proposal removes. (c) Checksums only, as today. **Recommended:** (a).
2. **Who holds the key, and when signing happens.** (a) The owner holds it offline and signs at publication, after qualification. (b) A GitHub Actions secret in a protected environment that requires the owner's approval. A GitHub compromise could then sign as well as replace assets. **Recommended:** (a).
3. **Where `/install` comes from.** (a) A copy committed to the website repository, updated when the bootstrap changes. (b) A Vercel rewrite to the script on GitHub. This makes the website depend on GitHub, and a change to `main` would reach users without a release. **Recommended:** (a).
4. **How "latest" is found.** (a) GitHub's `releases/latest`, so the launch release is a full release and not a prerelease. (b) A `latest` pointer file on the website, updated at each publication. **Recommended:** (a).
5. **`gh` in `install-release.sh`.** (a) Replace it with HTTPS downloads. (b) Keep `gh` as a fallback for private forks. **Recommended:** (a). Private forks can still use `--from`.
