# Install contract

The one-line install from peerspan.dev. The design, its reasons and the options considered are in the [install proposal](install-proposal.md); the decisions are [INST-1 to INST-5](decision-log.md#inst-1-to-inst-5-one-line-install-2026-11-04), [INST-6](decision-log.md#inst-6-who-may-change-the-release-keys-2026-11-04) and [INST-7](decision-log.md#inst-7-no-conformance-suite-for-the-install-scripts-2026-11-04). This contract is the specification for the implementation. There is no conformance suite for the install scripts (INST-7): they are checked by the release procedure's live installs.

## Release assets

The Draft Linux release workflow adds `release.json` to the draft's assets. Publication adds `release.json.sig`. A published release therefore has twelve assets: the ten listed in the [release procedure](releasing.md#build-a-draft-candidate), `release.json`, and `release.json.sig`.

### `release.json`

A UTF-8 JSON object, at most 64 KiB, with exactly these members:

| Member | Value |
| --- | --- |
| `format` | the number `1` |
| `name` | the string `"peerspan"` |
| `version` | the release version without `v`, matching `^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$` |
| `source_revision` | the workflow commit, 40 lowercase hexadecimal characters |
| `assets` | an object mapping each asset file name to its SHA-256 as 64 lowercase hexadecimal characters |

Each archive's `RELEASE.json`, written by the packaging scripts, has at least `version`, `os` (`"linux"`), `architecture` (`amd64` or `arm64`), `source_revision` and `source_dirty`; host archives also have `implementation` (`"rust"`). An archive's single root directory is its file name without `.tar.gz`. The checks below that name these fields compare them exactly.

`assets` names exactly the two host archives, the two helper archives and `install-release.sh` of that release. It does not list the `.sha256` files, `release.json` or `release.json.sig`. The workflow writes it only after the checks it already makes on each archive's `RELEASE.json`, and from the same digests.

A reader refuses a manifest that isn't valid JSON, exceeds 64 KiB, lacks a member, has a member of the wrong type or form, or whose `format` isn't `1`. It ignores members it doesn't know.

### `release.json.sig`

One line: the standard base64 encoding (with padding) of a 64-byte Ed25519 signature over the exact bytes of `release.json` as published, followed by a newline. No other content is accepted.

### Release keys

A release key is an Ed25519 key. Its public half is written as the base64url encoding, without padding, of its 32 raw bytes (the `x` member of its JWK). `scripts/install.sh` and `scripts/install-release.sh` each contain the same list of 1 to 4 accepted public keys, as one assignment near the top of the file:

```sh
PEERSPAN_RELEASE_KEYS="KEY1 KEY2"
```

A signature is valid when it verifies under any listed key. Verification uses Node's `crypto.verify(null, data, key, signature)` with the key built from its JWK.

A listed value that isn't a usable key is ignored, never trusted. That's one that:
- isn't 43 base64url characters decoding to 32 bytes;
- is a non-canonical encoding, with its y-coordinate (the 32 bytes little-endian with the top bit cleared) at least p = 2^255 − 19;
- or has the y-coordinate of a point of order 1, 2, 4 or 8: y = 0, 1, p − 1, or either y-coordinate of the four order-8 points. All-zero bytes are one of these.

Node accepts such small-order keys, and signatures can be forged for them without a private key, so each script rejects them itself before verifying. A list with no usable key accepts nothing.

The list holds the keys of the latest key decision in the [decision log](decision-log.md). Since [INST-8](decision-log.md#inst-8-the-first-release-key-2026-11-05) that is one key, `KEVbydgOxsDcbjKkau07nJT5lKQUChqJYGhGqNg0pRc`. Before INST-8 the scripts shipped with an off-curve placeholder, `AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, under which nothing installed.

The private key is held offline by the owner ([INST-2](decision-log.md#inst-2-who-holds-the-key-and-when-signing-happens)). It is never stored in a repository, a CI secret or a shared machine.

### Changing the release keys

Anyone can generate an Ed25519 key, with `sign-release.sh --generate` or any other tool. Only the listed keys are trusted, so the list is what's protected ([INST-6](decision-log.md#inst-6-who-may-change-the-release-keys-2026-11-04)):

- **Owner decision.** Adding or removing a key is an owner decision, with its own decision-log entry naming the public key. The change lands in a pull request that changes nothing else.
- **Owner review.** `.github/CODEOWNERS` names the owner for `scripts/install.sh`, `scripts/install-release.sh`, `scripts/sign-release.sh` and itself. This is enforced when the `main` ruleset requires code-owner review.
- **Matching lists.** `PEERSPAN_RELEASE_KEYS` is identical in `scripts/install.sh` and `scripts/install-release.sh`, at every commit.
- **Release checks.** Before publication, the key holder checks that the list in the tagged `scripts/install.sh` and in the release's `install-release.sh` asset equals the keys of the latest key decision in the log; a difference stops publication. After publication, the served `https://peerspan.dev/install` is checked the same way ([Release procedure](#after-publication)).

## `scripts/sign-release.sh`

```sh
scripts/sign-release.sh --generate KEYFILE
scripts/sign-release.sh DIRECTORY KEYFILE
```

- **`--generate`** creates a new Ed25519 key, asks twice for a passphrase (on the terminal, or as two lines of standard input when there is none; the two must match), writes it to `KEYFILE` as passphrase-encrypted PKCS#8 PEM with mode `0600`, and prints the public key in the form above. It refuses to overwrite an existing file, and refuses an empty passphrase.
- **Signing** reads `DIRECTORY/release.json` and checks it as a reader does. It then checks that every asset it lists is in `DIRECTORY` with the listed digest, and that each archive's `RELEASE.json` names the manifest's version, `source_revision`, `source_dirty: false`, the architecture in its file name, and, for host archives, `implementation: "rust"`. Only then does it ask for the passphrase (on the terminal, or as one line of standard input when there is none), sign, and write `DIRECTORY/release.json.sig`. It prints the public key it signed with. It refuses to replace an existing `release.json.sig`. Any failed check writes nothing and exits 1.

## `scripts/install.sh`

The bootstrap. The website serves a byte-identical copy at `https://peerspan.dev/install` ([INST-3](decision-log.md#inst-3-where-install-comes-from)).

```sh
install.sh [--version VERSION] [--no-service]
```

Read from standard input (`curl … | bash`, `curl … | bash -s -- ARGS`) or run as a file, it behaves the same. An unknown argument, a repeated argument, or a `--version` that doesn't match the version pattern prints a usage line to standard error and exits 2 before any check below.

Near the top of the file, as single assignments, are `PEERSPAN_RELEASE_KEYS` and:

```sh
PEERSPAN_RELEASES_URL="https://github.com/peerspan/peerspan/releases"
```

The rest of the script is a function definition, and its last line calls that function inside braces (`{ peerspan_bootstrap "$@"; }`). A copy cut off before its last line is complete executes nothing: every such copy either only defines the function or is a syntax error.

### Steps

1. **Preflight.** In this order, it requires: Linux (`uname -s`); amd64 or arm64 (`uname -m` of `x86_64`, `amd64`, `aarch64` or `arm64`); `tar`; `flock`; `node` with a major version of 22 or more; and `curl` or `wget`, preferring `curl` when both exist. The first failure prints one line to standard error naming what is missing or unsupported, and exits 1. A Node failure also prints where to get Node.js 22. Nothing is downloaded or written before preflight passes.
2. **Announce.** It prints one line naming the version it will look for (`latest` or `VERSION`), the architecture, and that it installs into the user's home.
3. **Manifest.** It creates a new directory with `mktemp -d` under `${TMPDIR:-/tmp}` with mode `0700`. It downloads `release.json` and `release.json.sig` from `PEERSPAN_RELEASES_URL/latest/download/`, or from `PEERSPAN_RELEASES_URL/download/vVERSION/` with `--version`. It verifies the signature, then checks the manifest as a reader does. With `--version`, the manifest's `version` must equal it. The manifest must list `peerspan-V-linux-ARCH-rust.tar.gz` for this machine's architecture and `install-release.sh`, where `V` is the manifest's version.
4. **Files.** From the same release, `PEERSPAN_RELEASES_URL/download/vV/`, it downloads the host archive and `install-release.sh`. Each must match its signed digest. It doesn't download the archive's `.sha256`. Instead it writes `peerspan-V-linux-ARCH-rust.tar.gz.sha256` itself, containing the signed digest, two spaces, the archive name, and a newline.
5. **Handoff.** It runs `bash DIR/install-release.sh V --from DIR`, adding `--no-service` when given, with the caller's environment. It exits with that command's status.
6. **Cleanup.** It removes the temporary directory on every exit after step 3 began, including failures and signals.

Every failure in steps 3 and 4 prints one line to standard error naming the file and the reason, with the download tool's own error message folded into that line rather than printed separately (download failed, bad signature, invalid manifest, version mismatch, missing architecture, digest mismatch), and exits 1. Before step 5, the bootstrap writes nothing outside its temporary directory.

### Downloads

- With `curl`: `curl --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 --max-filesize LIMIT -fsSL -o FILE URL`.
- With `wget`: `wget --https-only --max-redirect=5 --tries=1 --timeout=60 -q -O FILE URL`. Outside recursive mode, wget's `--https-only` doesn't stop a redirect to plain HTTP. That only matters for privacy, not integrity: every file is accepted only by its signature or signed digest. This is one reason `curl` is preferred.

Redirects are followed up to 5 times (and with `curl` only to HTTPS), any HTTP error status is a failure, and a download is tried once. `release.json`, `release.json.sig`, `install-release.sh` and a `.sha256` file are refused above 64 KiB, 1 KiB, 1 MiB and 1 KiB respectively; with `curl` the limit is also passed as `--max-filesize`, and every file's size is checked after download. The host archive has no size limit: its signed digest bounds what's accepted. The bootstrap never runs `gh` or `sudo`, and never edits shell profiles.

## `scripts/install-release.sh`

The archive installer keeps its interface, layout and service behavior: it installs each release under `${PEERSPAN_INSTALL_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}}/peerspan/releases/`, links the launcher `${PEERSPAN_INSTALL_BIN_DIR:-$HOME/.local/bin}/peerspan` to the release's `bin/peerspan`, and runs `peerspan install` unless given `--no-service`. Two things change:

- **`--from-github OWNER/REPO`** no longer uses `gh` ([INST-5](decision-log.md#inst-5-gh-in-install-releasesh)). It downloads `release.json`, `release.json.sig`, the host archive and its `.sha256` from `https://github.com/OWNER/REPO/releases/download/vVERSION/` with the bootstrap's download rules. It requires the signature to verify under its `PEERSPAN_RELEASE_KEYS`, the manifest to be valid with `version` equal to `VERSION`, and the archive to match both its signed digest and its `.sha256`. A missing manifest or signature is a failure. A missing `curl` and `wget` is reported instead of a missing `gh`.
- **`--from DIRECTORY`:** when `DIRECTORY` contains both `release.json` and `release.json.sig`, it verifies them the same way before installing. When it contains exactly one of the two, it refuses. When it contains neither, it behaves as before: checksum only.

## Release procedure

Publication splits into checks that qualify the draft and checks that need the published release. A draft's assets can't be downloaded without authentication, and the website's `/install` changes only after publication, so the real one-liner can only be checked afterwards. [releasing.md](releasing.md) and the [roadmap's qualification sequence](production-roadmap.md#release-qualification) gain these steps.

### Before publication

After the existing draft qualification:
1. download the draft's assets into an empty directory;
2. check that `PEERSPAN_RELEASE_KEYS` in the tagged `scripts/install.sh` and in the draft's `install-release.sh` asset equals the keys of the latest key decision in the log ([Changing the release keys](#changing-the-release-keys));
3. run `scripts/sign-release.sh DIRECTORY KEYFILE`;
4. on clean Debian 12, Ubuntu 22.04 and Ubuntu 24.04 machines, on amd64 and arm64, with no `gh` installed, copy that directory (now including `release.json.sig`) and install with its `install-release.sh VERSION --from DIRECTORY`. This exercises the signed-manifest check on the exact candidate. Then follow the quick start. The bootstrap itself can't run against a draft, so it is first exercised for real by step 9;
5. upload `release.json.sig` to the draft.

Any failure stops publication.

### Publication

6. Publish the draft as a full release, not a prerelease ([INST-4](decision-log.md#inst-4-how-latest-is-found)). Clear both flags explicitly, whatever the draft was created with: `gh release edit vVERSION --repo peerspan/peerspan --draft=false --prerelease=false`. The Draft Linux release workflow also stops passing `--prerelease` when it creates the draft.
7. When the release changes `scripts/install.sh`, update the website's `/install` copy from the release's tag, after step 6. A new bootstrap served before its release is published would find only the previous release.

### After publication

8. Check that the served `https://peerspan.dev/install` is byte-identical to `scripts/install.sh` at the tag, and that its `PEERSPAN_RELEASE_KEYS` equals the keys of the latest key decision.
9. On a clean Debian 12, Ubuntu 22.04 or Ubuntu 24.04 machine for each architecture, with no `gh` installed, run the real one-liner from `https://peerspan.dev/install`. It must install this release, as `latest` and as `--version VERSION`.

If step 8 or 9 fails, mark the release as a prerelease straight away. `releases/latest` then names the previous full release, or none, so the one-liner installs the previous release or fails closed. Then restore the website copy, fix the problem, and publish a new version. Assets of a published version are never replaced.
