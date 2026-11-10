# Install contract

The one-line install from peerspan.dev. The design, its reasons and the options considered are in the [install proposal](install-proposal.md); the decisions are [INST-1 to INST-5](decision-log.md#inst-1-to-inst-5-one-line-install-2026-11-04), [INST-6](decision-log.md#inst-6-who-may-change-the-release-keys-2026-11-04), [INST-7](decision-log.md#inst-7-no-conformance-suite-for-the-install-scripts-2026-11-04) and [INST-9 to INST-11](decision-log.md#inst-9-to-inst-11-bundled-nodejs-and-our-own-release-verifier-2026-11-10). Nothing in the install path needs Node.js on the machine: the release is checked by Peerspan's own verifier, and each host bundle carries its own Node.js. This contract is the specification for the implementation. There is no conformance suite for the install scripts (INST-7): they are checked by the release procedure's live installs.

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

A signature is valid when it verifies under any listed key. The [release verifier](#release-verifier) checks it with strict Ed25519 verification (RFC 8032, rejecting a non-canonical `R` or `S` and a small-order public key or `R`).

A listed value that isn't a usable key is ignored, never trusted. That's one that:
- isn't 43 base64url characters decoding to 32 bytes;
- is a non-canonical encoding, with its y-coordinate (the 32 bytes little-endian with the top bit cleared) at least p = 2^255 − 19;
- or has the y-coordinate of a point of order 1, 2, 4 or 8: y = 0, 1, p − 1, or either y-coordinate of the four order-8 points. All-zero bytes are one of these.

Signatures can be forged for small-order keys without a private key, and Ed25519 libraries differ on whether they accept them, so the verifier rejects them itself before verifying. A list with no usable key accepts nothing.

The list holds the keys of the latest key decision in the [decision log](decision-log.md). Since [INST-8](decision-log.md#inst-8-the-first-release-key-2026-11-05) that is one key, `KEVbydgOxsDcbjKkau07nJT5lKQUChqJYGhGqNg0pRc`. Before INST-8 the scripts shipped with an off-curve placeholder, `AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, under which nothing installed.

The private key is held offline by the owner ([INST-2](decision-log.md#inst-2-who-holds-the-key-and-when-signing-happens)). It is never stored in a repository, a CI secret or a shared machine.

### Changing the release keys

Anyone can generate an Ed25519 key, with `sign-release.sh --generate` or any other tool. Only the listed keys are trusted, so the list is what's protected ([INST-6](decision-log.md#inst-6-who-may-change-the-release-keys-2026-11-04)):

- **Owner decision.** Adding or removing a key is an owner decision, with its own decision-log entry naming the public key. The change lands in a pull request that changes nothing else.
- **Owner review.** `.github/CODEOWNERS` names the owner for `scripts/install.sh`, `scripts/install-release.sh`, `scripts/sign-release.sh`, the verifier's source and the workflow that builds it, and itself. This is enforced when the `main` ruleset requires code-owner review.
- **Matching lists.** `PEERSPAN_RELEASE_KEYS` is identical in `scripts/install.sh` and `scripts/install-release.sh`, at every commit.
- **Release checks.** Before publication, the key holder checks that the list in the tagged `scripts/install.sh` and in the release's `install-release.sh` asset equals the keys of the latest key decision in the log; a difference stops publication. After publication, the served `https://peerspan.dev/install` is checked the same way ([Release procedure](#after-publication)).

## Release verifier

[INST-10](decision-log.md#inst-10-what-verifies-the-release-before-node-is-available): a small program of Peerspan's own checks a release before anything from it runs, so the install path needs neither Node.js nor `openssl`.

### Build and publication

- **Source.** A separate crate in this repository, `verifier/`, depending only on an Ed25519 implementation with strict verification, a SHA-256 implementation and a JSON parser. Its dependency versions are pinned in its own `Cargo.lock`.
- **Binaries.** `peerspan-verify-linux-amd64` and `peerspan-verify-linux-arm64`: statically linked (musl) executables with no runtime library dependencies, built by a workflow of their own.
- **Release.** They are published as the only assets of a release tagged `verifier-vN` (N = 1, 2, …). That release is marked as a prerelease, so it never becomes `releases/latest` ([INST-4](decision-log.md#inst-4-how-latest-is-found)). A `verifier-vN` release is never changed after publication; a new verifier gets a new N.
- **Pinned digests.** `scripts/install.sh` and `scripts/install-release.sh` each contain the same two assignments near the top, next to `PEERSPAN_RELEASE_KEYS`:

  ```sh
  PEERSPAN_VERIFIER_RELEASE="verifier-v1"
  PEERSPAN_VERIFIER_SHA256="amd64:HEX arm64:HEX"
  ```

  `PEERSPAN_VERIFIER_SHA256` lists, per architecture, the SHA-256 of the verifier binary from that release. A downloaded verifier runs only if its digest equals the listed one for this machine's architecture.
- **Changing the verifier** follows the same rules as [changing the release keys](#changing-the-release-keys): the new `verifier-vN` release is published first, then one pull request that changes nothing else updates both assignments in both scripts. The owner reviews it. The website's `/install` copy changes only with the next host release (step 7 below). Every `verifier-vN` release ever pinned stays published.
- **Across rotations.** A bootstrap and the `install-release.sh` it installs can pin different verifiers: an older bootstrap fetching the latest release, or a newer bootstrap with `--version` of an older one. The bootstrap therefore always hands the installer the verifier that *installer* pins (step 6 of the bootstrap). That installer's pins are trustworthy because its file was already accepted by its signed digest, under the bootstrap's own verifier.

### Interface

```sh
peerspan-verify --keys "KEY1 KEY2" --manifest release.json --signature release.json.sig \
  [--version VERSION] [--file NAME[=PATH] ...]
```

It succeeds, prints the manifest's `version` on one line and exits 0 only when all of these hold:

1. at least one key in `--keys` is usable, by the rules of [Release keys](#release-keys);
2. `--signature` is exactly one line in the [`release.json.sig`](#releasejsonsig) form, and is a valid signature over the exact bytes of `--manifest` under one usable key;
3. `--manifest` is a valid `release.json` as a reader checks it, and with `--version` its `version` equals `VERSION`;
4. for every `--file NAME[=PATH]`, `NAME` is listed in the manifest's `assets`, and, when `PATH` is given, the SHA-256 of the file at `PATH` equals the listed digest. `--file NAME` alone lets the bootstrap check that a file is listed before downloading it.

It reads nothing else, writes nothing, and makes no network requests. Any other result prints one line to standard error naming the file and the reason (`bad signature`, `no usable release key`, `invalid manifest`, `version mismatch`, `not listed`, `digest mismatch`), and exits 1. A usage error exits 2. Files are limited as in [Downloads](#downloads), and an archive passed with `--file` is hashed as a stream.

## Bundled Node.js

[INST-9](decision-log.md#inst-9-nodejs-for-the-install-and-the-integrations) and [INST-11](decision-log.md#inst-11-which-nodejs-line-the-bundle-carries): each host archive carries the Node.js runtime its integrations run on.

- **Version.** Node.js 24 LTS, pinned to one exact release in `scripts/package-release.sh` (v24.22.2 when this was decided). A patch or security update within line 24 is an ordinary pull request. Moving to another major line is an owner decision.
- **Provenance.** The packaging script downloads the official `node-vV-linux-x64.tar.xz` or `node-vV-linux-arm64.tar.xz` from `https://nodejs.org/dist/vV/`. It requires the file's SHA-256 to equal a digest pinned in the script, copied from that release's `SHASUMS256.txt`. Otherwise packaging fails.
- **Layout.** The archive holds `share/peerspan/node/bin/node`, `share/peerspan/node/LICENSE` and `share/peerspan/node/README.md` from the Node.js tarball, and nothing else from it (no `npm`, `npx`, `corepack` or headers). The host archive's `RELEASE.json` gains `node`, the bundled version without `v`, and drops `node_requirement`.
- **Use.** When an integration's command starts with `node` and no `--runner` is given, the daemon runs it with the release's own `share/peerspan/node/bin/node`. That Node then runs the integration's channel, sidecar and MCP processes. `--runner PATH` still overrides it. A source checkout without a bundled Node keeps using `node` from `PATH`.
- **Requirement.** The bundled Node needs glibc 2.28 or later, which the supported distributions (Debian 12, Ubuntu 22.04 and 24.04) exceed. `install-release.sh` refuses a machine where the bundled `node --version` doesn't run, naming the glibc requirement.

## `scripts/sign-release.sh`

```sh
scripts/sign-release.sh --generate KEYFILE
scripts/sign-release.sh DIRECTORY KEYFILE
```

- **`--generate`** creates a new Ed25519 key, asks twice for a passphrase (on the terminal, or as two lines of standard input when there is none; the two must match), writes it to `KEYFILE` as passphrase-encrypted PKCS#8 PEM with mode `0600`, and prints the public key in the form above. It refuses to overwrite an existing file, and refuses an empty passphrase.
Signing runs on the owner's machine and still uses that machine's Node.js 22 or later; it is not part of the install path.

- **Signing** reads `DIRECTORY/release.json` and checks it as a reader does. It then checks that every asset it lists is in `DIRECTORY` with the listed digest, and that each archive's `RELEASE.json` names the manifest's version, `source_revision`, `source_dirty: false`, the architecture in its file name, and, for host archives, `implementation: "rust"`. Only then does it ask for the passphrase (on the terminal, or as one line of standard input when there is none), sign, and write `DIRECTORY/release.json.sig`. It prints the public key it signed with. It refuses to replace an existing `release.json.sig`. Any failed check writes nothing and exits 1.

## `scripts/install.sh`

The bootstrap. The website serves a byte-identical copy at `https://peerspan.dev/install` ([INST-3](decision-log.md#inst-3-where-install-comes-from)).

```sh
install.sh [--version VERSION] [--no-service]
```

Read from standard input (`curl … | bash`, `curl … | bash -s -- ARGS`) or run as a file, it behaves the same. An unknown argument, a repeated argument, or a `--version` that doesn't match the version pattern prints a usage line to standard error and exits 2 before any check below.

Near the top of the file, as single assignments, are `PEERSPAN_RELEASE_KEYS`, `PEERSPAN_VERIFIER_RELEASE`, `PEERSPAN_VERIFIER_SHA256` and:

```sh
PEERSPAN_RELEASES_URL="https://github.com/peerspan/peerspan/releases"
```

The rest of the script is a function definition, and its last line calls that function inside braces (`{ peerspan_bootstrap "$@"; }`). A copy cut off before its last line is complete executes nothing: every such copy either only defines the function or is a syntax error.

### Steps

1. **Preflight.** In this order, it requires: Linux (`uname -s`); amd64 or arm64 (`uname -m` of `x86_64`, `amd64`, `aarch64` or `arm64`); `tar`; `flock`; `sha256sum`; and `curl` or `wget`, preferring `curl` when both exist. It does not require Node.js. The first failure prints one line to standard error naming what is missing or unsupported, and exits 1. Nothing is downloaded or written before preflight passes.
2. **Announce.** It prints one line naming the version it will look for (`latest` or `VERSION`), the architecture, and that it installs into the user's home.
3. **Verifier.** It creates a new directory with `mktemp -d` under `${TMPDIR:-/tmp}` with mode `0700`. It downloads `peerspan-verify-linux-ARCH` from `PEERSPAN_RELEASES_URL/download/PEERSPAN_VERIFIER_RELEASE/`, checks its SHA-256 with `sha256sum` against `PEERSPAN_VERIFIER_SHA256` for this architecture, and only then makes it executable.
4. **Manifest.** It downloads `release.json` and `release.json.sig` from `PEERSPAN_RELEASES_URL/latest/download/`, or from `PEERSPAN_RELEASES_URL/download/vVERSION/` with `--version`. The verifier checks the signature and the manifest, and with `--version` that the manifest's `version` equals it. The manifest must list `peerspan-V-linux-ARCH-rust.tar.gz` for this machine's architecture and `install-release.sh`, where `V` is the manifest's version.
5. **Files.** From the same release, `PEERSPAN_RELEASES_URL/download/vV/`, it downloads the host archive and `install-release.sh`. The verifier checks each against its signed digest. It doesn't download the archive's `.sha256`. Instead it writes `peerspan-V-linux-ARCH-rust.tar.gz.sha256` itself, containing the signed digest, two spaces, the archive name, and a newline.
6. **Installer's verifier.** It reads `PEERSPAN_VERIFIER_RELEASE` and `PEERSPAN_VERIFIER_SHA256` from the verified `install-release.sh`. It requires exactly one line of each, of the exact form `NAME="VALUE"` at the start of a line. `VALUE` must match `verifier-v[1-9][0-9]*` for the release, and be `amd64:` and `arm64:` each followed by 64 lowercase hexadecimal characters for the digests. It never executes that file to read them. When the installer pins the same release and digest as the bootstrap, the verifier already downloaded is used. Otherwise it downloads `peerspan-verify-linux-ARCH` from the installer's pinned release and requires its SHA-256 to equal the installer's pinned digest. Either way, the verifier the installer pins is placed in `DIR` as `peerspan-verify-linux-ARCH`, mode `0755`.
7. **Handoff.** It runs `bash DIR/install-release.sh V --from DIR`, adding `--no-service` when given, with the caller's environment. It exits with that command's status.
8. **Cleanup.** It removes the temporary directory on every exit after step 3 began, including failures and signals.

Every failure in steps 3 to 6 prints one line to standard error naming the file and the reason, with the download tool's own error message folded into that line rather than printed separately (download failed, verifier digest mismatch, bad signature, invalid manifest, version mismatch, missing architecture, digest mismatch, invalid installer pins), and exits 1. Before step 7, the bootstrap writes nothing outside its temporary directory.

### Downloads

- With `curl`: `curl --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 --max-filesize LIMIT -fsSL -o FILE URL`.
- With `wget`: `wget --https-only --max-redirect=5 --tries=1 --timeout=60 -q -O FILE URL`. Outside recursive mode, wget's `--https-only` doesn't stop a redirect to plain HTTP. That only matters for privacy, not integrity: every file is accepted only by its signature or signed digest. This is one reason `curl` is preferred.

Redirects are followed up to 5 times (and with `curl` only to HTTPS), any HTTP error status is a failure, and a download is tried once. `release.json`, `release.json.sig`, `install-release.sh`, a `.sha256` file and the verifier are refused above 64 KiB, 1 KiB, 1 MiB, 1 KiB and 16 MiB respectively; with `curl` the limit is also passed as `--max-filesize`, and every file's size is checked after download. The host archive has no size limit: its signed digest bounds what's accepted. The bootstrap never runs `gh` or `sudo`, and never edits shell profiles.

## `scripts/install-release.sh`

The archive installer keeps its interface, layout and service behavior: it installs each release under `${PEERSPAN_INSTALL_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}}/peerspan/releases/`, links the launcher `${PEERSPAN_INSTALL_BIN_DIR:-$HOME/.local/bin}/peerspan` to the release's `bin/peerspan`, and runs `peerspan install` unless given `--no-service`. It contains the same `PEERSPAN_RELEASE_KEYS`, `PEERSPAN_VERIFIER_RELEASE` and `PEERSPAN_VERIFIER_SHA256` as the bootstrap, and doesn't require Node.js on the machine: every check before extraction uses the verifier and `sha256sum`. After the archive is verified and extracted, its later checks (reading `RELEASE.json`, checking the bundle) may use the bundle's own `share/peerspan/node/bin/node`. These things change:

- **`--from-github OWNER/REPO`** no longer uses `gh` ([INST-5](decision-log.md#inst-5-gh-in-install-releasesh)). It downloads `release.json`, `release.json.sig`, the host archive and its `.sha256` from `https://github.com/OWNER/REPO/releases/download/vVERSION/` with the bootstrap's download rules. It downloads the verifier as the bootstrap does. The verifier must accept the signature under its `PEERSPAN_RELEASE_KEYS`, the manifest with `version` equal to `VERSION`, and the archive's signed digest. The archive must also match its `.sha256`. A missing manifest or signature is a failure. A missing `curl` and `wget` is reported instead of a missing `gh`.
- **`--from DIRECTORY`:** when `DIRECTORY` contains both `release.json` and `release.json.sig`, it verifies them the same way before installing. The verifier must then be in `DIRECTORY` as `peerspan-verify-linux-ARCH`, with its pinned digest. It is never downloaded in this mode, so an offline directory stays offline. A missing verifier is refused with one line naming where to download it. When `DIRECTORY` contains exactly one of `release.json` and `release.json.sig`, it refuses. When it contains neither, it behaves as before, checksum only, using `sha256sum`.

## Release procedure

Publication splits into checks that qualify the draft and checks that need the published release. A draft's assets can't be downloaded without authentication, and the website's `/install` changes only after publication, so the real one-liner can only be checked afterwards. [releasing.md](releasing.md) and the [roadmap's qualification sequence](production-roadmap.md#release-qualification) gain these steps.

### Before publication

The `verifier-vN` release that the tagged scripts pin must already be published, with digests equal to `PEERSPAN_VERIFIER_SHA256`. After the existing draft qualification:
1. download the draft's assets into an empty directory;
2. check that `PEERSPAN_RELEASE_KEYS` in the tagged `scripts/install.sh` and in the draft's `install-release.sh` asset equals the keys of the latest key decision in the log ([Changing the release keys](#changing-the-release-keys));
3. run `scripts/sign-release.sh DIRECTORY KEYFILE`;
4. on clean Debian 12, Ubuntu 22.04 and Ubuntu 24.04 machines, on amd64 and arm64, with no `gh` and no Node.js installed, copy that directory (now including `release.json.sig`, plus the verifier for that architecture from the pinned `verifier-vN` release) and install with its `install-release.sh VERSION --from DIRECTORY`. This exercises the signed-manifest check on the exact candidate. Then follow the quick start. The bootstrap itself can't run against a draft, so it is first exercised for real by step 9;
5. upload `release.json.sig` to the draft.

Any failure stops publication.

### Publication

6. Publish the draft as a full release, not a prerelease ([INST-4](decision-log.md#inst-4-how-latest-is-found)). Clear both flags explicitly, whatever the draft was created with: `gh release edit vVERSION --repo peerspan/peerspan --draft=false --prerelease=false`. The Draft Linux release workflow also stops passing `--prerelease` when it creates the draft.
7. When the release changes `scripts/install.sh`, update the website's `/install` copy from the release's tag, after step 6. A new bootstrap served before its release is published would find only the previous release.

### After publication

8. Check that the served `https://peerspan.dev/install` is byte-identical to `scripts/install.sh` at the tag, and that its `PEERSPAN_RELEASE_KEYS` equals the keys of the latest key decision.
9. On a clean Debian 12, Ubuntu 22.04 or Ubuntu 24.04 machine for each architecture, with no `gh` and no Node.js installed, run the real one-liner from `https://peerspan.dev/install`. It must install this release, as `latest` and as `--version VERSION`.

If step 8 or 9 fails, mark the release as a prerelease straight away. `releases/latest` then names the previous full release, or none, so the one-liner installs the previous release or fails closed. Then restore the website copy, fix the problem, and publish a new version. Assets of a published version are never replaced.
