# Install contract

The one-line install from peerspan.dev. The design, its reasons and the options considered are in the [install proposal](install-proposal.md); the decisions are [INST-1 to INST-5](decision-log.md#inst-1-to-inst-5-one-line-install-2026-11-04). This contract is the specification for the implementation and for the independent `install` suite.

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

The private key is held offline by the owner ([INST-2](decision-log.md#inst-2-who-holds-the-key-and-when-signing-happens)). It is never stored in a repository, a CI secret or a shared machine.

## `scripts/sign-release.sh`

```sh
scripts/sign-release.sh --generate KEYFILE
scripts/sign-release.sh DIRECTORY KEYFILE
```

- **`--generate`** creates a new Ed25519 key, asks twice for a passphrase, writes it to `KEYFILE` as passphrase-encrypted PKCS#8 PEM with mode `0600`, and prints the public key in the form above. It refuses to overwrite an existing file, and refuses an empty passphrase.
- **Signing** reads `DIRECTORY/release.json` and checks it as a reader does. It then checks that every asset it lists is in `DIRECTORY` with the listed digest, and that each archive's `RELEASE.json` names the manifest's version, `source_revision`, `source_dirty: false`, the architecture in its file name, and, for host archives, `implementation: "rust"`. Only then does it ask for the passphrase (on the terminal, or as one line of standard input when there is none), sign, and write `DIRECTORY/release.json.sig`. It prints the public key it signed with. Any failed check writes nothing and exits 1.

## `scripts/install.sh`

The bootstrap. The website serves a byte-identical copy at `https://peerspan.dev/install` ([INST-3](decision-log.md#inst-3-where-install-comes-from)).

```sh
install.sh [--version VERSION] [--no-service]
```

Read from standard input (`curl … | bash`, `curl … | bash -s -- ARGS`) or run as a file, it behaves the same. An unknown argument, a repeated argument, or a `--version` that doesn't match the version pattern prints a usage line to standard error and exits 2 before any check below.

Near the top of the file, as single assignments a test can rewrite, are `PEERSPAN_RELEASE_KEYS` and:

```sh
PEERSPAN_RELEASES_URL="https://github.com/peerspan/peerspan/releases"
```

The rest of the script is a function definition, and its last line calls that function. A copy cut off at any byte executes nothing.

### Steps

1. **Preflight.** In this order, it requires: Linux (`uname -s`); amd64 or arm64 (`uname -m` of `x86_64`, `amd64`, `aarch64` or `arm64`); `tar`; `flock`; `node` with a major version of 22 or more; and `curl` or `wget`, preferring `curl` when both exist. The first failure prints one line to standard error naming what is missing or unsupported, and exits 1. A Node failure also prints where to get Node.js 22. Nothing is downloaded or written before preflight passes.
2. **Announce.** It prints one line naming the version it will look for (`latest` or `VERSION`), the architecture, and that it installs into the user's home.
3. **Manifest.** It creates a new directory with `mktemp -d` under `${TMPDIR:-/tmp}` with mode `0700`. It downloads `release.json` and `release.json.sig` from `PEERSPAN_RELEASES_URL/latest/download/`, or from `PEERSPAN_RELEASES_URL/download/vVERSION/` with `--version`. It verifies the signature, then checks the manifest as a reader does. With `--version`, the manifest's `version` must equal it. The manifest must list `peerspan-V-linux-ARCH-rust.tar.gz` for this machine's architecture and `install-release.sh`, where `V` is the manifest's version.
4. **Files.** From the same release, `PEERSPAN_RELEASES_URL/download/vV/`, it downloads the host archive and `install-release.sh`. Each must match its signed digest. It doesn't download the archive's `.sha256`. Instead it writes `peerspan-V-linux-ARCH-rust.tar.gz.sha256` itself, containing the signed digest, two spaces, the archive name, and a newline.
5. **Handoff.** It runs `bash DIR/install-release.sh V --from DIR`, adding `--no-service` when given, with the caller's environment. It exits with that command's status.
6. **Cleanup.** It removes the temporary directory on every exit after step 3 began, including failures and signals.

Every failure in steps 3 and 4 prints one line to standard error naming the file and the reason (download failed, bad signature, invalid manifest, version mismatch, missing architecture, digest mismatch), and exits 1. Before step 5, the bootstrap writes nothing outside its temporary directory.

### Downloads

- With `curl`: `curl --proto '=https' --tlsv1.2 -fsSL -o FILE URL`.
- With `wget`: `wget --https-only -q -O FILE URL`.

Redirects are followed, any HTTP error status is a failure, and every URL is HTTPS. `release.json`, `release.json.sig` and `install-release.sh` are refused above 64 KiB, 1 KiB and 1 MiB respectively. The bootstrap never runs `gh` or `sudo`, and never edits shell profiles.

## `scripts/install-release.sh`

The archive installer keeps its interface, layout and service behavior. Two things change:

- **`--from-github OWNER/REPO`** no longer uses `gh` ([INST-5](decision-log.md#inst-5-gh-in-install-releasesh)). It downloads `release.json`, `release.json.sig`, the host archive and its `.sha256` from `https://github.com/OWNER/REPO/releases/download/vVERSION/` as the bootstrap does. It requires the signature to verify under its `PEERSPAN_RELEASE_KEYS`, the manifest to be valid with `version` equal to `VERSION`, and the archive to match both its signed digest and its `.sha256`. A missing manifest or signature is a failure. A missing `curl` and `wget` is reported instead of a missing `gh`.
- **`--from DIRECTORY`:** when `DIRECTORY` contains both `release.json` and `release.json.sig`, it verifies them the same way before installing. When it contains exactly one of the two, it refuses. When it contains neither, it behaves as before: checksum only.

## Release procedure

[releasing.md](releasing.md) gains these steps, after qualification and before publication:
1. download the draft's assets into an empty directory;
2. run `scripts/sign-release.sh DIRECTORY KEYFILE`;
3. upload `release.json.sig` to the draft;
4. publish the draft as a full release, not a prerelease ([INST-4](decision-log.md#inst-4-how-latest-is-found)).

When a release changes `scripts/install.sh`, the website's `/install` copy is updated from that release's tag in the same publication. Qualification checks that the served `/install` is byte-identical to `scripts/install.sh` at the tag.

Release qualification ([roadmap](production-roadmap.md#release-qualification)) adds this live check: the real one-liner from `https://peerspan.dev/install`, with no `gh` installed, on clean Debian 12, Ubuntu 22.04 and Ubuntu 24.04 machines, on amd64 and arm64, followed by the quick start.

## Verification

`conformance/slim/install.py` is written from this contract by an author who doesn't read the implementation. It is a per-push suite, budgeted at under 60 seconds and about 400 lines ([DEC-OWN14](decision-log.md#dec-own14-to-dec-own17-a-budget-for-the-conformance-suites-2026-11-03)).

**Fixtures:**
- A local HTTPS server with a test certificate authority, trusted through `CURL_CA_BUNDLE` and `SSL_CERT_FILE`. The server records every request, and serves `latest/download/` by redirecting to a chosen version.
- Test keys generated per run. Each case uses a copy of `scripts/install.sh` (or `install-release.sh`) with `PEERSPAN_RELEASES_URL` and `PEERSPAN_RELEASE_KEYS` rewritten.
- Fixture host archives with the real bundle layout (`RELEASE.json`, an executable `bin/peerspan-host`, and the `bin/peerspan` link), installed with `--no-service`.
- `HOME`, `TMPDIR`, `PEERSPAN_INSTALL_DATA_DIR` and `PEERSPAN_INSTALL_BIN_DIR` redirected per case.
- `PATH` built per case from links to real tools, so that `gh`, `curl`, `wget` or `node` can be absent, or replaced by a stub reporting a given version or architecture.

**Cases:**
- **Install:**
  - latest installs;
  - `--version` installs that version;
  - the launcher points at the release directory;
  - the installed archive's digest equals the signed one;
  - the bootstrap works read from standard input and run as a file.
- **Without `gh`:**
  - installs succeed with only `curl`, and with only `wget`;
  - `gh` is never run (a stub `gh` that records calls stays uncalled).
- **Refusals**, each exiting 1, leaving the data and bin directories unchanged and the temporary directory removed:
  - signature missing, not base64, the wrong length, or made with an unlisted key;
  - `release.json` changed by one byte after signing;
  - manifest with a missing member, wrong `format`, wrong `name`, a malformed digest, or over 64 KiB;
  - manifest version different from `--version`;
  - this architecture's archive not listed;
  - archive or `install-release.sh` not matching its digest;
  - an HTTP error on any download;
  - a response cut short;
  - a file over its size limit.
- **A second listed key:** a manifest signed with the second of two listed keys installs.
- **Preflight**, each exiting 1 with the missing piece named on standard error and the server recording no request:
  - no `node`;
  - Node 21;
  - no `tar`;
  - no `flock`;
  - neither `curl` nor `wget`;
  - an unsupported `uname -m`;
  - a non-Linux `uname -s`.
- **Usage:** an unknown argument, a repeated `--version`, or a malformed version exits 2 with no request.
- **Truncation:** the bootstrap cut at several byte offsets, piped to `bash`, makes no request and writes nothing.
- **Rerun:**
  - a newer release upgrades the launcher;
  - the same release again leaves the release directory and launcher unchanged.
- **`install-release.sh --from-github`:**
  - succeeds without `gh`;
  - refuses a missing or bad `release.json.sig`;
  - refuses a manifest whose version differs.
- **`install-release.sh --from`:**
  - with both manifest files it verifies them;
  - with only one it refuses;
  - with neither it installs from the checksum as before.

**`sign-release.sh`** is checked by the same author:
- `--generate` writes an encrypted `0600` key and prints a public key that the bootstrap accepts;
- it refuses to overwrite a key file;
- signing writes nothing when an asset's digest is wrong or a `RELEASE.json` disagrees;
- a produced signature verifies.

The suite supplies the passphrase on standard input, with no terminal.
