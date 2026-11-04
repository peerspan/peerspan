# Linux preview releases

The [Draft Linux release workflow](../.github/workflows/linux-release.yml) is run manually from `main`. It builds the Rust host bundle and the separate optional helper natively on Linux amd64 and arm64, checks installed bundles and checksums, and creates a **draft release** in the repository it runs in. It also attaches the installer script and its checksum. Publishing the draft makes the release visible to everyone who can see the repository.

Coordinator-free host packages need no coordinator address, coordinator public key, staging identity or vendor helper default. Do not set `PEERSPAN_COORDINATOR` or `PEERSPAN_COORDINATOR_KEY` when packaging, including empty values: the scripts refuse those obsolete options. The workflow does not consume the old repository variables. Optional helper addresses, transport pins and resource credentials are explicit private host configuration, separate from network authority.

## Build a draft candidate

1. Merge the reviewed source and run the Rust checks and all slim conformance suites at the intended revision. Record that exact commit. The remaining installed and live checks qualify the resulting draft before publication.
2. Set the version in `Cargo.toml` to the intended release version. The workflow requires its `version` input to match. Use a new version for each release; do not replace assets for an existing tag.
3. Run **Draft Linux release** from `main` with the version without the `v` prefix. The workflow checks the selected branch and creates `vVERSION` at the workflow commit only after both host bundles pass.

With authenticated GitHub CLI, dispatch and follow the candidate build:

```sh
gh workflow run linux-release.yml --repo peerspan/peerspan --ref main -f version=VERSION
gh run list --repo peerspan/peerspan --workflow linux-release.yml --limit 1
gh run watch RUN_ID --repo peerspan/peerspan --exit-status
```

Review the draft's ten build assets: two host archives, two helper archives, four matching `.sha256` files, `install-release.sh`, and `install-release.sh.sha256`. Every archive's `RELEASE.json` must name the workflow commit, the correct architecture and `source_dirty: false`; host archives also name `rust` as their implementation. The workflow verifies those fields before creating the draft. After those checks it also attaches `release.json`, the release manifest: format `1`, name `peerspan`, the version, the workflow commit as `source_revision`, and the SHA-256 of the two host archives, the two helper archives and `install-release.sh` ([install contract](install-contract.md#releasejson)). Publication adds `release.json.sig`, so a published release has twelve assets. Builds use Ubuntu 22.04 as their glibc baseline. Validate the bundles on the Linux versions intended for launch, then run the quick start on clean machines with no coordinator process/address/key. Check direct participant operation with helpers disabled and optional-helper operation separately.

The native local packaging commands are:

```sh
scripts/package-release.sh rust VERSION dist
scripts/package-helper.sh VERSION dist
```

The host archive includes the native Claude onboarding plugin and a local
marketplace rooted at `share/peerspan`. Its plugin version matches
`RELEASE.json.version`; the runtime sources are copied from the reviewed tree.
No plugin installation runs during packaging or extraction. Users explicitly
install from the archive through Claude's plugin CLI; see the bundled native
frontend guide for that route.

`scripts/installed-acceptance.sh [WORK_DIR]` builds a real Linux archive from the
checkout, runs the unchanged installed-bundle smoke test, checks the relocated
native plugin with Claude Code 2.1.303, and runs the installed terminal, upgrade
and participant checks, writing sanitized receipts to `WORK_DIR/receipts`. It runs
locally, not in CI ([DEC-OWN18](decision-log.md)); run it before a release and on
packaging changes. The draft-release architecture jobs run the two installed
checks too. To check an already built archive locally, with Python 3.12+:

```sh
python3 conformance/installed_bundle.py --archive ARCHIVE --node /absolute/path/to/node
python3 conformance/onboarding_bundle.py --archive ARCHIVE --claude /absolute/path/to/claude
```

Keep the archive's matching `.sha256` beside it. The native check installs only
inside a new private temporary Claude configuration. It verifies strict manifests,
the enabled version and the relocated executable setting. It does not run a model
or establish actual UI reload, delivery, remote access or host-state upgrade.

The helper archive is `peerspan-helper-VERSION-linux-ARCH.tar.gz`. Its named root contains `bin/peerspan-helper`, the operator guide as `README.md`, and `RELEASE.json`; it needs no Node or host integration bundle. It supplies transport only. The [operator contract](decentralized-helper-contract.md) explains explicit state/listen/account configuration and identity handoff. Normal host bundles and the host installer do not install or launch it.

## Qualify the candidate

Download the draft assets into an empty directory using the authenticated
maintainer account. Verify each checksum and the embedded source revision
before installing. Record the archive names and checksums, Linux distribution,
architecture, Node and native-agent versions, actual network topology, commands,
observed outcomes and any failed attempts. Keep invite codes, private keys and
access tokens out of the result record.

Follow the [preview qualification sequence](production-roadmap.md#release-qualification)
and [manual acceptance guide](manual-agent-testing.md). Use clean installation
state, test same-person linking and cross-owner joining, and check useful
model-produced results on separate machines. Run direct connectivity with
helpers disabled and independently configured helper/relay connectivity. Check
restart recovery, offline catch-up and refusal of new work after access is
withdrawn. Record expired-authority recovery separately; signed history does
not revive an authority chain that was never admitted while current.

A successful archive build, fixture agent or draft release is not evidence of
live model execution or a restrictive-network path. Older coordinator-era
results and retired Go/Rust pairing gates do not qualify this candidate.

## Publish the preview

Publication splits into checks that qualify the draft and checks that need the published release ([install contract](install-contract.md#release-procedure)). A draft's assets can't be downloaded without authentication, and the website's `/install` changes only after publication, so the real one-liner can only be checked afterwards. Any failure before publication stops it.

The release key is an Ed25519 key held offline by the owner ([INST-2](decision-log.md#inst-2-who-holds-the-key-and-when-signing-happens)); it is never stored in a repository, a CI secret or a shared machine. The accepted public keys are `PEERSPAN_RELEASE_KEYS` in `scripts/install.sh` and `scripts/install-release.sh`. Changing that list is an owner decision with its own decision-log entry, in a pull request that changes nothing else ([INST-6](decision-log.md#inst-6-who-may-change-the-release-keys-2026-11-04)). The list currently holds a placeholder that no signature verifies under, so no release installs through the bootstrap or `--from-github` until the owner's first key decision replaces it. The owner creates the key on their own machine with:

```sh
scripts/sign-release.sh --generate KEYFILE
```

It asks twice for a passphrase, writes `KEYFILE` as passphrase-encrypted PKCS#8 PEM with mode `0600`, and prints the public key to record in the key decision.

### Before publication

After the candidate qualification above:

1. Download the draft's assets into an empty directory with the authenticated maintainer account:

   ```sh
   gh release download vVERSION --repo peerspan/peerspan --dir DIRECTORY
   ```

2. Check that `PEERSPAN_RELEASE_KEYS` in the tagged `scripts/install.sh` and in the draft's `install-release.sh` asset equals the keys of the latest key decision in the [decision log](decision-log.md). A difference stops publication.
3. Sign the manifest:

   ```sh
   scripts/sign-release.sh DIRECTORY KEYFILE
   ```

   It checks `release.json`, every listed asset's digest and every archive's `RELEASE.json` before asking for the passphrase, then writes `DIRECTORY/release.json.sig` and prints the public key it signed with. Any failed check writes nothing.
4. On clean Debian 12, Ubuntu 22.04 and Ubuntu 24.04 machines, on amd64 and arm64, with no `gh` installed, copy that directory (now including `release.json.sig`) and install from it. This exercises the signed-manifest check on the exact candidate:

   ```sh
   bash DIRECTORY/install-release.sh VERSION --from DIRECTORY
   ```

   Then follow the [quick start](quick-start.md). The bootstrap itself is covered by the `install` conformance suite.
5. Upload the signature to the draft:

   ```sh
   gh release upload vVERSION DIRECTORY/release.json.sig --repo peerspan/peerspan
   ```

### Publication

6. Publish the draft as a full release, not a prerelease: `releases/latest`, which the one-liner uses, skips prereleases ([INST-4](decision-log.md#inst-4-how-latest-is-found)). The workflow creates the draft marked as a prerelease, so clear both flags. Release notes can still say "preview". Keep the source revision, tested platforms, acceptance evidence and known limits in the release notes:

   ```sh
   gh release edit vVERSION --repo peerspan/peerspan --draft=false --prerelease=false
   ```

7. When the release changes `scripts/install.sh`, update the website's `/install` copy from the release's tag, after step 6 ([INST-3](decision-log.md#inst-3-where-install-comes-from)). A new bootstrap served before its release is published would find only the previous release.

### After publication

8. Check that the served `https://peerspan.dev/install` is byte-identical to `scripts/install.sh` at the tag, and that its `PEERSPAN_RELEASE_KEYS` equals the keys of the latest key decision:

   ```sh
   curl -fsSL https://peerspan.dev/install | cmp - <(git show vVERSION:scripts/install.sh)
   ```

9. On a clean Debian 12, Ubuntu 22.04 or Ubuntu 24.04 machine for each architecture, with no `gh` installed, run the real one-liner. It must install this release, both as `latest` and pinned:

   ```sh
   curl -fsSL https://peerspan.dev/install | bash
   curl -fsSL https://peerspan.dev/install | bash -s -- --version VERSION
   ```

If step 8 or 9 fails, mark the release as a prerelease straight away:

```sh
gh release edit vVERSION --repo peerspan/peerspan --prerelease
```

`releases/latest` then names the previous full release, or none, so the one-liner installs the previous release or fails closed. Then restore the website copy, fix the problem, and publish a new version. Assets of a published version are never replaced.

## Install a published release

Users install with the one-line install in the [quick start](quick-start.md#install). It needs no GitHub account and no GitHub CLI.

To read the installer before running it, download it and let it fetch the archive over HTTPS with `curl` or `wget`:

```sh
version=VERSION
curl --proto '=https' --tlsv1.2 -fsSLO "https://github.com/peerspan/peerspan/releases/download/v$version/install-release.sh"
bash install-release.sh "$version" --from-github peerspan/peerspan
```

`--from-github` downloads `release.json`, `release.json.sig`, the host archive and its `.sha256` from that release. It requires the signature to verify under its `PEERSPAN_RELEASE_KEYS`, the manifest's version to equal `VERSION`, and the archive to match both its signed digest and its `.sha256`; a missing manifest or signature is a failure. Compare the downloaded script's `PEERSPAN_RELEASE_KEYS` with the one in this repository and the release notes before trusting it. `--from DIRECTORY` stays the offline path: it verifies `release.json` and `release.json.sig` when both are in the directory, refuses when only one is, and checks only the `.sha256` when neither is.

The installer installs the Rust host. The Go host moved to [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go); `--implementation go` is refused, and an existing Go installation is not switched to Rust in place. It checks the digest and `RELEASE.json`, then installs the bundle.

Selected: portable host packages with no embedded mandatory service, plus an independently operated helper artifact. Discarded: a required staging coordinator, a vendor helper pin in the binary, and starting a helper during ordinary host installation.
