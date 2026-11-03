# Linux preview releases

The [Draft Linux release workflow](../.github/workflows/linux-release.yml) is run manually from `main`. It builds the Rust host bundle and the separate optional helper natively on Linux amd64 and arm64, checks installed bundles and checksums, and creates a **draft release** in the repository it runs in. It also attaches the installer script and its checksum. Publishing the draft makes the release visible to everyone who can see the repository.

Coordinator-free host packages need no coordinator address, coordinator public key, staging identity or vendor helper default. Do not set `PEERSPAN_COORDINATOR` or `PEERSPAN_COORDINATOR_KEY` when packaging, including empty values: the scripts refuse those obsolete options. The workflow does not consume the old repository variables. Optional helper addresses, transport pins and resource credentials are explicit private host configuration, separate from network authority.

## Build a draft candidate

1. Merge the reviewed source and run the Rust checks and all slim conformance suites at the intended revision. Record that exact commit. The remaining installed and live checks qualify the resulting draft before publication.
2. Set the version in `rust/Cargo.toml` to the intended release version. The workflow requires its `version` input to match. Use a new version for each release; do not replace assets for an existing tag.
3. Run **Draft Linux release** from `main` with the version without the `v` prefix. The workflow checks the selected branch and creates `vVERSION` at the workflow commit only after both host bundles pass.

With authenticated GitHub CLI, dispatch and follow the candidate build:

```sh
gh workflow run linux-release.yml --repo peerspan/peerspan --ref main -f version=VERSION
gh run list --repo peerspan/peerspan --workflow linux-release.yml --limit 1
gh run watch RUN_ID --repo peerspan/peerspan --exit-status
```

Review the draft's ten assets: two host archives, two helper archives, four matching `.sha256` files, `install-release.sh`, and `install-release.sh.sha256`. Every archive's `RELEASE.json` must name the workflow commit, the correct architecture and `source_dirty: false`; host archives also name `rust` as their implementation. The workflow verifies those fields before creating the draft. Builds use Ubuntu 22.04 as their glibc baseline. Validate the bundles on the Linux versions intended for launch, then run the quick start on clean machines with no coordinator process/address/key. Check direct participant operation with helpers disabled and optional-helper operation separately.

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

The PR's **Installed onboarding bundle** job builds a real Linux amd64 archive,
runs the unchanged installed-bundle smoke test, and checks the relocated native
plugin with Claude Code2.1.303. The draft-release architecture jobs run both
installed checks too. To check an already built archive locally, with Python3.12+:

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

After candidate review and the installed/live checks pass, publish the draft
as a prerelease in the public repository. Keep its source revision, tested
platforms, acceptance evidence and known limits in the release notes:

```sh
gh release edit vVERSION --repo peerspan/peerspan --draft=false
```

Users can then install without a source checkout. In an empty download directory,
authenticate GitHub CLI and download the installer and its checksum:

```sh
version=VERSION
gh auth login
gh release download "v$version" --repo peerspan/peerspan \
  --pattern install-release.sh --pattern install-release.sh.sha256
sha256sum -c install-release.sh.sha256
bash install-release.sh "$version" --from-github peerspan/peerspan
```

The installer installs the Rust host. The Go host moved to [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go); `--implementation go` is refused, and an existing Go installation is not switched to Rust in place. The installer downloads only the named host archive and matching `.sha256` file from the selected release, checks the digest and `RELEASE.json`, then installs the bundle. These checks detect corruption and mismatches; verify that the release comes from the intended public repository, since a checksum alone does not authenticate its publisher.

Selected: portable host packages with no embedded mandatory service, plus an independently operated helper artifact. Discarded: a required staging coordinator, a vendor helper pin in the binary, and starting a helper during ordinary host installation.
