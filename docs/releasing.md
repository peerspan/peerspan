# Private Linux releases

The [Draft Linux release workflow](../.github/workflows/linux-release.yml) is run manually from `main`. It builds Rust and Go host bundles and the separate optional helper natively on Linux amd64 and arm64, checks installed bundles and checksums, and creates a **draft release in the private `peerspan-internal` repository**. It also attaches the installer script and its checksum. Publishing that draft makes it available to collaborators with repository access; it does not make the release public.

Coordinator-free host packages need no coordinator address, coordinator public key, staging identity or vendor helper default. Do not set `PEERSPAN_COORDINATOR` or `PEERSPAN_COORDINATOR_KEY` when packaging, including empty values: the scripts refuse those obsolete options. The workflow does not consume the old repository variables. Optional helper addresses, transport pins and resource credentials are explicit private host configuration, separate from network authority.

## Before running the workflow

1. Complete the [coordinator-free release gates](decentralized-network-contract.md#delivery-slices-and-review-gates) at the intended revision. Retain actual source, package/checksum, topology and result evidence. A successful archive build or draft release alone does not establish working setup, migration, restrictive-NAT transport or live-agent execution.
2. Set the version in `rust/Cargo.toml` to the intended release version. The workflow requires its `version` input to match. Use a new version for each release; do not replace assets for an existing tag.
3. Run **Draft Linux release** from `main` with the version without the `v` prefix. The workflow checks the selected branch and creates `vVERSION` at the workflow commit only after all four bundles pass.

Review the draft's fourteen assets: four host archives, two helper archives, six matching `.sha256` files, `install-release.sh`, and `install-release.sh.sha256`. Every archive's `RELEASE.json` must name the workflow commit, the correct architecture and `source_dirty: false`; host archives also name their selected implementation. The workflow verifies those fields before creating the draft. Rust builds use Ubuntu 22.04 as their glibc baseline; Go builds disable cgo. Validate the bundles on the Linux versions intended for launch, then run the quick start on clean machines with no coordinator process/address/key. Check direct participant operation with helpers disabled and optional-helper operation separately.

The native local packaging commands are:

```sh
scripts/package-release.sh rust VERSION dist
scripts/package-release.sh go VERSION dist
scripts/package-helper.sh VERSION dist
```

The helper archive is `peerspan-helper-VERSION-linux-ARCH.tar.gz`. Its named root contains `bin/peerspan-helper`, the operator guide as `README.md`, and `RELEASE.json`; it needs no Node or host integration bundle. It supplies transport only. The [operator contract](decentralized-helper-contract.md) explains explicit state/listen/account configuration and identity handoff. Normal host bundles and the host installer do not install or launch it.

## Publish to collaborators

After review and clean-machine checks, publish the draft within the private repository:

```sh
gh release edit vVERSION --repo peerspan/peerspan-internal --draft=false
```

Collaborators with access to the repository can then install without a source checkout. In an empty download directory, authenticate GitHub CLI once and download the installer and its checksum:

```sh
version=VERSION
gh auth login
gh release download "v$version" --repo peerspan/peerspan-internal \
  --pattern install-release.sh --pattern install-release.sh.sha256
sha256sum -c install-release.sh.sha256
bash install-release.sh "$version" --from-github peerspan/peerspan-internal
```

Rust is the installer default. Add `--implementation go` to select the supported Go host. The installer downloads only the named host archive and matching `.sha256` file from the selected release, checks the digest and `RELEASE.json`, then installs the bundle. These checks detect corruption and mismatches; verify that the release comes from the intended private repository, since a checksum alone does not authenticate its publisher.

Selected: portable host packages with no embedded mandatory service, plus an independently operated helper artifact. Discarded: a required staging coordinator, a vendor helper pin in the binary, and starting a helper during ordinary host installation.
