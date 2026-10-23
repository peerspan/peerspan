# Private Linux releases

The [Draft Linux release workflow](../.github/workflows/linux-release.yml) is run manually from `main`. It builds Rust and Go bundles natively on Linux amd64 and arm64, checks each installed bundle and checksum, and creates a **draft release in the private `peerspan-internal` repository**. It also attaches the installer script and its checksum. Publishing that draft makes it available to collaborators with repository access; it does not make the release public.

## Before running the workflow

1. Provision the hosted coordinator and record its address and public key from `peerspan-coord info`. Set repository variables `PEERSPAN_COORDINATOR` and `PEERSPAN_COORDINATOR_KEY` to those values. The key is public and is embedded in both host binaries. The release workflow fails if either value is missing.
2. Set the version in `rust/Cargo.toml` to the intended release version. The workflow requires its `version` input to match. Use a new version for each release; do not replace assets for an existing tag.
3. Run **Draft Linux release** from `main` with the version without the `v` prefix. The workflow checks the selected branch and creates `vVERSION` at the workflow commit only after all four bundles pass.

Review the draft's ten assets: four archives, four matching `.sha256` files, `install-release.sh`, and `install-release.sh.sha256`. Each archive's `RELEASE.json` must name the workflow commit, the selected implementation and architecture, and `source_dirty: false`. The workflow verifies those fields before creating the draft. The Rust builds use Ubuntu 22.04 as their glibc baseline; Go builds disable cgo. Validate the bundles on the Linux versions intended for launch, then run the quick start on clean machines with the actual hosted coordinator.

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

Rust is the installer default. Add `--implementation go` to select the supported Go host. The installer downloads only the named archive and matching `.sha256` file from the selected release, checks the digest and `RELEASE.json`, then installs the bundle. These checks detect corruption and mismatches; verify that the release comes from the intended private repository, since a checksum alone does not authenticate its publisher.
