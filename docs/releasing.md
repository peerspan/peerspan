# Linux release staging

The [Draft Linux release workflow](../.github/workflows/linux-release.yml) is run manually from `main`. It builds Rust and Go bundles natively on Linux amd64 and arm64, checks each installed bundle and checksum, and creates a **draft release in the private `peerspan-internal` repository**. It also attaches the installer script and its checksum. A draft here is for review; it is not a public download.

## Before running the workflow

1. Provision the hosted coordinator and record its address and public key from `peerspan-coord info`. Set repository variables `PEERSPAN_COORDINATOR` and `PEERSPAN_COORDINATOR_KEY` to those values. The key is public and is embedded in both host binaries. The release workflow fails if either value is missing.
2. Set the version in `rust/Cargo.toml` to the intended release version. The workflow requires its `version` input to match. Use a new version for each release; do not replace assets for an existing tag.
3. Run **Draft Linux release** from `main` with the version without the `v` prefix. The workflow checks the selected branch and creates `vVERSION` at the workflow commit only after all four bundles pass.

Review the draft's ten assets: four archives, four matching `.sha256` files, `install-release.sh`, and `install-release.sh.sha256`. Each archive's `RELEASE.json` must name the workflow commit, the selected implementation and architecture, and `source_dirty: false`. The workflow verifies those fields before creating the draft. The Rust builds use Ubuntu 22.04 as their glibc baseline; Go builds disable cgo. Validate the bundles on the Linux versions intended for launch, then run the quick start on clean machines with the actual hosted coordinator.

## Public download path

A public release repository or host is still required. Copy the reviewed assets unchanged to one trusted HTTPS release directory for each version. The private draft URL cannot serve unauthenticated installs. Once the public location is selected, the quick start can give its exact URL and the release workflow can publish to it directly.

The source checkout is unnecessary for installation once the assets are public. For a release whose download directory is `RELEASE_URL`, the bootstrap is:

```sh
version=VERSION
release_url=RELEASE_URL
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output install-release.sh "$release_url/install-release.sh"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output install-release.sh.sha256 "$release_url/install-release.sh.sha256"
sha256sum -c install-release.sh.sha256
bash install-release.sh "$version" --from-url "$release_url"
```

Rust is the installer default. Add `--implementation go` to select the supported Go host. The installer downloads only the named archive and matching `.sha256` file, rejects non-HTTPS URLs and redirects, checks the digest and `RELEASE.json`, then installs the bundle. These checks detect corruption and mismatches; the HTTPS release location must also be trusted as the publisher.
