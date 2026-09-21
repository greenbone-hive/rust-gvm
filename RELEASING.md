# Releasing rust-gvm

Releases are managed via the repository's
[Orchestrated Release workflow](https://github.com/greenbone-hive/rust-gvm/actions/workflows/release-orchestrated.yml).

## How It Works

First, update `[workspace.package].version` and `Cargo.lock` in a normal pull
request. Merge that pull request through the protected `main` branch after all
required review and checks pass. Add reviewed release notes at
`docs/releases/v<version>.md`, including a link to the corresponding migration
guide. Then dispatch the release workflow from the exact protected `main`
commit with that exact version.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Protected main                                    │
│  Version and Cargo.lock update merged through a reviewed pull request    │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │ workflow_dispatch with the exact merged version
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    release-orchestrated.yml                              │
│  1. Validates the exact protected-main SHA, version, lockfile, and notes  │
│  2. Creates the changelog, tag, and GitHub release via pontos            │
│  3. Publishes the reviewed release notes                                 │
│  4. Waits for the exact-SHA release.yml run to complete                  │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │ tag push triggers
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         release.yml                                      │
│  1. Runs tests                                                           │
│  2. Builds gvm-mock-server binaries (5 platforms)                        │
│  3. Publishes Docker image to GHCR                                       │
│  4. Generates SBOM (CycloneDX)                                           │
│  5. Uploads all artifacts to the GitHub release                          │
│  6. Verifies assets, checksums, attestations, and GHCR manifests          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Versioning

The workflow accepts the exact semantic version already merged to `main`,
without a leading `v`. Versions containing a pre-release suffix, such as
`0.7.0-alpha.1` or `0.7.0-rc.1`, are published as GitHub pre-releases
automatically. There is no separate scheduled nightly workflow.

## Do NOT

- **Do NOT** dispatch a version that is not already merged to `main`
- **Do NOT** dispatch from a commit other than the current protected `main` head
- **Do NOT** dispatch without reviewed `docs/releases/v<version>.md` notes
- **Do NOT** push version tags manually — let pontos handle it
- **Do NOT** create GitHub releases manually — pontos + release.yml handle everything

## Release Artifacts

Each release includes:

- **Binaries**: five `gvm-mock-server` archives for Linux (amd64 GNU,
  arm64 GNU, amd64 musl) and macOS (amd64, arm64), each with a SHA-256 file
- **Docker image**:
  `ghcr.io/greenbone-hive/gvm-mock-server:v<version>` as a Linux amd64/arm64
  image index; neither `latest` nor an unprefixed version tag is published
- **SBOM**: `rust-gvm-sbom.tar.gz` containing CycloneDX 1.5 JSON and XML for
  all five workspace crates, its SHA-256 file, and a separate
  `sbomqs-results.json` quality report
- **Attestations**: Sigstore build provenance for each binary archive, the SBOM
  archive, and the registry-backed container index

## Verifying Artifacts

```bash
gh attestation verify gvm-mock-server-linux-amd64.tar.gz --owner greenbone-hive
gh attestation verify oci://ghcr.io/greenbone-hive/gvm-mock-server:v0.7.0 \
  --repo greenbone-hive/rust-gvm
```

The release workflow also runs `scripts/verify_release.py published` against
the immutable tag and qualified commit. It rejects missing or extra assets,
checksum or embedded-version mismatches, incomplete SBOMs, a JSON quality score
below 8.3, missing archive/container provenance, incorrect container platforms
or labels, a wrong runtime build version, and release notes that omit the exact
tagged migration-guide URL.
