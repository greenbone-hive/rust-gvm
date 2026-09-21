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

The workflow accepts the exact semantic version already merged to `main`.
Versions containing a pre-release suffix, such as `0.6.0-alpha.1` or
`0.6.0-rc.1`, are published as GitHub pre-releases automatically.

## Do NOT

- **Do NOT** dispatch a version that is not already merged to `main`
- **Do NOT** dispatch from a commit other than the current protected `main` head
- **Do NOT** dispatch without reviewed `docs/releases/v<version>.md` notes
- **Do NOT** push version tags manually — let pontos handle it
- **Do NOT** create GitHub releases manually — pontos + release.yml handle everything

## Release Artifacts

Each release includes:

- **Binaries**: `gvm-mock-server` for Linux (amd64, arm64, musl), macOS (amd64, arm64)
- **Docker image**: `ghcr.io/greenbone-hive/gvm-mock-server:<version>`
- **SBOM**: CycloneDX JSON/XML with quality scoring
- **Attestations**: Sigstore build provenance for all artifacts

## Verifying Artifacts

```bash
gh attestation verify gvm-mock-server-linux-amd64.tar.gz --owner greenbone-hive
gh attestation verify oci://ghcr.io/greenbone-hive/gvm-mock-server:v0.7.0 \
  --repo greenbone-hive/rust-gvm
```

The release workflow also runs `scripts/verify_release.py published` against
the immutable tag and qualified commit. It rejects missing or extra assets,
checksum or version mismatches, incomplete SBOMs, missing provenance, incorrect
container platforms or labels, and release notes that omit the migration guide.
