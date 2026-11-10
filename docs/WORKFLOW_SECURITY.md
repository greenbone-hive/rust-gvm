# Workflow Security Policy

This document defines the security requirements and practices for GitHub Actions workflows in this repository.

## Action Pinning

**All external actions MUST be pinned by full commit SHA**, not by tag or branch.
The policy test scans every `.yml` and `.yaml` file in
`.github/workflows`; adding a workflow cannot opt out of this check.

### Why?
- Tags can be force-pushed (attacker replaces `v2` with malicious code)
- SHA pins are immutable — the exact code you reviewed is what runs
- Protects against compromised upstream repos and supply chain attacks

### Format
```yaml
# ✅ Correct - pinned by SHA
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6

# ❌ Wrong - pinned by tag (can be moved)
- uses: actions/checkout@v6
```

### Updating Pinned Actions
When Dependabot proposes an action update:
1. Review the changelog for the action
2. Verify the SHA corresponds to a signed/verified release
3. Check if the action has OpenSSF Scorecard results
4. Merge only after validation

The selected-actions policy does not allow `dtolnay/rust-toolchain`,
`Swatinem/rust-cache`, `taiki-e/install-action`, or
`returntocorp/semgrep-action`. Rust jobs use
`greenbone/actions/setup-rust` pinned to the approved full SHA instead. Every
use declares the Rust version, component input, and a unique cache key. Cache
keys separate workflow/job purpose, toolchain, runner OS and architecture,
relevant build target or Cargo tool version, and the content of every
`Cargo.lock` file. The release workflow installs every matrix target explicitly
because the approved setup action does not provide a target input.

The CI matrix and dedicated MSRV gate also set `RUSTUP_TOOLCHAIN` explicitly so
`rust-toolchain.toml` cannot silently turn the `1.89.0` lane back into stable.
Formatting, Clippy, and coverage select `rustfmt`, `clippy`, and
`llvm-tools-preview`, respectively; other Rust lanes retain the repository's
baseline `rustfmt` component input required by the approved composite action.

## Tool Version Pinning

Release and publication-critical tool installs must specify versions. Diagnostic
tool installs should also be pinned before their output is treated as
reproducible evidence.

### Why?
- `@latest` or unpinned installs can pull malicious versions
- Reproducible builds require fixed dependencies
- Auditing requires knowing exactly what version ran

### Format
```yaml
# ✅ Correct - pinned versions
- run: cargo install cargo-audit@0.22.1 --locked

- run: go install github.com/interlynk-io/sbomqs@v2.0.5

- run: cargo install cross --git https://github.com/cross-rs/cross --rev 88f49ff79e777bef6d3564531636ee4d3cc2f8d2 --locked

# ❌ Wrong - unpinned
- run: cargo install cargo-audit
- run: go install github.com/example/tool@latest
```

Current release tooling pins `cargo-cyclonedx` 0.5.9, `sbomqs` 2.0.5, and
`cross` to an immutable Git revision. CI pins `cargo-deny` 0.20.2 and
`cargo-llvm-cov` 0.9.1. Security pins `cargo-audit` 0.22.1, `cargo-machete`
0.9.1, `cargo-vet` 0.10.3, `cargo-cyclonedx` 0.5.9, and `cargo-geiger` 0.14.0.
All direct Cargo registry installs use an exact version plus `--locked`;
Git-based Cargo installs use an immutable commit and the reviewed upstream
lockfile. The policy test checks the complete install allowlist, so a new
unpinned or unlocked direct Cargo tool install fails closed.

Semgrep runs directly from the reviewed
`semgrep/semgrep:1.176.1` image pinned by its full SHA-256 digest, with the
workspace mounted read-only. The scan fails on findings and normalizes the
SARIF driver name before upload; the excluded Semgrep action publisher must not
be reintroduced.

## Runtime Monitoring

Jobs that configure [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) use it for:
- Network egress monitoring (audit mode)
- Detection of anomalous outbound connections
- Supply chain attack detection

It is currently in `audit` mode. CI build/test jobs, the E2E dispatch, and the
network-sensitive release jobs configure it. Journal automation, Scorecard,
several Security jobs and aggregate-only jobs do not; macOS binary builds also
skip it because that release step is conditional on Linux. After baseline is
established, consider broader coverage and `block` mode for sensitive jobs.

## Build Provenance

Tagged release builds generate
[Sigstore attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
for:

- each of the five binary archives;
- the packaged SBOM archive; and
- the multi-platform GHCR container index.

The workflow creates GitHub build-provenance attestations; this documentation
does not assign an unsupported SLSA level. There is no scheduled nightly build.

### Verifying Attestations
```bash
gh attestation verify gvm-mock-server-linux-amd64.tar.gz --owner greenbone-hive
```

## Permissions

Workflows follow least-privilege principle:
- Default: `contents: read` only
- `contents: write` only when creating releases/tags
- `packages: write` only when publishing containers
- `id-token: write` + `attestations: write` only for provenance generation

## Runners

The checked workflows use GitHub-hosted `ubuntu-latest` and `macos-latest`
runners. They do not declare self-hosted or Hetzner labels. Any future move to
self-hosted runners requires a separate isolation, credential, patching, and
ephemerality review.

Release container indexes also receive registry-backed build provenance and
are verified with `gh attestation verify oci://...` before the release workflow
can succeed.

## SBOM Generation

Every tagged release includes CycloneDX 1.5 JSON and XML SBOMs:

- generated with the same exact, locked `cargo-cyclonedx` version enforced by
  the Security workflow;
- JSON metadata post-processed and quality-scored with `sbomqs` (minimum
  8.3/10); and
- packaged as `rust-gvm-sbom.tar.gz` with a checksum, quality report, and build
  provenance.

## Scheduled Security Scans

| Scan | Frequency | Tool |
|------|-----------|------|
| Rust advisories | Weekly + relevant pushes/PRs | `cargo-audit` |
| Dependency licenses/sources | Relevant CI pushes/PRs | `cargo-deny` |
| Unused dependencies | Weekly + relevant pushes/PRs | `cargo-machete` |
| Dependency vetting | Weekly + relevant pushes/PRs | `cargo-vet` |
| SBOM quality | Weekly + relevant pushes/PRs | `cargo-cyclonedx`, `sbomqs` |
| SAST | Weekly + relevant pushes/PRs | Semgrep |
| OpenSSF Scorecard | Weekly + pushes/manual, public repositories only | Scorecard |

## Future Improvements

- [ ] Extend Harden-Runner coverage to the remaining networked jobs
- [ ] Switch Harden-Runner to `block` mode after baseline
- [ ] Define an isolation policy before introducing self-hosted runners

## References

- [SLSA Framework](https://slsa.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)
- [Sigstore](https://sigstore.dev/)
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
