# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.6.x   | ✅ Latest published minor |
| 0.5.x and older | Critical fixes only, at maintainer discretion |

The `main` branch currently identifies itself as `0.7.0`, but it is an
unreleased Technology Preview until the qualified `v0.7.0` release completes.

We support the latest minor release with security patches. Once a new minor or major version is published, prior versions receive patches only for critical vulnerabilities at maintainer discretion.

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, use **GitHub Private Vulnerability Reporting**:

1. Go to the [Security Advisories](https://github.com/greenbone-hive/rust-gvm/security/advisories) tab
2. Click **"Report a vulnerability"**
3. Fill in the details — affected crate(s), reproduction steps, and impact assessment

No alternate private contact channel is published in this repository. If the
GitHub reporting control is unavailable, contact a maintainer without including
exploit details and ask for a private disclosure channel.

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Patch timeline** depends on severity:
  - **Critical / High**: Target fix within 7 days
  - **Medium**: Target fix within 30 days
  - **Low**: Next scheduled release
- We will coordinate disclosure timing with you. We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure) practices.

### What qualifies

- Vulnerabilities in `gvm-protocol`, `gvm-gmp`, `gvm-client`, or
  `gvm-connection`
- Authentication bypass or credential exposure in transport handling (SSH, Unix socket, TLS)
- XML parsing vulnerabilities (injection, XXE, billion-laughs)
- Memory safety issues
- Dependency vulnerabilities with a viable attack path through our code

### What doesn't qualify

- Vulnerabilities in `gvm-mock-server` — it is a testing tool, not production
  software
- Issues in upstream dependencies without a demonstrated attack path through rust-gvm
- Denial-of-service via malformed GMP XML from a trusted gvmd server (trusted network assumption)

## Security Measures

### Dependency Auditing

- **[cargo-audit](https://github.com/rustsec/rustsec)** runs on relevant pushes
  and pull requests plus the weekly [Security workflow](.github/workflows/security.yml),
  checking against the [RustSec Advisory Database](https://rustsec.org/)
- **[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)** enforces license compliance, bans, and source restrictions (see [`deny.toml`](deny.toml))
- **[Dependabot](https://docs.github.com/en/code-security/dependabot)** monitors Cargo, pip, Docker, and GitHub Actions dependencies with weekly update PRs ([`.github/dependabot.yml`](.github/dependabot.yml))
- **[cargo-machete](https://github.com/bnjbvr/cargo-machete)** checks for unused dependencies in CI
- **cargo-vet**, workspace unsafe-code gates, Semgrep, and release-SBOM quality
  checks are also part of the Security aggregate

### Known Advisory Exceptions

There are currently no accepted RustSec advisory exceptions. The SSH dependency
is built without russh's optional RSA support, removing the vulnerable `rsa`
crate from the resolved graph while retaining compression and AWS-LC.

### Supply Chain

- All dependencies sourced exclusively from [crates.io](https://crates.io)
- Git dependencies denied by default (`[sources] unknown-git = "deny"`)
- GitHub Actions pinned to immutable commit SHAs; Dependabot keeps them current
- CycloneDX JSON is generated and quality-gated in Security; tagged releases
  publish the verified JSON/XML SBOM bundle

### Code Quality

- `cargo clippy` with `-D warnings` in CI
- workspace `unsafe_code = "forbid"`, reinforced by the Security workflow's
  source and cargo-geiger gates
- MSRV tested (currently Rust 1.89.0)
- XML framing uses `quick-xml` with a 64 MiB default frame limit and a separate
  256-element nesting limit; transport response and mock request limits are
  configurable

## Security-Relevant Architecture

### Trust Model

```
┌─────────────┐     GMP/XML      ┌──────────┐
│ rust-gvm    │◄────────────────►│  gvmd    │
│ (client)    │  Unix / SSH / TLS │ (server) │
└─────────────┘                   └──────────┘
       ▲
       │ The transport layer (gvm-connection) handles:
       │ • SSH host key verification
       │ • Unix socket file permissions (OS-level)
       │ • TLS certificate and DNS/IP SAN validation
       │
       │ GMP authentication is username/password over
       │ the encrypted transport — never plaintext TCP.
```

- **gvmd is trusted**: rust-gvm is a client library; it trusts the server's XML responses. Malicious server responses are out of scope (same trust model as python-gvm).
- **Credentials**: Passed at runtime, never stored by the library. Callers are responsible for secure credential management.
- **Transport security**: SSH and TLS transports encrypt all GMP traffic. Unix sockets rely on filesystem permissions.

## GitHub Security Features Checklist

GitHub repository settings below were verified live on **2026-09-21**. They
are distinct from workflow configuration kept in this checkout.

| Feature | Status | Notes |
|---------|--------|-------|
| Private vulnerability reporting | ✅ Enabled | Settings → Security → Advisories |
| Dependabot version updates | ✅ Configured | Cargo, Actions, pip, and Docker |
| Dependabot alerts/security updates | ✅ Enabled | Security update PRs are enabled |
| Secret scanning | ✅ Enabled | Repository security setting |
| Secret scanning push protection | ✅ Enabled | Repository security setting |
| Code scanning | ✅ Active | Semgrep uploads SARIF code-scanning results |
| Branch protection | ✅ Enforced on `main` | Administrators included; strict `CI` and `Security` checks; one CODEOWNER review; stale-review dismissal; last-push approval; linear history |
| Signed commits | ❌ Not enabled | This setting is not currently required |
| OSSF Scorecard | ✅ Active | Public repository workflow runs on `main` pushes, weekly, and manual dispatch |

### Verification Follow-up

Recheck these live settings after repository-visibility, branch-protection, or
security-policy changes. Required signed commits remain a separate policy
decision; they are not enabled as of the verification date.

## Changelog

| Date | Change |
|------|--------|
| 2026-03-17 | Initial security policy |
| 2026-09-21 | Reconciled versions, transport controls, workflows, and release/SBOM claims with v0.7 |
