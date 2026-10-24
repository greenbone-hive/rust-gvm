# rust-gvm Roadmap and Support Direction

rust-gvm's primary goal is to be a current, typed Rust client and protocol ecosystem for Greenbone Management Protocol (GMP) and Greenbone Vulnerability Manager (gvmd).

Compatibility with python-gvm is important for migration, interoperability, and validation, but rust-gvm should not be limited to python-gvm's public API shape or coverage. When python-gvm and current GMP/GVMD behavior differ, rust-gvm should model the protocol behavior directly and document any migration impact.

## Support Goals

- Track current GMP/GVMD protocol versions and behavior directly.
- Model command and response types from GMP/GVMD semantics.
- Preserve compatibility shims or migration affordances where they help existing python-gvm users.
- Keep the mock server aligned with real gvmd behavior, including errors and ignored or unsupported attributes.
- Add conformance and end-to-end coverage against supported gvmd versions.
- Document supported GMP versions, known gaps, and compatibility expectations.

## Version Support

The current codebase negotiates GMP 22.4 through 22.8+:

- GMP 22.4 maps to the `Gmp224`/`GmpVersioned::V224` client family.
- GMP 22.5 maps to the `Gmp225`/`GmpVersioned::V225` client family.
- GMP 22.6 maps to the `Gmp226`/`GmpVersioned::V226` client family.
- GMP 22.7 maps to the `Gmp227`/`GmpVersioned::V227` client family.
- GMP 22.8 and newer currently map to `GmpNext`/`GmpVersioned::Next`.
- GMP versions older than 22.4 are rejected as unsupported.

This is a code-level support snapshot, not a full conformance guarantee. See
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) for the qualified command/version
matrix, public evidence pin, and deterministic schema drift audit. Real gvmd
validation remains a separate follow-up.

## Compatibility Policy

Release `v0.7.0` completed the SemVer-incompatible migration from the v0.6
request surface. Issue #602 replaced temporary parallel
options/builders/facade inputs with canonical complete request values, and
issue #678 completed the final surface audit with 1,038 classified rows, zero
transitional entries, and 267 typed facades. Current `main` is the
post-`v0.7.0` Technology Preview line. See the
[convergence audit](canonical-request-convergence-audit.md) and
[v0.7.0 migration guide](v0.7.0-migration.md).

python-gvm compatibility is a secondary target:

- Use python-gvm tests to catch migration and interoperability regressions.
- Keep examples and migration notes clear for python-gvm users.
- Avoid cloning python-gvm's API shape when GMP/GVMD semantics call for a different Rust model.
- Prefer typed Rust options and response models that match the protocol.
- Keep raw `send`/`call` access available for commands or response details that are not yet modeled.

## Coverage Policy

A GMP feature is considered covered when the relevant pieces are aligned:

- Canonical request codecs (and the frozen ticket builders) emit the
  gvmd-supported XML shape.
- Response models parse the gvmd-supported XML shape.
- Version gates reflect the GMP versions where a command is available.
- Mock-server behavior does not mask drift from real gvmd.
- Tests cover serialization, parsing, client flow, and relevant mock-server behavior.
- Docs identify any known limitations or migration differences.

## Deliberate Scope Limits

GMP ticket support is frozen at the currently shipped surface. Existing ticket
command builders, response models, typed-client integration, and mock behavior
remain supported and may receive correctness, security, compatibility,
documentation, and test maintenance. New ticket-specific commands, fields,
helpers, mock behavior, or conformance work are intentionally out of scope.

This is a product-scope decision, not a claim that gvmd lacks additional ticket
behavior. Coverage and schema-drift audits must record newly observed ticket
functionality as an intentional exclusion rather than automatically turning it
into roadmap work. See the canonical
[GMP ticket surface decision](https://github.com/greenbone-hive/rust-gvm-api/blob/main/docs/ticket-surface-scope.md),
recorded from
[`rust-gvm-api` PR #417](https://github.com/greenbone-hive/rust-gvm-api/pull/417).

## Current Tracking

Open work:

- [#715](https://github.com/greenbone-hive/rust-gvm/issues/715) closes the
  gvmd 26.40 report-export, typed-schema, and real-gvmd E2E parity gaps. The
  seven report-export commands and five schema projections are present on
  `main`; downstream exact-revision E2E qualification is the remaining gate.
- [#524](https://github.com/greenbone-hive/rust-gvm/issues/524) tracks SSH
  session/exec channel support alongside the existing stream-local transport.
- [#417](https://github.com/greenbone-hive/rust-gvm/issues/417) tracks replacing
  the temporary `wnaf` Cargo Vet exemption.
- [#4](https://github.com/greenbone-hive/rust-gvm/issues/4) tracks a streaming
  design for very large report responses.
- [#9](https://github.com/greenbone-hive/rust-gvm/issues/9) tracks possible
  mock-server record-and-replay support.

The completed #523/#602 canonical-request program, #678 surface audit, and
#172 protocol-gap program remain documented in [STATUS.md](STATUS.md), the
ADRs, migration guide, and gvmd evidence documents rather than as open roadmap
items.

## Near-Term Implementation Order

1. Complete #715 exact-revision real-gvmd qualification for report export,
   schema projections, EPSS fields, and validation/error behavior.
2. Keep protected-`main` downstream dispatch pinned to the exact successful
   rust-gvm commit SHA and preserve immutable runtime evidence.
3. Address the remaining transport, dependency-vetting, and large-response
   work tracked by #524, #417, and #4.
4. Expand real-gvmd conformance and python-gvm migration documentation as new
   protocol differences are discovered.
