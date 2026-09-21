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

The current `main` branch is the unreleased `0.7.0` development line. It is
intentionally SemVer-incompatible with `v0.6.0`: issue #602 replaces temporary
parallel options/builders/facade inputs with canonical complete request values
before the next downstream-ready release. The release remains gated on the
final #602 surface audit and `rust-gvm-api#457` validation. See the
[v0.7.0 migration guide](v0.7.0-migration.md) for caller-visible changes.

python-gvm compatibility is a secondary target:

- Use python-gvm tests to catch migration and interoperability regressions.
- Keep examples and migration notes clear for python-gvm users.
- Avoid cloning python-gvm's API shape when GMP/GVMD semantics call for a different Rust model.
- Prefer typed Rust options and response models that match the protocol.
- Keep raw `send`/`call` access available for commands or response details that are not yet modeled.

## Coverage Policy

A GMP feature is considered covered when the relevant pieces are aligned:

- Command builders emit the gvmd-supported XML shape.
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

Existing issues:

- [#523](https://github.com/greenbone-hive/rust-gvm/issues/523) tracks the
  additive typed request/associated-response execution architecture, completed
  family-by-family migration, protected-`main` promotion, and the remaining
  release program. [#602](https://github.com/greenbone-hive/rust-gvm/issues/602)
  is its accepted pre-release canonical-request gate, recorded in
  [ADR 0002](adr/0002-canonical-request-ownership.md).
- [#172](https://github.com/greenbone-hive/rust-gvm/issues/172) tracks remaining rust-gvm vs gvmd GMP coverage gaps.
- [#247](https://github.com/greenbone-hive/rust-gvm/issues/247) tracks report option drift where rust-gvm exposes an attribute gvmd ignores.
- [#251](https://github.com/greenbone-hive/rust-gvm/issues/251) tracks response model drift around user host access and similar XML shape mismatches.
- [#311](https://github.com/greenbone-hive/rust-gvm/issues/311) tracks generic GMP asset commands alongside typed wrappers.
- [#313](https://github.com/greenbone-hive/rust-gvm/issues/313) tracks generic GMP config commands alongside scan-config and policy wrappers.
- [#648](https://github.com/greenbone-hive/rust-gvm/issues/648) completes the
  bounded canonical NVT/SecInfo discovery slice, including pinned dispatch
  discrepancies and stateful mock qualification.
- [#649](https://github.com/greenbone-hive/rust-gvm/issues/649) completes the
  generic configuration, scan-configuration, and policy lifecycle slice:
  required copy/import creation, metadata-only modification, bounded stateful
  behavior, and removal of unsupported GMP synchronization. Configured
  preference and NVT/family mutation remains the next strictly ordered child.
- [#659](https://github.com/greenbone-hive/rust-gvm/issues/659) and
  [#660](https://github.com/greenbone-hive/rust-gvm/issues/660) complete the
  standard and specialized task/audit canonical request surfaces. The latter
  preserves the GMP 22.8 specialized-task gates, audit usage identity, typed
  move destinations, confidential preference redaction, and bounded stateful
  lifecycle/rollback conformance. Work proceeds only to the next ordered
  #602 slice after this patch; #661 is not part of #660.

Follow-up issues or milestones should cover:

- Add real gvmd end-to-end or conformance validation for supported versions.
- Document python-gvm migration compatibility expectations and known differences.

## Near-Term Implementation Order

1. Complete #602 in bounded slices: execution foundation, targets reference
   family, remaining resource families, and the final public-surface audit.
2. Validate the canonical surface once through `rust-gvm-api#457`.
3. Complete the remaining #523 release gate: versioned release, artifact
   verification, and downstream pinning.
4. Finish the remaining high-value GMP coverage gaps from #172 and known
   protocol drift.
5. Expand real-gvmd conformance and python-gvm migration documentation.
