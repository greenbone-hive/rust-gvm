# GMP and gvmd Support Matrix

This document describes what rust-gvm's code can negotiate and exercise. It is
not a claim of full conformance with every gvmd deployment or feature build.

## Version routing

| Negotiated GMP version | Typed client family | Registry entries permitted | Mock version |
|---|---|---:|---|
| 22.4 | `Gmp224` | 115 | `V22_4` |
| 22.5 | `Gmp225` | 115 | `V22_5` |
| 22.6 | `Gmp226` | 120 | `V22_6` |
| 22.7 | `Gmp227` | 122 | `V22_7` |
| 22.8 and newer | `GmpNext` | 157 | `V22_8` |

The command count is derived from
`gvm_gmp::capabilities::COMMAND_CAPABILITIES`. Five commands require GMP 22.6
and later, two structured audit-report commands require GMP 22.7 and later,
and another 35 require GMP 22.8. It describes typed-client gates and stateful
mock behavior, not the commands enabled in every gvmd feature build. The client
deliberately permits unknown raw commands for forward compatibility; standard
mock responses reject commands absent from the registry. Explicit fixture and
scenario configuration remains programmable by design.

`export_scan_report` is the exception to pure version routing. It requires at
least GMP 22.7, but it was added without a new GMP version: servers with and
without the command can advertise 22.7 or 22.8. Call
`GmpClient::discover_commands` (or the equivalent method on `GmpVersioned`) to
parse and cache the XML `help` command listing before using its raw, versioned,
or typed helper. The command is therefore represented in the registry and
current-schema count but not in any version-only count above.

`get_audit_report` and `get_audit_report_hosts` are gated at 22.7 and exposed
through `Gmp227Commands` on both `Gmp227` and `GmpNext`. The placement follows
the reviewed gvmd build contract rather than commit dates: default builds set
`GMP_VERSION` to 22.7 and compile the structured audit-report sources that
exist at that revision. Enabling agent or container-scanning features changes
the advertised version to 22.8; select `V22_8` explicitly when a test needs
that feature-enabled surface. `get_audit_report` is present in released
[`v26.35.0`](https://github.com/greenbone/gvmd/releases/tag/v26.35.0);
`get_audit_report_hosts` is post-release current-main behavior at the evidence
pin below.

`get_scan_report` follows the public python-gvm `GMPNext` placement and is
therefore gated at 22.8. Current gvmd source compiles the command
unconditionally even in builds that may still advertise 22.7, so applications
using such a deployment can use deliberate raw/custom execution through a
lower-level connection path, but the versioned high-level client will reject
the canonical request until the server advertises 22.8.

## Command and mock qualification

The registry contains 158 wire command names:

| Qualification | Count | Meaning |
|---|---:|---|
| Stateful mock behavior | 145 | Bespoke behavior or deterministic generic CRUD |
| Fixture mock behavior | 8 | Deterministic built-in fixture response |
| Echo-only mock behavior | 4 | Intentionally limited to a generic success response |
| Explicitly rejected mock behavior | 1 | Known schema name with a source-backed negative built-in response |
| Current pinned `GMP.xml.in` | 155 | Present in the public schema snapshot |
| Public gvmd source only | 3 | Implemented publicly but omitted from that schema |
| Legacy compatibility | 0 | Retained for public legacy-client compatibility |

Mock support is test support, not proof of real-gvmd conformance. In particular,
generic CRUD does not imply that every field and side effect matches gvmd.
The `run_wizard` handler validates the current request shape and returns a
deterministic nested response for client tests. It records an accepted bounded
run without exposing parameter values, but does not execute a real wizard or
populate ordinary mock resources from wizard steps. Authentication groups,
license presence, and user-setting values are stateful; their bounded behavior
does not claim licensing-service, full setting-catalogue, ACL, or wizard-file
conformance.

Report-format verification is stateful rather than echo-only. Signed cases use
injected deterministic yes/no/unknown outcomes; the mock does not run GPG.
Imported files remain inert in memory, and the handler does not claim complete
ACL/filter, filesystem, database-row-order, or trash-detail conformance.

The five NVT/SecInfo discovery roots use bounded stateful behavior. NVT OIDs,
configuration membership and preference overlays, SecInfo records, saved
filters, database availability, permissions, and observed vulnerabilities are
explicitly seeded state. This covers the query and negative paths documented in
the [NVT/SecInfo evidence](nvt-secinfo-request-gvmd-evidence.md), but it is not a
feed parser, SQL emulator, complete ACL engine, or general GMP filter language.

The four configuration lifecycle roots use bounded stateful behavior shared by
generic config, scan-config, and policy aliases. Copy/import, literal usage and
bounded filters, independent active expansions, metadata rollback, trash/task
reference rules, and explicit sync rejection are covered. Expanded trash
reads, complete ACL/filter/feed behavior, internal selector cleanup, and the
full upstream reconciliation/feed-maintenance engine are not claimed. The
configured preference and ordered NVT/family mutation family is implemented
with bounded seeded-state behavior and atomic rollback. See
the [scan-config/policy evidence](scan-config-policy-request-gvmd-evidence.md).

The three commands outside the pinned schema are explicitly qualified:

- `modify_credential_store` is gvmd build-feature-gated and implemented in current public
  gvmd source, but is absent from the pinned `GMP.xml.in`.
- `verify_credential_store` is likewise gvmd build-feature-gated and implemented in the
  public credential-store source while absent from the pinned schema.
- `delete_tls_certificate` is absent from the schema but is dispatched by
  pinned `gmp.c`, handled by the common delete path, and implemented as
  permanent deletion in `manage_sql_tls_certificates.c`.

## Pinned public evidence and drift audit

The deterministic snapshot is extracted from Greenbone's public gvmd commit
[`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/commit/55e5d4c657c48ce52ee340c2439680418bfe1a4d),
file
[`src/schema_formats/XML/GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in).
The snapshot records SHA-256
`ee7054ffffbdce859f90086b28cdc876eebb8225a2a53ad0f7e8100084e1e0b0`
and its 155 unique top-level commands. The asynchronous export contract is
backed by the same commit's
[`export_scan_report`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_scan_report_exports.c).
The structured audit contracts are
backed by the same commit's
[`get_audit_report`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_audit_report.c),
[`get_audit_report_hosts`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_audit_report_hosts.c),
and
[`GMP_VERSION` selection](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/CMakeLists.txt).
The source-only qualification is backed by the same commit's
[credential-store implementation](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_credential_stores.c),
plus the TLS-certificate
[parser dispatch](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5462),
[common delete handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_delete.c#L99),
and [SQL deletion](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_tls_certificates.c#L846).
The complete TLS source/schema comparison and bounded mock qualifications are
recorded in the
[TLS-certificate evidence](tls-certificate-request-gvmd-evidence.md).

To audit another public `GMP.xml.in` checkout:

```console
cargo run -p gvm-gmp --example audit_gmp_schema -- /path/to/GMP.xml.in
```

The command exits unsuccessfully and lists schema-only or registry-only names
when the public schema has drifted. Updating the pin requires reviewing those
differences and their version/evidence qualifications; replacing the snapshot
alone is insufficient.

## Validation boundary

The support claim covers deterministic serialization/parsing tests, shared
client/mock version gates, transport-level mock interoperability, and the
pinned public schema audit. It does not yet include a release-by-release
real-gvmd conformance suite. The structured audit-report fixtures are derived
from the pinned public schema, but no live gvmd service was available for this
snapshot; that gap should remain explicit until live validation is run.
