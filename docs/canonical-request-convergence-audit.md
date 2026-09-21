# Canonical request convergence audit

Issue #678 closes the issue #602 canonical-request gate. The audited protected
baseline is `d4ba3f45ccf674cfa12c1edef49477478e567ead`; the release-migration
comparison baseline is tag `v0.6.0` at
`c10577ae06326c7363286ddf7d71ecec0f63ee10`.

## Final surface

The checked disposition inventory has exactly 1,026 rows:

| Disposition | Rows |
| --- | ---: |
| `canonical-request` | 409 |
| `removed` | 475 |
| `retained-construction` | 130 |
| `frozen-ticket` | 12 |
| `transitional` | 0 |

The 409 canonical rows comprise 280 complete request values and 129 typed
facades. The retained rows comprise 129 request-by-value facade spellings and
one reusable nested value, `AgentConfigOpts`. Each retained facade accepts a
canonical request unchanged; source inspection and the enforced facade test
prove that it delegates exactly once to `execute`. No free builder or options
bag remains active outside the frozen ticket surface, except
`AgentConfigOpts`, which is shared by two agent mutation requests.

Exactly 12 rows are frozen tickets: six builders, three option bags, and three
client helpers. The ticket helpers are the only typed facades that use the raw
send-and-parse path. This preserves the product decision without extending the
ticket surface.

The audit reconciled the 262-method protected baseline and removed the redundant
`get_credential_stores_with_opts` forwarding alias. The final client has exactly
261 public typed facade helpers. Of these, 258 accept
one complete request and call `execute`; `get_tickets`, `create_ticket`, and
`modify_ticket` retain their raw paths. Unsupported configuration
synchronization, operating-system asset modification, `_parsed`, duplicate
raw-report, and byte-identical restore construction paths are absent.

## v0.6.0 migration audit

The v0.6.0 request-construction surface contains 417 public option/builder
symbols. The final surface removes 407, freezes nine ticket symbols, and keeps
only shared nested `AgentConfigOpts`. The v0.6.0 client contributes 200 facade
names to this scope: 165 now accept one canonical request, 32 are removed or
renamed, and three ticket helpers remain frozen. The complete family and
exception mappings are in the [v0.7.0 migration guide](v0.7.0-migration.md).

A strict `cargo-semver-checks` comparison is intentionally red for a forced
patch comparison because v0.7.0 is the documented pre-1.0 breaking release.
The normal comparison recognizes `0.6.0` to `0.7.0` as a major-compatible
version step. Strict results were used as an audit input, not treated as a
release-policy failure.

## Preserved low-level boundary

`gvm_protocol::Request`, `gvm_protocol::Response`, `GmpClient::send`,
`GmpClient::call`, and their `GmpVersioned` delegates remain public. Callers can
therefore issue custom or deliberately unmodeled XML without retaining a
parallel builder for every canonical family. Custom `GmpRequestCodec`
implementations remain supported for typed extensions.

## Reproduction

Run the inventory gates directly:

```console
UPDATE_CANONICAL_REQUEST_DISPOSITION=1 \
  cargo test -p gvm-client --test canonical_request_surface_inventory
cargo test -p gvm-client --test canonical_request_surface_inventory
cargo test -p gvm-client --test typed_facade_inventory
```

The first command must produce no diff after regeneration. The tests reject
unknown or stale active rows, a reappearing removed symbol, ticket drift,
non-concrete retained rationales, facade path drift, unsupported sync aliases,
and loss of the raw escape hatches.

The exported v0.6.0 comparison used:

```console
cargo semver-checks check-release --baseline-rev v0.6.0 --workspace
cargo semver-checks check-release --baseline-rev v0.6.0 \
  --package gvm-client --release-type patch
cargo semver-checks check-release --baseline-rev v0.6.0 \
  --package gvm-gmp --release-type patch
```

Release validation for this audit consists of formatting; default and
all-feature workspace tests; strict Clippy; warning-free rustdoc; Rust 1.89;
examples and doctests; dependency, advisory, supply-chain, unsafe, SBOM, and
coverage policy gates; and python-gvm integration where its external
dependencies are available. Exact results belong in the issue worklog and
commit handoff because tool and infrastructure availability can differ by
environment.
