# Integration-configuration request gvmd evidence

Issue #615 changes Rust API ownership for integration configurations; it does
not change their GMP wire contract. The contract is anchored in the public
gvmd source pinned by this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L17964)
  defines the shared `get_integration_configs` list/detail root and its
  optional identifier, filter, and saved-filter inputs. The same snapshot
  defines the complete replacement payload and response at
  [line 37901](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L37901).
- [`gmp_integration_configs.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_integration_configs.c#L88)
  routes the common list/detail attributes through the generic get parser. Its
  modify handler requires the UUID plus the service and OIDC containers and
  reads their URL, CA certificate, client ID, and client secret values
  ([line 314](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_integration_configs.c#L314)).
- [`manage_sql_integration_configs.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_integration_configs.c#L94)
  treats an all-empty configuration as the clear operation. Any non-empty
  replacement is validated for a service URL, OIDC URL, client ID, and client
  secret at
  [line 114](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_integration_configs.c#L114)
  before the encrypted secret and replacement are stored.

This source/schema evidence is intentionally separate from repository-local
mock evidence:

- request-module and public integration tests assert independent exact XML,
  semantic alias metadata, static response associations, clear behavior, and
  secret-free validation/debug output;
- `gvm-client/tests/canonical_request_foundation.rs` proves all three requests
  are rejected on GMP 22.7 with empty transport history and that a partial
  replacement fails validation before the version gate;
- the stateful GMP 22.8 client test exercises list, detail, replacement, and
  clear through the request-accepting facade;
- the mock-server protocol test retains raw malformed/partial server behavior
  separately from canonical client-side validation.

The mock is not claimed as real-gvmd interoperability proof. The existing
post-merge Community E2E dispatch remains the deployed runtime check against
gvmd; this pinned evidence is reviewable before that main-branch-only gate.
