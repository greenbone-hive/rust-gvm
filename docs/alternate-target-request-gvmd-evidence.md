# Alternate target request gvmd evidence

Issue #609 changes Rust API ownership for OCI-image and web-application
targets; it does not change their GMP wire contract. The contract is anchored
in the public gvmd source pinned by this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L4936)
  documents the OCI-image create operation; the same snapshot contains its
  delete, list/detail, and modify roots at lines 7782, 19473, and 38190.
- The same schema documents the web-application create operation
  ([line 7162](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L7162))
  and its delete, list/detail, and modify roots at lines 8615, 35907, and
  39945. `gmp_schema_snapshot` verifies all eight wire roots remain in the
  checked command registry.
- [`gmp_oci_image_targets.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_oci_image_targets.c#L108)
  handles clone through `<copy>`, then consumes `name`, `comment`,
  `image_references`, and credential ID for create. Its modify handler consumes
  the same mutable fields
  ([line 413](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_oci_image_targets.c#L413));
  list/detail parsing uses the common get attributes plus the `tasks` flag
  ([line 608](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_oci_image_targets.c#L608)).
- [`gmp_web_application_targets.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_web_application_targets.c#L118)
  handles clone through `<copy>` and consumes `name`, `comment`, `urls`,
  `exclude_urls`, and credential ID for create. Its modify and list/detail
  handlers preserve those fields and the `tasks` flag
  ([modify](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_web_application_targets.c#L508),
  [get](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_web_application_targets.c#L763)).
- Issue #812 traced `exclude_urls` through the pinned revision and the
  then-current upstream `main`
  [`c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935`](https://github.com/greenbone/gvmd/tree/c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935)
  (checked 2026-11-08). Omission leaves `target_data->exclude_urls` null,
  while a present empty element supplies an empty string
  ([pinned parser](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_web_application_targets.c#L517-L545),
  [current parser](https://github.com/greenbone/gvmd/blob/c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935/src/gmp_web_application_targets.c#L526-L545)).
  The SQL modify path skips null, replaces non-empty text, and explicitly sets
  `exclude_urls = NULL` for the empty string
  ([pinned persistence](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_web_application_targets.c#L370-L402),
  [current persistence](https://github.com/greenbone/gvmd/blob/c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935/src/manage_sql_web_application_targets.c#L370-L402)).
  Consequently omission preserves, non-empty text replaces, and
  `<exclude_urls/>` is the supported clear form.
- The central parser dispatches both delete roots through gvmd's resource
  deletion path
  ([OCI image](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L5302),
  [web application](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L5477)).

This source/schema evidence is intentionally separate from repository-local
mock evidence:

- the request-module tests assert independent exact XML for all twelve
  semantic operations and verify their metadata and static response types; the
  external `web_application_targets_test` sidecar separately asserts exact
  preserve, replacement, and clear XML;
- `gvm-client/tests/canonical_request_foundation.rs` proves every operation is
  rejected on GMP 22.7 with empty transport history;
- `gvm-client/tests/typed_facade_coverage.rs` executes every operation on GMP
  22.8 and exercises server-status and parse-error normalization;
- stateful client and mock-server tests exercise both lifecycles and typed
  response decoding.

The mock is not claimed as real-gvmd interoperability proof. The existing
post-merge Community E2E dispatch remains the deployed runtime check against
gvmd; this pinned evidence is reviewable before that main-branch-only gate.
