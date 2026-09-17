# Port-list request gvmd evidence

Issue #617 changes Rust API ownership for port lists and ranges. It preserves
the established port-list contract and corrects the legacy Rust
`create_port_range` encoder to the public gvmd wire shape. The contract is
anchored in the gvmd source pinned by this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L5322)
  defines port-list creation, including name, optional comment, clone source,
  initial port range, and the created-resource response. The same snapshot
  defines `create_port_range` at
  [line 5409](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L5409):
  optional comment plus `port_list`, `start`, `end`, and `type` child elements.
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L24477)
  parses those range child elements and requires start, end, and a port-list
  identifier before invoking the manager operation. This is why the canonical
  encoder uses child elements instead of the legacy Rust builder's root
  attributes.
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L20890)
  defines one `get_port_lists` root for list and identifier-selected detail
  queries. Delete-list and delete-range identifier attributes are defined at
  [line 7937](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L7937),
  while name/comment replacement is defined at
  [line 38514](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L38514).
- [`manage_sql_port_lists.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_port_lists.c#L1422)
  stores an empty value for each omitted modify field, establishing full
  replacement semantics. Its range implementation validates ports 1 through
  65535 at
  [line 1507](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_port_lists.c#L1507).

gvmd normalizes a descending range by swapping its endpoints. The canonical
Rust request deliberately rejects `start > end` before capability checks or
transport instead, so caller intent is not silently rewritten. This narrowing
is part of the pre-release #602 contract and is recorded explicitly in #617.

This source/schema evidence is separate from repository-local mock evidence:

- request-module and public integration tests assert independent exact XML,
  semantic list/detail and create/clone aliases, static response associations,
  optional range comments, and final-value validation;
- `gvm-client/tests/canonical_request_foundation.rs` proves invalid ranges fail
  before support classification and leave transport history empty;
- the baseline GMP 22.4 fixture test executes all eight semantic operations,
  while the stateful GMP 22.8 test exercises create, detail, clone,
  replacement, list, range creation, and deletion through the request-accepting
  facade.

The mock is not claimed as real-gvmd interoperability proof. The existing
post-merge Community E2E dispatch remains the deployed runtime check against
gvmd; this pinned evidence makes the protocol correction reviewable before
that main-branch-only gate.
