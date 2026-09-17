# Filter request gvmd evidence

Issue #622 changes Rust API ownership for the six filter lifecycle operations
and reconciles the transitional input model with the gvmd source pinned by this
repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in create_filter`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L4627)
  defines required `name` plus optional `comment`, `copy`, `term`, and `type`
  children. It does not define the transitional Rust `sort_order` child.
- [`GMP.xml.in get_filters`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L15768)
  defines the shared list/detail root, including `filter_id`, inline `filter`,
  saved `filt_id`, `trash`, and `alerts` selectors. Generic GMP get handling
  additionally accepts `details`, which the single-detail semantic request sets
  to `1`.
- [`GMP.xml.in modify_filter`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L37779)
  requires the `filter_id` root attribute and supports `comment`, `name`,
  `term`, and `type` children. The canonical request therefore adds the rename
  field omitted by `FilterOpts` and removes its unsupported `sort_order` field.
- [`gmp.c` create handling](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L23745)
  rejects a missing or empty non-clone name. Clone handling passes optional
  name and comment overrides to `copy_filter`; the canonical clone request
  represents both without inventing a parallel builder.
- [`gmp.c` filter response handling](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L14166)
  emits type and term for every filter and conditionally expands referencing
  alerts when the `alerts` selector is true.
- [`gmp.c` modify handling](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L27267)
  forwards optional name, comment, term, and type values to the manager. Its
  element-start states initialize present empty children, so canonical modify
  encoding preserves explicit empty comment and term strings instead of
  collapsing them into omission.

Filter sorting is expressed inside the filter term using `sort=` or
`sort-reverse=`. The pinned create/modify schema and parser have no
`sort_order` child, so removing that Rust-only field corrects protocol drift
rather than removing a supported gvmd capability.

Repository-local evidence is intentionally separate from the pinned source:

- request-module and external command tests assert independent exact XML for
  list/detail selectors, create, clone overrides, modify rename/clearing, and
  deletion, plus compile-time response associations and semantic aliases;
- `gvm-client/tests/canonical_request_foundation.rs` proves a publicly mutated
  empty create name returns `GvmError::Request` with empty transport history;
- `gvm-client/tests/filter_canonical_integration.rs` exercises typed
  create/detail/rename/clear/clone/list/trash/delete behavior through the
  stateful mock and verifies alert-selector wire output;
- both checked public-surface inventories fail if a removed options type or
  builder reappears or a canonical request/facade method loses its disposition.

The mock and python-gvm Unix/TLS/mTLS suites are not claimed as live-gvmd
interoperability proof. This development container has no Docker client or
reachable gvmd socket. The external Community E2E runner remains blocked on
its known readiness-loop reauthentication and removed-helper compatibility
repairs, so this slice records pinned public source/schema evidence and does
not claim a live filter lifecycle.
