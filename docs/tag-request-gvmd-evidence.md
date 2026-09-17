# Tag request gvmd evidence

Issue #624 changes Rust API ownership for the six tag lifecycle operations and
reconciles the transitional input model with the gvmd source pinned by this
repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in create_tag`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L6075)
  defines required `name` and `resources`; resources contain a required type,
  zero or more resource IDs, and an optional filter. Create also supports
  `copy`, `value`, `comment`, and `active`. It does not define the transitional
  Rust `severity` child.
- [`GMP.xml.in get_tags`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L30862)
  defines the shared list/detail root with tag ID, inline filter, saved filter,
  trash, and `names_only` selectors. Generic GMP get handling additionally
  accepts `details`, which the single-detail semantic request sets to `1`.
- [`GMP.xml.in modify_tag`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L39056)
  requires the `tag_id` root attribute and supports `name`, `resources`,
  `value`, `comment`, and `active`. Resources accept an optional
  add/set/remove action, optional filter, multiple resource IDs, and required
  type.
- [`gmp.c` create parser](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L8241)
  reads the resources filter attribute and every nested resource ID. Create
  handling rejects missing/empty names, missing resources/type, invalid types,
  and the resource type `tag`; clone handling passes optional name/comment
  overrides to `copy_tag`.
- [`gmp.c` modify parser](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L7155)
  reads resource action/filter/IDs and initializes present text elements even
  when empty. The canonical request therefore preserves explicit empty
  comment/value children as clearing operations.
- [`manage_sql_tags.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_tags.c#L762)
  applies create selections, while
  [`modify_tag`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_tags.c#L885)
  implements replacement/default, add, and remove semantics.

The canonical Rust model keeps the existing `EntityType::Policy` to GMP
`config` mapping and validates `EntityType::Tag` before capability checks or
transport. Removing tag `severity` corrects protocol drift rather than removing
a supported gvmd capability.

Repository-local evidence is intentionally separate from the pinned source:

- request-module and external command tests assert independent exact XML for
  list/detail selectors, multiple IDs/filter, clone overrides, rename,
  add/set/remove action encoding, clearing, and deletion, plus compile-time
  response associations and semantic aliases;
- `gvm-client/tests/canonical_request_foundation.rs` proves invalid final tag
  resource types return `GvmError::Request` with empty transport history;
- `gvm-client/tests/tag_canonical_integration.rs` exercises typed
  create/detail/rename/clear/resource-update/clone/list/trash/delete behavior
  through the stateful mock and verifies `names_only` and action wire output;
- both checked public-surface inventories fail if a removed options type or
  builder reappears or a canonical request/facade method loses its disposition.

The mock and python-gvm Unix/TLS/mTLS suites are not claimed as live-gvmd
interoperability proof. This development container has no Docker client or
reachable gvmd socket. The external Community E2E runner remains blocked on
its known readiness-loop reauthentication and removed-helper compatibility
repairs, so this slice records pinned public source/schema evidence and does
not claim a live tag lifecycle.
