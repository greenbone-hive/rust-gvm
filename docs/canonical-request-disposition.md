# Canonical request surface disposition

Issue [#602](https://github.com/greenbone-hive/rust-gvm/issues/602)
replaces the transitional builder-backed request layer in bounded resource
families. The machine-readable ledger in
[`canonical-request-disposition.tsv`](canonical-request-disposition.tsv)
prevents a family migration from silently omitting a public options type, free
command builder, semantic request wrapper, or typed facade method.

Each tab-separated row is keyed by surface kind, repository-relative source
path, and symbol. It carries one disposition and a non-empty rationale:

- `transitional`: present at the foundation baseline and awaiting its bounded
  family decision;
- `canonical-request`: the complete request value owns the operation's input
  and typed encoding;
- `retained-construction`: a public options type or builder remains because it
  provides reusable domain structure, validation, or material construction
  ergonomics rather than compatibility forwarding;
- `raw-custom`: retained specifically as a low-level or custom GMP escape
  hatch;
- `frozen-ticket`: retained under the product decision that freezes the
  existing ticket surface;
- `removed`: no longer present after an approved breaking migration, with the
  row retained as an audit record.

`canonical_request_surface_inventory` scans the command and facade source on
every test run. New public surfaces fail until they are classified. Deleted or
renamed surfaces fail until their old row is marked `removed`; a `removed` row
also fails while its symbol still exists. Ticket entries are locked to
`frozen-ticket`.

During a bounded family migration, update only that family's rows. A retained
surface needs a concrete rationale. The final removal slice must contain no
`transitional` entries. To add newly discovered rows without changing existing
decisions, run:

```console
UPDATE_CANONICAL_REQUEST_DISPOSITION=1 \
  cargo test -p gvm-client --test canonical_request_surface_inventory
```

The update command deliberately preserves stale active rows so removal remains
an explicit reviewed decision rather than a generated side effect.

After the bounded report-format migration in #646, the ledger contains exactly
965 rows: 396 `transitional`, 191 `canonical-request`, 255 `removed`, 111
`retained-construction`, and 12 `frozen-ticket`. The inventory test protects
both these counts and the source-to-ledger correspondence.
