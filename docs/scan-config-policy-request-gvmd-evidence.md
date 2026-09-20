# Scan-configuration and policy lifecycle evidence

This document records the public gvmd evidence used by issue
[#649](https://github.com/greenbone-hive/rust-gvm/issues/649). It covers only
generic configuration, scan-configuration, and policy lifecycle requests. The
configured-preference and NVT/family-selection mutation family remains deferred.

## Revisions and independent comparison

- Reviewed Rust surface:
  [`ebfdb93`](https://github.com/greenbone-hive/rust-gvm/tree/ebfdb93dab53f1748d68df5d4e831d89fbf2b71d).
- Existing schema snapshot:
  [`55e5d4c`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d).
- Behavioral source pin:
  [`864aa1b`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
- Current upstream comparison:
  [`8525407`](https://github.com/greenbone/gvmd/commit/8525407f910fbe7b8c9f1edb452387e2cf01bb89).

The current comparison was repeated independently on 2026-09-19. GitHub's
`refs/heads/main` still resolved to `8525407f910fbe7b8c9f1edb452387e2cf01bb89`.
For the schema, behavioral, and current revisions, the complete
`src/gmp_configs.c`, `src/manage_sql_configs.c`, and `src/gmp_get.c` files had
matching SHA-256 values respectively:

- `48c33a175d67d7d53abf5e893399cf1dbe5f9d3ab3db96ae50ee2bc35f50b0ec`
- `e00cafb2c5dc9b1b5a5644559a515b3b25527d3f09841f3155bc57c648fd0031`
- `e34a2fc4ece0f1d1d9c74151a744f993f2983debf9abef0213e0e691baa4b9ea`

Both complete pinned/current `src/gmp.c` files contain zero `sync_config`
occurrences. This supports the narrow statements below; it does not generalize
byte identity to all of `gmp.c` or `manage_sql.c`.

Primary sources are the pinned/current
[`gmp_configs.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c),
[`manage_sql_configs.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c),
[`manage_sql_resources.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_resources.c),
[`manage_sql.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c),
[`gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c),
[`gmp_get.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c), and the
[`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in)
schema. The current
[`gmp_configs.c`](https://github.com/greenbone/gvmd/blob/8525407f910fbe7b8c9f1edb452387e2cf01bb89/src/gmp_configs.c),
[`manage_sql_configs.c`](https://github.com/greenbone/gvmd/blob/8525407f910fbe7b8c9f1edb452387e2cf01bb89/src/manage_sql_configs.c), and
[`gmp.c`](https://github.com/greenbone/gvmd/blob/8525407f910fbe7b8c9f1edb452387e2cf01bb89/src/gmp.c)
were checked separately.

## Source-derived lifecycle decisions

`create_config` has two supported creation branches. A direct imported
`get_configs_response/config` takes precedence; otherwise a `copy` source is
required. There is no successful name-only or OSP-scanner constructor. Copy
uses a supplied nonempty name or a generated clone name, inherits an omitted or
empty comment and usage, deep-copies selectors/preferences, and clears
predefined state.
([P1:389](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c#L389),
[P1:524](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c#L524),
[P2:2899](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2899),
[P4:482](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_resources.c#L482))

Configuration usage is a typed `scan`/`policy` boundary. On copy, a nonempty
raw `policy` override selects policy and any other nonempty raw spelling is
coerced to scan. Import treats case-insensitive policy as policy and defaults
other values to scan. Canonical requests therefore expose only
`ConfigUsageType::Scan` and `Policy`; raw/custom XML remains the escape hatch.
Policy import adds an outer policy override. Clone aliases inherit the source
usage unless the caller explicitly supplies a typed override.
([P2:2504](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2504),
[P2:2941](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2941))

List usage is a literal predicate. ID selection takes the common single-ID
iterator path and bypasses usage, ordinary filter, and pagination predicates;
therefore a policy detail request can return a scan configuration selected by
ID. Families expand for `families || details`, preferences for
`preferences || details`, selectors only for details, and task associations
only for `tasks`. Policy's Rust `audits` field maps to `<tasks>`, not an
`audits` wire attribute or container.
([P2:2689](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2689),
[P2:3219](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L3219),
[P5:915](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c#L915),
[P5:1053](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c#L1053),
[P6:5628](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5628),
[P6:12835](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L12835),
[P2:4144](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L4144))

Inline filter text and saved-filter IDs are independently encoded and remain
opaque to the client; in particular empty filter text and IDs `0`/`-2` are
preserved. The configs path does not gain the shared pagination-bypass fields.
([P7:39](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c#L39),
[P5:891](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c#L891))

Import is an embedded XML document. Canonical requests require one exact,
unnamespaced `get_configs_response` root with one direct config, a nonempty
direct name, and explicit `nvt_selectors` and `preferences` containers. They
remove only an accepted BOM/XML declaration and otherwise preserve carrier
bytes. DTDs, entity tricks, namespace substitution, ambiguous direct fields,
and malformed XML are rejected locally without including caller XML in errors.
Preference values are XML text; a nonempty NVT OID requires a nonempty ID.
Feed reconciliation remains server-authoritative.
([P1:393](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c#L393),
[P2:2457](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2457),
[P1:192](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c#L192),
[P2:1292](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L1292),
[P2:2337](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2337),
[P2:2220](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2220),
[P1:273](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c#L273),
[P2:2589](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2589),
[P2:2967](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2967))

Metadata modification changes only nonempty supplied name/comment values.
Absent and empty values preserve existing data, usage is ignored, duplicate
names roll back the compound metadata operation, and predefined configs reject
even no-op modification. Metadata edits do not borrow the in-use restriction
from deferred preference/selection mutations.
([P1:145](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c#L145),
[P1:1050](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_configs.c#L1050),
[P2:3796](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L3796),
[P2:3350](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L3350))

Nonultimate deletion trashes active configurations and succeeds again for an
already trashed item. Visible active task references block trashing; hidden
references move to the trash location. Ultimate deletion is blocked by any
task reference at the resource's current active/trash location. Missing IDs use
the find-error path. Expanded trash reads and complete selector cleanup have
source limitations and are not claimed as rich round-trip behavior.
([P2:2996](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L2996),
[P6:11865](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L11865),
[P6:12923](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L12923),
[P2:283](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L283),
[P2:1921](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c#L1921))

The public schema names `sync_config`, but neither pinned nor current GMP
dispatch implements it. Built-in mock modes therefore return the source-shaped
`<gmp_response status="400" status_text="Bogus command name"/>`. The request,
builder, and both typed facades were removed. This is not renamed into feed
administration.
([P3:40388](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L40388),
[P6:6563](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L6563),
[P8:576](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_configs.c#L576))

## Typed response and confidentiality boundary

Generic and scan projections remain compact. They tolerate rich family,
selector, preference, task, and extension subtrees but do not reconstruct a
full export. Mixed count elements retain the outer numeric text rather than
concatenating nested `<growing>` values. Callers needing a complete export use
raw responses.

Import request `Debug`, validation diagnostics, and wire traces do not expose
the embedded document. Trace redaction also covers preference `value`,
`default`, and `alt` content in configuration responses and nested imported
envelopes. Raw response access remains intentionally data-bearing.

## Bounded mock evidence

Stateful tests model seeded scan configs, policies, predefined state, saved
filters, selectors/preferences (including a sensitive value), and visible,
hidden, and trash-location task references. The mock covers creation branch
precedence, deep copy, first-item raw import, name uniquification, a bounded
all/family/NVT include/exclude selector subset, known preference reconciliation,
literal filtering/paging/counts, independent expansions, metadata rollback,
and reference-sensitive deletion.

Unknown feed-dependent selectors/preferences, expanded trash reads, full ACLs,
the complete GMP filter language, feed maintenance, and internal SQL cleanup
are explicit mock limitations. Deferred preference/NVT/family mutation actions
return a limitation error before metadata changes. Echo and scenario modes
remain programmable synthetic tools; they are not protocol conformance.

No live gvmd instance was exercised for this change. Source/schema review,
bounded mock conformance, and live-server evidence are deliberately separate.
