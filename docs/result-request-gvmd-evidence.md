# Result request behavior in pinned gvmd

Issue #643 canonicalizes the existing result list/detail family against gvmd
revision
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The repository command registry/schema snapshot remains pinned separately at
`55e5d4c657c48ce52ee340c2439680418bfe1a4d`; the complete
`get_results` schema section is identical at both revisions. This is public
source/schema evidence, not live-gvmd validation.

## Request and selection behavior

The
[`get_results` schema](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L28248)
defines the eight root attributes `result_id`, `filter`, `filt_id`,
`task_id`, `notes_details`, `overrides_details`, `details`, and
`get_counts`. The
[`get_results` parser](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L6049)
combines common GET parsing with task context, expansion-detail flags, and
counts. Omitted `get_counts` defaults to enabled; omitted expansion-detail
flags default to disabled.

The
[`get_results` handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L17698)
rejects trash retrieval, resolves supplied result and task references,
forcibly disables `ignore_pagination`, and invokes result rendering with lean
and delta output disabled. The canonical request therefore does not expose
`trash`, `ignore_pagination`, root `report_id`, `lean`,
`delta_report_id`, `delta_states`, or root inclusion/application helpers.
Pagination and sorting remain opaque filter terms.

The
[`result_iterator` path](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c#L12041)
receives no root-task restriction. Root `task_id` is note/override context,
not a result selector; task and report selection use filter terms such as
`task_id=...` and `report_id=...`. The iterator also has distinct list and
ID-selection paths and obtains override application from the effective filter.
The client preserves filter text rather than interpreting those rules.

The schema prose associates some expansion flags with task context, but the
pinned implementation has no blanket rejection. ID-selected rendering can
infer context, and detailed list rendering can infer it per result. The
canonical client follows the implementation: it does not require root task
context, parse override-related filter text, or compare a supplied context task
with a selected result's task.

## Saved filters, expansion, and counts

[`init_get`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c#L92)
resolves concrete saved filters and user defaults. The saved-filter
[`FILTER_ID_NONE` and `FILTER_ID_USER_SETTING` sentinels](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_filters.h#L15)
are `"0"` and `"-2"`. Inline and saved filters remain independent
request inputs; the client preserves both, including empty inline text and the
two lexical sentinels. A concrete saved filter takes precedence upstream, and
missing saved filters can enter fallback behavior, so the client does not
claim that every missing filter is a 404.

The
[`filter_term_apply_overrides` lookup](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_filter_utils.c#L894)
shows that applying overrides is independent of displaying them. Filter terms
`notes` and `overrides` request inclusion; `notes_details` and
`overrides_details` change association richness; `apply_overrides` changes
severity application. Detail flags alone do not request inclusion.

[`get_data_complete`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c#L733)
emits filter/sort/pagination metadata and conditionally emits counts.
`get_counts=0` removes the count block, not result items or pagination
metadata. `CountInfo.total`, `filtered`, and `page` remain distinct;
`page` is the number of items returned on the page, and an ID-selected
response's total need not be one. The bounded mock resolves omitted or
negative `rows` to 100, caps positive values at 100, and preserves that
effective maximum and the requested `first` independently of returned page
length or the ID-selection shortcut.

## Response boundary

[`result_to_xml`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L10390)
can add task/report references when details are enabled and can infer
per-result task context. Result names are conditional, so the result-specific
parser accepts an absent name as an empty `EntityMeta.name` while still
requiring and validating `result.id`. ID-only report references remain
valid.

The typed `ScanResult` projection retains result identity, host/port,
task/report references, NVT fields and both supported CVE encodings,
threat/severity, QoD, description, and counts. Nested note, override, ticket,
detection, tag, delta, and original-severity payloads remain outside this
bounded input-ownership slice. Their presence does not break parsing, but
callers that need the complete expanded XML must use raw `send` or `call`.

## Repository and mock evidence

Repository-local validation is kept separate from the pinned source evidence:

- result request tests assert independent exact XML, all boolean states,
  sentinels, escaping, final-value validation, metadata, and response
  association;
- result response tests use top-level `result` children plus the separate
  `results` metadata element and cover optional names, ID-only report
  references, expansion subtrees, missing counts, mixed-text counts, and
  malformed fields;
- client integration tests execute both requests directly and through both
  named facades on baseline and newer GMP versions, including pre-transport
  validation and status/parse normalization;
- stateful result conformance tests cover ID/list paths, context, saved/inline
  filtering, selection, sorting, pagination, counts, expansions, override
  application, ignored unsupported roots, trash rejection, and read-only
  retrieval by comparing the complete seeded task/report/result/filter/note/
  override graph.

The stateful mock intentionally implements only a documented subset of GMP
result filtering: equality for identifiers, name, host, port, threat, task and
report; numeric equality/ranges for severity and QoD; `min_qod`;
`sort`/`sort-reverse`; `first`/`rows`; and the
`notes`/`overrides`/`apply_overrides` controls. It uses a seeded
default minimum QoD of 70. Its bounded override policy chooses the lowest-ID
stored override associated with both the result and its stored task, then uses
the effective severity and derived threat for filtering, sorting, counts,
pagination, and rendering. Rendering uses a supplied task context, or infers
one for ID selection and detailed lists; unexpanded lists do not invent one.
Association expansion is restricted by result and effective task context.
Equal primary sort keys use ascending result ID as the deterministic
tie-breaker. Unsupported fields, relations, compound operators, and malformed
or non-finite numeric operands return an explicit error before resource
selection.

The mock gates `original_severity` and `original_threat` output on the
`overrides` inclusion control, independently of whether an association exists
or application is enabled. This raw XML remains intentionally outside the
typed `ScanResult` projection.

The mock does not implement user-setting filter resolution, missing-filter
fallback subtleties, the unstable `_and_report_id` mechanism, dynamic
severity, the full override/CVSS/permission engine, or delta result rendering.
Its raw root `ignore_pagination` and report/lean/delta attributes acquire no
invented behavior. Mock and python-gvm validation are interoperability checks
against the mock only. No live-gvmd validation is claimed.
