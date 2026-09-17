# Alert request gvmd evidence

The canonical alert requests are based on the public gvmd source pinned by
this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in)
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c)
- [`manage_sql_alerts.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_alerts.c)

## Create and clone

The schema defines the create body and nested condition, event, and method data
at [lines 3843–3969](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L3843).
The parser rejects an empty name, condition, event, or method before dispatch
at [lines 23007–23043](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L23007).
`CreateAlertRequest` therefore requires typed event, condition, and method
values at construction and validates the final name and nested data names.

Clone is a semantic operation over `create_alert`. The handler passes optional
name and comment overrides with the copy identifier at
[lines 22962–22966](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L22962),
and the management function applies those overrides while copying the alert and
all three data collections at
[lines 62–103](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_alerts.c#L62).

## List, detail, modify, and test

The `get_alerts` schema exposes its single-alert selector and ordinary GET
filtering at
[lines 10557–10573](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L10557).
The detail request retains a distinct semantic name while emitting
`get_alerts alert_id="…" details="1"`.

The modify schema makes the alert identifier required and the replacement
fields optional at
[lines 37032–37145](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L37032).
The parser also accepts `active`, although the schema pattern omits it
([lines 6709–6733](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L6709)).
The management update always replaces the filter with the resolved filter ID,
so omitting `<filter>` clears the binding; omitted `active` instead preserves
the current column value
([lines 1178–1239](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_alerts.c#L1178)).

The `test_alert` schema requires only `alert_id` and defines the ordinary action
response plus optional status details at
[lines 40457–40492](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L40457).

## Triggering and sensitive data

Alert triggering is a semantic use of `get_reports`: its parser consumes
`report_id`, `delta_report_id`, `alert_id`, and `format_id` at
[lines 5917–5931](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L5917).
`TriggerAlertRequest` therefore owns the `trigger_alert` semantic alias while
retaining the `GetReportsResponse` association.

Alert data is open-ended and may carry passwords, tokens, credentials, or
other delivery secrets. `AlertData` always redacts its value in `Debug`, and
wire tracing replaces nested event, condition, and method data payloads before
they reach a trace sink. Exact XML tests exercise the unredacted encoder; trace
tests independently assert that secret sentinels are absent.

The stateful mock lifecycle tests cover create, list, modify, active-state
preservation, and nested data behavior. They are deterministic integration
evidence, not a claim of live-gvmd interoperability.
