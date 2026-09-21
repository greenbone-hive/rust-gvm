# Report and audit-report request evidence

Issue #661 reconciles the ten historical report lifecycle and structured-report
surfaces. Report drill-down projections and synchronous/asynchronous exports
remain explicitly deferred to #662.

## Evidence baseline

The authoritative repository pin is gvmd commit
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The review also compared current gvmd commit `8525407f910f...` from 2026-09-18
and python-gvm v27.8.0 commit `1bb3782b6253...`. Current gvmd has no semantic
change to the successful report shapes below; its only relevant parser diff is
an internal allocation replacement in imported host start/end handling.
python-gvm is used for interoperability, while pinned gvmd remains the
protocol authority.

The reviewed pinned artifacts and SHA-256 digests are:

| Artifact | SHA-256 |
| --- | --- |
| `src/gmp.c` | `ff46494e6ac9842c03e07c91e5ce56d0c6c4342b2a930d2cf4a1e24cb27f3397` |
| `src/schema_formats/XML/GMP.xml.in` | `9fd7e9382c040b2c062ea6ab48d8ffa3b2258eea500e07f45ff66bf8ddbf3338` |
| `src/gmp_scan_report.c` | `db92250624150342e114535bf5539495bd78a2ebd65dfcc026105284719cb06b` |
| `src/gmp_audit_report.c` | `d4bdaec2c3a0d95582d7c9612bf210a7ea71ca38875fcf4034db9809ab160f4f` |
| `src/gmp_audit_report_hosts.c` | `1fdb6e690d07240dc3604a297c69a18108e09c418074db2f69d563c80c302d3a` |
| `src/manage_sql.c` | `ce7d5cc850ba32b55697113b42bfc484e90aa372f33fea52618e70b5a6a547db` |

The published grammar defines
[`create_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L5509),
[`delete_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L8041),
[`get_reports`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L27001),
[`get_scan_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L21615),
[`get_audit_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L12019),
and
[`get_audit_report_hosts`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L12820).

## Creation is XML import

- Despite its command name, pinned `create_report` exclusively imports one XML
  report wrapper into an existing import task. Its ordered grammar is
  `<report>`, `<task>`, then optional `<in_assets>`. There is no empty report
  creation form and no `report_format`, saved-filter, or
  `ignore_pagination` input. The old `CreateReportRequest`, option bag, and
  builder emitted that unsupported shape and were removed.
- `ImportReportRequest` is the one canonical request for this gvmd operation.
  It owns the task relationship, original report bytes, and optional asset
  behavior. It accepts exactly one well-formed `<report>` root and rejects a
  declaration/doctype, wrong root, malformed document, or multiple roots.
  Validation diagnostics never include payload content, and `Debug` redacts
  the bytes.
- Validation runs before semantic support checks and transport. Encoding then
  embeds the original bytes unchanged, avoiding a parse/reserialize step that
  could alter authoritative report content.
- Omitted `in_assets` follows gvmd's false/default behavior. Explicit false
  and true encode as `0` and `1`. The stateful mock accepts only import tasks,
  commits the report, bounded imported results, and host-asset changes under a
  single store lock, and validates every host before the first mutation.

## Ordinary and audit `get_reports`

Pinned
[`GET_REPORTS` parsing](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5893)
maintains two independent common-get values:

- `report_filter` and `report_filt_id` filter the report collection;
- `filter` and `filt_id` filter results inside one selected report.

`GetReportsRequest` therefore owns report-list filters, details,
`ignore_pagination`, note/override detail inclusion, result tags, and lean
selection. `GetReportRequest` owns the report ID plus the result-filter and the
same applicable detail/inclusion controls. The detail constructor explicitly
sets `details=1`; list details and every Boolean option otherwise omit by
default. Pinned parser defaults for lean, note/override details, result tags,
and pagination ignore are false.

From GMP 22.6 onward, ordinary list/detail requests explicitly select
`usage_type=scan`; the 22.4/22.5 encoding omits the not-yet-supported
attribute. `GetAuditReportsRequest` is a distinct 22.6 semantic operation that
always selects `usage_type=audit` and decodes into a distinct
`GetAuditReportsResponse`, even though gvmd shares the
`get_reports_response` wire envelope.

The grammar also accepts `format_id`, `config_id`, `delta_report_id`, and
`alert_id`. These switch or specialize report generation rather than the
ordinary lifecycle response. In particular, a format selector produces a
synchronous export with a different response association. Those selectors
remain with the export/delta work in #662; they are intentionally absent from
the fixed `GetReportsResponse` lifecycle requests rather than being silently
accepted with the wrong response type.

## Deletion

Pinned `delete_report_data_t` calls its permanence integer a dummy field, and
the
[`DELETE_REPORT` parser](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5349)
reads only `report_id`. The database implementation
[`delete_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c#L14568)
always deletes permanently, starts an immediate transaction, and rolls back
when the report is active or another dependency check fails.

`DeleteReportRequest` and the 22.6 `DeleteAuditReportRequest` semantic alias
therefore own only their typed identifier and never emit `ultimate`. The audit
surface preserves python-gvm's non-ultimate wire shape, while the distinct
Rust semantic name prevents it from collapsing into ordinary report policy.
The stateful mock keeps the active-report dependency failure atomic and uses
permanent deletion for both identities.

## Structured scan and audit identities

- `GetScanReportRequest` is gated at GMP 22.8 and emits
  `scan_report_id` plus optional result `filter`/`filt_id`. Its response remains
  `GetScanReportResponse`.
- `GetAuditReportRequest` is gated at GMP 22.7 and emits
  `audit_report_id` plus optional compliance/result `filter`/`filt_id`. Its
  response remains `GetAuditReportResponse`.
- `GetAuditReportHostsRequest` is independently gated at GMP 22.7. It emits
  `report_id`, optional filter selection, optional `details`, and optional
  `lean`. Omission leaves both Boolean parser defaults false: count metadata is
  returned without host rows, and requested rows are non-lean unless selected.

The dedicated parsers in `responses/report.rs`, `scan_report.rs`, and
`audit_report.rs` remain explicit. They preserve nested report envelopes,
mixed/repeated result data, structured count/filter/sort metadata, and large
streamed report XML instead of forcing these irregular responses through a
generic deserializer.

## Bounded mock behavior

The stateful report module models import-task enforcement, report/result/task
linkage, host-asset create/update behavior, report versus result filter
namespaces, list/detail counts, pagination, audit/scan separation, structured
filters, audit-host detail/lean behavior, active-report deletion failures, and
atomic rollback. It does not model gvmd permissions, every report XML field,
every filter keyword, asynchronous scanner timing, or export generation beyond
the already retained compatibility fixtures.
