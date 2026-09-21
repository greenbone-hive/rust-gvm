# Report and audit-report request evidence

Issues #661 and #662 reconcile the report lifecycle, structured reports, all
nine drill-down projections, synchronous report-format export, and asynchronous
scan-report export. Delta and alert-selected generation remain outside this
slice.

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
| `src/gmp_get.c` | `e34a2fc4ece0f1d1d9c74151a744f993f2983debf9abef0213e0e691baa4b9ea` |
| `src/gmp_report_hosts.c` | `e6e1674128184c5103f331c67b91383ed97a1a3505ff483d9f4af382ee3e0472` |
| `src/gmp_report_ports.c` | `0d772ff5165e96bd10fe596f10d4a7bcb287a60a9711a1c816d1cd82f7572f39` |
| `src/gmp_report_applications.c` | `b9b7c226d982e9892305275df6e80768ee84abf0bb41ad654247ec314cc38c8d` |
| `src/gmp_report_operating_systems.c` | `9ac59dc4ca260f35c90c827863e254e0754665eef5851c268414051ce6548812` |
| `src/gmp_report_cves.c` | `43a28d2878d5a986a89f67ab2deec92c6f4cbe6e60eb3c25b13bd9c3328feac6` |
| `src/gmp_report_vulns.c` | `5d32c36d75207f801cd60110aabbfcb11a943855d3cf0ef8542e71ae27f5251d` |
| `src/gmp_report_tls_certificates.c` | `c10eb2424f551463874112050193c53507472fe448437d5c43ba09c3dd1350ab` |
| `src/gmp_report_errors.c` | `f365736ddcb8a60f741077c88e7cbb33d8c21855051a299299cfef027f0d7663` |
| `src/gmp_report_closed_cves.c` | `ecacf217ed0cf9f906b18f7f27157193909c0529d9a9daf1fba7796df52903c4` |
| `src/gmp_scan_report_exports.c` | `a09134565f8fe2ae2030300131e5a3eb23771955577fb7521eff7c65cd5b24f5` |
| `src/manage_scan_report_exports.c` | `b6bd4ebc02bb137d0d5d77f70638cf054b6a402cf30655bd8cdcaa1afd868205` |

The published grammar defines
[`create_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L5509),
[`delete_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L8041),
[`get_reports`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L27001),
[`get_scan_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L21615),
[`get_audit_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L12019),
and
[`get_audit_report_hosts`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L12820).
The same grammar defines
[`export_scan_report`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L8807)
and the nine projections from
[`get_report_applications`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L22398)
through
[`get_report_vulns`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in#L26546).

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
ordinary lifecycle response. A format selector produces a synchronous export
with a different response association and is modeled by
`GetReportExportRequest`; delta and alert selection remain separate work.

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
bounded report XML instead of forcing these irregular responses through a
generic deserializer.

## Drill-down projections

Pinned gvmd routes hosts, ports, applications, operating systems, CVEs,
vulnerabilities, TLS certificates, errors, and closed CVEs through
[`get_data_parse_attributes`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c#L39).
Every request therefore owns `report_id`, inline `filter`, saved `filt_id`,
`details`, and `ignore_pagination`. Hosts alone parse `lean`; the other eight
requests deliberately do not expose it. Omitted Boolean attributes follow
gvmd's false defaults, so constructors emit only the required report ID.

Current successful responses are not one generic flat shape. Host detail rows
are direct children, while ports, applications, operating systems, CVEs,
vulnerabilities, TLS certificates, errors, and closed CVEs use named
containers. GET metadata uses `report_host_count`, `report_port_count`, and the
corresponding `report_*_count` names. Explicit parsers recognize those pinned
shapes, retain legacy flat fixtures, use container `<count>` when GET metadata
is absent, and preserve the original order when vulnerability or closed-CVE
element spellings are mixed. Missing optional fields remain `None`; repeated
rows remain repeated.

`get_report_vulns` is the sole canonical vulnerability name because it is the
actual command. The old `get_report_vulnerabilities` builder/facade was a
byte-identical forwarding alias with no distinct response semantic and is
removed. Likewise, `_parsed` projection names and raw typed-facade duplicates
are removed. Generic `send`/`call`, `XmlCommand`, and custom codecs remain the
documented escape hatch for intentionally unmodeled XML.

## Synchronous report-format export

`GetReportExportRequest` models the format-selected `get_reports` operation as
a separate semantic command. It owns required report and report-format IDs,
optional configuration, inline/saved result-filter selection, details,
pagination bypass, lean output, note/override detail, and result-tag inclusion.
All Boolean omissions retain gvmd's false defaults; callers migrating from the
old convenience builder must explicitly select `details=Some(true)` and
`ignore_pagination=Some(true)` when they want that former policy.

The associated `ReportExport` parser accepts standard-base64 arbitrary bytes,
including non-UTF-8 payloads, and nested XML reports without normalizing the
inner XML. It tolerates report metadata before either carrier, retains absent
content-type/extension fields, rejects non-success envelopes before payload
decoding, and remains bounded by the connection frame limit. Synchronous
export requires the semantic GMP 22.8 capability even though its XML root is
the older `get_reports` command.

## Asynchronous export creation and reuse

Pinned
[`export_scan_report_start`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_scan_report_exports.c#L77)
parses `report_id`, `format_id`, `config_id`, inline `filter`,
`ignore_pagination`, `lean`, `notes_details`, `overrides_details`, and
`result_tags`. It has no saved-filter ID or `details` attribute. Although the
published schema marks `format_id` required, the executable handler explicitly
defaults its omission to the XML report-format UUID; the canonical request
follows that observed behavior and documents the discrepancy.

The manager reuses an equivalent export and reports its processing state, or
creates a new export ID. `ExportScanReportResponse` therefore retains both the
ID and optional `export_status`. Version 22.7 is only a lower bound:
`export_scan_report` requires positive XML-help discovery before encoding or
transmission, and a completed discovery that omits it rejects the request.

## Bounded mock behavior

The stateful report module models import-task enforcement, report/result/task
linkage, host-asset create/update behavior, report versus result filter
namespaces, list/detail counts, pagination, audit/scan separation, structured
filters, audit-host detail/lean behavior, active-report deletion failures,
asynchronous export creation/reuse and validation, and atomic rollback.
Projection and synchronous-export parser coverage uses bounded fixtures because
the mock does not synthesize every gvmd report field or report-format payload.
The mock also does not model gvmd permissions, every filter keyword, or
asynchronous scanner timing.
