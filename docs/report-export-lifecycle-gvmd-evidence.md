# Asynchronous report-export lifecycle: pinned gvmd evidence

This note records the externally observable protocol contract used by the
canonical seven-command asynchronous report-export lifecycle. It intentionally
does not define the later enum/subtype modeling phase.

## Pins and integrity

The contract was checked at both required public gvmd revisions:

- release `v26.40.2`, commit
  [`99503647e445c799b65483817d5cd87bbbf004b4`](https://github.com/greenbone/gvmd/commit/99503647e445c799b65483817d5cd87bbbf004b4);
- audit commit
  [`5385fcb0130bb15230ada02effb78fab74c166b1`](https://github.com/greenbone/gvmd/commit/5385fcb0130bb15230ada02effb78fab74c166b1).

The five report-export handler files are byte-identical at both revisions:

| File | SHA-256 |
|---|---|
| `src/gmp_report_exports.c` | `6d359780aca35a9bf8add8f23407f2e145bb18fcc1c2a71b02fad400ff4fb265` |
| `src/gmp_scan_report_exports.c` | `a09134565f8fe2ae2030300131e5a3eb23771955577fb7521eff7c65cd5b24f5` |
| `src/gmp_audit_report_exports.c` | `14bdd80e7f1981ccd677fb7187f659c06fe4e2a3f710da21869d6109ba49e45a` |
| `src/gmp_delta_audit_report_exports.c` | `234202b2f81cbe2ac1788e2fc65839418776c2ea392b62691d8d70a7dcb273de` |
| `src/gmp_delta_scan_report_exports.c` | `4c1ff98ff8d13f266b960f4776137e7fe879ed88704c7ec5d4b34e7e7cd09979` |

The audited `GMP.xml.in` SHA-256 is
`9b9520ab75fb123f200dba26bd196153fb2eb685c448e7ded44ef8457e407559`.
The release schema SHA-256 is
`c8c815d9a468f1ec0a42f5efd0810b708d13e4f145d77032c8dbcfeb2cfb9c6c`;
the only report-adjacent schema difference is later documentation of the
already-implemented `delete_tls_certificate` command.

## Version and capability gate

Default builds at both pins advertise GMP 22.7, while builds with agent or
container-scanning features advertise 22.8
([build selection](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/CMakeLists.txt#L107-L112)).
All seven report-export commands are compiled independently of that selection.
They were added without a distinct negotiated GMP version, so 22.7 is only a
lower bound. A client must confirm each command in XML `help` before use; a
22.7 or 22.8 version response alone is not proof of support.

The source history confirms why version-only routing is insufficient:

| Command | Introducing commit | First release tag containing it |
|---|---|---|
| `export_scan_report` | [`e83cc9d4`](https://github.com/greenbone/gvmd/commit/e83cc9d474f1e10d7c352da9cf5cb3733c20f762) | `v26.37.0` |
| `get_report_exports` | [`fbe52227`](https://github.com/greenbone/gvmd/commit/fbe522277e1f7b1146ad03d23f7dfaa2a7044b7e) | `v26.38.0` |
| `download_report_export` | [`8cc78ae8`](https://github.com/greenbone/gvmd/commit/8cc78ae897607d09ac3f16b18d2759c8b2aa8f0c) | `v26.39.0` |
| `export_audit_report` | [`3b42e540`](https://github.com/greenbone/gvmd/commit/3b42e5407e611c732ecaf8eb5f9a127956ad6c5b) | `v26.39.0` |
| `export_delta_audit_report` | [`a4caf3e7`](https://github.com/greenbone/gvmd/commit/a4caf3e7a2a8b6c6caaef485a90c04fd1aabf592) | `v26.39.0` |
| `export_delta_scan_report` | [`f88fcf8f`](https://github.com/greenbone/gvmd/commit/f88fcf8f60ecd86923bfd79cb1f4afab0d24c575) | `v26.39.0` |
| `cancel_report_export` | [`8ba4837c`](https://github.com/greenbone/gvmd/commit/8ba4837c4135153ac94bf5a5775a539f4565d366) | `v26.40.0` |

Every one of those release tags still selects GMP 22.7 for its default build
and 22.8 for the relevant feature builds.

## Request and response shapes

The audited schema documents all seven commands at
[`cancel_report_export`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L3870),
[`download_report_export`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L8998),
[`export_audit_report`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L9221),
[`export_delta_audit_report`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L9328),
[`export_delta_scan_report`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L9442),
[`export_scan_report`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L9556),
and
[`get_report_exports`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/schema_formats/XML/GMP.xml.in#L25185).
The v26.40.2 schema contains the same command contracts at lines 3870, 8952,
9175, 9282, 9396, 9510, and 25139 respectively.

| Command | Request | Successful response |
|---|---|---|
| `get_report_exports` | Optional `report_export_id`, `filter`, `filt_id`, and `details` attributes. | Repeated `report_export` resources plus standard GET filter/sort/page/count metadata. Each resource carries common metadata, string `type`, `status`, and `progress`, report/format/config IDs, file metadata, error/attempt fields, and start/end times. |
| `download_report_export` | Required `report_export_id`. | One `report_export` with `done`/`completed` state, IDs and file metadata, and standard-base64 `content`. After the complete response is sent, gvmd removes the export and generated file. |
| `cancel_report_export` | Required `report_export_id`. | Status-only response. Pending exports become `canceled` immediately; running exports become `cancel_requested` until the worker finishes cancellation. Already requested/canceled is idempotent; done/error exports cannot be canceled. |
| `export_scan_report` | Required `report_id`; optional `format_id`, `config_id`, inline `filter`, `ignore_pagination`, `lean`, `notes_details`, `overrides_details`, and `result_tags`. | Created ID with status 201 (without `export_status` in current source), or reused ID with status 200 and `export_status`. |
| `export_audit_report` | Same controls as scan export, with an audit `report_id`. | Created/reused ID and `export_status`; status 201 for create and 200 for reuse. |
| `export_delta_scan_report` | Scan export controls plus required `delta_report_id`. | Created/reused ID and `export_status`; status 201 for create and 200 for reuse. |
| `export_delta_audit_report` | Audit export controls plus required `delta_report_id`. | Created/reused ID and `export_status`; status 201 for create and 200 for reuse. |

Executable parsing and response construction are authoritative where schema
requiredness differs from behavior:

- [`get_report_exports_start`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_report_exports.c#L61)
  uses the common GET parser; the same file parses downloads at
  [line 297](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_report_exports.c#L297),
  streams base64 at
  [line 502](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_report_exports.c#L502),
  deletes only after sending at
  [line 563](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_report_exports.c#L563),
  and implements cancellation at
  [lines 637–730](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_report_exports.c#L637).
- The four creation parsers are
  [`scan`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_scan_report_exports.c#L77),
  [`audit`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_audit_report_exports.c#L77),
  [`delta scan`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_delta_scan_report_exports.c#L79),
  and
  [`delta audit`](https://github.com/greenbone/gvmd/blob/5385fcb0130bb15230ada02effb78fab74c166b1/src/gmp_delta_audit_report_exports.c#L79).
  Each defaults an omitted `format_id` to the XML report format even though the
  published schema marks that attribute required. Saved filter IDs and a
  `details` creation attribute are not parsed.

The observable state strings are `pending`, `running`, `done`, `error`,
`cancel_requested`, `canceled`, and `expired`; progress strings are `queued`,
`preparing`, `generating`, and `completed`. This phase preserves those values
as strings so a later typed-field/subtype change remains separate.
