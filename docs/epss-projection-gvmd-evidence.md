# EPSS response projection evidence

Issue [#792](https://github.com/greenbone-hive/rust-gvm/issues/792)
adds the shared typed EPSS projection used by result NVT references and
dedicated NVT responses. The source of truth for this contract is public gvmd
commit
[`b1515d4d3eb4b1806fb3c3db39c56af0a3020732`](https://github.com/greenbone/gvmd/tree/b1515d4d3eb4b1806fb3c3db39c56af0a3020732).
This document records source evidence; exact-revision live parity is tracked
separately by
[`rust-gvm-e2e-tests#231`](https://github.com/clawosiris/rust-gvm-e2e-tests/issues/231).

## Shared wire shape

The result renderer's
[`results_xml_append_epss`](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/gmp.c#L9548-L9582)
emits `<max_severity>` and `<max_epss>` independently. Each selection contains
score, percentile, and a CVE `id` attribute with nested severity. Ordinary and
CVE-shaped result NVTs call that helper only when the result iterator has an
EPSS CVE
([lines 9624–9625](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/gmp.c#L9624-L9625)
and
[9778–9779](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/gmp.c#L9778-L9779)).

Detailed NVT rendering uses the same two selections and field names
([`get_nvt_xml`, lines 5233–5278](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/manage.c#L5233-L5278)).
Unlike the result helper, it conditionally omits nested CVE severity when the
SCAP severity is unavailable
([lines 5246–5252](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/manage.c#L5246-L5252)
and
[5266–5272](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/manage.c#L5266-L5272)).
The `get_nvts` handler selects detailed or compact rendering explicitly; only
the detailed branch can carry EPSS
([lines 15015–15060](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/gmp.c#L15015-L15060)).

`Epss`, `EpssSelection`, and `EpssCve` therefore form one public response
model, and both `NvtRef` and `Nvt` use the same parser helper. The model keeps
the numeric source text unchanged so it retains gvmd's formatting and remains
`Eq`; finite-number accessors return `None` for malformed, `NaN`, or infinite
text. Unknown additive children are ignored.

## Percentile unit

gvmd reads the feed percentile as a fraction and stores
[`percentile * 100.0`](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/manage_sql_secinfo.c#L5880-L5901).
The later NVT enrichment queries copy that stored value into both selections
without renormalizing it
([lines 6775–6827](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/manage_sql_secinfo.c#L6775-L6827)).
Consequently the response percentile is the backend-native percentage value,
normally in `0..=100`, not a `0..=1` fraction. The protocol model deliberately
does not convert it.

## Omission and compatibility boundary

No `<epss>` element means `None`. This covers older gvmd releases, NVTs without
an EPSS-bearing CVE, and compact `get_nvts` responses without requiring a
version gate. A present block must contain both source-defined selections;
nested CVE severity remains optional.

`ReportVulnerability` is deliberately unchanged. Current
[`gmp_report_vulns.c`](https://github.com/greenbone/gvmd/blob/b1515d4d3eb4b1806fb3c3db39c56af0a3020732/src/gmp_report_vulns.c#L91-L133)
emits NVT identity/name, CVEs, counts, severity, and threat, but no EPSS
subtree. Modeling EPSS there would claim wire data that gvmd does not provide.
This issue also does not add or interpret EPSS filter syntax.
