# NVT and SecInfo canonical request evidence

Issue [#648](https://github.com/greenbone-hive/rust-gvm/issues/648)
canonicalizes the seven NVT, ten SecInfo, and two observed-vulnerability
requests. This document separates protocol-source evidence, schema evidence,
migration compatibility, and bounded mock behavior; none is used as a proxy for
another.

## Pins and audit boundary

Behavior was reviewed at public gvmd commit
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/commit/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The parser/handler evidence is in
[`src/gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c),
with iterator/rendering behavior in
[`src/manage_sql_nvts.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_nvts.c),
[`src/manage_sql_configs.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_configs.c),
and [`src/manage_sql.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c).

The repository-wide schema snapshot remains pinned independently at
[`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/commit/55e5d4c657c48ce52ee340c2439680418bfe1a4d),
with SHA-256
`ee7054ffffbdce859f90086b28cdc876eebb8225a2a53ad0f7e8100084e1e0b0`.
Current upstream was compared at
[`8525407f910fbe7b8c9f1edb452387e2cf01bb89`](https://github.com/greenbone/gvmd/commit/8525407f910fbe7b8c9f1edb452387e2cf01bb89).
The complete schema files at these revisions are not byte-identical. The audit
compared only the five relevant command blocks (`get_nvts`,
`get_nvt_families`, `get_preferences`, `get_info`, and `get_vulns`) and found
them identical at the schema snapshot, behavioral pin, and current-upstream
comparison. This is deliberately not a whole-file identity claim.

The snapshot and behavioral pin also have identical bodies for all five
handlers. Current upstream retains their dispatch, selectors, validation, and
family, preference, and vulnerability behavior. The relevant NVT,
preference, and vulnerability iterator bodies remain unchanged as well;
current upstream therefore does not add OS/OVAL/vulnerability `get_info`
dispatch, make NVT filters effective, or repair the config-only NVT-list SQL
branch.

There is one response-expansion drift that matters to compatibility. Current
NVT rendering accepts an internal `include_tech_info` argument. Generic
`get_info type="NVT"` passes its `details` value, while dedicated `get_nvts`
passes false. This is not a new wire request attribute, and this crate does not
claim byte-identical current responses. The response codecs tolerate unknown
technical-information extensions while continuing to project the modeled
fields.

## Schema/source discrepancies

The reviewed schema incorrectly requires an NVT OID even though gvmd supports
list requests, omits newer NVT expansion flags, and does not express the
detail/config/selector cross-field constraints enforced by the handler and SQL
branches. Its unconfigured-preference prose describes a stale name/value-only
shape; the handler always emits the structured preference form. The
`get_vulns` schema annotates vulnerability identifiers as UUIDs even though
observed identifiers may be NVT OIDs. A registry entry proves the wire command
name, not every historical subtype or field. The canonical types follow the
source-derived behavior and retain textual identities where the source does.

## Reviewed request behavior

| Wire root | Pinned behavior represented by the canonical requests |
|---|---|
| `get_nvts` | `nvt_oid` and `family` are distinct selectors; config-scoped lists require a family; `config_id` restricts list membership while detail selection does not; `preferences_config_id` changes preference values without membership filtering; detail-dependent flags and timeout context are validated; the dedicated parser does not consume generic `filter`/`filt_id`. |
| `get_nvt_families` | The command owns only family sorting. The response uses `<families><family>` with `max_nvt_count`; `-1` means unknown rather than an unsigned value. |
| `get_preferences` | Optional NVT restriction and the exact suffix after the stored key's second colon are supported. Rows retain stored-key order, detail selection returns the first match, timeout/internal preferences are excluded, radio alternatives are preserved, and password values/defaults are blank. An empty NVT marker is a scanner preference; a missing OID or an empty OID with a nonempty NVT name is malformed. |
| `get_info` | A type is required. Pinned dispatch supports only `CERT_BUND_ADV`, `CPE`, `CVE`, `DFN_CERT_ADV`, and `NVT`. List `name` and detail `info_id` are distinct. Inline/saved filters and details are preserved. Responses are authoritative repeated `<info id>` wrappers with direct typed payload children and an `info_count`. |
| `get_vulns` | This is the observed-vulnerability query, separate from SecInfo. It supports `vuln_id`, inline/saved filters, and richer severity, QoD, result-count, host-count, and context data while the typed response intentionally keeps a compact identity projection. |

The response decoder gives the enclosing `<info>` wrapper authority over
nested payload identities. Nested CVE references or NVT OIDs therefore cannot
replace the requested object's ID/name. More than one supported direct payload
inside a wrapper is rejected. Historical direct typed children remain an
explicit compatibility fallback only when no authoritative wrapper exists, so
mixed shapes cannot double-count.

## Source discrepancies and removed aliases

The historical Rust `InfoType` spellings for operating systems (`os`), OVAL
definitions (`OVALDEF`), and vulnerabilities (`vuln` or `vulnerability`) do
not correspond to branches in pinned or current `handle_get_info`.
Consequently `GenericInfoType` exposes only the five supported branches, and
the former OS/vulnerability `get_info` requests and facades are removed.

Operating-system assets remain owned by the asset commands. Observed
vulnerabilities remain owned by `get_vulns`; `GetVulnsRequest` and the semantic
`GetVulnerabilityRequest` both encode that root. The similarly named
historical `get_vuln` builder is not retained as a second codec. Raw execution
is still available for deliberate experiments, but it does not turn an absent
gvmd dispatch into a supported typed API.

## Canonical ownership and migration

The canonical surface is exactly 19 request values:

- NVT: `GetNvtsRequest`, `GetNvtRequest`, `GetScanConfigNvtsRequest`,
  `GetScanConfigNvtRequest`, `GetNvtPreferencesRequest`,
  `GetNvtPreferenceRequest`, and `GetNvtFamiliesRequest`;
- SecInfo: `GetInfoListRequest`, `GetInfoRequest`, the four specialized list
  requests, and the four corresponding detail requests; and
- observed vulnerabilities: `GetVulnsRequest` and
  `GetVulnerabilityRequest`.

Each owns public inputs, final-value validation, `GmpCommand` metadata, direct
fallible XML encoding, and its typed response association. The corresponding
`GmpClient` method takes that same request by value and delegates unchanged to
`execute`. Former option bags, public free builders, wrapper requests, and the
two unsupported facades were removed. `InfoType` remains only as historical
wire vocabulary and cannot be converted wholesale into `GenericInfoType`.

Preference response structs preserve serde data, but their `Debug` output
redacts value/default/alternative fields. Opt-in wire tracing redacts
`value`, `default`, and `alt` contents plus value-bearing attributes beneath
preference entries in `get_preferences_response`, `get_nvts_response`, and
`get_info_response`, including namespaced or differently cased XML. Raw
responses and explicit serde remain data-bearing APIs.

## Bounded mock qualification

Fixture and Stateful modes share type validation and source-shaped response
rendering for the five roots. Stateful mode additionally requires
authentication and owns small deterministic maps keyed by textual OIDs and
SecInfo/vulnerability IDs. Public seed controls cover NVTs, SecInfo,
vulnerabilities, config membership/preference overrides, saved filters,
user-default filter resolution, database/feed availability, and SecInfo read
permission.

The mock models exact selector/context distinctions, requested NVT detail
expansions, family sorting, preference suffix/order/redaction behavior,
source-shaped SecInfo wrappers/counts, detail not-found behavior, pagination,
a bounded sort/filter field set, `filt_id=0`, explicitly seeded `filt_id=-2`,
and immutable reads. Unsupported fields and unmodeled user-default resolution
fail clearly instead of succeeding silently.

It does not model feed ingestion, SQL collation, every gvmd filter operator,
complete permissions, CERT/SCAP schemas, every NVT detail field, database
transactions, or scanner execution. Real-gvmd conformance remains a separate
evidence class.

## Evidence classes

- Source inspection establishes the request contract above from immutable
  gvmd revisions and records the bounded current-upstream comparison.
- Mock tests establish this repository's deterministic subset, including raw
  negative/ignored-field behavior, prerequisite ordering, selector paths,
  exclusions, pagination, and immutable reads. They are not live-server
  transcripts.
- No live-gvmd validation is claimed for this change. Unix and TLS/mTLS
  interoperability checks exercise the hash-pinned Python client against the
  bounded mock; future live-runner work remains outside this issue.

## Protected checks

Focused coverage lives in:

- `gvm-gmp` request/response unit and integration tests;
- `gvm-client/tests/nvt_secinfo_canonical_integration.rs` for direct execution,
  all request-by-value facades, version aliases, final mutation, diagnostics,
  and error normalization; and
- `gvm-mock-server/tests/stateful_nvt_secinfo_conformance.rs` for stateful
  positive, negative, filtering, availability, permission, and immutability
  behavior.

The canonical disposition inventory protects the exact post-#648 arithmetic:
977 rows = 314 transitional + 241 canonical requests + 299 removed + 111
retained construction helpers + 12 frozen ticket entries.
