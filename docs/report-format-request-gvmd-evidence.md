# Report-format request behavior in pinned gvmd

Issue #646 canonicalizes report-format list, detail, import, clone, modify,
delete, and verify requests against gvmd revision
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The repository command-registry/schema snapshot remains pinned separately at
`55e5d4c657c48ce52ee340c2439680418bfe1a4d`. This document records public
source and schema inspection. Repository tests and the bounded mock are
separate evidence categories; no live-gvmd validation is claimed.

## Pin comparison

The reviewed source pin, repository schema pin, and upstream `main` as
resolved during issue review (`8525407f910fbe7b8c9f1edb452387e2cf01bb89`)
were compared byte-for-byte. At all three revisions:

- `src/gmp_report_formats.c` has SHA-256
  `0c7677b3cdd0cd52a7ef1e61145ebb48507b76b3a24d8cb3703832a1aba9acc7`;
- `src/manage_report_formats.c` has SHA-256
  `a71102bbb4ae7b0940336b4d9d7664857aeda8e44d0e33fbb6380ed2222e7659`;
- `src/manage_sql_report_formats.c` has SHA-256
  `7d09bea7adf0c9e62c33a893fef7ab4afa61fe66933e12ec55382871674f28c4`;
- `src/gmp_get.c` has SHA-256
  `e34a2fc4ece0f1d1d9c74151a744f993f2983debf9abef0213e0e691baa4b9ea`;
- all five complete report-format schema command sections are identical; and
- the inspected GET, modify-parser/dispatch, and verify-dispatch slices in
  `gmp.c` are identical.

The last two comparisons are deliberately narrow. They do not repin the
global schema or claim that the complete schema and `gmp.c` files are
otherwise identical.

## Creation and opaque import

The
[`create_report_format` handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_report_formats.c#L312)
first checks for a direct `<copy>` child. Without copy it requires a direct
exported `<get_report_formats_response>` envelope containing a
`<report_format>`. A bare format, already wrapped creation command, unrelated
root, empty envelope, or name-only payload is not supported. The old direct
creation request, free builder, options, and facade are therefore removed;
callers choose import or clone explicitly.

`ImportReportFormatRequest` owns the original exported XML. Its codec checks
well-formed framing, valid attributes/references, one unqualified supported
root, exactly one direct format, and nonempty direct ID/name. Declarations,
DTDs, multiple roots, breakout text/content, namespaces on the root, unknown
entities, and multiple formats are rejected before transport. Comments,
CDATA, ordinary whitespace, escaped text, and nested empty elements remain
permitted. After validation the original bytes are embedded unchanged; the
codec does not reconstruct the document, trim fields, reorder children, or
base64-encode the envelope.

The raw handler selects the first matching format, so the one-format rule is a
deliberate typed restriction. Raw `send`/`call` remains available for callers
who intentionally need that server behavior. Presence of an ID is checked
locally, while gvmd's UUID acceptance and complete definition validation stay
server-authoritative and do not tighten the general `EntityId` policy.

The
[`import parser`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_report_formats.c#L166)
reads name, content type, extension, summary, description, signature, files,
parameter definitions, and report type. Exported active, trust, predefined,
owner, permission, and timestamp observations are not creation controls.
Imports are inactive and non-predefined, and missing or invalid report type
falls back to `all`. Existing UUIDs allocate a new ID; name collisions receive
numeric suffixes beginning at `2`. Callers must use the created response ID.

File payloads are already base64 and remain opaque to the client. The mock
stores valid fixtures only as inert in-memory data: neither layer executes a
script or writes imported files. Parameter-definition values/defaults are
plain XML text, not modification's base64 carrier. The server remains
authoritative for parameter types, defaults, duplicate names, sentinel bounds,
selection choices, string lengths, report-format-list grammar, and
multi-selection JSON.

## Clone behavior

Clone accepts the source ID and optional name only. Omitted or empty name
requests an upstream-generated unique name; an explicit nonempty name is exact
and collisions fail. Copy takes precedence over import and other creation
children. Metadata, active state, report type, parameter rows, and files are
copied; `predefined` is cleared, and clones of predefined formats are treated
as trusted. The pinned
[`clone implementation`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_report_formats.c#L1393)
does not copy parameter-option rows. The mock preserves this omission instead
of silently repairing it.

## Modification and parameters

The
[`modify parser`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L7050)
supports `name`, `summary`, `active`, and one accumulated `param`. Omitted
metadata preserves its value, and a selector-only request is valid. Empty name
or summary is emitted as paired tags (`<name></name>`), because the source text
callback does not establish a value for a self-closing element. Whitespace is
preserved. Predefined formats reject modification.

`ReportFormatParamUpdate` carries one exact name and decoded UTF-8 text.
Omitting `param` preserves every parameter. A present parameter with no value,
or with an explicitly empty value, clears that parameter. A nonempty value is
standard-base64 encoded exactly once. There is no default-reset operation and
no heuristic for already-base64-looking strings. Restoring a desired default
requires sending that text explicitly. NUL is rejected before transport to
avoid C-string truncation; other server-side value rules are not duplicated.

Two source defects remain explicit:

1. metadata is committed before the parameter setter, so a later missing or
   invalid parameter error can leave name, summary, or active changes visible;
2. initial parameter lookup is insufficiently scoped by format, so duplicate
   names in different formats can affect validation in database-order-dependent
   ways.

The mock models the first partial effect. It uses deterministic per-format
lookup for its bounded seeded subset and does not claim to reproduce database
row-order behavior.

`ReportFormatType` remains as a standalone compatibility enum but has no
lifecycle role here. Its display labels are neither report-format IDs, GMP
parameter types, nor the `scan`/`audit`/`all` report-type values. There is no
label-to-UUID conversion and modification emits no invented `<type>` field.

## Query and response boundary

List and detail expose report-format ID, inline filter, saved filter, trash,
details, alerts, params, report configurations, and `ignore_pagination`.
Optional booleans preserve absent/false/true. Detail defaults details to true
but callers may override it. Empty inline filters and saved-filter sentinels
`0` and `-2` remain distinct inputs; inline and saved filters may coexist.
Sorting and pagination stay in filter text.

`params=true` requests parameter definitions without files/signature;
`details=true` requests parameters, files, and signature. Explicit
`params=false` does not suppress detail expansion. Alerts and report
configurations independently request associations and invisible-reference
counts. The typed codec rejects only `params=true, trash=true`; gvmd permits
`details=true, trash=true`, although trash option/file iteration can resolve
active-format state and is not a reliable complete export round trip.

ID selection follows a separate source path and ordinary list filters or
pagination do not hide the selected format. `CountInfo.total`, `filtered`, and
`page` have separate meanings. The typed `ReportFormat` response remains a
bounded projection: metadata, content type, extension, summary, trust text,
active, and predefined. It intentionally omits parameter definitions,
description, report type, configurability, files, signature, trust timestamp,
and expanded associations. Raw execution preserves access to those subtrees.

## Delete, trash, and verification

Omitted delete `ultimate` defaults false. Nonultimate deletion gives a
non-predefined format a new trash ID; callers must observe and use that ID for
later trash operations. Predefined format IDs remain stable. Parameter
definitions/options follow the trash resource and ultimate deletion removes
them. Active alert use can block deletion; trash alert handling differs. A
report-configuration reference alone neither blocks deletion nor cascades, so
configurations can become orphaned while retaining #645's observation and
modify behavior.

Verification checks signature trust, including files and definition material;
it neither generates a report nor proves that the format works. A successful
action response means verification completed, not that trust is `yes`. Read
the format afterward to observe `yes`, `no`, or `unknown`. Missing signatures
can produce unknown. Verification updates trust, trust time, and modification
time without activating the format. Feed signatures take precedence over a
stored signature. Active predefined formats render trust as yes independently
of the stored field.

## Schema differences

The stable schema differs materially from the pinned implementation:

- modify describes a one-of pattern, while source accepts combined
  metadata/parameter updates and a no-op selector-only request;
- delete marks `ultimate` required, while source defaults omission to false;
- GET omits the common parser's `ignore_pagination`; and
- schema descriptions do not capture paired-empty parsing, partial metadata
  commits, cross-format parameter lookup, clone option omission, or trash
  rendering limitations.

The canonical codecs follow pinned source behavior. No schema snapshot is
repinned or rewritten.

## Mock and validation evidence

Exact-wire tests independently specify all seven requests, every optional
boolean state, filters/sentinels, escaping, Unicode, paired empties,
base64-once behavior, final mutation, direct-encode validation, static response
associations, semantic aliases, and confidential diagnostics. Import tests
cover valid rich byte preservation, framing, entities, breakout attempts, and
typed multi-format rejection. Parser fixtures cover source-shaped rich/empty
lists, mixed trust content, absent and distinct counts, malformed values,
required IDs/names, and ignored expansion subtrees.

The stateful mock implements a bounded subset: valid import definitions and
inert files; collision ID/name allocation; raw first-format selection; clone
naming/state/option omission; exact single-parameter updates; metadata partial
effects; active/trash query selection; one concrete saved filter; deterministic
sorting/pagination/counts; independent alert/config associations; new trash
IDs; deletion guards/orphans; and injected yes/no/unknown verification
outcomes. It does not implement real GPG verification, filesystem deployment,
complete ACL/filter or user-setting engines, every validator, database-row
ordering, or reliable complete trash-detail rendering. Python interoperability
with this mock is not live-gvmd validation.
