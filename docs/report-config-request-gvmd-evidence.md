# Report-configuration request behavior in pinned gvmd

Issue #645 canonicalizes report-configuration list, detail, create, clone,
modify, and delete requests against gvmd revision
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The repository command registry/schema snapshot remains pinned separately at
`55e5d4c657c48ce52ee340c2439680418bfe1a4d`. This document records public
source and schema inspection. Repository mock tests are a separate evidence
category; no live-gvmd validation is claimed.

## Pin comparison

The reviewed source pin, the repository schema pin, and upstream `main` as
resolved during the issue review (`8525407f910fbe7b8c9f1edb452387e2cf01bb89`)
were compared byte-for-byte. At all three revisions:

- `src/gmp_report_configs.c` has SHA-256
  `06e8595250671c14318780d15e2c49f980f5cd5687a7a273c8a4f973da8a1a55`;
- `src/manage_sql_report_configs.c` has SHA-256
  `efbb9432f42a6d736156cca1de540788eb39ea8e42ae3f3ec3e1417171651ac4`;
- `src/gmp_get.c` has SHA-256
  `e34a2fc4ece0f1d1d9c74151a744f993f2983debf9abef0213e0e691baa4b9ea`;
- the four complete `create_report_config`, `delete_report_config`,
  `get_report_configs`, and `modify_report_config` schema command sections
  have the same combined SHA-256
  `54eff3f0c8a7241d98eaf6088747cd10f25108e579c30539c9ff248c0d3652af`;
- the report-configuration parameter renderer and GET handler slice in
  `gmp.c` has SHA-256
  `7ccbe1db35ef0f355db41fb43e6bff4f65d68ab9923802f93e97191155df65b1`.

These narrow comparisons do not repin the global schema or imply that the
complete `gmp.c` and schema files are otherwise identical.

## Create, clone, and import boundary

The
[`create_report_config` handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_report_configs.c#L198)
has two branches: copy when a direct `<copy>` child is present, and direct
creation otherwise. Direct creation requires nonempty `<name>` and a
`<report_format id="..."/>` reference. The older rust-gvm
`<report_format_id>` child is not supported. The format must exist, be
accessible, and have configurable parameters. Those state-dependent checks
remain server-authoritative.

The complete handler has no report-configuration import branch. Nested
`<get_report_configs_response>` or `<report_config>` documents do not provide
the required direct children. rust-gvm therefore exposes no import request,
payload parser, facade, or semantic alias for this family.

The copy branch takes precedence over direct-create fields. It accepts only an
optional name override and copies the format association, comment, and stored
parameter overrides. Omitted and explicitly empty names both request the
upstream generated unique name; a nonempty override is exact and a collision
fails atomically. Supplied comment, format, and parameter extras acquire no
effect. The
[`copy_report_config` path](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_report_configs.c#L45)
does not rerun direct-create format configurability checks, so an orphaned
source can still be cloned.

## Modification and parameter updates

The
[`modify_report_config` parser](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_report_configs.c#L482)
requires the root `report_config_id`. Omitted name and comment preserve stored
values; an empty comment clears it; an explicitly empty name is invalid. The
handler does not support changing the report-format association, and a
request with no caller-visible changes is valid.

Create and modify parse repeated direct parameter children:

```xml
<param><name>Parameter name</name><value>literal text</value></param>
```

Names are stripped only of surrounding ASCII whitespace by gvmd. Value text
is preserved and XML text escaped; it is not base64. Missing names, names
empty after stripping, and missing value elements are skipped by the raw
parser. Canonical typed requests reject the malformed name cases before
transport while preserving the accepted spelling on the wire.

`Value("")` is an explicit empty assignment. Omission preserves a stored
override. On modify, `UseDefault` emits
`<value use_default="1"></value>` and removes only that named override. On
create, the same input skips its own insertion; it does not undo an earlier
duplicate assignment. Ordering and duplicate names are therefore preserved.
Ordinary assignments upsert in order, while a later modify reset removes an
earlier assignment. Reset bypasses format parameter/value validation, whereas
assignments are checked against the referenced format. Parameter existence,
selection choices, numeric bounds, string byte lengths, multi-selection JSON,
and report-format-list grammar remain server-authoritative and are not
reimplemented by request validation.

The SQL mutation paths apply metadata and parameter changes transactionally.
An invalid later parameter rolls back earlier assignments and accompanying
name/comment changes.

### Orphan modification quirk

Source tracing indicates that even a metadata-only modification of an orphan
is rejected at the pinned revision. `params_from_entity` always terminates the
parameter array, and the SQL path checks its length before resolving the
format. The terminator contributes an entry, so the format lookup can execute
with no actual parameter updates and roll the metadata transaction back. This
is a source-derived observation, not a live observation or a permanent
protocol guarantee. The bounded mock has an explicit regression for the
pinned behavior; orphan status otherwise remains server-authoritative.

## Delete and trash lifecycle

The
[`delete_report_config` implementation](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_report_configs.c#L395)
defaults omitted `ultimate` to false. Omitted or false moves an active record
and its overrides to trash; repeating nonultimate deletion of an already
trashed record succeeds. Ultimate deletion removes either the active or trash
record and its overrides. Missing records take the find-error path.

The source has in-use branches, but both report-configuration use-check helpers
currently return zero with TODOs. The mock consequently does not invent an
alert-reference deletion prohibition.

## GET controls, selection, and rendering

Report configurations use common GET parsing for `report_config_id`, inline
`filter`, saved `filt_id`, `trash`, `details`, and the implementation-supported
`ignore_pagination`. Pagination and sorting are filter terms such as `first`,
`rows`, `sort`, and `sort-reverse`; root `first` and `rows` are not parsed.
Empty inline filters and saved-filter sentinels `0` and `-2` remain distinct
valid inputs. Inline and saved filters may coexist. Concrete saved filters take
precedence, while missing-filter initialization can fall back, so the typed
contract does not promise that every unknown filter is a 404.

ID selection follows a separate path and is not hidden by ordinary list
predicates or pagination. Common iteration restarts an out-of-range inline
page from the beginning, but does not apply that restart to a concrete saved
filter. `CountInfo.total`, `filtered`, and `page` remain distinct; page is the
number of returned items. There is no canonical root `get_counts`, output
format, `filter_replace`, preference wrapper, usage type, policy, or scan
configuration input for this family.

The GET handler always invokes the parameter renderer. `details` affects
common expansions such as user tags; it does not gate parameter output.
Effective values use a stored override, then the report format's current
value, then its fallback. The response's default observation likewise reflects
the format's current value before fallback and is not an immutable factory
default.

For trash rows, `init_report_config_param_iterator` selects trash overrides
but resolves the format through an active-table helper. Output can therefore
depend on database row-ID relationships. rust-gvm does not claim a verified
trash parameter round trip or silently idealize this upstream behavior.

## Schema discrepancies

The four schema sections are stable across the compared revisions, but differ
from the implementation in these material ways:

- create's pattern lists name and format as required even though the copy
  branch needs copy plus an optional name only;
- delete marks `ultimate` required although the parser defaults omission to
  false;
- modify omits the required request `report_config_id` attribute and describes
  an ID-bearing response although the handler requires the selector and returns
  an ordinary action response;
- GET omits the common parser's `ignore_pagination` attribute;
- a parameter response example places `using_default` on `<param>`, while the
  renderer and response pattern place it on `<value>`.

The canonical codecs follow the pinned implementation. The repository schema
snapshot is not repinned or rewritten to conceal these discrepancies.

## Typed response boundary and mock evidence

The report-configuration parser retains identity/metadata and the associated
report-format reference. It now accepts an ID-only format reference and uses
the established empty-string convention for its absent name. Parameter
values/defaults/options/bounds, `using_default`, orphan status, format
permissions, and complete tag/permission expansion remain outside this
bounded input-ownership slice. Raw `send`/`call` remains available when those
observations are required; raw access does not guarantee that unsupported XML
will succeed.

Repository validation is distinct from source evidence. Exact-wire tests cover
the six requests, final-value validation, empty/preserve/reset distinctions,
booleans, filter sentinels, escaping, duplicates, and semantic response
associations. Parser fixtures use top-level `<report_config>` items, separate
`<report_configs start="..." max="..."/>` metadata, and
`report_config_count`, including ID-only associations and rich ignored
subtrees.

The stateful mock implements a bounded subset: seeded configurable and
nonconfigurable formats; `Label` string-length and `Graph Type` selection
validation; ordered overrides; clone naming; active/trash selection; name and
ID filters; sorting; filter pagination; `ignore_pagination`; and one concrete
saved filter. It does not model user-setting filter resolution, complete ACL
or tag behavior, every report-format validator, unknown-filter fallback
details, or SQL row-ID-dependent trash parameter rendering. Trash tests cover
selection and stored override preservation without claiming idealized
parameter output. Python interoperability against this mock is likewise not
live-gvmd validation.
