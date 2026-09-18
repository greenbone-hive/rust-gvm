# Asset request behavior in pinned gvmd

The canonical asset, host, and operating-system-asset requests are based on
gvmd revision
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The repository command registry remains pinned separately to
`55e5d4c657c48ce52ee340c2439680418bfe1a4d`; the relevant schema sections and
`manage_sql_assets.c` are identical at both revisions. This is source/schema
evidence, not a live-gvmd validation claim.

## Reads

The [`get_assets` parser](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5612)
reads and lowercases the required `type` attribute, then uses common get
handling for selectors and filters. The
[handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L12530)
rejects a missing type and recognizes `host` and `os`. Generic typed reads
therefore require one `AssetType`; aliases fix the type. Nonempty custom types
remain forward-compatible inputs whose acceptance is server-authoritative.

Requests expose `filter`, `filt_id`, `details`, and `ignore_pagination`.
Concrete saved filters are resolved by gvmd's
[common get initialization](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c#L90);
the client leaves filter expressions and saved-filter sentinels opaque.
The typed surface omits `trash`: it is absent from the asset schema, asset
iterators provide no trash columns, and generic trash SQL does not establish a
supported restorable asset lifecycle. Raw XML remains available.

## Direct creation, modification, and deletion

Outside report import, the
[create handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L22841)
creates only hosts. Asset management
[requires an IPv4 or IPv6 name](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_assets.c#L784)
and stores the supplied spelling. `CreateAssetRequest` and
`CreateHostRequest` therefore require `name`, always emit `type=host`, preserve
accepted spelling, and reject DNS names, lists, ranges, CIDRs, empty text, and
malformed addresses before transport. Rust's `IpAddr` parser is the explicit
typed lexical policy; it may be narrower than every spelling accepted by
upstream gvm-libs.

[`modify_asset`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_assets.c#L3463)
looks up a host and replaces its comment, using empty text when the child is
absent. Canonical modify requests require the final comment and always encode
it; empty text explicitly clears. There is no value update. An OS ID follows
the handler's host find-error path, so the former OS-modification request,
builder, and facade have no supported replacement.

The [`delete_asset` parser](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5231)
does not read `ultimate`; asset ID deletion is permanent. OS deletion is
guarded by any `host_oss` reference, including non-best matches, before removal
in [`manage_sql_assets.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_assets.c#L3843).
The typed ID-delete requests consequently carry only their identifier.
Report-ID bulk deletion remains outside this request family.

## Responses and distinct operating-system surfaces

Asset rendering uses `<asset><type>host|os</type>…</asset>` and `asset_count`.
The existing `GetAssetsResponse`, `GetHostsResponse`, and
`GetOperatingSystemAssetsResponse` retain identifiers, host source/OS
references, severity fields, install counts, and nested OS hosts. Generic
create retains an optional response ID for the distinct report-import branch;
direct host create requires its ID.

Asset OS requests encode `get_assets type="os"` and return rich
`OperatingSystemAsset` values. They are deliberately separate from the
deferred SecInfo `get_info type="os"` surface and from report OS projections.
At this pin, `handle_get_info` has no OS dispatch branch; that drift belongs to
the later NVT/SecInfo migration, not this asset correction.

## Stateful mock boundary

Strict mock mode models nested direct-host creation, type selection, comment
replacement/clear, permanent deletion, OS-modification rejection, stored
filter precedence, and OS reference protection. `filt_id="0"` does not model a
user-setting fallback, and aggregate `installs`/`all_installs` counts are a
seeded approximation of `host_oss` relationships. Legacy flat input and asset
trash fixtures remain isolated behind `AssetInputProfile::LegacyFlatCompatibility`;
they are compatibility tools, not gvmd conformance evidence.
