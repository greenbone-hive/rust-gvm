# TLS-certificate request behavior in pinned gvmd

Issue #647 canonicalizes TLS-certificate list, detail, create, clone, modify,
and delete requests against gvmd revision
[`864aa1b89ade61a2c2615c0946a69abc163dbc19`](https://github.com/greenbone/gvmd/tree/864aa1b89ade61a2c2615c0946a69abc163dbc19).
The repository command-registry/schema snapshot remains pinned separately at
`55e5d4c657c48ce52ee340c2439680418bfe1a4d`. This document records public
source and schema inspection. Repository tests and the bounded mock are
separate evidence categories; no live-gvmd validation is claimed.

## Pin comparison

The behavioral source pin, repository schema pin, and upstream `main` as
resolved during issue review (`8525407f910fbe7b8c9f1edb452387e2cf01bb89`)
were compared byte-for-byte. At all three revisions:

- `src/gmp_tls_certificates.c` has SHA-256
  `8f6f67c5aa35964522185f734b1bc3c5d89c74b715f5f08cf9fa3bdc34531eae`;
- `src/manage_sql_tls_certificates.c` has SHA-256
  `2764c80cfa70c12acc4324d95b08fc08f3034493e43b74e1e42294f966e8223d`;
- `src/manage_tls_certificates.c` has SHA-256
  `05f99fb9869a23b248d9cd424526f75f3ac6c17bcc8f42cb7a6a0b1af731a281`;
- `src/gmp_get.c` has SHA-256
  `e34a2fc4ece0f1d1d9c74151a744f993f2983debf9abef0213e0e691baa4b9ea`;
- `src/gmp_delete.c` has SHA-256
  `f22960c06a9d348536f4732927559239193d8258310f4fd2e0743bce94a565d5`;
- `src/manage_sql_resources.c` has SHA-256
  `037671395245006e5fa5164640169c1fd9e7f3f9e60da7a2cc4050bc67741304`;
- the complete create, get, and modify TLS-certificate schema sections are
  identical, and no delete section exists; and
- the inspected TLS-delete parser/dispatch sections in `gmp.c` are identical.

The schema-section and `gmp.c` comparisons are deliberately narrow. They do
not repin either complete file or imply that unrelated sections are identical.

## Creation and certificate bytes

The
[`create_tls_certificate` handler](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_tls_certificates.c#L497)
requires nonempty certificate data for direct creation. Name is optional:
omission or an empty name defaults to the SHA-256 fingerprint, not the MD5
fingerprint named by schema prose. Omitted comment becomes empty and omitted
trust becomes false. Nonempty names, including surrounding whitespace, are
preserved.

`CreateTlsCertificateRequest` owns the original certificate-file bytes and
standard-base64 encodes them exactly once. It does not accept an already
encoded GMP carrier, normalize PEM line endings, strip PEM armor, or inspect
DER. Arbitrary nonempty binary data, including NUL and non-UTF-8 bytes, is
valid client input; GnuTLS parsing and certificate acceptance stay
server-authoritative. Callers supply certificate-only data. gvmd extracts
metadata while parsing but stores the submitted base64 carrier, so neither
the client nor this contract promises to remove unrelated material embedded
in a payload. See the
[`base64/storage path`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_tls_certificates.c#L635)
and
[`certificate parser`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage.c#L438).

The authenticated user becomes owner. An existing SHA-256 or MD5 fingerprint
for that owner rejects creation; names are not certificate identity and a
different representation cannot evade fingerprint matching. Different owners
may hold the same certificate. Direct creation creates an `Import`
observation source. It is not an upsert and the client performs no preflight
query. The owner/fingerprint lookup is implemented in
[`manage_sql_tls_certificates.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_tls_certificates.c#L1402).

Trust is an optional stored boolean, independent of time validity and not a
request for chain verification. The raw parser treats empty and `0` as false
and other nonempty text as true; the typed request intentionally exposes only
`Option<bool>`. The `valid` response field is a server time-status
observation, not proof of signature or chain verification.

This resource has no private-key lifecycle. The handler does not consume the
old `<private>` creation/modification child, and modification cannot replace
certificate bytes. Canonical requests therefore expose neither field and do
not alias them to credentials, connection identity, rotation, import, key
generation, or verification operations.

## Clone behavior

Clone uses a direct `<copy>` child of `create_tls_certificate`; copy takes
precedence over direct-create certificate and trust children. The source may
belong to the current owner or be a visible, permitted foreign resource.
Cloning fails when the current owner already has either source fingerprint,
which makes cloning one's own certificate fail and prevents a name change
from bypassing certificate identity. Source visibility and create permission
remain server decisions. See the
[`shared copy checks`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_resources.c#L482).

Omitted or empty clone name copies the source name without a generated suffix.
A nonempty name is exact and checked for an owner-scoped name collision.
Omitted or empty comment likewise copies the source comment; clearing a clone's
comment requires a later modification. Whitespace is not trimmed.

The
[`TLS copy implementation`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_tls_certificates.c#L825)
copies certificate content, fingerprints, format and parsed metadata, and
trust. Shared copy logic also copies tag associations. Observation sources,
locations, and origins are not copied and clone adds no `Import` source, so a
clone can have certificate data without `last_seen`.

## Modification and deletion

Modification accepts name, comment, and trust only. Omitted fields preserve
their stored values; explicit empty name/comment values clear them. A
selector-only no-op is valid and need not change modification time. The
operation does not impose creation's name fallback or fingerprint uniqueness,
and the schema's optional modify `<copy>` child has no implementation. The
transactional implementation is in
[`manage_sql_tls_certificates.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_tls_certificates.c#L983).

TLS certificates have no trash lifecycle. Nonzero GET `trash` is rejected.
Deletion is always permanent, and the common parser's optional `ultimate`
attribute has no effect for this resource. The canonical delete request is
therefore ID-only. There is no restore path or invented in-use prohibition;
TLS resource helpers report writable and not-in-use independently of ACL
authorization.

Permanent deletion removes certificate permissions, tag associations, and
source relationships, then cleans unreferenced locations/origins. Shared
observations remain while referenced, and reports and host assets are not
deleted. Ownership inheritance during user deletion is a separate gvmd
operation, not TLS request input. See
[`SQL deletion`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_tls_certificates.c#L846).

## Query and response boundary

List and detail expose certificate ID, inline filter, saved-filter ID,
details, and certificate-data expansion. Optional booleans preserve
absent/false/true. Detail defaults details to true but callers may override it.
Empty inline filters and saved-filter sentinels `0` and `-2` remain distinct,
and inline and saved filters may coexist. Filter precedence, missing-filter
fallback, user settings, arbitrary grammar, sorting, and pagination remain
gvmd concerns. `host_id` and `report_id` are relationship filter terms, not
root attributes.

ID selection follows a separate source path, so ordinary predicates and
pagination do not hide the selected certificate, although filter resolution
can still fail. The common parser accepts `ignore_pagination`, but the common
SQL iterator's effective bypass whitelist excludes TLS certificates. The
typed API does not expose that ineffective control or root pagination.

Certificate text is included when `details || include_certificate_data`.
Sources are included only when details is true, and explicit
`include_certificate_data=false` cannot suppress detail certificate data.
Without either flag gvmd still emits an empty `<certificate format="…">`
element. The typed response keeps its bounded projection: identity and owner
metadata, issuer/subject, activation/expiration, MD5/SHA-256 fingerprints,
valid, and optional wire base64 certificate text. Empty and absent text both
map to `None`. Format, serial, trust, time status, last-seen, tags,
permissions, and source graphs remain available through raw responses.

Parser fixtures use top-level `<tls_certificate>` items, a separate
`<tls_certificates start="…" max="…"/>` metadata element, and
`<tls_certificate_count>` with distinct total, filtered, and page values.

## Schema and capability discrepancies

The preserved schema differs materially from the pinned implementation:

- create prose names MD5 for the default name, while source uses SHA-256;
- create requires certificate in its direct pattern although the copy branch
  needs only copy plus optional overrides;
- modify advertises a copy child that source does not implement;
- GET omits the supported `details` attribute;
- no `delete_tls_certificate` schema command exists; and
- common parsing accepts `ignore_pagination`, but it has no effective TLS
  behavior.

Canonical codecs follow pinned source behavior without changing the global
schema snapshot. Create, get, and modify retain `PinnedSchema` evidence.
Delete is `PublicSourceOnly`: it is dispatched by
[`gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c#L5462),
passes through the
[`common delete handler`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_delete.c#L99),
and has the concrete SQL implementation linked above. Availability remains the
existing GMP 22.4+ baseline through the forward-compatible version bucket.

## Typed restrictions, confidentiality, and mock evidence

All six requests own their final public inputs and invoke validation from
direct encoding. IDs are revalidated after deserialization, literal text must
contain XML 1.0 characters, empty literal fields use paired tags, and
certificate bytes must be nonempty. Validation does not parse X.509, reject
validity windows, validate trust chains, or guess a size limit. Request errors
carry static field context rather than values.

Create-request and typed-certificate `Debug` output redact certificate data,
and established wire tracing redacts certificate/private-key element variants
for typed and raw/custom traffic. Explicit byte encoding, raw responses, and
serde serialization remain intentionally data-bearing APIs rather than
redaction mechanisms. Raw `Request`, `XmlCommand`, `send`/`call`, and custom
`GmpRequestCodec` implementations remain available for deliberately unmodeled
XML.

The stateful mock implements a bounded registered-fixture model. Known PEM and
DER spellings share deterministic fingerprints and metadata; known invalid
content and all unregistered payloads are rejected. It accepts standard
base64 with ASCII whitespace removed before decoding, which is narrower than
GLib's generally permissive decoder. It models authenticated ownership,
visibility, owner-scoped SHA-256/MD5 collisions, clone override/copy
precedence, tag copying without observations, supported modification fields,
the data/source expansion truth table, a small declared filter grammar,
saved/inline filters, sorting/pagination/counts, ID bypass, and permanent
deletion with bounded association checks.

The mock does not claim general X.509/GnuTLS parsing, cryptographic
verification, full ACL or user-setting behavior, arbitrary filter grammar,
complete report/host joins, database cleanup internals, or release-by-release
gvmd conformance. Its tests establish deterministic repository behavior only;
they are not live-gvmd evidence.
