# Scanner request gvmd evidence

The canonical scanner requests are based on the public gvmd source pinned by
this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in)
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c)
- [`manage_sql.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c)

## Create and clone

The create schema includes name, comment, copy, host, port, type, CA
certificate, credential, relay host, and relay port at
[lines 5872–5950](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L5872).
For ordinary creation, the executable handler requires name, host, port, and
type, rejects a primary Unix-socket path over GMP, and forwards both relay
fields at
[lines 21260–21307](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L21260).
`CreateScannerRequest` therefore owns and validates those final values before
support checks or transport.

Clone is a semantic operation over `create_scanner`. The handler forwards
optional name and comment overrides to `copy_scanner` at
[lines 21212–21225](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L21212),
and the copy implementation treats null overrides as “copy existing” at
[lines 23660–23678](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c#L23660).
That implementation copies host, port, type, CA, and credential data but does
not copy relay fields; the stateful lifecycle locks down the same boundary.

## Modify and clear semantics

The modify schema exposes the identifier plus optional name, comment, host,
port, type, CA certificate, credential, relay host, and relay port at
[lines 38830–38904](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L38830).
The handler preserves omitted values and rejects a primary Unix-socket path at
[lines 21454–21477](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L21454).

The management layer supplies the exact update distinctions used by the Rust
request model:

- omitted host, port, relay host, and relay port preserve stored values;
- an empty relay host clears the relay and sets its port to zero;
- network ports must be in `1..=65535`, while Unix-socket relays use port zero;
- credential ID `""` or `"0"` detaches the credential;
- omitted name/comment preserve, while explicit empty comment clears; and
- empty `ca_pub` restores the default CA certificate.

These behaviors are implemented at
[lines 23776–23907](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c#L23776)
and
[lines 23962–24007](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c#L23962).
`ModifyScannerRequest` uses `Option` for text/port fields and
`ScalarUpdate<EntityId>` for the credential relationship so callers can
express preserve, replace, and clear without another options bag.

## Evidence boundary

The stateful mock lifecycle covers exact XML, list/detail parsing, relay
persistence, partial-update preservation, clone overrides, explicit clearing,
verification, and deletion. These deterministic tests validate the canonical
contract but are not a claim of live-gvmd interoperability.
