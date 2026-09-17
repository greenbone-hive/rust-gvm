# Credential request gvmd evidence

Issue #620 changes Rust API ownership for credentials and credential stores.
It preserves the established standard-credential wire contract, adds the
store-backed SNMP inputs required by gvmd, and corrects the legacy Rust
single-store selector to the documented attribute shape. The contract is
anchored in the gvmd source pinned by this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L4319)
  defines credential creation, including the name, clone source, password,
  nested key, certificate, Kerberos, SNMP, and type fields. The corresponding
  modification schema begins at
  [line 37575](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L37575),
  while list/detail queries share `get_credentials` at
  [line 14195](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L14195).
- The same schema defines `get_credential_stores` at
  [line 15007](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L15007)
  and identifies `credential_store_id` as a root attribute at
  [line 15018](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L15018).
  The old Rust detail builder emitted a child element; the canonical
  `GetCredentialStoreRequest` fixes that protocol defect.
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L23457)
  rejects empty create names and logins, key containers without public/private
  material, malformed keys, and invalid certificates before calling the
  manager operation. It forwards the standard values and the credential-store
  ID, vault ID, host identifier, privacy host identifier, and type at
  [line 23507](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L23507).
- [`manage_sql.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c#L19868)
  applies the selected credential-type requirements: login, private
  key/certificate, public key, Kerberos KDC/realm, SNMP authentication, and
  privacy-algorithm combinations. Explicit `up` requires a login but may omit
  its password for gvmd autogeneration; explicit `pw` may likewise omit its
  password. The accepted store-backed type set is `cs_pgp`, `cs_pw`,
  `cs_snmp`, `cs_smime`, `cs_up`, `cs_usk`, and `cs_krb5`. In particular,
  pinned gvmd does not accept the previously exposed Rust-only `cs_cc` type;
  the canonical input enum removes that unsupported value.
  Credential-store-backed values are checked
  at
  [line 19995](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c#L19995):
  an explicit or configured default store is required, vault and host
  identifiers are required, stored Kerberos credentials require KDC/realm
  values, and stored SNMP credentials require an authentication algorithm.
  The canonical Rust request requires caller-owned
  values but does not require an explicit store ID because gvmd may supply its
  configured default.
- gvmd validates modification against the stored credential type, starting at
  [`manage_sql.c` line 20608](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c#L20608).
  Canonical modify requests therefore validate only caller-known final values
  and do not guess the referenced credential's type. Store vault and host
  replacements reject empty values at
  [line 20803](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql.c#L20803).
- [`gmp_credential_stores.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_credential_stores.c#L451)
  parses store modification attributes, host/path/port/comment fields, and
  preference name/value pairs. Store verification reads the required root
  attribute at
  [line 621](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_credential_stores.c#L621).

Credential-store-backed create and modify reuse the `create_credential` and
`modify_credential` XML roots. Their canonical requests retain separate
`create_credential_store_credential` and
`modify_credential_store_credential` semantic identities so GMP 22.8 support
checks happen before encoding or transport. Store list/detail, modification,
and verification are also gated to GMP 22.8.

This source/schema evidence is intentionally separate from repository-local
mock evidence:

- request-module tests assert independent exact XML for standard,
  SSH/key, Kerberos, certificate, SNMP, store-backed Kerberos/SNMP,
  preference-bearing store, and semantic-alias requests, plus compile-time
  response associations;
- request and client tests inspect secret-safe `Debug`, error/source chains,
  and wire traces using unique sentinels for passwords, key/certificate
  material, SNMP values, vault/host identifiers, and preferences;
- `gvm-client/tests/canonical_request_foundation.rs` proves a mutated invalid
  store-backed request fails before its GMP 22.8 gate with empty transport
  history, while version tests cover every newer store operation;
- stateful mock lifecycles cover standard and store-backed credentials,
  including store-backed Kerberos create/get/modify KDC and realm round trips
  plus missing-KDC, missing-realm, and unsupported-`cs_cc` rejection. Store
  verification/modification are exercised without claiming an external vault
  integration that the test environment does not provide.

The mock and the repository's python-gvm Unix/TLS/mTLS suites are not claimed
as real-gvmd interoperability proof. This development container has no Docker
client, configured/reachable gvmd socket, or external credential-store service.
The previously populated Community E2E volumes live on an external self-hosted
runner and are not mounted here. That runner's current harness also needs its
known readiness-loop reauthentication and removed target-helper imports repaired
before a safe exact-revision run. Consequently, no live standard-credential or
store-backed lifecycle is claimed by this PR. The post-merge Community E2E
dispatch remains the intended deployed runtime gate once that external harness
is repaired; store-backed mutation additionally requires a configured external
credential-store service.
