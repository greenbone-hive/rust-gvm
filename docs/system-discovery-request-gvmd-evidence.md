# Core and system-discovery request evidence

Issue #663 was reconciled against the repository-pinned gvmd checkout at
`864aa1b89ade61a2c2615c0946a69abc163dbc19` and the interoperability pin,
python-gvm 27.8.0 at `1bb3782b62532c452af153b54a2b02a3ba62e264`.
gvmd is authoritative when its executable parser differs from schema examples,
python-gvm, or the mock server.

## Reviewed gvmd artifacts

| Artifact | SHA-256 | Evidence used |
|---|---|---|
| [`src/gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c) | `ff46494e6ac9842c03e07c91e5ce56d0c6c4342b2a930d2cf4a1e24cb27f3397` | Authentication state, aggregate/feed/feature/help/resource-name/settings/system-report/timezone parsing and responses |
| [`src/gmp_get.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_get.c) | `e34a2fc4ece0f1d1d9c74151a744f993f2983debf9abef0213e0e691baa4b9ea` | Shared filter, ID, trash, details, ignore-pagination, and filter-replacement parsing |
| [`src/manage_get.h`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_get.h) | `c3711a1cfcac2fbdc30270bd4c8e35fb7ffc681f75f5c82e3cf2ac8c45656066` | Common GET selection state consumed by aggregates and resource-name discovery |
| [`src/gmp_license.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_license.c) | `3d08f8306dab84edd4da8e3d8f8fd2e98ebdd8a3f15dbdbc0ceceafd492ae291` | License request and optional status/content response |
| [`src/schema_formats/XML/GMP.xml.in`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in) | `9fd7e9382c040b2c062ea6ab48d8ffa3b2258eea500e07f45ff66bf8ddbf3338` | Public command attributes, child shapes, formats, and examples |
| [`docs/token-based-authentication.md`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/docs/token-based-authentication.md) | `7059364d89bf99619875ce8835785877369461004f93cdb0cbfd8bf34a9c566d` | Token credential and requested-token response behavior |

## Wire decisions

| Operation | Canonical decision |
|---|---|
| `get_version` | Empty pre-authentication request. Connection negotiation encodes the same canonical request directly before a GMP version exists. |
| `authenticate` | Owns username/password or token credentials plus the optional root `token` request flag. Debug, errors, and wire traces redact username, password, and token values. |
| `help` | One request models text, brief XML discovery, and full `html`, `rnc`, `text`, or `xml` schema output. Brief mode is exactly `format="xml" type="brief"`. |
| `get_features` | Empty request with the existing GMP 22.6 pre-transport gate. |
| `get_feeds` | List and semantic detail requests share one authoritative root; detail owns the optional NVT, SCAP, CERT, or GVMD data selector. Missing response access flags remain `None`. |
| `get_timezones` | Empty request with the existing GMP 22.8 pre-transport gate. |
| `get_aggregates` | Current shape owns repeated `sort`, `data_column`, and `text_column` children. The deliberately distinct legacy shape owns gvmd's singular `data_column`, `sort_field`, `sort_stat`, and `sort_order` attributes. Both require `type` and own saved/inline filters, type-derived resource ID, filter replacement, trash/details/ignore-pagination controls, grouping, group paging, mode, and usage. |
| `get_settings` | Owns `setting_id`, inline `filter`, `first`, `max`, `sort_field`, and `sort_order`. The dedicated gvmd parser does not consume `filt_id`. Response filtering, page bounds, count, and optional certificate metadata are preserved. |
| `get_system_reports` | Owns name, duration, start/end time, brief mode, and scanner/slave ID. Report format/time metadata and payload remain optional because gvmd can omit them. |
| `get_resource_names` | Requires a type and owns common saved/inline filter, filter replacement, trash, details, and ignore-pagination controls. Detail is a semantic request with `resource_id`. Pagination remains part of the GMP filter grammar for this root. `AUDIT`, `AUDIT_REPORT`, and `POLICY` remain distinct from task, report, and config; the response type is read from the emitted child element, with the old attribute accepted on decode only. |
| `get_license` | Empty request associated with a concrete license response containing optional license, content, metadata, appliance, keys, and signatures. It is no longer associated with a generic action response. |
| `describe_auth` | Empty request associated with groups/settings and optional certificate metadata. |

The domain modules above are the only typed encoders. Duplicate `system`
builders/wrappers and byte-identical help/facade aliases are recorded as
`removed` in the disposition ledger. Named helpers accept the canonical value
unchanged and delegate only to `execute`; raw `send`, `call`, and custom codecs
remain the escape hatches.

## python-gvm comparison

The pinned python-gvm request files were reviewed as migration and
interoperability evidence, not as API-shape authority:

| File | SHA-256 |
|---|---|
| `requests/_version.py` | `19d1d09c457327a3dbc68538a713f7e8ecded57bcae65956a81f5b902d7a3dff` |
| `requests/v224/_aggregates.py` | `1b9ccee61e9c6bb7472322a9f75c99c95e9660ae0bbfa5bc1c99bb9b2af3fe43` |
| `requests/v224/_auth.py` | `46ad024e2032f96b21e654ae08ee0d09a3a2fe3d005d66020c13f62bcb80314d` |
| `requests/v224/_feed.py` | `899442ce73c011f9ad7b657220db2fd166c2bcc2a7d07b6e73e1eec0bbe9a415` |
| `requests/v224/_help.py` | `7c0fec7004372557f0b5e5033b9df3398e5463fa939f9deaf9dfd060f820238c` |
| `requests/v224/_system_reports.py` | `17b74daca99f071b0e62a00c11ead307808aa99054bf8686d6a7afa3c2f0a35d` |
| `requests/v225/_resource_names.py` | `ebfaaa51b315e68795c6c71b5bdb6dfe66ad8145632a235e9a63cb898ec82595` |
| `requests/v226/_resource_names.py` | `a724683e3c59702be07220ff086bb6956c446e13b05f873813cf56e9dab80f49` |

Pinned Unix, TLS, and mutual-TLS interoperability exercises python-gvm's
request generation against the Rust mock server separately from the request
ownership tests. This keeps compatibility evidence independent from the Rust
public API design.
