# System-administration, user-setting, and cleanup request evidence

Issue #664 was reconciled against the repository-pinned gvmd commit
`864aa1b89ade61a2c2615c0946a69abc163dbc19`. The pinned gvmd parser and
management implementation are authoritative where schema examples,
python-gvm, and the bounded mock differ.

## Reviewed source

| Artifact | SHA-256 | Evidence used |
|---|---|---|
| [`src/gmp.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp.c) | `ff46494e6ac9842c03e07c91e5ce56d0c6c4342b2a930d2cf4a1e24cb27f3397` | Authentication-group parsing, user-setting query/mutation dispatch, wizard defaults and response carrier, empty-trashcan/restore status mapping |
| [`src/gmp_license.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/gmp_license.c) | `3d08f8306dab84edd4da8e3d8f8fd2e98ebdd8a3f15dbdbc0ceceafd492ae291` | Base64 license payload, omitted `allow_empty=false`, clear behavior, action response |
| [`src/manage.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage.c) | `5ea04d60167b938a93bee3984f85b846fbfdd1613e6ff06456f2014c09da6a6c` | Wizard-name validation, file lookup, modes, parameter validation, read-only enforcement, nested command response |
| [`src/manage_sql.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql.c) | `ce7d5cc850ba32b55697113b42bfc484e90aa372f33fea52618e70b5a6a547db` | LDAP/RADIUS updates, transactional restore dependency/name/UUID checks, transactional empty-trashcan deletion |
| [`src/manage_sql_settings.c`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/manage_sql_settings.c) | `ab3c98648c21927c26e7dffbc2a8bfca35ef927c9fa9c90cab522c44467c3b35` | Base64/UTF-8 setting values, `Timezone`/`Password` name selectors, supported UUID settings, per-setting validation and clearing |
| [`src/schema_formats/XML/GMP.xml.in`](https://github.com/greenbone/gvmd/blob/864aa1b89ade61a2c2615c0946a69abc163dbc19/src/schema_formats/XML/GMP.xml.in) | `9fd7e9382c040b2c062ea6ab48d8ffa3b2258eea500e07f45ff66bf8ddbf3338` | Public request fields, boolean types, response envelopes, and baseline availability |

## Canonical decisions

| Operation | Decision |
|---|---|
| `modify_auth` | `ModifyAuthRequest` owns one group name and the complete ordered key/value set. Empty values are explicit string clears; an empty setting collection is the schema/parser no-op. The bounded mock validates the whole group before applying it. |
| `modify_license` | One request owns the base64 payload and `Option<bool>` `allow_empty`. Omission is gvmd's `false`; an empty payload is valid only with explicit `true` and clears bounded mock state. The former default and option-bearing request forms were byte-identical construction variants, not semantic operations, and are removed. |
| `modify_setting` | The selector is either an ID or gvmd's special `Timezone`/`Password` name. Values are UTF-8 at the Rust boundary and standard-base64 encoded exactly once; empty text is an explicit clear. The generic system and user-setting requests are distinct semantic types but share the one encoder because their wire and response semantics are identical. |
| `get_settings` | User-setting list owns inline filter, one-based `first`, `max` (`-1` or positive), sort field, and direction. Detail owns `setting_id`. Both use the actual `get_settings_response`, including filters, page bounds, items, and counts; the dedicated handler has no saved-filter-ID input. |
| `run_wizard` | One request owns name, ordered parameter pairs, optional mode, and optional read-only flag. Omitted `read_only` is false; omitted/empty mode selects the wizard default. Names are restricted to ASCII alphanumeric characters and underscore. The nested `<response>` remains opaque bytes in the typed response. Default and option-bearing Rust forms were redundant and are removed. |
| `empty_trashcan` | Payload-free baseline operation. gvmd removes the authenticated user's trashed graph in a transaction; the bounded mock deletes all trashed resources atomically. |
| `restore` | One baseline operation owns one required ID. gvmd checks trashed dependencies and active name/UUID collisions in a transaction. The Rust `restore_from_trashcan` name was only a byte-identical forwarding alias, so its builder, request, and facade are removed in favor of `RestoreRequest`. |

All commands in this slice are available throughout the supported baseline
GMP 22.4/22.5/22.6/22.7/22.8 range; there is no new capability gate. License
support can still be absent from a particular gvmd build because it depends on
the licensing library, which is a server response condition rather than a
protocol-version distinction.

Validation runs on complete request values before semantic support checks,
encoding, or transport. Validation errors contain only static field names and
reasons. Authentication settings, license payloads, wizard parameter values,
and setting values are redacted from request `Debug`, client diagnostics, and
request/response wire traces. Raw `send`, `call`, and custom request codecs
remain available for server extensions and unmodeled wizard payloads.

## Bounded mock contract

The stateful mock persists authentication groups, license presence, setting
values, and accepted wizard runs without exposing confidential state through
`Debug`. Protocol reads observe auth, license, and setting mutations. Invalid
references and malformed values are rejected before mutation; restore checks
task dependencies before restoring its task/report/result graph; emptying the
trash permanently removes the trashed graph. This is deterministic test
behavior, not a claim that the mock executes wizard files, validates every
gvmd setting UUID, implements licensing services, or reproduces gvmd ACL and
database behavior.

## python-gvm comparison

Interoperability is pinned to python-gvm 27.8.0 commit
`1bb3782b62532c452af153b54a2b02a3ba62e264`. Its request artifacts were used
as compatibility evidence:

| File | SHA-256 | Difference retained intentionally |
|---|---|---|
| `requests/v224/_auth.py` | `46ad024e2032f96b21e654ae08ee0d09a3a2fe3d005d66020c13f62bcb80314d` | Python requires a nonempty mapping; pinned gvmd accepts an empty group as a no-op. |
| `requests/v224/_user_settings.py` | `324ac364e813dc9651ed92d10919f82f415a423eee92d71cee4bac70de637d3e` | Python exposes only the inline filter for lists; Rust models all controls parsed by gvmd. |
| `requests/v224/_trashcan.py` | `5e35983a2e5cbd9de0d87dfcc6927f0f9bac76a8c5be6448fcab073ca969d14d` | Python names the sole wire operation `restore_from_trashcan`; Rust uses the protocol name `RestoreRequest`. |

The repository's pinned Unix, TLS, and mutual-TLS suites exercise python-gvm
against the Rust mock independently from this API-shape decision. Live-gvmd
end-to-end execution and the separate retained-surface/removal audit are not
part of #664.
