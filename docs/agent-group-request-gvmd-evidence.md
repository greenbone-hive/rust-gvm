# Agent-group request gvmd evidence

Issue #611 changes Rust API ownership for agent groups; it does not change
their GMP wire contract. The contract is anchored in the public gvmd source
pinned by this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L3736)
  documents `create_agent_group`; the same snapshot contains the delete,
  list/detail, and modify roots at lines 7290, 8897, and 36774.
  `gmp_schema_snapshot` verifies all four wire roots remain in the checked
  command registry.
- [`gmp_agent_groups.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_groups.c#L54)
  parses the common get attributes used for both list and identifier-scoped
  detail requests and emits the agent-group response collection.
- The create handler treats `<copy>` as clone input
  ([line 307](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_groups.c#L307));
  otherwise it consumes nonempty `name` and `scheduler_cron_time`, optional
  `comment`, and repeated `<agents><agent id="…"/></agents>` values
  ([line 355](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_groups.c#L355)).
- The modify handler consumes the `agent_group_id` attribute, name, scheduler,
  comment, and repeated agent identifiers
  ([line 657](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_groups.c#L657)).
- Issue #812 additionally traced omission and empty-list behavior through both
  the pinned revision and the then-current upstream `main`
  [`c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935`](https://github.com/greenbone/gvmd/tree/c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935)
  (checked 2026-11-08). The modify parser
  passes the number of `<agent>` children to `agent_uuid_list_new`
  ([pinned parser](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_groups.c#L724-L731),
  [current parser](https://github.com/greenbone/gvmd/blob/c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935/src/gmp_agent_groups.c#L768-L799)).
  The pinned/current constructor returns `NULL` for a zero count
  ([pinned constructor](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_agent_common.c#L31-L42),
  [current constructor](https://github.com/greenbone/gvmd/blob/c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935/src/manage_agent_common.c#L31-L42)),
  making `<agents/>` indistinguishable from omission. The SQL modify function
  then commits and returns before deleting relationships when the list is null
  or empty
  ([pinned persistence](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/manage_sql_agent_groups.c#L345-L364),
  [current persistence](https://github.com/greenbone/gvmd/blob/c11dc2e5adcfe97bb158ff73c51bd5dc5fee2935/src/manage_sql_agent_groups.c#L345-L376)).
  Therefore no real membership-clear wire form exists: omission preserves,
  non-empty `<agents>` replaces, and a Rust `Clear` request must fail locally
  rather than emit the successful server no-op `<agents/>`.
- [Upstream gvmd issue #3230](https://github.com/greenbone/gvmd/issues/3230)
  must preserve empty-element presence separately from omission,
  then treat `NULL` as preserve and a present zero-count list as deleting all
  `agent_group_agents` rows without entering the COPY path. Its controller
  synchronization/rollback flow must continue to update the union of old and
  replacement agents so removed agents lose stale cron configuration.
- The central parser routes `delete_agent_group` through gvmd's common
  deletion path
  ([line 5208](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L5208)).

This source/schema evidence is intentionally separate from repository-local
mock evidence:

- request-module tests assert independent exact XML for all six semantic
  operations and verify their metadata and static response types; the external
  `agent_groups_test` sidecar separately covers preserve and replacement XML
  plus rejection of unsupported clear intent;
- `gvm-client/tests/canonical_request_foundation.rs` proves every operation is
  rejected on GMP 22.7 with empty transport history;
- the stateful versioned-client test exercises create, clone, list, detail,
  modify, and delete through the request-accepting typed facade on GMP 22.8;
- mock-server version-gating tests separately verify 22.7 rejection and 22.8
  acceptance of the encoded wire commands.

The mock is not claimed as real-gvmd interoperability proof. The existing
post-merge Community E2E dispatch remains the deployed runtime check against
gvmd; this pinned evidence is reviewable before that main-branch-only gate.
