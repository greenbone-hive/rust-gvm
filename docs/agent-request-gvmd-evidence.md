# Agent request gvmd evidence

Issue #613 changes Rust API ownership for agents; it does not change their GMP
wire contract. The contract is anchored in the public gvmd source pinned by
this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in#L9255)
  documents the shared `get_agents` list/detail root and its optional
  `agent_id`, filter, and saved-filter attributes. The same snapshot registers
  delete at line 7345, installer instructions at line 9070, support bundles at
  line 9155, agent-control defaults at line 36622, modification at line 36860,
  and synchronization at line 40420.
- [`gmp_agents.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agents.c#L103)
  parses common get attributes for list and identifier-scoped detail requests.
  The modify handler requires an `<agents>` collection, validates every
  repeated agent identifier, and consumes optional authorization, update,
  comment, and nested configuration fields
  ([line 416](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agents.c#L416)).
- The delete handler likewise requires the repeated agent collection
  ([line 731](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agents.c#L731)),
  while synchronization is an input-free command
  ([line 902](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agents.c#L902)).
- [`gmp_agent_control_scan_agent_config.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_control_scan_agent_config.c#L107)
  requires `agent_control_id`, reads `<config_defaults>`, and applies nested
  agent defaults and the agent-controller update setting.
- [`gmp_agent_installer_instructions.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_installer_instructions.c#L78)
  parses `scanner_id`, `language`, and `origin_url`; the run handler rejects a
  request when any required attribute is absent or the language is unsupported.
- [`gmp_agent_support_bundle.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_support_bundle.c#L64)
  parses required `agent_uuid` and optional nonnegative `days`. Its response
  emits the filename, content type, declared size, and base64-encoded binary
  content
  ([line 288](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp_agent_support_bundle.c#L288)).

This source/schema evidence is intentionally separate from repository-local
mock evidence:

- request-module tests assert independent exact XML for all eight semantic
  operations and verify their metadata and static response types;
- `gvm-client/tests/canonical_request_foundation.rs` proves every operation is
  rejected on GMP 22.7 with empty transport history;
- the stateful versioned-client test exercises agent list, detail, modify,
  delete, synchronization, agent-control defaults, installer instructions, and
  support-bundle download through the request-accepting facade on GMP 22.8;
- response tests retain binary/base64 decoding and declared-size validation for
  support bundles.

The mock is not claimed as real-gvmd interoperability proof. The existing
post-merge Community E2E dispatch remains the deployed runtime check against
gvmd; this pinned evidence is reviewable before that main-branch-only gate.
