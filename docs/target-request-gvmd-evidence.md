# Standard target request gvmd evidence

The canonical target slice in issue #607 changes Rust API ownership, not GMP
semantics. Its wire contract is anchored separately from the mock server in the
public gvmd source pinned by this repository:

- gvmd commit
  [`55e5d4c657c48ce52ee340c2439680418bfe1a4d`](https://github.com/greenbone/gvmd/tree/55e5d4c657c48ce52ee340c2439680418bfe1a4d)
- [`GMP.xml.in`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/schema_formats/XML/GMP.xml.in)
  documents `create_target`, `delete_target`, `get_targets`, and
  `modify_target`; `gmp_schema_snapshot` verifies those roots remain in the
  checked command registry.
- [`gmp.c`](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L1090)
  defines the create inputs represented by `CreateTargetRequest`, including
  host selections, port list/range, credentials, reverse lookup, alive tests,
  and simultaneous-IP behavior.
- The same parser accepts target clone through `<create_target><copy>…</copy>`
  and dispatches it through `copy_target`
  ([handler](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L25181)).
- gvmd rejects simultaneous SMB and Kerberos credentials during create
  ([validation](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L25247));
  the canonical request performs the same value-independent validation before
  capability checks or transport.
- The modify handler forwards the complete replacement/update set—including
  port-list, SSH/elevation, SMB, ESXi, SNMP, Kerberos, reverse lookup, and alive
  tests—to the gvmd management layer
  ([dispatch](https://github.com/greenbone/gvmd/blob/55e5d4c657c48ce52ee340c2439680418bfe1a4d/src/gmp.c#L28302)).

This is source/schema evidence from gvmd itself. It is intentionally distinct
from repository-local mock evidence:

- `gvm-gmp/tests/test_targets.rs` asserts independent exact XML for all six
  semantic operations and verifies the pinned schema qualification.
- `gvm-client/tests/client_integration.rs` exercises target lifecycle,
  relationship mutation, error precedence, and typed response decoding against
  the stateful mock.
- `gvm-client/tests/canonical_request_foundation.rs` proves a mutated invalid
  target value leaves transport history empty.

The mock is not claimed as real-gvmd interoperability proof. The existing
post-merge Community E2E dispatch remains the runtime check against a deployed
gvmd; this source evidence is reviewable before that main-branch-only gate runs.
