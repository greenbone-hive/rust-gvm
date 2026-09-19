# Typed Client Facade Coverage

The public typed facade is the set of inherent `GmpClient` methods implemented
in the private resource-family modules under `crates/gvm-client/src/typed/`.
Issue #398 called this surface
`GmpClientExt`; the project keeps the existing inherent-method API rather than
introducing a compatibility-only extension trait.

Every current method is classified as **integration covered** in
`crates/gvm-client/tests/typed_facade_inventory.rs`. That inventory also has
explicit (currently empty) **compile only** and **requires integration**
classes. Its test discovers every Rust source in the private facade module
directory, extracts every `pub async fn`, rejects duplicate and unknown entries,
and fails when a new helper is not classified.
It additionally requires every integration-covered name to appear as a direct
method call in the client/mock integration suite.
The enforced surface currently contains 259 names: 256 direct `execute`
delegates and three frozen ticket raw paths. Unsupported configuration sync and
operating-system asset modification helpers are not part of the inventory.

Coverage is organized by behavior family:

- discovery/list and administration helpers use table-driven fixture
  responses and assert typed results plus command history;
- system authentication, license, and wizard helpers execute through their
  semantic requests, while the complete nine-request administration and
  user-setting inventory is exercised over a live Unix transport;
- create helpers use a shared response table and assert typed create IDs;
- report export exercises both the simple and options XML shapes;
- generic assets, host and operating-system aliases, and result queries assert
  every typed facade shape plus their shared wire-command inventory;
- generic configuration, scan-config/policy lifecycle, and port-list coverage
  exercises the complete request-by-value facades and shared wire roots;
- report configuration, report format, and TLS-certificate coverage exercises
  their complete canonical requests through fixed response associations;
- report import exercises the semantic create response plus malformed-response
  context, while direct execution covers create and both deletion intents;
- server-status and malformed-payload cases assert typed error mapping;
- the 22.6 registry gate, 22.8 registry gate, and 22.8 semantic-command gates
  are exercised through typed methods.
- credential and credential-store helpers accept complete canonical requests;
  standard and store-backed lifecycles, GMP 22.8 rejection, response parsing,
  and secret-safe tracing are integration covered.

The response-model expansion tracked by
[#371](https://github.com/greenbone-hive/rust-gvm/issues/371),
[#372](https://github.com/greenbone-hive/rust-gvm/issues/372),
[#373](https://github.com/greenbone-hive/rust-gvm/issues/373), and
[#374](https://github.com/greenbone-hive/rust-gvm/issues/374) is not duplicated
here. This inventory covers the public typed methods that exist now; those
issues remain the authority for any further model/API acceptance work.
