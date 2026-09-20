# Agent Code Map

This is a fast orientation guide for coding agents. It points to ownership boundaries and common edit paths so each task does not start with a repo-wide rediscovery pass.

## First Files

- `README.md`: public positioning, crate overview, quick-start examples.
- `docs/ROADMAP.md`: support direction, compatibility policy, and issue tracking.
- `docs/STATUS.md`: implementation status, version support snapshot, and coverage notes.
- `docs/gvmd-transport-analysis.md`: gvmd transport model and why GMP is handled as XML over persistent sockets.
- `docs/target-request-gvmd-evidence.md`: pinned public gvmd schema/source evidence for the canonical target reference slice.
- `docs/alternate-target-request-gvmd-evidence.md`: pinned gvmd evidence for canonical OCI-image and web-application target requests.
- `docs/agent-group-request-gvmd-evidence.md`: pinned gvmd evidence for the canonical agent-group lifecycle.
- `docs/agent-request-gvmd-evidence.md`: pinned gvmd evidence for canonical agent operations and support-bundle decoding.
- `docs/integration-config-request-gvmd-evidence.md`: pinned gvmd evidence for canonical integration-configuration queries, replacement validation, and clearing.
- `docs/port-list-request-gvmd-evidence.md`: pinned gvmd evidence for canonical port-list and port-range operations, including the corrected range payload.
- `docs/credential-request-gvmd-evidence.md`: pinned gvmd evidence for canonical credential and credential-store operations, validation, semantic aliases, and the corrected store-detail selector.
- `docs/filter-request-gvmd-evidence.md`: pinned gvmd evidence for canonical filter lifecycle requests, rename/clone overrides, alert expansion, and removal of the unsupported sort-order child.
- `docs/alert-request-gvmd-evidence.md`: pinned gvmd evidence for canonical alert lifecycle requests, clone overrides, modify semantics, trigger aliasing, and secret-bearing nested data.
- `docs/schedule-request-gvmd-evidence.md`: pinned gvmd evidence for canonical schedule lifecycle requests, required iCalendar data, timezone behavior, clone overrides, and modify clearing semantics.
- `docs/scanner-request-gvmd-evidence.md`: pinned gvmd evidence for canonical scanner lifecycle requests, required create fields, relay behavior, clone overrides, and modify clearing semantics.
- `docs/note-override-request-gvmd-evidence.md`: pinned gvmd evidence for canonical note/override lifecycles, required values, restriction replacement, activation, severity, and clone behavior.
- `docs/user-group-request-gvmd-evidence.md`: pinned gvmd evidence for canonical user/group lifecycles, selectors, membership, host access, authentication sources, replacement, clearing, and the unsupported delete-user `ultimate` input.
- `docs/v0.7.0-migration.md#users-and-groups`: user/group release migration, including delete-user selector/inheritor mapping and explicit `ultimate` removal.
- `docs/role-permission-request-gvmd-evidence.md`: pinned gvmd evidence for canonical role/permission lifecycles, partial references, replacement, clearing, and clone semantics.
- `docs/asset-request-gvmd-evidence.md`: pinned gvmd evidence for canonical generic asset/host requests, operating-system asset reads/deletion, and the unsupported OS-modification boundary.
- `docs/result-request-gvmd-evidence.md`: pinned gvmd evidence for canonical
  result list/detail requests, task context, filtering, expansions, counts, and
  the bounded typed response/mock boundary.
- `docs/report-config-request-gvmd-evidence.md`: pinned gvmd evidence for the
  canonical report-configuration lifecycle, ordered parameter updates, query
  controls, trash behavior, parser boundary, and bounded mock approximations.
- `docs/report-format-request-gvmd-evidence.md`: pinned gvmd evidence for the
  canonical report-format lifecycle, opaque import envelope, clone and
  parameter quirks, trash/verification behavior, typed response boundary, and
  bounded mock approximations.
- `docs/tls-certificate-request-gvmd-evidence.md`: pinned gvmd evidence for the
  canonical TLS-certificate lifecycle, original-byte encoding, ownership and
  fingerprint identity, clone/modify/delete semantics, query expansions, and
  bounded registered-fixture mock behavior.
- `docs/nvt-secinfo-request-gvmd-evidence.md`: pinned gvmd evidence for the 19
  canonical NVT/SecInfo requests, dispatch discrepancies, source-shaped
  responses, preference boundaries/redaction, filters, and bounded stateful
  discovery behavior.
- `docs/scan-config-policy-request-gvmd-evidence.md`: pinned/current gvmd
  evidence for generic configuration, scan-configuration, and policy
  lifecycle plus preference reads/mutations, NVT/family replacement,
  confidentiality, atomic rollback, and bounded stateful behavior.
- `docs/task-request-gvmd-evidence.md`: pinned/current gvmd evidence for the
  nine canonical standard-task operations, including clone overrides,
  observer/alert/schedule/preference semantics, removed host ordering,
  transactional mock updates, and report-producing state actions.
- `docs/specialized-task-audit-request-gvmd-evidence.md`: pinned/current gvmd
  evidence for specialized/import task creation, scanner-specific preferences,
  move destinations, audit usage identity, lifecycle actions, and bounded
  transactional mock behavior.
- `docs/report-request-gvmd-evidence.md`: pinned/current gvmd evidence for
  ordinary report import/list/detail/delete, audit list/delete, structured
  scan/audit retrieval, audit host summaries, source defaults, version gates,
  and the #662 export/drill-down boundary.
- `docs/response-models-rfc.md`: response parsing/modeling direction.

## Request Flow

The main client path is:

1. Application code calls `gvm-client`.
2. `gvm-client` negotiates version with `get_version`, checks version gates, and calls typed or raw GMP requests.
3. `gvm-gmp` builds typed GMP XML commands and parses typed response models.
4. `gvm-protocol` serializes commands, parses raw responses, and frames XML messages from byte streams.
5. `gvm-connection` sends and reads bytes over Unix sockets, verified TLS, or SSH tunnels.
6. `gvm-mock-server` can stand in for gvmd in unit/integration tests.

## Crate Ownership

- `crates/gvm-protocol`: XML command builder, raw response parser, `Request` trait, streaming XML completeness detection.
- `crates/gvm-gmp`: canonical typed requests, transitional command builders, protocol enums, reusable domain types, and typed response models.
- `crates/gvm-client`: high-level async API, version negotiation, `GmpVersioned`, version-gated traits, typed convenience methods.
- `crates/gvm-connection`: transport abstraction and concrete Unix/TLS/SSH connections.
- `crates/gvm-mock-server`: programmable mock gvmd with echo, fixture, stateful, scenario, fault, history, and version behavior.

## Common Edit Paths

Adding or changing a GMP command:

- Start in `crates/gvm-gmp/src/commands/<domain>.rs`.
- Add shared enum/type support in `crates/gvm-gmp/src/enums.rs`, `types.rs`, or `common.rs` only when the value is reused.
- Export the module or item through `crates/gvm-gmp/src/commands/mod.rs` or `crates/gvm-gmp/src/lib.rs` when public.
- Add serialization tests in `crates/gvm-gmp/tests/test_<domain>.rs`.
- For a converted family, put all required and optional inputs on one request,
  implement `GmpRequestCodec` directly, and update
  `docs/canonical-request-disposition.tsv`. Standard targets are the reference;
  alternate targets, agent groups, agents, integration configurations, port
  lists, credentials, filters, tags, alerts, schedules, scanners, notes,
  overrides, users, groups, roles, permissions, assets, results, report
  configurations, TLS certificates, and NVT/SecInfo discovery show the same contract across their
  applicable GMP versions.
- If exposed by the high-level client, update the matching private resource-family
  module under `crates/gvm-client/src/typed/`.
- If version-gated, update `crates/gvm-client/src/version.rs` and any typed version traits in `crates/gvm-client/src/lib.rs`.
- If the mock server should understand it, update `crates/gvm-mock-server/src/handler.rs`, `response_gen.rs`, `store.rs`, or `fixtures.rs` as appropriate.
  NVT/SecInfo discovery is isolated in `stateful_nvt_secinfo.rs`, with its
  seed/test state owned by `ResourceStore`.
  Scan-configuration and policy lifecycle, preference, and selection behavior
  is isolated in `stateful_scan_configs.rs`; atomic store application lives in
  `store.rs`.
  Task parsing/rendering lives in `handler.rs`; relationship and candidate-copy
  rollback plus move/start/stop/resume state live in `store.rs`, with bounded
  coverage in `stateful_task_lifecycle.rs`, `stateful_task_graph.rs`, and
  `stateful_specialized_task_audit.rs`.
  Report import/query/delete behavior is isolated in `stateful_reports.rs`;
  atomic report/result/host-asset insertion and deletion dependencies live in
  `store.rs`, with bounded coverage in `stateful_report_lifecycle.rs`,
  `stateful_scan_report.rs`, and `stateful_audit_report.rs`.

Changing response parsing:

- Start in `crates/gvm-gmp/src/responses/<domain>.rs`.
- Use shared helpers from `crates/gvm-gmp/src/responses/common.rs` before adding local XML traversal.
- Re-export response types from `crates/gvm-gmp/src/responses/mod.rs`.
- Add parser fixtures/tests near the domain response tests or in the relevant client integration test.
- Check whether mock responses in `crates/gvm-mock-server/src/response_gen.rs` or `fixtures.rs` need to match real gvmd.

Changing client behavior:

- `crates/gvm-client/src/lib.rs`: `GmpClient`, `GmpVersioned`, version-specific wrapper traits, raw `send`/`call`.
- `crates/gvm-client/src/typed/`: private resource-family modules containing
  inherent typed convenience methods on `GmpClient`.
- `crates/gvm-client/src/typed.rs`: private module root for the typed facade.
- `crates/gvm-client/src/version.rs`: version parsing, mapping, command minimums, command support checks.
- `crates/gvm-client/src/error.rs`: high-level error variants and display behavior.
- Tests live under `crates/gvm-client/tests/`.

Changing transport behavior:

- `crates/gvm-connection/src/connection.rs`: transport trait.
- `crates/gvm-connection/src/unix.rs`: Unix socket transport.
- `crates/gvm-connection/src/ssh.rs`: SSH streamlocal tunnel transport.
- `crates/gvm-connection/src/tls.rs`: verified TLS transport and optional client identity.
- `crates/gvm-connection/src/error.rs`: transport error mapping.
- Tests live under `crates/gvm-connection/tests/`.

Changing mock server behavior:

- `crates/gvm-mock-server/src/handler.rs`: command dispatch and session/auth behavior.
- `crates/gvm-mock-server/src/command_parser.rs`: incoming XML command parsing.
- `crates/gvm-mock-server/src/response_gen.rs`: generated GMP response XML.
- `crates/gvm-mock-server/src/store.rs`: in-memory state and CRUD resources.
- `crates/gvm-mock-server/src/stateful_results.rs`: bounded result-specific
  filtering, pagination/counts, associations, and expansion rendering.
- `crates/gvm-mock-server/src/stateful_report_configs.rs`: bounded
  report-configuration create/clone/modify/query rendering and filtering;
  atomic storage operations remain in `store.rs`.
- `crates/gvm-mock-server/src/stateful_report_formats.rs`: bounded
  report-format import/clone/modify/query/delete/verify behavior; files remain
  inert and signed verification outcomes are injected rather than computed.
- `crates/gvm-mock-server/src/stateful_tls_certificates.rs`: bounded
  registered-fixture TLS creation/clone/modify/query/delete behavior,
  authenticated ownership, fingerprint collisions, expansions, and filters.
- `crates/gvm-mock-server/src/fixtures.rs`: fixture-mode responses.
- `crates/gvm-mock-server/src/fault.rs` and `scenario.rs`: failure injection and scripted playback.
- Tests live under `crates/gvm-mock-server/tests/`.

## Protocol Drift Checklist

When fixing a mismatch with real gvmd, check all of these before calling it done:

- Command XML matches gvmd-supported attributes/elements.
- Response parser accepts the gvmd-supported XML shape.
- Mock server does not simulate behavior gvmd does not have.
- Version gates match the GMP version where the command/field exists.
- Public typed API is not misleading; if compatibility requires keeping an old field, document or deprecate it.
- Tests cover both serialization and parsing when both sides exist.

## Targeted Tests

- Command XML only: `cargo test -p gvm-gmp --test test_<domain>`
- Response model only: `cargo test -p gvm-gmp <response_or_domain_filter>`
- Client typed API: `cargo test -p gvm-client`
- Version gates: `cargo test -p gvm-client version`
- Mock-server command behavior: `cargo test -p gvm-mock-server --test <test_file>`
- Transport behavior: `cargo test -p gvm-connection`
- Python interoperability: `make test-integration`
- Full workspace smoke: `cargo test --workspace`

## Things Not To Rediscover

- GMP is not HTTP. gvmd exposes XML over persistent Unix/TCP/TLS sockets; see `docs/gvmd-transport-analysis.md`.
- `python-gvm` compatibility is useful, but current GMP/GVMD behavior is the source of truth for protocol modeling.
- The mock server is a test tool, not proof that behavior matches gvmd.
- Raw `send`/`call` exists so unsupported or not-yet-modeled GMP details can still be reached without adding premature wrappers.
- `GmpNext` is the forward-compatible bucket for newer supported versions, not a guarantee that every new command is modeled.
