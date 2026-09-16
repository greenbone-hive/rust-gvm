# ADR 0001: Typed request/response execution

- Status: Accepted; superseded in part by
  [ADR 0002](0002-canonical-request-ownership.md) for request ownership, typed
  encoding, execution precedence, semantic capability metadata, and the
  pre-release compatibility boundary
- Date: 2026-08-31
- Tracking issue: [#523](https://github.com/greenbone-hive/rust-gvm/issues/523)

## Context

`rust-gvm` already separates transports, raw XML framing, GMP command builders,
and typed response models. The high-level client previously reconnected a
builder and its parser in command-specific methods, while raw callers could pair
a request with the wrong response parser. Replacing hundreds of builders in one
change would create unnecessary compatibility and review risk.

The first production slice must prove one generic contract across version
negotiation, authentication, target list/get/create/modify/delete, and the
irregular asynchronous scan-report export command. Existing builders, raw
requests, convenience methods, transports, mock behavior, redaction, and error
semantics must remain available.

## Decision

### Ownership

- `gvm-protocol` retains only transport-independent raw `Request`, `Response`,
  XML construction, parsing, and framing.
- `gvm-gmp` owns semantic request structs, typed response models,
  `GmpRequest`, and `GmpResponse` because those contracts name GMP resources and
  commands.
- `gvm-client` owns negotiated-version and help-discovery checks, transport,
  tracing, and `GmpClient::execute` / `GmpVersioned::execute`.

### Request encoding

`GmpRequest` extends the existing `gvm_protocol::Request` contract and has one
associated `GmpResponse`. Semantic request structs implement `Request` by
delegating to the existing command builders. The builders therefore remain the
single wire-encoding implementation and the compatibility oracle during the
incremental migration.

Validation that can fail occurs in semantic request constructors, just as it
does in the existing fallible builders. The representative slice has no
version-dependent request bytes. The client still checks the encoded semantic
command against the negotiated version and help-discovery state before sending.
When a later family needs different bytes for different GMP versions, it must
use distinct semantic request types or introduce a reviewed internal codec
extension; it must not hide version branching in transport code.

### Response decoding and errors

`GmpResponse::decode` receives both the raw `Response` and negotiated
`GmpVersion`. Version-independent models delegate to their existing
`from_response` parser. This leaves room for explicitly version-dependent
response shapes without moving protocol semantics into the client.

`execute` calls `send`, then invokes the associated response decoder. It does
not call `call`, because `send` is the shared raw transport path and response
decoders still own status and payload interpretation. At the client boundary,
`ParseError::ServerError { status, message }` is promoted to
`GvmError::Server { status, message }`. `call`, `execute`, and typed convenience
methods therefore classify an equivalent valid non-success GMP response the
same way. Malformed XML, missing required fields, invalid values, and other
uninterpretable responses remain `GvmError::Parse`, while raw `send` continues
to return non-success responses for caller inspection.

This normalization corrects an inconsistency in the initial typed-execution
implementation. Consumers that matched the earlier nested
`GvmError::Parse(ParseError::ServerError { .. })` representation must match
`GvmError::Server { .. }` instead.

Version negotiation is the bootstrap exception. `GmpClient::connect` sends a
`GetVersionRequest`, but parses and validates the advertised version before a
negotiated `GmpVersion` exists. Later explicit `get_version` calls use
`execute` normally.

### Capability classification

The client uses one `CommandSupport` classification for public support queries
and the pre-send execution gate. It distinguishes supported, discovery-pending,
insufficient-version, negatively discovered, and unknown command names.
Discovery stays explicit. Pending discovery returns
`GvmError::CommandDiscoveryRequired`; a completed XML-help inventory that omits
the command returns `GvmError::CommandNotAdvertised`; version rejection retains
`GvmError::UnsupportedCommand`. `Supported` means only that library version
policy permits the command and any required server advertisement is present;
it does not guarantee authorization or successful execution.

The original `supports_command() -> Option<bool>` method remains as a
deprecated compatibility shim. New callers use `command_support()` so pending
discovery is not confused with an unknown name. Unknown raw command names are
not rejected before transmission, preserving the custom-command escape hatch.
The query migration is source-compatible. The two new execution-error variants
expand the exhaustive `GvmError` enum, so `gvm-client`'s pre-1.0 SemVer policy
requires a minor release and the later #523 release gate must select one before
publication. `cargo-semver-checks` records that explicit Technology Preview
policy; it must be removed when the API stabilizes at 1.0.

### Compatibility and security

- Existing command-builder functions and typed convenience methods remain
  public. Converted convenience methods are thin wrappers over semantic request
  construction and `execute`.
- `send` and `call` remain the raw/custom escape hatch for commands that have
  not migrated or require caller-owned XML.
- `execute` reuses `send`, preserving the shared actionable version/help gate
  and redacted wire tracing before bytes reach observers.
- `AuthenticateRequest` has a custom redacted `Debug` implementation; request
  bytes still pass through the existing structural wire redactor.
- Asynchronous report export uses the same typed contract but retains its
  positive XML-help-discovery requirement.

## Consequences

The compiler now selects the response from the request type, and callers cannot
ask `execute` to decode an unrelated response. New families can migrate without
removing their old builders or changing downstream behavior. There is temporary
duplication between semantic request structs and builder function signatures,
but no duplicated XML encoder.

This ADR does not authorize a repository-wide conversion or removal of old
APIs. Phase 1 stabilizes the public `GmpRequest`, `GmpResponse`, and
`GmpClient::execute` names and the ownership boundaries above. The set of
migrated command families remains intentionally incomplete until later phases.

## Validation

- Compile-fail documentation proves `GetVersionRequest` cannot satisfy a
  request bound associated with `AuthenticateResponse`.
- Exact-byte tests compare every representative semantic request with its
  existing builder, including target validation and asynchronous report export.
- Client integration tests exercise `execute`, compatibility wrappers,
  non-success and malformed responses, every command-support state and
  execution error, the unknown-command escape hatch, and wire redaction.
- Workspace formatting, tests, strict Clippy, documentation, and documented
  SemVer-policy checks remain required before merge.
