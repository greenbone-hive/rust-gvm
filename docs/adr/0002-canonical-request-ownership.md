# ADR 0002: Canonical request ownership and typed execution precedence

- Status: Accepted
- Date: 2026-09-16
- Issues: [#602](https://github.com/greenbone-hive/rust-gvm/issues/602),
  [#605](https://github.com/greenbone-hive/rust-gvm/issues/605)
- Supersedes: ADR 0001 only for request ownership, typed encoding, error
  precedence, semantic capability metadata, and the pre-release compatibility
  boundary

## Context

ADR 0001 introduced typed execution additively. Semantic request wrappers
implemented the infallible low-level `gvm_protocol::Request` trait and delegated
XML construction to existing free builders and options objects. That let all
resource families migrate without breaking the raw API, but it also left three
parallel public input shapes: required method arguments, an options object, and
a semantic request wrapper.

The additive architecture cannot validate a publicly mutable final request at
execution time without panicking or hiding failure in infallible
`Request::to_bytes()`. It also classifies typed command support only after XML
encoding by recovering the root element. Semantic operations that share a wire
root need a separate capability identity, so encoded XML is not an authoritative
description of the requested operation.

The project is still a Technology Preview. Issue #602 is therefore a
pre-release gate under #523: downstream-ready publication waits for the
canonical request surface so downstream consumers migrate once. ADR 0001
remains the historical record of the additive migration and every decision not
explicitly superseded here.

## Decision

### Separate raw and typed encoding contracts

`gvm_protocol::Request` remains the infallible low-level escape hatch used by
`GmpClient::send` and `GmpClient::call`. Its behavior and forward-compatible
support for raw/custom commands do not change.

Typed execution is owned by `gvm_gmp::GmpRequestCodec` and
`gvm_gmp::GmpRequest`:

- `GmpRequestCodec::validate` checks the final semantic value on every
  execution;
- `GmpRequestCodec::command` exposes the semantic capability identity and wire
  command without rendering XML;
- `GmpRequestCodec::encode` performs fallible, negotiated-version-aware XML
  encoding;
- `GmpRequest` adds the statically associated `GmpResponse` type.

Canonical complete request types implement `GmpRequestCodec` directly and
return semantic command metadata. During bounded migration, the blanket codec
adapter for existing `Request` implementations preserves their bytes and
semantic aliases. An absent command value is reserved for that transitional
adapter and keeps the encoded-root support gate until the owning family is
converted.

### Fix observable execution precedence

`GmpClient::execute` performs these stages in order:

1. validate the final semantic request value;
2. classify version and help-discovery support from semantic request metadata;
3. encode for the negotiated GMP version;
4. redact/trace and transmit bytes;
5. decode the statically associated response and normalize server status.

Validation failure therefore wins over every support or encoding result.
Support failure wins over encoding. Both leave transport history empty.
Encoding failure also occurs before tracing or transport. Once bytes enter the
shared transport path, connection, server-status, and response-parse errors
retain their existing meanings.

Semantic aliases are checked before their shared wire command. The five
`CommandSupport` outcomes from #600 remain authoritative. Unknown command names
stay forward compatible for raw/custom extensions; known version and discovery
failures remain actionable and distinct.

### Use one scalable request-error boundary

Fallible validation and encoding map through `GmpRequestError` and the single
client-level `GvmError::Request` variant. Request failures do not reuse support,
connection, server, or response `ParseError` variants. Resource families must
provide field or combination context without including secret-bearing values
in errors, `Debug`, `Display`, sources, or traces. Command-specific legacy error
variants can be removed only in the later audited family/removal slices.

### Migrate by audited family slices

No resource API is removed by the foundation. Each later family makes one
complete request type own required and optional inputs, final validation,
semantic metadata, encoding, and response association. Public builders and
options survive only when they provide reusable domain structure, validation,
or meaningful construction ergonomics.

The checked [surface disposition ledger](../canonical-request-disposition.md)
classifies every public options type, free builder, request wrapper, and typed
facade method. Its transitional baseline is updated in each family PR and must
contain no transitional rows before release. The existing ticket surface is
frozen and cannot expand through this work.

## Consequences

- A canonical request can be constructed directly, mutated, and still cannot
  bypass final-value validation at execution.
- Typed capability decisions no longer depend on XML rendering or root parsing.
- Request, support, encoding, transport, server, and response-parse failures
  have a deterministic precedence and separate caller handling paths.
- `GmpRequest` no longer implies `gvm_protocol::Request`. Generic code that
  needs raw bytes must depend on the raw trait explicitly or use the typed
  codec.
- Existing semantic request values and direct `execute` call sites remain
  source-compatible through the transitional adapter until their bounded family
  conversion.
- The final public API is intentionally breaking relative to the unreleased
  additive Technology Preview; no compatibility alias is retained solely to
  preserve the temporary shape.

## Rejected alternatives

### Make `Request::to_bytes` fallible

Rejected because it would break the low-level raw/custom contract and force
unrelated protocol and transport users into the typed request error model.

### Encode before capability classification

Rejected because invalid final values could perform unnecessary work, semantic
aliases cannot be derived reliably from a shared XML root, and the observable
error winner would depend on codec details.

### Keep options, builders, requests, and facade arguments permanently

Rejected because parallel input models duplicate ownership and create repeated
validation and migration paths. Retention requires concrete reuse or ergonomic
value.

### Add one client error variant per command

Rejected because hundreds of operation-specific variants do not scale and
would make the top-level error enum mirror the command registry.

### Convert every resource family in one change

Rejected because a repository-wide rewrite would hide protocol drift and make
wire, capability, redaction, and removal decisions unauditable. Targets will be
the reference family before bounded follow-up batches.

### Rewrite ADR 0001

Rejected because ADR 0001 accurately records the additive migration decision.
This ADR supersedes only the boundaries that #602 deliberately changes.
