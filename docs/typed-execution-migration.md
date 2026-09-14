# Typed execution migration notes

The typed request/response API is an additive execution path for GMP commands.
Each semantic request implements `GmpRequest` and selects exactly one
`GmpResponse` through its associated `Response` type. `GmpClient::execute`
therefore prevents a caller from pairing a request with an unrelated parser.

This guide is for downstream consumers moving from retained convenience
methods or raw command builders. It complements the contributor-oriented
[typed execution guide](typed-execution.md).

## Choosing an execution API

| API | Use it when | Result and non-success behavior |
| --- | --- | --- |
| `GmpClient::execute(request)` | A semantic request type exists and compile-time response association is desired. | Returns the request's associated response type; non-2xx GMP statuses are reported as `GvmError::Parse(ParseError::ServerError { .. })`. |
| Typed convenience method | Existing code already uses methods such as `get_targets` or the method is more ergonomic. | Returns the same typed response and, for migrated non-ticket methods, delegates to `execute`. |
| `GmpClient::call(builder)` | Raw XML response details are needed. | Returns `gvm_protocol::Response`; non-2xx GMP statuses are reported as `GvmError::Server`. |
| `GmpClient::send(builder)` | The caller must inspect every raw GMP status itself. | Returns `gvm_protocol::Response` for success and non-success statuses. |

No application must migrate merely to consume the release. Existing builders,
`send`, `call`, typed convenience methods, transports, framing, response
models, and wire formats remain supported.

## Moving from a convenience method

Existing code remains valid:

```rust
let targets = client.get_targets(Default::default()).await?;
```

Use the semantic request directly when generic code or compile-time request and
response association is useful:

```rust
use gvm_gmp::commands::targets::{GetTargetsOpts, GetTargetsRequest};

let targets = client
    .execute(GetTargetsRequest::new(GetTargetsOpts::default()))
    .await?;
```

Both forms use the same established builder and response decoder. Migrating
one family does not require migrating another.

## Moving from a raw builder

Raw execution remains available:

```rust
use gvm_gmp::commands::targets;

let raw = client
    .call(targets::get_targets(Default::default()))
    .await?;
```

Replacing it with a semantic request removes the manual parser choice:

```rust
use gvm_gmp::commands::targets::{GetTargetsOpts, GetTargetsRequest};

let targets = client
    .execute(GetTargetsRequest::new(GetTargetsOpts::default()))
    .await?;
```

Review error matching during this change. `call` reports a non-2xx GMP status
as `GvmError::Server`; typed response decoders preserve the existing typed
facade contract and report it as
`GvmError::Parse(ParseError::ServerError { .. })`.

## Version and capability checks

`execute` uses the negotiated GMP version and the server help inventory before
sending registered commands. Semantic aliases keep the correct capability
check when an operation reuses another command's XML root, including
specialized tasks and credential-store-backed credential operations. Requests
that require GMP 22.8 are rejected before transport on older servers.

The same protection applies when a known specialized shape is passed through
the retained raw builders. Unknown custom command names remain possible
through `send` and `call`.

## Irregular responses and custom commands

Typed execution does not require every response to fit one Serde-derived XML
shape. Report exports, binary or base64 payloads, mixed/repeated elements, and
other irregular responses use explicit codecs while retaining the same
`GmpRequest`/`GmpResponse` association.

For commands outside the modeled surface, either:

- implement `gvm_protocol::Request` and use `send` or `call`; or
- implement `Request` plus `GmpRequest`, and implement `GmpResponse` for the
  associated response type.

Custom typed decoders must reject non-2xx statuses as
`ParseError::ServerError` and preserve useful field context for malformed
responses. Secret-bearing request diagnostics and observed wire bytes remain
redacted before trace observers run.

## Compatibility boundary

The release is additive. It does not remove or rename the established command
builders, raw execution APIs, typed convenience methods, transports, or
response models. The facade's private resource-family modules are an internal
maintenance boundary and do not create new public module paths.

The facade inventory locks all 255 current public async methods: 251 delegate
directly to `execute`, three frozen ticket helpers keep their explicit raw
compatibility path, and the deprecated `sync_scan_config` alias delegates
indirectly through `sync_config`.

The existing rust-gvm GMP ticket surface is frozen: it remains supported for
compatibility and may receive maintenance, but it is not expanded or migrated
to semantic typed execution. Downstream projects may independently choose not
to expose tickets.

## Release and downstream adoption

The bounded typed-execution change set and these migration notes have completed
their protected `next` review and protected-`main` promotion. A
downstream-ready release still requires a separate reviewed workspace-version
and lockfile update, followed by an orchestrated release whose tag and artifacts
are verified.

Git-based consumers should replace a `branch = "next"` dependency with the
exact released revision after publication and commit the resulting lockfile.
The dependency update is an explicit downstream integration event and should
run that repository's full CI, Security, and end-to-end gates.
