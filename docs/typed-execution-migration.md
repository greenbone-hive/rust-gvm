# Typed execution migration notes

The typed request/response API began as the additive execution path from #523.
ADR 0002 makes the canonical-request redesign in #602 a pre-release gate. Each
semantic request still implements `GmpRequest` and selects exactly one
`GmpResponse`, while converted complete request values also own final
validation, semantic capability metadata, and fallible version-aware encoding.
`GmpClient::execute` therefore prevents a caller from pairing a request with an
unrelated parser and rejects invalid final values before support checks or
transport.

This guide is for downstream consumers moving from retained convenience
methods or raw command builders. It complements the contributor-oriented
[typed execution guide](typed-execution.md).

## Choosing an execution API

| API | Use it when | Result and non-success behavior |
| --- | --- | --- |
| `GmpClient::execute(request)` | A semantic request type exists and compile-time response association is desired. | Returns the request's associated response type; valid non-2xx GMP statuses are reported as `GvmError::Server { status, message }`. |
| Typed convenience method | Existing code already uses methods such as `get_targets` or the method is more ergonomic. | Returns the same typed response and, for migrated non-ticket methods, delegates to `execute`; valid non-2xx GMP statuses are reported as `GvmError::Server { status, message }`. |
| `GmpClient::call(builder)` | Raw XML response details are needed. | Returns `gvm_protocol::Response`; non-2xx GMP statuses are reported as `GvmError::Server`. |
| `GmpClient::send(builder)` | The caller must inspect every raw GMP status itself. | Returns `gvm_protocol::Response` for success and non-success statuses. |

During the bounded migration, existing builders, options, and convenience
methods remain available. The first downstream-ready release occurs only after
the disposition audit, so applications adopt the final canonical surface once.
Raw `send`/`call`, transports, framing, response models, and wire formats remain
supported.

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

`call`, `execute`, and typed convenience methods report an equivalent valid
non-2xx GMP response as `GvmError::Server { status, message }`. Malformed XML,
missing required fields, invalid values, and other uninterpretable responses
remain `GvmError::Parse`. This is a compatibility correction from the initial
typed-execution implementation: consumers that matched
`GvmError::Parse(ParseError::ServerError { .. })` must update that match to
`GvmError::Server { .. }`.

## Version and capability checks

`execute` uses the negotiated GMP version and the server help inventory before
sending registered commands. Semantic aliases keep the correct capability
check when an operation reuses another command's XML root, including
specialized tasks and credential-store-backed credential operations. Requests
that require GMP 22.8 are rejected before transport on older servers.

`GmpClient::command_support` and `GmpVersioned::command_support` expose the
same classification used by execution:

| State | Caller action | Execution error |
| --- | --- | --- |
| `CommandSupport::Supported` | Attempt the command. This does not guarantee authorization or success. | Any later transport, server, or decode error. |
| `CommandSupport::RequiresDiscovery` | Call `discover_commands()` and retry the query or operation. | `GvmError::CommandDiscoveryRequired`. |
| `CommandSupport::UnsupportedVersion { required }` | Use a compatible operation or newer server. | `GvmError::UnsupportedCommand`. |
| `CommandSupport::NotAdvertised` | Select an alternative; discovery has already answered negatively. | `GvmError::CommandNotAdvertised`. |
| `CommandSupport::UnknownCommand` | Correct a possible typo or intentionally use the raw/custom escape hatch. | No pre-send rejection for raw custom commands. |

The older `supports_command() -> Option<bool>` query remains as a deprecated
source-compatible shim. It preserves its historical mapping: pending discovery
and unknown names are `None`, while insufficient versions and negatively
discovered commands are `Some(false)`. New code should use `command_support`
so those states are not collapsed.

Adding the two actionable `GvmError` variants expands an exhaustive public
enum. While `gvm-client` remains a pre-1.0 Technology Preview, that change is
classified as requiring the next minor release rather than a 1.0 release; the
crate's `cargo-semver-checks` policy enforces that boundary. The separate #523
release gate must therefore select a newer minor version before publication.

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
- implement `GmpRequestCodec` plus `GmpRequest`, and implement `GmpResponse` for
  the associated response type.

Custom typed decoders must reject non-2xx statuses as
`ParseError::ServerError`; the high-level client normalizes that result to
`GvmError::Server`. They preserve useful field context for malformed responses.
Secret-bearing request diagnostics and observed wire bytes remain
redacted before trace observers run.

## Compatibility boundary

The promoted #523 baseline was additive, but it has not been published as the
downstream-ready typed-execution release. #602 is an explicit Technology
Preview breaking gate: redundant options, builders, and facade signatures may
be removed only after their canonical replacements and migration notes exist.
Raw execution APIs, transports, framing, protocol behavior, and response models
remain supported.

The actionable command-support correction adds error variants and therefore
requires the next pre-1.0 minor release as described above. The legacy
`supports_command` signature remains available during migration.

The facade inventory locks all 255 current public async methods: 251 delegate
directly to `execute`, three frozen ticket helpers keep their explicit raw
compatibility path, and the deprecated `sync_scan_config` alias delegates
indirectly through `sync_config`.

The existing rust-gvm GMP ticket surface is frozen: it remains supported for
compatibility and may receive maintenance, but it is not expanded or migrated
to semantic typed execution. Downstream projects may independently choose not
to expose tickets.

## Release and downstream adoption

The bounded typed-execution change set completed protected-`main` promotion.
A downstream-ready release now waits for the canonical-request family
migrations, final disposition audit, `rust-gvm-api#457` validation, and then a
reviewed workspace-version and lockfile update followed by verified release
artifacts.

Git-based consumers should replace a `branch = "next"` dependency with the
exact released revision after publication and commit the resulting lockfile.
The dependency update is an explicit downstream integration event and should
run that repository's full CI, Security, and end-to-end gates.
