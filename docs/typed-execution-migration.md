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

During the bounded migration, unconverted builders and options remain
available. Converted families remove redundant surfaces after their canonical
replacement and migration notes exist. The first downstream-ready release occurs only after
the disposition audit, so applications adopt the final canonical surface once.
Raw `send`/`call`, transports, framing, response models, and wire formats remain
supported.

## Moving from a convenience method

The standard target convenience accepts its complete canonical request:

```rust
use gvm_gmp::commands::targets::GetTargetsRequest;

let targets = client.get_targets(GetTargetsRequest::default()).await?;
```

Use the semantic request directly when generic code or compile-time request and
response association is useful:

```rust
use gvm_gmp::commands::targets::GetTargetsRequest;

let targets = client
    .execute(GetTargetsRequest::default())
    .await?;
```

Both forms execute the same request value and response decoder. Migrating one
family does not require migrating another.

## Standard target family

The target reference slice removes `CreateTargetOpts`, `GetTargetsOpts`, and
`ModifyTargetOpts`, together with the six standard-target free builders. Move
all inputs onto the corresponding complete request. Required create inputs use
the constructor; optional inputs remain directly editable:

```rust
use gvm_gmp::commands::targets::CreateTargetRequest;
use gvm_gmp::{AliveTest, TargetHost, TargetHosts, TargetPortSelection};

let hosts = TargetHosts::new(["192.0.2.1".parse::<TargetHost>()?], [])?;
let ports = TargetPortSelection::PortRange("T:22, T:80-443".parse()?);
let mut request = CreateTargetRequest::new("production", hosts, ports);
request.comment = Some("primary scanner target".into());
request.alive_test = Some(AliveTest::IcmpAndArpPing);

let target = client.execute(request).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Modify inputs begin with the required target ID. `ScalarUpdate<T>` continues to
distinguish omission, replacement, and supported detach/reset operations:

```rust
use gvm_gmp::commands::targets::ModifyTargetRequest;
use gvm_gmp::ScalarUpdate;

let mut request = ModifyTargetRequest::new(target.id.clone());
request.name = Some("renamed".into());
request.ssh_credential_id = ScalarUpdate::Clear;
client.modify_target(request).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Construction does not freeze the value. `execute` validates the final request,
so an invalid combination introduced by later mutation is still returned as
`GvmError::Request` before capability checks or transport.

## OCI-image and web-application target families

The alternate-target slice removes the six `*Opts` types and all twelve free
builders. It also replaces the raw-response client signatures and `_parsed`
aliases with one discoverable convenience per operation. Each convenience
accepts the same request value as `execute` and returns its statically
associated response.

Required create inputs use constructors; optional inputs are fields on the
same request:

```rust
use gvm_gmp::commands::oci_image_targets::CreateOciImageTargetRequest;

let mut request = CreateOciImageTargetRequest::new(
    "registry target",
    vec!["registry.example/app:stable".into()],
);
request.comment = Some("production image".into());
request.credential_id = Some(credential_id);

let created = client.create_oci_image_target(request).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

All-optional list requests implement `Default`. Detail and clone requests keep
distinct semantic intent even though their XML roots are shared with list and
create respectively:

```rust
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, GetWebApplicationTargetsRequest,
};

let targets = client
    .get_web_application_targets(GetWebApplicationTargetsRequest::default())
    .await?;
let clone = client
    .clone_web_application_target(CloneWebApplicationTargetRequest::new(target_id))
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

These operations require GMP 22.8. The client applies that gate from semantic
metadata before encoding or transport, including detail and clone aliases.

## Agent-group family

The agent-group slice removes `CreateAgentGroupOpts`, `GetAgentGroupsOpts`,
`ModifyAgentGroupOpts`, and all six free builders. Required create fields use
the constructor; optional and mutable fields live on the same request value:

```rust
use gvm_gmp::commands::agent_groups::{
    CreateAgentGroupRequest, ModifyAgentGroupRequest,
};

let mut create = CreateAgentGroupRequest::new(
    "scheduled agents",
    vec![agent_id],
    "0 */5 * * *",
);
create.comment = Some("production agents".into());
let created = client.create_agent_group(create).await?;

let mut modify =
    ModifyAgentGroupRequest::new(created.id, "0 */10 * * *");
modify.name = Some("renamed agents".into());
modify.agent_ids = vec![replacement_agent_id];
client.modify_agent_group(modify).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

List requests implement `Default`; detail, clone, and delete requests use
their resource identifier constructors. The six named client conveniences
accept those canonical request values unchanged and return their associated
typed responses. Every operation remains gated to GMP 22.8 before encoding or
transport, including clone and detail semantic aliases over the create and
list wire roots. Specialized `create_agent_group_task` remains in the task
family and is not changed by this migration.

## Agent family

The agent slice removes `GetAgentsOpts`, `ModifyAgentOpts`,
`ModifyAgentControlScanConfigOpts`, and all eight free builders. List requests
implement `Default`; detail, delete, installer-instruction, support-bundle, and
agent-control-default requests use constructors for their required values.
Agent updates start with the selected identifiers, with optional mutation
fields on the same request:

```rust
use gvm_gmp::commands::agents::{
    GetAgentSupportBundleRequest, ModifyAgentRequest,
};

let mut modify = ModifyAgentRequest::new(vec![agent_id.clone()]);
modify.authorized = Some(true);
modify.update_to_latest = Some(true);
modify.comment = Some("production agent".into());
client.modify_agent(modify).await?;

let bundle = client
    .get_agent_support_bundle(GetAgentSupportBundleRequest::new(
        agent_id,
        Some(7),
    ))
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`AgentConfigOpts` is intentionally retained as reusable nested configuration
for both agent updates and agent-control defaults. `SyncAgentsRequest` is an
input-free request value. The eight named client conveniences accept the
canonical requests unchanged and preserve the installer-instruction and
binary support-bundle response types. Every operation remains gated to GMP
22.8 before encoding or transport; detail remains a semantic alias over the
`get_agents` wire root.

## Integration-configuration family

The integration-configuration slice removes `GetIntegrationConfigsOpts`,
`ModifyIntegrationConfigOpts`, all three free builders, the three raw duplicate
client signatures, and the `_parsed` aliases. The list request owns its filter
fields; the detail request owns its identifier and detail flag while preserving
the `get_integration_configs` wire root:

```rust
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, ModifyIntegrationConfigRequest,
};

let current = client
    .get_integration_config(GetIntegrationConfigRequest::new(
        integration_config_id.clone(),
        Some(true),
    ))
    .await?;

let mut replacement =
    ModifyIntegrationConfigRequest::new(integration_config_id.clone());
replacement.service_url = Some("https://service.example".into());
replacement.oidc_provider_url = Some("https://oidc.example".into());
replacement.oidc_provider_client_id = Some("client-id".into());
replacement.oidc_provider_client_secret = Some("client-secret".into());
client.modify_integration_config(replacement).await?;

client
    .modify_integration_config(ModifyIntegrationConfigRequest::new(
        integration_config_id,
    ))
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The final call is the explicit clear operation: every configurable field is
unset. If any field is set, the service URL, OIDC provider URL, client ID, and
client secret must all be present and non-empty. Partial replacements return a
value-free `GmpRequestError` before capability checks or transmission. The
service CA certificate remains optional; it and the client secret are redacted
from request diagnostics and wire tracing. All three named client methods
accept the canonical requests unchanged and require GMP 22.8.

## Port-list family

The port-list slice removes `PortListOpts`, `ModifyPortListOpts`,
`GetPortListsOpts`, and all eight free builders. List requests implement
`Default`; detail, clone, and delete requests own their identifiers. Create and
modify inputs live directly on the request value:

```rust
use gvm_gmp::commands::port_lists::{
    CreatePortListRequest, ModifyPortListRequest,
};

let mut create = CreatePortListRequest::new("web services");
create.comment = Some("production ports".into());
create.port_range = Some("T:80,443".into());
let created = client.create_port_list(create).await?;

let mut replace = ModifyPortListRequest::new(created.id);
replace.name = Some("public web services".into());
client.modify_port_list(replace).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Modification remains a full replacement: omitting name or comment clears that
field in gvmd. Port ranges are changed separately. Their canonical create
request owns the optional comment and uses gvmd's documented child-element
payload:

```rust
use gvm_gmp::commands::port_lists::CreatePortRangeRequest;
use gvm_gmp::PortRangeType;

let mut range = CreatePortRangeRequest::new(
    port_list_id,
    PortRangeType::Tcp,
    80,
    443,
);
range.comment = Some("web ports".into());
client.create_port_range(range).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Ports must be in the inclusive range 1–65535, and `start` must not exceed
`end`. Invalid final values return `GvmError::Request` before capability checks
or transport. All eight operations are baseline GMP 22.4 commands. The named
client methods accept canonical requests unchanged; raw `send`/`call` remains
the low-level escape hatch.

## Credential and credential-store family

The credential slice removes `CredentialOpts`, `ModifyCredentialOpts`,
`GetCredentialsOpts`, `GetCredentialStoresOpts`,
`CredentialStoreCredentialOpts`, `ModifyCredentialStoreOpts`, and
`ModifyCredentialStoreCredentialOpts`, together with all thirteen free
builders. Inputs now live directly on twelve canonical request types. Required
create values use constructors; optional values remain editable and are
revalidated immediately before support classification and transport:

```rust
use gvm_gmp::commands::credentials::{
    CreateCredentialRequest, CreateCredentialStoreCredentialRequest,
};
use gvm_gmp::{CredentialStoreCredentialType, CredentialType};

let mut standard = CreateCredentialRequest::new("scanner login");
standard.credential_type = Some(CredentialType::UsernamePassword);
standard.login = Some("scanner".into());
standard.password = Some(password);
let created = client.create_credential(standard).await?;

let mut stored = CreateCredentialStoreCredentialRequest::new(
    "vault login",
    CredentialStoreCredentialType::UsernamePassword,
    "vault-entry-1",
    "host-1",
);
stored.credential_store_id = Some(store_id);
client.create_credential_store_credential(stored).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Credential-store list/detail, verification, modification, and store-backed
credential operations require GMP 22.8. Store-backed create and modify retain
their semantic aliases even though their XML roots are `create_credential` and
`modify_credential`. The single-store selector is now the schema-defined
`credential_store_id` root attribute; callers relying on the legacy Rust child
shape should move to `GetCredentialStoreRequest`.

Create validation follows gvmd's selected credential type requirements. An
explicit username/password credential may omit its password for gvmd
autogeneration, while its login remains required; password-only credentials
may also autogenerate their secret. Store-backed Kerberos creation requires a
KDC and realm. Store-backed SNMP creation requires `auth_algorithm`; its
optional privacy host identifier requires a privacy algorithm. Modify requests
validate only caller-known final values because gvmd applies type-specific
modify rules using the stored resource type. The store-backed input enum omits
`cs_cc`, which pinned gvmd rejects; client certificates remain available as
standard `cc` credentials. Request diagnostics and wire traces redact passwords,
private/public keys, key phrases, certificates, SNMP community and privacy
values, vault/host identifiers, and credential-store preference values.

## Filter family

The filter slice removes `FilterOpts`, `GetFiltersOpts`, and all six free
builders. List, detail, create, clone, modify, and delete inputs now live on
complete canonical request values, and the six named client methods accept
those values unchanged:

```rust
use gvm_gmp::commands::filters::{CreateFilterRequest, GetFiltersRequest};
use gvm_gmp::FilterType;

let mut create = CreateFilterRequest::new("recent tasks");
create.term = Some("rows=10 sort-reverse=modified".into());
create.filter_type = Some(FilterType::Task);
let created = client.create_filter(create).await?;

let filters = client
    .get_filters(GetFiltersRequest {
        details: Some(true),
        alerts: Some(true),
        ..Default::default()
    })
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Create requests validate their required final name before support checks or
transport. Clone and modify requests likewise reject an explicitly empty name,
including after public-field mutation. `GetFilterRequest` and
`CloneFilterRequest` retain distinct semantic identities over the shared
`get_filters` and `create_filter` XML roots.

Pinned gvmd source corrects three transitional-model gaps. Filter sorting is
part of the filter term (`sort=` or `sort-reverse=`), so the unsupported
create/modify `sort_order` child is removed. Modify now represents gvmd's
supported rename element; clone represents optional name/comment overrides;
and list/detail requests expose the supported `alerts` expansion selector.
Empty comment and term elements remain representable for modification so
callers can clear those text values.

## Alert family

The alert slice removes `AlertOpts`, `GetAlertsOpts`, `TriggerAlertOpts`, and
all eight free builders. List, detail, create, clone, modify, delete, test, and
trigger inputs now live on complete canonical request values, and the eight
named client methods accept those values unchanged:

```rust
use gvm_gmp::commands::alerts::{AlertData, CreateAlertRequest};
use gvm_gmp::{AlertCondition, AlertEvent, AlertMethod};

let mut create = CreateAlertRequest::new(
    "completed scan",
    AlertEvent::TaskRunStatusChanged,
    AlertCondition::Always,
    AlertMethod::Email,
);
create.event_data.push(AlertData::new("status", "Done"));
create
    .method_data
    .push(AlertData::new("to_address", "ops@example.com"));
let created = client.create_alert(create).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Create owns gvmd's required event, condition, and method values and validates
the final name. Clone accepts the server-supported name/comment overrides.
Modify preserves omitted active state but follows gvmd's filter replacement
behavior: omitting `filter_id` clears the current binding. Detail, clone, and
trigger preserve distinct semantic identities over shared XML roots. Trigger
continues to decode `GetReportsResponse`. Alert data values are redacted from
request diagnostics and wire traces.

## Scanner family

The scanner slice removes `ScannerOpts`, `GetScannersOpts`, and all seven free
builders. List, detail, create, clone, modify, delete, and verify inputs now
live on complete canonical request values, and the seven named client methods
accept those values unchanged:

```rust
use gvm_gmp::commands::scanners::{
    CreateScannerRequest, ModifyScannerRequest,
};
use gvm_gmp::{ScalarUpdate, ScannerType};

let mut create = CreateScannerRequest::new(
    "remote",
    "scanner.example",
    9390,
    ScannerType::OpenVasScanner,
);
create.relay_host = Some("relay.example".into());
create.relay_port = Some(9391);
let created = client.create_scanner(create).await?;

let mut modify = ModifyScannerRequest::new(created.id);
modify.ca_pub = Some(String::new());
modify.credential_id = ScalarUpdate::Clear;
modify.relay_host = Some(String::new());
client.modify_scanner(modify).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Creation requires a non-empty name and host, a non-zero port, and a scanner
type. The primary host cannot be a Unix socket over GMP. Network relays require
a non-zero relay port, while Unix-socket relays omit it. On modify, omission
preserves existing fields; empty comment, CA, and relay elements clear them,
and `ScalarUpdate::Clear` detaches the credential.

## Schedule family

The schedule slice removes `ScheduleOpts`, `GetSchedulesOpts`, all eight free
builders, and the duplicate typed create/modify request wrappers. List, detail,
create, clone, modify, and delete inputs now live on six complete canonical
request values, and the six named client methods accept those values unchanged:

```rust
use gvm_gmp::commands::schedules::{
    CreateScheduleRequest, ModifyScheduleRequest,
};
use gvm_gmp::{
    ScheduleDefinition, ScheduleInput, ScheduleRecurrence, ScheduleTimestamp,
    ScheduleTimezone,
};

let input = ScheduleInput::new(
    ScheduleDefinition {
        first_run: ScheduleTimestamp::parse("2030-01-01T00:00:00Z")?,
        recurrence: ScheduleRecurrence::Daily,
    },
    ScheduleTimezone::new("UTC")?,
);
let created = client
    .create_schedule(CreateScheduleRequest::from_input("daily", input))
    .await?;

let raw = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR";
client
    .modify_schedule(ModifyScheduleRequest::new(created.id, raw))
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`ScheduleInput` remains the reusable validated recurrence model. Its conversion
and raw iCalendar construction now converge on the same request types. Pinned
gvmd requires non-empty iCalendar data for both create and modify, even though
the schema renders the modify child as optional; canonical validation follows
the handler and fails before support checks or transport. Clone retains its
distinct semantic identity and supports gvmd's name/comment overrides.

## Tag family

The tag slice removes `TagOpts`, `GetTagsOpts`, and all six free builders.
List, detail, create, clone, modify, and delete inputs now live on complete
canonical request values, and the six named client methods accept those values
unchanged:

```rust
use gvm_gmp::commands::tags::{
    CreateTagRequest, ModifyTagRequest, TagResourceAction, TagResourceUpdate,
    TagResources,
};
use gvm_gmp::EntityType;

let mut resources = TagResources::new(EntityType::Task);
resources.filter = Some("status=Running".into());
let mut create = CreateTagRequest::new("running tasks", resources);
create.value = Some("triage".into());
let created = client.create_tag(create).await?;

let mut replacement = TagResources::new(EntityType::Policy);
replacement.filter = Some("name=baseline".into());
let mut modify = ModifyTagRequest::new(created.id);
modify.resource_update = Some(TagResourceUpdate {
    resources: replacement,
    action: Some(TagResourceAction::Set),
});
modify.comment = Some(String::new());
client.modify_tag(modify).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Create requests validate their required final name and resource type before
support checks or transport. Clone and modify reject an explicitly empty name,
and tag-on-tag resource selections are invalid. `GetTagRequest` and
`CloneTagRequest` retain distinct semantic identities over the shared
`get_tags` and `create_tag` XML roots.

Pinned gvmd source corrects the transitional model: resources support multiple
IDs and a filter, modify supports add/set/remove actions and rename, list
supports `names_only`, and clone supports optional name/comment overrides.
Policy resources keep the historical `config` wire mapping. Explicit empty
modify comment/value strings remain representable for clearing. The old tag
`severity` option is removed because gvmd does not define or parse it.

## Moving from a raw builder

Raw execution remains available:

```rust
let raw = client.call(b"<get_targets/>".as_slice()).await?;
```

Replacing it with a semantic request removes the manual parser choice:

```rust
use gvm_gmp::commands::targets::GetTargetsRequest;

let targets = client
    .execute(GetTargetsRequest::default())
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

The facade inventory locks all 267 current public async methods: 263 delegate
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
