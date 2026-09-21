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

## Standard task family

The nine standard scan-task operations now use complete canonical request
values. Their named client methods accept the same values unchanged and call
`execute` only:

```rust
use gvm_gmp::commands::tasks::{
    CreateTaskRequest, ModifyTaskRequest, StartTaskRequest, TaskPreference,
};
use gvm_gmp::{CollectionUpdate, ScalarUpdate};

let mut create = CreateTaskRequest::new(
    "nightly scan", config_id, target_id, scanner_id,
);
create.schedule_id = Some(schedule_id);
create.schedule_periods = Some(5);
create.observers = vec!["alice".into()];
create.preferences.push(TaskPreference::new("auto_delete", "keep"));
let task = client.create_task(create).await?;

let mut modify = ModifyTaskRequest::new(task.id.clone());
modify.schedule_id = ScalarUpdate::Clear;
modify.alert_ids = CollectionUpdate::Clear;
modify.observers = CollectionUpdate::Clear;
client.modify_task(modify).await?;
client.start_task(StartTaskRequest::new(task.id)).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`GetTasksOpts`, `CreateTaskOpts`, and `ModifyTaskOpts` are removed. The nine
free standard-task builders are also removed.

Schedule uses `ScalarUpdate` to distinguish preserve, replace, and detach;
alerts and observers use `CollectionUpdate`. A group update must include an
explicit user replacement or clear because both share gvmd's `<observers>`
container. Target/config/scanner relationships are replace-or-preserve.
Clone exposes comment and alterable overrides but no unsupported name
override. The stale `hosts_ordering` request input is removed because pinned
gvmd does not parse it and dropped its database column. Preference values are
redacted from diagnostics and traces. See the
[pinned gvmd evidence](task-request-gvmd-evidence.md).

## Specialized tasks and audits

Issue #660 completes the remaining task-family request migration. Import and
container/import creation own only name and comment. Agent-group creation owns
its group and optional matching scanner. OCI/container-image and
web-application creation own the specialized target, required scanner, and
their supported common creation values. All three true specialized scan
variants retain their GMP 22.8 semantic gates.

```rust
use gvm_gmp::commands::tasks::{
    CreateAgentGroupTaskRequest, CreateAuditRequest,
    CreateWebApplicationTaskRequest, ModifyAuditRequest, MoveTaskRequest,
    TaskMoveDestination,
};
use gvm_gmp::CollectionUpdate;

let agent = CreateAgentGroupTaskRequest::new("agents", agent_group_id);
client.create_agent_group_task(agent).await?;

let web = CreateWebApplicationTaskRequest::new(
    "web", web_target_id, web_scanner_id,
);
client.create_web_application_task(web).await?;

client.move_task(MoveTaskRequest::new(
    task_id,
    TaskMoveDestination::Master,
)).await?;

let audit = client.create_audit(CreateAuditRequest::new(
    "audit", policy_id, target_id, scanner_id,
)).await?;
let mut modify = ModifyAuditRequest::new(audit.id);
modify.observers = CollectionUpdate::Clear;
modify.observer_group_ids = CollectionUpdate::Clear;
client.modify_audit(modify).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`move_task` now requires `TaskMoveDestination::Master` or `Slave(id)`; omission
is not a valid gvmd request. Audit list/detail/create carry audit usage
identity, while clone inherits it and ID-selected mutation/action requests do
not invent a parser-unsupported usage child. Audit delete now owns its
`ultimate` decision. Specialized preference validation follows scanner type,
and preference values remain redacted from diagnostics and traces. See the
[pinned gvmd evidence](specialized-task-audit-request-gvmd-evidence.md).

## Report and audit-report lifecycle

Issue #661 replaces the report lifecycle and structured-report forwarding
surfaces with complete request values. Each named typed helper accepts the
canonical request unchanged and delegates to `execute`.

```rust
use gvm_gmp::commands::reports::{
    DeleteReportRequest, GetAuditReportHostsRequest, GetAuditReportsRequest,
    GetReportRequest, GetReportsRequest, GetScanReportRequest,
    ImportReportRequest,
};

let reports = client.get_reports(GetReportsRequest::default()).await?;

let mut detail = GetReportRequest::new(report_id.clone());
detail.filter_string = Some("rows=25 first=1".into());
let report = client.get_report(detail).await?;

let mut import = ImportReportRequest::new(import_task_id, report_xml);
import.in_assets = Some(true);
let created = client.import_report(import).await?;

client
    .delete_report(DeleteReportRequest::new(created.id.clone()))
    .await?;

let audits = client
    .get_audit_reports(GetAuditReportsRequest::default())
    .await?;
let hosts = client
    .get_audit_report_hosts(GetAuditReportHostsRequest::new(audit_report_id))
    .await?;
let scan = client
    .get_scan_report(GetScanReportRequest::new(report_id))
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Migration mapping:

- `get_reports(opts)` becomes `get_reports(GetReportsRequest { ... })`;
- `get_report(&id)` becomes `get_report(GetReportRequest::new(id))`;
- the empty `create_report` form and `CreateReportRequest` are removed because
  pinned gvmd only creates reports from an imported `<report>` envelope;
- `import_report(xml, &task, opts)` becomes
  `import_report(ImportReportRequest::new(task_id, xml))`;
- `delete_report(&id, ultimate)` becomes
  `delete_report(DeleteReportRequest::new(id))`; gvmd has no permanence
  choice here and successful ordinary deletion is permanent;
- `get_audit_reports(opts)` and `delete_audit_report(&id)` become the distinct
  `GetAuditReportsRequest` and `DeleteAuditReportRequest` operations;
- structured scan, structured audit, and audit-host calls take
  `GetScanReportRequest`, `GetAuditReportRequest`, and
  `GetAuditReportHostsRequest`, respectively.

Import validation occurs before capability checks or transport. It accepts
exactly one supported `<report>` document, rejects trailing or sibling XML,
retains the original bytes for authoritative embedding, and redacts the
payload from diagnostics. `task_id` is a required existing import-task
relationship. `in_assets` is optional and is omitted by default.

Report-list selection uses `report_filter`/`report_filt_id`; result selection
inside an ID-selected ordinary report and all structured-report selection use
`filter`/`filt_id`. Detail, pagination bypass, note details, override details,
result tags, and lean output are independently optional and omitted by
default. `GetReportRequest::new` explicitly selects detailed output; list and
audit-host constructors preserve gvmd's omitted defaults. Audit lists fix
`usage_type=audit`; ordinary report list/detail requests add scan usage only
when GMP 22.6 supports the selector.

The response associations remain intentionally separate: ordinary list/detail
XML uses the explicit nested report parser, audit lists have their own semantic
response association, structured scan and audit responses retain their
mixed/repeated parsers, and host summaries keep their lean/detail model. Audit
list/delete require GMP 22.6, structured audit and hosts require 22.7, and
structured scan requires 22.8.

### Report drill-downs and exports

Issue #662 replaces every report projection and export forwarding surface with
one complete request value. The nine projection constructors retain gvmd's
omitted false defaults; set `details=Some(true)` when rows, rather than count
metadata, are required. Hosts additionally expose `lean`.

```rust
use gvm_gmp::commands::reports::{
    ExportScanReportRequest, GetReportExportRequest, GetReportHostsRequest,
};

let mut hosts = GetReportHostsRequest::new(report_id.clone());
hosts.filter_string = Some("rows=25 first=1".into());
hosts.details = Some(true);
hosts.lean = Some(true);
let hosts = client.get_report_hosts(hosts).await?;

let mut export = GetReportExportRequest::new(report_id.clone(), format_id);
export.report_config_id = Some(config_id);
export.ignore_pagination = Some(true);
let bytes = client.get_report_export(export).await?.bytes;

client.discover_commands().await?;
let queued = client
    .export_scan_report(ExportScanReportRequest::new(report_id))
    .await?;
# let _ = (hosts, bytes, queued);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Migration mapping:

- `get_report_hosts(&id, opts)` and the other projection builders become their
  corresponding `GetReport*Request::new(id)` values;
- `_parsed` facade suffixes are removed; the unsuffixed names are typed;
- `get_report_vulnerabilities` is removed; use the concrete wire name
  `get_report_vulns(GetReportVulnsRequest::new(id))`;
- `get_report_export(&id, &format)` and `_with_opts` become
  `get_report_export(GetReportExportRequest::new(id, format))`;
- `export_scan_report(&id, opts)` becomes
  `export_scan_report(ExportScanReportRequest::new(id))`, with optional fields
  set on the request.

The old synchronous-export builder forced details and pagination bypass. The
canonical constructor follows gvmd omission defaults instead; set both fields
explicitly to preserve the former policy. Asynchronous export accepts no saved
filter ID or `details`, and omitted format selects gvmd's executable XML
default despite the published schema saying it is required.

All projections and synchronous export require GMP 22.8. Asynchronous export
has a 22.7 lower bound but additionally requires positive XML-help discovery.
The explicit response codecs preserve projection container/count variants,
mixed-element order, nested XML, and binary/base64 payloads within the existing
bounded response limit. Streaming redesign remains tracked separately by #4.
See the [pinned gvmd evidence](report-request-gvmd-evidence.md).

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

## Note and override families

The note and override slices remove six option bags and twelve free builders.
List, detail, create, clone, modify, and delete inputs now live on twelve
complete canonical request values, and all twelve named client methods accept
those values unchanged:

```rust
use gvm_gmp::commands::notes::{CreateNoteRequest, ModifyNoteRequest};
use gvm_gmp::commands::overrides::{
    CreateOverrideRequest, ModifyOverrideRequest,
};

let mut note = CreateNoteRequest::new("1.3.6.1", "initial note");
note.hosts.push("192.0.2.10".into());
let note = client.create_note(note).await?;

// Omitted restrictions clear; omitted NVT and activation preserve.
client
    .modify_note(ModifyNoteRequest::new(note.id, "updated note"))
    .await?;

let override_ = client
    .create_override(CreateOverrideRequest::new(
        "1.3.6.1",
        "accepted risk",
        5.0,
    ))
    .await?;
client
    .modify_override(ModifyOverrideRequest::new(
        override_.id,
        "false positive",
        -3.0,
    ))
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Final-value validation covers required text/NVT fields, result-port syntax,
host entries, original severity, replacement severity, and activation days.
The canonical note surface removes the parser-ignored `orphan` child. Detail
and clone keep distinct semantic identities over the shared list/create wire
commands.

## User and group families

The user/group slice removes `UserOpts`, `ModifyUserOpts`, `GetUsersOpts`,
`GroupOpts`, `GetGroupsOpts`, and all twelve free builders. List, detail,
create, clone, modify, and delete inputs now live on twelve complete canonical
request values, and all twelve named client methods accept those values
unchanged:

```rust
use gvm_gmp::commands::groups::{
    CreateGroupRequest, ModifyGroupRequest,
};
use gvm_gmp::commands::users::{
    CreateUserRequest, ModifyUserRequest, UserHostAccess,
};
use gvm_gmp::CollectionUpdate;

let mut group = CreateGroupRequest::new("operators");
group.users = vec!["alice".into(), "bob".into()];
let group = client.create_group(group).await?;

let mut user = CreateUserRequest::new("alice");
user.password = Some(password);
user.host_access = Some(UserHostAccess::deny("192.0.2.0/24"));
user.group_ids = vec![group.id.clone()];
let user = client.create_user(user).await?;

let mut modify =
    ModifyUserRequest::new(user.id, UserHostAccess::allow(""));
modify.group_ids = CollectionUpdate::Clear;
client.modify_user(modify).await?;

client
    .modify_group(ModifyGroupRequest::new(
        group.id,
        "operators",
        "",
        Vec::new(),
    ))
    .await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

User role and group updates distinguish preservation, replacement, and
clearing. Host access is a required final value on modification because gvmd
replaces it even when the legacy child was omitted. Group modification owns the
final name, comment, and user membership; empty comment and membership values
clear them. Detail and clone retain distinct semantic identities over their
shared list/create wire commands. Password-bearing request diagnostics and wire
traces remain redacted.

`DeleteUserRequest` intentionally removes the old `ultimate` boolean, which
pinned gvmd ignores. Use `new(user_id)` or `by_name(name)` and optionally set
one inheritor selector. See the [v0.7 migration mapping](v0.7.0-migration.md#users-and-groups)
and [pinned deletion evidence](user-group-request-gvmd-evidence.md#user-deletion-has-no-ultimate-input).

## Role and permission families

All twelve lifecycle helpers accept complete request values. `RoleOpts`,
`GetRolesOpts`, `PermissionOpts`, `GetPermissionsOpts`, and all twelve free
builders are removed. The list/detail/create/clone/modify/delete request types
remain under `commands::roles` and `commands::permissions` and can be passed
either to the corresponding facade method or directly to `execute`.

```rust
use gvm_gmp::commands::roles::{CreateRoleRequest, ModifyRoleRequest};
use gvm_gmp::commands::permissions::{
    CreatePermissionRequest, ModifyPermissionRequest, PermissionSubject,
};
use gvm_gmp::{PermissionSubjectType, ScalarUpdate};

let role = client.create_role(CreateRoleRequest::new("operators")).await?;
let permission = client.create_permission(CreatePermissionRequest::new(
    "get_tasks",
    PermissionSubject::new(role.id.clone(), PermissionSubjectType::Role),
)).await?;

// gvmd replaces all three values on every role modification.
client.modify_role(ModifyRoleRequest::new(
    role.id, "operators", "", Vec::new(),
)).await?;

let mut modify = ModifyPermissionRequest::new(permission.id);
modify.comment = Some(String::new()); // Clear; None preserves.
modify.resource_id = ScalarUpdate::Clear; // <resource id="0"/>.
client.modify_permission(modify).await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Permission creation requires a complete subject, using `PermissionSubject`.
Its optional `PermissionResource` requires an ID; normal command names infer
the resource type, while `Super` requires an explicit `user`, `group`, or `role`
type. Permission modification keeps subject ID/type and resource ID/type
independently expressible, matching gvmd's preservation of omitted counterparts.
For `Super`, supply both resource ID and type to replace an existing identity
resource type; a type-only update can retain the stored identity type.
Unknown permission names and checks requiring existing server state remain
gvmd's responsibility.

`CloneRoleRequest` supports name/comment overrides. When its name is omitted,
gvmd chooses the first available `<existing name> Clone <number>` value,
starting at 1. An explicit name that belongs to an active role returns 400
before the role or its eligible permissions are copied; a trashed role does not
reserve its name. `ClonePermissionRequest` supports only comment. Empty or
omitted clone comments preserve the original. Role cloning copies eligible
permissions, not user membership. Clearing the resource from a stored `Super`
permission receives gvmd's resource-not-found response and rolls back every
requested change. If that clear also supplies a non-identity resource type,
gvmd validates the supplied type first and returns 400, including rollback of
an accompanying comment change. Detail and clone requests retain their semantic
aliases over list/create wire roots. See the
[pinned evidence](role-permission-request-gvmd-evidence.md) for source references
and the mock's bounded scope.

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

## Asset, host, and operating-system-asset families

The thirteen supported operations now accept one complete request value. The
seven asset-family option bags and thirteen public free builders are removed.
Named client helpers take the same request unchanged and delegate to
`execute`.

```rust
use gvm_gmp::commands::assets::{
    AssetType, CreateAssetRequest, GetAssetsRequest, ModifyAssetRequest,
};

let mut list = GetAssetsRequest::new(AssetType::Host);
list.filter_string = Some("severity>5.0".into());
list.ignore_pagination = Some(true);
let hosts = client.get_assets(list).await?;

let mut create = CreateAssetRequest::new("2001:0db8:0:0:0:0:0:1");
create.comment = Some("edge host".into());
let created = client.create_asset(create).await?;
let id = created.id.expect("direct host creation returns an ID");

client
    .modify_asset(ModifyAssetRequest::new(id, ""))
    .await?; // empty final comment clears it
# let _ = hosts;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Migration rules:

- `GetAssetsRequest::new(asset_type)` replaces optional `asset_type`/`type_`;
  host and OS list requests implement `Default` with a fixed type.
- Move `filter_string`, `filter_id`, `details`, and `ignore_pagination` onto the
  list request. Remove typed asset `trash`.
- `CreateAssetRequest::new(name)` and `CreateHostRequest::new(name)` require one
  IPv4 or IPv6 address. Remove create `asset_type` and `value`.
- Modify constructors take the final comment. Empty clears; remove `value`.
- Delete constructors take only the ID. Both old `ultimate` values map to the
  same permanent deletion request.
- Remove `ModifyOperatingSystemAssetRequest`, `modify_operating_system`, and
  `modify_operating_system_asset`. Pinned gvmd only modifies host comments, so
  there is no supported OS-modification replacement.

After free-builder removal, low-level callers can pass raw XML to `send` or
`call`, or implement `GmpRequestCodec` for custom typed execution. Raw XML is
not a workaround for unsupported OS modification. Asset OS continues to use
`get_assets type="os"` and its rich response; it is separate from SecInfo OS.
See [pinned gvmd evidence](asset-request-gvmd-evidence.md).

## Result list and detail family

`GetResultsOpts` and the public `get_results` / `get_result` free
builders are removed. The two request names and two named client methods remain,
but each request now owns the complete input and direct fallible encoding:

```rust
use gvm_gmp::commands::results::{GetResultRequest, GetResultsRequest};
use gvm_gmp::EntityId;

let mut request = GetResultsRequest::default();
request.filter_string = Some("report_id=report-1 first=1 rows=25".into());
request.notes_details = Some(true);
request.get_counts = Some(false);
let listed = client.get_results(request).await?;

let result_id = EntityId::new("result-1")?;
let detail = client
    .get_result(GetResultRequest::new(result_id))
    .await?;
# let _ = (listed, detail);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Direct signature migrations:

- `GetResultsRequest::new(GetResultsOpts { ... })` becomes
  `GetResultsRequest { ..., ..Default::default() }`;
- `client.get_results(opts)` becomes `client.get_results(request)`;
- `client.get_result(&id)` becomes
  `client.get_result(GetResultRequest::new(id))`;
- free-builder callers move to `execute(request)`, or deliberately keep raw
  XML/custom codecs through `send`, `call`, `gvm_protocol::Request`,
  `XmlCommand`, and downstream `GmpRequestCodec` implementations.

Both requests expose `task_id`, `filter_string`, `filter_id`,
`details`, `notes_details`, `overrides_details`, and
`get_counts`; the list request additionally has optional `result_id`.
The detail constructor sets `details = Some(true)`, which remains publicly
mutable.

Root `task_id` supplies note/override context and does not select results.
Use `task_id=...` or `report_id=...` inside the filter for selection.
`notes_details` and `overrides_details` only control expansion richness;
filter terms `notes` and `overrides` request inclusion, while
`apply_overrides` independently changes severity application. Inline and
saved filters may coexist. Empty inline filters and the `0`/`-2` saved
filter sentinels are preserved for gvmd.

`get_counts = Some(false)` can produce a response with items and pagination
metadata but no count block. `CountInfo::default()` represents that absence;
page, filtered, and total counts have distinct meanings.

There is no canonical result field replacing trash, root report selection,
lean/delta output, pagination bypass, root inclusion/application flags, or
`filter_replace`. Pagination and sorting stay in filter text, and opaque
delta-related text is not a promise of delta rendering. The current
`ScanResult` intentionally omits nested note/override, ticket, detection,
tag, delta, original-severity, and other rich expansion payloads. Use raw
execution when those complete subtrees are required. See
[pinned gvmd evidence](result-request-gvmd-evidence.md).

## Report-configuration lifecycle

The nine report-configuration free builders, four `*Opts` bags, and three
`*WithOptsRequest` wrappers are removed. Construct one of the six complete
requests and pass it to the same-named facade or `execute`:

```rust
use gvm_gmp::commands::report_configs::{
    CreateReportConfigRequest, GetReportConfigsRequest, ModifyReportConfigRequest,
    ReportConfigParam, ReportConfigParamValue,
};
use gvm_gmp::EntityId;

let format_id = EntityId::new("report-format-1")?;
let mut create = CreateReportConfigRequest::new("configuration", format_id);
create.comment = Some("initial".into());
create.params.push(ReportConfigParam {
    name: "Label".into(),
    value: ReportConfigParamValue::Value("custom".into()),
});
let created = client.create_report_config(create).await?;

let mut modify = ModifyReportConfigRequest::new(created.id);
modify.comment = Some(String::new()); // clear comment
modify.params.push(ReportConfigParam {
    name: "Label".into(),
    value: ReportConfigParamValue::UseDefault, // remove this override
});
client.modify_report_config(modify).await?;

let mut list = GetReportConfigsRequest::default();
list.filter_string = Some("first=1 rows=-1 sort=name".into());
let observed = client.get_report_configs(list).await?;
# let _ = observed;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Direct signature migrations:

- `get_report_configs_parsed(opts)` becomes
  `get_report_configs(GetReportConfigsRequest { ... })`;
- `get_report_config(&id)` becomes
  `get_report_config(GetReportConfigRequest::new(id))`;
- `create_report_config(name, format)` and
  `create_report_config_with_opts(name, format, opts)` become
  `create_report_config(CreateReportConfigRequest::new(name, format_id))`, with
  comment/parameters placed on that request;
- `clone_report_config(&id)` becomes
  `clone_report_config(CloneReportConfigRequest::new(id))`;
- `modify_report_config(&id, opts)` becomes a complete
  `ModifyReportConfigRequest::new(id)`;
- `delete_report_config(&id)` and `delete_report_config_with_opts(&id, opts)`
  become `delete_report_config(DeleteReportConfigRequest::new(id))`, with
  `ultimate` on the request.

The five raw report-configuration methods are removed from
`Gmp226Commands`. Use the canonical typed facade or generic `execute`; both
return the associated typed response rather than raw `gvm_protocol::Response`.
`GmpVersioned` retains generic `execute(request)`. Raw callers may deliberately
use `send`/`call`, `gvm_protocol::Request`, `XmlCommand`, or a downstream custom
codec.

Selectors are `EntityId`, whose accepted lexical policy is not UUID-only.
Root `first` and `rows` are removed because gvmd reads them from filter text;
`rows=-1` remains caller-authored filter syntax. Direct create now emits
`<report_format id="..."/>`, not `<report_format_id>`. Omitted comment and
parameters preserve on modify; empty comment clears; empty parameter values
are assignments; `UseDefault` resets one named override. Clone supports only a
name override; comment, format, and parameter clone overrides are unsupported.
There is no import, preference, usage-type, policy, or modify-format
replacement request.

The typed response remains a bounded metadata/format projection. Parameter
lifecycle observations require raw response XML. The pinned orphan-modify and
trash-rendering quirks and the mock's bounded validation/filter subsets are
documented separately in the
[source evidence](report-config-request-gvmd-evidence.md); they are not
live-gvmd compatibility claims.

## Report-format lifecycle

The eight report-format free builders and two option bags are removed. The
unsupported direct-create request/facade is also removed: gvmd creates a
report format only by importing an exported response envelope or cloning an
existing format. Construct one of the seven complete requests and pass it to
the same-named facade or `execute`:

```rust
use gvm_gmp::commands::report_formats::{
    GetReportFormatsRequest, ImportReportFormatRequest,
    ModifyReportFormatRequest, ReportFormatParamUpdate,
};
use gvm_gmp::EntityId;

let exported = r#"<get_report_formats_response><report_format id="11111111-1111-1111-1111-111111111111"><name>Imported</name></report_format></get_report_formats_response>"#;
let created = client
    .import_report_format(ImportReportFormatRequest::new(exported))
    .await?;

let mut modify = ModifyReportFormatRequest::new(created.id);
modify.summary = Some(String::new()); // emits <summary></summary>
modify.param = Some(ReportFormatParamUpdate {
    name: "Label".into(),
    value: Some("red".into()), // encoded as standard base64 exactly once
});
client.modify_report_format(modify).await?;

let mut list = GetReportFormatsRequest::new();
list.params = Some(true);
let formats = client.get_report_formats(list).await?;
# let _ = formats;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Direct signature migrations:

- `get_report_formats(opts)` becomes
  `get_report_formats(GetReportFormatsRequest { ... })`;
- `get_report_format(&id, opts)` becomes
  `get_report_format(GetReportFormatRequest::new(id))`, with query controls on
  that request;
- `create_report_format(name, opts)` and `CreateReportFormatRequest` have no
  direct replacement; select import or clone explicitly;
- `import_report_format(xml)` becomes
  `import_report_format(ImportReportFormatRequest::new(exported_envelope))`;
- `clone_report_format(&id)` becomes
  `clone_report_format(CloneReportFormatRequest::new(id))`;
- `modify_report_format(&id, opts)` becomes a complete
  `ModifyReportFormatRequest::new(id)`;
- `delete_report_format(&id, ultimate)` becomes
  `delete_report_format(DeleteReportFormatRequest::new(id))`, with optional
  `ultimate` on the request; and
- `verify_report_format(&id)` becomes
  `verify_report_format(VerifyReportFormatRequest::new(id))`.

Import now takes a complete `get_report_formats_response` envelope containing
exactly one direct format with nonempty ID/name. The infallible constructor
owns the original spelling; final validation is a `GmpRequestError` during
typed execution, not a response `ParseError`. Valid bytes are embedded without
normalization. UUID acceptance, complete definition validation, and collision
allocation remain server-side; always use the returned created ID. Raw
`Request`, `XmlCommand`, `send`/`call`, and custom codecs remain available for
deliberate raw multi-format/unsupported XML.

Modification no longer exposes comment, content type, or format type; these
have no supported mutation replacement. Omitted summary preserves it, while
`Some("")` clears it with paired tags. One parameter may be changed. Omitted
parameter preserves all; `value: None` and `value: Some("")` both clear one
value; neither restores its default. Unlike report-configuration parameters,
report-format parameter text is base64-carried. Compound metadata and
parameter modification is not atomic upstream: a later parameter error may
leave metadata committed.

Clone supports only an optional exact name. Omitted/empty name asks gvmd to
generate one. Its upstream implementation does not copy parameter-option rows.
Nonultimate deletion can assign a new trash ID, and active alert use can block
deletion; report-configuration references do not block or cascade. Successful
verification is completion, not a trusted boolean—read the format afterward
to observe trust.

Queries add independent params, details, alerts, and report-config expansion
flags. The typed response remains metadata/content/trust/active/predefined,
not a full export. `ReportFormatType` is retained but is not lifecycle input.
See the [source evidence](report-format-request-gvmd-evidence.md) for schema
differences, source quirks, response limits, and declared mock approximations;
no live-gvmd validation is claimed.

## TLS-certificate lifecycle

The two TLS option bags and six free builders are removed. Construct one of
the six complete requests and pass it unchanged to the same-named client
method or `execute`:

```rust
use gvm_gmp::commands::tls_certificates::{
    CloneTlsCertificateRequest, CreateTlsCertificateRequest,
    DeleteTlsCertificateRequest, GetTlsCertificateRequest,
    GetTlsCertificatesRequest, ModifyTlsCertificateRequest,
};

let pem = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n";
let mut create = CreateTlsCertificateRequest::new(pem.to_vec());
create.name = Some("gateway certificate".into());
create.trust = Some(true);
let created = client.create_tls_certificate(create).await?;

let mut modify = ModifyTlsCertificateRequest::new(created.id.clone());
modify.comment = Some(String::new()); // explicit empty clears
client.modify_tls_certificate(modify).await?;

let mut detail = GetTlsCertificateRequest::new(created.id.clone());
detail.details = Some(false);
detail.include_certificate_data = Some(true);
let certificate = client.get_tls_certificate(detail).await?;

client
    .delete_tls_certificate(DeleteTlsCertificateRequest::new(created.id))
    .await?;
# let _ = (certificate, CloneTlsCertificateRequest::new,
#     GetTlsCertificatesRequest::new);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Direct signature migrations:

- `get_tls_certificates(opts)` becomes
  `get_tls_certificates(GetTlsCertificatesRequest { ... })`;
- `get_tls_certificate(&id)` becomes
  `get_tls_certificate(GetTlsCertificateRequest::new(id))`;
- `create_tls_certificate(name, opts)` becomes
  `create_tls_certificate(CreateTlsCertificateRequest::new(original_bytes))`,
  with name/comment/trust on the request;
- `clone_tls_certificate(&id)` becomes
  `clone_tls_certificate(CloneTlsCertificateRequest::new(id))`;
- `modify_tls_certificate(&id, opts)` becomes
  `modify_tls_certificate(ModifyTlsCertificateRequest::new(id))`; and
- `delete_tls_certificate(&id, ultimate)` becomes
  `delete_tls_certificate(DeleteTlsCertificateRequest::new(id))`.

Creation input is now the original certificate-file bytes. Callers that
previously held a GMP base64 carrier must decode it once before constructing
the request; already-base64-looking bytes are encoded as literal bytes again.
PEM line endings and binary DER are preserved. Certificate must be nonempty,
but X.509 parsing, validity windows, chain trust, and size policy remain
server-authoritative. Name is optional, and omission or empty text requests
gvmd's SHA-256 fingerprint fallback. There is no compatibility field for the
unsupported private key or for certificate replacement during modification.

Creation and cloning use owner-scoped SHA-256 or MD5 identity rather than
names. A permitted foreign certificate can be cloned once if the caller does
not already own its fingerprint. Empty or omitted clone name/comment copies
the source; empty comment does not clear during clone. Clone copies parsed
certificate metadata, trust, and tag associations, but not observation
sources. To clear its comment, modify the created certificate afterward.

Modify omission preserves name, comment, and trust. Explicit empty name or
comment clears it, and selector-only modification is valid. Trust is a stored
boolean independent of the response's time-validity observation. TLS deletion
is permanent for both former `ultimate` values; there is no trash selector,
restore path, ownership assignment, root pagination, or effective pagination
bypass on the canonical surface.

Certificate text is requested independently with
`include_certificate_data`; details also includes it and additionally asks
for sources. The typed response retains optional wire base64 text and a
bounded projection. Format, serial, trust, time status, last-seen, tags,
permissions, and source graphs require raw response access. `Debug` and wire
trace diagnostics redact certificate/private-key element content, while raw
responses, explicit encoding, and serde remain data-bearing APIs.

Create/get/modify retain pinned-schema evidence and source-supported delete
retains its GMP 22.4+ availability. Raw `Request`, `XmlCommand`, `send`/`call`,
and downstream custom codecs remain available for intentionally unmodeled XML;
they do not make unsupported private-key or certificate mutation meaningful.
See the [pinned source evidence](tls-certificate-request-gvmd-evidence.md) for
schema discrepancies and bounded mock limitations.

## NVT and SecInfo discovery

NVT/SecInfo calls now take one of 19 complete canonical requests. Former
`GetNvtsOpts`, `GetNvtPreferencesOpts`, `GetInfoListOpts`, `GetSecInfoOpts`,
`GetInfoOpts`, their free builders, and duplicate system wrappers are removed.
Move every supported option onto the request before passing it to either
`execute` or the identically named facade:

```rust
use gvm_gmp::commands::nvts::{GetNvtRequest, GetScanConfigNvtsRequest};
use gvm_gmp::commands::secinfo::{GenericInfoType, GetCvesRequest, GetInfoRequest};
use gvm_gmp::commands::system::GetVulnerabilityRequest;

let nvt = client.get_nvt(GetNvtRequest::new("1.3.6.1.4.1.25623.1")).await?;
let mut members = GetScanConfigNvtsRequest::new(config_id, "General");
members.details = Some(true);
members.preferences = Some(true);
let members = client.get_scan_config_nvts(members).await?;
let cves = client.get_cves(GetCvesRequest::default()).await?;
let cve = client
    .get_info(GetInfoRequest::new("CVE-2026-1000", GenericInfoType::Cve))
    .await?;
let observed = client
    .get_vulnerability(GetVulnerabilityRequest::new("vuln-1"))
    .await?;
# let _ = (nvt, members, cves, cve, observed);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Config membership and preference-value contexts are not interchangeable.
Detail selectors bypass membership; list selectors do not. The dedicated NVT
handler ignores generic filters, so those fields are absent. Detail-dependent
flags and timeout context are validated against the final request before I/O.

`GenericInfoType` now contains only pinned `get_info` dispatches:
`CERT_BUND_ADV`, `CPE`, `CVE`, `DFN_CERT_ADV`, and `NVT`. There is no OVAL,
operating-system, or vulnerability alias. Use asset OS requests for OS assets
and `GetVulnsRequest`/`GetVulnerabilityRequest` for observed vulnerabilities.
The historical `InfoType` is vocabulary only and no longer converts into the
canonical enum.

SecInfo typed responses follow authoritative `<info id>` wrappers. Direct typed
children remain a labeled compatibility fallback. Preference `Debug` and wire
traces redact configured/default/alternate values, but raw response and serde
access remain data-bearing. See the
[pinned evidence](nvt-secinfo-request-gvmd-evidence.md).

## Configuration, scan-configuration, policy, and preferences

Lifecycle calls now take one of 24 complete requests. Six generic and fourteen
scoped facade methods accept their request unchanged; the four policy
create/clone/modify/delete aliases remain available through `execute` and do
not gain new symmetry facades.

```rust
use gvm_gmp::commands::configs::CreateConfigRequest;
use gvm_gmp::commands::scan_configs::{GetPoliciesRequest, ImportPolicyRequest};

let created = client
    .create_config(CreateConfigRequest::new("Copied", base_config_id))
    .await?;
let policies = client.get_policies(GetPoliciesRequest::new()).await?;
let imported = client
    .import_policy(ImportPolicyRequest::new(exported_config_xml))
    .await?;
# let _ = (created, policies, imported);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Named create requests require a base. Clone requests may omit/empty the name
for generated naming and inherit omitted/empty comment and usage values.
Canonical usage is `ConfigUsageType::Scan` or `Policy`; audit remains a task
usage. Policy import adds an outer policy override, while scan import can carry
an optional typed override.

Import constructors are infallible storage boundaries. Final validation accepts
an optional BOM/declaration, requires one unnamespaced exported config with a
nonempty name and explicit selector/preference containers, and preserves all
remaining carrier bytes. Failures are request errors before discovery or I/O
and diagnostics do not include the XML.

Modify requests no longer contain usage. Empty name/comment elements and omitted
values preserve existing metadata; they do not clear. Detail requests retain
collection response types, and ID selection bypasses usage/filter/pagination
predicates even though policy/scan detail aliases still emit their usage field.

Remove uses of `SyncConfigRequest`, `scan_configs::sync_config`,
`GmpClient::sync_config`, and deprecated `sync_scan_config`. The schema name has
no pinned/current gvmd dispatcher and is explicitly rejected in built-in mock
modes. This is not feed synchronization.

Preference list/single requests and all eight configured preference/NVT/family
mutation requests are canonical direct codecs. Use generic `execute`; the two
preference facades, the preference options bag, and the ten old builders are
removed. `None` deletes a preference override while `Some("")` sends an
explicit empty value; decoded values are base64-encoded exactly once. NVT and
family inputs are ordered replacements, with empty vectors clearing their
scope. List/single response types preserve absent values and missing matches,
and secret values are redacted from Debug, errors, and traces. See the
[pinned evidence](scan-config-policy-request-gvmd-evidence.md).

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

The facade inventory locks all 262 current public async methods: 259 delegate
directly to `execute`, three frozen ticket helpers keep their explicit raw
compatibility path. Unsupported `sync_config` and its deprecated per-config
delegate are absent.

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
