# Typed request/response execution

The Technology Preview client provides typed execution described by issue
#523. ADR 0002 makes issue #602 a pre-release convergence gate: the current
builder-backed request wrappers remain available during bounded migration, but
complete request values become the canonical input before publication.
Each migrated semantic request implements `GmpRequest` and selects exactly one
`GmpResponse` through an associated type:

```rust
use gvm_gmp::commands::targets::GetTargetsRequest;

let response = client
    .execute(GetTargetsRequest::default())
    .await?;
```

No response type annotation or manual `from_response` call is required. Passing
the request to `execute` determines the result type at compile time.

## Compatibility APIs

Typed convenience methods may remain during bounded family migration when they
improve discoverability. Canonical methods accept the same complete request and
delegate to `execute` without maintaining a parallel input model:

```rust
use gvm_gmp::commands::targets::GetTargetsRequest;

let response = client.get_targets(GetTargetsRequest::default()).await?;
```

Existing command builders in unconverted families remain available until their
ledger disposition is reviewed. The standard target builders were removed with
their canonical requests. Raw `send` and `call` remain supported; use them for custom XML,
commands that have not migrated, or response details not yet represented by a
typed model:

```rust
let raw = client.call(b"<get_targets/>".as_slice()).await?;
```

`send` returns any GMP status as a raw response. `call`, `execute`, and typed
convenience methods raise `GvmError::Server { status, message }` for an
equivalent valid non-2xx GMP response. Malformed XML, missing required fields,
invalid values, and other uninterpretable responses remain
`GvmError::Parse`. This normalization corrects the initial typed-execution
behavior; consumers that matched
`GvmError::Parse(ParseError::ServerError { .. })` must now match
`GvmError::Server { .. }`.

The typed contract is owned by `gvm-gmp` (`GmpRequestCodec`, `GmpRequest`, and
`GmpResponse`) and `gvm-client` (`GmpClient::execute`). `gvm-client` re-exports
those traits for ergonomic imports. `GmpRequestCodec` separates fallible final
validation and version-aware encoding from the infallible raw `Request` escape
hatch. See [ADR 0002](adr/0002-canonical-request-ownership.md), the checked
[surface disposition ledger](canonical-request-disposition.md), and the
downstream [migration notes](typed-execution-migration.md) for API selection,
compatibility, and release adoption.

## Custom codecs

Custom and irregular commands have two supported paths. If raw bytes are the
right abstraction, implement `gvm_protocol::Request` (or pass `Vec<u8>`/a byte
slice) and use `send` or `call`. If the command should participate in typed
execution, implement `GmpRequestCodec` plus `GmpRequest` on the request type and
`GmpResponse` on its associated response type:

```rust
use gvm_gmp::{
    GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpResponse,
    GmpVersion,
};
use gvm_gmp::responses::ParseError;
use gvm_protocol::{Request as _, Response, XmlCommand};

struct CustomRequest {
    resource_id: String,
}

impl GmpRequestCodec for CustomRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.resource_id.is_empty() {
            return Err(GmpRequestError::invalid_field(
                "resource_id",
                "must not be empty",
            ));
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("custom_command"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("custom_command")
            .attribute("resource_id", &self.resource_id)
            .to_bytes())
    }
}

struct CustomResponse(Response);

impl GmpResponse for CustomResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        let status = response
            .status_code()
            .ok_or_else(|| ParseError::MissingElement("status".into()))?;
        let message = response
            .status_text()
            .ok_or_else(|| ParseError::MissingElement("status_text".into()))?;
        if !(200..300).contains(&status) {
            return Err(ParseError::ServerError { status, message });
        }
        Ok(Self(response.clone()))
    }
}

impl GmpRequest for CustomRequest {
    type Response = CustomResponse;
}
```

Custom response codecs must reject non-2xx statuses as
`ParseError::ServerError`; `gvm-client` promotes that decoder error to
`GvmError::Server`. Codecs retain structural field context in other parse
errors. `execute` validates the final request, applies negotiated-version/help
checks from `GmpCommand`, then encodes and enters the shared redacted transport
path. Unknown custom names retain the raw path's forward compatibility. A
semantic alias supplied by `GmpCommand::with_semantic_name` is checked before
its shared wire command. Existing builder-backed request wrappers use the
temporary raw adapter until their family conversion. The standard target
family implements this contract directly and serves as the reference slice.

## Authoring a migrated command

1. Define one complete semantic request struct in the owning `gvm-gmp` command
   module, containing required and optional inputs.
2. Implement `GmpRequestCodec::validate` for final-value field and combination
   constraints. Error reasons must not retain caller-provided secret values.
3. Return `GmpCommand` metadata for the semantic operation and shared wire root,
   without inspecting encoded XML.
4. Implement fallible, version-aware encoding on the request. Keep private
   shared encoding helpers where they avoid duplication.
5. Implement `GmpRequest` and associate exactly one response model.
6. Implement `GmpResponse` on that existing response model. Use the negotiated
   version only when the response wire shape genuinely differs by version.
7. Decide every options type, free builder, and convenience method in the
   checked disposition ledger. Retain it only for concrete reuse or ergonomics.
8. Add independent exact XML, final-validation precedence, response parsing,
   all support states, non-success, malformed-response, and redaction tests as
   applicable.

Irregular commands are first-class. They may retain explicit XML codecs and do
not need Serde derives. A request whose encoding genuinely differs by GMP
version must make that distinction explicit in the GMP layer; transport code is
not the place for command-specific branching.

## Specialized task variants

Task variants that share an XML root still use distinct semantic Rust values.
For example, standard scans, imports, agent-group scans, OCI/container-image
scans, web-application scans, and audits all reuse `<create_task>`, but each has
a request type whose fields match that operation. Compatibility aliases such as
container/import and container-image/OCI remain separately named while
delegating to the same established builders.

Agent-group, OCI/container-image, and web-application task requests declare
their GMP Next semantic capability even though the wire root is the baseline
`create_task` command. Generic execution therefore rejects them before sending
on GMP 22.7 and earlier, preserving the existing versioned-client boundary.
The client also recognizes these shapes when their existing raw builders are
passed to `send` or `call`, so the compatibility escape hatch cannot bypass the
same gate. Import/container and move requests retain their established baseline
behavior.

## Agents and integration configurations

All agent, agent-group, and integration-configuration commands require GMP
22.8. Agent-group list, detail, create, clone, modify, and delete requests are
canonical: they directly own filters, identifiers, scheduler values, repeated
agent relationships, mutation fields, semantic aliases, and exact XML. Their
named facade methods accept the same requests and delegate to `execute`.
Agent list, detail, modify, delete, synchronization, agent-control-default,
installer-instruction, and support-bundle requests follow the same contract.
`AgentConfigOpts` remains a reusable nested configuration value shared by the
two agent mutation shapes. Integration-configuration list, detail, and
replacement/clear requests are canonical as well. Detail keeps a semantic
alias over the list wire root. A completely empty modification clears the
configuration; any replacement validates the four required service/OIDC
values before the GMP 22.8 capability check or transport.

Agent installer instructions retain their language and origin metadata.
Support-bundle responses continue to decode base64 content into binary bytes
and validate declared sizes. Integration service CA certificates and OIDC
client secrets remain redacted from semantic-request diagnostics and wire
tracing.

## System administration and user settings

The system administration slice represents all six public mutation builders:
authentication configuration, default and option-bearing license updates, the
system-module setting compatibility wrapper, and default and option-bearing
wizard execution. The three user-setting builders cover list, detail, and
modification. Every request delegates to its established builder, so XML bytes,
base64 setting encoding, option semantics, identifiers, status handling, and
specialized wizard response parsing remain unchanged.

The system-module `ModifySettingRequest` and user-setting-module
`ModifyUserSettingRequest` are distinct semantic values over the same canonical
encoder. Authentication, license, and wizard convenience helpers use
`execute`; the user-setting requests are available directly through generic
execution without adding another facade. `Debug` output redacts authentication
setting values, license files, wizard parameter values, and user-setting
values, matching the wire-trace boundary's secret handling.

Audit list, detail, create, clone, modify, delete, start, stop, and resume
requests likewise remain audit-scoped types even where their wire command is a
task command. This keeps compile-time intent explicit without duplicating XML
encoding or changing server behavior. Fallible audit modification validates
observer updates in its constructor before execution.

## Credential stores and semantic aliases

Credential stores are available from GMP 22.8. Their list, detail,
verification, and preference-bearing modification requests use dedicated wire
roots. Store-backed credentials instead reuse `create_credential` and
`modify_credential`, so their semantic request values explicitly identify the
newer operation before sending:

```rust
use gvm_gmp::commands::credentials::{
    CreateCredentialStoreCredentialRequest,
};
use gvm_gmp::CredentialStoreCredentialType;

let credential = client
    .execute(CreateCredentialStoreCredentialRequest::new(
        "production vault credential",
        CredentialStoreCredentialType::UsernamePassword,
        "vault-entry-1",
        "host-1",
    ))
    .await?;
```

This preserves the `create_credential_store_credential` and
`modify_credential_store_credential` capability gates even though those names
do not appear as XML roots. A client negotiated below GMP 22.8 rejects them
before transport. The canonical requests now own the vault, host, SNMP, and
preference fields directly. Their custom `Debug` implementations and the wire
trace boundary redact credential material, vault/host identifiers, and
preference values. The low-level raw `send`/`call` path remains available for
custom XML.

## Canonical filter requests

Filter list, detail, create, clone, modify, and delete operations use complete
canonical requests. `FilterOpts`, `GetFiltersOpts`, and the six forwarding
builders are removed; discoverable client methods accept the same request
values and delegate to `execute`. Detail and clone preserve their semantic
aliases over the `get_filters` and `create_filter` wire roots.

The request model follows pinned gvmd rather than the transitional builder:
sorting remains part of the filter term, so the unsupported `sort_order` child
is gone. Modify supports filter rename, clone supports optional name/comment
overrides, and list/detail support alert expansion. Required or explicitly
replaced names are validated from the final value before support checks and
transport.

## Canonical tag requests

Tag list, detail, create, clone, modify, and delete operations use complete
canonical requests. `TagOpts`, `GetTagsOpts`, and the six forwarding builders
are removed; discoverable client methods accept the same request values and
delegate to `execute`. Detail and clone preserve their semantic aliases over
the `get_tags` and `create_tag` wire roots.

`TagResources` owns a required resource type plus zero or more IDs and an
optional filter. `TagResourceUpdate` adds gvmd's optional add/set/remove action
for modification. Policy resources retain the `config` wire spelling, while
tag-on-tag resources fail final-value validation before support checks or
transport. Modify preserves explicit empty comment/value elements so callers
can clear them. The unsupported transitional `severity` field is removed.

## Canonical scanner requests

Scanner list, detail, create, clone, modify, delete, and verify operations use
seven complete canonical requests. `ScannerOpts`, `GetScannersOpts`, and the
seven forwarding builders are removed; named client methods accept the same
request values and delegate to `execute`.

Create owns gvmd's required name, host, port, and scanner type. Relay host and
port are represented on create, modify, and response values. Modify uses
`ScalarUpdate<EntityId>` for the credential relationship and explicit empty
text for comment, CA certificate, and relay clearing. Omission preserves the
corresponding value. Detail and clone retain semantic identities over the
`get_scanners` and `create_scanner` wire roots.

## Alert and schedule command shapes

Alert list, detail, create, clone, modify, delete, test, and trigger operations
use complete canonical requests. `AlertOpts`, `GetAlertsOpts`,
`TriggerAlertOpts`, and the eight forwarding builders are removed; named client
methods accept the same request values and delegate to `execute`. List/detail
and create/clone remain distinct Rust request types over shared wire roots and
response models.

Create owns gvmd's required event, condition, and method values. Modify exposes
the server's filter-clearing-on-omission behavior and active-state preservation.
Nested alert data values are redacted from request diagnostics and wire traces.
Alert triggering emits `<get_reports alert_id="..." report_id="...">`, keeps a
`trigger_alert` semantic alias, and associates the request with
`GetReportsResponse`; `test_alert` uses the ordinary action response codec.

Schedule list, detail, create, clone, modify, and delete operations use six
complete canonical requests. `ScheduleOpts`, `GetSchedulesOpts`, the eight free
builders, and the duplicate typed create/modify wrappers are removed. Raw
iCalendar construction uses `CreateScheduleRequest::new` or
`ModifyScheduleRequest::new`; validated recurrence construction uses
`from_input` on those same request types. Create and modify validate gvmd's
required non-empty iCalendar value before capability checks or transport.

## Supporting resource lifecycles and trashcan recovery

Filters and tags each expose semantic list, detailed-get, create, clone,
modify, and delete request values. The list/detail and create/clone pairs keep
separate Rust types even where they share a wire command and response model,
so call-site intent remains explicit while the established builders remain the
single XML encoders.

Notes and overrides use twelve complete canonical request values. Their six
option bags and twelve forwarding builders are removed, while the named facade
helpers accept each request unchanged and delegate to `execute`. Create owns
gvmd's required NVT/text values; override create and modify additionally own the
required replacement severity. Modify clears omitted host, port, original
severity, task, and result restrictions while preserving omitted NVT and
activation. The unsupported note `orphan` child is no longer emitted.

Trashcan operations follow the same rule. `EmptyTrashcanRequest` selects the
existing empty-trashcan response, while `RestoreRequest` and
`RestoreFromTrashcanRequest` preserve the two public builder names as distinct
semantic values over the same byte-identical `<restore>` command and typed
response. All of these baseline commands remain available on every supported
GMP version, and retained facade helpers delegate through `execute` without
changing raw `send` or `call` behavior.

## Identity and authorization lifecycles

Users and groups expose twelve complete canonical list, detailed-get, create,
clone, modify, and delete request values. Their five former option bags and
twelve forwarding builders are removed. The list/detail and create/clone pairs
remain separate Rust types despite sharing XML roots and response models,
making the caller's intent explicit without introducing a second wire encoder.
The request values own authentication source, host access, group membership,
role assignment, user membership, replacement, and explicit clearing. Password
diagnostics and wire traces remain redacted. The twelve corresponding
`GmpClient` convenience methods accept each request unchanged and delegate to
`execute`; raw `send` and `call` remain available.

Roles and permissions retain the earlier additive typed-execution surface
until their bounded canonical-request slice. Their semantic request values
still delegate to the existing builders and preserve role membership and
permission subject/resource relationships.

## NVT and SecInfo queries

The seven NVT, ten SecInfo, and two observed-vulnerability requests are
complete canonical codecs. They own public inputs, final-value validation,
semantic metadata, direct encoding, and typed response association. Each named
facade accepts the same request by value and delegates unchanged to `execute`;
the parallel option bags and public builders are removed.

NVT contexts remain semantically distinct. `config_id` restricts list
membership, while a detail selector remains visible even when it is not a
member. `preferences_config_id` changes observed preference values without
membership filtering. Config-scoped lists require a family. Preferences,
preference counts, lean output, and skip flags require details; timeout also
requires a configuration context. NVT preference list/detail requests reuse
`GetScanConfigPreferencesResponse`, including the scanner-preference empty-OID
boundary and value-redacting `Debug` implementation.

Pinned `get_info` dispatch supports exactly CERT-Bund, CPE, CVE, DFN-CERT, and
NVT. Generic and specialized requests share that one root and authoritative
`<info>` wrapper response shape. Historical OS/vulnerability spellings remain
documented by `InfoType`, but cannot be converted wholesale into
`GenericInfoType` and have no canonical request/facade. OS assets use the asset
family. Observed vulnerabilities use `GetVulnsRequest` or the semantic
`GetVulnerabilityRequest`, both over `get_vulns`.

Response models intentionally expose bounded projections. Generic SecInfo uses
the wrapper's ID/name and direct payload type; richer payload content and
observed-vulnerability detail remain available through raw execution. Trace
redaction covers preference value/default/alternative content and attributes,
while raw responses and serde remain data-bearing. See the
[pinned evidence and mock qualification](nvt-secinfo-request-gvmd-evidence.md).

## Assets, hosts, operating-system assets, and results

The thirteen supported generic asset, host, and operating-system-asset
operations are canonical complete requests. They own public inputs, final
validation, semantic command metadata, direct fallible encoding, and response
association. Their named facade methods accept the same request unchanged and
delegate to `execute`; the parallel option bags and public free builders are
removed.

Generic reads require one `AssetType`; host and OS aliases fix `host` and `os`.
List requests expose opaque inline/saved filters, optional details, and
`ignore_pagination`, but no asset trash mode. Direct create requires one IPv4
or IPv6 `name`, fixes the type to host, preserves accepted address spelling,
and rejects DNS names, ranges, CIDRs, lists, and malformed text before
transport. Modify requires the final comment and always replaces it; an empty
string clears. Delete takes only an ID and is permanent, with OS references
remaining server-authoritative. No `value`, `ultimate`, `trash`, or duplicate
type-alias field is encoded.

The old operating-system modification request/helper is removed: pinned gvmd
only modifies host comments and returns a find error for an OS asset ID. There
is no supported typed replacement. Raw XML remains an escape hatch for
unmodeled commands, not an OS-modification workaround. Asset OS remains a rich
`get_assets type="os"` family and is not interchangeable with the deferred
SecInfo OS or report projection surfaces. See the
[pinned evidence](asset-request-gvmd-evidence.md).

Result list and detail are complete canonical requests over the same
`get_results` wire root and share `GetResultsResponse`.
`GetResultsRequest::default()` omits all eight selectors/controls.
`GetResultRequest::new(id)` requires the result ID and defaults `details`
to true, but callers may set it to false or omit it. Both requests expose
optional task context, inline and saved filters, details,
`notes_details`, `overrides_details`, and `get_counts`; the plural
request also exposes an optional result selector.

Root task context does not restrict the list. Task/report selection,
pagination, sorting, expansion inclusion, and override application stay in the
opaque GMP filter. Expansion-detail flags change richness but do not request
inclusion. The client preserves empty filters and saved-filter sentinels,
rejects XML 1.0-forbidden filter characters before transport, and otherwise
leaves filter interpretation to gvmd.

The typed response accepts source-shaped top-level results, optional result
names, ID-only report references, and absent count blocks. Nested notes,
overrides, tickets, detections, tags, delta data, and original severity remain
outside `ScanResult`; raw `send`/`call` preserves access to the complete
XML. See the [pinned result evidence](result-request-gvmd-evidence.md).

## Report configurations

Report-configuration list, detail, direct create, clone, modify, and delete use
six explicit complete requests with GMP 22.6 metadata. Detail and clone retain
semantic aliases over `get_report_configs` and `create_report_config`; they do
not create new wire commands. The six same-named `GmpClient` facades accept the
request by value and call `execute` directly. Versioned clients use their
existing generic `execute(request)` wrapper. The five old raw
`Gmp226Commands` lifecycle methods are removed; `get_features` remains.

Queries expose ID, inline and saved filters, trash, details, and
`ignore_pagination`. Pagination and sorting stay in filter text. Direct create
requires a name and `EntityId` format reference and emits
`<report_format id="..."/>`. Create and modify accept ordered
`ReportConfigParam` values; omission, `Value("")`, and `UseDefault` are
distinct. Modify cannot replace the format. Clone supports only an optional
name override, where omission and explicit empty request automatic naming.

The typed `ReportConfig` response intentionally retains metadata and an
optional format association only. It accepts ID-only orphan references but
does not expose parameter values/defaults/options/bounds, `using_default`,
orphan state, or full permission/tag expansions. Use raw `send`/`call` when
those complete subtrees are required. There is no report-configuration import,
preference wrapper, usage type, or policy surface. See the
[pinned evidence](report-config-request-gvmd-evidence.md).

## Alternate target lifecycles

The target command boundary includes a semantic `CloneTargetRequest` for the
standard target clone operation and complete list, detail, create,
clone, modify, and delete request types for both OCI-image and web-application
targets. The alternate-target requests directly own filters, saved-filter
identifiers, trash and task flags, image/URL collections, credential
relationships, ultimate deletion, and exact XML encoding.

Standard target cloning retains the baseline `create_target` capability. The
OCI-image and web-application request types keep their separate semantic intent
and their existing GMP 22.8 command gates, including clone requests encoded by
the respective creation command. Their named convenience methods accept the
same canonical request values and are thin `execute` wrappers. The redundant
options types, free builders, raw duplicate client signatures, and `_parsed`
aliases are removed. Raw `send`/`call` with literal XML remain the low-level
escape hatch without introducing a second typed encoding path.

## Generic configurations and port lists

Generic configurations retain separate list, detail, create, clone, modify,
and delete request values over the existing generic config builders. Port
lists now use complete canonical requests for that lifecycle plus create and
delete port ranges. The associated response is fixed for every operation,
including the action-shaped port-range responses. List/detail and create/clone
remain distinct semantic aliases over shared wire roots. The range request
owns its optional comment and uses gvmd's child-element payload; ports outside
1–65535 and descending ranges are rejected before support checks or transport.
The three redundant options types and eight free builders are removed; raw
`send`/`call` remains supported.

## Report formats

Report-format list, detail, import, clone, modify, delete, and verify use seven
explicit complete requests. Detail, import, and clone retain semantic aliases
over shared wire roots. The seven same-named `GmpClient` facades accept request
values and call `execute` directly; `GmpVersioned` uses generic
`execute(request)`. Unsupported name-only creation and all eight free builders
and two option bags are removed.

Import accepts one complete exported `get_report_formats_response` envelope.
The codec validates its framing and required identity/name without caching or
rebuilding it, then embeds the original bytes. Server-assigned replacement IDs
and collision-suffixed names are authoritative. Clone accepts only an optional
name and deliberately inherits upstream's omission of parameter-option rows.

Modify supports optional name, summary, active state, and one
`ReportFormatParamUpdate`. Paired empty name/summary elements preserve the
source's empty-text distinction. Parameter text is standard-base64 encoded
once; omission preserves, while missing/empty value clears and never means
reset-to-default. Upstream commits metadata before parameter validation, so a
compound failure can leave metadata changed.

Queries expose inline/saved filters, trash, details, params, alerts,
report-config associations, and pagination bypass. Params-only and details
expansions differ; alert/config expansions are independent. The typed response
keeps metadata/content/trust/active/predefined only. Delete may change the ID
when moving a non-predefined format to trash. Successful verify means the
check completed; read the format afterward to observe trust. See the
[pinned evidence](report-format-request-gvmd-evidence.md).

`ReportFormatType` remains standalone compatibility vocabulary. Its labels are
not format IDs, parameter types, or `scan`/`audit`/`all` report-type values and
are not used by lifecycle requests.

## TLS certificates

TLS certificates use six complete requests for list, detail, create, clone,
modify, and delete. The six named client methods accept those requests by
value and delegate directly to `execute`. Creation owns original PEM or DER
bytes, requires them to be nonempty, and standard-base64 encodes them exactly
once. Name is optional; omitted or empty name asks gvmd to use the SHA-256
fingerprint.

The lifecycle has no private-key input or certificate replacement. Clone may
copy a permitted foreign resource into the caller's collection, subject to
owner-scoped SHA-256/MD5 identity. Empty clone name/comment copies the source;
empty modify name/comment clears. Trust is an independent optional stored
boolean, not validity or chain verification. Deletion is permanent and
ID-only: TLS has no trash/restore lifecycle and `ultimate` is ineffective.

Certificate data is returned when details or `include_certificate_data` is
true, while observation sources require details. The typed response retains
wire base64 text and a bounded metadata projection; use raw execution for
format, serial, trust, time status, tags, permissions, or source graphs.
Request and response `Debug` output plus wire traces redact certificate data,
but raw responses and serde remain data-bearing. See the
[migration guide](typed-execution-migration.md#tls-certificate-lifecycle) and
[pinned evidence](tls-certificate-request-gvmd-evidence.md).

## Read-only system discovery

The system-discovery family adds semantic requests across aggregates, features,
feed, help, system-report, and remaining compatibility modules. #648 moves the
NVT/SecInfo roots to their owning modules and replaces the old
`get_vuln`/`get_vulnerability` wrappers with two direct canonical
`get_vulns` requests.

The associated response remains the established domain model. In particular,
the payload-free `get_license` response uses `ActionResponse`. Existing
typed-returning convenience methods for
aggregates, features, feeds, timezones, settings, system reports, help,
authentication description, and vulnerabilities are thin `execute` wrappers.

Version policy is unchanged. `GetFeaturesRequest` requires GMP 22.6 and
`GetTimezonesRequest` requires GMP 22.8; generic execution checks those semantic
command identities before writing to the transport. All other requests in this
read-only slice retain their existing baseline gates. Raw builders, `send`, and
`call` remain available without introducing another XML encoder.

## Irregular report codecs and version policy

The Phase 3 report family demonstrates that `GmpResponse` is a codec contract,
not a Serde constraint. Report list/detail responses, structured scan and audit
reports, report drill-downs, and both export styles all use `execute` while
retaining their existing explicit parsers:

```rust
use gvm_gmp::commands::reports::{
    GetReportExportOpts, GetReportExportRequest, GetReportVulnsRequest,
};

let export = client
    .execute(GetReportExportRequest::new(
        report_id.clone(),
        GetReportExportOpts::new(report_format_id),
    ))
    .await?;

let vulnerabilities = client
    .execute(GetReportVulnsRequest::new(report_id, Default::default()))
    .await?;
```

`ReportExport` accepts base64-encoded arbitrary bytes and the nested XML export
shape. Structured report parsers retain mixed/repeated element handling and
large responses remain subject to the same bounded transport frame limit as raw
execution. No report parser requires `DeserializeOwned`, and the entire response
is still returned as the request's associated type.

Report command availability is intentionally not inferred from the XML root
alone:

- structured audit reports and audit-report hosts require GMP 22.7;
- structured scan reports, report drill-downs, and synchronous report-format
  export require GMP 22.8;
- synchronous export uses `<get_reports ...>` on the wire but declares the
  semantic capability `get_report_export`;
- asynchronous `export_scan_report` was added without a distinct GMP version
  and therefore continues to require positive XML-help discovery.

`GmpClient::command_support` exposes the execution gate's actionable state.
It distinguishes a registered command that still needs discovery from an
unknown name, a version mismatch, and a completed discovery that omitted the
command. Execution reports the same distinctions as
`GvmError::CommandDiscoveryRequired`, `GvmError::UnsupportedCommand`, and
`GvmError::CommandNotAdvertised`, respectively. `CommandSupport::Supported`
only means that library version policy permits the operation and any required
server advertisement exists; authorization and command success are still
determined when gvmd executes it. Unknown names retain the raw `send`/`call`
escape hatch.

These checks run before transmission through the same `send` path used by raw
and ordinary typed requests. The retained raw builders and helpers remain
available when callers need unmodeled report details.

## Report mutations

Report creation and XML import use separate semantic request values even though
both delegate to the existing `<create_report>` builders and decode the same
typed create response. Import validation and payload encoding still happen in
the legacy builder before transmission. Ordinary and audit-report deletion are
likewise distinct semantic values over the established `<delete_report>` wire
shape and action response. The `import_report` convenience method is a thin
`execute` wrapper; raw builders and custom report XML remain supported.

## Scan configurations, policies, and preferences

Generic configurations, scan configurations, and policies share the
`get_configs`, `create_config`, `modify_config`, and `delete_config` wire roots.
Their lifecycle, preference, and selection requests own complete inputs and
direct encoding. Named
creation requires a source; clone may omit its name to request server-generated
naming. Import embeds one validated export document without reserialization:

```rust
use gvm_gmp::commands::scan_configs::{CreatePolicyRequest, GetPolicyRequest};

let created = client
    .execute(CreatePolicyRequest::new("Reviewed policy", base_config_id))
    .await?;

let policy = client
    .get_policy(GetPolicyRequest::new(created.id))
    .await?;
```

Canonical usage construction is deliberately limited to `Scan` and `Policy`.
List usage remains a literal server predicate, while ID-selected detail bypasses
usage and ordinary filter/pagination predicates. Families, preferences, and
tasks expand independently; policy `audits` maps to the wire `tasks` field.

Metadata requests contain only name/comment fields. Empty values are emitted
but are server no-ops, not clear operations, and raw usage children do not
modify usage. Imports accept an optional BOM/declaration, preserve the remaining
carrier bytes, and require one direct config with a name plus selector and
preference containers. Their Debug/errors/traces redact the carrier and
preference value/default/alternative data.

Preference list and single reads have distinct source-faithful typed responses;
a missing single match is `item: None`, and absent preference values remain
distinct from empty values. The eight scan-config/policy mutations encode
decoded preference values exactly once, distinguish delete from explicit empty,
and preserve ordered replacement/empty-clear semantics for NVTs and families.
Secret values are redacted from request diagnostics and wire traces. Use
`execute` for these operations; the redundant builders, options bag, and two
preference facades are removed. There is no canonical or facade `sync_config`:
the public schema names it, but pinned/current gvmd have no GMP dispatcher and
built-in mock modes return the source-shaped 400 response.

The compact response types tolerate rich expansion subtrees but are not export
models. Use raw `send`/`call` or a custom codec for complete exports and
deliberately unmodeled server XML. See the
[pinned evidence](scan-config-policy-request-gvmd-evidence.md).

See [ADR 0001](adr/0001-typed-request-response-execution.md) for ownership,
compatibility, error, and security decisions.
