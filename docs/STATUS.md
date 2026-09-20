# Implementation Status

Last updated: 2026-09-20

## Support Direction

rust-gvm is intended to track current GMP/GVMD behavior directly. python-gvm compatibility remains useful for migration, interoperability, and validation, but it is a secondary target rather than the project's product boundary.

See [ROADMAP.md](ROADMAP.md) for the version support stance, compatibility policy, known coverage gaps, and follow-up work.

## Crate Status

The Technology Preview client contains the completed additive typed
request/associated-response implementation tracked by issue #523, promoted
from the protected `next` integration lane to protected `main`. `GmpRequest`
binds a semantic request to one `GmpResponse`, and `GmpClient::execute`
preserves existing command gates, redacted tracing, parsing, and compatibility
APIs. Every current typed facade method is classified and integration-covered;
retained non-ticket helpers delegate to `execute`, and their implementation is
split into private resource-family modules without changing public paths. See
[ADR 0001](adr/0001-typed-request-response-execution.md) and the
[typed-execution guide](typed-execution.md). Downstream API selection,
compatibility, and release adoption are summarized in the
[migration notes](typed-execution-migration.md).

The unreleased additive request wrappers are now the transition baseline for
the canonical-request program in issue #602. [ADR 0002](adr/0002-canonical-request-ownership.md)
separates fallible typed validation/encoding from raw `Request`, fixes execution
precedence as validate → semantic support → encode → transport → decode, and
makes #602 a pre-release gate. The checked
[surface disposition ledger](canonical-request-disposition.md) currently tracks
all public options, builder, request, and typed-facade symbols. The standard
target family is the first converted reference slice: its six complete requests
own validation, semantic metadata, encoding, and response association, while
the three redundant options types and six free builders are removed. Its
[pinned gvmd evidence](target-request-gvmd-evidence.md) is recorded separately
from mock-server validation. Issue #609 applies that contract to all twelve
OCI-image and web-application target operations, removes their six redundant
options types, twelve free builders, raw duplicate client signatures, and
`_parsed` naming, and records separate
[alternate-target gvmd evidence](alternate-target-request-gvmd-evidence.md).
Issue #611 applies the same ownership contract to the six GMP 22.8 agent-group
operations. Their complete requests now own filters, identifiers, scheduler
data, repeated agent relationships, mutation fields, semantic aliases, and XML
encoding. Three options types and six forwarding builders are removed; the six
named client helpers accept the canonical requests unchanged. Independent
[agent-group gvmd evidence](agent-group-request-gvmd-evidence.md) records the
server contract.

Issue #613 converts the remaining eight GMP 22.8 agent operations to complete
canonical requests: list, detail, modify, delete, synchronize, agent-control
defaults, installer instructions, and support-bundle download. Three redundant
options types and eight forwarding builders are removed; `AgentConfigOpts`
remains as shared nested configuration used by both mutation requests. The
eight named client helpers accept the canonical values unchanged, and
[agent gvmd evidence](agent-request-gvmd-evidence.md) independently records the
wire contract and binary response behavior.

Issue #615 converts the three GMP 22.8 integration-configuration operations to
complete canonical requests. Two redundant options types, three free builders,
three raw duplicate client methods, and the `_parsed` aliases are removed. The
named methods now accept canonical list, detail, and replacement/clear request
values. Detail keeps its semantic alias over the list wire root; modifications
validate complete replacement fields while preserving the all-empty clear
operation and redacting service CA and OIDC secret values. Independent
[integration-configuration gvmd evidence](integration-config-request-gvmd-evidence.md)
records the list/detail, validation, and clear contracts.

Issue #617 converts all eight baseline GMP 22.4 port-list and port-range
operations to complete canonical requests. Three redundant options types and
eight free builders are removed; the named methods accept the canonical values
unchanged. List/detail and create/clone retain distinct semantic aliases over
shared roots, port-list modification keeps full-replacement semantics, and
invalid final ranges fail before support checks or transport. The range request
also corrects the legacy Rust attribute payload to gvmd's child-element wire
shape and now owns its optional comment. Independent
[port-list gvmd evidence](port-list-request-gvmd-evidence.md) records that
protocol correction and the server-side contracts.

Issue #620 converts the complete credential and credential-store family to
twelve canonical requests. Seven redundant options types and thirteen free
builders are removed; ten existing named facade helpers accept the canonical
values unchanged and delegate to `execute`. Credential autogeneration/type
requirements, store-backed Kerberos/SNMP fields, and final-value validation
follow pinned gvmd source.
Credential-store create/modify operations keep their distinct GMP 22.8
semantic identities over shared credential wire roots, and the detail request
corrects the legacy child selector to gvmd's documented
`credential_store_id` attribute. Passwords, keys, certificates, SNMP values,
vault/host identifiers, and store preferences are redacted from diagnostics
and wire traces. Independent
[credential gvmd evidence](credential-request-gvmd-evidence.md) records the
wire and validation contracts.

Issue #622 converts all six baseline filter operations to complete canonical
requests. Two redundant options types and six free builders are removed; the
six named facade methods accept request values unchanged. List/detail and
create/clone keep distinct semantic identities over their shared wire roots,
and final required names are validated before support checks or transport.
Pinned gvmd reconciliation removes the unsupported create/modify `sort_order`
child while adding supported rename, clone name/comment overrides, list alert
expansion, and explicit comment/term clearing. Independent
[filter gvmd evidence](filter-request-gvmd-evidence.md) records those contracts.

Issue #624 converts all six tag operations to complete canonical requests.
Two redundant options types and six free builders are removed; the six named
facade methods accept request values unchanged. Create and modify use reusable
resource selection/update values for required type, multiple IDs, filters, and
add/set/remove actions. Pinned gvmd reconciliation adds list `names_only`,
clone overrides, rename, and explicit comment/value clearing; removes the
unsupported tag `severity` input; preserves policy-to-config wire mapping; and
rejects tag-on-tag resources before support checks or transport. Independent
[tag gvmd evidence](tag-request-gvmd-evidence.md) records those contracts.

Issue #627 converts all eight alert operations to complete canonical requests.
Three redundant options types and eight free builders are removed; the eight
named facade methods accept request values unchanged. Create requires gvmd's
final event, condition, and method values; clone supports name/comment
overrides; modify documents filter clearing on omission while preserving
omitted active state. Detail, clone, and report-trigger operations retain their
semantic aliases, and trigger remains associated with `GetReportsResponse`.
Alert data values are redacted from request diagnostics and wire traces.
Independent [alert gvmd evidence](alert-request-gvmd-evidence.md) records those
contracts.

Issue #602 converts all twelve role and permission lifecycle operations to
complete canonical requests. Role clone omission follows gvmd's deterministic
`<existing name> Clone <number>` generation, while explicit overrides remain
exact. Explicit clone-name collisions return 400 atomically before either the
role or eligible permissions are copied, while names held only by trashed roles
remain reusable. The stateful mock also maps a stored `Super` resource clear to
gvmd's 404 resource-find result and rolls back the whole modification. When the
same clear supplies a non-identity resource type, gvmd validates that type first,
returns 400, and likewise rolls back the accompanying comment update. Independent
[role/permission gvmd evidence](role-permission-request-gvmd-evidence.md)
records these contracts and the mock's bounded authorization model.

Issue #629 converts the six schedule operations to complete canonical
requests. Two redundant options types, eight free builders, and the duplicate
typed create/modify wrappers and facade methods are removed. `ScheduleInput`
remains the reusable recurrence model, with raw and typed construction
converging on `CreateScheduleRequest` and `ModifyScheduleRequest`. Final create
and modify values require non-empty iCalendar before support checks or
transport, matching the pinned gvmd handler even where the schema is looser.
Detail and clone retain semantic aliases, and clone exposes supported
name/comment overrides. Independent
[schedule gvmd evidence](schedule-request-gvmd-evidence.md) records those
contracts.

Issue #631 converts all seven scanner operations to complete canonical
requests. Two redundant options types and seven free builders are removed; the
seven named facade methods accept request values unchanged. Create owns gvmd's
required name, host, port, and scanner type, while create/modify/response
models now include relay host and port. Modify distinguishes omission from
explicit clearing for comment, CA certificate, credential relationship, and
relay. Final host, port, and relay shapes fail validation before support checks
or transport. Independent
[scanner gvmd evidence](scanner-request-gvmd-evidence.md) records those
contracts.

Issue #633 converts all twelve note and override operations to complete
canonical requests. Six redundant options types and twelve free builders are
removed; the twelve named facade methods accept request values unchanged.
Create now owns required NVT/text values, and override create/modify own gvmd's
required replacement severity. Modify models the server's replacement boundary:
omitted host, port, original severity, task, and result restrictions clear,
while omitted NVT and activation preserve. Final values fail validation before
support checks or transport, and the parser-ignored legacy note `orphan` child
is removed. Independent
[note/override gvmd evidence](note-override-request-gvmd-evidence.md) records
those contracts.

Issue #636 converts all twelve user and group operations to complete canonical
requests. Five redundant options types and twelve free builders are removed;
the twelve named facade methods accept request values unchanged. User create
and modify own roles, groups, host access, authentication source, and
secret-bearing password input, while collection updates distinguish preserving,
replacing, and clearing relationships. User modification requires the final
host-access value because gvmd replaces it on every modification. Group
modification similarly owns final name, comment, and membership values. Detail
and clone retain semantic aliases, final values fail validation before support
checks or transport, and password diagnostics and wire traces remain redacted.
Independent [user/group gvmd evidence](user-group-request-gvmd-evidence.md)
records those contracts. Issue #639 documents why the legacy delete-user
`ultimate` input is intentionally absent and provides the
[v0.7 user/group migration mapping](v0.7.0-migration.md#users-and-groups).

The report-configuration, report-format, TLS-certificate, and bounded
NVT/SecInfo children are complete. Report retrieval, exports, and
report-specific lean/delta behavior remain separately ordered families.

The sections below retain the bounded delivery history for each migrated
family.

The bounded canonical standard-task batch, tracked by
[`#659`](https://github.com/greenbone-hive/rust-gvm/issues/659), now gives
list/detail/create/clone/modify/delete/start/stop/resume complete request
values, direct codecs, fixed response associations, and request-by-value
facades. Final mutated values validate before support checks or transport;
observer users cannot be cleared implicitly by group updates; preference
values are redacted; and the stateful mock applies compound updates
transactionally while preserving report-producing action state. The removed
`hosts_ordering` request input is source drift, not a compatibility omission:
pinned gvmd neither parses it nor retains its task column. See the
[task gvmd evidence](task-request-gvmd-evidence.md) and
[v0.7 migration mapping](v0.7.0-migration.md#standard-tasks).

Issue #660 completes the remaining 16 task-family semantic operations:
import/container, agent-group, OCI/container-image, and web-application task
creation; `move_task`; and the audit list/detail/create/clone/modify/delete/
start/stop/resume lifecycle. Complete request values directly encode each
variant's actual shape, the GMP 22.8 gates remain attached to agent/OCI/web
semantic identities, move destinations are explicit, and audit usage identity
is preserved without emitting an unsupported modify child. All remaining task
option bags and forwarding builders are removed. The stateful mock covers each
creation shape, scanner/target relationships, move semantics, audit state,
observer coupling, and atomic rollback. See the
[specialized task/audit gvmd evidence](specialized-task-audit-request-gvmd-evidence.md)
and [v0.7 migration mapping](v0.7.0-migration.md#specialized-tasks-and-audits).

The earlier additive credential batches in #544 and #551 established typed
execution while retaining their builders and options. The bounded canonical
migration in #620 supersedes that transitional construction model for the
complete credential and credential-store family.

The scanner-focused Phase 2 batch, tracked by
[`#542`](https://github.com/greenbone-hive/rust-gvm/issues/542), migrates the
scanner list/get/create/clone/modify/delete/verify lifecycle. Scanner builders
remain the single byte-compatible encoders, and the existing convenience
methods remain additive wrappers over generic typed execution. Scan
configurations were handled by a separate batch because they include larger
and more specialized command surfaces.

The additive scan-config/policy Phase 2 batch, tracked by
[`#549`](https://github.com/greenbone-hive/rust-gvm/issues/549), established
semantic wrappers. Issue [#649](https://github.com/greenbone-hive/rust-gvm/issues/649)
supersedes its lifecycle portion with 24 complete direct-codec requests over
the four shared config roots and 20 request-by-value facades. Named creation
requires an explicit base; clone inherits hidden selector/preference state;
import validates one exported config and policy import adds an outer policy
override. Metadata changes only nonempty names/comments, and canonical usage
is restricted to scan/policy. The unsupported schema-only `sync_config`
request and both sync facades are removed. Preference retrieval and the eight
configured preference/NVT/family mutation requests are completed by
[#658](https://github.com/greenbone-hive/rust-gvm/issues/658) as ten canonical
direct codecs with distinct scan-config/policy metadata, source-faithful
list/single responses, secret-safe diagnostics/traces, and atomic bounded mock
behavior. Their redundant builders, preference options bag, and two preference
facades are removed. Raw `send`, `call`, and custom codecs remain available.

The earlier additive alert-and-schedule Phase 2 batch, tracked by
[`#555`](https://github.com/greenbone-hive/rust-gvm/issues/555), migrates every
public alert and schedule builder to semantic typed execution. Alert list,
detail, create, clone, modify, delete, test, and report-trigger operations keep
their established response shapes, including the report response returned by
triggering. Schedule list, detail, create, clone, modify, and delete retain both
raw compatibility options and typed recurrence input. Existing builders remain
the sole wire encoders and all facade helpers delegate to generic execution.
The bounded canonical alert migration in #627 and schedule migration in #629
supersede both transitional construction models.

The supporting-resource Phase 2 batch, tracked by
[`#557`](https://github.com/greenbone-hive/rust-gvm/issues/557), migrates the
complete filter and tag list/detail/create/clone/modify/delete lifecycles plus
trashcan empty and restore operations. Existing builders remain the sole wire
encoders, both restore builder names retain byte-identical behavior through
distinct semantic request values, and all facade helpers delegate to generic
typed execution without changing response or version policy.

The note-and-override Phase 2 batch, tracked by
[`#559`](https://github.com/greenbone-hive/rust-gvm/issues/559), migrates both
complete list/detail/create/clone/modify/delete lifecycles. The list/detail and
create/clone pairs remain distinct semantic request types despite sharing wire
roots and response models. Existing builders remain the sole XML encoders,
including optional relationship fields, omit/replace/clear host updates, and
ultimate-delete behavior; all facade helpers delegate to generic execution.

The identity-and-permission Phase 2 batch, tracked by
[`#561`](https://github.com/greenbone-hive/rust-gvm/issues/561), migrates the
complete user, group, role, and permission list/detail/create/clone/modify/delete
lifecycles. Each semantic request delegates to its existing builder, preserving
user authentication, role, host-access, and relationship-update shapes while
the facade methods delegate to generic typed execution. Existing raw builders,
response models, and compatibility APIs remain supported.

Issue [#648](https://github.com/greenbone-hive/rust-gvm/issues/648)
supersedes the additive NVT-and-SecInfo wrappers from #563. Nineteen complete
canonical requests now own their public fields, validation, semantic metadata,
direct encoding, and response association; their facades take those requests
unchanged. Redundant options, builders, wrappers, and unsupported SecInfo OS
and vulnerability facades are removed. Pinned `get_info` dispatch supports
only CERT-Bund, CPE, CVE, DFN-CERT, and NVT; operating-system assets remain in
the asset family and observed vulnerabilities use `get_vulns`. Source-shaped
`<info>` parsing, NVT family/solution parsing, scanner-preference boundaries,
preference diagnostics/trace redaction, and a bounded stateful mock are covered
by the [NVT/SecInfo evidence](nvt-secinfo-request-gvmd-evidence.md).

The asset family is canonicalized under
[`#642`](https://github.com/greenbone-hive/rust-gvm/issues/642): thirteen
generic asset, host, and operating-system-asset requests own complete inputs,
validation, semantic metadata, direct encoding, and response associations.
Reads require a type and expose filters, details, and pagination control without
asset trash. Direct creation requires one IPv4 or IPv6 host name; modification
replaces or clears the host comment; deletion is permanent without an
`ultimate` mode. The unsupported OS-modification request, builder, and facade
are removed. Asset OS remains distinct from deferred SecInfo OS. See the
[pinned evidence](asset-request-gvmd-evidence.md).

Issue #643 completes the result child of the asset/results group: the plural
and discoverable detail requests now own all eight supported query controls,
final-value validation, semantic metadata, direct encoding, and their shared
`GetResultsResponse`. The redundant `GetResultsOpts` and two public free
builders are removed; both named facade methods accept canonical requests
unchanged. Root task context remains distinct from task/report filter
selection, expansion richness remains distinct from inclusion and override
application, and counts may be absent. Result names are optional in the
source-shaped response parser. Nested expansion payloads remain outside the
typed `ScanResult` projection. See the
[pinned result evidence](result-request-gvmd-evidence.md).

Issue #645 completes the report-configuration lifecycle child. Six explicit
canonical requests own list/detail/create/clone/modify/delete input, final-value
validation, semantic metadata, exact encoding, and response association. The
nine public free builders, four option bags, three option-bearing wrappers,
three redundant facades, and five raw `Gmp226Commands` methods are removed.
Direct create now emits `<report_format id="..."/>`; query pagination/sorting
uses filter text; and ordered parameter updates distinguish omission, explicit
empty values, and per-name reset. The parser accepts orphaned ID-only format
references while retaining its bounded metadata/association projection. The
stateful mock adds seeded format dependencies, transactional lifecycle
semantics, clone naming, query controls/counts, and the pinned orphan-modify
regression. Source/schema findings, mock validation, and the absence of
live-gvmd validation are separated in the
[pinned evidence](report-config-request-gvmd-evidence.md).

Issue #646 completes the report-format lifecycle child. Seven explicit
canonical requests own list/detail/import/clone/modify/delete/verify input,
final-value validation, semantic aliases, exact encoding, and response
association. Unsupported name-only creation, eight builders, two option bags,
and its facade are removed. Import validates one exported response envelope
while preserving its bytes; modification base64-encodes one decoded parameter
value and retains upstream's possible metadata partial commit. The parser keeps
a bounded metadata/trust projection. The stateful mock adds inert import data,
clone-option omission, query expansions/counts, changing trash IDs, deletion
guards/orphan behavior, and injected verification outcomes without claiming
GPG or filesystem behavior. Source/schema findings, mock validation, and the
absence of live-gvmd validation are separated in the
[pinned evidence](report-format-request-gvmd-evidence.md).

The additive alternate-target Phase 2 batch, tracked by
[`#567`](https://github.com/greenbone-hive/rust-gvm/issues/567), originally
introduced semantic wrappers for OCI-image and web-application targets. The
canonical follow-up in
[`#609`](https://github.com/greenbone-hive/rust-gvm/issues/609) replaces those
wrappers with complete list/detail/create/clone/modify/delete request values.
They directly own filters, relationship fields, mutation behavior, semantic
aliases, exact XML, and their GMP 22.8 gates. The clean named facade methods
accept the same canonical values and delegate to `execute`; literal XML remains
available through raw `send` and `call`.

The agent-and-integration Phase 3 batch, tracked by
[`#568`](https://github.com/greenbone-hive/rust-gvm/issues/568), migrates all 17
public agent, agent-group, and integration-configuration builders to semantic
typed execution. Existing agent and agent-group typed helpers and the parsed
integration helpers now delegate to `execute`, while the raw integration
methods, builders, and response models remain supported. All requests preserve
their GMP 22.8 pre-send gate, and installer instructions, identifier
collections, integration secrets, and binary/base64 support bundles retain
their established wire and decoding behavior.

The canonical follow-up in
[`#611`](https://github.com/greenbone-hive/rust-gvm/issues/611) replaces the
agent-group wrappers with complete list/detail/create/clone/modify/delete
requests and removes that family's options types and free builders. Named
client helpers now accept those request values directly; agent CRUD,
integration configurations, and specialized task creation remain separate.
Issues
[`#613`](https://github.com/greenbone-hive/rust-gvm/issues/613) and
[`#615`](https://github.com/greenbone-hive/rust-gvm/issues/615) subsequently
canonicalize the agent and integration-configuration surfaces while leaving
specialized task creation in the task family.

The generic-configuration and port-list Phase 3 batch, tracked by
[`#572`](https://github.com/greenbone-hive/rust-gvm/issues/572), migrates all
generic configuration list/detail/create/clone/modify/delete operations and the
complete port-list and port-range lifecycle to semantic typed execution.
Existing builders remain the single encoders, all established typed helpers
delegate to `execute`, and additive detail, clone, delete, and port-range
helpers expose protocol operations that were already available as builders.

The earlier report-configuration, report-format, and TLS-certificate Phase 3 batch,
tracked by [`#573`](https://github.com/greenbone-hive/rust-gvm/issues/573),
migrated 23 builders to additive semantic typed execution. Issues #645 and
#646 supersede the report-configuration and report-format wrappers, and #647
supersedes the TLS-certificate wrappers, with complete canonical requests.
TLS creation now owns original PEM/DER bytes and standard-base64 encodes them
once. Unsupported private-key input, certificate replacement, trash,
`ultimate`, ownership, and ineffective pagination-bypass controls are absent.
All six named TLS helpers accept complete requests and delegate to `execute`.
The [pinned evidence](tls-certificate-request-gvmd-evidence.md) records source,
schema, bounded response, and mock limits.

Issue #663 completes core and read-only system discovery. Pre-authentication
version/authentication, help, features, feeds/timezones, current and legacy
aggregates, settings, system reports, resource names, license retrieval, and
authentication description now have one authoritative encoder each. Complete
request values own every supported selector and query control; named facades
accept them unchanged and delegate only to `execute`. Authentication supports
password and token credentials plus requested-token responses while Debug,
errors, diagnostics, and wire traces redact credentials. `get_features`
retains its GMP 22.6 pre-transport gate and `get_timezones` its GMP 22.8 gate.
Responses preserve optional feed/system metadata, setting counts and
certificate information, resource-name response type, session metadata, and
structured license content. Duplicate builders, system wrappers, and
byte-identical facade aliases are removed with zero transitional ledger rows
in scope. See the
[pinned evidence](system-discovery-request-gvmd-evidence.md). Mutations, user
settings, wizard execution, and trashcan cleanup remain deferred to #664.

The system-administration Phase 3 batch, tracked by
[`#575`](https://github.com/greenbone-hive/rust-gvm/issues/575), migrates all
nine public authentication, license, wizard, and user-setting builder shapes to
semantic typed execution. The default and option-bearing compatibility forms
remain distinct request types over the existing byte-identical encoders, and
the system-module `modify_setting` wrapper continues to share the canonical
user-setting encoding. Existing authentication, license, and wizard typed
helpers now delegate to `execute`. Semantic request diagnostics redact auth
configuration values, license payloads, wizard parameter values, and
user-setting values; raw builders and custom execution remain supported.

Issues #661 and #662 complete the report lifecycle, structured-report,
drill-down, and export request migration. The lifecycle operations plus all
nine projections, synchronous report-format export, and asynchronous export
creation/reuse now own complete canonical values. Pinned gvmd has no empty
report-creation form, so validated report import remains the sole creation
operation.

Ordinary, audit-list, structured scan, structured audit, and audit-host
responses retain separate associations and explicit parsers for nested,
mixed, repeated, binary/base64, absent-field, and large bounded report data.
Projection and synchronous-export operations require GMP 22.8;
`export_scan_report` requires positive XML-help discovery. Duplicate
vulnerability names, `_parsed` suffixes, raw projection facades, and forwarding
option variants are removed. Delta/alert-selected generation and streaming
redesign remain separate work. See the
[pinned evidence](report-request-gvmd-evidence.md).

| Crate | Status | Lines | Tests | Description |
|-------|--------|-------|-------|-------------|
| `gvm-protocol` | ✅ Implemented | ~2,330 | 67 | XML command builder, response parser, streaming reader |
| `gvm-mock-server` | ✅ Implemented | ~5,850 | 266 | Programmable mock GMP server |
| `gvm-connection` | ✅ Implemented | ~1,500 | 45+ | Async Unix socket, verified TLS/mTLS, and SSH transports |
| `gvm-gmp` | ✅ Implemented | ~19,800 | 838 | Typed GMP command builders and response models |
| `gvm-client` | ✅ Implemented | ~3,590 | 62 | High-level async client with version negotiation and typed methods |

**Total: ~32,640 lines of Rust, 1,278 tests**

Canonical schedule create/modify requests support typed first-run input and
once, hourly, daily, weekly, and yearly recurrence, or raw iCalendar through
the same request types. Schedule observations expose normalized typed
first-run/next-run timestamps reported by gvmd and distinguish floating or
`TZID`-qualified starts, recurrence dates, exclusions, and unsupported recurrence
rules from one-time schedules; raw iCalendar remains available for compatibility.
Raw create follows gvmd's default-timezone behavior, and raw modify requires an
iCalendar payload.

Target create and modify inputs use validated `TargetHost` values inside a
non-empty `TargetHosts` aggregate. The aggregate de-duplicates canonical values
across alternate address/network/range spellings and makes included/excluded
modify updates atomic. It can test whether exclusions cover every included
specification without expanding networks, using gvmd's usable-address treatment
for CIDRs; trailing-dot hostnames remain distinct from undotted hostnames.
IPv4 and IPv6 addresses, CIDR networks, address ranges, and ASCII hostnames are
rejected locally when malformed; IPv4 leading zeroes are normalized like gvmd,
and CIDR prefixes follow gvmd's `/1` through `/30` restriction. Unicode hostname
case-fold lookalikes are intentionally outside the typed API's accepted hostname
policy. DNS resolution and deployment policy, including gvmd's configured maximum
IP count, remain server-side. Typed creation models manual hosts; the stateful raw
mock also resolves gvmd-style `asset_hosts` filters, with filter precedence over a
supplied manual host list.
The same strict filter evaluator drives `get_assets` and target resolution,
including quoted values, relations, sorting, and pagination. Raw mock target
storage applies gvmd-style trimming, separator cleanup, and exact textual
de-duplication without rewriting otherwise valid host spellings.

---

## gvm-protocol

### XmlCommand Builder

| Feature | Status | Notes |
|---------|--------|-------|
| Command with attributes | ✅ | `XmlCommand::new("get_tasks").attr("task_id", "...")` |
| Child elements with text | ✅ | `.add_element("name").text("My Task")` |
| Child elements with attributes | ✅ | `.add_element("target").attr("id", "...")` |
| Nested children | ✅ | Arbitrary depth |
| XML escaping | ✅ | `&`, `<`, `>`, `"` in text and attributes |
| Filter string helper | ✅ | `.filter_string("name=foo")` |
| Serialization to bytes | ✅ | `.to_bytes()` |

### Response Parser

| Feature | Status | Notes |
|---------|--------|-------|
| Status code extraction | ✅ | `response.status_code()` → `Option<u16>` |
| Status text extraction | ✅ | `response.status_text()` → `Option<String>` |
| Success check | ✅ | `response.is_success()` → 2xx range |
| Resource ID extraction | ✅ | `response.id()` for create responses |
| Child text extraction | ✅ | `response.child_text("version")` |
| Root element name | ✅ | `response.root_element_name()` |
| Raw bytes access | ✅ | `response.data()` / `response.as_str()` |
| Raise for status | ✅ | `response.raise_for_status()` → Result |

### XmlReader (Streaming Framing)

| Feature | Status | Notes |
|---------|--------|-------|
| Self-closing elements | ✅ | `<get_version/>` |
| Elements with children | ✅ | `<get_tasks_response>...</get_tasks_response>` |
| Chunked delivery | ✅ | Feed partial data, detect completion |
| Nested same-name elements | ✅ | `<report><report>...</report></report>` |
| Exact frame boundaries | ✅ | Preserve coalesced bytes for the next response |
| Input size limit | ✅ | 64 MiB per frame by default; configurable |
| Nesting limit | ✅ | 256 elements per frame by default; configurable |
| Strict XML 1.0 checks | ✅ | Reject malformed declarations, names, references, and forbidden literals |
| Reset for reuse | ✅ | `reader.reset()` |

---

## gvm-mock-server

### Server Modes

| Mode | Status | Description |
|------|--------|-------------|
| Echo | ✅ | Generic well-formed responses |
| Fixture | ✅ | Realistic pre-built XML responses |
| Stateful | ✅ | In-memory CRUD with auth |
| Scenario | ✅ | Scripted request→response playback |

### Builder API

| Feature | Status | Notes |
|---------|--------|-------|
| Mode selection | ✅ | `.mode(ServerMode::Stateful)` |
| Version configuration | ✅ | Defaults to `V22_7`; explicit 22.4–22.8 emulation remains available |
| Unix socket (path) | ✅ | `.unix_socket("/tmp/gvmd.sock")` |
| Unix socket (auto temp) | ✅ | `.unix_socket_auto()` |
| TCP listener | ✅ | `.tcp("127.0.0.1:9390")` |
| TLS listener | ✅ | `.tls("127.0.0.1:9390")`; generated certificate exposed for pinning |
| Mutual TLS | ✅ | `.require_client_cert("client-ca.pem")` |
| Credentials | ✅ | `.credentials("admin", "admin")` |
| Fixture overrides | ✅ | `.override_response("get_tasks", xml)` |
| Pre-seeding | ✅ | `.seed(\|store\| { ... })` |
| Fault injection | ✅ | `.inject_fault(Fault::once(FaultKind::Disconnect))` |
| Scenario steps | ✅ | `.scenario_step(ScenarioStep { ... })` |

### Stateful CRUD

| Resource Type | Create | Get (single) | Get (list) | Modify | Delete | Clone |
|---------------|--------|-------------|-----------|--------|--------|-------|
| task | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| target | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| config | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| scanner | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| alert | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| credential | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| filter | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| note | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| override | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| port_list | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| report | ✅ | ✅ (nested) | ✅ | ✅ | ✅ | ✅ |
| schedule | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| tag | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ticket | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| user | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| role | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| asset | ✅ | ✅ | ✅ (by type) | ✅ | ✅ | ✅ |
| result | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| nvt | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Task Lifecycle

| Transition | Status |
|-----------|--------|
| New → Running (start_task) | ✅ |
| Running → Stopped (stop_task) | ✅ |
| Stopped → Running (resume_task) | ✅ |
| Start creates report resource | ✅ |
| Start returns report_id | ✅ |
| Conflict detection (already running, etc.) | ✅ |

### Special Handlers

| Feature | Status | Notes |
|---------|--------|-------|
| get_version (pre-auth) | ✅ | Always allowed without authentication |
| authenticate (credential validation) | ✅ | Per-session state |
| direct-host asset lifecycle and canonical `get_assets` | ✅ | Strict gvmd behavior by default; legacy flat inputs are explicit opt-in; report import creates or updates host assets only when requested |
| result list/detail conformance | ✅ | Bounded saved/inline filter, effective task context, resolved pagination/counts, ID-tied sorting, task-restricted expansions, and effective seeded override behavior; unsupported or malformed terms are explicit and the full gvmd filter/permission/CVSS engine is not modeled |
| report lifecycle | ✅ | Import-task validation, XML/result/asset persistence, scan/audit selection, list/detail filters, pagination/counts, dependency-safe permanent deletion, and atomic rollback |
| get_report (nested results XML) | ✅ | Proper `<report><report><results>` nesting with explicit parser preservation |
| structured audit reports (22.7+) | ✅ | Typed summaries and hosts with compliance filtering, pagination, details, and lean output |
| create_note/override (text + nvt_oid) | ✅ | Non-standard element parsing |
| create_ticket (result_id + comment) | ✅ | Non-standard element parsing |
| modify_ticket (status attribute) | ✅ | Ticket-specific handling |
| Trash/restore/empty_trashcan | ✅ | Full trashcan lifecycle |
| Task schedule relationships | ✅ | Stateful create/get persistence, schedule-period round trips, omit/set/clear modify semantics, reference validation, and dependency-safe deletion |

### Fault Injection

| Fault Type | Status |
|-----------|--------|
| Server error (500) | ✅ |
| Custom error status + message | ✅ |
| Connection disconnect | ✅ |
| Response delay | ✅ |
| Malformed XML | ✅ |
| Truncated response | ✅ |

| Trigger | Status |
|---------|--------|
| Always | ✅ |
| Once | ✅ |
| After N commands | ✅ |
| On specific command | ✅ |
| Per-session isolation | ✅ |
| Multiple fault composition | ✅ |

### Fixture Library

| Category | Commands Covered |
|----------|-----------------|
| System | get_version, authenticate, help, get_timezones |
| Tasks | get_tasks, create_task, modify_task, delete_task, start_task, stop_task |
| Targets | get_targets |
| Reports | get_reports (with nested results), get_report_vulns, get_report_tls_certificates, get_report_errors, get_report_closed_cves |
| Configs | get_scan_configs |
| Scanners | get_scanners |
| Alerts | get_alerts |
| Credentials | get_credentials, get_credential_stores |
| Filters | get_filters |
| Notes | get_notes |
| Overrides | get_overrides |
| Port Lists | get_port_lists |
| Schedules | get_schedules |
| Tags | get_tags |
| Tickets | get_tickets |
| Users | get_users |
| Roles | get_roles |
| Error templates | 400, 401, 404, 409, 500 |

### Version Gating

| Feature | Status | Notes |
|---------|--------|-------|
| Version-specific command rejection | ✅ | Returns 400 for commands unavailable in configured version |
| `report_config` commands (22.6+) | ✅ | create, get, modify, delete |
| `features` command (22.6+) | ✅ | get_features |
| structured audit-report commands (22.7+) | ✅ | get_audit_report and get_audit_report_hosts |
| REST-support GMP helpers (22.8+) | ✅ | structured scan report, typed report drill-downs and synchronous export, get_timezones, get_credential_stores |
| Discoverable asynchronous report export | ✅ | `export_scan_report` requires positive XML-help discovery after its 22.7 lower bound |
| Version range metadata in responses | ✅ | Status text includes version requirement |

### CLI (Standalone Binary)

| Feature | Status |
|---------|--------|
| `--mode echo\|fixture\|stateful` | ✅ |
| `--version 22.4\|22.5\|22.6\|22.7\|22.8` | ✅ (22.7 default) |
| `--socket <path>` | ✅ |
| `--tcp <addr:port>` | ✅ |
| `--max-request-bytes <bytes>` | ✅ (64 MiB default) |
| XML nesting limit | ✅ (256 elements per frame; enforced across protocol, client, and mock readers) |
| `--tls <addr:port>` | ✅ (`tls` feature) |
| `--tls-client-ca <path>` | ✅ (`tls` feature) |
| `--tls-cert-out <path>` | ✅ (`tls` feature) |
| Cross-platform binaries | ✅ (5 targets in CI) |
| GHCR release image | ✅ `ghcr.io/clawosiris/gvm-mock-server:<tag>` |

---

## gvm-connection

### GvmConnection Trait

| Method | Status | Notes |
|--------|--------|-------|
| `connect()` | ✅ | Async, with timeout |
| `disconnect()` | ✅ | Graceful shutdown |
| `send(&[u8])` | ✅ | Write bytes to transport |
| `read() -> Vec<u8>` | ✅ | Uses `XmlReader` for frame detection |
| `is_connected()` | ✅ | Synchronous check |

### Transports

| Transport | Status | Feature Flag | Notes |
|-----------|--------|-------------|-------|
| Unix socket | ✅ | `unix` (default) | `UnixSocketConnection` with configurable path, timeout, buffer size |
| SSH tunnel | ✅ | `ssh` | `SshConnection` via `russh` — `direct-streamlocal` to remote gvmd socket |
| TLS (TCP) | ✅ | `tls` | `TlsConnection` via `tokio-rustls`, verified server SAN/roots, optional client identity |

### UnixSocketConfig

| Field | Default | Notes |
|-------|---------|-------|
| `path` | `/run/gvmd/gvmd.sock` | Configurable |
| `timeout` | 60s | Connect, request write/flush, and response-read timeout |
| `read_buffer_size` | 64 KB | Per-read allocation |

### SshConfig

| Field | Default | Notes |
|-------|---------|-------|
| `hostname` | `localhost` | SSH server address |
| `port` | 22 | SSH port |
| `username` | `root` | SSH user |
| `auth` | `Agent` | `Password`, `PrivateKey { key_path, passphrase }`, or `Agent` |
| `remote_socket` | `/run/gvmd/gvmd.sock` | Path to gvmd socket on remote host |
| `timeout` | 60s | Connect/auth/channel, request write/flush, and response-read timeout |
| `read_buffer_size` | 64 KB | Per-read allocation |
| `host_key_policy` | `KnownHosts` | Standard or custom `known_hosts`, pinned SHA-256 fingerprint, or explicit insecure opt-out |

### TlsConfig

| Field | Default | Notes |
|-------|---------|-------|
| `hostname` | `127.0.0.1` | TCP destination |
| `port` | 9390 | gvmd TLS port |
| `server_name` | Same as hostname | Required DNS/IP certificate SAN |
| `use_native_roots` | `true` | Platform trust store; disabling does not disable verification |
| custom roots | None | PEM roots can be supplied in memory or from a file |
| client identity | None | Optional PEM certificate chain plus unencrypted private key for mTLS |
| `timeout` | 60s | TCP connect, TLS handshake, request write/flush, and response-read timeout |
| `max_response_bytes` | 64 MiB | Bounded XML response size |

### Error Types

| Variant | Description |
|---------|-------------|
| `NotConnected` | Operation requires active connection |
| `AlreadyConnected` | Double-connect attempt |
| `ConnectFailed` | Transport-level connection error |
| `SendFailed` | Write error |
| `ReadFailed` | Read error or unexpected EOF |
| `Timeout` | Operation exceeded configured timeout |
| `InvalidConfiguration` | Trust roots, server name, or certificate/key material is unusable |
| `SocketNotFound` | Unix socket path does not exist |

### Integration Tests (against gvm-mock-server)

| Test | Status |
|------|--------|
| Connect + get_version | ✅ |
| Auth + create_target | ✅ |
| Reconnect flow (python-gvm pattern) | ✅ |
| Timeout invalidation and clean reconnect | ✅ |
| Not-connected error paths | ✅ |
| Double-connect error | ✅ |

Once an active transport returns a send or read error, it is invalidated. Callers
must reconnect before issuing another request; this prevents partial writes or
late responses from being associated with a later GMP command.

## gvm-gmp

Typed GMP command builders covering all entity types, system commands, and enums. Full rustdoc coverage.

### Target Port-List Updates

`ModifyTargetRequest::port_list_id` models omission and replacement with
`ScalarUpdate<EntityId>`. Current gvmd accepts a real port-list UUID when
replacing the relationship, but it does not define a sentinel or other wire
representation for detaching an existing port list. Consequently,
`ScalarUpdate::Clear` is rejected locally with
`GmpRequestError::InvalidField`; no capability check or GMP request is sent.

`CreateTargetRequest` requires a `TargetPortSelection`, enforcing a typed one-of
choice between an existing `<port_list>` and a validated direct `<port_range>`.
Raw GMP also permits both, with gvmd validating the range before giving the port
list precedence. Direct ranges support gvmd's implicit TCP and protocol
carry-forward grammar, and validate the `1..=65535` port domain and ascending
range bounds before canonical serialization.

### Target Credential Service Ports

`CreateTargetRequest` and `ModifyTargetRequest` expose the SSH service port next to
the credential relationship. `ServicePort` validates the gvmd-supported
range `1..=65535`; typed target observations reject zero, nonnumeric, and
out-of-range backend values instead of losing malformed data. Both list and
single-target client reads preserve effective default and custom ports.

This is an intentional pre-1.0 API break: create ports use
`Option<ServicePort>`, modify ports use `ScalarUpdate<ServicePort>`, and the
complete request remains mutable, and final-value validation prevents a port
without an SSH credential ID from reaching capability checks or transport. The
high-level client exposes the failure as `GvmError::Request`.

Modify requests distinguish leaving the binding untouched, setting or replacing
the port, resetting it to gvmd's default port 22, and detaching the credential.
The reset operation keeps gvmd's numeric sentinel internal to the command
encoder. The stateful mock mirrors these defaults and round trips SSH and SMB
credential identifiers, but rejects SMB service ports because current GMP/gvmd
only defines a nested port for the SSH credential. It also rejects create-time
detach sentinels and credential types that gvmd does not allow for SSH or SMB
target bindings.

The stateful mock also preserves target alive-test values. Stateful responses
and create/modify requests use gvmd's plural `alive_tests` field. The typed
request option remains named `alive_test` for source compatibility. Target
responses without an explicit alive-test value report `Scan Config Default`,
matching gvmd's observation behavior.

### Command Modules (29)

alerts, authentication, credentials, filters, groups, hosts, notes, nvts, overrides, permissions, port_lists, report_formats, reports, resource_names, results, roles, scan_configs, scanners, schedules, system, tags, targets, tasks, tickets, tls_certificates, trashcan, users, version

### Enums (22)

AlertEvent, AlertCondition, AlertMethod, AliveTest, AggregateStatistic, CredentialFormat, CredentialType, EntityType (34 variants), FeedType, FilterType (25 variants), HelpFormat, InfoType, PermissionSubjectType, PortRangeType, ReportFormatType, ScannerType, SeverityLevel, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm, SortOrder, TicketStatus, UserAuthType

### Tests

`cargo test -p gvm-gmp --all-features -- --list` currently discovers 701 tests.
The categories below are a tracked subset of that complete inventory.

| Tracked category | Count |
|------------------|-------|
| Inline unit tests (command XML) | 80 |
| External command tests | 54 |
| Enum exhaustive tests | 347 |
| EntityId/type tests | 6 |
| **Tracked subset** | **487** |

## gvm-client

High-level async `GmpClient<C>` and `GmpVersioned<C>` that combines `gvm-connection`, `gvm-protocol`, and `gvm-gmp`. Connects, negotiates GMP version (22.4–22.7+), and provides typed `send`/`call` methods.

### GmpClient API

| Method | Description |
|--------|-------------|
| `GmpClient::connect(connection)` | Connect, get_version, negotiate — returns ready client |
| `client.version()` | Returns negotiated `GmpVersion` |
| `client.command_support(name)` | Distinguishes supported, discovery-pending, version-rejected, not-advertised, and unknown commands |
| `client.discover_commands()` | Explicitly cache the server's XML-help command inventory |
| `client.send(request)` | Send request, return raw `Response` |
| `client.call(request)` | Send request, raise `GvmError::Server` on non-2xx |
| `client.disconnect()` | Graceful transport shutdown |
| `client.connection()` / `connection_mut()` | Borrow underlying transport |
| `client.into_inner()` | Consume client, return transport |

### GmpVersioned API

| Method | Description |
|--------|-------------|
| `GmpVersioned::connect(connection)` | Connect and wrap as version-specific variant |
| `send` / `call` / `disconnect` / `version` | Delegated to inner `GmpClient` |

### Version Negotiation

| Server Version | Client Variant |
|---------------|----------------|
| 22.4 | `GmpVersioned::V224` |
| 22.5 | `GmpVersioned::V225` |
| 22.6 | `GmpVersioned::V226` |
| 22.7 | `GmpVersioned::V227` |
| 22.8+ | `GmpVersioned::Next` |
| < 22.4 | `GvmError::UnsupportedVersion` |

### GvmError

| Variant | Description |
|---------|-------------|
| `Connection(ConnectionError)` | Transport failure (preserves source chain) |
| `Server { status, message }` | Non-2xx GMP response |
| `XmlParse(String)` | Malformed version/response XML |
| `Parse(ParseError)` | Typed response model parsing failure |
| `UnsupportedVersion(major, minor)` | Server GMP version too old |
| `UnsupportedCommand { .. }` | Registered command requires a newer GMP version |
| `CommandDiscoveryRequired { command }` | Registered command requires explicit XML-help discovery |
| `CommandNotAdvertised { command }` | Completed discovery omitted the registered command |
| `Timeout(Duration)` | Operation timeout |
| `InvalidState(String)` | Client state error |

### Typed Client Methods

Convenience methods on `GmpClient<C>` that execute semantic requests and return
typed responses in a single call. They are implemented in private resource-family
modules under `crates/gvm-client/src/typed/`; only the frozen ticket surface keeps
its explicit raw-send compatibility path.

| Domain | Get | Create | Notes |
|--------|-----|--------|-------|
| version | ✅ | — | `get_version(GetVersionRequest)` |
| auth | — | — | `authenticate(AuthenticateRequest)` |
| target | ✅ | ✅ | |
| scan_config | ✅ | ✅ | Complete requests cover lifecycle aliases plus preference reads/mutations and ordered NVT/family replacement; creation requires copy/import, and unsupported GMP sync is removed |
| scanner | ✅ | ✅ | Also: `get_scanner()`, `modify_scanner()`, `delete_scanner()`, `verify_scanner()`, `clone_scanner()` |
| port_list | ✅ | ✅ | |
| task | ✅ | ✅ | Also: `start_task()` |
| report | ✅ | ✅ | Canonical lifecycle/structured operations, nine drill-downs, synchronous export, and discoverable asynchronous export; import is gvmd's report creation form |
| result | ✅ | — | |
| feed | ✅ | — | |
| nvt | ✅ | — | Also: `get_nvt_families()` |
| secinfo | ✅ | — | CVE, CPE, CERT-Bund, DFN-CERT |
| alert | ✅ | ✅ | |
| credential | ✅ | ✅ | Also: `get_credential_stores()` |
| filter | ✅ | ✅ | |
| note | ✅ | ✅ | |
| override | ✅ | ✅ | |
| schedule | ✅ | ✅ | |
| tag | ✅ | ✅ | |
| ticket | ✅ | ✅ | |
| user | ✅ | ✅ | |
| group | ✅ | ✅ | |
| role | ✅ | ✅ | |
| permission | ✅ | ✅ | |
| host | ✅ | ✅ | |
| tls_certificate | ✅ | ✅ | |
| report_format | ✅ | ✅ | Seven canonical lifecycle facades; direct creation means explicit import or clone |
| report_config | ✅ | ✅ | Six canonical lifecycle facades; list is `get_report_configs(request)` |
| system | ✅ | — | Canonical request values cover settings, help, features, aggregates, system reports, resource names, license, authentication description, feeds, and timezones |

### Features

| Feature | Status |
|---------|--------|
| Auto version negotiation | ✅ |
| `GmpVersioned` enum (V224–VNext) | ✅ |
| `GvmError` with server/connection/parse/timeout/unsupported | ✅ |
| Typed convenience methods (50+ methods, all GMP domains) | ✅ |
| Version parsing from XML | ✅ |
| Full CRUD lifecycle tests | ✅ |
| Disconnect + error path tests | ✅ |
| Works with Unix socket transport | ✅ |
| Works with SSH transport | ✅ |
| Works with verified TLS and mTLS transports | ✅ |

---

## Test Coverage

**Line coverage: 95.4%** (via `cargo-llvm-cov`)

| Test Category | Count | Notes |
|---------------|-------|-------|
| Unit tests (protocol) | 37 | XML builder, response parser, reader, request trait |
| Unit tests (mock server) | 73 | Store, parser, fixtures, faults, scenarios, history, version, util |
| Integration tests (mock server) | 137 | All modes, CRUD, lifecycle, faults, MCP compat (feature-gated) |
| Integration tests (connection) | — | Unix socket + SSH + verified TLS/mTLS transport tests (feature-gated) |
| Unit tests (connection) | — | Config, error display, and construction coverage |
| Unit tests (gvm-gmp inline) | 80 | Command builder XML verification |
| External tests (gvm-gmp) | 53 | Per-module command XML tests |
| Enum exhaustive tests | 347 | Every variant as_gmp_str + FromStr + invalid |
| Type tests (EntityId) | 6 | Validation, Display, Hash, FromStr |
| Unit tests (gvm-client) | 7 | Version parsing and negotiation |
| Integration tests (gvm-client) | 6 | Version negotiation, CRUD lifecycle, error paths (feature-gated) |
| Python integration tests | 15 steps | python-gvm full lifecycle against mock server |
| **Total** | **620+ tests** | |

### Per-File Coverage

| File | Coverage |
|------|----------|
| `history.rs` | 100% |
| `version.rs` | 100% |
| `request.rs` | 100% |
| `xml_command.rs` | 99.6% |
| `handler.rs` | 88.3% |
| `builder.rs` | 80.8% |

## CI Pipelines

| Pipeline | Status | Jobs |
|----------|--------|------|
| CI (push/PR) | ✅ | fmt, clippy, test, test-all-features, doc, deny, coverage, MSRV, python-gvm |
| Security | ✅ | cargo-audit, cargo-machete |
| Nightly | ✅ | Full CI + 5-target cross-platform builds + SBOM generation + sbomqs quality gate |
| Release | ✅ | Full test → 5-target builds → SBOM + sbomqs → GitHub Release |

## SBOM Quality

SBOMs are generated by `cargo-cyclonedx` (CycloneDX 1.5 JSON + XML) and post-processed via `scripts/sbom_postprocess.py`:
- CC0-1.0 data license in document metadata
- Build lifecycle phase (`build`)
- Supplier hints: workspace crates → `clawosiris`, crates.io deps → `crates.io`

Quality gate: **sbomqs ≥ 7.0** enforced in CI (nightly + release).

## Security

- **SECURITY.md** — vulnerability reporting via GitHub Private Security Advisories
- **cargo-audit** — RustSec advisory database checks (weekly + on push)
- **cargo-deny** — license compliance, bans, source restrictions
- **Dependabot** — automated dependency updates (Cargo, pip, GitHub Actions)
- **cargo-machete** — unused dependency detection
