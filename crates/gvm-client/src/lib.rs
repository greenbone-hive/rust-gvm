// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! High-level async GMP client with version negotiation.
//!
//! Combines [`gvm_connection`], [`gvm_protocol`], and [`gvm_gmp`] into a
//! single client that connects, negotiates the GMP version, and provides
//! typed access to all GMP commands.
//!
//! Opt-in wire tracing on [`GmpClient`] observes redacted request and response
//! XML at the client boundary. This is separate from GMP `details` flags, which
//! are request parameters that ask gvmd for more or less resource detail.

#![forbid(unsafe_code)]

mod error;
mod typed;
mod version;
mod wire_trace;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use gvm_connection::GvmConnection;
use gvm_gmp::commands::agent_groups::{
    CloneAgentGroupRequest, CreateAgentGroupRequest, DeleteAgentGroupRequest, GetAgentGroupRequest,
    GetAgentGroupsRequest, ModifyAgentGroupRequest,
};
use gvm_gmp::commands::agents::{
    DeleteAgentRequest, GetAgentInstallerInstructionRequest, GetAgentRequest,
    GetAgentSupportBundleRequest, GetAgentsRequest, ModifyAgentControlScanConfigRequest,
    ModifyAgentRequest, SyncAgentsRequest,
};
use gvm_gmp::commands::credentials::{
    CreateCredentialStoreCredentialRequest, GetCredentialStoreRequest, GetCredentialStoresRequest,
    ModifyCredentialStoreCredentialRequest, VerifyCredentialStoreRequest,
};
use gvm_gmp::commands::features::get_features;
use gvm_gmp::commands::help::help_with_mode;
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, GetIntegrationConfigsRequest, ModifyIntegrationConfigRequest,
};
use gvm_gmp::commands::oci_image_targets::{
    CloneOciImageTargetRequest, CreateOciImageTargetRequest, DeleteOciImageTargetRequest,
    GetOciImageTargetRequest, GetOciImageTargetsRequest, ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::reports::{
    export_scan_report, get_report_applications, get_report_closed_cves, get_report_cves,
    get_report_errors, get_report_hosts, get_report_operating_systems, get_report_ports,
    get_report_tls_certificates, get_report_vulns, get_scan_report, GetScanReportRequest,
};
use gvm_gmp::commands::system::get_timezones;
use gvm_gmp::commands::tasks::{
    CreateAgentGroupTaskRequest, CreateContainerImageTaskRequest, CreateOciImageTargetTaskRequest,
    CreateWebApplicationTaskRequest,
};
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, CreateWebApplicationTargetRequest,
    DeleteWebApplicationTargetRequest, GetWebApplicationTargetRequest,
    GetWebApplicationTargetsRequest, ModifyWebApplicationTargetRequest,
};
use gvm_gmp::responses::{
    CloneAgentGroupResponse, CreateAgentGroupResponse, CreateCredentialResponse,
    CreateOciImageTargetResponse, CreateTaskResponse, CreateWebApplicationTargetResponse,
    DeleteAgentGroupResponse, DeleteAgentResponse, DeleteOciImageTargetResponse,
    DeleteWebApplicationTargetResponse, GetAgentGroupsResponse,
    GetAgentInstallerInstructionResponse, GetAgentSupportBundleResponse, GetAgentsResponse,
    GetCredentialStoresResponse, GetIntegrationConfigsResponse, GetOciImageTargetsResponse,
    GetScanReportResponse, GetWebApplicationTargetsResponse, HelpResponse,
    ModifyAgentControlScanConfigResponse, ModifyAgentGroupResponse, ModifyAgentResponse,
    ModifyCredentialResponse, ModifyIntegrationConfigResponse, ModifyOciImageTargetResponse,
    ModifyWebApplicationTargetResponse, SyncAgentsResponse, VerifyCredentialStoreResponse,
};
use gvm_gmp::types::{EntityId, GmpVersion};
use gvm_protocol::{Request, Response};
use wire_trace::redact_wire_bytes;

pub use error::GvmError;
pub use gvm_gmp::commands::agents::{
    AgentConfigOpts, AgentControlConfig, AgentHeartbeatConfig, AgentInstallerLanguage,
    AgentRetryConfig, AgentScriptExecutorConfig,
};
pub use gvm_gmp::commands::aggregates::{
    AggregateMode, AggregateSort, AggregateSortStatistic, GetAggregatesRequestOpts,
};
pub use gvm_gmp::commands::help::HelpMode;
pub use gvm_gmp::commands::reports::{
    ExportScanReportOpts, GetAuditReportHostsOpts, GetAuditReportOpts, GetReportDetailsOpts,
    GetReportExportOpts, GetScanReportOpts, ImportReportOpts,
};
pub use gvm_gmp::commands::system_reports::GetSystemReportsOpts;
pub use gvm_gmp::commands::usage_type::UsageType;
pub use gvm_gmp::enums::{CredentialStoreCredentialType, FeedType};
pub use gvm_gmp::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpResponse};
pub use version::{
    command_supported, map_supported_version, minimum_version_for_command, parse_version_text,
    required_version_label,
};

/// The client's current knowledge of whether a registered GMP command can be
/// attempted.
///
/// This classification combines the negotiated GMP version, rust-gvm's
/// command registry, and cached XML-help discovery. [`Self::Supported`] means
/// that library version policy permits the command and, when required, the
/// server advertised it. It does not guarantee authorization or successful
/// execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "command support states require different caller actions"]
#[non_exhaustive]
pub enum CommandSupport {
    /// Library policy permits the command and any required discovery succeeded.
    Supported,
    /// The command is version-permitted but requires [`GmpClient::discover_commands`].
    RequiresDiscovery,
    /// The negotiated server version is older than the command's minimum.
    UnsupportedVersion {
        /// Minimum GMP version required by the command.
        required: GmpVersion,
    },
    /// Discovery completed, but the server did not advertise the command.
    NotAdvertised,
    /// The name is absent from rust-gvm's command and semantic-alias registry.
    ///
    /// Unknown names remain permitted through raw [`GmpClient::send`] and
    /// [`GmpClient::call`] for forward-compatible custom commands.
    UnknownCommand,
}

impl CommandSupport {
    const fn legacy_option(self) -> Option<bool> {
        match self {
            Self::Supported => Some(true),
            Self::UnsupportedVersion { .. } | Self::NotAdvertised => Some(false),
            Self::RequiresDiscovery | Self::UnknownCommand => None,
        }
    }
}

/// High-level async GMP client over an abstract transport.
pub struct GmpClient<C: GvmConnection> {
    connection: C,
    version: GmpVersion,
    wire_trace: Option<Arc<dyn WireTrace>>,
    discovered_commands: Option<BTreeSet<String>>,
}

impl<C: GvmConnection + fmt::Debug> fmt::Debug for GmpClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmpClient")
            .field("connection", &self.connection)
            .field("version", &self.version)
            .field("wire_trace_enabled", &self.wire_trace.is_some())
            .finish()
    }
}

/// Direction of a GMP wire trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireTraceDirection {
    /// XML bytes sent to gvmd.
    Request,
    /// XML bytes received from gvmd.
    Response,
}

/// Redacted GMP wire data captured at the client boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireTraceEvent {
    /// Whether the bytes are outbound request XML or inbound response XML.
    pub direction: WireTraceDirection,
    /// Redacted XML bytes.
    pub bytes: Vec<u8>,
}

/// Sink for opt-in GMP wire trace events.
///
/// Events are structurally parsed and redacted before this callback is invoked.
/// Known GMP secret fields, the `modify_license/file` payload, generic `value`,
/// `default_value`, `param`, report-format file bodies, and nested alert-data
/// payloads, sensitive attributes, comments, and processing instructions are removed.
/// Malformed or non-UTF-8 payloads are
/// replaced entirely with a fixed marker.
///
/// This policy is not a general secret detector for arbitrary custom XML field
/// names. Applications sending raw custom requests should still restrict trace
/// access as they would other diagnostic data. The tracing hook is disabled
/// unless configured explicitly on [`GmpClient`].
pub trait WireTrace: Send + Sync + 'static {
    /// Receive a redacted GMP wire trace event.
    fn trace(&self, event: WireTraceEvent);
}

impl<F> WireTrace for F
where
    F: Fn(WireTraceEvent) + Send + Sync + 'static,
{
    fn trace(&self, event: WireTraceEvent) {
        self(event);
    }
}

impl<C: GvmConnection> GmpClient<C> {
    /// Connect, negotiate GMP version, and construct a client.
    ///
    /// # Errors
    /// Returns an error if the transport fails, version negotiation fails, or
    /// the server advertises an unsupported GMP version.
    pub async fn connect(connection: C) -> Result<Self, GvmError> {
        Self::connect_inner(connection, None).await
    }

    /// Connect, negotiate GMP version, and construct a client with wire tracing.
    ///
    /// The trace sink receives redacted request and response XML for the version
    /// negotiation request and later client calls.
    ///
    /// # Errors
    /// Returns an error if the transport fails, version negotiation fails, or
    /// the server advertises an unsupported GMP version.
    pub async fn connect_with_wire_trace<T>(connection: C, wire_trace: T) -> Result<Self, GvmError>
    where
        T: WireTrace,
    {
        Self::connect_inner(connection, Some(Arc::new(wire_trace))).await
    }

    async fn connect_inner(
        mut connection: C,
        wire_trace: Option<Arc<dyn WireTrace>>,
    ) -> Result<Self, GvmError> {
        connection.connect().await?;

        let response = Self::send_on(
            &mut connection,
            GetVersionRequest::new(),
            wire_trace.as_deref(),
        )
        .await?;
        let response = Self::raise_for_status(response)?;
        let version_text = response.child_text("version").ok_or_else(|| {
            GvmError::XmlParse("missing <version> in get_version response".to_string())
        })?;
        let version = map_supported_version(parse_version_text(&version_text)?)?;

        Ok(Self {
            connection,
            version,
            wire_trace,
            discovered_commands: None,
        })
    }

    /// Return the negotiated GMP version.
    #[must_use]
    pub fn version(&self) -> GmpVersion {
        self.version
    }

    /// Query the server's XML `help` command listing and cache the advertised
    /// command names.
    ///
    /// This is required before invoking commands whose availability cannot be
    /// proven by the negotiated GMP version, including `export_scan_report`.
    ///
    /// # Errors
    /// Returns an error if the request fails, the response cannot be parsed,
    /// or the server does not return a structured command listing.
    pub async fn discover_commands(&mut self) -> Result<HelpResponse, GvmError> {
        let response = self.call(help_with_mode(HelpMode::BriefXml)).await?;
        let parsed = HelpResponse::from_response(&response).map_err(GvmError::from)?;
        let schema = parsed.schema.as_ref().ok_or_else(|| {
            GvmError::XmlParse("help response did not include an XML command listing".to_string())
        })?;
        self.discovered_commands = Some(
            schema
                .commands
                .iter()
                .map(|command| command.name.clone())
                .collect(),
        );
        Ok(parsed)
    }

    /// Classify the client's current knowledge of a command's support.
    ///
    /// This is the same classification used by the execution gate. Discovery
    /// remains explicit: [`CommandSupport::RequiresDiscovery`] instructs the
    /// caller to invoke [`Self::discover_commands`] and retry. An
    /// [`CommandSupport::UnknownCommand`] may still be sent through the raw
    /// custom-command APIs.
    pub fn command_support(&self, command_name: &str) -> CommandSupport {
        if let Some(capability) = gvm_gmp::capabilities::command_capability(command_name) {
            if let Some(required) = capability.min_version {
                if self.version < required {
                    return CommandSupport::UnsupportedVersion { required };
                }
            }
            if capability.requires_help_discovery {
                return match &self.discovered_commands {
                    None => CommandSupport::RequiresDiscovery,
                    Some(commands) if commands.contains(command_name) => CommandSupport::Supported,
                    Some(_) => CommandSupport::NotAdvertised,
                };
            }
            return CommandSupport::Supported;
        }

        if let Some(required) = version::minimum_version_for_command(command_name) {
            return if self.version < required {
                CommandSupport::UnsupportedVersion { required }
            } else {
                CommandSupport::Supported
            };
        }

        CommandSupport::UnknownCommand
    }

    /// Return the legacy tri-state view of a command's support.
    ///
    /// This compatibility method maps both pending discovery and unknown names
    /// to `None`. Use [`Self::command_support`] when those states need different
    /// caller actions.
    #[deprecated(since = "0.6.0", note = "use command_support for actionable states")]
    #[must_use]
    pub fn supports_command(&self, command_name: &str) -> Option<bool> {
        self.command_support(command_name).legacy_option()
    }

    /// Enable redacted GMP wire tracing on this client.
    #[must_use]
    pub fn with_wire_trace<T>(mut self, wire_trace: T) -> Self
    where
        T: WireTrace,
    {
        self.wire_trace = Some(Arc::new(wire_trace));
        self
    }

    /// Disable GMP wire tracing on this client.
    #[must_use]
    pub fn without_wire_trace(mut self) -> Self {
        self.wire_trace = None;
        self
    }

    /// Send a request and return the raw parsed response.
    ///
    /// # Errors
    /// Returns an error if request transmission or response parsing fails.
    pub async fn send<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        let semantic_command_name = request.semantic_command_name();
        let request_bytes = request.to_bytes();
        self.ensure_command_supported(&request_bytes, semantic_command_name)?;
        Self::send_on_bytes(
            &mut self.connection,
            request_bytes,
            self.wire_trace.as_deref(),
        )
        .await
    }

    /// Execute a semantic request and decode its statically associated response.
    ///
    /// Canonical requests validate their final semantic value first, classify
    /// support from explicit semantic metadata second, encode for the
    /// negotiated version third, and only then enter the shared redacted
    /// transport path. Existing builder-backed requests retain the legacy
    /// encoded-root support gate until their resource family is converted.
    /// Valid non-success GMP responses are normalized to [`GvmError::Server`];
    /// malformed or uninterpretable responses remain [`GvmError::Parse`].
    ///
    /// The request's associated response type is enforced at compile time:
    ///
    /// ```compile_fail
    /// use gvm_client::{GmpClient, GvmError};
    /// use gvm_connection::GvmConnection;
    /// use gvm_gmp::commands::version::GetVersionRequest;
    /// use gvm_gmp::responses::AuthenticateResponse;
    ///
    /// async fn mismatched_response<C: GvmConnection>(
    ///     client: &mut GmpClient<C>,
    /// ) -> Result<(), GvmError> {
    ///     let _: AuthenticateResponse = client.execute(GetVersionRequest::new()).await?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns an error if request validation/encoding, command support checks,
    /// transmission, or typed response decoding fails.
    pub async fn execute<R: GmpRequest>(&mut self, request: R) -> Result<R::Response, GvmError> {
        let version = self.version;
        request.validate()?;
        let command = request.command();
        if let Some(command) = command {
            self.ensure_typed_command_supported(command)?;
        }
        let legacy_semantic_command_name = request.legacy_semantic_command_name();
        let request_bytes = request.encode(version)?;
        if command.is_none() {
            self.ensure_command_supported(&request_bytes, legacy_semantic_command_name)?;
        }
        let response = Self::send_on_bytes(
            &mut self.connection,
            request_bytes,
            self.wire_trace.as_deref(),
        )
        .await?;
        R::Response::decode(&response, version).map_err(GvmError::from)
    }

    /// Send a request and raise a server error on non-2xx responses.
    ///
    /// # Errors
    /// Returns an error if transport fails, parsing fails, or the server
    /// responds with a non-success status.
    pub async fn call<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        let response = self.send(request).await?;
        Self::raise_for_status(response)
    }

    /// Disconnect the underlying transport.
    ///
    /// # Errors
    /// Returns an error if the transport fails to disconnect.
    pub async fn disconnect(&mut self) -> Result<(), GvmError> {
        self.connection.disconnect().await?;
        Ok(())
    }

    /// Borrow the underlying connection.
    #[must_use]
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// Mutably borrow the underlying connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut C {
        &mut self.connection
    }

    /// Consume the client and return the underlying connection.
    #[must_use]
    pub fn into_inner(self) -> C {
        self.connection
    }

    async fn send_on<R: Request>(
        connection: &mut C,
        request: R,
        wire_trace: Option<&dyn WireTrace>,
    ) -> Result<Response, GvmError> {
        Self::send_on_bytes(connection, request.to_bytes(), wire_trace).await
    }

    async fn send_on_bytes(
        connection: &mut C,
        request_bytes: Vec<u8>,
        wire_trace: Option<&dyn WireTrace>,
    ) -> Result<Response, GvmError> {
        emit_wire_trace(wire_trace, WireTraceDirection::Request, &request_bytes);
        connection.send(&request_bytes).await?;
        let bytes = connection.read().await?;
        emit_wire_trace(wire_trace, WireTraceDirection::Response, &bytes);
        Ok(Response::new(bytes))
    }

    fn ensure_command_supported(
        &self,
        request_bytes: &[u8],
        semantic_command_name: Option<&'static str>,
    ) -> Result<(), GvmError> {
        let Some(command_name) = request_command_name(request_bytes) else {
            return Ok(());
        };

        let semantic_command_name = semantic_command_name
            .or_else(|| next_only_semantic_command(command_name, request_bytes));
        if let Some(semantic_command_name) = semantic_command_name {
            self.ensure_named_command_supported(semantic_command_name)?;
        }

        self.ensure_named_command_supported(command_name)
    }

    fn ensure_named_command_supported(&self, command_name: &str) -> Result<(), GvmError> {
        match self.command_support(command_name) {
            CommandSupport::Supported | CommandSupport::UnknownCommand => Ok(()),
            CommandSupport::RequiresDiscovery => Err(GvmError::CommandDiscoveryRequired {
                command: command_name.to_string(),
            }),
            CommandSupport::UnsupportedVersion { .. } => Err(GvmError::UnsupportedCommand {
                command: command_name.to_string(),
                version: self.version,
                required: version::required_version_label(command_name)
                    .unwrap_or("a newer GMP version"),
            }),
            CommandSupport::NotAdvertised => Err(GvmError::CommandNotAdvertised {
                command: command_name.to_string(),
            }),
        }
    }

    fn ensure_typed_command_supported(&self, command: GmpCommand) -> Result<(), GvmError> {
        if let Some(semantic_name) = command.semantic_name() {
            self.ensure_named_command_supported(semantic_name)?;
        }
        self.ensure_named_command_supported(command.wire_name())
    }

    /// Get one structured vulnerability report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_scan_report(
        &mut self,
        scan_report_id: &EntityId,
        opts: GetScanReportOpts,
    ) -> Result<GetScanReportResponse, GvmError> {
        self.execute(GetScanReportRequest::new(scan_report_id.clone(), opts))
            .await
    }

    /// Get one structured vulnerability report without typed response parsing.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_scan_report_raw(
        &mut self,
        scan_report_id: &EntityId,
        opts: GetScanReportOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_scan_report(scan_report_id, opts)).await
    }

    /// Queue or reuse an asynchronous scan-report export and return the raw
    /// response.
    ///
    /// Call [`Self::discover_commands`] first. The negotiated GMP version is
    /// not sufficient evidence that the server implements this command.
    ///
    /// # Errors
    /// Returns [`GvmError::CommandDiscoveryRequired`] before discovery,
    /// [`GvmError::CommandNotAdvertised`] when discovery omits the command, or
    /// a request/response error after the command is attempted.
    pub async fn export_scan_report_raw(
        &mut self,
        report_id: &EntityId,
        opts: ExportScanReportOpts,
    ) -> Result<Response, GvmError> {
        self.call(export_scan_report(report_id, opts)).await
    }

    /// Get host summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_hosts(report_id, opts)).await
    }

    /// Get port summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_ports(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_ports(report_id, opts)).await
    }

    /// Get application summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_applications(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_applications(report_id, opts)).await
    }

    /// Get operating system summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_operating_systems(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_operating_systems(report_id, opts))
            .await
    }

    /// Get CVE summaries for a report.
    ///
    /// # Errors
    /// Returns an error if the server does not support the command, the transport fails,
    /// parsing fails, or the server returns a non-success status.
    pub async fn get_report_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.call(get_report_cves(report_id, opts)).await
    }

    fn raise_for_status(response: Response) -> Result<Response, GvmError> {
        if response.is_success() {
            return Ok(response);
        }

        Err(GvmError::Server {
            status: response.status_code().unwrap_or(0),
            message: response
                .status_text()
                .unwrap_or_else(|| "Unknown error".to_string()),
        })
    }
}

fn emit_wire_trace(
    wire_trace: Option<&dyn WireTrace>,
    direction: WireTraceDirection,
    bytes: &[u8],
) {
    if let Some(wire_trace) = wire_trace {
        wire_trace.trace(WireTraceEvent {
            direction,
            bytes: redact_wire_bytes(bytes),
        });
    }
}

/// GMP 22.4 client wrapper.
#[derive(Debug)]
pub struct Gmp224<C: GvmConnection>(GmpClient<C>);

/// GMP 22.5 client wrapper.
#[derive(Debug)]
pub struct Gmp225<C: GvmConnection>(GmpClient<C>);

/// GMP 22.6 client wrapper.
#[derive(Debug)]
pub struct Gmp226<C: GvmConnection>(GmpClient<C>);

/// GMP 22.7 client wrapper.
#[derive(Debug)]
pub struct Gmp227<C: GvmConnection>(GmpClient<C>);

/// GMP next-version client wrapper.
#[derive(Debug)]
pub struct GmpNext<C: GvmConnection>(GmpClient<C>);

/// Commands available in GMP 22.6 and later.
#[async_trait::async_trait]
pub trait Gmp226Commands {
    /// Send a `get_features` request.
    async fn get_features(&mut self) -> Result<Response, GvmError>;
}

/// Structured audit-report commands available in GMP 22.7 and later.
#[async_trait::async_trait]
pub trait Gmp227Commands {
    /// Get one structured audit report.
    async fn get_audit_report(
        &mut self,
        audit_report_id: &EntityId,
        opts: GetAuditReportOpts,
    ) -> Result<gvm_gmp::responses::GetAuditReportResponse, GvmError>;

    /// Get structured host summaries for an audit report.
    async fn get_audit_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetAuditReportHostsOpts,
    ) -> Result<gvm_gmp::responses::GetAuditReportHostsResponse, GvmError>;
}

/// Commands available only in GMP 22.8 and later.
#[async_trait::async_trait]
pub trait GmpNextCommands {
    /// List agents.
    async fn get_agents(
        &mut self,
        request: GetAgentsRequest,
    ) -> Result<GetAgentsResponse, GvmError>;

    /// Get a single agent.
    async fn get_agent(&mut self, request: GetAgentRequest) -> Result<GetAgentsResponse, GvmError>;

    /// Modify one or more agents.
    async fn modify_agent(
        &mut self,
        request: ModifyAgentRequest,
    ) -> Result<ModifyAgentResponse, GvmError>;

    /// Delete one or more agents.
    async fn delete_agent(
        &mut self,
        request: DeleteAgentRequest,
    ) -> Result<DeleteAgentResponse, GvmError>;

    /// Synchronize agents.
    async fn sync_agents(
        &mut self,
        request: SyncAgentsRequest,
    ) -> Result<SyncAgentsResponse, GvmError>;

    /// Modify the agent-control scan configuration defaults.
    async fn modify_agent_control_scan_config(
        &mut self,
        request: ModifyAgentControlScanConfigRequest,
    ) -> Result<ModifyAgentControlScanConfigResponse, GvmError>;

    /// Get agent installer instructions.
    async fn get_agent_installer_instruction(
        &mut self,
        request: GetAgentInstallerInstructionRequest,
    ) -> Result<GetAgentInstallerInstructionResponse, GvmError>;

    /// Get an agent support bundle.
    async fn get_agent_support_bundle(
        &mut self,
        request: GetAgentSupportBundleRequest,
    ) -> Result<GetAgentSupportBundleResponse, GvmError>;

    /// Create an agent group.
    async fn create_agent_group(
        &mut self,
        request: CreateAgentGroupRequest,
    ) -> Result<CreateAgentGroupResponse, GvmError>;

    /// Create a task that scans an agent group.
    async fn create_agent_group_task(
        &mut self,
        request: CreateAgentGroupTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError>;

    /// Clone an agent group.
    async fn clone_agent_group(
        &mut self,
        request: CloneAgentGroupRequest,
    ) -> Result<CloneAgentGroupResponse, GvmError>;

    /// Get a single agent group.
    async fn get_agent_group(
        &mut self,
        request: GetAgentGroupRequest,
    ) -> Result<GetAgentGroupsResponse, GvmError>;

    /// List agent groups.
    async fn get_agent_groups(
        &mut self,
        request: GetAgentGroupsRequest,
    ) -> Result<GetAgentGroupsResponse, GvmError>;

    /// Modify an agent group.
    async fn modify_agent_group(
        &mut self,
        request: ModifyAgentGroupRequest,
    ) -> Result<ModifyAgentGroupResponse, GvmError>;

    /// Delete an agent group.
    async fn delete_agent_group(
        &mut self,
        request: DeleteAgentGroupRequest,
    ) -> Result<DeleteAgentGroupResponse, GvmError>;

    /// Create an OCI image target.
    async fn create_oci_image_target(
        &mut self,
        request: CreateOciImageTargetRequest,
    ) -> Result<CreateOciImageTargetResponse, GvmError>;

    /// Create a task that scans an OCI image target.
    async fn create_oci_image_target_task(
        &mut self,
        request: CreateOciImageTargetTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError>;

    /// Create a task that scans an OCI image target using python-gvm's
    /// historical container-image helper name.
    async fn create_container_image_task(
        &mut self,
        request: CreateContainerImageTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError>;

    /// Clone an OCI image target.
    async fn clone_oci_image_target(
        &mut self,
        request: CloneOciImageTargetRequest,
    ) -> Result<CreateOciImageTargetResponse, GvmError>;

    /// Get a single OCI image target.
    async fn get_oci_image_target(
        &mut self,
        request: GetOciImageTargetRequest,
    ) -> Result<GetOciImageTargetsResponse, GvmError>;

    /// List OCI image targets.
    async fn get_oci_image_targets(
        &mut self,
        request: GetOciImageTargetsRequest,
    ) -> Result<GetOciImageTargetsResponse, GvmError>;

    /// Modify an OCI image target.
    async fn modify_oci_image_target(
        &mut self,
        request: ModifyOciImageTargetRequest,
    ) -> Result<ModifyOciImageTargetResponse, GvmError>;

    /// Delete an OCI image target.
    async fn delete_oci_image_target(
        &mut self,
        request: DeleteOciImageTargetRequest,
    ) -> Result<DeleteOciImageTargetResponse, GvmError>;

    /// Create a web application target.
    async fn create_web_application_target(
        &mut self,
        request: CreateWebApplicationTargetRequest,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError>;

    /// Clone a web application target.
    async fn clone_web_application_target(
        &mut self,
        request: CloneWebApplicationTargetRequest,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError>;

    /// Get a single web application target.
    async fn get_web_application_target(
        &mut self,
        request: GetWebApplicationTargetRequest,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError>;

    /// List web application targets.
    async fn get_web_application_targets(
        &mut self,
        request: GetWebApplicationTargetsRequest,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError>;

    /// Modify a web application target.
    async fn modify_web_application_target(
        &mut self,
        request: ModifyWebApplicationTargetRequest,
    ) -> Result<ModifyWebApplicationTargetResponse, GvmError>;

    /// Delete a web application target.
    async fn delete_web_application_target(
        &mut self,
        request: DeleteWebApplicationTargetRequest,
    ) -> Result<DeleteWebApplicationTargetResponse, GvmError>;

    /// Create a scan task for a web application target.
    async fn create_web_application_task(
        &mut self,
        request: CreateWebApplicationTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError>;

    /// Get a single integration configuration.
    async fn get_integration_config(
        &mut self,
        request: GetIntegrationConfigRequest,
    ) -> Result<GetIntegrationConfigsResponse, GvmError>;

    /// List integration configurations.
    async fn get_integration_configs(
        &mut self,
        request: GetIntegrationConfigsRequest,
    ) -> Result<GetIntegrationConfigsResponse, GvmError>;

    /// Modify an integration configuration.
    async fn modify_integration_config(
        &mut self,
        request: ModifyIntegrationConfigRequest,
    ) -> Result<ModifyIntegrationConfigResponse, GvmError>;

    /// Get one structured vulnerability report.
    async fn get_scan_report(
        &mut self,
        scan_report_id: &EntityId,
        opts: GetScanReportOpts,
    ) -> Result<GetScanReportResponse, GvmError>;

    /// Get one structured vulnerability report without typed response parsing.
    async fn get_scan_report_raw(
        &mut self,
        scan_report_id: &EntityId,
        opts: GetScanReportOpts,
    ) -> Result<Response, GvmError>;

    /// Get report host summaries.
    async fn get_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report port summaries.
    async fn get_report_ports(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report application summaries.
    async fn get_report_applications(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report operating system summaries.
    async fn get_report_operating_systems(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report CVE summaries.
    async fn get_report_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report vulnerability summaries.
    async fn get_report_vulns(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report vulnerability summaries using python-gvm's descriptive helper name.
    async fn get_report_vulnerabilities(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.get_report_vulns(report_id, opts).await
    }

    /// Get report TLS certificate summaries.
    async fn get_report_tls_certificates(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report error summaries.
    async fn get_report_errors(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// Get report closed CVE summaries.
    async fn get_report_closed_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError>;

    /// List timezones.
    async fn get_timezones(&mut self) -> Result<Response, GvmError>;

    /// List credential stores.
    async fn get_credential_stores(
        &mut self,
        request: GetCredentialStoresRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError>;

    /// Verify a credential store connection.
    async fn verify_credential_store(
        &mut self,
        request: VerifyCredentialStoreRequest,
    ) -> Result<VerifyCredentialStoreResponse, GvmError>;

    /// List credential stores with optional filters.
    async fn get_credential_stores_with_opts(
        &mut self,
        request: GetCredentialStoresRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError>;

    /// Get a single credential store.
    async fn get_credential_store(
        &mut self,
        request: GetCredentialStoreRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError>;

    /// Create a credential-store-backed credential.
    async fn create_credential_store_credential(
        &mut self,
        request: CreateCredentialStoreCredentialRequest,
    ) -> Result<CreateCredentialResponse, GvmError>;

    /// Modify a credential-store-backed credential.
    async fn modify_credential_store_credential(
        &mut self,
        request: ModifyCredentialStoreCredentialRequest,
    ) -> Result<ModifyCredentialResponse, GvmError>;
}

macro_rules! impl_gmp226_commands {
    ($client:ident) => {
        #[async_trait::async_trait]
        impl<C: GvmConnection + Send> Gmp226Commands for $client<C> {
            async fn get_features(&mut self) -> Result<Response, GvmError> {
                self.0.call(get_features()).await
            }
        }
    };
}

macro_rules! impl_gmp227_commands {
    ($client:ident) => {
        #[async_trait::async_trait]
        impl<C: GvmConnection + Send> Gmp227Commands for $client<C> {
            async fn get_audit_report(
                &mut self,
                audit_report_id: &EntityId,
                opts: GetAuditReportOpts,
            ) -> Result<gvm_gmp::responses::GetAuditReportResponse, GvmError> {
                self.0.get_audit_report(audit_report_id, opts).await
            }

            async fn get_audit_report_hosts(
                &mut self,
                report_id: &EntityId,
                opts: GetAuditReportHostsOpts,
            ) -> Result<gvm_gmp::responses::GetAuditReportHostsResponse, GvmError> {
                self.0.get_audit_report_hosts(report_id, opts).await
            }
        }
    };
}

/// Versioned GMP client wrapper selected during negotiation.
#[derive(Debug)]
pub enum GmpVersioned<C: GvmConnection> {
    /// GMP 22.4
    V224(Gmp224<C>),
    /// GMP 22.5
    V225(Gmp225<C>),
    /// GMP 22.6
    V226(Gmp226<C>),
    /// GMP 22.7
    V227(Gmp227<C>),
    /// Newer than 22.7 within supported major 22.
    Next(GmpNext<C>),
}

impl<C: GvmConnection> GmpVersioned<C> {
    fn from_client(client: GmpClient<C>) -> Self {
        match client.version() {
            GmpVersion(22, 4) => Self::V224(Gmp224(client)),
            GmpVersion(22, 5) => Self::V225(Gmp225(client)),
            GmpVersion(22, 6) => Self::V226(Gmp226(client)),
            GmpVersion(22, 7) => Self::V227(Gmp227(client)),
            _ => Self::Next(GmpNext(client)),
        }
    }

    fn inner(&self) -> &GmpClient<C> {
        match self {
            Self::V224(client) => &client.0,
            Self::V225(client) => &client.0,
            Self::V226(client) => &client.0,
            Self::V227(client) => &client.0,
            Self::Next(client) => &client.0,
        }
    }

    fn inner_mut(&mut self) -> &mut GmpClient<C> {
        match self {
            Self::V224(client) => &mut client.0,
            Self::V225(client) => &mut client.0,
            Self::V226(client) => &mut client.0,
            Self::V227(client) => &mut client.0,
            Self::Next(client) => &mut client.0,
        }
    }

    /// Connect and wrap the negotiated client by version.
    ///
    /// # Errors
    /// Returns an error if the transport or negotiation fails.
    pub async fn connect(connection: C) -> Result<Self, GvmError> {
        let client = GmpClient::connect(connection).await?;
        Ok(Self::from_client(client))
    }

    /// Connect with wire tracing and wrap the negotiated client by version.
    ///
    /// The trace sink receives redacted request and response XML for the version
    /// negotiation request and later client calls.
    ///
    /// # Errors
    /// Returns an error if the transport or negotiation fails.
    pub async fn connect_with_wire_trace<T>(connection: C, wire_trace: T) -> Result<Self, GvmError>
    where
        T: WireTrace,
    {
        let client = GmpClient::connect_with_wire_trace(connection, wire_trace).await?;
        Ok(Self::from_client(client))
    }

    /// Return the negotiated GMP version.
    #[must_use]
    pub fn version(&self) -> GmpVersion {
        self.inner().version()
    }

    /// Query and cache the server's XML command listing.
    ///
    /// # Errors
    /// Returns an error if help discovery or response parsing fails.
    pub async fn discover_commands(&mut self) -> Result<HelpResponse, GvmError> {
        self.inner_mut().discover_commands().await
    }

    /// Classify the versioned client's current knowledge of command support.
    pub fn command_support(&self, command_name: &str) -> CommandSupport {
        self.inner().command_support(command_name)
    }

    /// Return the legacy tri-state view of command support.
    ///
    /// Use [`Self::command_support`] to distinguish pending discovery from an
    /// unknown command name.
    #[deprecated(since = "0.6.0", note = "use command_support for actionable states")]
    #[must_use]
    pub fn supports_command(&self, command_name: &str) -> Option<bool> {
        self.command_support(command_name).legacy_option()
    }

    /// Queue or reuse an asynchronous scan-report export.
    ///
    /// Call [`Self::discover_commands`] first because GMP 22.7 or 22.8 alone
    /// does not prove that the server implements this command.
    ///
    /// # Errors
    /// Returns [`GvmError::CommandDiscoveryRequired`] before discovery,
    /// [`GvmError::CommandNotAdvertised`] when discovery omits the command, or
    /// a request/response error after the command is attempted.
    pub async fn export_scan_report(
        &mut self,
        report_id: &EntityId,
        opts: ExportScanReportOpts,
    ) -> Result<Response, GvmError> {
        self.inner_mut()
            .export_scan_report_raw(report_id, opts)
            .await
    }

    /// Execute a semantic request and decode its statically associated response.
    ///
    /// # Errors
    /// Returns an error if request transmission, command support checks, or
    /// typed response decoding fails.
    pub async fn execute<R: GmpRequest>(&mut self, request: R) -> Result<R::Response, GvmError> {
        self.inner_mut().execute(request).await
    }

    /// Send a request and return the raw parsed response.
    ///
    /// # Errors
    /// Returns an error if request transmission or response parsing fails.
    pub async fn send<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        self.inner_mut().send(request).await
    }

    /// Send a request and raise a server error on non-2xx responses.
    ///
    /// # Errors
    /// Returns an error if transport fails, parsing fails, or the server
    /// responds with a non-success status.
    pub async fn call<R: Request>(&mut self, request: R) -> Result<Response, GvmError> {
        self.inner_mut().call(request).await
    }

    /// Disconnect the underlying transport.
    ///
    /// # Errors
    /// Returns an error if the transport fails to disconnect.
    pub async fn disconnect(&mut self) -> Result<(), GvmError> {
        self.inner_mut().disconnect().await
    }
}

impl_gmp226_commands!(Gmp226);
impl_gmp226_commands!(Gmp227);
impl_gmp226_commands!(GmpNext);
impl_gmp227_commands!(Gmp227);
impl_gmp227_commands!(GmpNext);

#[async_trait::async_trait]
impl<C: GvmConnection + Send> GmpNextCommands for GmpNext<C> {
    async fn get_agents(
        &mut self,
        request: GetAgentsRequest,
    ) -> Result<GetAgentsResponse, GvmError> {
        self.0.get_agents(request).await
    }

    async fn get_agent(&mut self, request: GetAgentRequest) -> Result<GetAgentsResponse, GvmError> {
        self.0.get_agent(request).await
    }

    async fn modify_agent(
        &mut self,
        request: ModifyAgentRequest,
    ) -> Result<ModifyAgentResponse, GvmError> {
        self.0.modify_agent(request).await
    }

    async fn delete_agent(
        &mut self,
        request: DeleteAgentRequest,
    ) -> Result<DeleteAgentResponse, GvmError> {
        self.0.delete_agent(request).await
    }

    async fn sync_agents(
        &mut self,
        request: SyncAgentsRequest,
    ) -> Result<SyncAgentsResponse, GvmError> {
        self.0.sync_agents(request).await
    }

    async fn modify_agent_control_scan_config(
        &mut self,
        request: ModifyAgentControlScanConfigRequest,
    ) -> Result<ModifyAgentControlScanConfigResponse, GvmError> {
        self.0.modify_agent_control_scan_config(request).await
    }

    async fn get_agent_installer_instruction(
        &mut self,
        request: GetAgentInstallerInstructionRequest,
    ) -> Result<GetAgentInstallerInstructionResponse, GvmError> {
        self.0.get_agent_installer_instruction(request).await
    }

    async fn get_agent_support_bundle(
        &mut self,
        request: GetAgentSupportBundleRequest,
    ) -> Result<GetAgentSupportBundleResponse, GvmError> {
        self.0.get_agent_support_bundle(request).await
    }

    async fn create_agent_group(
        &mut self,
        request: CreateAgentGroupRequest,
    ) -> Result<CreateAgentGroupResponse, GvmError> {
        self.0.create_agent_group(request).await
    }

    async fn create_agent_group_task(
        &mut self,
        request: CreateAgentGroupTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.0.create_agent_group_task(request).await
    }

    async fn clone_agent_group(
        &mut self,
        request: CloneAgentGroupRequest,
    ) -> Result<CloneAgentGroupResponse, GvmError> {
        self.0.clone_agent_group(request).await
    }

    async fn get_agent_group(
        &mut self,
        request: GetAgentGroupRequest,
    ) -> Result<GetAgentGroupsResponse, GvmError> {
        self.0.get_agent_group(request).await
    }

    async fn get_agent_groups(
        &mut self,
        request: GetAgentGroupsRequest,
    ) -> Result<GetAgentGroupsResponse, GvmError> {
        self.0.get_agent_groups(request).await
    }

    async fn modify_agent_group(
        &mut self,
        request: ModifyAgentGroupRequest,
    ) -> Result<ModifyAgentGroupResponse, GvmError> {
        self.0.modify_agent_group(request).await
    }

    async fn delete_agent_group(
        &mut self,
        request: DeleteAgentGroupRequest,
    ) -> Result<DeleteAgentGroupResponse, GvmError> {
        self.0.delete_agent_group(request).await
    }

    async fn create_oci_image_target(
        &mut self,
        request: CreateOciImageTargetRequest,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.0.create_oci_image_target(request).await
    }

    async fn create_oci_image_target_task(
        &mut self,
        request: CreateOciImageTargetTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.0.create_oci_image_target_task(request).await
    }

    async fn create_container_image_task(
        &mut self,
        request: CreateContainerImageTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.0.create_container_image_task(request).await
    }

    async fn clone_oci_image_target(
        &mut self,
        request: CloneOciImageTargetRequest,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.0.clone_oci_image_target(request).await
    }

    async fn get_oci_image_target(
        &mut self,
        request: GetOciImageTargetRequest,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.0.get_oci_image_target(request).await
    }

    async fn get_oci_image_targets(
        &mut self,
        request: GetOciImageTargetsRequest,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.0.get_oci_image_targets(request).await
    }

    async fn modify_oci_image_target(
        &mut self,
        request: ModifyOciImageTargetRequest,
    ) -> Result<ModifyOciImageTargetResponse, GvmError> {
        self.0.modify_oci_image_target(request).await
    }

    async fn delete_oci_image_target(
        &mut self,
        request: DeleteOciImageTargetRequest,
    ) -> Result<DeleteOciImageTargetResponse, GvmError> {
        self.0.delete_oci_image_target(request).await
    }

    async fn create_web_application_target(
        &mut self,
        request: CreateWebApplicationTargetRequest,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.0.create_web_application_target(request).await
    }

    async fn clone_web_application_target(
        &mut self,
        request: CloneWebApplicationTargetRequest,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.0.clone_web_application_target(request).await
    }

    async fn get_web_application_target(
        &mut self,
        request: GetWebApplicationTargetRequest,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.0.get_web_application_target(request).await
    }

    async fn get_web_application_targets(
        &mut self,
        request: GetWebApplicationTargetsRequest,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.0.get_web_application_targets(request).await
    }

    async fn modify_web_application_target(
        &mut self,
        request: ModifyWebApplicationTargetRequest,
    ) -> Result<ModifyWebApplicationTargetResponse, GvmError> {
        self.0.modify_web_application_target(request).await
    }

    async fn delete_web_application_target(
        &mut self,
        request: DeleteWebApplicationTargetRequest,
    ) -> Result<DeleteWebApplicationTargetResponse, GvmError> {
        self.0.delete_web_application_target(request).await
    }

    async fn create_web_application_task(
        &mut self,
        request: CreateWebApplicationTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.0.create_web_application_task(request).await
    }

    async fn get_integration_config(
        &mut self,
        request: GetIntegrationConfigRequest,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.0.get_integration_config(request).await
    }

    async fn get_integration_configs(
        &mut self,
        request: GetIntegrationConfigsRequest,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.0.get_integration_configs(request).await
    }

    async fn modify_integration_config(
        &mut self,
        request: ModifyIntegrationConfigRequest,
    ) -> Result<ModifyIntegrationConfigResponse, GvmError> {
        self.0.modify_integration_config(request).await
    }

    async fn get_scan_report(
        &mut self,
        scan_report_id: &EntityId,
        opts: GetScanReportOpts,
    ) -> Result<GetScanReportResponse, GvmError> {
        self.0.get_scan_report(scan_report_id, opts).await
    }

    async fn get_scan_report_raw(
        &mut self,
        scan_report_id: &EntityId,
        opts: GetScanReportOpts,
    ) -> Result<Response, GvmError> {
        self.0.get_scan_report_raw(scan_report_id, opts).await
    }

    async fn get_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_hosts(report_id, opts)).await
    }

    async fn get_report_ports(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_ports(report_id, opts)).await
    }

    async fn get_report_applications(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_applications(report_id, opts)).await
    }

    async fn get_report_operating_systems(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(get_report_operating_systems(report_id, opts))
            .await
    }

    async fn get_report_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_cves(report_id, opts)).await
    }

    async fn get_report_vulns(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_vulns(report_id, opts)).await
    }

    async fn get_report_tls_certificates(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0
            .call(get_report_tls_certificates(report_id, opts))
            .await
    }

    async fn get_report_errors(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_errors(report_id, opts)).await
    }

    async fn get_report_closed_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<Response, GvmError> {
        self.0.call(get_report_closed_cves(report_id, opts)).await
    }

    async fn get_timezones(&mut self) -> Result<Response, GvmError> {
        self.0.call(get_timezones()).await
    }

    async fn get_credential_stores(
        &mut self,
        request: GetCredentialStoresRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.0.get_credential_stores(request).await
    }

    async fn verify_credential_store(
        &mut self,
        request: VerifyCredentialStoreRequest,
    ) -> Result<VerifyCredentialStoreResponse, GvmError> {
        self.0.verify_credential_store(request).await
    }

    async fn get_credential_stores_with_opts(
        &mut self,
        request: GetCredentialStoresRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.0.get_credential_stores_with_opts(request).await
    }

    async fn get_credential_store(
        &mut self,
        request: GetCredentialStoreRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.0.get_credential_store(request).await
    }

    async fn create_credential_store_credential(
        &mut self,
        request: CreateCredentialStoreCredentialRequest,
    ) -> Result<CreateCredentialResponse, GvmError> {
        self.0.create_credential_store_credential(request).await
    }

    async fn modify_credential_store_credential(
        &mut self,
        request: ModifyCredentialStoreCredentialRequest,
    ) -> Result<ModifyCredentialResponse, GvmError> {
        self.0.modify_credential_store_credential(request).await
    }
}

fn request_command_name(request_bytes: &[u8]) -> Option<&str> {
    let request = std::str::from_utf8(request_bytes).ok()?.trim_start();
    let request = request.strip_prefix('<')?;
    let end = request
        .find(|ch: char| ch == '>' || ch == '/' || ch.is_whitespace())
        .unwrap_or(request.len());
    Some(&request[..end])
}

fn next_only_semantic_command(command_name: &str, request_bytes: &[u8]) -> Option<&'static str> {
    match command_name {
        "create_task" => specialized_task_semantic_command(request_bytes),
        "create_credential" if request_contains_credential_store_type(request_bytes) => {
            Some("create_credential_store_credential")
        }
        "modify_credential" if request_contains_credential_store_modify_field(request_bytes) => {
            Some("modify_credential_store_credential")
        }
        _ => None,
    }
}

fn specialized_task_semantic_command(request_bytes: &[u8]) -> Option<&'static str> {
    let request = std::str::from_utf8(request_bytes).ok()?;
    [
        ("agent_group", "create_agent_group_task"),
        ("oci_image_target", "create_oci_image_target_task"),
        ("web_application_target", "create_web_application_task"),
    ]
    .into_iter()
    .find_map(|(element, command)| request_contains_element(request, element).then_some(command))
}

fn request_contains_credential_store_type(request_bytes: &[u8]) -> bool {
    let Ok(request) = std::str::from_utf8(request_bytes) else {
        return false;
    };
    request_element_text(request, "type").is_some_and(|value| value.starts_with("cs_"))
}

fn request_element_text<'a>(request: &'a str, element_name: &str) -> Option<&'a str> {
    let opening = format!("<{element_name}");
    let closing = format!("</{element_name}>");
    let mut search_from = 0;

    while let Some(relative_start) = request[search_from..].find(&opening) {
        let element_start = search_from + relative_start;
        let after_name = element_start + opening.len();
        let delimiter = request.as_bytes().get(after_name).copied()?;
        if delimiter != b'>' && !delimiter.is_ascii_whitespace() {
            search_from = after_name;
            continue;
        }

        let opening_end = after_name + request[after_name..].find('>')?;
        if request[..opening_end].trim_end().ends_with('/') {
            return Some("");
        }
        let content_start = opening_end + 1;
        let content_end = content_start + request[content_start..].find(&closing)?;
        return Some(request[content_start..content_end].trim());
    }

    None
}

fn request_contains_credential_store_modify_field(request_bytes: &[u8]) -> bool {
    let Ok(request) = std::str::from_utf8(request_bytes) else {
        return false;
    };
    [
        "credential_store_id",
        "vault_id",
        "host_identifier",
        "privacy_host_identifier",
    ]
    .iter()
    .any(|field| request_contains_element(request, field))
}

fn request_contains_element(request: &str, element_name: &str) -> bool {
    let opening = format!("<{element_name}");
    let mut search_from = 0;
    while let Some(relative_start) = request[search_from..].find(&opening) {
        let after_name = search_from + relative_start + opening.len();
        let Some(delimiter) = request.as_bytes().get(after_name).copied() else {
            return false;
        };
        if matches!(delimiter, b'>' | b'/') || delimiter.is_ascii_whitespace() {
            return true;
        }
        search_from = after_name;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use gvm_connection::{ConnectionError, GvmConnection};

    use super::*;

    #[derive(Debug)]
    struct ScriptedConnection {
        responses: VecDeque<Vec<u8>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        connected: bool,
    }

    impl ScriptedConnection {
        fn new<I, S>(responses: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: AsRef<[u8]>,
        {
            Self {
                responses: responses
                    .into_iter()
                    .map(|response| response.as_ref().to_vec())
                    .collect(),
                sent: Arc::new(Mutex::new(Vec::new())),
                connected: false,
            }
        }

        fn sent(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
            Arc::clone(&self.sent)
        }
    }

    #[async_trait]
    impl GvmConnection for ScriptedConnection {
        async fn connect(&mut self) -> gvm_connection::Result<()> {
            self.connected = true;
            Ok(())
        }

        async fn disconnect(&mut self) -> gvm_connection::Result<()> {
            self.connected = false;
            Ok(())
        }

        async fn send(&mut self, data: &[u8]) -> gvm_connection::Result<()> {
            if !self.connected {
                return Err(ConnectionError::NotConnected);
            }
            self.sent.lock().expect("sent lock").push(data.to_vec());
            Ok(())
        }

        async fn read(&mut self) -> gvm_connection::Result<Vec<u8>> {
            self.responses.pop_front().ok_or_else(|| {
                ConnectionError::ReadFailed(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "scripted response exhausted",
                ))
            })
        }

        fn is_connected(&self) -> bool {
            self.connected
        }
    }

    fn version_response(version: &str) -> String {
        format!(
            r#"<get_version_response status="200" status_text="OK"><version>{version}</version></get_version_response>"#
        )
    }

    fn auth_response() -> &'static str {
        r#"<authenticate_response status="200" status_text="OK"/>"#
    }

    fn event_text(event: &WireTraceEvent) -> String {
        String::from_utf8(event.bytes.clone()).expect("trace event is utf-8")
    }

    async fn connected_client_with_response(response: &str) -> GmpClient<ScriptedConnection> {
        GmpClient::connect(ScriptedConnection::new([
            version_response("22.8"),
            response.to_string(),
        ]))
        .await
        .expect("client connects")
    }

    fn assert_server_error(error: GvmError, expected_status: u16, expected_message: &str) {
        assert!(matches!(
            error,
            GvmError::Server { status, message }
                if status == expected_status && message == expected_message
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn command_support_distinguishes_actionable_states() {
        let undiscovered = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 7),
            wire_trace: None,
            discovered_commands: None,
        };

        assert_eq!(
            undiscovered.command_support("get_tasks"),
            CommandSupport::Supported
        );
        assert_eq!(
            undiscovered.command_support("export_scan_report"),
            CommandSupport::RequiresDiscovery
        );
        assert_eq!(
            undiscovered.command_support("export_scan_reprot"),
            CommandSupport::UnknownCommand
        );
        assert_eq!(undiscovered.supports_command("export_scan_report"), None);
        assert_eq!(undiscovered.supports_command("export_scan_reprot"), None);
        assert_eq!(
            undiscovered.command_support("get_report_export"),
            CommandSupport::UnsupportedVersion {
                required: GmpVersion(22, 8),
            }
        );

        let absent = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 8),
            wire_trace: None,
            discovered_commands: Some(BTreeSet::from(["get_tasks".to_string()])),
        };
        assert_eq!(
            absent.command_support("export_scan_report"),
            CommandSupport::NotAdvertised
        );
        assert_eq!(absent.supports_command("export_scan_report"), Some(false));

        let advertised = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 8),
            wire_trace: None,
            discovered_commands: Some(BTreeSet::from(["export_scan_report".to_string()])),
        };
        assert_eq!(
            advertised.command_support("export_scan_report"),
            CommandSupport::Supported
        );
        assert_eq!(
            advertised.supports_command("export_scan_report"),
            Some(true)
        );
    }

    #[tokio::test]
    async fn unknown_raw_command_remains_forward_compatible() {
        let connection = ScriptedConnection::new([
            version_response("22.8"),
            r#"<custom_command_response status="200" status_text="OK"/>"#.to_string(),
        ]);
        let sent = connection.sent();
        let mut client = GmpClient::connect(connection)
            .await
            .expect("client connects");

        assert_eq!(
            client.command_support("custom_command"),
            CommandSupport::UnknownCommand
        );
        client
            .call(b"<custom_command/>".as_slice())
            .await
            .expect("unknown raw command reaches the transport");

        let sent = sent.lock().expect("sent lock");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1], b"<custom_command/>");
    }

    #[tokio::test]
    async fn execute_redacts_wire_bytes_before_trace_observation() {
        let connection =
            ScriptedConnection::new([version_response("22.7"), auth_response().to_string()]);
        let sent = connection.sent();
        let events = Arc::new(Mutex::new(Vec::new()));
        let trace_events = Arc::clone(&events);

        let mut client = GmpClient::connect_with_wire_trace(connection, move |event| {
            trace_events.lock().expect("trace lock").push(event);
        })
        .await
        .expect("client connects");

        client
            .execute(gvm_gmp::commands::authentication::AuthenticateRequest::new(
                "admin",
                "secret-password",
            ))
            .await
            .expect("authenticate succeeds");

        let sent = sent.lock().expect("sent lock");
        assert_eq!(sent.len(), 2);
        assert_eq!(
            std::str::from_utf8(&sent[0]).expect("utf-8"),
            "<get_version/>"
        );
        assert!(std::str::from_utf8(&sent[1])
            .expect("utf-8")
            .contains("<password>secret-password</password>"));

        let events = events.lock().expect("trace lock");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].direction, WireTraceDirection::Request);
        assert_eq!(event_text(&events[0]), "<get_version/>");
        assert_eq!(events[1].direction, WireTraceDirection::Response);
        assert!(event_text(&events[1]).contains("<get_version_response"));
        assert_eq!(events[2].direction, WireTraceDirection::Request);

        let auth_request = event_text(&events[2]);
        assert!(auth_request.contains("<authenticate>"));
        assert!(auth_request.contains("<password><redacted/></password>"));
        assert!(!auth_request.contains("secret-password"));

        assert_eq!(events[3].direction, WireTraceDirection::Response);
        assert!(event_text(&events[3]).contains("<authenticate_response"));
    }

    #[tokio::test]
    async fn default_client_does_not_emit_wire_trace() {
        let connection = ScriptedConnection::new([version_response("22.7")]);

        let client = GmpClient::connect(connection)
            .await
            .expect("client connects");

        assert!(client.wire_trace.is_none());
    }

    #[tokio::test]
    async fn valid_non_success_responses_are_classified_consistently() {
        let mut call_client = connected_client_with_response(
            r#"<get_targets_response status="503" status_text="backend unavailable"/>"#,
        )
        .await;
        let call_error = call_client
            .call(b"<get_targets/>".as_slice())
            .await
            .expect_err("call rejects non-success status");
        assert_server_error(call_error, 503, "backend unavailable");

        let mut execute_client = connected_client_with_response(
            r#"<get_targets_response status="503" status_text="backend unavailable"/>"#,
        )
        .await;
        let execute_error = execute_client
            .execute(gvm_gmp::commands::targets::GetTargetsRequest::default())
            .await
            .expect_err("execute rejects non-success status");
        assert_server_error(execute_error, 503, "backend unavailable");

        let mut agent_client = connected_client_with_response(
            r#"<get_agents_response status="503" status_text="backend unavailable"/>"#,
        )
        .await;
        let agent_error = agent_client
            .get_agents(GetAgentsRequest::default())
            .await
            .expect_err("migrated call-based helper rejects non-success status");
        assert_server_error(agent_error, 503, "backend unavailable");

        let mut report_client = connected_client_with_response(
            r#"<get_scan_report_response status="503" status_text="backend unavailable"/>"#,
        )
        .await;
        let report_error = report_client
            .get_scan_report(
                &EntityId::new("report-1").expect("valid id"),
                GetScanReportOpts::default(),
            )
            .await
            .expect_err("migrated send-based helper rejects non-success status");
        assert_server_error(report_error, 503, "backend unavailable");

        let mut send_client = connected_client_with_response(
            r#"<get_targets_response status="503" status_text="backend unavailable"/>"#,
        )
        .await;
        let raw = send_client
            .send(b"<get_targets/>".as_slice())
            .await
            .expect("send exposes raw non-success response");
        assert_eq!(raw.status_code(), Some(503));
        assert_eq!(raw.status_text().as_deref(), Some("backend unavailable"));
    }

    #[tokio::test]
    async fn malformed_and_structurally_invalid_responses_remain_parse_errors() {
        let mut malformed_client = connected_client_with_response(
            r#"<get_targets_response status="200" status_text="OK"><target>"#,
        )
        .await;
        let malformed = malformed_client
            .execute(gvm_gmp::commands::targets::GetTargetsRequest::default())
            .await
            .expect_err("malformed XML must fail");
        assert!(matches!(malformed, GvmError::Parse(_)));

        let mut missing_client = connected_client_with_response(
            r#"<get_targets_response status="200" status_text="OK"><target><name>missing id</name></target></get_targets_response>"#,
        )
        .await;
        let missing = missing_client
            .execute(gvm_gmp::commands::targets::GetTargetsRequest::default())
            .await
            .expect_err("missing required field must fail");
        assert!(matches!(
            missing,
            GvmError::Parse(gvm_gmp::responses::ParseError::MissingElement(field))
                if field == "target.id"
        ));

        let mut invalid_client = connected_client_with_response(
            r#"<get_targets_response status="200" status_text="OK"><target id="target-1"><name>invalid boolean</name><reverse_lookup_only>maybe</reverse_lookup_only></target></get_targets_response>"#,
        )
        .await;
        let invalid = invalid_client
            .execute(gvm_gmp::commands::targets::GetTargetsRequest::default())
            .await
            .expect_err("invalid value must fail");
        assert!(matches!(
            invalid,
            GvmError::Parse(gvm_gmp::responses::ParseError::InvalidValue { field, value })
                if field == "reverse_lookup_only" && value == "maybe"
        ));
    }

    #[tokio::test]
    async fn versioned_connect_with_wire_trace_wraps_negotiated_client() {
        let connection = ScriptedConnection::new([version_response("22.6")]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let trace_events = Arc::clone(&events);

        let client = GmpVersioned::connect_with_wire_trace(connection, move |event| {
            trace_events.lock().expect("trace lock").push(event);
        })
        .await
        .expect("client connects");

        assert!(matches!(client, GmpVersioned::V226(_)));

        let events = events.lock().expect("trace lock");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].direction, WireTraceDirection::Request);
        assert_eq!(event_text(&events[0]), "<get_version/>");
    }

    #[test]
    fn credential_store_create_semantic_detection_matches_next_shape() {
        assert_eq!(
            next_only_semantic_command(
                "create_credential",
                b"<create_credential><type>cs_pw</type></create_credential>",
            ),
            Some("create_credential_store_credential")
        );
        assert_eq!(
            next_only_semantic_command(
                "create_credential",
                b"<create_credential><type>up</type></create_credential>",
            ),
            None
        );
        assert_eq!(
            next_only_semantic_command(
                "modify_credential",
                b"<modify_credential><type>cs_pw</type></modify_credential>",
            ),
            None
        );
        assert!(!request_contains_credential_store_type(b"\xff"));

        for credential_type in [
            "cs_krb5", "cs_snmp", "cs_up", "cs_usk", "cs_smime", "cs_pgp", "cs_pw",
        ] {
            let request =
                format!("<create_credential><type>{credential_type}</type></create_credential>");
            assert!(request_contains_credential_store_type(request.as_bytes()));
        }
        assert!(request_contains_credential_store_type(
            b"<create_credential><type>\n  cs_future \t</type></create_credential>"
        ));
    }

    #[test]
    fn specialized_task_semantic_detection_matches_next_shapes() {
        for (element, semantic_command) in [
            ("agent_group", "create_agent_group_task"),
            ("oci_image_target", "create_oci_image_target_task"),
            ("web_application_target", "create_web_application_task"),
        ] {
            let request = format!("<create_task><{element} id=\"target-1\"/></create_task>");
            assert_eq!(
                next_only_semantic_command("create_task", request.as_bytes()),
                Some(semantic_command)
            );
        }

        assert_eq!(
            next_only_semantic_command(
                "create_task",
                b"<create_task><target id=\"target-1\"/></create_task>",
            ),
            None
        );
        assert_eq!(
            next_only_semantic_command(
                "modify_task",
                b"<modify_task><agent_group id=\"agent-group-1\"/></modify_task>",
            ),
            None
        );
        assert_eq!(next_only_semantic_command("create_task", b"\xff"), None);
    }

    #[test]
    fn specialized_task_shape_gate_uses_next_version_without_request_metadata() {
        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 7),
            wire_trace: None,
            discovered_commands: None,
        };

        for (element, semantic_command) in [
            ("agent_group", "create_agent_group_task"),
            ("oci_image_target", "create_oci_image_target_task"),
            ("web_application_target", "create_web_application_task"),
        ] {
            let request = format!("<create_task><{element} id=\"target-1\"/></create_task>");
            let error = client
                .ensure_command_supported(request.as_bytes(), None)
                .expect_err("specialized task shape is gated before 22.8");
            assert!(matches!(
                error,
                GvmError::UnsupportedCommand {
                    ref command,
                    version: GmpVersion(22, 7),
                    required: "22.8",
                } if command == semantic_command
            ));
        }

        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 8),
            wire_trace: None,
            discovered_commands: None,
        };
        client
            .ensure_command_supported(
                b"<create_task><agent_group id=\"agent-group-1\"/></create_task>",
                None,
            )
            .expect("specialized task shape is available in 22.8");
    }

    #[test]
    fn credential_store_modify_semantic_detection_matches_next_shape() {
        for field in [
            "credential_store_id",
            "vault_id",
            "host_identifier",
            "privacy_host_identifier",
        ] {
            let request = format!(
                "<modify_credential credential_id=\"credential-1\"><{field}>value</{field}></modify_credential>"
            );
            assert_eq!(
                next_only_semantic_command("modify_credential", request.as_bytes()),
                Some("modify_credential_store_credential")
            );
            assert!(request_contains_credential_store_modify_field(
                request.as_bytes()
            ));
        }

        assert_eq!(
            next_only_semantic_command(
                "modify_credential",
                b"<modify_credential credential_id=\"credential-1\"><comment>keep</comment></modify_credential>",
            ),
            None
        );
        assert_eq!(
            next_only_semantic_command(
                "create_credential",
                b"<create_credential><vault_id>vault-1</vault_id></create_credential>",
            ),
            None
        );
        assert!(!request_contains_credential_store_modify_field(b"\xff"));
        assert!(request_contains_credential_store_modify_field(
            b"<modify_credential><vault_id/></modify_credential>"
        ));
        assert!(request_contains_credential_store_modify_field(
            b"<modify_credential><host_identifier ></host_identifier></modify_credential>"
        ));
    }

    #[test]
    fn credential_store_create_semantic_gate_uses_next_version() {
        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 7),
            wire_trace: None,
            discovered_commands: None,
        };
        let error = client
            .ensure_command_supported(
                b"<create_credential><type>cs_up</type></create_credential>",
                None,
            )
            .expect_err("credential-store create is gated before 22.8");

        assert!(matches!(
            error,
            GvmError::UnsupportedCommand {
                ref command,
                version: GmpVersion(22, 7),
                required: "22.8",
            } if command == "create_credential_store_credential"
        ));

        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 8),
            wire_trace: None,
            discovered_commands: None,
        };
        client
            .ensure_command_supported(
                b"<create_credential><type>cs_up</type></create_credential>",
                None,
            )
            .expect("credential-store create is available in 22.8");
        client
            .ensure_command_supported(b"<get_version/>", None)
            .expect("normal supported command still passes");
    }

    #[test]
    fn credential_store_modify_semantic_gate_uses_next_version() {
        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 7),
            wire_trace: None,
            discovered_commands: None,
        };
        let error = client
            .ensure_command_supported(
                b"<modify_credential credential_id=\"credential-1\"><vault_id>vault-1</vault_id></modify_credential>",
                None,
            )
            .expect_err("credential-store modify is gated before 22.8");

        assert!(matches!(
            error,
            GvmError::UnsupportedCommand {
                ref command,
                version: GmpVersion(22, 7),
                required: "22.8",
            } if command == "modify_credential_store_credential"
        ));

        let error = client
            .ensure_command_supported(
                b"<modify_credential credential_id=\"credential-1\"/>",
                Some("modify_credential_store_credential"),
            )
            .expect_err("semantic request metadata is gated before 22.8");
        assert!(matches!(
            error,
            GvmError::UnsupportedCommand { command, .. }
                if command == "modify_credential_store_credential"
        ));
        let client = GmpClient {
            connection: ScriptedConnection::new(std::iter::empty::<&str>()),
            version: GmpVersion(22, 8),
            wire_trace: None,
            discovered_commands: None,
        };
        client
            .ensure_command_supported(
                b"<modify_credential credential_id=\"credential-1\"><vault_id>vault-1</vault_id></modify_credential>",
                None,
            )
            .expect("credential-store modify is available in 22.8");
        client
            .ensure_command_supported(
                b"<modify_credential credential_id=\"credential-1\"/>",
                Some("modify_credential_store_credential"),
            )
            .expect("semantic request metadata is available in 22.8");
    }

    #[tokio::test]
    async fn next_trait_create_credential_store_credential_sends_request() {
        let mut connection = ScriptedConnection::new([
            r#"<create_credential_response id="credential-1" status="201" status_text="Created"/>"#,
        ]);
        connection.connect().await.expect("connection opens");
        let mut client = GmpNext(GmpClient {
            connection,
            version: GmpVersion(22, 8),
            wire_trace: None,
            discovered_commands: None,
        });

        let response = client
            .create_credential_store_credential(CreateCredentialStoreCredentialRequest::new(
                "Credential",
                CredentialStoreCredentialType::UsernamePassword,
                "vault-1",
                "host-1",
            ))
            .await
            .expect("request succeeds");

        assert_eq!(response.status, 201);
    }

    #[tokio::test]
    async fn next_trait_modify_credential_store_credential_sends_request() {
        let mut connection = ScriptedConnection::new([
            r#"<modify_credential_response status="200" status_text="OK"/>"#,
        ]);
        connection.connect().await.expect("connection opens");
        let mut client = GmpNext(GmpClient {
            connection,
            version: GmpVersion(22, 8),
            wire_trace: None,
            discovered_commands: None,
        });

        let response = client
            .modify_credential_store_credential({
                let mut request = ModifyCredentialStoreCredentialRequest::new(
                    EntityId::new("credential-1").expect("valid id"),
                );
                request.vault_id = Some("vault-1".into());
                request
            })
            .await
            .expect("request succeeds");

        assert_eq!(response.status, 200);
    }

    #[test]
    fn redacts_known_credential_elements() {
        let bytes = br#"<root><password>pw</password><community>snmp</community><private>key</private><private_key>key2</private_key><public>public-key</public><certificate>certificate-data</certificate><phrase>key-phrase</phrase><passphrase>passphrase-value</passphrase><secret>oidc-secret</secret><auth_password>auth</auth_password><privacy_password>privacy</privacy_password><vault_id>vault-secret</vault_id><host_identifier>host-secret</host_identifier><privacy_host_identifier>privacy-host-secret</privacy_host_identifier><password algorithm="x">again</password></root>"#;

        let redacted = String::from_utf8(redact_wire_bytes(bytes)).expect("utf-8");

        assert_eq!(
            redacted,
            r#"<root><password><redacted/></password><community><redacted/></community><private><redacted/></private><private_key><redacted/></private_key><public><redacted/></public><certificate><redacted/></certificate><phrase><redacted/></phrase><passphrase><redacted/></passphrase><secret><redacted/></secret><auth_password><redacted/></auth_password><privacy_password><redacted/></privacy_password><vault_id><redacted/></vault_id><host_identifier><redacted/></host_identifier><privacy_host_identifier><redacted/></privacy_host_identifier><password algorithm="x"><redacted/></password></root>"#
        );
        assert!(!redacted.contains(">pw<"));
        assert!(!redacted.contains(">snmp<"));
        assert!(!redacted.contains(">key<"));
        assert!(!redacted.contains(">key2<"));
        assert!(!redacted.contains(">public-key<"));
        assert!(!redacted.contains(">certificate-data<"));
        assert!(!redacted.contains(">key-phrase<"));
        assert!(!redacted.contains(">passphrase-value<"));
        assert!(!redacted.contains(">oidc-secret<"));
        assert!(!redacted.contains(">auth<"));
        assert!(!redacted.contains(">privacy<"));
        assert!(!redacted.contains(">vault-secret<"));
        assert!(!redacted.contains(">host-secret<"));
        assert!(!redacted.contains(">privacy-host-secret<"));
        assert!(!redacted.contains(">again<"));
    }

    #[test]
    fn redacts_modify_license_file_without_hiding_generic_files() {
        let request = gvm_gmp::commands::system::modify_license("license-secret").to_bytes();

        let redacted = String::from_utf8(redact_wire_bytes(&request)).expect("utf-8");

        assert_eq!(
            redacted,
            "<modify_license><file><redacted/></file></modify_license>"
        );
        assert!(!redacted.contains("license-secret"));
        assert_eq!(
            redact_wire_bytes(b"<root><file>visible</file></root>"),
            b"<root><file>visible</file></root>"
        );
    }

    #[test]
    fn redaction_ignores_similar_and_self_closing_tags() {
        let bytes = br#"<root><password_hash>keep</password_hash><secret_name>keep-secret-name</secret_name><password/><secret/><password>pw</password><secret>s</secret></root>"#;

        let redacted = String::from_utf8(redact_wire_bytes(bytes)).expect("utf-8");

        assert_eq!(
            redacted,
            r#"<root><password_hash>keep</password_hash><secret_name>keep-secret-name</secret_name><password/><secret/><password><redacted/></password><secret><redacted/></secret></root>"#
        );
    }

    #[test]
    fn redacts_canonical_credential_store_request_values() {
        use gvm_gmp::commands::credentials::{
            CredentialStorePreference, ModifyCredentialStoreRequest,
        };

        let request = {
            let mut request = ModifyCredentialStoreRequest::new(
                EntityId::new("credential-store-1").expect("valid ID"),
            );
            request.host = Some("store.example".into());
            request.preferences = vec![CredentialStorePreference {
                name: "token".into(),
                value: "preference-sentinel".into(),
            }];
            request.encode(GmpVersion(22, 8)).expect("request encodes")
        };
        let redacted = String::from_utf8(redact_wire_bytes(&request)).expect("UTF-8 trace");

        assert!(redacted.contains("<host><redacted/></host>"));
        assert!(!redacted.contains("store.example"));
        assert!(redacted.contains("<name>token</name>"));
        assert!(redacted.contains("<value><redacted/></value>"));
        assert!(!redacted.contains("preference-sentinel"));
    }

    #[test]
    fn redacts_non_utf8_wire_bytes() {
        assert_eq!(redact_wire_bytes(&[0xff]), b"<non-utf8-redacted/>");
    }
}
