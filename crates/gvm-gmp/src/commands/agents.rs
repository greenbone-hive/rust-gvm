// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for agent operations.

use gvm_protocol::{xml_command::XmlElement, Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str};
use crate::responses::{
    DeleteAgentResponse, GetAgentInstallerInstructionResponse, GetAgentSupportBundleResponse,
    GetAgentsResponse, ModifyAgentControlScanConfigResponse, ModifyAgentResponse,
    SyncAgentsResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Supported agent installer instruction languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstallerLanguage {
    /// English instructions.
    En,
    /// German instructions.
    De,
}

impl AgentInstallerLanguage {
    /// Return the GMP wire value.
    #[must_use]
    pub fn as_gmp_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::De => "de",
        }
    }
}

/// Retry defaults inside an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentRetryConfig {
    /// Number of retry attempts.
    pub attempts: Option<u32>,
    /// Retry delay in seconds.
    pub delay_in_seconds: Option<u32>,
    /// Maximum retry jitter in seconds.
    pub max_jitter_in_seconds: Option<u32>,
}

/// Agent-control section of an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentControlConfig {
    /// Retry configuration.
    pub retry: Option<AgentRetryConfig>,
}

/// Agent-script-executor section of an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentScriptExecutorConfig {
    /// Bulk size.
    pub bulk_size: Option<u32>,
    /// Bulk throttle time in milliseconds.
    pub bulk_throttle_time_in_ms: Option<u32>,
    /// Indexer directory depth.
    pub indexer_dir_depth: Option<u32>,
    /// Scheduler cron expressions.
    pub scheduler_cron_time: Vec<String>,
}

/// Heartbeat section of an agent configuration.
#[derive(Debug, Clone, Default)]
pub struct AgentHeartbeatConfig {
    /// Heartbeat interval in seconds.
    pub interval_in_seconds: Option<u32>,
    /// Missed-heartbeat count before the agent is considered inactive.
    pub miss_until_inactive: Option<u32>,
}

/// Reusable agent configuration payload shared by agent update requests.
#[derive(Debug, Clone, Default)]
pub struct AgentConfigOpts {
    /// Agent-control configuration.
    pub agent_control: Option<AgentControlConfig>,
    /// Agent-script-executor configuration.
    pub agent_script_executor: Option<AgentScriptExecutorConfig>,
    /// Heartbeat configuration.
    pub heartbeat: Option<AgentHeartbeatConfig>,
}

/// Semantic request for listing agents.
#[derive(Debug, Clone, Default)]
pub struct GetAgentsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

impl GmpRequestCodec for GetAgentsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_agents"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_agents_command(self).to_bytes())
    }
}

impl GmpRequest for GetAgentsRequest {
    type Response = GetAgentsResponse;
}

/// Semantic request for one agent.
#[derive(Debug, Clone)]
pub struct GetAgentRequest {
    /// Agent identifier to retrieve.
    pub agent_id: EntityId,
}

impl GetAgentRequest {
    /// Create a single-agent request.
    #[must_use]
    pub fn new(agent_id: EntityId) -> Self {
        Self { agent_id }
    }
}

impl GmpRequestCodec for GetAgentRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_agents", "get_agent"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_agent_command(&self.agent_id).to_bytes())
    }
}

impl GmpRequest for GetAgentRequest {
    type Response = GetAgentsResponse;
}

/// Semantic request for modifying one or more agents.
#[derive(Debug, Clone)]
pub struct ModifyAgentRequest {
    /// Agent identifiers to modify.
    pub agent_ids: Vec<EntityId>,
    /// Whether the selected agents are authorized.
    pub authorized: Option<bool>,
    /// Whether selected agents should update to the latest version.
    pub update_to_latest: Option<bool>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional shared agent configuration update.
    pub config: Option<AgentConfigOpts>,
}

impl ModifyAgentRequest {
    /// Create an agent-modification request with its selected agents.
    #[must_use]
    pub fn new(agent_ids: Vec<EntityId>) -> Self {
        Self {
            agent_ids,
            authorized: None,
            update_to_latest: None,
            comment: None,
            config: None,
        }
    }
}

impl GmpRequestCodec for ModifyAgentRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_agent"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_agent_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyAgentRequest {
    type Response = ModifyAgentResponse;
}

/// Semantic request for deleting one or more agents.
#[derive(Debug, Clone)]
pub struct DeleteAgentRequest {
    /// Agent identifiers to delete.
    pub agent_ids: Vec<EntityId>,
}

impl DeleteAgentRequest {
    /// Create an agent-deletion request.
    #[must_use]
    pub fn new(agent_ids: Vec<EntityId>) -> Self {
        Self { agent_ids }
    }
}

impl GmpRequestCodec for DeleteAgentRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_agent"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_agent_command(&self.agent_ids).to_bytes())
    }
}

impl GmpRequest for DeleteAgentRequest {
    type Response = DeleteAgentResponse;
}

/// Semantic request for synchronizing agents.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncAgentsRequest;

impl SyncAgentsRequest {
    /// Create an agent-synchronization request.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for SyncAgentsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("sync_agents"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("sync_agents").to_bytes())
    }
}

impl GmpRequest for SyncAgentsRequest {
    type Response = SyncAgentsResponse;
}

/// Semantic request for modifying agent-control defaults.
#[derive(Debug, Clone)]
pub struct ModifyAgentControlScanConfigRequest {
    /// Agent-control scanner identifier to modify.
    pub agent_control_id: EntityId,
    /// Default configuration for controlled agents.
    pub agent_defaults: Option<AgentConfigOpts>,
    /// Default update-to-latest value for controlled agents.
    pub update_to_latest: Option<bool>,
}

impl ModifyAgentControlScanConfigRequest {
    /// Create an agent-control defaults request.
    #[must_use]
    pub fn new(agent_control_id: EntityId) -> Self {
        Self {
            agent_control_id,
            agent_defaults: None,
            update_to_latest: None,
        }
    }
}

impl GmpRequestCodec for ModifyAgentControlScanConfigRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_agent_control_scan_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_agent_control_scan_config_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyAgentControlScanConfigRequest {
    type Response = ModifyAgentControlScanConfigResponse;
}

/// Semantic request for agent installer instructions.
#[derive(Debug, Clone)]
pub struct GetAgentInstallerInstructionRequest {
    /// Scanner identifier for which to render the instructions.
    pub scanner_id: EntityId,
    /// Instruction language.
    pub language: AgentInstallerLanguage,
    /// Public origin URL used by the installer instructions.
    pub origin_url: String,
}

impl GetAgentInstallerInstructionRequest {
    /// Create an installer-instruction request.
    #[must_use]
    pub fn new(
        scanner_id: EntityId,
        language: AgentInstallerLanguage,
        origin_url: impl Into<String>,
    ) -> Self {
        Self {
            scanner_id,
            language,
            origin_url: origin_url.into(),
        }
    }
}

impl GmpRequestCodec for GetAgentInstallerInstructionRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_agent_installer_instruction"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_agent_installer_instruction_command(self).to_bytes())
    }
}

impl GmpRequest for GetAgentInstallerInstructionRequest {
    type Response = GetAgentInstallerInstructionResponse;
}

/// Semantic request for an agent support bundle.
#[derive(Debug, Clone)]
pub struct GetAgentSupportBundleRequest {
    /// Agent identifier whose support bundle should be generated.
    pub agent_uuid: EntityId,
    /// Optional number of days to include.
    pub days: Option<u32>,
}

impl GetAgentSupportBundleRequest {
    /// Create a support-bundle request.
    #[must_use]
    pub fn new(agent_uuid: EntityId, days: Option<u32>) -> Self {
        Self { agent_uuid, days }
    }
}

impl GmpRequestCodec for GetAgentSupportBundleRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_agent_support_bundle"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_agent_support_bundle_command(self).to_bytes())
    }
}

impl GmpRequest for GetAgentSupportBundleRequest {
    type Response = GetAgentSupportBundleResponse;
}

fn get_agents_command(request: &GetAgentsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_agents");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    cmd
}

fn get_agent_command(agent_id: &EntityId) -> XmlCommand {
    XmlCommand::new("get_agents").attribute("agent_id", agent_id.as_str())
}

fn modify_agent_command(request: &ModifyAgentRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_agent");
    add_agents_element(&mut cmd, &request.agent_ids);
    if let Some(authorized) = request.authorized {
        cmd.add_element_with_text("authorized", bool_str(authorized));
    }
    if let Some(update_to_latest) = request.update_to_latest {
        cmd.add_element_with_text("update_to_latest", bool_str(update_to_latest));
    }
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    if let Some(config) = request.config.as_ref() {
        let config_element = cmd.add_element("config");
        add_agent_config(config_element, config);
    }
    cmd
}

fn delete_agent_command(agent_ids: &[EntityId]) -> XmlCommand {
    let mut cmd = XmlCommand::new("delete_agent");
    add_agents_element(&mut cmd, agent_ids);
    cmd
}

fn modify_agent_control_scan_config_command(
    request: &ModifyAgentControlScanConfigRequest,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_agent_control_scan_config")
        .attribute("agent_control_id", request.agent_control_id.as_str());
    let defaults = cmd.add_element("config_defaults");
    if let Some(agent_defaults) = request.agent_defaults.as_ref() {
        let agent_defaults_element = defaults.add_child("agent_defaults");
        add_agent_config(agent_defaults_element, agent_defaults);
    }
    if let Some(update_to_latest) = request.update_to_latest {
        defaults
            .add_child("agent_control_defaults")
            .add_child_with_text("update_to_latest", bool_str(update_to_latest));
    }
    cmd
}

fn get_agent_installer_instruction_command(
    request: &GetAgentInstallerInstructionRequest,
) -> XmlCommand {
    XmlCommand::new("get_agent_installer_instruction")
        .attribute("language", request.language.as_gmp_str())
        .attribute("origin_url", &request.origin_url)
        .attribute("scanner_id", request.scanner_id.as_str())
}

fn get_agent_support_bundle_command(request: &GetAgentSupportBundleRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_agent_support_bundle")
        .attribute("agent_uuid", request.agent_uuid.as_str());
    if let Some(days) = request.days {
        cmd.set_attribute("days", &days.to_string());
    }
    cmd
}

fn add_agents_element(cmd: &mut XmlCommand, agent_ids: &[EntityId]) {
    let agents = cmd.add_element("agents");
    for agent_id in agent_ids {
        agents
            .add_child("agent")
            .set_attribute("id", agent_id.as_str());
    }
}

fn add_agent_config(parent: &mut XmlElement, opts: &AgentConfigOpts) {
    if let Some(agent_control) = opts.agent_control.as_ref() {
        add_agent_control_config(parent.add_child("agent_control"), agent_control);
    }
    if let Some(agent_script_executor) = opts.agent_script_executor.as_ref() {
        add_agent_script_executor_config(
            parent.add_child("agent_script_executor"),
            agent_script_executor,
        );
    }
    if let Some(heartbeat) = opts.heartbeat.as_ref() {
        add_heartbeat_config(parent.add_child("heartbeat"), heartbeat);
    }
}

fn add_agent_control_config(parent: &mut XmlElement, opts: &AgentControlConfig) {
    if let Some(retry) = opts.retry.as_ref() {
        let retry_element = parent.add_child("retry");
        add_u32_child(retry_element, "attempts", retry.attempts);
        add_u32_child(retry_element, "delay_in_seconds", retry.delay_in_seconds);
        add_u32_child(
            retry_element,
            "max_jitter_in_seconds",
            retry.max_jitter_in_seconds,
        );
    }
}

fn add_agent_script_executor_config(parent: &mut XmlElement, opts: &AgentScriptExecutorConfig) {
    add_u32_child(parent, "bulk_size", opts.bulk_size);
    add_u32_child(
        parent,
        "bulk_throttle_time_in_ms",
        opts.bulk_throttle_time_in_ms,
    );
    add_u32_child(parent, "indexer_dir_depth", opts.indexer_dir_depth);
    if !opts.scheduler_cron_time.is_empty() {
        let scheduler = parent.add_child("scheduler_cron_time");
        for item in &opts.scheduler_cron_time {
            scheduler.add_child_with_text("item", item);
        }
    }
}

fn add_heartbeat_config(parent: &mut XmlElement, opts: &AgentHeartbeatConfig) {
    add_u32_child(parent, "interval_in_seconds", opts.interval_in_seconds);
    add_u32_child(parent, "miss_until_inactive", opts.miss_until_inactive);
}

fn add_u32_child(parent: &mut XmlElement, name: &str, value: Option<u32>) {
    if let Some(value) = value {
        parent.add_child_with_text(name, &value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GmpResponse;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn sample_config() -> AgentConfigOpts {
        AgentConfigOpts {
            agent_control: Some(AgentControlConfig {
                retry: Some(AgentRetryConfig {
                    attempts: Some(3),
                    delay_in_seconds: Some(10),
                    max_jitter_in_seconds: Some(5),
                }),
            }),
            agent_script_executor: Some(AgentScriptExecutorConfig {
                bulk_size: Some(20),
                bulk_throttle_time_in_ms: Some(100),
                indexer_dir_depth: Some(4),
                scheduler_cron_time: vec!["0 */6 * * *".into(), "30 */6 * * *".into()],
            }),
            heartbeat: Some(AgentHeartbeatConfig {
                interval_in_seconds: Some(60),
                miss_until_inactive: Some(3),
            }),
        }
    }

    fn request_xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(
            request
                .encode(GmpVersion(22, 8))
                .expect("valid agent request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetAgentsRequest {
                filter_string: Some("scanner=agent-controller".into()),
                filter_id: Some(id("filter-1")),
            }),
            "<get_agents filt_id=\"filter-1\" filter=\"scanner=agent-controller\"/>"
        );
        assert_eq!(
            request_xml(&GetAgentRequest::new(id("agent-1"))),
            "<get_agents agent_id=\"agent-1\"/>"
        );

        let mut modify = ModifyAgentRequest::new(vec![id("agent-1"), id("agent-2")]);
        modify.authorized = Some(true);
        modify.update_to_latest = Some(false);
        modify.comment = Some("managed".into());
        modify.config = Some(sample_config());
        assert_eq!(
            request_xml(&modify),
            "<modify_agent><agents><agent id=\"agent-1\"/><agent id=\"agent-2\"/></agents><authorized>1</authorized><update_to_latest>0</update_to_latest><comment>managed</comment><config><agent_control><retry><attempts>3</attempts><delay_in_seconds>10</delay_in_seconds><max_jitter_in_seconds>5</max_jitter_in_seconds></retry></agent_control><agent_script_executor><bulk_size>20</bulk_size><bulk_throttle_time_in_ms>100</bulk_throttle_time_in_ms><indexer_dir_depth>4</indexer_dir_depth><scheduler_cron_time><item>0 */6 * * *</item><item>30 */6 * * *</item></scheduler_cron_time></agent_script_executor><heartbeat><interval_in_seconds>60</interval_in_seconds><miss_until_inactive>3</miss_until_inactive></heartbeat></config></modify_agent>"
        );
        assert_eq!(
            request_xml(&DeleteAgentRequest::new(vec![id("agent-1"), id("agent-2")])),
            "<delete_agent><agents><agent id=\"agent-1\"/><agent id=\"agent-2\"/></agents></delete_agent>"
        );
        assert_eq!(request_xml(&SyncAgentsRequest), "<sync_agents/>");

        let mut control = ModifyAgentControlScanConfigRequest::new(id("scanner-1"));
        control.agent_defaults = Some(sample_config());
        control.update_to_latest = Some(true);
        assert_eq!(
            request_xml(&control),
            "<modify_agent_control_scan_config agent_control_id=\"scanner-1\"><config_defaults><agent_defaults><agent_control><retry><attempts>3</attempts><delay_in_seconds>10</delay_in_seconds><max_jitter_in_seconds>5</max_jitter_in_seconds></retry></agent_control><agent_script_executor><bulk_size>20</bulk_size><bulk_throttle_time_in_ms>100</bulk_throttle_time_in_ms><indexer_dir_depth>4</indexer_dir_depth><scheduler_cron_time><item>0 */6 * * *</item><item>30 */6 * * *</item></scheduler_cron_time></agent_script_executor><heartbeat><interval_in_seconds>60</interval_in_seconds><miss_until_inactive>3</miss_until_inactive></heartbeat></agent_defaults><agent_control_defaults><update_to_latest>1</update_to_latest></agent_control_defaults></config_defaults></modify_agent_control_scan_config>"
        );
        assert_eq!(
            request_xml(&GetAgentInstallerInstructionRequest::new(
                id("scanner-1"),
                AgentInstallerLanguage::En,
                "https://gvmd.example",
            )),
            "<get_agent_installer_instruction language=\"en\" origin_url=\"https://gvmd.example\" scanner_id=\"scanner-1\"/>"
        );
        assert_eq!(
            request_xml(&GetAgentSupportBundleRequest::new(id("agent-1"), Some(14))),
            "<get_agent_support_bundle agent_uuid=\"agent-1\" days=\"14\"/>"
        );
        assert_eq!(
            request_xml(&GetAgentSupportBundleRequest::new(id("agent-1"), None)),
            "<get_agent_support_bundle agent_uuid=\"agent-1\"/>"
        );
    }

    #[test]
    fn requests_expose_semantic_capability_metadata() {
        assert_eq!(
            GetAgentsRequest::default().command(),
            Some(GmpCommand::new("get_agents"))
        );
        assert_eq!(
            GetAgentRequest::new(id("agent-1")).command(),
            Some(GmpCommand::with_semantic_name("get_agents", "get_agent"))
        );
        assert_eq!(
            ModifyAgentRequest::new(vec![]).command(),
            Some(GmpCommand::new("modify_agent"))
        );
        assert_eq!(
            DeleteAgentRequest::new(vec![]).command(),
            Some(GmpCommand::new("delete_agent"))
        );
        assert_eq!(
            SyncAgentsRequest.command(),
            Some(GmpCommand::new("sync_agents"))
        );
        assert_eq!(
            ModifyAgentControlScanConfigRequest::new(id("scanner-1")).command(),
            Some(GmpCommand::new("modify_agent_control_scan_config"))
        );
        assert_eq!(
            GetAgentInstallerInstructionRequest::new(
                id("scanner-1"),
                AgentInstallerLanguage::En,
                "https://gvmd.example"
            )
            .command(),
            Some(GmpCommand::new("get_agent_installer_instruction"))
        );
        assert_eq!(
            GetAgentSupportBundleRequest::new(id("agent-1"), None).command(),
            Some(GmpCommand::new("get_agent_support_bundle"))
        );
    }

    #[test]
    fn requests_remain_statically_associated_with_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_response::<_, GetAgentsResponse>(&GetAgentsRequest::default());
        assert_response::<_, GetAgentsResponse>(&GetAgentRequest::new(id("agent-1")));
        assert_response::<_, ModifyAgentResponse>(&ModifyAgentRequest::new(vec![]));
        assert_response::<_, DeleteAgentResponse>(&DeleteAgentRequest::new(vec![]));
        assert_response::<_, SyncAgentsResponse>(&SyncAgentsRequest);
        assert_response::<_, ModifyAgentControlScanConfigResponse>(
            &ModifyAgentControlScanConfigRequest::new(id("scanner-1")),
        );
        assert_response::<_, GetAgentInstallerInstructionResponse>(
            &GetAgentInstallerInstructionRequest::new(
                id("scanner-1"),
                AgentInstallerLanguage::En,
                "https://gvmd.example",
            ),
        );
        assert_response::<_, GetAgentSupportBundleResponse>(&GetAgentSupportBundleRequest::new(
            id("agent-1"),
            None,
        ));
    }
}
