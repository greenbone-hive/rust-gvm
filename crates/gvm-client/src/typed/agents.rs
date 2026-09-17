// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
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
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, GetIntegrationConfigsRequest, ModifyIntegrationConfigRequest,
};
use gvm_gmp::responses::{
    CloneAgentGroupResponse, CreateAgentGroupResponse, DeleteAgentGroupResponse,
    DeleteAgentResponse, GetAgentGroupsResponse, GetAgentInstallerInstructionResponse,
    GetAgentSupportBundleResponse, GetAgentsResponse, GetIntegrationConfigsResponse,
    ModifyAgentControlScanConfigResponse, ModifyAgentGroupResponse, ModifyAgentResponse,
    ModifyIntegrationConfigResponse, SyncAgentsResponse,
};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Agents ────────────────────────────────────────────────────────────────

    /// Send a `get_agents` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_agents(
        &mut self,
        request: GetAgentsRequest,
    ) -> Result<GetAgentsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_agents` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_agent(
        &mut self,
        request: GetAgentRequest,
    ) -> Result<GetAgentsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_agent` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_agent(
        &mut self,
        request: ModifyAgentRequest,
    ) -> Result<ModifyAgentResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_agent` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_agent(
        &mut self,
        request: DeleteAgentRequest,
    ) -> Result<DeleteAgentResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `sync_agents` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn sync_agents(
        &mut self,
        request: SyncAgentsRequest,
    ) -> Result<SyncAgentsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_agent_control_scan_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_agent_control_scan_config(
        &mut self,
        request: ModifyAgentControlScanConfigRequest,
    ) -> Result<ModifyAgentControlScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_agent_installer_instruction` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_agent_installer_instruction(
        &mut self,
        request: GetAgentInstallerInstructionRequest,
    ) -> Result<GetAgentInstallerInstructionResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_agent_support_bundle` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_agent_support_bundle(
        &mut self,
        request: GetAgentSupportBundleRequest,
    ) -> Result<GetAgentSupportBundleResponse, GvmError> {
        self.execute(request).await
    }

    // ── Agent Groups ─────────────────────────────────────────────────────────

    /// Send a `create_agent_group` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_agent_group(
        &mut self,
        request: CreateAgentGroupRequest,
    ) -> Result<CreateAgentGroupResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_agent_group` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_agent_group(
        &mut self,
        request: CloneAgentGroupRequest,
    ) -> Result<CloneAgentGroupResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_agent_groups` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_agent_group(
        &mut self,
        request: GetAgentGroupRequest,
    ) -> Result<GetAgentGroupsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_agent_groups` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_agent_groups(
        &mut self,
        request: GetAgentGroupsRequest,
    ) -> Result<GetAgentGroupsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_agent_group` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_agent_group(
        &mut self,
        request: ModifyAgentGroupRequest,
    ) -> Result<ModifyAgentGroupResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_agent_group` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_agent_group(
        &mut self,
        request: DeleteAgentGroupRequest,
    ) -> Result<DeleteAgentGroupResponse, GvmError> {
        self.execute(request).await
    }

    // ── Integration Configurations ────────────────────────────────────────────

    /// Send a detailed `get_integration_configs` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_integration_config(
        &mut self,
        request: GetIntegrationConfigRequest,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_integration_configs` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_integration_configs(
        &mut self,
        request: GetIntegrationConfigsRequest,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_integration_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_integration_config(
        &mut self,
        request: ModifyIntegrationConfigRequest,
    ) -> Result<ModifyIntegrationConfigResponse, GvmError> {
        self.execute(request).await
    }
}
