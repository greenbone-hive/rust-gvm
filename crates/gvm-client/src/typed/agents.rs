// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, GetIntegrationConfigsOpts, GetIntegrationConfigsRequest,
    ModifyIntegrationConfigOpts, ModifyIntegrationConfigRequest,
};
use gvm_gmp::responses::{GetIntegrationConfigsResponse, ModifyIntegrationConfigResponse};
use gvm_gmp::types::EntityId;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Integration Configurations ────────────────────────────────────────────

    /// Send a single `get_integration_config` request and return a typed response.
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_integration_config`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_integration_config_parsed(
        &mut self,
        integration_config_id: &EntityId,
        details: Option<bool>,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.execute(GetIntegrationConfigRequest::new(
            integration_config_id.clone(),
            details,
        ))
        .await
    }

    /// Send a `get_integration_configs` request and return a typed response.
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_integration_configs`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_integration_configs_parsed(
        &mut self,
        opts: GetIntegrationConfigsOpts,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.execute(GetIntegrationConfigsRequest::new(opts)).await
    }

    /// Send a `modify_integration_config` request and return a typed response.
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::modify_integration_config`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_integration_config_parsed(
        &mut self,
        integration_config_id: &EntityId,
        opts: ModifyIntegrationConfigOpts,
    ) -> Result<ModifyIntegrationConfigResponse, GvmError> {
        self.execute(ModifyIntegrationConfigRequest::new(
            integration_config_id.clone(),
            opts,
        ))
        .await
    }
}
