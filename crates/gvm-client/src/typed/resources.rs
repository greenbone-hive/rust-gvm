// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::assets::{
    AssetType, CreateAssetOpts, CreateAssetRequest, DeleteAssetOpts, DeleteAssetRequest,
    GetAssetRequest, GetAssetsOpts, GetAssetsRequest, ModifyAssetOpts, ModifyAssetRequest,
};
use gvm_gmp::commands::configs::{
    CloneConfigOpts, CloneConfigRequest, CreateConfigOpts, CreateConfigRequest, DeleteConfigOpts,
    DeleteConfigRequest, GetConfigOpts, GetConfigRequest, GetConfigsOpts, GetConfigsRequest,
    ModifyConfigOpts, ModifyConfigRequest,
};
use gvm_gmp::commands::hosts::{
    CreateHostRequest, DeleteHostRequest, GetHostRequest, GetHostsOpts, GetHostsRequest, HostOpts,
    ModifyHostRequest,
};
use gvm_gmp::commands::operating_systems::{
    DeleteOperatingSystemAssetRequest, GetOperatingSystemAssetRequest,
    GetOperatingSystemAssetsRequest, GetOperatingSystemsOpts, ModifyOperatingSystemAssetRequest,
};
use gvm_gmp::commands::port_lists::{
    ClonePortListRequest, CreatePortListRequest, CreatePortRangeRequest, DeletePortListRequest,
    DeletePortRangeRequest, GetPortListRequest, GetPortListsRequest, ModifyPortListRequest,
};
use gvm_gmp::responses::{
    CreateAssetResponse, CreateConfigResponse, CreateHostResponse, CreatePortListResponse,
    CreatePortRangeResponse, DeleteAssetResponse, DeleteConfigResponse, DeleteHostResponse,
    DeletePortListResponse, DeletePortRangeResponse, GetAssetsResponse, GetConfigsResponse,
    GetHostsResponse, GetOperatingSystemAssetsResponse, GetPortListsResponse, ModifyAssetResponse,
    ModifyConfigResponse, ModifyHostResponse, ModifyPortListResponse,
};
use gvm_gmp::types::EntityId;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Port Lists ────────────────────────────────────────────────────────────

    /// Send a `get_port_lists` request and return a typed [`GetPortListsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_port_lists(
        &mut self,
        request: GetPortListsRequest,
    ) -> Result<GetPortListsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_port_lists` request for one port list.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_port_list(
        &mut self,
        request: GetPortListRequest,
    ) -> Result<GetPortListsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_port_list` request and return a typed [`CreatePortListResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_port_list(
        &mut self,
        request: CreatePortListRequest,
    ) -> Result<CreatePortListResponse, GvmError> {
        self.execute(request).await
    }

    /// Clone a port list through `create_port_list`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_port_list(
        &mut self,
        request: ClonePortListRequest,
    ) -> Result<CreatePortListResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_port_list` request and return a typed
    /// [`ModifyPortListResponse`].
    ///
    /// gvmd replaces both the name and comment, clearing either field when its
    /// option is omitted. Use the port-range commands to change ranges.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_port_list(
        &mut self,
        request: ModifyPortListRequest,
    ) -> Result<ModifyPortListResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_port_list` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_port_list(
        &mut self,
        request: DeletePortListRequest,
    ) -> Result<DeletePortListResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_port_range` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_port_range(
        &mut self,
        request: CreatePortRangeRequest,
    ) -> Result<CreatePortRangeResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_port_range` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_port_range(
        &mut self,
        request: DeletePortRangeRequest,
    ) -> Result<DeletePortRangeResponse, GvmError> {
        self.execute(request).await
    }

    // ── Hosts ─────────────────────────────────────────────────────────────────

    /// Send a `get_hosts` request and return a typed [`GetHostsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_hosts(&mut self, opts: GetHostsOpts) -> Result<GetHostsResponse, GvmError> {
        self.execute(GetHostsRequest::new(opts)).await
    }

    /// Send a single-host `get_assets` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_host(&mut self, host_id: &EntityId) -> Result<GetHostsResponse, GvmError> {
        self.execute(GetHostRequest::new(host_id.clone())).await
    }

    /// Send a `create_host` request and return a typed [`CreateHostResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_host(&mut self, opts: HostOpts) -> Result<CreateHostResponse, GvmError> {
        self.execute(CreateHostRequest::new(opts)).await
    }

    /// Send a `modify_asset` request for a host and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_host(
        &mut self,
        host_id: &EntityId,
        opts: HostOpts,
    ) -> Result<ModifyHostResponse, GvmError> {
        self.execute(ModifyHostRequest::new(host_id.clone(), opts))
            .await
    }

    /// Send a `delete_asset` request for a host and return a typed response.
    ///
    /// The `ultimate` value is retained for compatibility and remains ignored
    /// by the host builder because gvmd applies asset-specific deletion.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_host(
        &mut self,
        host_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteHostResponse, GvmError> {
        self.execute(DeleteHostRequest::new(host_id.clone(), ultimate))
            .await
    }

    // ── Assets ──────────────────────────────────────────────────────────────────

    /// Send a `get_assets` request and return a typed [`GetAssetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_assets(&mut self, opts: GetAssetsOpts) -> Result<GetAssetsResponse, GvmError> {
        self.execute(GetAssetsRequest::new(opts)).await
    }

    /// Send a single-asset `get_assets` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_asset(
        &mut self,
        asset_id: &EntityId,
        asset_type: AssetType,
    ) -> Result<GetAssetsResponse, GvmError> {
        self.execute(GetAssetRequest::new(asset_id.clone(), asset_type))
            .await
    }

    /// Send a `create_asset` request and return a typed [`CreateAssetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_asset(
        &mut self,
        opts: CreateAssetOpts,
    ) -> Result<CreateAssetResponse, GvmError> {
        self.execute(CreateAssetRequest::new(opts)).await
    }

    /// Send a `modify_asset` request and return a typed [`ModifyAssetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_asset(
        &mut self,
        asset_id: &EntityId,
        opts: ModifyAssetOpts,
    ) -> Result<ModifyAssetResponse, GvmError> {
        self.execute(ModifyAssetRequest::new(asset_id.clone(), opts))
            .await
    }

    /// Send a `delete_asset` request and return a typed [`DeleteAssetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_asset(
        &mut self,
        asset_id: &EntityId,
        opts: DeleteAssetOpts,
    ) -> Result<DeleteAssetResponse, GvmError> {
        self.execute(DeleteAssetRequest::new(asset_id.clone(), opts))
            .await
    }

    /// Send a `get_assets type="os"` request and return typed operating-system assets.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_operating_system_assets(
        &mut self,
        opts: GetOperatingSystemsOpts,
    ) -> Result<GetOperatingSystemAssetsResponse, GvmError> {
        self.execute(GetOperatingSystemAssetsRequest::new(opts))
            .await
    }

    /// Send a single operating-system asset request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_operating_system_asset(
        &mut self,
        operating_system_id: &EntityId,
        details: Option<bool>,
    ) -> Result<GetOperatingSystemAssetsResponse, GvmError> {
        self.execute(GetOperatingSystemAssetRequest::new(
            operating_system_id.clone(),
            details,
        ))
        .await
    }

    /// Send a `modify_asset` request for an operating-system asset.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_operating_system_asset(
        &mut self,
        operating_system_id: &EntityId,
        comment: Option<String>,
    ) -> Result<ModifyAssetResponse, GvmError> {
        self.execute(ModifyOperatingSystemAssetRequest::new(
            operating_system_id.clone(),
            comment,
        ))
        .await
    }

    /// Send a `delete_asset` request for an operating-system asset.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_operating_system_asset(
        &mut self,
        operating_system_id: &EntityId,
    ) -> Result<DeleteAssetResponse, GvmError> {
        self.execute(DeleteOperatingSystemAssetRequest::new(
            operating_system_id.clone(),
        ))
        .await
    }

    // ── Generic Configs ──────────────────────────────────────────────────────

    /// Send a generic `get_configs` request and return typed generic configs.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_configs(
        &mut self,
        opts: GetConfigsOpts,
    ) -> Result<GetConfigsResponse, GvmError> {
        self.execute(GetConfigsRequest::new(opts)).await
    }

    /// Send a generic single-config `get_configs` request and return typed generic configs.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_config(
        &mut self,
        config_id: &EntityId,
        opts: GetConfigOpts,
    ) -> Result<GetConfigsResponse, GvmError> {
        self.execute(GetConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a generic `create_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_config(
        &mut self,
        opts: CreateConfigOpts,
    ) -> Result<CreateConfigResponse, GvmError> {
        self.execute(CreateConfigRequest::new(opts)).await
    }

    /// Send a generic config clone request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_config(
        &mut self,
        config_id: &EntityId,
        opts: CloneConfigOpts,
    ) -> Result<CreateConfigResponse, GvmError> {
        self.execute(CloneConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a generic `modify_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_config(
        &mut self,
        config_id: &EntityId,
        opts: ModifyConfigOpts,
    ) -> Result<ModifyConfigResponse, GvmError> {
        self.execute(ModifyConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a generic `delete_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_config(
        &mut self,
        config_id: &EntityId,
        opts: DeleteConfigOpts,
    ) -> Result<DeleteConfigResponse, GvmError> {
        self.execute(DeleteConfigRequest::new(config_id.clone(), opts))
            .await
    }
}
