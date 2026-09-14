// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::oci_image_targets::{
    CloneOciImageTargetRequest, CreateOciImageTargetOpts, CreateOciImageTargetRequest,
    DeleteOciImageTargetRequest, GetOciImageTargetRequest, GetOciImageTargetsOpts,
    GetOciImageTargetsRequest, ModifyOciImageTargetOpts, ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::targets::{
    CreateTargetOpts, CreateTargetRequest, DeleteTargetRequest, GetTargetRequest, GetTargetsOpts,
    GetTargetsRequest, ModifyTargetOpts, ModifyTargetRequest,
};
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, CreateWebApplicationTargetOpts,
    CreateWebApplicationTargetRequest, DeleteWebApplicationTargetRequest,
    GetWebApplicationTargetRequest, GetWebApplicationTargetsOpts, GetWebApplicationTargetsRequest,
    ModifyWebApplicationTargetOpts, ModifyWebApplicationTargetRequest,
};
use gvm_gmp::responses::{
    CreateOciImageTargetResponse, CreateTargetResponse, CreateWebApplicationTargetResponse,
    DeleteOciImageTargetResponse, DeleteTargetResponse, DeleteWebApplicationTargetResponse,
    GetOciImageTargetsResponse, GetTargetsResponse, GetWebApplicationTargetsResponse,
    ModifyOciImageTargetResponse, ModifyTargetResponse, ModifyWebApplicationTargetResponse,
};
use gvm_gmp::types::EntityId;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Targets ───────────────────────────────────────────────────────────────

    /// Send a `get_targets` request and return a typed [`GetTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_targets(
        &mut self,
        opts: GetTargetsOpts,
    ) -> Result<GetTargetsResponse, GvmError> {
        self.execute(GetTargetsRequest::new(opts)).await
    }

    /// Send a detailed `get_targets` request for one target and return a typed
    /// [`GetTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_target(
        &mut self,
        target_id: &EntityId,
    ) -> Result<GetTargetsResponse, GvmError> {
        self.execute(GetTargetRequest::new(target_id.clone())).await
    }

    /// Send a `create_target` request and return a typed [`CreateTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_target(
        &mut self,
        name: &str,
        opts: CreateTargetOpts,
    ) -> Result<CreateTargetResponse, GvmError> {
        let request = CreateTargetRequest::new(name, opts)?;
        self.execute(request).await
    }

    /// Send a `modify_target` request and return a typed [`ModifyTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_target(
        &mut self,
        target_id: &EntityId,
        opts: ModifyTargetOpts,
    ) -> Result<ModifyTargetResponse, GvmError> {
        let request = ModifyTargetRequest::new(target_id.clone(), opts)?;
        self.execute(request).await
    }

    /// Send a `delete_target` request and return a typed [`DeleteTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_target(
        &mut self,
        target_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteTargetResponse, GvmError> {
        self.execute(DeleteTargetRequest::new(target_id.clone(), ultimate))
            .await
    }

    /// Send a `create_oci_image_target` request and return a typed
    /// [`CreateOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_oci_image_target_parsed(
        &mut self,
        name: &str,
        image_references: &[String],
        opts: CreateOciImageTargetOpts,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.execute(CreateOciImageTargetRequest::new(
            name,
            image_references.to_vec(),
            opts,
        ))
        .await
    }

    /// Send a `clone_oci_image_target` request and return a typed
    /// [`CreateOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.execute(CloneOciImageTargetRequest::new(oci_image_target_id.clone()))
            .await
    }

    /// Send a `get_oci_image_targets` request for one target and return a typed
    /// [`GetOciImageTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.execute(GetOciImageTargetRequest::new(
            oci_image_target_id.clone(),
            tasks,
        ))
        .await
    }

    /// Send a `get_oci_image_targets` request and return a typed
    /// [`GetOciImageTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_oci_image_targets_parsed(
        &mut self,
        opts: GetOciImageTargetsOpts,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.execute(GetOciImageTargetsRequest::new(opts)).await
    }

    /// Send a `modify_oci_image_target` request and return a typed
    /// [`ModifyOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
        opts: ModifyOciImageTargetOpts,
    ) -> Result<ModifyOciImageTargetResponse, GvmError> {
        self.execute(ModifyOciImageTargetRequest::new(
            oci_image_target_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `delete_oci_image_target` request and return a typed
    /// [`DeleteOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteOciImageTargetResponse, GvmError> {
        self.execute(DeleteOciImageTargetRequest::new(
            oci_image_target_id.clone(),
            ultimate,
        ))
        .await
    }

    /// Send a `create_web_application_target` request and return a typed
    /// [`CreateWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_web_application_target_parsed(
        &mut self,
        name: &str,
        urls: &[String],
        opts: CreateWebApplicationTargetOpts,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.execute(CreateWebApplicationTargetRequest::new(
            name,
            urls.to_vec(),
            opts,
        ))
        .await
    }

    /// Send a `clone_web_application_target` request and return a typed
    /// [`CreateWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.execute(CloneWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
        ))
        .await
    }

    /// Send a `get_web_application_targets` request for one target and return a
    /// typed [`GetWebApplicationTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.execute(GetWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
            tasks,
        ))
        .await
    }

    /// Send a `get_web_application_targets` request and return a typed
    /// [`GetWebApplicationTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_web_application_targets_parsed(
        &mut self,
        opts: GetWebApplicationTargetsOpts,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.execute(GetWebApplicationTargetsRequest::new(opts))
            .await
    }

    /// Send a `modify_web_application_target` request and return a typed
    /// [`ModifyWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
        opts: ModifyWebApplicationTargetOpts,
    ) -> Result<ModifyWebApplicationTargetResponse, GvmError> {
        self.execute(ModifyWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `delete_web_application_target` request and return a typed
    /// [`DeleteWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteWebApplicationTargetResponse, GvmError> {
        self.execute(DeleteWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
            ultimate,
        ))
        .await
    }
}
