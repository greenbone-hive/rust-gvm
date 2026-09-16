// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::oci_image_targets::{
    CloneOciImageTargetRequest, CreateOciImageTargetRequest, DeleteOciImageTargetRequest,
    GetOciImageTargetRequest, GetOciImageTargetsRequest, ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::targets::{
    CreateTargetRequest, DeleteTargetRequest, GetTargetRequest, GetTargetsRequest,
    ModifyTargetRequest,
};
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, CreateWebApplicationTargetRequest,
    DeleteWebApplicationTargetRequest, GetWebApplicationTargetRequest,
    GetWebApplicationTargetsRequest, ModifyWebApplicationTargetRequest,
};
use gvm_gmp::responses::{
    CreateOciImageTargetResponse, CreateTargetResponse, CreateWebApplicationTargetResponse,
    DeleteOciImageTargetResponse, DeleteTargetResponse, DeleteWebApplicationTargetResponse,
    GetOciImageTargetsResponse, GetTargetsResponse, GetWebApplicationTargetsResponse,
    ModifyOciImageTargetResponse, ModifyTargetResponse, ModifyWebApplicationTargetResponse,
};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Targets ───────────────────────────────────────────────────────────────

    /// Send a `get_targets` request and return a typed [`GetTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_targets(
        &mut self,
        request: GetTargetsRequest,
    ) -> Result<GetTargetsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_targets` request for one target and return a typed
    /// [`GetTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_target(
        &mut self,
        request: GetTargetRequest,
    ) -> Result<GetTargetsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_target` request and return a typed [`CreateTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_target(
        &mut self,
        request: CreateTargetRequest,
    ) -> Result<CreateTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_target` request and return a typed [`ModifyTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_target(
        &mut self,
        request: ModifyTargetRequest,
    ) -> Result<ModifyTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_target` request and return a typed [`DeleteTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_target(
        &mut self,
        request: DeleteTargetRequest,
    ) -> Result<DeleteTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_oci_image_target` request and return a typed
    /// [`CreateOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_oci_image_target(
        &mut self,
        request: CreateOciImageTargetRequest,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_oci_image_target` request and return a typed
    /// [`CreateOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_oci_image_target(
        &mut self,
        request: CloneOciImageTargetRequest,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_oci_image_targets` request for one target and return a typed
    /// [`GetOciImageTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_oci_image_target(
        &mut self,
        request: GetOciImageTargetRequest,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_oci_image_targets` request and return a typed
    /// [`GetOciImageTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_oci_image_targets(
        &mut self,
        request: GetOciImageTargetsRequest,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_oci_image_target` request and return a typed
    /// [`ModifyOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_oci_image_target(
        &mut self,
        request: ModifyOciImageTargetRequest,
    ) -> Result<ModifyOciImageTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_oci_image_target` request and return a typed
    /// [`DeleteOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_oci_image_target(
        &mut self,
        request: DeleteOciImageTargetRequest,
    ) -> Result<DeleteOciImageTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_web_application_target` request and return a typed
    /// [`CreateWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_web_application_target(
        &mut self,
        request: CreateWebApplicationTargetRequest,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_web_application_target` request and return a typed
    /// [`CreateWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_web_application_target(
        &mut self,
        request: CloneWebApplicationTargetRequest,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_web_application_targets` request for one target and return a
    /// typed [`GetWebApplicationTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_web_application_target(
        &mut self,
        request: GetWebApplicationTargetRequest,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_web_application_targets` request and return a typed
    /// [`GetWebApplicationTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_web_application_targets(
        &mut self,
        request: GetWebApplicationTargetsRequest,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_web_application_target` request and return a typed
    /// [`ModifyWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_web_application_target(
        &mut self,
        request: ModifyWebApplicationTargetRequest,
    ) -> Result<ModifyWebApplicationTargetResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_web_application_target` request and return a typed
    /// [`DeleteWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_web_application_target(
        &mut self,
        request: DeleteWebApplicationTargetRequest,
    ) -> Result<DeleteWebApplicationTargetResponse, GvmError> {
        self.execute(request).await
    }
}
