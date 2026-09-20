// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::aggregates::{GetAggregatesRequest, GetLegacyAggregatesRequest};
use gvm_gmp::commands::features::GetFeaturesRequest;
use gvm_gmp::commands::help::HelpRequest;
use gvm_gmp::commands::resource_names::{GetResourceNameRequest, GetResourceNamesRequest};
use gvm_gmp::commands::system::{
    DescribeAuthRequest, GetLicenseRequest, GetSettingsRequest, ModifyAuthRequest,
    ModifyLicenseOpts, ModifyLicenseWithOptsRequest, RunWizardOpts, RunWizardWithOptsRequest,
};
use gvm_gmp::commands::system_reports::GetSystemReportsRequest;
use gvm_gmp::responses::{
    DescribeAuthResponse, GetAggregatesResponse, GetFeaturesResponse, GetLicenseResponse,
    GetResourceNamesResponse, GetSettingsResponse, GetSystemReportsResponse, HelpResponse,
    ModifyAuthResponse, ModifyLicenseResponse, RunWizardResponse,
};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── System ────────────────────────────────────────────────────────────────

    /// Send a current gvmd `get_aggregates` request and return its typed result.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_aggregates(
        &mut self,
        request: GetAggregatesRequest,
    ) -> Result<GetAggregatesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send the pinned gvmd legacy-attribute aggregate shape.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_legacy_aggregates(
        &mut self,
        request: GetLegacyAggregatesRequest,
    ) -> Result<GetAggregatesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_features` request and return a typed
    /// [`GetFeaturesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_features(
        &mut self,
        request: GetFeaturesRequest,
    ) -> Result<GetFeaturesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_settings` request and return a typed [`GetSettingsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_settings(
        &mut self,
        request: GetSettingsRequest,
    ) -> Result<GetSettingsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_system_reports` request and return typed report metadata and payloads.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_system_reports(
        &mut self,
        request: GetSystemReportsRequest,
    ) -> Result<GetSystemReportsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `help` request and return a typed [`HelpResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_help(&mut self, request: HelpRequest) -> Result<HelpResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `describe_auth` request and return a typed [`DescribeAuthResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn describe_auth(
        &mut self,
        request: DescribeAuthRequest,
    ) -> Result<DescribeAuthResponse, GvmError> {
        self.execute(request).await
    }

    /// Discover resource names for one resource type.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_resource_names(
        &mut self,
        request: GetResourceNamesRequest,
    ) -> Result<GetResourceNamesResponse, GvmError> {
        self.execute(request).await
    }

    /// Discover one resource name.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_resource_name(
        &mut self,
        request: GetResourceNameRequest,
    ) -> Result<GetResourceNamesResponse, GvmError> {
        self.execute(request).await
    }

    /// Retrieve current license status and content.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_license(
        &mut self,
        request: GetLicenseRequest,
    ) -> Result<GetLicenseResponse, GvmError> {
        self.execute(request).await
    }

    /// Modify a named authentication group and return a typed
    /// [`ModifyAuthResponse`].
    ///
    /// `auth_conf_settings` must contain at least one key/value pair.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_auth(
        &mut self,
        group_name: &str,
        auth_conf_settings: &[(String, String)],
    ) -> Result<ModifyAuthResponse, GvmError> {
        self.execute(ModifyAuthRequest::new(
            group_name,
            auth_conf_settings.iter().cloned(),
        ))
        .await
    }

    /// Upload a base64-encoded license file and return a typed
    /// [`ModifyLicenseResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_license(
        &mut self,
        file: &str,
        opts: ModifyLicenseOpts,
    ) -> Result<ModifyLicenseResponse, GvmError> {
        self.execute(ModifyLicenseWithOptsRequest::new(file, opts))
            .await
    }

    /// Run a gvmd wizard and return its typed response envelope.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn run_wizard(
        &mut self,
        name: &str,
        params: &[(String, String)],
        opts: RunWizardOpts,
    ) -> Result<RunWizardResponse, GvmError> {
        self.execute(RunWizardWithOptsRequest::new(
            name,
            params.iter().cloned(),
            opts,
        ))
        .await
    }
}
