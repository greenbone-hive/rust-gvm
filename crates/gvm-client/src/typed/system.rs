// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::aggregates::{GetAggregatesRequest, GetAggregatesRequestOpts};
use gvm_gmp::commands::features::GetFeaturesRequest;
use gvm_gmp::commands::help::{HelpMode, HelpRequest, HelpWithModeRequest};
use gvm_gmp::commands::system::{
    DescribeAuthRequest, GetSettingsRequest, ModifyAuthRequest, ModifyLicenseOpts,
    ModifyLicenseWithOptsRequest, RunWizardOpts, RunWizardWithOptsRequest,
};
use gvm_gmp::commands::system_reports::{GetSystemReportsOpts, GetSystemReportsRequest};
use gvm_gmp::responses::{
    DescribeAuthResponse, GetAggregatesResponse, GetFeaturesResponse, GetSettingsResponse,
    GetSystemReportsResponse, HelpResponse, ModifyAuthResponse, ModifyLicenseResponse,
    RunWizardResponse,
};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── System ────────────────────────────────────────────────────────────────

    /// Send a current gvmd `get_aggregates` request and return its typed result.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_aggregates(
        &mut self,
        resource_type: &str,
        opts: GetAggregatesRequestOpts,
    ) -> Result<GetAggregatesResponse, GvmError> {
        self.execute(GetAggregatesRequest::new(resource_type, opts))
            .await
    }

    /// Send a `get_features` request and return a typed
    /// [`GetFeaturesResponse`].
    ///
    /// The `_parsed` suffix avoids conflicting with the raw
    /// [`crate::Gmp226Commands::get_features`] versioned-client method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_features_parsed(&mut self) -> Result<GetFeaturesResponse, GvmError> {
        self.execute(GetFeaturesRequest::new()).await
    }

    /// Send a `get_settings` request and return a typed [`GetSettingsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_settings(&mut self) -> Result<GetSettingsResponse, GvmError> {
        self.execute(GetSettingsRequest::default()).await
    }

    /// Send a `get_system_reports` request and return typed report metadata and payloads.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_system_reports(
        &mut self,
        opts: GetSystemReportsOpts,
    ) -> Result<GetSystemReportsResponse, GvmError> {
        self.execute(GetSystemReportsRequest::new(opts)).await
    }

    /// Send a `help` request and return a typed [`HelpResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_help(&mut self) -> Result<HelpResponse, GvmError> {
        self.execute(HelpRequest::new(None)).await
    }

    /// Send a `help` request for an explicit response mode.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_help_with_mode(&mut self, mode: HelpMode) -> Result<HelpResponse, GvmError> {
        self.execute(HelpWithModeRequest::new(mode)).await
    }

    /// Send a `describe_auth` request and return a typed [`DescribeAuthResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn describe_auth(&mut self) -> Result<DescribeAuthResponse, GvmError> {
        self.execute(DescribeAuthRequest::new()).await
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
