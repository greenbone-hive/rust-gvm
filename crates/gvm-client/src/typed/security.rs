// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::credentials::{
    CreateCredentialRequest, CreateCredentialStoreCredentialRequest, DeleteCredentialRequest,
    GetCredentialStoreRequest, GetCredentialStoresRequest, GetCredentialsRequest,
    ModifyCredentialRequest, ModifyCredentialStoreCredentialRequest, VerifyCredentialStoreRequest,
};
use gvm_gmp::commands::feed::{GetFeedRequest, GetFeedsRequest};
use gvm_gmp::commands::nvts::{
    GetNvtFamiliesRequest, GetNvtPreferenceRequest, GetNvtPreferencesRequest, GetNvtRequest,
    GetNvtsRequest, GetScanConfigNvtRequest, GetScanConfigNvtsRequest,
};
use gvm_gmp::commands::secinfo::{
    GetCertBundAdvisoriesRequest, GetCertBundAdvisoryRequest, GetCpeRequest, GetCpesRequest,
    GetCveRequest, GetCvesRequest, GetDfnCertAdvisoriesRequest, GetDfnCertAdvisoryRequest,
    GetInfoListRequest, GetInfoRequest,
};
use gvm_gmp::commands::system::{GetTimezonesRequest, GetVulnerabilityRequest, GetVulnsRequest};
use gvm_gmp::responses::{
    CreateCredentialResponse, DeleteCredentialResponse, GetCertBundAdvisoriesResponse,
    GetCpesResponse, GetCredentialStoresResponse, GetCredentialsResponse, GetCvesResponse,
    GetDfnCertAdvisoriesResponse, GetFeedsResponse, GetInfoResponse, GetNvtFamiliesResponse,
    GetNvtsResponse, GetPreferencesResponse, GetTimezonesResponse, GetVulnerabilitiesResponse,
    ModifyCredentialResponse, VerifyCredentialStoreResponse,
};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Feeds ─────────────────────────────────────────────────────────────────

    /// Send a `get_feeds` request and return a typed [`GetFeedsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_feeds(
        &mut self,
        request: GetFeedsRequest,
    ) -> Result<GetFeedsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a type-filtered `get_feeds` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_feed(
        &mut self,
        request: GetFeedRequest,
    ) -> Result<GetFeedsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_timezones` request and return a typed [`GetTimezonesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_timezones(
        &mut self,
        request: GetTimezonesRequest,
    ) -> Result<GetTimezonesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_credential_stores` request and return a typed [`GetCredentialStoresResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credential_stores(
        &mut self,
        request: GetCredentialStoresRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `verify_credential_store` request and return a typed
    /// [`VerifyCredentialStoreResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_credential_store(
        &mut self,
        request: VerifyCredentialStoreRequest,
    ) -> Result<VerifyCredentialStoreResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a filtered `get_credential_stores` request and return a typed
    /// [`GetCredentialStoresResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credential_stores_with_opts(
        &mut self,
        request: GetCredentialStoresRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a single-store `get_credential_stores` request and return a typed
    /// [`GetCredentialStoresResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credential_store(
        &mut self,
        request: GetCredentialStoreRequest,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.execute(request).await
    }

    // ── NVTs ──────────────────────────────────────────────────────────────────

    /// Send a `get_nvts` request and return a typed [`GetNvtsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvts(&mut self, request: GetNvtsRequest) -> Result<GetNvtsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_nvts` request for one NVT.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt(&mut self, request: GetNvtRequest) -> Result<GetNvtsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a scan-config scoped `get_nvts` request and return a typed [`GetNvtsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config_nvts(
        &mut self,
        request: GetScanConfigNvtsRequest,
    ) -> Result<GetNvtsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a scan-config compatibility `get_nvts` request for a single NVT.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config_nvt(
        &mut self,
        request: GetScanConfigNvtRequest,
    ) -> Result<GetNvtsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_preferences` request for NVT preferences.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt_preferences(
        &mut self,
        request: GetNvtPreferencesRequest,
    ) -> Result<GetPreferencesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_preferences` request for one NVT preference.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt_preference(
        &mut self,
        request: GetNvtPreferenceRequest,
    ) -> Result<GetPreferencesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_nvt_families` request and return a typed [`GetNvtFamiliesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt_families(
        &mut self,
        request: GetNvtFamiliesRequest,
    ) -> Result<GetNvtFamiliesResponse, GvmError> {
        self.execute(request).await
    }

    // ── SecInfo ───────────────────────────────────────────────────────────────

    /// Send a `get_info` request for CVE entries and return a typed [`GetCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cves(&mut self, request: GetCvesRequest) -> Result<GetCvesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_info` request for a single CVE entry and return a typed
    /// [`GetCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cve(&mut self, request: GetCveRequest) -> Result<GetCvesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_info` request for CPE entries and return a typed [`GetCpesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cpes(&mut self, request: GetCpesRequest) -> Result<GetCpesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_info` request for a single CPE entry and return a typed
    /// [`GetCpesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cpe(&mut self, request: GetCpeRequest) -> Result<GetCpesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_info` request for CERT-Bund advisories and return a typed
    /// [`GetCertBundAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cert_bund_advisories(
        &mut self,
        request: GetCertBundAdvisoriesRequest,
    ) -> Result<GetCertBundAdvisoriesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_info` request for a single CERT-Bund advisory and return a
    /// typed [`GetCertBundAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cert_bund_advisory(
        &mut self,
        request: GetCertBundAdvisoryRequest,
    ) -> Result<GetCertBundAdvisoriesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_info` request for DFN-CERT advisories and return a typed
    /// [`GetDfnCertAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_dfn_cert_advisories(
        &mut self,
        request: GetDfnCertAdvisoriesRequest,
    ) -> Result<GetDfnCertAdvisoriesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_info` request for a single DFN-CERT advisory and return a
    /// typed [`GetDfnCertAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_dfn_cert_advisory(
        &mut self,
        request: GetDfnCertAdvisoryRequest,
    ) -> Result<GetDfnCertAdvisoriesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a generic single-entry `get_info` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_info(&mut self, request: GetInfoRequest) -> Result<GetInfoResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a generic `get_info` list request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_info_list(
        &mut self,
        request: GetInfoListRequest,
    ) -> Result<GetInfoResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_vulns` request for vulnerabilities and return a typed
    /// [`GetVulnerabilitiesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_vulnerabilities(
        &mut self,
        request: GetVulnsRequest,
    ) -> Result<GetVulnerabilitiesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_vulns` request for a single vulnerability and return a typed
    /// [`GetVulnerabilitiesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_vulnerability(
        &mut self,
        request: GetVulnerabilityRequest,
    ) -> Result<GetVulnerabilitiesResponse, GvmError> {
        self.execute(request).await
    }

    // ── Credentials ───────────────────────────────────────────────────────────

    /// Send a `get_credentials` request and return a typed [`GetCredentialsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credentials(
        &mut self,
        request: GetCredentialsRequest,
    ) -> Result<GetCredentialsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_credential` request and return a typed [`CreateCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_credential(
        &mut self,
        request: CreateCredentialRequest,
    ) -> Result<CreateCredentialResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_credential` request and return a typed
    /// [`ModifyCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_credential(
        &mut self,
        request: ModifyCredentialRequest,
    ) -> Result<ModifyCredentialResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_credential` request and return a typed
    /// [`DeleteCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_credential(
        &mut self,
        request: DeleteCredentialRequest,
    ) -> Result<DeleteCredentialResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a credential-store-backed `create_credential` request and return a
    /// typed [`CreateCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_credential_store_credential(
        &mut self,
        request: CreateCredentialStoreCredentialRequest,
    ) -> Result<CreateCredentialResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a credential-store-backed `modify_credential` request and return a
    /// typed [`ModifyCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_credential_store_credential(
        &mut self,
        request: ModifyCredentialStoreCredentialRequest,
    ) -> Result<ModifyCredentialResponse, GvmError> {
        self.execute(request).await
    }
}
