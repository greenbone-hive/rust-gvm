// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::report_configs::{
    CloneReportConfigRequest, CreateReportConfigRequest, DeleteReportConfigRequest,
    GetReportConfigRequest, GetReportConfigsRequest, ModifyReportConfigRequest,
};
use gvm_gmp::commands::report_formats::{
    CloneReportFormatRequest, DeleteReportFormatRequest, GetReportFormatRequest,
    GetReportFormatsRequest, ImportReportFormatRequest, ModifyReportFormatRequest,
    VerifyReportFormatRequest,
};
use gvm_gmp::commands::reports::{
    DeleteAuditReportRequest, DeleteReportRequest, ExportScanReportRequest,
    GetAuditReportHostsRequest, GetAuditReportRequest, GetAuditReportsRequest,
    GetReportApplicationsRequest, GetReportClosedCvesRequest, GetReportCvesRequest,
    GetReportErrorsRequest, GetReportExportRequest, GetReportHostsRequest,
    GetReportOperatingSystemsRequest, GetReportPortsRequest, GetReportRequest,
    GetReportTlsCertificatesRequest, GetReportVulnsRequest, GetReportsRequest,
    GetScanReportRequest, ImportReportRequest,
};
use gvm_gmp::commands::results::{GetResultRequest, GetResultsRequest};
use gvm_gmp::commands::tls_certificates::{
    CloneTlsCertificateRequest, CreateTlsCertificateRequest, DeleteTlsCertificateRequest,
    GetTlsCertificateRequest, GetTlsCertificatesRequest, ModifyTlsCertificateRequest,
};
use gvm_gmp::responses::{
    CreateReportConfigResponse, CreateReportFormatResponse, CreateReportResponse,
    CreateTlsCertificateResponse, DeleteReportConfigResponse, DeleteReportFormatResponse,
    DeleteReportResponse, DeleteTlsCertificateResponse, ExportScanReportResponse,
    GetAuditReportHostsResponse, GetAuditReportResponse, GetAuditReportsResponse,
    GetReportApplicationsResponse, GetReportClosedCvesResponse, GetReportConfigsResponse,
    GetReportCvesResponse, GetReportErrorsResponse, GetReportFormatsResponse,
    GetReportHostsResponse, GetReportOperatingSystemsResponse, GetReportPortsResponse,
    GetReportTlsCertificatesResponse, GetReportVulnsResponse, GetReportsResponse,
    GetResultsResponse, GetScanReportResponse, GetTlsCertificatesResponse,
    ModifyReportConfigResponse, ModifyReportFormatResponse, ModifyTlsCertificateResponse,
    ReportExport, VerifyReportFormatResponse,
};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Reports ───────────────────────────────────────────────────────────────

    /// Send a `get_audit_report` request and return a typed structured report.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit_report(
        &mut self,
        request: GetAuditReportRequest,
    ) -> Result<GetAuditReportResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_audit_report_hosts` request and return typed host summaries.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit_report_hosts(
        &mut self,
        request: GetAuditReportHostsRequest,
    ) -> Result<GetAuditReportHostsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_reports` request and return a typed [`GetReportsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_reports(
        &mut self,
        request: GetReportsRequest,
    ) -> Result<GetReportsResponse, GvmError> {
        self.execute(request).await
    }

    /// Retrieve one detailed ordinary scan report.
    ///
    /// # Errors
    /// Returns an error if validation, support checks, transport, or parsing fails.
    pub async fn get_report(
        &mut self,
        request: GetReportRequest,
    ) -> Result<GetReportsResponse, GvmError> {
        self.execute(request).await
    }

    /// List audit reports through the audit-scoped `get_reports` operation.
    ///
    /// # Errors
    /// Returns an error if validation, support checks, transport, or parsing fails.
    pub async fn get_audit_reports(
        &mut self,
        request: GetAuditReportsRequest,
    ) -> Result<GetAuditReportsResponse, GvmError> {
        self.execute(request).await
    }

    /// Retrieve one structured vulnerability report.
    ///
    /// # Errors
    /// Returns an error if validation, support checks, transport, or parsing fails.
    pub async fn get_scan_report(
        &mut self,
        request: GetScanReportRequest,
    ) -> Result<GetScanReportResponse, GvmError> {
        self.execute(request).await
    }

    /// Permanently delete one ordinary scan report.
    ///
    /// # Errors
    /// Returns an error if support checks, transport, or parsing fails.
    pub async fn delete_report(
        &mut self,
        request: DeleteReportRequest,
    ) -> Result<DeleteReportResponse, GvmError> {
        self.execute(request).await
    }

    /// Delete one audit report through the non-ultimate audit semantic alias.
    ///
    /// # Errors
    /// Returns an error if support checks, transport, or parsing fails.
    pub async fn delete_audit_report(
        &mut self,
        request: DeleteAuditReportRequest,
    ) -> Result<DeleteReportResponse, GvmError> {
        self.execute(request).await
    }

    /// Queue or reuse an asynchronous scan-report export and return its typed
    /// identifier and optional processing status.
    ///
    /// Call [`GmpClient::discover_commands`] first. The negotiated GMP version
    /// does not prove that the server implements this command.
    ///
    /// # Errors
    /// Returns [`crate::GvmError::CommandDiscoveryRequired`] before discovery,
    /// [`crate::GvmError::CommandNotAdvertised`] when discovery omits the
    /// command, or a request/response error after it is attempted.
    pub async fn export_scan_report(
        &mut self,
        request: ExportScanReportRequest,
    ) -> Result<ExportScanReportResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_vulns` request and return a typed [`GetReportVulnsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_vulns(
        &mut self,
        request: GetReportVulnsRequest,
    ) -> Result<GetReportVulnsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_tls_certificates` request and return a typed [`GetReportTlsCertificatesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_tls_certificates(
        &mut self,
        request: GetReportTlsCertificatesRequest,
    ) -> Result<GetReportTlsCertificatesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_hosts` request and return a typed
    /// [`GetReportHostsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_hosts(
        &mut self,
        request: GetReportHostsRequest,
    ) -> Result<GetReportHostsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_ports` request and return a typed
    /// [`GetReportPortsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_ports(
        &mut self,
        request: GetReportPortsRequest,
    ) -> Result<GetReportPortsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_applications` request and return a typed
    /// [`GetReportApplicationsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_applications(
        &mut self,
        request: GetReportApplicationsRequest,
    ) -> Result<GetReportApplicationsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_operating_systems` request and return a typed
    /// [`GetReportOperatingSystemsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_operating_systems(
        &mut self,
        request: GetReportOperatingSystemsRequest,
    ) -> Result<GetReportOperatingSystemsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_cves` request and return a typed
    /// [`GetReportCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_cves(
        &mut self,
        request: GetReportCvesRequest,
    ) -> Result<GetReportCvesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_errors` request and return a typed [`GetReportErrorsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_errors(
        &mut self,
        request: GetReportErrorsRequest,
    ) -> Result<GetReportErrorsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_report_closed_cves` request and return a typed [`GetReportClosedCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_closed_cves(
        &mut self,
        request: GetReportClosedCvesRequest,
    ) -> Result<GetReportClosedCvesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_reports` export request and return a typed [`ReportExport`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_export(
        &mut self,
        request: GetReportExportRequest,
    ) -> Result<ReportExport, GvmError> {
        self.execute(request).await
    }

    // ── Results ───────────────────────────────────────────────────────────────

    /// Send a `get_results` request and return a typed [`GetResultsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_results(
        &mut self,
        request: GetResultsRequest,
    ) -> Result<GetResultsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a single-result `get_results` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_result(
        &mut self,
        request: GetResultRequest,
    ) -> Result<GetResultsResponse, GvmError> {
        self.execute(request).await
    }

    // ── TLS Certificates ──────────────────────────────────────────────────────

    /// Send a `get_tls_certificates` request and return a typed
    /// [`GetTlsCertificatesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tls_certificates(
        &mut self,
        request: GetTlsCertificatesRequest,
    ) -> Result<GetTlsCertificatesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_tls_certificates` request for one certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tls_certificate(
        &mut self,
        request: GetTlsCertificateRequest,
    ) -> Result<GetTlsCertificatesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_tls_certificate` request and return a typed
    /// [`CreateTlsCertificateResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_tls_certificate(
        &mut self,
        request: CreateTlsCertificateRequest,
    ) -> Result<CreateTlsCertificateResponse, GvmError> {
        self.execute(request).await
    }

    /// Clone a TLS certificate through `create_tls_certificate`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_tls_certificate(
        &mut self,
        request: CloneTlsCertificateRequest,
    ) -> Result<CreateTlsCertificateResponse, GvmError> {
        self.execute(request).await
    }

    /// Modify a TLS certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_tls_certificate(
        &mut self,
        request: ModifyTlsCertificateRequest,
    ) -> Result<ModifyTlsCertificateResponse, GvmError> {
        self.execute(request).await
    }

    /// Delete a TLS certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_tls_certificate(
        &mut self,
        request: DeleteTlsCertificateRequest,
    ) -> Result<DeleteTlsCertificateResponse, GvmError> {
        self.execute(request).await
    }

    // ── Report Formats ────────────────────────────────────────────────────────

    /// Send a `get_report_formats` request and return a typed [`GetReportFormatsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_formats(
        &mut self,
        request: GetReportFormatsRequest,
    ) -> Result<GetReportFormatsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_report_formats` request for one report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_format(
        &mut self,
        request: GetReportFormatRequest,
    ) -> Result<GetReportFormatsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_report_format` request that clones an existing report
    /// format and return a typed [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_report_format(
        &mut self,
        request: CloneReportFormatRequest,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_report_format` request that imports report-format XML and
    /// return a typed [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn import_report_format(
        &mut self,
        request: ImportReportFormatRequest,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(request).await
    }

    /// Modify a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_report_format(
        &mut self,
        request: ModifyReportFormatRequest,
    ) -> Result<ModifyReportFormatResponse, GvmError> {
        self.execute(request).await
    }

    /// Delete a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_format(
        &mut self,
        request: DeleteReportFormatRequest,
    ) -> Result<DeleteReportFormatResponse, GvmError> {
        self.execute(request).await
    }

    /// Verify a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_report_format(
        &mut self,
        request: VerifyReportFormatRequest,
    ) -> Result<VerifyReportFormatResponse, GvmError> {
        self.execute(request).await
    }

    // ── Reports ───────────────────────────────────────────────────────────────

    /// Send a `create_report` request that imports report XML and return a typed
    /// [`CreateReportResponse`].
    ///
    /// # Errors
    /// Returns an error if request construction fails, the request fails, or
    /// response parsing fails.
    pub async fn import_report(
        &mut self,
        request: ImportReportRequest,
    ) -> Result<CreateReportResponse, GvmError> {
        self.execute(request).await
    }

    // ── Report Configs ────────────────────────────────────────────────────────

    /// Send a `get_report_configs` request and return a typed
    /// [`GetReportConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_configs(
        &mut self,
        request: GetReportConfigsRequest,
    ) -> Result<GetReportConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed `get_report_configs` request for one report configuration.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_config(
        &mut self,
        request: GetReportConfigRequest,
    ) -> Result<GetReportConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Create a report configuration with default options.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_report_config(
        &mut self,
        request: CreateReportConfigRequest,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_report_config` request and return a typed
    /// [`CreateReportConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_report_config(
        &mut self,
        request: CloneReportConfigRequest,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Modify a report configuration.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_report_config(
        &mut self,
        request: ModifyReportConfigRequest,
    ) -> Result<ModifyReportConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Delete a report configuration with default options.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_config(
        &mut self,
        request: DeleteReportConfigRequest,
    ) -> Result<DeleteReportConfigResponse, GvmError> {
        self.execute(request).await
    }
}
