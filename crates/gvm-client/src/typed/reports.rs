// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::report_configs::{
    CloneReportConfigRequest, CreateReportConfigOpts, CreateReportConfigRequest,
    CreateReportConfigWithOptsRequest, DeleteReportConfigOpts, DeleteReportConfigRequest,
    DeleteReportConfigWithOptsRequest, GetReportConfigRequest, GetReportConfigsOpts,
    GetReportConfigsWithOptsRequest, ModifyReportConfigOpts, ModifyReportConfigRequest,
};
use gvm_gmp::commands::report_formats::{
    CloneReportFormatRequest, CreateReportFormatRequest, DeleteReportFormatRequest,
    GetReportFormatRequest, GetReportFormatsOpts, GetReportFormatsRequest,
    ImportReportFormatRequest, ModifyReportFormatRequest, ReportFormatOpts,
    VerifyReportFormatRequest,
};
use gvm_gmp::commands::reports::{
    ExportScanReportOpts, ExportScanReportRequest, GetAuditReportHostsOpts,
    GetAuditReportHostsRequest, GetAuditReportOpts, GetAuditReportRequest,
    GetReportApplicationsRequest, GetReportClosedCvesRequest, GetReportCvesRequest,
    GetReportDetailsOpts, GetReportErrorsRequest, GetReportExportOpts, GetReportExportRequest,
    GetReportHostsRequest, GetReportOperatingSystemsRequest, GetReportPortsRequest,
    GetReportTlsCertificatesRequest, GetReportVulnsRequest, GetReportsOpts, GetReportsRequest,
    ImportReportOpts, ImportReportRequest,
};
use gvm_gmp::commands::results::{GetResultRequest, GetResultsOpts, GetResultsRequest};
use gvm_gmp::commands::tls_certificates::{
    CloneTlsCertificateRequest, CreateTlsCertificateRequest, DeleteTlsCertificateRequest,
    GetTlsCertificateRequest, GetTlsCertificatesOpts, GetTlsCertificatesRequest,
    ModifyTlsCertificateRequest, TlsCertificateOpts,
};
use gvm_gmp::responses::{
    CreateReportConfigResponse, CreateReportFormatResponse, CreateReportResponse,
    CreateTlsCertificateResponse, DeleteReportConfigResponse, DeleteReportFormatResponse,
    DeleteTlsCertificateResponse, ExportScanReportResponse, GetAuditReportHostsResponse,
    GetAuditReportResponse, GetReportApplicationsResponse, GetReportClosedCvesResponse,
    GetReportConfigsResponse, GetReportCvesResponse, GetReportErrorsResponse,
    GetReportFormatsResponse, GetReportHostsResponse, GetReportOperatingSystemsResponse,
    GetReportPortsResponse, GetReportTlsCertificatesResponse, GetReportVulnsResponse,
    GetReportsResponse, GetResultsResponse, GetTlsCertificatesResponse, ModifyReportConfigResponse,
    ModifyReportFormatResponse, ModifyTlsCertificateResponse, ReportExport,
    VerifyReportFormatResponse,
};
use gvm_gmp::types::EntityId;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Reports ───────────────────────────────────────────────────────────────

    /// Send a `get_audit_report` request and return a typed structured report.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit_report(
        &mut self,
        audit_report_id: &EntityId,
        opts: GetAuditReportOpts,
    ) -> Result<GetAuditReportResponse, GvmError> {
        self.execute(GetAuditReportRequest::new(audit_report_id.clone(), opts))
            .await
    }

    /// Send a `get_audit_report_hosts` request and return typed host summaries.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetAuditReportHostsOpts,
    ) -> Result<GetAuditReportHostsResponse, GvmError> {
        self.execute(GetAuditReportHostsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_reports` request and return a typed [`GetReportsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_reports(
        &mut self,
        opts: GetReportsOpts,
    ) -> Result<GetReportsResponse, GvmError> {
        self.execute(GetReportsRequest::new(opts)).await
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
        report_id: &EntityId,
        opts: ExportScanReportOpts,
    ) -> Result<ExportScanReportResponse, GvmError> {
        self.execute(ExportScanReportRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_vulns` request and return a typed [`GetReportVulnsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_vulns(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportVulnsResponse, GvmError> {
        self.execute(GetReportVulnsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_vulns` request using python-gvm's descriptive helper
    /// name and return a typed [`GetReportVulnsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_vulnerabilities(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportVulnsResponse, GvmError> {
        self.execute(GetReportVulnsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_tls_certificates` request and return a typed [`GetReportTlsCertificatesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_tls_certificates(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportTlsCertificatesResponse, GvmError> {
        self.execute(GetReportTlsCertificatesRequest::new(
            report_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `get_report_hosts` request and return a typed
    /// [`GetReportHostsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_hosts`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_hosts_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportHostsResponse, GvmError> {
        self.execute(GetReportHostsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_ports` request and return a typed
    /// [`GetReportPortsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_ports`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_ports_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportPortsResponse, GvmError> {
        self.execute(GetReportPortsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_applications` request and return a typed
    /// [`GetReportApplicationsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_applications`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_applications_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportApplicationsResponse, GvmError> {
        self.execute(GetReportApplicationsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_operating_systems` request and return a typed
    /// [`GetReportOperatingSystemsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_operating_systems`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_operating_systems_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportOperatingSystemsResponse, GvmError> {
        self.execute(GetReportOperatingSystemsRequest::new(
            report_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `get_report_cves` request and return a typed
    /// [`GetReportCvesResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_cves`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_cves_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportCvesResponse, GvmError> {
        self.execute(GetReportCvesRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_errors` request and return a typed [`GetReportErrorsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_errors(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportErrorsResponse, GvmError> {
        self.execute(GetReportErrorsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_closed_cves` request and return a typed [`GetReportClosedCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_closed_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportClosedCvesResponse, GvmError> {
        self.execute(GetReportClosedCvesRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_reports` export request and return a typed [`ReportExport`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_export(
        &mut self,
        report_id: &EntityId,
        report_format_id: &EntityId,
    ) -> Result<ReportExport, GvmError> {
        self.execute(GetReportExportRequest::new(
            report_id.clone(),
            GetReportExportOpts::new(report_format_id.clone()),
        ))
        .await
    }

    /// Send a `get_reports` export request with export options and return a typed [`ReportExport`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_export_with_opts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportExportOpts,
    ) -> Result<ReportExport, GvmError> {
        self.execute(GetReportExportRequest::new(report_id.clone(), opts))
            .await
    }

    // ── Results ───────────────────────────────────────────────────────────────

    /// Send a `get_results` request and return a typed [`GetResultsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_results(
        &mut self,
        opts: GetResultsOpts,
    ) -> Result<GetResultsResponse, GvmError> {
        self.execute(GetResultsRequest::new(opts)).await
    }

    /// Send a single-result `get_results` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_result(
        &mut self,
        result_id: &EntityId,
    ) -> Result<GetResultsResponse, GvmError> {
        self.execute(GetResultRequest::new(result_id.clone())).await
    }

    // ── TLS Certificates ──────────────────────────────────────────────────────

    /// Send a `get_tls_certificates` request and return a typed
    /// [`GetTlsCertificatesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tls_certificates(
        &mut self,
        opts: GetTlsCertificatesOpts,
    ) -> Result<GetTlsCertificatesResponse, GvmError> {
        self.execute(GetTlsCertificatesRequest::new(opts)).await
    }

    /// Send a detailed `get_tls_certificates` request for one certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
    ) -> Result<GetTlsCertificatesResponse, GvmError> {
        self.execute(GetTlsCertificateRequest::new(tls_certificate_id.clone()))
            .await
    }

    /// Send a `create_tls_certificate` request and return a typed
    /// [`CreateTlsCertificateResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_tls_certificate(
        &mut self,
        name: &str,
        opts: TlsCertificateOpts,
    ) -> Result<CreateTlsCertificateResponse, GvmError> {
        self.execute(CreateTlsCertificateRequest::new(name, opts))
            .await
    }

    /// Clone a TLS certificate through `create_tls_certificate`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
    ) -> Result<CreateTlsCertificateResponse, GvmError> {
        self.execute(CloneTlsCertificateRequest::new(tls_certificate_id.clone()))
            .await
    }

    /// Modify a TLS certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
        opts: TlsCertificateOpts,
    ) -> Result<ModifyTlsCertificateResponse, GvmError> {
        self.execute(ModifyTlsCertificateRequest::new(
            tls_certificate_id.clone(),
            opts,
        ))
        .await
    }

    /// Delete a TLS certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteTlsCertificateResponse, GvmError> {
        self.execute(DeleteTlsCertificateRequest::new(
            tls_certificate_id.clone(),
            ultimate,
        ))
        .await
    }

    // ── Report Formats ────────────────────────────────────────────────────────

    /// Send a `get_report_formats` request and return a typed [`GetReportFormatsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_formats(
        &mut self,
        opts: GetReportFormatsOpts,
    ) -> Result<GetReportFormatsResponse, GvmError> {
        self.execute(GetReportFormatsRequest::new(opts)).await
    }

    /// Send a detailed `get_report_formats` request for one report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_format(
        &mut self,
        report_format_id: &EntityId,
    ) -> Result<GetReportFormatsResponse, GvmError> {
        self.execute(GetReportFormatRequest::new(report_format_id.clone()))
            .await
    }

    /// Send a `create_report_format` request and return a typed
    /// [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_report_format(
        &mut self,
        name: &str,
        opts: ReportFormatOpts,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(CreateReportFormatRequest::new(name, opts))
            .await
    }

    /// Send a `create_report_format` request that clones an existing report
    /// format and return a typed [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_report_format(
        &mut self,
        report_format_id: &EntityId,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(CloneReportFormatRequest::new(report_format_id.clone()))
            .await
    }

    /// Send a `create_report_format` request that imports report-format XML and
    /// return a typed [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn import_report_format(
        &mut self,
        report_format_xml: &str,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(ImportReportFormatRequest::new(report_format_xml)?)
            .await
    }

    /// Modify a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_report_format(
        &mut self,
        report_format_id: &EntityId,
        opts: ReportFormatOpts,
    ) -> Result<ModifyReportFormatResponse, GvmError> {
        self.execute(ModifyReportFormatRequest::new(
            report_format_id.clone(),
            opts,
        ))
        .await
    }

    /// Delete a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_format(
        &mut self,
        report_format_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteReportFormatResponse, GvmError> {
        self.execute(DeleteReportFormatRequest::new(
            report_format_id.clone(),
            ultimate,
        ))
        .await
    }

    /// Verify a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_report_format(
        &mut self,
        report_format_id: &EntityId,
    ) -> Result<VerifyReportFormatResponse, GvmError> {
        self.execute(VerifyReportFormatRequest::new(report_format_id.clone()))
            .await
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
        report_xml: &str,
        task_id: &EntityId,
        opts: ImportReportOpts,
    ) -> Result<CreateReportResponse, GvmError> {
        self.execute(ImportReportRequest::new(report_xml, task_id, opts)?)
            .await
    }

    // ── Report Configs ────────────────────────────────────────────────────────

    /// Send a `get_report_configs` request with filter options and return a typed
    /// [`GetReportConfigsResponse`].
    ///
    /// Note: This method uses the `_parsed` suffix to avoid conflicting with the
    /// [`crate::Gmp226Commands::get_report_configs`] trait method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_configs_parsed(
        &mut self,
        opts: GetReportConfigsOpts,
    ) -> Result<GetReportConfigsResponse, GvmError> {
        self.execute(GetReportConfigsWithOptsRequest::new(opts))
            .await
    }

    /// Send a detailed `get_report_configs` request for one report configuration.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_config(
        &mut self,
        id: &str,
    ) -> Result<GetReportConfigsResponse, GvmError> {
        self.execute(GetReportConfigRequest::new(id)).await
    }

    /// Create a report configuration with default options.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_report_config(
        &mut self,
        name: &str,
        report_format_id: &str,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(CreateReportConfigRequest::new(name, report_format_id))
            .await
    }

    /// Create a report configuration with optional fields.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_report_config_with_opts(
        &mut self,
        name: &str,
        report_format_id: &str,
        opts: CreateReportConfigOpts,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(CreateReportConfigWithOptsRequest::new(
            name,
            report_format_id,
            opts,
        ))
        .await
    }

    /// Send a `clone_report_config` request and return a typed
    /// [`CreateReportConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_report_config(
        &mut self,
        id: &str,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(CloneReportConfigRequest::new(id)).await
    }

    /// Modify a report configuration.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_report_config(
        &mut self,
        id: &str,
        opts: ModifyReportConfigOpts,
    ) -> Result<ModifyReportConfigResponse, GvmError> {
        self.execute(ModifyReportConfigRequest::new(id, opts)).await
    }

    /// Delete a report configuration with default options.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_config(
        &mut self,
        id: &str,
    ) -> Result<DeleteReportConfigResponse, GvmError> {
        self.execute(DeleteReportConfigRequest::new(id)).await
    }

    /// Delete a report configuration with optional fields.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_config_with_opts(
        &mut self,
        id: &str,
        opts: DeleteReportConfigOpts,
    ) -> Result<DeleteReportConfigResponse, GvmError> {
        self.execute(DeleteReportConfigWithOptsRequest::new(id, opts))
            .await
    }
}
