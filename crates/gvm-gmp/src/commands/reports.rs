// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical report lifecycle, projection, and export requests.

use std::fmt;

use gvm_protocol::{Request as _, XmlCommand};
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::commands::usage_type::UsageType;
use crate::common::{add_filter_attrs, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateReportResponse, DeleteReportResponse, ExportScanReportResponse,
    GetAuditReportHostsResponse, GetAuditReportResponse, GetAuditReportsResponse,
    GetReportApplicationsResponse, GetReportClosedCvesResponse, GetReportCvesResponse,
    GetReportErrorsResponse, GetReportHostsResponse, GetReportOperatingSystemsResponse,
    GetReportPortsResponse, GetReportTlsCertificatesResponse, GetReportVulnsResponse,
    GetReportsResponse, GetScanReportResponse, ReportExport,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for importing one XML report into an existing import task.
///
/// The original XML bytes are retained verbatim. Validation confirms that the
/// payload is exactly one embedded `<report>` envelope before command support
/// is checked or transport is attempted.
#[derive(Clone)]
pub struct ImportReportRequest {
    /// Existing import-task relationship.
    pub task_id: EntityId,
    /// Original report envelope bytes.
    pub report_xml: Vec<u8>,
    /// Whether host assets in the imported report should be created or updated.
    /// Omission lets gvmd apply its false/default behavior.
    pub in_assets: Option<bool>,
}

impl ImportReportRequest {
    /// Own a report envelope for import into `task_id`.
    #[must_use]
    pub fn new(task_id: EntityId, report_xml: impl AsRef<[u8]>) -> Self {
        Self {
            task_id,
            report_xml: report_xml.as_ref().to_vec(),
            in_assets: None,
        }
    }
}

impl fmt::Debug for ImportReportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportReportRequest")
            .field("task_id", &self.task_id)
            .field("report_xml", &"<redacted>")
            .field("in_assets", &self.in_assets)
            .finish()
    }
}

impl GmpRequestCodec for ImportReportRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_report_envelope(&self.report_xml)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_report",
            "import_report",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(import_report_bytes(self))
    }
}

impl GmpRequest for ImportReportRequest {
    type Response = CreateReportResponse;
}

/// Request for permanently deleting an ordinary scan report.
///
/// Pinned gvmd does not parse an `ultimate` attribute for reports. Unlike
/// trash-capable resources, a successful report deletion is permanent.
#[derive(Debug, Clone)]
pub struct DeleteReportRequest {
    /// Report identifier to delete.
    pub report_id: EntityId,
}

impl DeleteReportRequest {
    /// Create a permanent report-deletion request.
    #[must_use]
    pub fn new(report_id: EntityId) -> Self {
        Self { report_id }
    }
}

impl GmpRequestCodec for DeleteReportRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_report"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_report_command(&self.report_id).to_bytes())
    }
}

impl GmpRequest for DeleteReportRequest {
    type Response = DeleteReportResponse;
}

/// Request for deleting an audit report through the shared report command.
///
/// This semantic alias deliberately emits no unsupported permanence
/// attribute and is available only with the GMP 22.6 audit-report surface.
#[derive(Debug, Clone)]
pub struct DeleteAuditReportRequest {
    /// Audit-report identifier to delete.
    pub audit_report_id: EntityId,
}

impl DeleteAuditReportRequest {
    /// Create an audit-report deletion request.
    #[must_use]
    pub fn new(audit_report_id: EntityId) -> Self {
        Self { audit_report_id }
    }
}

impl GmpRequestCodec for DeleteAuditReportRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "delete_report",
            "delete_audit_report",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_report_command(&self.audit_report_id).to_bytes())
    }
}

impl GmpRequest for DeleteAuditReportRequest {
    type Response = DeleteReportResponse;
}

/// Request for listing ordinary scan reports.
#[derive(Debug, Clone, Default)]
pub struct GetReportsRequest {
    /// Optional inline report filter, encoded as `report_filter`.
    pub filter_string: Option<String>,
    /// Optional saved report filter, encoded as `report_filt_id`.
    pub filter_id: Option<EntityId>,
    /// Whether report bodies and result details are included. Omission is false.
    pub details: Option<bool>,
    /// Whether pagination terms in the report filter are ignored. Omission is false.
    pub ignore_pagination: Option<bool>,
    /// Whether details are included for notes selected by the result filter.
    pub notes_details: Option<bool>,
    /// Whether details are included for overrides selected by the result filter.
    pub overrides_details: Option<bool>,
    /// Whether result tags are included.
    pub result_tags: Option<bool>,
    /// Whether gvmd may omit selected redundant report fields.
    pub lean: Option<bool>,
}

impl GmpRequestCodec for GetReportsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_reports"))
    }

    fn encode(&self, version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_reports_command(self, UsageType::Scan, version).to_bytes())
    }
}

impl GmpRequest for GetReportsRequest {
    type Response = GetReportsResponse;
}

/// Request for one detailed ordinary scan report.
#[derive(Debug, Clone)]
pub struct GetReportRequest {
    /// Report identifier to retrieve.
    pub report_id: EntityId,
    /// Optional inline result filter.
    pub filter_string: Option<String>,
    /// Optional saved result-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request report details. The constructor defaults this to true.
    pub details: Option<bool>,
    /// Whether result pagination terms are ignored. Omission is false.
    pub ignore_pagination: Option<bool>,
    /// Whether gvmd may omit selected redundant report fields.
    pub lean: Option<bool>,
    /// Whether included notes use detailed output.
    pub notes_details: Option<bool>,
    /// Whether included overrides use detailed output.
    pub overrides_details: Option<bool>,
    /// Whether result tags are included.
    pub result_tags: Option<bool>,
}

impl GetReportRequest {
    /// Create an ID-selected request with details explicitly enabled.
    #[must_use]
    pub fn new(report_id: EntityId) -> Self {
        Self {
            report_id,
            filter_string: None,
            filter_id: None,
            details: Some(true),
            ignore_pagination: None,
            lean: None,
            notes_details: None,
            overrides_details: None,
            result_tags: None,
        }
    }
}

impl GmpRequestCodec for GetReportRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_reports", "get_report"))
    }

    fn encode(&self, version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_report_command(self, UsageType::Scan, version).to_bytes())
    }
}

impl GmpRequest for GetReportRequest {
    type Response = GetReportsResponse;
}

/// Request for listing audit reports through the shared `get_reports` root.
#[derive(Debug, Clone, Default)]
pub struct GetAuditReportsRequest {
    /// Optional inline report filter, encoded as `report_filter`.
    pub filter_string: Option<String>,
    /// Optional saved report filter, encoded as `report_filt_id`.
    pub filter_id: Option<EntityId>,
    /// Whether report bodies and result details are included. Omission is false.
    pub details: Option<bool>,
    /// Whether pagination terms in the report filter are ignored. Omission is false.
    pub ignore_pagination: Option<bool>,
    /// Whether included notes use detailed output.
    pub notes_details: Option<bool>,
    /// Whether included overrides use detailed output.
    pub overrides_details: Option<bool>,
    /// Whether result tags are included.
    pub result_tags: Option<bool>,
    /// Whether gvmd may omit selected redundant report fields.
    pub lean: Option<bool>,
}

impl GmpRequestCodec for GetAuditReportsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_reports",
            "get_audit_reports",
        ))
    }

    fn encode(&self, version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_audit_reports_command(self, version).to_bytes())
    }
}

impl GmpRequest for GetAuditReportsRequest {
    type Response = GetAuditReportsResponse;
}

/// Request for one structured vulnerability report.
#[derive(Debug, Clone)]
pub struct GetScanReportRequest {
    /// Structured scan-report identifier.
    pub scan_report_id: EntityId,
    /// Optional inline result filter.
    pub filter_string: Option<String>,
    /// Optional saved result-filter identifier.
    pub filter_id: Option<EntityId>,
}

impl GetScanReportRequest {
    /// Create an unfiltered structured scan-report request.
    #[must_use]
    pub fn new(scan_report_id: EntityId) -> Self {
        Self {
            scan_report_id,
            filter_string: None,
            filter_id: None,
        }
    }
}

impl GmpRequestCodec for GetScanReportRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_scan_report"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(structured_report_command(
            "get_scan_report",
            "scan_report_id",
            &self.scan_report_id,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetScanReportRequest {
    type Response = GetScanReportResponse;
}

/// Request for one structured audit report.
#[derive(Debug, Clone)]
pub struct GetAuditReportRequest {
    /// Structured audit-report identifier.
    pub audit_report_id: EntityId,
    /// Optional inline result filter.
    pub filter_string: Option<String>,
    /// Optional saved result-filter identifier.
    pub filter_id: Option<EntityId>,
}

impl GetAuditReportRequest {
    /// Create an unfiltered structured audit-report request.
    #[must_use]
    pub fn new(audit_report_id: EntityId) -> Self {
        Self {
            audit_report_id,
            filter_string: None,
            filter_id: None,
        }
    }
}

impl GmpRequestCodec for GetAuditReportRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_audit_report"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(structured_report_command(
            "get_audit_report",
            "audit_report_id",
            &self.audit_report_id,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetAuditReportRequest {
    type Response = GetAuditReportResponse;
}

/// Request for structured audit-report host summaries.
#[derive(Debug, Clone)]
pub struct GetAuditReportHostsRequest {
    /// Audit-report identifier whose hosts are summarized.
    pub audit_report_id: EntityId,
    /// Optional inline result/host filter.
    pub filter_string: Option<String>,
    /// Optional saved result-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether selected optional/redundant host XML is omitted. Omission is false.
    pub lean: Option<bool>,
    /// Whether host entries are included. Omission returns count metadata only.
    pub details: Option<bool>,
}

impl GetAuditReportHostsRequest {
    /// Create an audit-report host-summary request with source defaults.
    #[must_use]
    pub fn new(audit_report_id: EntityId) -> Self {
        Self {
            audit_report_id,
            filter_string: None,
            filter_id: None,
            lean: None,
            details: None,
        }
    }
}

impl GmpRequestCodec for GetAuditReportHostsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_audit_report_hosts"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = structured_report_command(
            "get_audit_report_hosts",
            "report_id",
            &self.audit_report_id,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        );
        set_optional_bool_attr(&mut command, "lean", self.lean);
        set_optional_bool_attr(&mut command, "details", self.details);
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetAuditReportHostsRequest {
    type Response = GetAuditReportHostsResponse;
}

/// Request for a synchronous report-format export through `get_reports`.
#[derive(Debug, Clone)]
pub struct GetReportExportRequest {
    /// Report identifier to export.
    pub report_id: EntityId,
    /// Report format to apply.
    pub report_format_id: EntityId,
    /// Optional report configuration. It must belong to the selected format.
    pub report_config_id: Option<EntityId>,
    /// Optional inline result filter.
    pub filter_string: Option<String>,
    /// Optional saved result-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether report details are included. Omission leaves gvmd's false default.
    pub details: Option<bool>,
    /// Whether pagination terms in the result filter are ignored.
    pub ignore_pagination: Option<bool>,
    /// Whether gvmd may omit selected redundant report fields.
    pub lean: Option<bool>,
    /// Whether included notes use detailed output.
    pub notes_details: Option<bool>,
    /// Whether included overrides use detailed output.
    pub overrides_details: Option<bool>,
    /// Whether result tags are included.
    pub result_tags: Option<bool>,
}

impl GetReportExportRequest {
    /// Create an export request with gvmd's Boolean omission defaults.
    #[must_use]
    pub fn new(report_id: EntityId, report_format_id: EntityId) -> Self {
        Self {
            report_id,
            report_format_id,
            report_config_id: None,
            filter_string: None,
            filter_id: None,
            details: None,
            ignore_pagination: None,
            lean: None,
            notes_details: None,
            overrides_details: None,
            result_tags: None,
        }
    }
}

impl GmpRequestCodec for GetReportExportRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_reports",
            "get_report_export",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("get_reports")
            .attribute("report_id", self.report_id.as_str())
            .attribute("format_id", self.report_format_id.as_str());
        if let Some(report_config_id) = &self.report_config_id {
            command.set_attribute("config_id", report_config_id.as_str());
        }
        add_filter_attrs(
            &mut command,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        );
        set_optional_bool_attr(&mut command, "details", self.details);
        set_optional_bool_attr(&mut command, "ignore_pagination", self.ignore_pagination);
        set_optional_bool_attr(&mut command, "lean", self.lean);
        set_optional_bool_attr(&mut command, "notes_details", self.notes_details);
        set_optional_bool_attr(&mut command, "overrides_details", self.overrides_details);
        set_optional_bool_attr(&mut command, "result_tags", self.result_tags);
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetReportExportRequest {
    type Response = ReportExport;
}

/// Request for report host summaries.
#[derive(Debug, Clone)]
pub struct GetReportHostsRequest {
    /// Report identifier whose hosts are projected.
    pub report_id: EntityId,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether pagination terms in the filter are ignored.
    pub ignore_pagination: Option<bool>,
    /// Whether host rows are included. Omission returns count metadata only.
    pub details: Option<bool>,
    /// Whether selected redundant host fields are omitted.
    pub lean: Option<bool>,
}

impl GetReportHostsRequest {
    /// Create a host projection with gvmd's omission defaults.
    #[must_use]
    pub fn new(report_id: EntityId) -> Self {
        Self {
            report_id,
            filter_string: None,
            filter_id: None,
            ignore_pagination: None,
            details: None,
            lean: None,
        }
    }
}

impl GmpRequestCodec for GetReportHostsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_report_hosts"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(report_projection_command(
            "get_report_hosts",
            &self.report_id,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.ignore_pagination,
            self.details,
            self.lean,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetReportHostsRequest {
    type Response = GetReportHostsResponse;
}

macro_rules! report_projection_request {
    ($request:ident, $response:ty, $command:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            /// Report identifier whose data is projected.
            pub report_id: EntityId,
            /// Optional inline filter expression.
            pub filter_string: Option<String>,
            /// Optional saved filter identifier.
            pub filter_id: Option<EntityId>,
            /// Whether pagination terms in the filter are ignored.
            pub ignore_pagination: Option<bool>,
            /// Whether projection rows are included. Omission returns summary data.
            pub details: Option<bool>,
        }

        impl $request {
            /// Create a projection request with gvmd's omission defaults.
            #[must_use]
            pub fn new(report_id: EntityId) -> Self {
                Self {
                    report_id,
                    filter_string: None,
                    filter_id: None,
                    ignore_pagination: None,
                    details: None,
                }
            }
        }

        impl GmpRequestCodec for $request {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_filter(self.filter_string.as_deref())
            }

            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::new($command))
            }

            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                Ok(report_projection_command(
                    $command,
                    &self.report_id,
                    self.filter_string.as_deref(),
                    self.filter_id.as_ref(),
                    self.ignore_pagination,
                    self.details,
                    None,
                )
                .to_bytes())
            }
        }

        impl GmpRequest for $request {
            type Response = $response;
        }
    };
}

report_projection_request!(
    GetReportPortsRequest,
    GetReportPortsResponse,
    "get_report_ports",
    "Request for report port summaries."
);
report_projection_request!(
    GetReportApplicationsRequest,
    GetReportApplicationsResponse,
    "get_report_applications",
    "Request for report application summaries."
);
report_projection_request!(
    GetReportOperatingSystemsRequest,
    GetReportOperatingSystemsResponse,
    "get_report_operating_systems",
    "Request for report operating-system summaries."
);
report_projection_request!(
    GetReportCvesRequest,
    GetReportCvesResponse,
    "get_report_cves",
    "Request for report CVE summaries."
);
report_projection_request!(
    GetReportVulnsRequest,
    GetReportVulnsResponse,
    "get_report_vulns",
    "Request for report vulnerability summaries."
);
report_projection_request!(
    GetReportTlsCertificatesRequest,
    GetReportTlsCertificatesResponse,
    "get_report_tls_certificates",
    "Request for report TLS-certificate summaries."
);
report_projection_request!(
    GetReportErrorsRequest,
    GetReportErrorsResponse,
    "get_report_errors",
    "Request for report errors."
);
report_projection_request!(
    GetReportClosedCvesRequest,
    GetReportClosedCvesResponse,
    "get_report_closed_cves",
    "Request for report closed-CVE summaries."
);

/// Request for queuing or reusing an asynchronous scan-report export.
#[derive(Debug, Clone)]
pub struct ExportScanReportRequest {
    /// Scan-report identifier to export.
    pub report_id: EntityId,
    /// Optional report format. Omission selects gvmd's XML format default.
    pub report_format_id: Option<EntityId>,
    /// Optional report configuration.
    pub report_config_id: Option<EntityId>,
    /// Optional inline result filter. Saved filter IDs are not accepted by gvmd.
    pub filter_string: Option<String>,
    /// Whether pagination terms in the filter are ignored.
    pub ignore_pagination: Option<bool>,
    /// Whether gvmd may omit selected redundant report fields.
    pub lean: Option<bool>,
    /// Whether included notes use detailed output.
    pub notes_details: Option<bool>,
    /// Whether included overrides use detailed output.
    pub overrides_details: Option<bool>,
    /// Whether result tags are included.
    pub result_tags: Option<bool>,
}

impl ExportScanReportRequest {
    /// Create an asynchronous export with gvmd's omission defaults.
    #[must_use]
    pub fn new(report_id: EntityId) -> Self {
        Self {
            report_id,
            report_format_id: None,
            report_config_id: None,
            filter_string: None,
            ignore_pagination: None,
            lean: None,
            notes_details: None,
            overrides_details: None,
            result_tags: None,
        }
    }
}

impl GmpRequestCodec for ExportScanReportRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_filter(self.filter_string.as_deref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("export_scan_report"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command =
            XmlCommand::new("export_scan_report").attribute("report_id", self.report_id.as_str());
        if let Some(report_format_id) = &self.report_format_id {
            command.set_attribute("format_id", report_format_id.as_str());
        }
        if let Some(report_config_id) = &self.report_config_id {
            command.set_attribute("config_id", report_config_id.as_str());
        }
        if let Some(filter_string) = &self.filter_string {
            command.set_attribute("filter", filter_string);
        }
        set_optional_bool_attr(&mut command, "ignore_pagination", self.ignore_pagination);
        set_optional_bool_attr(&mut command, "lean", self.lean);
        set_optional_bool_attr(&mut command, "notes_details", self.notes_details);
        set_optional_bool_attr(&mut command, "overrides_details", self.overrides_details);
        set_optional_bool_attr(&mut command, "result_tags", self.result_tags);
        Ok(command.to_bytes())
    }
}

impl GmpRequest for ExportScanReportRequest {
    type Response = ExportScanReportResponse;
}

fn import_report_bytes(request: &ImportReportRequest) -> Vec<u8> {
    let in_assets_len = request
        .in_assets
        .map(|_| "<in_assets>0</in_assets>".len())
        .unwrap_or_default();
    let mut bytes = Vec::with_capacity(
        "<create_report><task id=\"\"/></create_report>".len()
            + request.task_id.as_str().len()
            + in_assets_len
            + request.report_xml.len(),
    );
    bytes.extend_from_slice(b"<create_report>");
    bytes.extend_from_slice(&request.report_xml);
    bytes.extend_from_slice(b"<task id=\"");
    bytes.extend_from_slice(request.task_id.as_str().as_bytes());
    bytes.extend_from_slice(b"\"/>");
    if let Some(in_assets) = request.in_assets {
        bytes.extend_from_slice(b"<in_assets>");
        bytes.extend_from_slice(bool_str(in_assets).as_bytes());
        bytes.extend_from_slice(b"</in_assets>");
    }
    bytes.extend_from_slice(b"</create_report>");
    bytes
}

fn delete_report_command(report_id: &EntityId) -> XmlCommand {
    XmlCommand::new("delete_report").attribute("report_id", report_id.as_str())
}

fn get_reports_command(
    request: &GetReportsRequest,
    usage_type: UsageType,
    version: GmpVersion,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_reports");
    if version >= GmpVersion(22, 6) {
        command.set_attribute("usage_type", usage_type.as_gmp_str());
    }
    if let Some(filter) = &request.filter_string {
        command.set_attribute("report_filter", filter);
    }
    if let Some(filter_id) = &request.filter_id {
        command.set_attribute("report_filt_id", filter_id.as_str());
    }
    set_optional_bool_attr(&mut command, "details", request.details);
    set_optional_bool_attr(&mut command, "ignore_pagination", request.ignore_pagination);
    set_optional_bool_attr(&mut command, "notes_details", request.notes_details);
    set_optional_bool_attr(&mut command, "overrides_details", request.overrides_details);
    set_optional_bool_attr(&mut command, "result_tags", request.result_tags);
    set_optional_bool_attr(&mut command, "lean", request.lean);
    command
}

fn get_audit_reports_command(request: &GetAuditReportsRequest, version: GmpVersion) -> XmlCommand {
    let ordinary = GetReportsRequest {
        filter_string: request.filter_string.clone(),
        filter_id: request.filter_id.clone(),
        details: request.details,
        ignore_pagination: request.ignore_pagination,
        notes_details: request.notes_details,
        overrides_details: request.overrides_details,
        result_tags: request.result_tags,
        lean: request.lean,
    };
    get_reports_command(&ordinary, UsageType::Audit, version)
}

fn get_report_command(
    request: &GetReportRequest,
    usage_type: UsageType,
    version: GmpVersion,
) -> XmlCommand {
    let mut command =
        XmlCommand::new("get_reports").attribute("report_id", request.report_id.as_str());
    if version >= GmpVersion(22, 6) {
        command.set_attribute("usage_type", usage_type.as_gmp_str());
    }
    add_filter_attrs(
        &mut command,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut command, "details", request.details);
    set_optional_bool_attr(&mut command, "ignore_pagination", request.ignore_pagination);
    set_optional_bool_attr(&mut command, "lean", request.lean);
    set_optional_bool_attr(&mut command, "notes_details", request.notes_details);
    set_optional_bool_attr(&mut command, "overrides_details", request.overrides_details);
    set_optional_bool_attr(&mut command, "result_tags", request.result_tags);
    command
}

fn structured_report_command(
    command_name: &str,
    id_attribute: &str,
    report_id: &EntityId,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> XmlCommand {
    let mut command = XmlCommand::new(command_name).attribute(id_attribute, report_id.as_str());
    add_filter_attrs(&mut command, filter_string, filter_id);
    command
}

fn report_projection_command(
    command_name: &str,
    report_id: &EntityId,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    ignore_pagination: Option<bool>,
    details: Option<bool>,
    lean: Option<bool>,
) -> XmlCommand {
    let mut command = XmlCommand::new(command_name).attribute("report_id", report_id.as_str());
    add_filter_attrs(&mut command, filter_string, filter_id);
    set_optional_bool_attr(&mut command, "ignore_pagination", ignore_pagination);
    set_optional_bool_attr(&mut command, "details", details);
    set_optional_bool_attr(&mut command, "lean", lean);
    command
}

fn validate_filter(filter: Option<&str>) -> Result<(), GmpRequestError> {
    if filter.is_some_and(|value| {
        value
            .chars()
            .any(|character| !is_xml_1_0_character(character))
    }) {
        return Err(GmpRequestError::invalid_field(
            "filter_string",
            "must contain only XML 1.0 characters",
        ));
    }
    Ok(())
}

const fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(character as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn validate_report_envelope(report_xml: &[u8]) -> Result<(), GmpRequestError> {
    let invalid = || {
        GmpRequestError::invalid_field(
            "report_xml",
            "must be exactly one well-formed embedded report envelope",
        )
    };
    let mut reader = Reader::from_reader(report_xml);
    reader.config_mut().trim_text(true);
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut completed_root = false;

    loop {
        match reader.read_event().map_err(|_| invalid())? {
            Event::Start(event) => {
                if completed_root || (depth == 0 && event.name().as_ref() != "report") {
                    return Err(invalid());
                }
                saw_root = true;
                depth += 1;
            }
            Event::Empty(event) => {
                if completed_root || (depth == 0 && event.name().as_ref() != "report") {
                    return Err(invalid());
                }
                saw_root = true;
                if depth == 0 {
                    completed_root = true;
                }
            }
            Event::End(_) => {
                if depth == 0 {
                    return Err(invalid());
                }
                depth -= 1;
                if depth == 0 {
                    completed_root = true;
                }
            }
            Event::Text(event) => {
                if depth == 0 && !event.as_ref().trim_ascii().is_empty() {
                    return Err(invalid());
                }
            }
            Event::Eof => {
                return if saw_root && completed_root && depth == 0 {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
            Event::Decl(_) | Event::DocType(_) | Event::CData(_) | Event::GeneralRef(_)
                if depth == 0 =>
            {
                return Err(invalid());
            }
            Event::PI(_) | Event::Comment(_) => {}
            Event::Decl(_) | Event::DocType(_) | Event::CData(_) | Event::GeneralRef(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GmpResponse;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn encode<R: GmpRequestCodec>(request: &R, version: GmpVersion) -> Vec<u8> {
        request.encode(version).expect("request should encode")
    }

    fn encode_text<R: GmpRequestCodec>(request: &R, version: GmpVersion) -> String {
        String::from_utf8(encode(request, version)).expect("encoded request should be UTF-8")
    }

    #[test]
    fn canonical_sync_export_encodes_source_defaults() {
        let export = GetReportExportRequest::new(id("r1"), id("rf1"));
        assert_eq!(
            export.command().and_then(GmpCommand::semantic_name),
            Some("get_report_export")
        );
        assert_eq!(
            encode_text(&export, GmpVersion(22, 8)),
            "<get_reports format_id=\"rf1\" report_id=\"r1\"/>"
        );
    }

    #[test]
    fn report_get_delete_build_xml() {
        let request = GetReportsRequest {
            details: Some(false),
            ..GetReportsRequest::default()
        };
        assert_eq!(
            encode_text(&request, GmpVersion(22, 6)),
            "<get_reports details=\"0\" usage_type=\"scan\"/>"
        );
        let delete = DeleteReportRequest::new(id("r1"));
        assert_eq!(
            encode_text(&delete, GmpVersion(22, 4)),
            "<delete_report report_id=\"r1\"/>"
        );
    }

    #[test]
    fn asynchronous_scan_report_export_encodes_all_source_attributes() {
        let request = ExportScanReportRequest {
            report_id: id("report-1"),
            report_format_id: Some(id("format-1")),
            report_config_id: Some(id("config-1")),
            filter_string: Some("severity>5".into()),
            ignore_pagination: Some(true),
            lean: Some(false),
            notes_details: Some(true),
            overrides_details: Some(false),
            result_tags: Some(true),
        };

        assert_eq!(
            encode(&request, GmpVersion(22, 8)),
            br#"<export_scan_report config_id="config-1" filter="severity&gt;5" format_id="format-1" ignore_pagination="1" lean="0" notes_details="1" overrides_details="0" report_id="report-1" result_tags="1"/>"#
        );

        assert_eq!(
            encode(
                &ExportScanReportRequest::new(id("report-1")),
                GmpVersion(22, 8),
            ),
            br#"<export_scan_report report_id="report-1"/>"#
        );
    }

    fn assert_associated_response<R, T>()
    where
        R: GmpRequest<Response = T>,
        T: GmpResponse,
    {
    }

    #[test]
    fn semantic_report_requests_have_fixed_response_types() {
        assert_associated_response::<ImportReportRequest, CreateReportResponse>();
        assert_associated_response::<DeleteReportRequest, DeleteReportResponse>();
        assert_associated_response::<DeleteAuditReportRequest, DeleteReportResponse>();
        assert_associated_response::<GetReportsRequest, GetReportsResponse>();
        assert_associated_response::<GetReportRequest, GetReportsResponse>();
        assert_associated_response::<GetAuditReportsRequest, GetAuditReportsResponse>();
        assert_associated_response::<GetScanReportRequest, GetScanReportResponse>();
        assert_associated_response::<GetAuditReportRequest, GetAuditReportResponse>();
        assert_associated_response::<GetAuditReportHostsRequest, GetAuditReportHostsResponse>();
        assert_associated_response::<GetReportExportRequest, ReportExport>();
        assert_associated_response::<GetReportHostsRequest, GetReportHostsResponse>();
        assert_associated_response::<GetReportPortsRequest, GetReportPortsResponse>();
        assert_associated_response::<GetReportApplicationsRequest, GetReportApplicationsResponse>();
        assert_associated_response::<
            GetReportOperatingSystemsRequest,
            GetReportOperatingSystemsResponse,
        >();
        assert_associated_response::<GetReportCvesRequest, GetReportCvesResponse>();
        assert_associated_response::<GetReportVulnsRequest, GetReportVulnsResponse>();
        assert_associated_response::<
            GetReportTlsCertificatesRequest,
            GetReportTlsCertificatesResponse,
        >();
        assert_associated_response::<GetReportErrorsRequest, GetReportErrorsResponse>();
        assert_associated_response::<GetReportClosedCvesRequest, GetReportClosedCvesResponse>();
        assert_associated_response::<ExportScanReportRequest, ExportScanReportResponse>();
    }

    #[test]
    fn canonical_report_mutations_encode_directly() {
        let task_id = id("task-1");
        let report_xml = r#"<report id="imported-report"><name>Imported</name></report>"#;
        let mut import = ImportReportRequest::new(task_id, report_xml);
        import.in_assets = Some(true);
        assert_eq!(
            encode(&import, GmpVersion(22, 4)),
            br#"<create_report><report id="imported-report"><name>Imported</name></report><task id="task-1"/><in_assets>1</in_assets></create_report>"#
        );
        assert!(ImportReportRequest::new(id("task-1"), "<not-report/>")
            .validate()
            .is_err());

        let report_id = id("report-1");
        assert_eq!(
            encode(
                &DeleteReportRequest::new(report_id.clone()),
                GmpVersion(22, 4),
            ),
            br#"<delete_report report_id="report-1"/>"#
        );
        assert_eq!(
            encode(&DeleteAuditReportRequest::new(report_id), GmpVersion(22, 6),),
            br#"<delete_report report_id="report-1"/>"#
        );
    }

    #[test]
    fn canonical_lifecycle_queries_encode_source_shapes() {
        let report_id = id("report-1");
        let list = GetReportsRequest {
            filter_string: Some("severity>5".into()),
            details: Some(true),
            ..GetReportsRequest::default()
        };
        assert_eq!(
            encode(&list, GmpVersion(22, 6)),
            br#"<get_reports details="1" report_filter="severity&gt;5" usage_type="scan"/>"#
        );
        let detail = GetReportRequest::new(report_id.clone());
        assert_eq!(
            encode(&detail, GmpVersion(22, 6)),
            br#"<get_reports details="1" report_id="report-1" usage_type="scan"/>"#
        );
        let audit_list = GetAuditReportsRequest {
            filter_string: Some("name~audit".into()),
            ..GetAuditReportsRequest::default()
        };
        assert_eq!(
            encode(&audit_list, GmpVersion(22, 6)),
            br#"<get_reports report_filter="name~audit" usage_type="audit"/>"#
        );

        let mut scan = GetScanReportRequest::new(report_id.clone());
        scan.filter_string = Some("levels=chml".into());
        scan.filter_id = Some(id("filter-1"));
        assert_eq!(
            encode(&scan, GmpVersion(22, 8)),
            br#"<get_scan_report filt_id="filter-1" filter="levels=chml" scan_report_id="report-1"/>"#
        );
        let mut audit = GetAuditReportRequest::new(report_id.clone());
        audit.filter_string = Some("compliance_levels=yniu".into());
        audit.filter_id = Some(id("filter-2"));
        assert_eq!(
            encode(&audit, GmpVersion(22, 7)),
            br#"<get_audit_report audit_report_id="report-1" filt_id="filter-2" filter="compliance_levels=yniu"/>"#
        );
        let mut hosts = GetAuditReportHostsRequest::new(report_id.clone());
        hosts.filter_string = Some("rows=25".into());
        hosts.lean = Some(true);
        hosts.details = Some(false);
        assert_eq!(
            encode(&hosts, GmpVersion(22, 7)),
            br#"<get_audit_report_hosts details="0" filter="rows=25" lean="1" report_id="report-1"/>"#
        );
    }

    #[test]
    fn canonical_projection_and_export_queries_encode_source_shapes() {
        let report_id = id("report-1");
        let mut export = GetReportExportRequest::new(report_id.clone(), id("format-1"));
        export.report_config_id = Some(id("config-1"));
        export.filter_string = Some("severity>5".into());
        export.filter_id = Some(id("filter-3"));
        export.details = Some(true);
        export.ignore_pagination = Some(false);
        export.lean = Some(true);
        export.notes_details = Some(false);
        export.overrides_details = Some(true);
        export.result_tags = Some(false);
        assert_eq!(
            encode(&export, GmpVersion(22, 8)),
            br#"<get_reports config_id="config-1" details="1" filt_id="filter-3" filter="severity&gt;5" format_id="format-1" ignore_pagination="0" lean="1" notes_details="0" overrides_details="1" report_id="report-1" result_tags="0"/>"#
        );
        assert_eq!(
            export.command().and_then(GmpCommand::semantic_name),
            Some("get_report_export")
        );

        let mut hosts = GetReportHostsRequest::new(report_id.clone());
        hosts.filter_string = Some("rows=10".into());
        hosts.filter_id = Some(id("filter-4"));
        hosts.ignore_pagination = Some(true);
        hosts.details = Some(false);
        hosts.lean = Some(true);
        assert_eq!(
            encode(&hosts, GmpVersion(22, 8)),
            br#"<get_report_hosts details="0" filt_id="filter-4" filter="rows=10" ignore_pagination="1" lean="1" report_id="report-1"/>"#
        );

        macro_rules! assert_projection {
            ($request:ident, $command:literal) => {{
                let mut request = $request::new(report_id.clone());
                request.filter_string = Some("rows=10".into());
                request.filter_id = Some(id("filter-5"));
                request.ignore_pagination = Some(false);
                request.details = Some(true);
                assert_eq!(
                    encode(&request, GmpVersion(22, 8)),
                    format!(concat!(
                        "<",
                        $command,
                        " details=\"1\" filt_id=\"filter-5\" filter=\"rows=10\" ",
                        "ignore_pagination=\"0\" report_id=\"report-1\"/>"
                    ))
                    .as_bytes()
                );
            }};
        }
        assert_projection!(GetReportPortsRequest, "get_report_ports");
        assert_projection!(GetReportApplicationsRequest, "get_report_applications");
        assert_projection!(
            GetReportOperatingSystemsRequest,
            "get_report_operating_systems"
        );
        assert_projection!(GetReportCvesRequest, "get_report_cves");
        assert_projection!(GetReportVulnsRequest, "get_report_vulns");
        assert_projection!(
            GetReportTlsCertificatesRequest,
            "get_report_tls_certificates"
        );
        assert_projection!(GetReportErrorsRequest, "get_report_errors");
        assert_projection!(GetReportClosedCvesRequest, "get_report_closed_cves");
    }

    #[test]
    fn audit_report_commands_build_xml() {
        let list = GetAuditReportsRequest::default();
        assert_eq!(
            encode_text(&list, GmpVersion(22, 6)),
            "<get_reports usage_type=\"audit\"/>"
        );
        let delete = DeleteAuditReportRequest::new(id("r1"));
        assert_eq!(
            encode_text(&delete, GmpVersion(22, 6)),
            "<delete_report report_id=\"r1\"/>"
        );
        let mut audit = GetAuditReportRequest::new(id("r1"));
        audit.filter_string = Some("compliance_levels=yniu min_qod=70".into());
        audit.filter_id = Some(id("f1"));
        assert_eq!(
            encode_text(&audit, GmpVersion(22, 7)),
            "<get_audit_report audit_report_id=\"r1\" filt_id=\"f1\" filter=\"compliance_levels=yniu min_qod=70\"/>"
        );
        let mut hosts = GetAuditReportHostsRequest::new(id("r1"));
        hosts.filter_string = Some("levels=yniu rows=10 first=1".into());
        hosts.lean = Some(true);
        hosts.details = Some(false);
        assert_eq!(
            encode_text(&hosts, GmpVersion(22, 7)),
            "<get_audit_report_hosts details=\"0\" filter=\"levels=yniu rows=10 first=1\" lean=\"1\" report_id=\"r1\"/>"
        );
    }
}
