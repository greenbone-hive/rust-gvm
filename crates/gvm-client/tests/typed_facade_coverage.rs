// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{CommandSupport, GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::agent_groups::{
    CloneAgentGroupRequest, CreateAgentGroupRequest, DeleteAgentGroupRequest, GetAgentGroupRequest,
    GetAgentGroupsRequest, ModifyAgentGroupRequest,
};
use gvm_gmp::commands::agents::{
    AgentInstallerLanguage, DeleteAgentRequest, GetAgentInstallerInstructionRequest,
    GetAgentRequest, GetAgentSupportBundleRequest, GetAgentsRequest,
    ModifyAgentControlScanConfigRequest, ModifyAgentRequest, SyncAgentsRequest,
};
use gvm_gmp::commands::aggregates::GetAggregatesRequestOpts;
use gvm_gmp::commands::alerts::{
    CloneAlertRequest, CreateAlertRequest, DeleteAlertRequest, GetAlertRequest, GetAlertsRequest,
    ModifyAlertRequest, TestAlertRequest, TriggerAlertRequest,
};
use gvm_gmp::commands::assets::{
    AssetType, CreateAssetRequest, DeleteAssetRequest, GetAssetRequest, GetAssetsRequest,
    ModifyAssetRequest,
};
use gvm_gmp::commands::configs::{
    CloneConfigRequest, ConfigUsageType, CreateConfigRequest, DeleteConfigRequest,
    GetConfigRequest, GetConfigsRequest, ModifyConfigRequest,
};
use gvm_gmp::commands::credentials::{
    CloneCredentialRequest, CreateCredentialRequest, DeleteCredentialRequest, GetCredentialRequest,
    GetCredentialsRequest, ModifyCredentialRequest,
};
use gvm_gmp::commands::filters::{
    CloneFilterRequest, CreateFilterRequest, DeleteFilterRequest, GetFilterRequest,
    GetFiltersRequest, ModifyFilterRequest,
};
use gvm_gmp::commands::groups::{
    CloneGroupRequest, CreateGroupRequest, DeleteGroupRequest, GetGroupRequest, GetGroupsRequest,
    ModifyGroupRequest,
};
use gvm_gmp::commands::help::HelpMode;
use gvm_gmp::commands::hosts::{
    CreateHostRequest, DeleteHostRequest, GetHostRequest, GetHostsRequest, ModifyHostRequest,
};
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, GetIntegrationConfigsRequest, ModifyIntegrationConfigRequest,
};
use gvm_gmp::commands::notes::{
    CloneNoteRequest, CreateNoteRequest, DeleteNoteRequest, GetNoteRequest, GetNotesRequest,
    ModifyNoteRequest,
};
use gvm_gmp::commands::nvts::{
    GetNvtFamiliesRequest, GetNvtPreferenceRequest, GetNvtPreferencesRequest, GetNvtRequest,
    GetNvtsRequest, GetScanConfigNvtRequest, GetScanConfigNvtsRequest,
};
use gvm_gmp::commands::oci_image_targets::{
    CloneOciImageTargetRequest, CreateOciImageTargetRequest, DeleteOciImageTargetRequest,
    GetOciImageTargetRequest, GetOciImageTargetsRequest, ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::operating_systems::{
    DeleteOperatingSystemAssetRequest, GetOperatingSystemAssetRequest,
    GetOperatingSystemAssetsRequest,
};
use gvm_gmp::commands::overrides::{
    CloneOverrideRequest, CreateOverrideRequest, DeleteOverrideRequest, GetOverrideRequest,
    GetOverridesRequest, ModifyOverrideRequest,
};
use gvm_gmp::commands::permissions::*;
use gvm_gmp::commands::port_lists::{
    ClonePortListRequest, CreatePortListRequest, CreatePortRangeRequest, DeletePortListRequest,
    DeletePortRangeRequest, GetPortListRequest, GetPortListsRequest, ModifyPortListRequest,
};
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
    DeleteAuditReportRequest, DeleteReportRequest, ExportScanReportRequest, GetAuditReportsRequest,
    GetReportApplicationsRequest, GetReportClosedCvesRequest, GetReportCvesRequest,
    GetReportErrorsRequest, GetReportExportRequest, GetReportHostsRequest,
    GetReportOperatingSystemsRequest, GetReportPortsRequest, GetReportRequest,
    GetReportTlsCertificatesRequest, GetReportVulnsRequest, GetReportsRequest,
    GetScanReportRequest, ImportReportRequest,
};
use gvm_gmp::commands::results::{GetResultRequest, GetResultsRequest};
use gvm_gmp::commands::roles::*;
use gvm_gmp::commands::scan_configs::GetScanConfigsRequest;
use gvm_gmp::commands::scanners::{
    CloneScannerRequest, CreateScannerRequest, DeleteScannerRequest, GetScannerRequest,
    GetScannersRequest, ModifyScannerRequest, VerifyScannerRequest,
};
use gvm_gmp::commands::schedules::{
    CloneScheduleRequest, CreateScheduleRequest, DeleteScheduleRequest, GetScheduleRequest,
    GetSchedulesRequest, ModifyScheduleRequest,
};
use gvm_gmp::commands::secinfo::{
    GenericInfoType, GetCertBundAdvisoriesRequest, GetCertBundAdvisoryRequest, GetCpeRequest,
    GetCpesRequest, GetCveRequest, GetCvesRequest, GetDfnCertAdvisoriesRequest,
    GetDfnCertAdvisoryRequest, GetInfoListRequest, GetInfoRequest,
};
use gvm_gmp::commands::system::{
    GetVulnerabilityRequest, GetVulnsRequest, ModifyAuthRequest, ModifyLicenseOpts,
    ModifyLicenseRequest, ModifyLicenseWithOptsRequest, ModifySettingRequest, RunWizardOpts,
    RunWizardRequest, RunWizardWithOptsRequest,
};
use gvm_gmp::commands::system_reports::GetSystemReportsOpts;
use gvm_gmp::commands::tags::{
    CloneTagRequest, CreateTagRequest, DeleteTagRequest, GetTagRequest, GetTagsRequest,
    ModifyTagRequest, TagResources,
};
use gvm_gmp::commands::targets::{
    CloneTargetRequest, DeleteTargetRequest, GetTargetRequest, GetTargetsRequest,
    ModifyTargetRequest,
};
use gvm_gmp::commands::tasks::{
    CloneAuditRequest, CloneTaskRequest, CreateAgentGroupTaskRequest, CreateAuditRequest,
    CreateContainerImageTaskRequest, CreateContainerTaskRequest, CreateImportTaskRequest,
    CreateOciImageTargetTaskRequest, CreateTaskRequest, CreateWebApplicationTaskRequest,
    DeleteAuditRequest, DeleteTaskRequest, GetAuditRequest, GetAuditsRequest, GetTaskRequest,
    GetTasksRequest, ModifyAuditRequest, ModifyTaskRequest, MoveTaskRequest, ResumeAuditRequest,
    ResumeTaskRequest, StartAuditRequest, StartTaskRequest, StopAuditRequest, StopTaskRequest,
    TaskMoveDestination,
};
use gvm_gmp::commands::tickets::{CreateTicketOpts, GetTicketsOpts, TicketOpenNote};
use gvm_gmp::commands::tls_certificates::{
    CloneTlsCertificateRequest, CreateTlsCertificateRequest, DeleteTlsCertificateRequest,
    GetTlsCertificateRequest, GetTlsCertificatesRequest, ModifyTlsCertificateRequest,
};
use gvm_gmp::commands::user_settings::{
    GetUserSettingRequest, GetUserSettingsOpts, GetUserSettingsRequest, ModifyUserSettingOpts,
    ModifyUserSettingRequest,
};
use gvm_gmp::commands::users::{
    CloneUserRequest, CreateUserRequest, DeleteUserRequest, GetUserRequest, GetUsersRequest,
    ModifyUserRequest, UserHostAccess,
};
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, CreateWebApplicationTargetRequest,
    DeleteWebApplicationTargetRequest, GetWebApplicationTargetRequest,
    GetWebApplicationTargetsRequest, ModifyWebApplicationTargetRequest,
};
use gvm_gmp::responses::{ActionResponse, ParseError};
use gvm_gmp::types::{EntityId, GmpVersion, ScalarUpdate};
use gvm_gmp::{
    AlertCondition, AlertEvent, AlertMethod, EntityType, FeedType, GmpRequest, PortRangeType,
    ScannerType, ScheduleDefinition, ScheduleInput, ScheduleRecurrence, ScheduleTimestamp,
    ScheduleTimezone,
};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};
use gvm_protocol::Request;

const CREATED_ID: &str = "11111111-1111-1111-1111-111111111111";

fn tag_resources() -> TagResources {
    TagResources::new(EntityType::Task)
}

fn alert_create_request(name: &str) -> CreateAlertRequest {
    CreateAlertRequest::new(
        name,
        AlertEvent::TaskRunStatusChanged,
        AlertCondition::Always,
        AlertMethod::Email,
    )
}

const SYSTEM_ADMIN_OVERRIDES: &[(&str, &str)] = &[
    (
        "modify_auth",
        r#"<modify_auth_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_license",
        r#"<modify_license_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_setting",
        r#"<modify_setting_response status="200" status_text="OK"/>"#,
    ),
    (
        "run_wizard",
        r#"<run_wizard_response status="202" status_text="OK, request submitted"><response><start_task_response status="202" status_text="OK"/></response></run_wizard_response>"#,
    ),
    (
        "get_settings",
        r#"<get_settings_response status="200" status_text="OK"><setting id="setting-1"><name>timezone</name><value>UTC</value></setting></get_settings_response>"#,
    ),
];
const TASK_LIFECYCLE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_tasks",
        r#"<get_tasks_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_task",
        r#"<create_task_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_task",
        r#"<modify_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_task",
        r#"<delete_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "start_task",
        r#"<start_task_response status="202" status_text="OK"><report_id>22222222-2222-2222-2222-222222222222</report_id></start_task_response>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "resume_task",
        r#"<resume_task_response status="202" status_text="OK"><report_id>33333333-3333-3333-3333-333333333333</report_id></resume_task_response>"#,
    ),
];

const DEFERRED_TASK_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_tasks",
        r#"<get_tasks_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_task",
        r#"<create_task_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_task",
        r#"<modify_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_task",
        r#"<delete_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "move_task",
        r#"<move_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "start_task",
        r#"<start_task_response status="202" status_text="OK"><report_id>22222222-2222-2222-2222-222222222222</report_id></start_task_response>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "resume_task",
        r#"<resume_task_response status="202" status_text="OK"><report_id>33333333-3333-3333-3333-333333333333</report_id></resume_task_response>"#,
    ),
];

const CREDENTIAL_LIFECYCLE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_credentials",
        r#"<get_credentials_response status="200" status_text="OK"><credential_count>0<filtered>0</filtered></credential_count></get_credentials_response>"#,
    ),
    (
        "create_credential",
        r#"<create_credential_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_credential",
        r#"<modify_credential_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_credential",
        r#"<delete_credential_response status="200" status_text="OK"/>"#,
    ),
];

const SCANNER_LIFECYCLE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_scanners",
        r#"<get_scanners_response status="200" status_text="OK"><scanner_count>0<filtered>0</filtered></scanner_count></get_scanners_response>"#,
    ),
    (
        "create_scanner",
        r#"<create_scanner_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_scanner",
        r#"<modify_scanner_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_scanner",
        r#"<delete_scanner_response status="200" status_text="OK"/>"#,
    ),
    (
        "verify_scanner",
        r#"<verify_scanner_response status="200" status_text="OK"/>"#,
    ),
];

const ALERT_SCHEDULE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_alerts",
        r#"<get_alerts_response status="200" status_text="OK"><alert_count>0<filtered>0</filtered></alert_count></get_alerts_response>"#,
    ),
    (
        "create_alert",
        r#"<create_alert_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_alert",
        r#"<modify_alert_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_alert",
        r#"<delete_alert_response status="200" status_text="OK"/>"#,
    ),
    (
        "test_alert",
        r#"<test_alert_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_reports",
        r#"<get_reports_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_schedules",
        r#"<get_schedules_response status="200" status_text="OK"><schedule_count>0<filtered>0</filtered></schedule_count></get_schedules_response>"#,
    ),
    (
        "create_schedule",
        r#"<create_schedule_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_schedule",
        r#"<modify_schedule_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_schedule",
        r#"<delete_schedule_response status="200" status_text="OK"/>"#,
    ),
];

const IDENTITY_PERMISSION_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_users",
        r#"<get_users_response status="200" status_text="OK"><user_count>0<filtered>0</filtered></user_count></get_users_response>"#,
    ),
    (
        "create_user",
        r#"<create_user_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_user",
        r#"<modify_user_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_user",
        r#"<delete_user_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_groups",
        r#"<get_groups_response status="200" status_text="OK"><group_count>0<filtered>0</filtered></group_count></get_groups_response>"#,
    ),
    (
        "create_group",
        r#"<create_group_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_group",
        r#"<modify_group_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_group",
        r#"<delete_group_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_roles",
        r#"<get_roles_response status="200" status_text="OK"><role_count>0<filtered>0</filtered></role_count></get_roles_response>"#,
    ),
    (
        "create_role",
        r#"<create_role_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_role",
        r#"<modify_role_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_role",
        r#"<delete_role_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_permissions",
        r#"<get_permissions_response status="200" status_text="OK"><permission_count>0<filtered>0</filtered></permission_count></get_permissions_response>"#,
    ),
    (
        "create_permission",
        r#"<create_permission_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_permission",
        r#"<modify_permission_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_permission",
        r#"<delete_permission_response status="200" status_text="OK"/>"#,
    ),
];

const NVT_SECINFO_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_nvts",
        r#"<get_nvts_response status="200" status_text="OK"><nvt oid="1.3.6.1"><name>Example NVT</name></nvt><nvt_count>1<filtered>1</filtered></nvt_count></get_nvts_response>"#,
    ),
    (
        "get_preferences",
        r#"<get_preferences_response status="200" status_text="OK"><preference><name>timeout</name><value>30</value></preference></get_preferences_response>"#,
    ),
    (
        "get_nvt_families",
        r#"<get_nvt_families_response status="200" status_text="OK"><nvt_family><name>General</name><count>1</count></nvt_family><family_count>1</family_count></get_nvt_families_response>"#,
    ),
    (
        "get_info",
        r#"<get_info_response status="200" status_text="OK"><cert_bund_adv id="CB-1"><name>CERT</name></cert_bund_adv><cpe id="cpe:/a:example"><name>CPE</name></cpe><cve id="CVE-2026-0001"><name>CVE</name></cve><dfn_cert_adv id="DFN-1"><name>DFN</name></dfn_cert_adv><nvt oid="1.3.6.1"><name>NVT</name></nvt><ovaldef id="oval:example:def:1"><name>OVAL</name></ovaldef><os id="os-1"><name>OS</name></os><vuln id="vuln-1"><name>Vulnerability</name></vuln></get_info_response>"#,
    ),
];

const ALTERNATE_TARGET_OVERRIDES: &[(&str, &str)] = &[
    (
        "create_target",
        r#"<create_target_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "create_oci_image_target",
        r#"<create_oci_image_target_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "get_oci_image_targets",
        r#"<get_oci_image_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_oci_image_target",
        r#"<modify_oci_image_target_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_oci_image_target",
        r#"<delete_oci_image_target_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_web_application_target",
        r#"<create_web_application_target_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "get_web_application_targets",
        r#"<get_web_application_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_web_application_target",
        r#"<modify_web_application_target_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_web_application_target",
        r#"<delete_web_application_target_response status="200" status_text="OK"/>"#,
    ),
];

const ASSET_HOST_RESULT_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_assets",
        r#"<get_assets_response status="200" status_text="OK"><asset_count>0<filtered>0</filtered></asset_count></get_assets_response>"#,
    ),
    (
        "create_asset",
        r#"<create_asset_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_asset",
        r#"<modify_asset_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_asset",
        r#"<delete_asset_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_results",
        r#"<get_results_response status="200" status_text="OK"><result_count>0<filtered>0</filtered></result_count></get_results_response>"#,
    ),
];

const CONFIG_PORT_LIST_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_configs",
        r#"<get_configs_response status="200" status_text="OK"><config_count>0<filtered>0</filtered></config_count></get_configs_response>"#,
    ),
    (
        "create_config",
        r#"<create_config_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_config",
        r#"<modify_config_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_config",
        r#"<delete_config_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_port_lists",
        r#"<get_port_lists_response status="200" status_text="OK"><port_list_count>0<filtered>0</filtered></port_list_count></get_port_lists_response>"#,
    ),
    (
        "create_port_list",
        r#"<create_port_list_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_port_list",
        r#"<modify_port_list_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_port_list",
        r#"<delete_port_list_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_port_range",
        r#"<create_port_range_response status="201" status_text="OK"/>"#,
    ),
    (
        "delete_port_range",
        r#"<delete_port_range_response status="200" status_text="OK"/>"#,
    ),
];

const REPORT_CONFIG_FORMAT_TLS_OVERRIDES: &[(&str, &str)] = &[
    (
        "create_report_config",
        r#"<create_report_config_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "delete_report_config",
        r#"<delete_report_config_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_report_configs",
        r#"<get_report_configs_response status="200" status_text="OK"><report_config_count>0<filtered>0</filtered></report_config_count></get_report_configs_response>"#,
    ),
    (
        "modify_report_config",
        r#"<modify_report_config_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_report_format",
        r#"<create_report_format_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "delete_report_format",
        r#"<delete_report_format_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_report_formats",
        r#"<get_report_formats_response status="200" status_text="OK"><report_format_count>0<filtered>0</filtered></report_format_count></get_report_formats_response>"#,
    ),
    (
        "modify_report_format",
        r#"<modify_report_format_response status="200" status_text="OK"/>"#,
    ),
    (
        "verify_report_format",
        r#"<verify_report_format_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_tls_certificate",
        r#"<create_tls_certificate_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "delete_tls_certificate",
        r#"<delete_tls_certificate_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tls_certificates",
        r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate_count>0<filtered>0</filtered></tls_certificate_count></get_tls_certificates_response>"#,
    ),
    (
        "modify_tls_certificate",
        r#"<modify_tls_certificate_response status="200" status_text="OK"/>"#,
    ),
];

const SYSTEM_DISCOVERY_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_aggregates",
        r#"<get_aggregates_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_features",
        r#"<get_features_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_feeds",
        r#"<get_feeds_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_timezones",
        r#"<get_timezones_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_settings",
        r#"<get_settings_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_system_reports",
        r#"<get_system_reports_response status="200" status_text="OK"/>"#,
    ),
    ("help", r#"<help_response status="200" status_text="OK"/>"#),
    (
        "describe_auth",
        r#"<describe_auth_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_vulns",
        r#"<get_vulns_response status="200" status_text="OK"/>"#,
    ),
];

struct SemanticAliasRequest;

impl Request for SemanticAliasRequest {
    fn to_bytes(&self) -> Vec<u8> {
        b"<get_reports/>".to_vec()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("get_report_export")
    }
}

impl GmpRequest for SemanticAliasRequest {
    type Response = ActionResponse;
}

fn permission_create_request() -> CreatePermissionRequest {
    CreatePermissionRequest::new(
        "get_tasks",
        PermissionSubject::new(id(CREATED_ID), gvm_gmp::PermissionSubjectType::Role),
    )
}

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("test entity id")
}

async fn fixture_server(version: MockVersion, overrides: &[(&str, &str)]) -> Option<MockGmpServer> {
    let mut builder = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto();
    for (command, response) in overrides {
        builder = builder.override_response(command, response);
    }

    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn client(server: &MockGmpServer) -> GmpClient<UnixSocketConnection> {
    GmpClient::connect(UnixSocketConnection::with_path(
        server.socket_path().expect("unix socket path"),
    ))
    .await
    .expect("client should connect")
}

macro_rules! assert_typed_success {
    ($future:expr) => {{
        let response = $future.await.expect("typed helper should parse");
        assert_eq!(response.status, 200);
        response
    }};
}

macro_rules! assert_create_success {
    ($future:expr) => {{
        let response = $future.await.expect("typed create helper should parse");
        assert_eq!(response.status, 201);
        assert_eq!(response.id.as_str(), CREATED_ID);
        response
    }};
}

macro_rules! assert_server_error {
    ($future:expr, $status:literal, $message:literal) => {{
        let error = $future.await.expect_err("typed helper should reject server error");
        assert!(matches!(
            error,
            GvmError::Server { status: $status, message }
                if message == $message
        ));
    }};
}

macro_rules! assert_unsupported_command {
    ($future:expr, $command:literal, $version:expr, $required:literal) => {{
        let error = $future
            .await
            .expect_err("typed helper should reject unsupported command before sending");
        assert!(matches!(
            error,
            GvmError::UnsupportedCommand {
                command,
                version,
                required: $required,
            } if command == $command && version == $version
        ));
    }};
}

macro_rules! create_response {
    ($root:literal) => {
        concat!(
            "<",
            $root,
            r#" status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#
        )
    };
}

#[tokio::test]
async fn system_admin_and_user_setting_requests_execute_over_unix_transport() {
    let Some(server) = fixture_server(MockVersion::V22_8, SYSTEM_ADMIN_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let auth_settings = vec![("password".into(), "auth-secret".into())];
    assert_typed_success!(
        client.execute(ModifyAuthRequest::new("method:ldap_connect", auth_settings))
    );
    assert_typed_success!(client.execute(ModifyLicenseRequest::new("license-secret")));
    assert_typed_success!(client.execute(ModifyLicenseWithOptsRequest::new(
        "license-secret",
        ModifyLicenseOpts {
            allow_empty: Some(false),
        }
    )));

    let setting_id = id("setting-1");
    assert_typed_success!(client.execute(ModifySettingRequest::new(
        setting_id.clone(),
        "Europe/Berlin"
    )));

    let wizard = client
        .execute(RunWizardRequest::new(
            "quick_first_scan",
            [("hosts".into(), "localhost".into())],
        ))
        .await
        .expect("default wizard request should parse");
    assert_eq!(wizard.status, 202);
    let wizard_with_opts = client
        .execute(RunWizardWithOptsRequest::new(
            "quick_first_scan",
            [("hosts".into(), "localhost".into())],
            RunWizardOpts {
                mode: Some("step".into()),
                read_only: Some(false),
            },
        ))
        .await
        .expect("option-bearing wizard request should parse");
    assert_eq!(wizard_with_opts.status, 202);

    let settings = client
        .execute(GetUserSettingsRequest::new(GetUserSettingsOpts::default()))
        .await
        .expect("user-setting list should parse");
    assert_eq!(settings.settings.len(), 1);
    let setting = client
        .execute(GetUserSettingRequest::new(setting_id.clone()))
        .await
        .expect("single user setting should parse");
    assert_eq!(setting.settings[0].id, setting_id);
    assert_typed_success!(client.execute(ModifyUserSettingRequest::new(
        id("setting-1"),
        ModifyUserSettingOpts {
            value: "Europe/Berlin".into(),
        }
    )));

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "modify_auth",
            "modify_license",
            "modify_license",
            "modify_setting",
            "run_wizard",
            "run_wizard",
            "get_settings",
            "get_settings",
            "modify_setting",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn system_admin_execution_preserves_status_and_user_setting_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "modify_auth",
                r#"<modify_auth_response status="409" status_text="authentication conflict"/>"#,
            ),
            (
                "get_settings",
                r#"<get_settings_response status="200" status_text="OK"><setting><name>timezone</name></setting></get_settings_response>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    assert_server_error!(
        client.execute(ModifyAuthRequest::new(
            "method:ldap_connect",
            [("enable".into(), "true".into())]
        )),
        409,
        "authentication conflict"
    );
    let parse_error = client
        .execute(GetUserSettingRequest::new(id("setting-1")))
        .await
        .expect_err("missing user-setting id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "setting.id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn user_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_users(GetUsersRequest::default()));
    assert_typed_success!(client.get_user(GetUserRequest::new(entity_id.clone())));
    assert_create_success!(client.create_user(CreateUserRequest::new("user")));
    assert_create_success!(client.clone_user(CloneUserRequest::new(entity_id.clone())));
    assert_typed_success!(client.modify_user(ModifyUserRequest::new(
        entity_id.clone(),
        UserHostAccess::allow("")
    )));
    assert_typed_success!(client.delete_user(DeleteUserRequest::new(entity_id)));

    server.shutdown().await;
}

#[tokio::test]
async fn group_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_groups(GetGroupsRequest::default()));
    assert_typed_success!(client.get_group(GetGroupRequest::new(entity_id.clone())));
    assert_create_success!(client.create_group(CreateGroupRequest::new("group")));
    assert_create_success!(client.clone_group(CloneGroupRequest::new(entity_id.clone())));
    assert_typed_success!(client.modify_group(ModifyGroupRequest::new(
        entity_id.clone(),
        "group",
        "",
        Vec::new()
    )));
    assert_typed_success!(client.delete_group(DeleteGroupRequest::new(entity_id, false)));

    server.shutdown().await;
}

#[tokio::test]
async fn role_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_roles(GetRolesRequest::default()));
    assert_typed_success!(client.get_role(GetRoleRequest::new(entity_id.clone())));
    assert_create_success!(client.create_role(CreateRoleRequest::new("role")));
    assert_create_success!(client.clone_role(CloneRoleRequest::new(entity_id.clone())));
    assert_typed_success!(client.modify_role(ModifyRoleRequest::new(
        entity_id.clone(),
        "role",
        "",
        Vec::new()
    )));
    assert_typed_success!(client.delete_role(DeleteRoleRequest::new(entity_id.clone(), false)));

    server.shutdown().await;
}

#[tokio::test]
async fn permission_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_permissions(GetPermissionsRequest::default()));
    assert_typed_success!(client.get_permission(GetPermissionRequest::new(entity_id.clone())));
    assert_create_success!(client.create_permission(permission_create_request()));
    assert_create_success!(client.clone_permission(ClonePermissionRequest::new(entity_id.clone())));
    assert_typed_success!(client.modify_permission(ModifyPermissionRequest::new(entity_id.clone())));
    assert_typed_success!(
        client.delete_permission(DeletePermissionRequest::new(entity_id.clone(), false))
    );

    server.shutdown().await;
}

#[tokio::test]
async fn identity_and_permission_facades_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "get_users",
                r#"<get_users_response status="409" status_text="identity conflict"/>"#,
            ),
            (
                "create_permission",
                r#"<create_permission_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    assert_server_error!(
        client.get_user(GetUserRequest::new(id("user-1"))),
        409,
        "identity conflict"
    );
    let parse_error = client
        .clone_permission(ClonePermissionRequest::new(id("permission-1")))
        .await
        .expect_err("missing cloned permission id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn nvt_and_secinfo_queries_execute_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, NVT_SECINFO_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_typed_success!(client.get_nvts(GetNvtsRequest::default()));
    assert_typed_success!(client.get_nvt(GetNvtRequest::new("1.3.6.1")));
    assert_typed_success!(
        client.get_scan_config_nvts(GetScanConfigNvtsRequest::new(id("config-1"), "General"))
    );
    assert_typed_success!(client.get_scan_config_nvt(GetScanConfigNvtRequest::new("1.3.6.1")));
    assert_typed_success!(client.get_nvt_preferences(GetNvtPreferencesRequest::default()));
    let mut preference = GetNvtPreferenceRequest::new("entry:timeout");
    preference.nvt_oid = Some("1.3.6.1".into());
    assert_typed_success!(client.get_nvt_preference(preference));
    assert_typed_success!(client.get_nvt_families(GetNvtFamiliesRequest::new()));

    assert_typed_success!(
        client.get_info(GetInfoRequest::new("CVE-2026-0001", GenericInfoType::Cve))
    );
    assert_typed_success!(client.get_info_list(GetInfoListRequest::new(GenericInfoType::Nvt)));
    assert_typed_success!(client.get_cpes(GetCpesRequest::default()));
    assert_typed_success!(client.get_cpe(GetCpeRequest::new("cpe:/a:example")));
    assert_typed_success!(client.get_cves(GetCvesRequest::default()));
    assert_typed_success!(client.get_cve(GetCveRequest::new("CVE-2026-0001")));
    assert_typed_success!(client.get_cert_bund_advisories(GetCertBundAdvisoriesRequest::default()));
    assert_typed_success!(client.get_cert_bund_advisory(GetCertBundAdvisoryRequest::new("CB-1")));
    assert_typed_success!(client.get_dfn_cert_advisories(GetDfnCertAdvisoriesRequest::default()));
    assert_typed_success!(client.get_dfn_cert_advisory(GetDfnCertAdvisoryRequest::new("DFN-1")));

    let history = server.command_history();
    assert_eq!(history.len(), 17);
    for (command, expected_count) in [
        ("get_nvts", 4),
        ("get_preferences", 2),
        ("get_nvt_families", 1),
        ("get_info", 10),
    ] {
        assert_eq!(
            history
                .iter()
                .filter(|record| record.command_name() == command)
                .count(),
            expected_count,
            "unexpected facade inventory for {command}"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn alternate_target_requests_execute_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, ALTERNATE_TARGET_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let target_id = id(CREATED_ID);

    assert_create_success!(client.execute(CloneTargetRequest::new(target_id.clone())));

    assert_create_success!(
        client.create_oci_image_target(CreateOciImageTargetRequest::new(
            "oci",
            vec!["registry.example/image:latest".into()],
        ))
    );
    assert_create_success!(
        client.clone_oci_image_target(CloneOciImageTargetRequest::new(target_id.clone()))
    );
    assert_typed_success!(client.get_oci_image_target(GetOciImageTargetRequest {
        oci_image_target_id: target_id.clone(),
        tasks: Some(true),
    }));
    assert_typed_success!(client.get_oci_image_targets(GetOciImageTargetsRequest::default()));
    assert_typed_success!(
        client.modify_oci_image_target(ModifyOciImageTargetRequest::new(target_id.clone()))
    );
    assert_typed_success!(
        client.delete_oci_image_target(DeleteOciImageTargetRequest::new(target_id.clone(), false))
    );

    assert_create_success!(client.create_web_application_target(
        CreateWebApplicationTargetRequest::new("web", vec!["https://example.com".into()])
    ));
    assert_create_success!(client
        .clone_web_application_target(CloneWebApplicationTargetRequest::new(target_id.clone())));
    assert_typed_success!(
        client.get_web_application_target(GetWebApplicationTargetRequest {
            web_application_target_id: target_id.clone(),
            tasks: Some(true),
        })
    );
    assert_typed_success!(
        client.get_web_application_targets(GetWebApplicationTargetsRequest::default())
    );
    assert_typed_success!(client
        .modify_web_application_target(ModifyWebApplicationTargetRequest::new(target_id.clone())));
    assert_typed_success!(client
        .delete_web_application_target(DeleteWebApplicationTargetRequest::new(target_id, false)));

    let history = server.command_history();
    assert_eq!(history.len(), 13);
    for (command, expected_count) in [
        ("create_target", 1),
        ("create_oci_image_target", 2),
        ("get_oci_image_targets", 2),
        ("modify_oci_image_target", 1),
        ("delete_oci_image_target", 1),
        ("create_web_application_target", 2),
        ("get_web_application_targets", 2),
        ("modify_web_application_target", 1),
        ("delete_web_application_target", 1),
    ] {
        assert_eq!(
            history
                .iter()
                .filter(|record| record.command_name() == command)
                .count(),
            expected_count,
            "unexpected semantic inventory for {command}"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn alternate_target_facades_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "get_oci_image_targets",
                r#"<get_oci_image_targets_response status="503" status_text="registry unavailable"/>"#,
            ),
            (
                "create_web_application_target",
                r#"<create_web_application_target_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    assert_server_error!(
        client.get_oci_image_target(GetOciImageTargetRequest::new(id("oci-1"))),
        503,
        "registry unavailable"
    );
    let parse_error = client
        .clone_web_application_target(CloneWebApplicationTargetRequest::new(id("web-1")))
        .await
        .expect_err("missing cloned target id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn nvt_and_secinfo_queries_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_nvts",
            r#"<get_nvts_response status="503" status_text="feed unavailable"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut status_client = client(&server).await;

    assert_server_error!(
        status_client.get_scan_config_nvt(GetScanConfigNvtRequest::new("1.3.6.1")),
        503,
        "feed unavailable"
    );

    server.shutdown().await;

    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_preferences",
            r#"<get_preferences_response status="200" status_text="OK"><preference><value>30</value></preference></get_preferences_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut parse_client = client(&server).await;
    let parse_error = parse_client
        .get_nvt_preferences(GetNvtPreferencesRequest::default())
        .await
        .expect_err("missing NVT preference name should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "preference.name"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn assets_hosts_operating_systems_and_results_execute_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, ASSET_HOST_RESULT_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    let asset_id = id(CREATED_ID);
    server.clear_history();

    assert_typed_success!(client.get_assets(GetAssetsRequest::new(AssetType::Host)));
    assert_typed_success!(client.get_asset(GetAssetRequest::new(asset_id.clone(), AssetType::Host)));
    let mut create_request = CreateAssetRequest::new("192.0.2.10");
    create_request.comment = Some("created".into());
    let created = client
        .create_asset(create_request)
        .await
        .expect("generic asset create should parse");
    assert_eq!(created.status, 201);
    assert_eq!(created.id.as_ref(), Some(&asset_id));
    assert_typed_success!(client.modify_asset(ModifyAssetRequest::new(asset_id.clone(), "updated")));
    assert_typed_success!(client.delete_asset(DeleteAssetRequest::new(asset_id.clone())));

    assert_typed_success!(client.get_hosts(GetHostsRequest::default()));
    assert_typed_success!(client.get_host(GetHostRequest::new(asset_id.clone())));
    assert_create_success!(client.create_host(CreateHostRequest::new("192.0.2.20")));
    assert_typed_success!(
        client.modify_host(ModifyHostRequest::new(asset_id.clone(), "updated host"))
    );
    assert_typed_success!(client.delete_host(DeleteHostRequest::new(asset_id.clone())));

    assert_typed_success!(
        client.get_operating_system_assets(GetOperatingSystemAssetsRequest::default())
    );
    let mut os_detail = GetOperatingSystemAssetRequest::new(asset_id.clone());
    os_detail.details = Some(true);
    assert_typed_success!(client.get_operating_system_asset(os_detail));
    assert_typed_success!(client
        .delete_operating_system_asset(DeleteOperatingSystemAssetRequest::new(asset_id.clone())));

    assert_typed_success!(client.get_results(GetResultsRequest::default()));
    assert_typed_success!(client.get_result(GetResultRequest::new(asset_id)));

    let history = server.command_history();
    for (command, expected_count) in [
        ("get_assets", 6),
        ("create_asset", 2),
        ("modify_asset", 2),
        ("delete_asset", 3),
        ("get_results", 2),
    ] {
        assert_eq!(
            history
                .iter()
                .filter(|record| record.command_name() == command)
                .count(),
            expected_count,
            "unexpected facade inventory for {command}"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn all_asset_requests_execute_directly_with_their_associated_responses() {
    let Some(server) = fixture_server(MockVersion::V22_8, ASSET_HOST_RESULT_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    let asset_id = id(CREATED_ID);
    server.clear_history();

    assert_typed_success!(client.execute(GetAssetsRequest::new(AssetType::Host)));
    assert_typed_success!(client.execute(GetAssetRequest::new(asset_id.clone(), AssetType::Host)));
    let created = client
        .execute(CreateAssetRequest::new("192.0.2.10"))
        .await
        .expect("generic asset response association should parse");
    assert_eq!(created.status, 201);
    assert_typed_success!(client.execute(ModifyAssetRequest::new(asset_id.clone(), "updated")));
    assert_typed_success!(client.execute(DeleteAssetRequest::new(asset_id.clone())));

    assert_typed_success!(client.execute(GetHostsRequest::default()));
    assert_typed_success!(client.execute(GetHostRequest::new(asset_id.clone())));
    assert_create_success!(client.execute(CreateHostRequest::new("192.0.2.20")));
    assert_typed_success!(client.execute(ModifyHostRequest::new(asset_id.clone(), "updated host")));
    assert_typed_success!(client.execute(DeleteHostRequest::new(asset_id.clone())));

    assert_typed_success!(client.execute(GetOperatingSystemAssetsRequest::default()));
    assert_typed_success!(client.execute(GetOperatingSystemAssetRequest::new(asset_id.clone())));
    assert_typed_success!(client.execute(DeleteOperatingSystemAssetRequest::new(asset_id)));

    let history = server.command_history();
    for (command, expected_count) in [
        ("get_assets", 6),
        ("create_asset", 2),
        ("modify_asset", 2),
        ("delete_asset", 3),
    ] {
        assert_eq!(
            history
                .iter()
                .filter(|record| record.command_name() == command)
                .count(),
            expected_count,
            "unexpected direct-execution inventory for {command}"
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn generic_and_host_create_keep_distinct_id_requirements() {
    let response = r#"<create_asset_response status="201" status_text="OK"/>"#;
    let Some(server) = fixture_server(MockVersion::V22_8, &[("create_asset", response)]).await
    else {
        return;
    };
    let mut generic_client = client(&server).await;
    let generic = generic_client
        .execute(CreateAssetRequest::new("192.0.2.10"))
        .await
        .expect("generic create keeps report-import-compatible optional ID");
    assert_eq!(generic.id, None);
    server.shutdown().await;

    let Some(server) = fixture_server(MockVersion::V22_8, &[("create_asset", response)]).await
    else {
        return;
    };
    let mut host_client = client(&server).await;
    let error = host_client
        .execute(CreateHostRequest::new("192.0.2.10"))
        .await
        .expect_err("direct host creation requires a response ID");
    assert!(matches!(
        error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn generic_config_and_port_list_facades_cover_every_semantic_request() {
    let Some(server) = fixture_server(MockVersion::V22_4, CONFIG_PORT_LIST_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    let config_id = id(CREATED_ID);
    let port_list_id = id(CREATED_ID);
    let port_range_id = id("22222222-2222-2222-2222-222222222222");
    server.clear_history();

    assert_typed_success!(client.get_configs(GetConfigsRequest::default()));
    assert_typed_success!(client.get_config(GetConfigRequest::new(config_id.clone())));
    let mut create_config = CreateConfigRequest::new("baseline", config_id.clone());
    create_config.comment = Some("generic".into());
    create_config.usage_type = Some(ConfigUsageType::Scan);
    assert_create_success!(client.create_config(create_config));
    assert_create_success!(client.clone_config(CloneConfigRequest::new(config_id.clone())));
    assert_typed_success!(client.modify_config(ModifyConfigRequest::new(config_id.clone())));
    assert_typed_success!(client.delete_config(DeleteConfigRequest::new(config_id.clone())));

    assert_typed_success!(client.get_port_lists(GetPortListsRequest::default()));
    assert_typed_success!(client.get_port_list(GetPortListRequest::new(port_list_id.clone())));
    assert_create_success!(client.create_port_list(CreatePortListRequest::new("web")));
    assert_create_success!(client.clone_port_list(ClonePortListRequest::new(port_list_id.clone())));
    assert_typed_success!(client.modify_port_list(ModifyPortListRequest::new(port_list_id.clone())));
    assert_typed_success!(
        client.delete_port_list(DeletePortListRequest::new(port_list_id.clone(), false))
    );
    let created_range = client
        .create_port_range(CreatePortRangeRequest::new(
            port_list_id.clone(),
            PortRangeType::Tcp,
            80,
            443,
        ))
        .await
        .expect("typed port-range creation should parse");
    assert_eq!(created_range.status, 201);
    assert_typed_success!(client.delete_port_range(DeletePortRangeRequest::new(port_range_id)));

    let history = server.command_history();
    assert_eq!(history.len(), 14);
    for (command, expected_count) in [
        ("get_configs", 2),
        ("create_config", 2),
        ("modify_config", 1),
        ("delete_config", 1),
        ("get_port_lists", 2),
        ("create_port_list", 2),
        ("modify_port_list", 1),
        ("delete_port_list", 1),
        ("create_port_range", 1),
        ("delete_port_range", 1),
    ] {
        assert_eq!(
            history
                .iter()
                .filter(|record| record.command_name() == command)
                .count(),
            expected_count,
            "unexpected facade inventory for {command}"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn system_discovery_queries_execute_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, SYSTEM_DISCOVERY_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_typed_success!(client.get_aggregates("task", GetAggregatesRequestOpts::default()));
    assert_typed_success!(client.get_features_parsed());
    assert_typed_success!(client.get_feeds());
    assert_typed_success!(client.get_feed(FeedType::Nvt));
    assert_typed_success!(client.get_timezones());
    assert_typed_success!(client.get_settings());
    assert_typed_success!(client.get_system_reports(GetSystemReportsOpts::default()));
    assert_typed_success!(client.get_help());
    assert_typed_success!(client.get_help_with_mode(HelpMode::BriefXml));
    assert_typed_success!(client.describe_auth());
    assert_typed_success!(client.get_vulnerabilities(GetVulnsRequest::default()));
    assert_typed_success!(client.get_vulnerability(GetVulnerabilityRequest::new("vuln-1")));

    let history = server.command_history();
    assert_eq!(history.len(), 12);
    for (command, expected_count) in [
        ("get_aggregates", 1),
        ("get_features", 1),
        ("get_feeds", 2),
        ("get_timezones", 1),
        ("get_settings", 1),
        ("get_system_reports", 1),
        ("help", 2),
        ("describe_auth", 1),
        ("get_vulns", 2),
    ] {
        assert_eq!(
            history
                .iter()
                .filter(|record| record.command_name() == command)
                .count(),
            expected_count,
            "unexpected facade inventory for {command}"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn asset_and_result_facades_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_assets",
            r#"<get_assets_response status="409" status_text="asset conflict"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut status_client = client(&server).await;
    assert_server_error!(
        status_client.get_host(GetHostRequest::new(id("host-1"))),
        409,
        "asset conflict"
    );
    server.shutdown().await;

    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_results",
            r#"<get_results_response status="200" status_text="OK"><result/></get_results_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut parse_client = client(&server).await;
    let parse_error = parse_client
        .get_result(GetResultRequest::new(id("result-1")))
        .await
        .expect_err("malformed result should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "result.id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn system_discovery_facades_preserve_status_and_parse_context() {
    let Some(status_server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_system_reports",
            r#"<get_system_reports_response status="503" status_text="metrics unavailable"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut status_client = client(&status_server).await;

    assert_server_error!(
        status_client.get_system_reports(GetSystemReportsOpts::default()),
        503,
        "metrics unavailable"
    );
    status_server.shutdown().await;

    let Some(parse_server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_features",
            r#"<get_features_response status="200" status_text="OK"><feature enabled="1"><name>ENABLE_AGENTS</name></feature></get_features_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut parse_client = client(&parse_server).await;
    let parse_error = parse_client
        .get_features_parsed()
        .await
        .expect_err("missing feature compiled-in state should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "feature.compiled_in"
    ));

    parse_server.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn report_config_format_and_tls_facades_cover_all_semantic_requests() {
    let Some(server) = fixture_server(MockVersion::V22_8, REPORT_CONFIG_FORMAT_TLS_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let resource_id = id(CREATED_ID);
    server.clear_history();

    assert_typed_success!(client.get_report_configs(GetReportConfigsRequest::new()));
    assert_typed_success!(
        client.get_report_config(GetReportConfigRequest::new(resource_id.clone()))
    );
    assert_create_success!(client.create_report_config(CreateReportConfigRequest::new(
        "config",
        resource_id.clone(),
    )));
    assert_create_success!(
        client.clone_report_config(CloneReportConfigRequest::new(resource_id.clone(),))
    );
    let mut modify = ModifyReportConfigRequest::new(resource_id.clone());
    modify.name = Some("renamed".into());
    modify.comment = Some("changed".into());
    assert_typed_success!(client.modify_report_config(modify));
    let mut delete = DeleteReportConfigRequest::new(resource_id.clone());
    delete.ultimate = Some(true);
    assert_typed_success!(client.delete_report_config(delete));

    assert_typed_success!(client.get_report_formats(GetReportFormatsRequest::default()));
    assert_typed_success!(
        client.get_report_format(GetReportFormatRequest::new(resource_id.clone()))
    );
    assert_create_success!(
        client.clone_report_format(CloneReportFormatRequest::new(resource_id.clone()))
    );
    assert_create_success!(client.import_report_format(ImportReportFormatRequest::new(
        r#"<get_report_formats_response status="200" status_text="OK"><report_format id="11111111-1111-1111-1111-111111111111"><name>Imported</name></report_format></get_report_formats_response>"#,
    )));
    assert_typed_success!(
        client.modify_report_format(ModifyReportFormatRequest::new(resource_id.clone()))
    );
    let mut delete_format = DeleteReportFormatRequest::new(resource_id.clone());
    delete_format.ultimate = Some(true);
    assert_typed_success!(client.delete_report_format(delete_format));
    assert_typed_success!(
        client.verify_report_format(VerifyReportFormatRequest::new(resource_id.clone()))
    );

    assert_typed_success!(client.get_tls_certificates(GetTlsCertificatesRequest::default()));
    assert_typed_success!(
        client.get_tls_certificate(GetTlsCertificateRequest::new(resource_id.clone()))
    );
    assert_create_success!(
        client.create_tls_certificate(CreateTlsCertificateRequest::new(b"certificate".to_vec()))
    );
    assert_create_success!(
        client.clone_tls_certificate(CloneTlsCertificateRequest::new(resource_id.clone()))
    );
    assert_typed_success!(
        client.modify_tls_certificate(ModifyTlsCertificateRequest::new(resource_id.clone()))
    );
    assert_typed_success!(
        client.delete_tls_certificate(DeleteTlsCertificateRequest::new(resource_id.clone()))
    );

    let history = server.command_history();
    assert_eq!(history.len(), 19);
    for (command, expected_count) in [
        ("create_report_config", 2),
        ("delete_report_config", 1),
        ("get_report_configs", 2),
        ("modify_report_config", 1),
        ("create_report_format", 2),
        ("delete_report_format", 1),
        ("get_report_formats", 2),
        ("modify_report_format", 1),
        ("verify_report_format", 1),
        ("create_tls_certificate", 2),
        ("delete_tls_certificate", 1),
        ("get_tls_certificates", 2),
        ("modify_tls_certificate", 1),
    ] {
        assert_eq!(
            history
                .iter()
                .filter(|record| record.command_name() == command)
                .count(),
            expected_count,
            "unexpected facade count for {command}",
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn report_config_format_and_tls_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "get_report_configs",
                r#"<get_report_configs_response status="409" status_text="configuration conflict"/>"#,
            ),
            (
                "create_tls_certificate",
                r#"<create_tls_certificate_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    assert_server_error!(
        client.get_report_config(GetReportConfigRequest::new(id(CREATED_ID))),
        409,
        "configuration conflict"
    );
    let error = client
        .clone_tls_certificate(CloneTlsCertificateRequest::new(id(CREATED_ID)))
        .await
        .expect_err("missing cloned certificate id should fail");
    assert!(matches!(
        error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn generic_config_and_port_list_facades_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "get_configs",
                r#"<get_configs_response status="409" status_text="configuration conflict"/>"#,
            ),
            (
                "create_port_list",
                r#"<create_port_list_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    assert_server_error!(
        client.get_config(GetConfigRequest::new(id("config-1"))),
        409,
        "configuration conflict"
    );
    let parse_error = client
        .clone_port_list(ClonePortListRequest::new(id("port-list-1")))
        .await
        .expect_err("missing cloned port-list id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn generic_execute_decodes_the_requests_associated_response() {
    let Some(server) = fixture_server(
        MockVersion::V22_7,
        &[(
            "get_targets",
            r#"<get_targets_response status="200" status_text="OK"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let response = client
        .execute(GetTargetsRequest::default())
        .await
        .expect("associated response should decode");

    assert_eq!(response.status, 200);
    assert!(response.items.is_empty());
}

#[tokio::test]
async fn semantic_report_export_executes_binary_and_nested_xml_codecs() {
    let cases = [
        (
            r#"<get_reports_response status="200" status_text="OK"><report extension="bin" content_type="application/octet-stream">AP8B/g==</report></get_reports_response>"#,
            vec![0, 255, 1, 254],
        ),
        (
            r#"<get_reports_response status="200" status_text="OK"><report extension="xml" content_type="text/xml"><report id="report-1"><results><result id="one"/><result id="two"/></results></report></report></get_reports_response>"#,
            br#"<report id="report-1"><results><result id="one"/><result id="two"/></results></report>"#.to_vec(),
        ),
    ];

    for (fixture, expected) in cases {
        let Some(server) = fixture_server(MockVersion::V22_8, &[("get_reports", fixture)]).await
        else {
            return;
        };
        let mut client = client(&server).await;
        server.clear_history();

        let export = client
            .execute(GetReportExportRequest::new(id("report-1"), id("format-1")))
            .await
            .expect("associated irregular export response decodes");

        assert_eq!(export.bytes, expected);
        assert_eq!(server.command_history().len(), 1);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn semantic_report_requests_execute_large_and_mixed_repeated_responses() {
    const REPORTS: usize = 2_000;
    let mut large_fixture = String::from(r#"<get_reports_response status="200" status_text="OK">"#);
    for index in 0..REPORTS {
        large_fixture.push_str(&format!(
            r#"<report id="report-{index}"><name>Report {index}</name></report>"#
        ));
    }
    large_fixture.push_str(&format!(
        "<report_count>{REPORTS}<filtered>{REPORTS}</filtered></report_count></get_reports_response>"
    ));
    let overrides = [("get_reports", large_fixture.as_str())];
    let Some(server) = fixture_server(MockVersion::V22_8, &overrides).await else {
        return;
    };
    let mut large_client = client(&server).await;

    let reports = large_client
        .execute(GetReportsRequest::default())
        .await
        .expect("large associated report response decodes");
    assert_eq!(reports.items.len(), REPORTS);
    server.shutdown().await;

    let mixed_fixture = r#"<get_report_vulns_response status="200" status_text="OK"><vulns><vuln id="one"><name>First</name></vuln><vulnerability id="two"><name>Second</name></vulnerability><vuln id="three"><name>Third</name></vuln></vulns><report_vuln_count>3<filtered>3</filtered></report_vuln_count></get_report_vulns_response>"#;
    let Some(server) =
        fixture_server(MockVersion::V22_8, &[("get_report_vulns", mixed_fixture)]).await
    else {
        return;
    };
    let mut mixed_client = client(&server).await;

    let vulnerabilities = mixed_client
        .execute(GetReportVulnsRequest::new(id("report-1")))
        .await
        .expect("mixed repeated response decodes");
    assert_eq!(vulnerabilities.items.len(), 3);
    assert_eq!(vulnerabilities.items[1].id.as_deref(), Some("two"));
    assert_eq!(vulnerabilities.items[2].id.as_deref(), Some("three"));
    server.shutdown().await;
}

#[tokio::test]
async fn remaining_report_mutations_execute_with_fixed_response_associations() {
    let overrides = [
        (
            "create_report",
            r#"<create_report_response status="201" status_text="OK, resource created" id="11111111-1111-1111-1111-111111111111"/>"#,
        ),
        (
            "delete_report",
            r#"<delete_report_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_6, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let task_id = id("22222222-2222-2222-2222-222222222222");
    let report_id = id("33333333-3333-3333-3333-333333333333");

    let created = client
        .execute(ImportReportRequest::new(
            task_id.clone(),
            br#"<report id="created"><name>Created</name></report>"#,
        ))
        .await
        .expect("report creation should decode");
    assert_eq!(created.status, 201);

    let mut import_request = ImportReportRequest::new(
        task_id,
        br#"<report id="imported"><name>Imported</name></report>"#,
    );
    import_request.in_assets = Some(true);
    let imported = client
        .execute(import_request)
        .await
        .expect("report import should decode");
    assert_eq!(imported.status, 201);

    let deleted = client
        .execute(DeleteReportRequest::new(report_id.clone()))
        .await
        .expect("report deletion should decode");
    assert_eq!(deleted.status, 200);

    let audit_deleted = client
        .execute(DeleteAuditReportRequest::new(report_id))
        .await
        .expect("audit-report deletion should decode");
    assert_eq!(audit_deleted.status, 200);

    let history = server.command_history();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].command_name(), "create_report");
    assert_eq!(history[1].command_name(), "create_report");
    assert_eq!(history[2].command_name(), "delete_report");
    assert_eq!(history[3].command_name(), "delete_report");
    server.shutdown().await;
}

#[tokio::test]
async fn canonical_report_lifecycle_facades_accept_complete_requests_unchanged() {
    let overrides = [
        (
            "get_reports",
            r#"<get_reports_response status="200" status_text="OK"><report_count>0<filtered>0</filtered></report_count></get_reports_response>"#,
        ),
        (
            "get_scan_report",
            r#"<get_scan_report_response status="200" status_text="OK"><report id="33333333-3333-3333-3333-333333333333"><name>scan</name></report><scan_report_count>1<filtered>1</filtered></scan_report_count></get_scan_report_response>"#,
        ),
        (
            "delete_report",
            r#"<delete_report_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_8, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    let report_id = id("33333333-3333-3333-3333-333333333333");
    server.clear_history();

    client
        .get_report(GetReportRequest::new(report_id.clone()))
        .await
        .expect("ordinary report detail facade");
    client
        .get_audit_reports(GetAuditReportsRequest::default())
        .await
        .expect("audit list facade");
    client
        .get_scan_report(GetScanReportRequest::new(report_id.clone()))
        .await
        .expect("structured scan facade");
    client
        .delete_report(DeleteReportRequest::new(report_id.clone()))
        .await
        .expect("ordinary delete facade");
    client
        .delete_audit_report(DeleteAuditReportRequest::new(report_id))
        .await
        .expect("audit delete facade");

    let history = server.command_history();
    assert_eq!(history.len(), 5);
    assert_eq!(history[0].command_name(), "get_reports");
    assert_eq!(history[1].command_name(), "get_reports");
    assert_eq!(history[2].command_name(), "get_scan_report");
    assert_eq!(history[3].command_name(), "delete_report");
    assert_eq!(history[4].command_name(), "delete_report");
    server.shutdown().await;
}

#[tokio::test]
async fn report_mutation_execution_preserves_server_status_and_parse_context() {
    let Some(status_server) = fixture_server(
        MockVersion::V22_4,
        &[(
            "create_report",
            r#"<create_report_response status="503" status_text="backend unavailable"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut status_client = client(&status_server).await;
    let status_error = status_client
        .execute(ImportReportRequest::new(
            id("22222222-2222-2222-2222-222222222222"),
            br#"<report id="status"><name>Status</name></report>"#,
        ))
        .await
        .expect_err("server status should fail");
    assert!(matches!(
        status_error,
        GvmError::Server { status: 503, message }
            if message == "backend unavailable"
    ));
    status_server.shutdown().await;

    let Some(malformed_server) = fixture_server(
        MockVersion::V22_4,
        &[(
            "create_report",
            r#"<create_report_response status="201" status_text="created"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut malformed_client = client(&malformed_server).await;
    let malformed_error = malformed_client
        .import_report(ImportReportRequest::new(
            id("22222222-2222-2222-2222-222222222222"),
            br#"<report id="imported"><name>Imported</name></report>"#,
        ))
        .await
        .expect_err("missing response id should retain parse context");
    assert!(matches!(
        malformed_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    malformed_server.shutdown().await;
}

#[tokio::test]
async fn standard_task_requests_execute_on_the_oldest_supported_version() {
    let Some(server) = fixture_server(MockVersion::V22_4, TASK_LIFECYCLE_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let task_id = id("task-1");

    let listed = client
        .execute(GetTasksRequest::default())
        .await
        .expect("task listing should be supported");
    assert_eq!(listed.status, 200);
    let detailed = client
        .execute(GetTaskRequest::new(task_id.clone()))
        .await
        .expect("detailed task get should be supported");
    assert_eq!(detailed.status, 200);

    let created = client
        .execute(CreateTaskRequest::new(
            "scan",
            id("config-1"),
            id("target-1"),
            id("scanner-1"),
        ))
        .await
        .expect("standard task creation should be supported");
    assert_eq!(created.status, 201);
    let cloned = client
        .execute(CloneTaskRequest::new(task_id.clone()))
        .await
        .expect("task cloning should be supported");
    assert_eq!(cloned.status, 201);

    let modified = client
        .execute(ModifyTaskRequest::new(task_id.clone()))
        .await
        .expect("task modification should be supported");
    assert_eq!(modified.status, 200);
    let deleted = client
        .execute(DeleteTaskRequest::new(task_id.clone(), false))
        .await
        .expect("task deletion should be supported");
    assert_eq!(deleted.status, 200);

    let started = client
        .execute(StartTaskRequest::new(task_id.clone()))
        .await
        .expect("task start should be supported");
    assert_eq!(started.status, 202);
    assert_eq!(
        started.report_id.as_ref().map(EntityId::as_str),
        Some("22222222-2222-2222-2222-222222222222")
    );
    let stopped = client
        .execute(StopTaskRequest::new(task_id.clone()))
        .await
        .expect("task stop should be supported");
    assert_eq!(stopped.status, 200);
    let resumed = client
        .execute(ResumeTaskRequest::new(task_id))
        .await
        .expect("task resume should be supported");
    assert_eq!(resumed.status, 202);

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_tasks",
            "get_tasks",
            "create_task",
            "create_task",
            "modify_task",
            "delete_task",
            "start_task",
            "stop_task",
            "resume_task",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn standard_task_execute_preserves_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_tasks",
                r#"<get_tasks_response status="409" status_text="task conflict"/>"#,
            ),
            (
                "create_task",
                r#"<create_task_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .execute(GetTaskRequest::new(id("task-1")))
        .await
        .expect_err("non-success task response should fail");
    assert!(matches!(
        status_error,
        GvmError::Server { status: 409, message }
            if message == "task conflict"
    ));

    let parse_error = client
        .execute(CloneTaskRequest::new(id("task-1")))
        .await
        .expect_err("missing clone id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn specialized_task_create_and_move_helpers_use_typed_execution() {
    let Some(server) = fixture_server(MockVersion::V22_8, DEFERRED_TASK_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let mut import = CreateImportTaskRequest::new("import");
    import.comment = Some("comment".into());
    assert_create_success!(client.create_import_task(import));
    assert_create_success!(
        client.create_container_task(CreateContainerTaskRequest::new("container"))
    );
    let mut agent = CreateAgentGroupTaskRequest::new("agents", id("agent-group-1"));
    agent.scanner_id = Some(id("scanner-1"));
    assert_create_success!(client.create_agent_group_task(agent));
    assert_create_success!(client.create_oci_image_target_task(
        CreateOciImageTargetTaskRequest::new("oci", id("oci-target-1"), id("scanner-1"))
    ));
    assert_create_success!(client.create_container_image_task(
        CreateContainerImageTaskRequest::new(
            "container image",
            id("oci-target-1"),
            id("scanner-1"),
        )
    ));
    assert_create_success!(client.create_web_application_task(
        CreateWebApplicationTaskRequest::new("web", id("web-target-1"), id("scanner-1"))
    ));
    assert_typed_success!(client.move_task(MoveTaskRequest::new(
        id("task-1"),
        TaskMoveDestination::Slave(id("slave-1")),
    )));

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "create_task",
            "create_task",
            "create_task",
            "create_task",
            "create_task",
            "create_task",
            "move_task",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn next_only_specialized_task_helpers_reject_before_send() {
    let Some(server) = fixture_server(MockVersion::V22_7, DEFERRED_TASK_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_unsupported_command!(
        client.execute(CreateAgentGroupTaskRequest::new(
            "raw agents",
            id("agent-group-1"),
        )),
        "create_agent_group_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.execute(CreateOciImageTargetTaskRequest::new(
            "raw oci",
            id("oci-target-1"),
            id("scanner-1"),
        )),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.execute(CreateContainerImageTaskRequest::new(
            "raw container image",
            id("oci-target-1"),
            id("scanner-1"),
        )),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.execute(CreateWebApplicationTaskRequest::new(
            "raw web",
            id("web-target-1"),
            id("scanner-1"),
        )),
        "create_web_application_task",
        GmpVersion(22, 7),
        "22.8"
    );

    assert_unsupported_command!(
        client.create_agent_group_task(CreateAgentGroupTaskRequest::new(
            "agents",
            id("agent-group-1"),
        )),
        "create_agent_group_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.create_oci_image_target_task(CreateOciImageTargetTaskRequest::new(
            "oci",
            id("oci-target-1"),
            id("scanner-1"),
        )),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.create_container_image_task(CreateContainerImageTaskRequest::new(
            "container image",
            id("oci-target-1"),
            id("scanner-1"),
        )),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.create_web_application_task(CreateWebApplicationTaskRequest::new(
            "web",
            id("web-target-1"),
            id("scanner-1"),
        )),
        "create_web_application_task",
        GmpVersion(22, 7),
        "22.8"
    );

    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn audit_variant_helpers_use_typed_execution_and_presend_validation() {
    let Some(server) = fixture_server(MockVersion::V22_4, DEFERRED_TASK_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_typed_success!(client.get_audits(GetAuditsRequest::default()));
    assert_typed_success!(client.get_audit(GetAuditRequest::new(id("audit-1"))));
    assert_create_success!(client.create_audit(CreateAuditRequest::new(
        "audit",
        id("config-1"),
        id("target-1"),
        id("scanner-1"),
    )));
    assert_create_success!(client.clone_audit(CloneAuditRequest::new(id("audit-1"))));
    assert_typed_success!(client.modify_audit(ModifyAuditRequest::new(id("audit-1"))));
    assert_typed_success!(client.delete_audit(DeleteAuditRequest::new(id("audit-1"), false)));
    assert_eq!(
        client
            .start_audit(StartAuditRequest::new(id("audit-1")))
            .await
            .expect("audit start should parse")
            .status,
        202
    );
    assert_typed_success!(client.stop_audit(StopAuditRequest::new(id("audit-1"))));
    assert_eq!(
        client
            .resume_audit(ResumeAuditRequest::new(id("audit-1")))
            .await
            .expect("audit resume should parse")
            .status,
        202
    );

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_tasks",
            "get_tasks",
            "create_task",
            "create_task",
            "modify_task",
            "delete_task",
            "start_task",
            "stop_task",
            "resume_task",
        ]
    );

    server.clear_history();
    let mut invalid = ModifyAuditRequest::new(id("audit-1"));
    invalid.observer_group_ids = gvm_gmp::types::CollectionUpdate::replace([id("group-1")]);
    let error = client
        .modify_audit(invalid)
        .await
        .expect_err("invalid audit observer update should fail before sending");
    assert!(matches!(
        error,
        GvmError::Request(gvm_gmp::GmpRequestError::InvalidCombination { .. })
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn standard_credential_requests_execute_on_the_oldest_supported_version() {
    let Some(server) = fixture_server(MockVersion::V22_4, CREDENTIAL_LIFECYCLE_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let credential_id = id("credential-1");

    let listed = client
        .execute(GetCredentialsRequest::default())
        .await
        .expect("credential listing should be supported");
    assert_eq!(listed.status, 200);
    let detailed = client
        .execute(GetCredentialRequest::new(credential_id.clone()))
        .await
        .expect("detailed credential get should be supported");
    assert_eq!(detailed.status, 200);

    let created = client
        .execute(CreateCredentialRequest::new("credential"))
        .await
        .expect("credential creation should be supported");
    assert_eq!(created.status, 201);
    let cloned = client
        .execute(CloneCredentialRequest::new(credential_id.clone()))
        .await
        .expect("credential cloning should be supported");
    assert_eq!(cloned.status, 201);

    let modified = client
        .execute(ModifyCredentialRequest::new(credential_id.clone()))
        .await
        .expect("credential modification should be supported");
    assert_eq!(modified.status, 200);
    let deleted = client
        .execute(DeleteCredentialRequest::new(credential_id, false))
        .await
        .expect("credential deletion should be supported");
    assert_eq!(deleted.status, 200);

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_credentials",
            "get_credentials",
            "create_credential",
            "create_credential",
            "modify_credential",
            "delete_credential",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn standard_credential_execute_preserves_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_credentials",
                r#"<get_credentials_response status="409" status_text="credential conflict"/>"#,
            ),
            (
                "create_credential",
                r#"<create_credential_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .execute(GetCredentialRequest::new(id("credential-1")))
        .await
        .expect_err("non-success credential response should fail");
    assert!(matches!(
        status_error,
        GvmError::Server { status: 409, message }
            if message == "credential conflict"
    ));

    let parse_error = client
        .execute(CloneCredentialRequest::new(id("credential-1")))
        .await
        .expect_err("missing clone id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn scanner_requests_execute_on_the_oldest_supported_version() {
    let Some(server) = fixture_server(MockVersion::V22_4, SCANNER_LIFECYCLE_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let scanner_id = id("scanner-1");

    let listed = client
        .execute(GetScannersRequest::default())
        .await
        .expect("scanner listing should be supported");
    assert_eq!(listed.status, 200);
    let detailed = client
        .execute(GetScannerRequest::new(scanner_id.clone()))
        .await
        .expect("detailed scanner get should be supported");
    assert_eq!(detailed.status, 200);

    let created = client
        .execute(CreateScannerRequest::new(
            "scanner",
            "scanner.example",
            9390,
            ScannerType::OpenVasScanner,
        ))
        .await
        .expect("scanner creation should be supported");
    assert_eq!(created.status, 201);
    let cloned = client
        .execute(CloneScannerRequest::new(scanner_id.clone()))
        .await
        .expect("scanner cloning should be supported");
    assert_eq!(cloned.status, 201);

    let modified = client
        .execute(ModifyScannerRequest::new(scanner_id.clone()))
        .await
        .expect("scanner modification should be supported");
    assert_eq!(modified.status, 200);
    let deleted = client
        .execute(DeleteScannerRequest::new(scanner_id.clone(), false))
        .await
        .expect("scanner deletion should be supported");
    assert_eq!(deleted.status, 200);
    let verified = client
        .execute(VerifyScannerRequest::new(scanner_id))
        .await
        .expect("scanner verification should be supported");
    assert_eq!(verified.status, 200);

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_scanners",
            "get_scanners",
            "create_scanner",
            "create_scanner",
            "modify_scanner",
            "delete_scanner",
            "verify_scanner",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn scanner_execute_preserves_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_scanners",
                r#"<get_scanners_response status="409" status_text="scanner conflict"/>"#,
            ),
            (
                "create_scanner",
                r#"<create_scanner_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .execute(GetScannerRequest::new(id("scanner-1")))
        .await
        .expect_err("non-success scanner response should fail");
    assert!(matches!(
        status_error,
        GvmError::Server { status: 409, message }
            if message == "scanner conflict"
    ));

    let parse_error = client
        .execute(CloneScannerRequest::new(id("scanner-1")))
        .await
        .expect_err("missing clone id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

fn typed_schedule_input() -> ScheduleInput {
    ScheduleInput::new(
        ScheduleDefinition {
            first_run: ScheduleTimestamp::parse("2030-01-01T00:00:00Z").expect("valid first run"),
            recurrence: ScheduleRecurrence::Daily,
        },
        ScheduleTimezone::new("UTC").expect("valid timezone"),
    )
}

#[tokio::test]
async fn alert_and_schedule_families_execute_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_4, ALERT_SCHEDULE_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let alert_id = id("alert-1");
    let report_id = id("report-1");
    let schedule_id = id("schedule-1");

    assert_typed_success!(client.get_alerts(GetAlertsRequest::default()));
    assert_typed_success!(client.get_alert(GetAlertRequest::new(alert_id.clone())));
    assert_create_success!(client.create_alert(alert_create_request("alert")));
    assert_create_success!(client.clone_alert(CloneAlertRequest::new(alert_id.clone())));
    assert_typed_success!(client.modify_alert(ModifyAlertRequest::new(alert_id.clone())));
    assert_typed_success!(client.delete_alert(DeleteAlertRequest::new(alert_id.clone(), false)));
    assert_typed_success!(client.test_alert(TestAlertRequest::new(alert_id.clone())));
    assert_typed_success!(
        client.trigger_alert(TriggerAlertRequest::new(alert_id.clone(), report_id))
    );

    assert_typed_success!(client.get_schedules(GetSchedulesRequest::default()));
    assert_typed_success!(client.get_schedule(GetScheduleRequest::new(schedule_id.clone())));
    assert_create_success!(client.create_schedule({
        let mut request = CreateScheduleRequest::new("raw", "BEGIN:VCALENDAR\r\nEND:VCALENDAR");
        request.timezone = Some("UTC".into());
        request
    }));
    assert_create_success!(client.create_schedule(CreateScheduleRequest::from_input(
        "typed",
        typed_schedule_input()
    )));
    assert_create_success!(client.clone_schedule(CloneScheduleRequest::new(schedule_id.clone())));
    assert_typed_success!(client.modify_schedule(ModifyScheduleRequest::new(
        schedule_id.clone(),
        "BEGIN:VCALENDAR\r\nEND:VCALENDAR"
    )));
    assert_typed_success!(client.modify_schedule(ModifyScheduleRequest::from_input(
        schedule_id.clone(),
        typed_schedule_input()
    )));
    assert_typed_success!(client.delete_schedule(DeleteScheduleRequest::new(schedule_id, true)));

    let history = server.command_history();
    let commands = history
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_alerts",
            "get_alerts",
            "create_alert",
            "create_alert",
            "modify_alert",
            "delete_alert",
            "test_alert",
            "get_reports",
            "get_schedules",
            "get_schedules",
            "create_schedule",
            "create_schedule",
            "create_schedule",
            "modify_schedule",
            "modify_schedule",
            "delete_schedule",
        ]
    );

    let trigger_xml = history
        .iter()
        .find(|record| record.command_name() == "get_reports")
        .and_then(|record| std::str::from_utf8(record.raw_xml()).ok())
        .expect("trigger request XML");
    assert!(trigger_xml.contains("alert_id=\"alert-1\""));
    assert!(trigger_xml.contains("report_id=\"report-1\""));
    assert!(history.iter().any(|record| {
        record.command_name() == "create_schedule"
            && std::str::from_utf8(record.raw_xml())
                .is_ok_and(|xml| xml.contains("BEGIN:VCALENDAR"))
    }));
    server.shutdown().await;
}

#[tokio::test]
async fn alert_and_schedule_execute_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_alerts",
                r#"<get_alerts_response status="409" status_text="alert conflict"/>"#,
            ),
            (
                "create_schedule",
                r#"<create_schedule_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .get_alert(GetAlertRequest::new(id("alert-1")))
        .await
        .expect_err("non-success alert response should fail");
    assert!(matches!(
        status_error,
        GvmError::Server { status: 409, message }
            if message == "alert conflict"
    ));

    let parse_error = client
        .clone_schedule(CloneScheduleRequest::new(id("schedule-1")))
        .await
        .expect_err("missing cloned schedule id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn generic_execute_preserves_semantic_alias_version_checks() {
    let Some(server) = fixture_server(MockVersion::V22_7, &[]).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let error = client
        .execute(SemanticAliasRequest)
        .await
        .expect_err("semantic alias should be checked before sending the wire command");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_report_export"
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

const MUTATION_SUCCESS_OVERRIDES: &[(&str, &str)] = &[
    (
        "delete_credential",
        r#"<delete_credential_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_schedule",
        r#"<modify_schedule_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_schedule",
        r#"<delete_schedule_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_target",
        r#"<delete_target_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_task",
        r#"<modify_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_task",
        r#"<delete_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="200" status_text="OK"/>"#,
    ),
];

const MUTATION_ERROR_OVERRIDES: &[(&str, &str)] = &[
    (
        "delete_credential",
        r#"<delete_credential_response status="409" status_text="conflict"/>"#,
    ),
    (
        "modify_schedule",
        r#"<modify_schedule_response status="409" status_text="conflict"/>"#,
    ),
    (
        "delete_schedule",
        r#"<delete_schedule_response status="409" status_text="conflict"/>"#,
    ),
    (
        "delete_target",
        r#"<delete_target_response status="409" status_text="conflict"/>"#,
    ),
    (
        "modify_task",
        r#"<modify_task_response status="409" status_text="conflict"/>"#,
    ),
    (
        "delete_task",
        r#"<delete_task_response status="409" status_text="conflict"/>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="409" status_text="conflict"/>"#,
    ),
];

const DISCOVERY_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_targets",
        r#"<get_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_oci_image_targets",
        r#"<get_oci_image_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_web_application_targets",
        r#"<get_web_application_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_configs",
        r#"<get_configs_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_scanners",
        r#"<get_scanners_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_port_lists",
        r#"<get_port_lists_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tasks",
        r#"<get_tasks_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_reports",
        r#"<get_reports_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_results",
        r#"<get_results_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_nvts",
        r#"<get_nvts_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_nvt_families",
        r#"<get_nvt_families_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_info",
        r#"<get_info_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_alerts",
        r#"<get_alerts_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_credentials",
        r#"<get_credentials_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_filters",
        r#"<get_filters_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_notes",
        r#"<get_notes_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_overrides",
        r#"<get_overrides_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_schedules",
        r#"<get_schedules_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tags",
        r#"<get_tags_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tickets",
        r#"<get_tickets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_users",
        r#"<get_users_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_groups",
        r#"<get_groups_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_roles",
        r#"<get_roles_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_permissions",
        r#"<get_permissions_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_assets",
        r#"<get_assets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tls_certificates",
        r#"<get_tls_certificates_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_report_formats",
        r#"<get_report_formats_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_report_configs",
        r#"<get_report_configs_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_settings",
        r#"<get_settings_response status="200" status_text="OK"/>"#,
    ),
    ("help", r#"<help_response status="200" status_text="OK"/>"#),
    (
        "describe_auth",
        r#"<describe_auth_response status="200" status_text="OK"/>"#,
    ),
];

#[tokio::test]
async fn discovery_and_administration_families_parse_through_real_client() {
    let Some(server) = fixture_server(MockVersion::V22_8, DISCOVERY_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;

    let version = assert_typed_success!(client.get_version());
    assert_eq!(version.version, "22.8");

    assert_typed_success!(client.get_targets(GetTargetsRequest::default()));
    assert_typed_success!(client.get_target(GetTargetRequest::new(id(
        "11111111-1111-1111-1111-111111111111"
    ))));
    assert_typed_success!(client.get_oci_image_targets(GetOciImageTargetsRequest::default()));
    assert_typed_success!(
        client.get_web_application_targets(GetWebApplicationTargetsRequest::default())
    );
    assert_typed_success!(client.get_scan_configs(GetScanConfigsRequest::default()));
    assert_typed_success!(client.get_scanners(GetScannersRequest::default()));
    assert_typed_success!(client.get_port_lists(GetPortListsRequest::default()));
    assert_typed_success!(client.get_tasks(GetTasksRequest::default()));
    assert_typed_success!(client.get_task(GetTaskRequest::new(id(
        "11111111-1111-1111-1111-111111111111"
    ))));
    assert_typed_success!(client.get_reports(GetReportsRequest::default()));
    assert_typed_success!(client.get_results(GetResultsRequest::default()));
    assert_typed_success!(client.get_nvts(GetNvtsRequest::default()));
    assert_typed_success!(client.get_nvt_families(GetNvtFamiliesRequest::new()));
    assert_typed_success!(client.get_cves(GetCvesRequest::default()));
    assert_typed_success!(client.get_cpes(GetCpesRequest::default()));
    assert_typed_success!(client.get_cert_bund_advisories(GetCertBundAdvisoriesRequest::default()));
    assert_typed_success!(client.get_dfn_cert_advisories(GetDfnCertAdvisoriesRequest::default()));
    assert_typed_success!(client.get_alerts(GetAlertsRequest::default()));
    assert_typed_success!(client.get_credentials(GetCredentialsRequest::default()));
    assert_typed_success!(client.get_filters(GetFiltersRequest::default()));
    assert_typed_success!(client.get_notes(GetNotesRequest::default()));
    assert_typed_success!(client.get_overrides(GetOverridesRequest::default()));
    assert_typed_success!(client.get_schedules(GetSchedulesRequest::default()));
    assert_typed_success!(client.get_tags(GetTagsRequest::default()));
    assert_typed_success!(client.get_tickets(GetTicketsOpts::default()));
    assert_typed_success!(client.get_users(GetUsersRequest::default()));
    assert_typed_success!(client.get_groups(GetGroupsRequest::default()));
    assert_typed_success!(client.get_roles(GetRolesRequest::default()));
    assert_typed_success!(client.get_permissions(GetPermissionsRequest::default()));
    assert_typed_success!(client.get_hosts(GetHostsRequest::default()));
    assert_typed_success!(client.get_tls_certificates(GetTlsCertificatesRequest::default()));
    assert_typed_success!(client.get_report_formats(GetReportFormatsRequest::default()));
    assert_typed_success!(client.get_report_configs(GetReportConfigsRequest::default()));
    assert_typed_success!(client.get_settings());
    assert_typed_success!(client.get_help());
    assert_typed_success!(client.describe_auth());

    let history = server.command_history();
    for expected in [
        "get_targets",
        "get_oci_image_targets",
        "get_web_application_targets",
        "get_configs",
        "get_scanners",
        "get_reports",
        "get_info",
        "get_report_configs",
        "describe_auth",
    ] {
        assert!(
            history
                .iter()
                .any(|record| record.command_name() == expected),
            "missing command history entry for {expected}"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn create_families_parse_typed_ids_from_table_driven_fixture_responses() {
    let overrides = [
        (
            "create_port_list",
            create_response!("create_port_list_response"),
        ),
        ("create_alert", create_response!("create_alert_response")),
        ("create_filter", create_response!("create_filter_response")),
        ("create_note", create_response!("create_note_response")),
        (
            "create_override",
            create_response!("create_override_response"),
        ),
        (
            "create_schedule",
            create_response!("create_schedule_response"),
        ),
        ("create_tag", create_response!("create_tag_response")),
        ("create_ticket", create_response!("create_ticket_response")),
        ("create_user", create_response!("create_user_response")),
        ("create_group", create_response!("create_group_response")),
        ("create_role", create_response!("create_role_response")),
        (
            "create_permission",
            create_response!("create_permission_response"),
        ),
        ("create_asset", create_response!("create_asset_response")),
        (
            "create_tls_certificate",
            create_response!("create_tls_certificate_response"),
        ),
        (
            "create_report_format",
            create_response!("create_report_format_response"),
        ),
        ("create_task", create_response!("create_task_response")),
    ];
    let Some(server) = fixture_server(MockVersion::V22_8, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    let related_id = id("22222222-2222-2222-2222-222222222222");

    assert_create_success!(client.create_port_list(CreatePortListRequest::new("ports")));
    assert_create_success!(client.create_alert(alert_create_request("alert")));
    assert_create_success!(client.create_filter(CreateFilterRequest::new("filter")));
    assert_create_success!(
        client.create_note(CreateNoteRequest::new("1.3.6.1.4.1.25623.1.0.1", "note",))
    );
    assert_create_success!(client.create_override(CreateOverrideRequest::new(
        "1.3.6.1.4.1.25623.1.0.1",
        "override",
        5.0,
    )));
    assert_create_success!(client.create_schedule({
        let mut request = CreateScheduleRequest::new("schedule", "BEGIN:VCALENDAR\nEND:VCALENDAR");
        request.timezone = Some("UTC".into());
        request
    }));
    assert_create_success!(client.create_tag(CreateTagRequest::new("tag", tag_resources())));
    assert_create_success!(client.create_ticket(
        &related_id,
        CreateTicketOpts {
            assigned_to: related_id.clone(),
            open_note: TicketOpenNote::new("Please investigate").expect("non-empty note"),
            comment: None,
        }
    ));
    assert_create_success!(client.create_user(CreateUserRequest::new("user")));
    assert_create_success!(client.create_group(CreateGroupRequest::new("group")));
    assert_create_success!(client.create_role(CreateRoleRequest::new("role")));
    assert_create_success!(client.create_permission(permission_create_request()));
    assert_create_success!(client.create_host(CreateHostRequest::new("192.0.2.10")));
    assert_create_success!(
        client.create_tls_certificate(CreateTlsCertificateRequest::new(b"certificate".to_vec()))
    );
    assert_create_success!(client.create_task(CreateTaskRequest::new(
        "scan",
        related_id.clone(),
        related_id.clone(),
        related_id.clone(),
    )));
    assert_create_success!(client.clone_task(CloneTaskRequest::new(related_id.clone())));

    let history = server.command_history();
    for (command, child) in [
        ("create_port_list", "<name>ports</name>"),
        ("create_note", r#"<nvt oid="1.3.6.1.4.1.25623.1.0.1"/>"#),
        ("create_schedule", "<timezone>UTC</timezone>"),
        ("create_asset", "<name>192.0.2.10</name>"),
    ] {
        let record = history
            .iter()
            .find(|record| record.command_name() == command)
            .unwrap_or_else(|| panic!("missing command history entry for {command}"));
        let xml = std::str::from_utf8(record.raw_xml()).expect("request XML");
        assert!(xml.contains(child), "{command} XML missing {child}: {xml}");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn filters_tags_and_trashcan_execute_through_typed_facade() {
    let overrides = [
        (
            "get_filters",
            r#"<get_filters_response status="200" status_text="OK"><filter_count>0<filtered>0</filtered></filter_count></get_filters_response>"#,
        ),
        ("create_filter", create_response!("create_filter_response")),
        (
            "modify_filter",
            r#"<modify_filter_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_filter",
            r#"<delete_filter_response status="200" status_text="OK"/>"#,
        ),
        (
            "get_tags",
            r#"<get_tags_response status="200" status_text="OK"><tag_count>0<filtered>0</filtered></tag_count></get_tags_response>"#,
        ),
        ("create_tag", create_response!("create_tag_response")),
        (
            "modify_tag",
            r#"<modify_tag_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_tag",
            r#"<delete_tag_response status="200" status_text="OK"/>"#,
        ),
        (
            "empty_trashcan",
            r#"<empty_trashcan_response status="200" status_text="OK"/>"#,
        ),
        (
            "restore",
            r#"<restore_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_4, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let resource_id = id("resource-1");

    assert_typed_success!(client.get_filters(GetFiltersRequest::default()));
    assert_typed_success!(client.get_filter(GetFilterRequest::new(resource_id.clone())));
    assert_create_success!(client.create_filter(CreateFilterRequest::new("filter")));
    assert_create_success!(client.clone_filter(CloneFilterRequest::new(resource_id.clone())));
    assert_typed_success!(client.modify_filter(ModifyFilterRequest::new(resource_id.clone())));
    assert_typed_success!(
        client.delete_filter(DeleteFilterRequest::new(resource_id.clone(), false))
    );

    assert_typed_success!(client.get_tags(GetTagsRequest::default()));
    assert_typed_success!(client.get_tag(GetTagRequest::new(resource_id.clone())));
    assert_create_success!(client.create_tag(CreateTagRequest::new("tag", tag_resources())));
    assert_create_success!(client.clone_tag(CloneTagRequest::new(resource_id.clone())));
    assert_typed_success!(client.modify_tag(ModifyTagRequest::new(resource_id.clone())));
    assert_typed_success!(client.delete_tag(DeleteTagRequest::new(resource_id.clone(), true)));

    assert_typed_success!(client.empty_trashcan());
    assert_typed_success!(client.restore(&resource_id));
    assert_typed_success!(client.restore_from_trashcan(&resource_id));

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_filters",
            "get_filters",
            "create_filter",
            "create_filter",
            "modify_filter",
            "delete_filter",
            "get_tags",
            "get_tags",
            "create_tag",
            "create_tag",
            "modify_tag",
            "delete_tag",
            "empty_trashcan",
            "restore",
            "restore",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn filters_tags_and_trashcan_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_filters",
                r#"<get_filters_response status="409" status_text="filter conflict"/>"#,
            ),
            (
                "create_tag",
                r#"<create_tag_response status="201" status_text="OK"/>"#,
            ),
            (
                "empty_trashcan",
                r#"<empty_trashcan_response status="409" status_text="trashcan conflict"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let filter_error = client
        .get_filter(GetFilterRequest::new(id("filter-1")))
        .await
        .expect_err("non-success filter response should fail");
    assert!(matches!(
        filter_error,
        GvmError::Server { status: 409, message }
            if message == "filter conflict"
    ));

    let tag_error = client
        .clone_tag(CloneTagRequest::new(id("tag-1")))
        .await
        .expect_err("missing cloned tag id should fail");
    assert!(matches!(
        tag_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    let trashcan_error = client
        .empty_trashcan()
        .await
        .expect_err("non-success empty-trashcan response should fail");
    assert!(matches!(
        trashcan_error,
        GvmError::Server { status: 409, message }
            if message == "trashcan conflict"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn notes_execute_through_typed_facade() {
    let overrides = [
        (
            "get_notes",
            r#"<get_notes_response status="200" status_text="OK"><note_count>0<filtered>0</filtered></note_count></get_notes_response>"#,
        ),
        ("create_note", create_response!("create_note_response")),
        (
            "modify_note",
            r#"<modify_note_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_note",
            r#"<delete_note_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_4, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let resource_id = id("resource-1");

    assert_typed_success!(client.get_notes(GetNotesRequest::default()));
    assert_typed_success!(client.get_note(GetNoteRequest::new(resource_id.clone())));
    assert_create_success!(client.create_note({
        let mut request = CreateNoteRequest::new("1.3.6.1.4.1.25623.1.0.1", "note body");
        request.hosts = vec!["192.0.2.1".into()];
        request
    }));
    assert_create_success!(client.clone_note(CloneNoteRequest::new(resource_id.clone())));
    assert_typed_success!(
        client.modify_note(ModifyNoteRequest::new(resource_id.clone(), "updated note"))
    );
    assert_typed_success!(client.delete_note(DeleteNoteRequest::new(resource_id.clone(), true)));

    let history = server.command_history();
    let commands = history
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_notes",
            "get_notes",
            "create_note",
            "create_note",
            "modify_note",
            "delete_note",
        ]
    );
    let modify_note = history
        .iter()
        .find(|record| record.command_name() == "modify_note")
        .expect("modify_note history");
    assert!(!std::str::from_utf8(modify_note.raw_xml())
        .expect("request XML")
        .contains("<hosts"));
    let delete_note = history
        .iter()
        .find(|record| record.command_name() == "delete_note")
        .expect("delete_note history");
    assert!(std::str::from_utf8(delete_note.raw_xml())
        .expect("request XML")
        .contains(r#"ultimate="1""#));
    server.shutdown().await;
}

#[tokio::test]
async fn overrides_execute_through_typed_facade() {
    let overrides = [
        (
            "get_overrides",
            r#"<get_overrides_response status="200" status_text="OK"><override_count>0<filtered>0</filtered></override_count></get_overrides_response>"#,
        ),
        (
            "create_override",
            create_response!("create_override_response"),
        ),
        (
            "modify_override",
            r#"<modify_override_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_override",
            r#"<delete_override_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_4, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let resource_id = id("resource-1");

    assert_typed_success!(client.get_overrides(GetOverridesRequest::default()));
    assert_typed_success!(client.get_override(GetOverrideRequest::new(resource_id.clone())));
    assert_create_success!(client.create_override(CreateOverrideRequest::new(
        "1.3.6.1.4.1.25623.1.0.1",
        "override body",
        3.0,
    )));
    assert_create_success!(client.clone_override(CloneOverrideRequest::new(resource_id.clone())));
    assert_typed_success!(client.modify_override({
        let mut request = ModifyOverrideRequest::new(resource_id.clone(), "updated override", 3.0);
        request.hosts = vec!["192.0.2.2".into()];
        request
    }));
    assert_typed_success!(
        client.delete_override(DeleteOverrideRequest::new(resource_id.clone(), false))
    );

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_overrides",
            "get_overrides",
            "create_override",
            "create_override",
            "modify_override",
            "delete_override",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn notes_and_overrides_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_notes",
                r#"<get_notes_response status="409" status_text="note conflict"/>"#,
            ),
            (
                "create_override",
                r#"<create_override_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let note_error = client
        .get_note(GetNoteRequest::new(id("note-1")))
        .await
        .expect_err("non-success note response should fail");
    assert!(matches!(
        note_error,
        GvmError::Server { status: 409, message }
            if message == "note conflict"
    ));

    let override_error = client
        .clone_override(CloneOverrideRequest::new(id("override-1")))
        .await
        .expect_err("missing cloned override id should fail");
    assert!(matches!(
        override_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn remaining_mutation_families_use_typed_facade_and_scalar_relationship_updates() {
    let Some(server) = fixture_server(MockVersion::V22_8, MUTATION_SUCCESS_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let resource_id = id("resource-1");
    assert_typed_success!(
        client.delete_credential(DeleteCredentialRequest::new(resource_id.clone(), false))
    );
    assert_typed_success!(client.modify_schedule({
        let mut request =
            ModifyScheduleRequest::new(resource_id.clone(), "BEGIN:VCALENDAR\r\nEND:VCALENDAR");
        request.comment = Some("updated".into());
        request
    }));
    assert_typed_success!(
        client.delete_schedule(DeleteScheduleRequest::new(resource_id.clone(), true))
    );

    assert_typed_success!(client.modify_target(ModifyTargetRequest::new(resource_id.clone())));
    assert_typed_success!(client.modify_target({
        let mut request = ModifyTargetRequest::new(resource_id.clone());
        request.ssh_credential_id = ScalarUpdate::set(id("credential-1"));
        request
    }));
    assert_typed_success!(client.modify_target({
        let mut request = ModifyTargetRequest::new(resource_id.clone());
        request.ssh_credential_id = ScalarUpdate::Clear;
        request
    }));
    assert_typed_success!(
        client.delete_target(DeleteTargetRequest::new(resource_id.clone(), false))
    );

    assert_typed_success!(client.modify_task(ModifyTaskRequest::new(resource_id.clone())));
    assert_typed_success!(client.modify_task({
        let mut request = ModifyTaskRequest::new(resource_id.clone());
        request.schedule_id = ScalarUpdate::set(id("schedule-1"));
        request
    }));
    assert_typed_success!(client.modify_task({
        let mut request = ModifyTaskRequest::new(resource_id.clone());
        request.schedule_id = ScalarUpdate::Clear;
        request
    }));
    assert_typed_success!(client.stop_task(StopTaskRequest::new(resource_id.clone())));
    assert_typed_success!(client.delete_task(DeleteTaskRequest::new(resource_id.clone(), true)));

    let history = server.command_history();
    let xml_for = |command: &str| {
        history
            .iter()
            .filter(|record| record.command_name() == command)
            .map(|record| {
                std::str::from_utf8(record.raw_xml())
                    .expect("request XML")
                    .to_string()
            })
            .collect::<Vec<_>>()
    };

    let target_updates = xml_for("modify_target");
    assert_eq!(target_updates.len(), 3);
    assert_eq!(
        target_updates[0],
        r#"<modify_target target_id="resource-1"/>"#
    );
    assert!(target_updates[1].contains(r#"<ssh_credential id="credential-1"/>"#));
    assert!(target_updates[2].contains(r#"<ssh_credential id="0"/>"#));

    let task_updates = xml_for("modify_task");
    assert_eq!(task_updates.len(), 3);
    assert_eq!(task_updates[0], r#"<modify_task task_id="resource-1"/>"#);
    assert!(task_updates[1].contains(r#"<schedule id="schedule-1"/>"#));
    assert!(task_updates[2].contains(r#"<schedule id="0"/>"#));

    server.shutdown().await;
}

#[tokio::test]
async fn remaining_mutation_families_surface_non_success_responses() {
    let Some(server) = fixture_server(MockVersion::V22_8, MUTATION_ERROR_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    let resource_id = id("resource-1");

    assert_server_error!(
        client.delete_credential(DeleteCredentialRequest::new(resource_id.clone(), false)),
        409,
        "conflict"
    );
    assert_server_error!(
        client.modify_schedule(ModifyScheduleRequest::new(
            resource_id.clone(),
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR"
        )),
        409,
        "conflict"
    );
    assert_server_error!(
        client.delete_schedule(DeleteScheduleRequest::new(resource_id.clone(), false)),
        409,
        "conflict"
    );
    assert_server_error!(
        client.delete_target(DeleteTargetRequest::new(resource_id.clone(), false)),
        409,
        "conflict"
    );
    assert_server_error!(
        client.modify_task(ModifyTaskRequest::new(resource_id.clone())),
        409,
        "conflict"
    );
    assert_server_error!(
        client.stop_task(StopTaskRequest::new(resource_id.clone())),
        409,
        "conflict"
    );
    assert_server_error!(
        client.delete_task(DeleteTaskRequest::new(resource_id, false)),
        409,
        "conflict"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn report_export_omitted_and_selected_fields_preserve_distinct_xml() {
    let response = r#"<get_reports_response status="200" status_text="OK"><report id="11111111-1111-1111-1111-111111111111" format_id="33333333-3333-3333-3333-333333333333" extension="txt" content_type="text/plain">aGVsbG8=</report></get_reports_response>"#;
    let Some(server) = fixture_server(MockVersion::V22_8, &[("get_reports", response)]).await
    else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let report_id = id(CREATED_ID);
    let format_id = id("33333333-3333-3333-3333-333333333333");

    let omitted = client
        .get_report_export(GetReportExportRequest::new(
            report_id.clone(),
            format_id.clone(),
        ))
        .await
        .expect("report export with omitted optional fields should parse");
    assert_eq!(omitted.bytes, b"hello");

    let mut configured_request = GetReportExportRequest::new(report_id, format_id);
    configured_request.report_config_id = Some(id("44444444-4444-4444-4444-444444444444"));
    configured_request.filter_string = Some("severity>5".into());
    configured_request.ignore_pagination = Some(false);
    let configured = client
        .get_report_export(configured_request)
        .await
        .expect("report export with selected optional fields should parse");
    assert_eq!(configured.content_type.as_deref(), Some("text/plain"));

    let requests: Vec<_> = server
        .command_history()
        .into_iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("request XML"))
        .collect();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains(r#"report_id="11111111-1111-1111-1111-111111111111""#));
    assert!(requests[0].contains(r#"format_id="33333333-3333-3333-3333-333333333333""#));
    assert!(!requests[0].contains("config_id"));
    assert!(requests[1].contains(r#"config_id="44444444-4444-4444-4444-444444444444""#));
    assert!(requests[1].contains(r#"filter="severity&gt;5""#));
    assert!(requests[1].contains(r#"ignore_pagination="0""#));

    server.shutdown().await;
}

#[tokio::test]
async fn asynchronous_scan_report_export_uses_positive_help_discovery() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "help",
                r#"<help_response status="200" status_text="OK"><schema format="XML"><command><name>export_scan_report</name></command></schema></help_response>"#,
            ),
            (
                "export_scan_report",
                r#"<export_scan_report_response status="201" status_text="OK, resource created" id="11111111-1111-1111-1111-111111111111"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;
    assert_eq!(
        client.command_support("export_scan_report"),
        CommandSupport::RequiresDiscovery
    );
    server.clear_history();
    let undiscovered = client
        .export_scan_report(ExportScanReportRequest::new(id(
            "22222222-2222-2222-2222-222222222222",
        )))
        .await
        .expect_err("valid request must require discovery before encoding and sending");
    assert!(matches!(
        undiscovered,
        GvmError::CommandDiscoveryRequired { command }
            if command == "export_scan_report"
    ));
    let mut invalid = ExportScanReportRequest::new(id("22222222-2222-2222-2222-222222222222"));
    invalid.filter_string = Some("rows=10\0secret".into());
    let invalid_error = client
        .export_scan_report(invalid)
        .await
        .expect_err("validation must precede discovery policy");
    assert!(matches!(invalid_error, GvmError::Request(_)));
    assert!(server.command_history().is_empty());
    client
        .discover_commands()
        .await
        .expect("help discovery should parse");
    assert_eq!(
        client.command_support("export_scan_report"),
        CommandSupport::Supported
    );

    let response = client
        .export_scan_report(ExportScanReportRequest::new(id(
            "22222222-2222-2222-2222-222222222222",
        )))
        .await
        .expect("asynchronous export should parse");

    assert_eq!(response.status, 201);
    assert_eq!(response.export_status, None);
    server.shutdown().await;
}

#[tokio::test]
async fn asynchronous_scan_report_export_rejects_negative_help_discovery_on_22_8() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "help",
            r#"<help_response status="200" status_text="OK"><schema format="XML"><command><name>get_tasks</name></command></schema></help_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;
    client
        .discover_commands()
        .await
        .expect("negative help discovery should still parse");
    assert_eq!(
        client.command_support("export_scan_report"),
        CommandSupport::NotAdvertised
    );
    server.clear_history();

    let error = client
        .export_scan_report(ExportScanReportRequest::new(id(
            "22222222-2222-2222-2222-222222222222",
        )))
        .await
        .expect_err("22.8 alone must not unlock the command");

    assert!(matches!(
        error,
        GvmError::CommandNotAdvertised { command }
            if command == "export_scan_report"
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn generic_execute_preserves_server_status_and_parse_error_context() {
    let Some(status_server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_targets",
            r#"<get_targets_response status="503" status_text="backend unavailable"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut status_client = client(&status_server).await;
    let status_error = status_client
        .execute(GetTargetsRequest::default())
        .await
        .expect_err("server status should fail");
    assert!(matches!(
        status_error,
        GvmError::Server {
            status: 503,
            message
        } if message == "backend unavailable"
    ));
    status_server.shutdown().await;

    let Some(malformed_server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_targets",
            r#"<get_targets_response status="200" status_text="OK"><target><name>missing id</name></target></get_targets_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut malformed_client = client(&malformed_server).await;
    let malformed_error = malformed_client
        .execute(GetTargetsRequest::default())
        .await
        .expect_err("malformed typed payload should fail");
    assert!(matches!(
        malformed_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "target.id"
    ));
    malformed_server.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn distinct_registry_and_semantic_version_gates_fail_before_transport_send() {
    let Some(v225_server) = fixture_server(MockVersion::V22_5, &[]).await else {
        return;
    };
    let mut v225_client = client(&v225_server).await;
    v225_server.clear_history();

    let features_error = v225_client
        .get_features_parsed()
        .await
        .expect_err("22.6 registry gate should reject 22.5");
    assert!(matches!(
        features_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 5),
            required: "22.6",
        } if command == "get_features"
    ));
    let report_configs_error = v225_client
        .get_report_configs(GetReportConfigsRequest::default())
        .await
        .expect_err("22.6 report-config gate should reject 22.5");
    assert!(matches!(
        report_configs_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 5),
            required: "22.6",
        } if command == "get_report_configs"
    ));
    assert!(v225_server.command_history().is_empty());
    v225_server.shutdown().await;

    let Some(v227_server) = fixture_server(MockVersion::V22_7, &[]).await else {
        return;
    };
    let mut v227_client = client(&v227_server).await;
    v227_server.clear_history();
    let report_id = id(CREATED_ID);
    let format_id = id("33333333-3333-3333-3333-333333333333");

    assert_unsupported_command!(
        v227_client.execute(GetAgentsRequest::default()),
        "get_agents",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetAgentRequest::new(id("agent-1"))),
        "get_agents",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(ModifyAgentRequest::new(vec![id("agent-1")])),
        "modify_agent",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(DeleteAgentRequest::new(vec![id("agent-1")])),
        "delete_agent",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(SyncAgentsRequest::new()),
        "sync_agents",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(ModifyAgentControlScanConfigRequest::new(id("scanner-1"))),
        "modify_agent_control_scan_config",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetAgentInstallerInstructionRequest::new(
            id("scanner-1"),
            AgentInstallerLanguage::En,
            "https://gvmd.example",
        )),
        "get_agent_installer_instruction",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetAgentSupportBundleRequest::new(id("agent-1"), Some(7))),
        "get_agent_support_bundle",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(CreateAgentGroupRequest::new(
            "group",
            vec![id("agent-1")],
            "0 */5 * * *",
        )),
        "create_agent_group",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(CloneAgentGroupRequest::new(id("group-1"))),
        "create_agent_group",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetAgentGroupsRequest::default()),
        "get_agent_groups",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetAgentGroupRequest::new(id("group-1"))),
        "get_agent_groups",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(ModifyAgentGroupRequest::new(id("group-1"), "0 */5 * * *")),
        "modify_agent_group",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(DeleteAgentGroupRequest::new(id("group-1"), false)),
        "delete_agent_group",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetIntegrationConfigsRequest::default()),
        "get_integration_configs",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetIntegrationConfigRequest::new(
            id("integration-1"),
            Some(true),
        )),
        "get_integration_configs",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(ModifyIntegrationConfigRequest::new(id("integration-1"))),
        "modify_integration_config",
        GmpVersion(22, 7),
        "22.8"
    );

    assert_unsupported_command!(
        v227_client.execute(GetReportHostsRequest::new(report_id.clone())),
        "get_report_hosts",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportPortsRequest::new(report_id.clone())),
        "get_report_ports",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportApplicationsRequest::new(report_id.clone())),
        "get_report_applications",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportOperatingSystemsRequest::new(report_id.clone())),
        "get_report_operating_systems",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportCvesRequest::new(report_id.clone())),
        "get_report_cves",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportVulnsRequest::new(report_id.clone())),
        "get_report_vulns",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportTlsCertificatesRequest::new(report_id.clone())),
        "get_report_tls_certificates",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportErrorsRequest::new(report_id.clone())),
        "get_report_errors",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        v227_client.execute(GetReportClosedCvesRequest::new(report_id.clone())),
        "get_report_closed_cves",
        GmpVersion(22, 7),
        "22.8"
    );

    let mut invalid_projection = GetReportHostsRequest::new(report_id.clone());
    invalid_projection.filter_string = Some("rows=10\0secret".into());
    let invalid_error = v227_client
        .execute(invalid_projection)
        .await
        .expect_err("request validation must precede the 22.8 capability check");
    assert!(matches!(invalid_error, GvmError::Request(_)));

    let export_error = v227_client
        .get_report_export(GetReportExportRequest::new(report_id, format_id))
        .await
        .expect_err("22.8 semantic export gate should reject 22.7");
    assert!(matches!(
        export_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_report_export"
    ));
    let timezones_error = v227_client
        .get_timezones()
        .await
        .expect_err("22.8 timezone gate should reject 22.7");
    assert!(matches!(
        timezones_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_timezones"
    ));
    let oci_error = v227_client
        .get_oci_image_targets(GetOciImageTargetsRequest::default())
        .await
        .expect_err("22.8 registry gate should reject 22.7");
    assert!(matches!(
        oci_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_oci_image_targets"
    ));
    let oci_clone_error = v227_client
        .clone_oci_image_target(CloneOciImageTargetRequest::new(id("oci-1")))
        .await
        .expect_err("22.8 OCI-image-target clone gate should reject 22.7");
    assert!(matches!(
        oci_clone_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "create_oci_image_target"
    ));
    let web_clone_error = v227_client
        .clone_web_application_target(CloneWebApplicationTargetRequest::new(id("web-1")))
        .await
        .expect_err("22.8 web-application-target clone gate should reject 22.7");
    assert!(matches!(
        web_clone_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "create_web_application_target"
    ));
    assert!(v227_server.command_history().is_empty());
    v227_server.shutdown().await;
}
