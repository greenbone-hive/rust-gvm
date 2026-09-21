// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-level requests.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::user_settings::{modify_user_setting, ModifyUserSettingOpts};
use crate::common::add_filter_attrs;
use crate::enums::SortOrder;
use crate::responses::{
    DescribeAuthResponse, GetLicenseResponse, GetSettingsResponse, GetTimezonesResponse,
    GetVulnerabilitiesResponse, ModifyAuthResponse, ModifyLicenseResponse, RunWizardResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Options for `modify_license` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyLicenseOpts {
    /// Whether gvmd may accept an empty license file.
    pub allow_empty: Option<bool>,
}

/// Options for `run_wizard` requests.
#[derive(Debug, Clone, Default)]
pub struct RunWizardOpts {
    /// Optional wizard execution mode.
    pub mode: Option<String>,
    /// Whether gvmd may only run a wizard marked as read-only.
    pub read_only: Option<bool>,
}

/// Semantic request for modifying a named authentication group.
#[derive(Clone)]
pub struct ModifyAuthRequest {
    group_name: String,
    auth_conf_settings: Vec<(String, String)>,
}

impl std::fmt::Debug for ModifyAuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyAuthRequest")
            .field("group_name", &self.group_name)
            .field("auth_conf_settings", &"<redacted>")
            .finish()
    }
}

impl ModifyAuthRequest {
    /// Create an authentication-configuration modification request.
    #[must_use]
    pub fn new(
        group_name: impl Into<String>,
        auth_conf_settings: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self {
            group_name: group_name.into(),
            auth_conf_settings: auth_conf_settings.into_iter().collect(),
        }
    }
}

impl Request for ModifyAuthRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_auth(&self.group_name, &self.auth_conf_settings).to_bytes()
    }
}

impl GmpRequest for ModifyAuthRequest {
    type Response = ModifyAuthResponse;
}

/// Semantic request backed by [`modify_license`].
#[derive(Clone)]
pub struct ModifyLicenseRequest {
    file: String,
}

impl std::fmt::Debug for ModifyLicenseRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyLicenseRequest")
            .field("file", &"<redacted>")
            .finish()
    }
}

impl ModifyLicenseRequest {
    /// Create a license modification with default options.
    #[must_use]
    pub fn new(file: impl Into<String>) -> Self {
        Self { file: file.into() }
    }
}

impl Request for ModifyLicenseRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_license(&self.file).to_bytes()
    }
}

impl GmpRequest for ModifyLicenseRequest {
    type Response = ModifyLicenseResponse;
}

/// Semantic request backed by [`modify_license_with_opts`].
#[derive(Clone)]
pub struct ModifyLicenseWithOptsRequest {
    file: String,
    opts: ModifyLicenseOpts,
}

impl std::fmt::Debug for ModifyLicenseWithOptsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyLicenseWithOptsRequest")
            .field("file", &"<redacted>")
            .field("allow_empty", &self.opts.allow_empty)
            .finish()
    }
}

impl ModifyLicenseWithOptsRequest {
    /// Create a license modification with explicit options.
    #[must_use]
    pub fn new(file: impl Into<String>, opts: ModifyLicenseOpts) -> Self {
        Self {
            file: file.into(),
            opts,
        }
    }
}

impl Request for ModifyLicenseWithOptsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_license_with_opts(&self.file, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyLicenseWithOptsRequest {
    type Response = ModifyLicenseResponse;
}

/// Semantic compatibility request backed by [`modify_setting`].
#[derive(Clone)]
pub struct ModifySettingRequest {
    setting_id: EntityId,
    value: String,
}

impl std::fmt::Debug for ModifySettingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifySettingRequest")
            .field("setting_id", &self.setting_id)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ModifySettingRequest {
    /// Create a system-module user-setting modification request.
    #[must_use]
    pub fn new(setting_id: EntityId, value: impl Into<String>) -> Self {
        Self {
            setting_id,
            value: value.into(),
        }
    }
}

impl Request for ModifySettingRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_setting(&self.setting_id, &self.value).to_bytes()
    }
}

impl GmpRequest for ModifySettingRequest {
    type Response = crate::responses::ModifyUserSettingResponse;
}

/// Semantic request backed by [`run_wizard`].
#[derive(Clone)]
pub struct RunWizardRequest {
    name: String,
    params: Vec<(String, String)>,
}

impl std::fmt::Debug for RunWizardRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunWizardRequest")
            .field("name", &self.name)
            .field("params", &"<redacted>")
            .finish()
    }
}

impl RunWizardRequest {
    /// Create a wizard request with default options.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        params: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self {
            name: name.into(),
            params: params.into_iter().collect(),
        }
    }
}

impl Request for RunWizardRequest {
    fn to_bytes(&self) -> Vec<u8> {
        run_wizard(&self.name, &self.params).to_bytes()
    }
}

impl GmpRequest for RunWizardRequest {
    type Response = RunWizardResponse;
}

/// Semantic request backed by [`run_wizard_with_opts`].
#[derive(Clone)]
pub struct RunWizardWithOptsRequest {
    name: String,
    params: Vec<(String, String)>,
    opts: RunWizardOpts,
}

impl std::fmt::Debug for RunWizardWithOptsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunWizardWithOptsRequest")
            .field("name", &self.name)
            .field("params", &"<redacted>")
            .field("mode", &self.opts.mode)
            .field("read_only", &self.opts.read_only)
            .finish()
    }
}

impl RunWizardWithOptsRequest {
    /// Create a wizard request with explicit options.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        params: impl IntoIterator<Item = (String, String)>,
        opts: RunWizardOpts,
    ) -> Self {
        Self {
            name: name.into(),
            params: params.into_iter().collect(),
            opts,
        }
    }
}

impl Request for RunWizardWithOptsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        run_wizard_with_opts(&self.name, &self.params, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for RunWizardWithOptsRequest {
    type Response = RunWizardResponse;
}

/// Canonical request for system-setting discovery.
#[derive(Debug, Clone, Default)]
pub struct GetSettingsRequest {
    /// Return a single setting by identifier.
    pub setting_id: Option<EntityId>,
    /// Inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// One-based first result.
    pub first: Option<u32>,
    /// Maximum results, or `-1` for all results.
    pub max: Option<i32>,
    /// Field used for sorting.
    pub sort_field: Option<String>,
    /// Sort direction.
    pub sort_order: Option<SortOrder>,
}

impl GetSettingsRequest {
    /// Create an unrestricted setting-discovery request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            setting_id: None,
            filter_string: None,
            first: None,
            max: None,
            sort_field: None,
            sort_order: None,
        }
    }
}

impl GmpRequestCodec for GetSettingsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.first == Some(0) {
            return Err(GmpRequestError::invalid_field(
                "first",
                "must be at least 1",
            ));
        }
        if self.max.is_some_and(|value| value == 0 || value < -1) {
            return Err(GmpRequestError::invalid_field(
                "max",
                "must be positive or -1",
            ));
        }
        if let Some(filter) = self.filter_string.as_deref() {
            validate_xml_text(filter, "filter_string")?;
        }
        if let Some(field) = self.sort_field.as_deref() {
            if field.trim().is_empty() {
                return Err(GmpRequestError::invalid_field(
                    "sort_field",
                    "must not be empty",
                ));
            }
            validate_xml_text(field, "sort_field")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_settings"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("get_settings");
        if let Some(id) = self.setting_id.as_ref() {
            command.set_attribute("setting_id", id.as_str());
        }
        if let Some(filter) = self.filter_string.as_deref() {
            command.set_attribute("filter", filter);
        }
        if let Some(first) = self.first {
            command.set_attribute("first", &first.to_string());
        }
        if let Some(max) = self.max {
            command.set_attribute("max", &max.to_string());
        }
        if let Some(field) = self.sort_field.as_deref() {
            command.set_attribute("sort_field", field);
        }
        if let Some(order) = self.sort_order {
            command.set_attribute("sort_order", order.as_gmp_str());
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetSettingsRequest {
    type Response = GetSettingsResponse;
}

/// Canonical request for timezone discovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetTimezonesRequest;

impl GetTimezonesRequest {
    /// Create a timezone-discovery request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for GetTimezonesRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_timezones"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_timezones").to_bytes())
    }
}

impl GmpRequest for GetTimezonesRequest {
    type Response = GetTimezonesResponse;
}

/// Canonical request for observed vulnerabilities occurring in reports.
#[derive(Debug, Clone, Default)]
pub struct GetVulnsRequest {
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. Sentinels `0` and `-2` are valid.
    pub filter_id: Option<EntityId>,
}

impl GmpRequestCodec for GetVulnsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_vulnerability_query(None, self.filter_string.as_deref(), self.filter_id.as_ref())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_vulns",
            "get_vulnerabilities",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(
            vulnerabilities_command(None, self.filter_string.as_deref(), self.filter_id.as_ref())
                .to_bytes(),
        )
    }
}

impl GmpRequest for GetVulnsRequest {
    type Response = GetVulnerabilitiesResponse;
}

/// Canonical request for one observed vulnerability through `get_vulns`.
#[derive(Debug, Clone)]
pub struct GetVulnerabilityRequest {
    /// Required opaque vulnerability identifier. NVT OIDs are valid identifiers here.
    pub vulnerability_id: String,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. Sentinels `0` and `-2` are valid.
    pub filter_id: Option<EntityId>,
}

impl GetVulnerabilityRequest {
    /// Create a descriptive-alias vulnerability request.
    #[must_use]
    pub fn new(vulnerability_id: impl Into<String>) -> Self {
        Self {
            vulnerability_id: vulnerability_id.into(),
            filter_string: None,
            filter_id: None,
        }
    }
}

impl GmpRequestCodec for GetVulnerabilityRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_vulnerability_query(
            Some(&self.vulnerability_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_vulns",
            "get_vulnerability",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(vulnerabilities_command(
            Some(&self.vulnerability_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetVulnerabilityRequest {
    type Response = GetVulnerabilitiesResponse;
}

fn vulnerabilities_command(
    vulnerability_id: Option<&str>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_vulns");
    if let Some(vulnerability_id) = vulnerability_id {
        command.set_attribute("vuln_id", vulnerability_id);
    }
    add_filter_attrs(&mut command, filter_string, filter_id);
    command
}

fn validate_vulnerability_query(
    vulnerability_id: Option<&str>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> Result<(), GmpRequestError> {
    if let Some(vulnerability_id) = vulnerability_id {
        if vulnerability_id.trim().is_empty() {
            return Err(GmpRequestError::invalid_field(
                "vulnerability_id",
                "must not be empty",
            ));
        }
        validate_xml_text(vulnerability_id, "vulnerability_id")?;
    }
    if let Some(filter_string) = filter_string {
        validate_xml_text(filter_string, "filter_string")?;
    }
    if filter_id.is_some_and(|value| EntityId::new(value.as_str()).is_err()) {
        return Err(GmpRequestError::invalid_field(
            "filter_id",
            "must be a valid entity identifier",
        ));
    }
    Ok(())
}

fn validate_xml_text(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.chars().all(|character| {
        matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
            || matches!(
                character as u32,
                0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
            )
    }) {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ))
    }
}

/// Semantic request for license discovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetLicenseRequest;

impl GetLicenseRequest {
    /// Create a license-discovery request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for GetLicenseRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_license"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_license").to_bytes())
    }
}

impl GmpRequest for GetLicenseRequest {
    type Response = GetLicenseResponse;
}

/// Semantic request for authentication-configuration discovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct DescribeAuthRequest;

impl DescribeAuthRequest {
    /// Create an authentication-description request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for DescribeAuthRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("describe_auth"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("describe_auth").to_bytes())
    }
}

impl GmpRequest for DescribeAuthRequest {
    type Response = DescribeAuthResponse;
}

/// Build a `modify_auth` request for a named authentication group.
///
/// `auth_conf_settings` must contain at least one key/value pair. Current gvmd
/// accepts a group containing authentication configuration settings; the old
/// `enabled` root attribute is not part of the command contract.
#[must_use]
pub fn modify_auth(group_name: &str, auth_conf_settings: &[(String, String)]) -> impl Request {
    let mut cmd = XmlCommand::new("modify_auth");
    let group = cmd.add_element("group");
    group.set_attribute("name", group_name);
    for (key, value) in auth_conf_settings {
        let setting = group.add_child("auth_conf_setting");
        setting.add_child_with_text("key", key);
        setting.add_child_with_text("value", value);
    }
    cmd
}

/// Build a `modify_license` request with a base64-encoded license file.
#[must_use]
pub fn modify_license(file: &str) -> impl Request {
    modify_license_with_opts(file, ModifyLicenseOpts::default())
}

/// Build a `modify_license` request with explicit options.
#[must_use]
pub fn modify_license_with_opts(file: &str, opts: ModifyLicenseOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_license");
    if let Some(allow_empty) = opts.allow_empty {
        cmd.set_attribute("allow_empty", if allow_empty { "1" } else { "0" });
    }
    cmd.add_element_with_text("file", file);
    cmd
}

/// Build a `modify_setting` request, Base64-encoding the UTF-8 value for GMP.
#[must_use]
pub fn modify_setting(setting_id: &EntityId, value: &str) -> impl Request {
    modify_user_setting(
        setting_id,
        ModifyUserSettingOpts {
            value: value.to_string(),
        },
    )
}

/// Build a `run_wizard` request.
#[must_use]
pub fn run_wizard(name: &str, params: &[(String, String)]) -> impl Request {
    run_wizard_with_opts(name, params, RunWizardOpts::default())
}

/// Build a `run_wizard` request with explicit execution options.
#[must_use]
pub fn run_wizard_with_opts(
    name: &str,
    params: &[(String, String)],
    opts: RunWizardOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("run_wizard");
    if let Some(read_only) = opts.read_only {
        cmd.set_attribute("read_only", if read_only { "1" } else { "0" });
    }
    if let Some(mode) = opts.mode.as_deref() {
        cmd.add_element_with_text("mode", mode);
    }
    cmd.add_element_with_text("name", name);
    let params_element = cmd.add_element("params");
    for (key, value) in params {
        let param = params_element.add_child("param");
        param.add_child_with_text("name", key);
        param.add_child_with_text("value", value);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn canonical_discovery_requests_encode() {
        let version = GmpVersion(22, 8);
        assert_eq!(
            GetLicenseRequest::new().encode(version).expect("encode"),
            b"<get_license/>"
        );
        assert_eq!(
            DescribeAuthRequest::new().encode(version).expect("encode"),
            b"<describe_auth/>"
        );
        assert_eq!(
            GetTimezonesRequest::new().encode(version).expect("encode"),
            b"<get_timezones/>"
        );
        let mut settings = GetSettingsRequest::new();
        settings.setting_id = Some(id("s1"));
        settings.filter_string = Some("name=Timezone".into());
        settings.first = Some(2);
        settings.max = Some(-1);
        settings.sort_field = Some("name".into());
        settings.sort_order = Some(SortOrder::Descending);
        assert_eq!(
            settings.encode(version).expect("encode"),
            br#"<get_settings filter="name=Timezone" first="2" max="-1" setting_id="s1" sort_field="name" sort_order="descending"/>"#
        );
    }

    #[test]
    fn system_filtered_mutation_commands_build_xml() {
        assert_eq!(
            xml(modify_auth(
                "method:ldap_connect",
                &[("enable".into(), "true".into())]
            )),
            "<modify_auth><group name=\"method:ldap_connect\"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting></group></modify_auth>"
        );
        assert_eq!(
            xml(modify_license("abc")),
            "<modify_license><file>abc</file></modify_license>"
        );
        assert_eq!(
            xml(modify_license_with_opts(
                "",
                ModifyLicenseOpts {
                    allow_empty: Some(true)
                }
            )),
            "<modify_license allow_empty=\"1\"><file></file></modify_license>"
        );
        assert_eq!(
            xml(modify_setting(&id("s1"), "Europe/Berlin")),
            "<modify_setting setting_id=\"s1\"><value>RXVyb3BlL0Jlcmxpbg==</value></modify_setting>"
        );
        assert_eq!(
            xml(run_wizard(
                "quick",
                &[("target".into(), "10.0.0.1".into())]
            )),
            "<run_wizard><name>quick</name><params><param><name>target</name><value>10.0.0.1</value></param></params></run_wizard>"
        );
        assert_eq!(
            xml(run_wizard_with_opts(
                "quick",
                &[],
                RunWizardOpts {
                    mode: Some("step".into()),
                    read_only: Some(true),
                }
            )),
            "<run_wizard read_only=\"1\"><mode>step</mode><name>quick</name><params/></run_wizard>"
        );
    }

    #[test]
    fn observed_vulnerability_requests_encode_and_validate_final_values() {
        let list = GetVulnsRequest {
            filter_string: Some("min_qod=70 rows=10".into()),
            filter_id: Some(id("0")),
        };
        assert_eq!(
            String::from_utf8(list.encode(GmpVersion(22, 4)).expect("valid request"))
                .expect("request is UTF-8"),
            "<get_vulns filt_id=\"0\" filter=\"min_qod=70 rows=10\"/>"
        );
        let detail = GetVulnerabilityRequest::new("1.3.6.1");
        assert_eq!(
            String::from_utf8(detail.encode(GmpVersion(22, 4)).expect("valid request"))
                .expect("request is UTF-8"),
            "<get_vulns vuln_id=\"1.3.6.1\"/>"
        );
        assert_eq!(
            list.command(),
            Some(GmpCommand::with_semantic_name(
                "get_vulns",
                "get_vulnerabilities"
            ))
        );
        let mut invalid = detail;
        invalid.vulnerability_id = " \t".into();
        assert!(invalid.encode(GmpVersion(22, 4)).is_err());
    }

    #[test]
    fn semantic_system_admin_requests_preserve_builder_bytes_and_associations() {
        fn auth<R: GmpRequest<Response = ModifyAuthResponse>>(_: &R) {}
        fn license<R: GmpRequest<Response = ModifyLicenseResponse>>(_: &R) {}
        fn setting<R: GmpRequest<Response = crate::responses::ModifyUserSettingResponse>>(_: &R) {}
        fn wizard<R: GmpRequest<Response = RunWizardResponse>>(_: &R) {}

        let settings = vec![("enable".into(), "auth-secret".into())];
        let auth_request = ModifyAuthRequest::new("method:ldap_connect", settings.clone());
        assert_eq!(
            auth_request.to_bytes(),
            modify_auth("method:ldap_connect", &settings).to_bytes()
        );
        auth(&auth_request);

        let license_request = ModifyLicenseRequest::new("license-secret");
        assert_eq!(
            license_request.to_bytes(),
            modify_license("license-secret").to_bytes()
        );
        license(&license_request);

        let license_opts = ModifyLicenseOpts {
            allow_empty: Some(false),
        };
        let license_with_opts =
            ModifyLicenseWithOptsRequest::new("license-secret", license_opts.clone());
        assert_eq!(
            license_with_opts.to_bytes(),
            modify_license_with_opts("license-secret", license_opts).to_bytes()
        );
        license(&license_with_opts);

        let setting_id = id("setting-1");
        let setting_request = ModifySettingRequest::new(setting_id.clone(), "setting-secret");
        assert_eq!(
            setting_request.to_bytes(),
            modify_setting(&setting_id, "setting-secret").to_bytes()
        );
        setting(&setting_request);

        let params = vec![("hosts".into(), "wizard-secret".into())];
        let wizard_request = RunWizardRequest::new("quick_first_scan", params.clone());
        assert_eq!(
            wizard_request.to_bytes(),
            run_wizard("quick_first_scan", &params).to_bytes()
        );
        wizard(&wizard_request);

        let wizard_opts = RunWizardOpts {
            mode: Some("step".into()),
            read_only: Some(false),
        };
        let wizard_with_opts =
            RunWizardWithOptsRequest::new("quick_first_scan", params.clone(), wizard_opts.clone());
        assert_eq!(
            wizard_with_opts.to_bytes(),
            run_wizard_with_opts("quick_first_scan", &params, wizard_opts).to_bytes()
        );
        wizard(&wizard_with_opts);
    }

    #[test]
    fn semantic_system_admin_debug_redacts_values() {
        let auth = format!(
            "{:?}",
            ModifyAuthRequest::new(
                "method:ldap_connect",
                [("password".into(), "auth-secret".into())]
            )
        );
        let license = format!("{:?}", ModifyLicenseRequest::new("license-secret"));
        let license_with_opts = format!(
            "{:?}",
            ModifyLicenseWithOptsRequest::new(
                "license-secret",
                ModifyLicenseOpts {
                    allow_empty: Some(false),
                }
            )
        );
        let setting = format!(
            "{:?}",
            ModifySettingRequest::new(id("setting-1"), "setting-secret")
        );
        let wizard = format!(
            "{:?}",
            RunWizardRequest::new(
                "quick_first_scan",
                [("hosts".into(), "wizard-secret".into())]
            )
        );
        let wizard_with_opts = format!(
            "{:?}",
            RunWizardWithOptsRequest::new(
                "quick_first_scan",
                [("hosts".into(), "wizard-secret".into())],
                RunWizardOpts::default(),
            )
        );

        for (debug, secret) in [
            (&auth, "auth-secret"),
            (&license, "license-secret"),
            (&license_with_opts, "license-secret"),
            (&setting, "setting-secret"),
            (&wizard, "wizard-secret"),
            (&wizard_with_opts, "wizard-secret"),
        ] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains(secret));
        }
    }
}
