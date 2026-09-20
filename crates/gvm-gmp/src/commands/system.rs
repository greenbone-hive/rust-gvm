// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-level requests.

use base64::Engine as _;
use gvm_protocol::{Request as _, XmlCommand};

use crate::commands::user_settings::{
    encode_setting_modification, validate_setting_modification, SettingSelector,
};
use crate::common::add_filter_attrs;
use crate::enums::SortOrder;
use crate::responses::{
    DescribeAuthResponse, GetLicenseResponse, GetSettingsResponse, GetTimezonesResponse,
    GetVulnerabilitiesResponse, ModifyAuthResponse, ModifyLicenseResponse, RunWizardResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Canonical request for modifying a named authentication group.
#[derive(Clone)]
pub struct ModifyAuthRequest {
    /// Authentication-method group name.
    pub group_name: String,
    /// Ordered setting-name/value replacements.
    ///
    /// An empty value explicitly clears the corresponding string setting.
    pub auth_conf_settings: Vec<(String, String)>,
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

impl GmpRequestCodec for ModifyAuthRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_nonempty_xml(&self.group_name, "group_name")?;
        for (name, value) in &self.auth_conf_settings {
            validate_nonempty_xml(name, "auth_conf_settings")?;
            validate_xml_text(value, "auth_conf_settings")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_auth"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("modify_auth");
        let group = command.add_element("group");
        group.set_attribute("name", &self.group_name);
        for (name, value) in &self.auth_conf_settings {
            let setting = group.add_child("auth_conf_setting");
            setting.add_child_with_text("key", name);
            setting.add_child_with_text("value", value);
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for ModifyAuthRequest {
    type Response = ModifyAuthResponse;
}

/// Canonical request for replacing or clearing the current license file.
#[derive(Clone)]
pub struct ModifyLicenseRequest {
    /// Base64-encoded license-file payload.
    pub file: String,
    /// Whether gvmd may accept an empty payload.
    ///
    /// Omission has the pinned gvmd default of `false`.
    pub allow_empty: Option<bool>,
}

impl std::fmt::Debug for ModifyLicenseRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyLicenseRequest")
            .field("file", &"<redacted>")
            .field("allow_empty", &self.allow_empty)
            .finish()
    }
}

impl ModifyLicenseRequest {
    /// Create a license modification with default options.
    #[must_use]
    pub fn new(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            allow_empty: None,
        }
    }
}

impl GmpRequestCodec for ModifyLicenseRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.file.is_empty() {
            if self.allow_empty != Some(true) {
                return Err(GmpRequestError::invalid_field(
                    "file",
                    "must not be empty unless allow_empty is true",
                ));
            }
            return Ok(());
        }
        base64::engine::general_purpose::STANDARD
            .decode(self.file.as_bytes())
            .map(|_| ())
            .map_err(|_| GmpRequestError::invalid_field("file", "must be valid standard Base64"))
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_license"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("modify_license");
        if let Some(allow_empty) = self.allow_empty {
            command.set_attribute("allow_empty", if allow_empty { "1" } else { "0" });
        }
        command.add_element_with_text("file", &self.file);
        Ok(command.to_bytes())
    }
}

impl GmpRequest for ModifyLicenseRequest {
    type Response = ModifyLicenseResponse;
}

/// Canonical generic setting modification.
#[derive(Clone)]
pub struct ModifySettingRequest {
    /// Setting selected by identifier or one of gvmd's name-addressable names.
    pub setting: SettingSelector,
    /// UTF-8 value to apply. An empty string requests an explicit clear.
    pub value: String,
}

impl std::fmt::Debug for ModifySettingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifySettingRequest")
            .field("setting", &self.setting)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ModifySettingRequest {
    /// Create a system-module user-setting modification request.
    #[must_use]
    pub fn new(setting_id: EntityId, value: impl Into<String>) -> Self {
        Self {
            setting: SettingSelector::Id(setting_id),
            value: value.into(),
        }
    }

    /// Create a setting modification selected by gvmd's setting name.
    #[must_use]
    pub fn by_name(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            setting: SettingSelector::Name(name.into()),
            value: value.into(),
        }
    }
}

impl GmpRequestCodec for ModifySettingRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_setting_modification(&self.setting)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_setting"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(encode_setting_modification(&self.setting, &self.value))
    }
}

impl GmpRequest for ModifySettingRequest {
    type Response = crate::responses::ModifyUserSettingResponse;
}

/// Canonical request for running a gvmd wizard.
#[derive(Clone)]
pub struct RunWizardRequest {
    /// Wizard name. Pinned gvmd accepts only ASCII alphanumeric characters and `_`.
    pub name: String,
    /// Ordered wizard parameter-name/value pairs.
    pub params: Vec<(String, String)>,
    /// Optional wizard execution mode. An empty mode selects the default mode.
    pub mode: Option<String>,
    /// Whether gvmd must reject a wizard that is not marked read-only.
    pub read_only: Option<bool>,
}

impl std::fmt::Debug for RunWizardRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunWizardRequest")
            .field("name", &self.name)
            .field("params", &"<redacted>")
            .field("mode", &self.mode)
            .field("read_only", &self.read_only)
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
            mode: None,
            read_only: None,
        }
    }
}

impl GmpRequestCodec for RunWizardRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.name.is_empty()
            || !self
                .name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Err(GmpRequestError::invalid_field(
                "name",
                "must contain only ASCII alphanumeric characters or underscore",
            ));
        }
        if let Some(mode) = self.mode.as_deref() {
            validate_xml_text(mode, "mode")?;
        }
        for (name, value) in &self.params {
            validate_nonempty_xml(name, "params")?;
            validate_xml_text(value, "params")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("run_wizard"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("run_wizard");
        if let Some(read_only) = self.read_only {
            command.set_attribute("read_only", if read_only { "1" } else { "0" });
        }
        if let Some(mode) = self.mode.as_deref() {
            command.add_element_with_text("mode", mode);
        }
        command.add_element_with_text("name", &self.name);
        let params = command.add_element("params");
        for (name, value) in &self.params {
            let param = params.add_child("param");
            param.add_child_with_text("name", name);
            param.add_child_with_text("value", value);
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for RunWizardRequest {
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

fn validate_nonempty_xml(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        return Err(GmpRequestError::invalid_field(field, "must not be empty"));
    }
    validate_xml_text(value, field)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn canonical_system_mutations_encode_complete_values() {
        let version = GmpVersion(22, 8);
        assert_eq!(
            ModifyAuthRequest::new(
                "method:ldap_connect",
                [("enable".into(), "true".into())]
            )
            .encode(version)
            .expect("valid auth"),
            b"<modify_auth><group name=\"method:ldap_connect\"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting></group></modify_auth>"
        );

        let mut license = ModifyLicenseRequest::new("YWJj");
        license.allow_empty = Some(false);
        assert_eq!(
            license.encode(version).expect("valid license"),
            b"<modify_license allow_empty=\"0\"><file>YWJj</file></modify_license>"
        );

        let mut empty_license = ModifyLicenseRequest::new("");
        empty_license.allow_empty = Some(true);
        assert_eq!(
            empty_license.encode(version).expect("valid clear"),
            b"<modify_license allow_empty=\"1\"><file></file></modify_license>"
        );
        assert_eq!(
            ModifySettingRequest::new(id("s1"), "Europe/Berlin")
                .encode(version)
                .expect("valid setting"),
            b"<modify_setting setting_id=\"s1\"><value>RXVyb3BlL0Jlcmxpbg==</value></modify_setting>"
        );

        let mut wizard = RunWizardRequest::new("quick", [("target".into(), "10.0.0.1".into())]);
        wizard.mode = Some("step".into());
        wizard.read_only = Some(true);
        assert_eq!(
            wizard.encode(version).expect("valid wizard"),
            b"<run_wizard read_only=\"1\"><mode>step</mode><name>quick</name><params><param><name>target</name><value>10.0.0.1</value></param></params></run_wizard>"
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
    fn canonical_system_admin_requests_have_fixed_associations() {
        fn auth<R: GmpRequest<Response = ModifyAuthResponse>>(_: &R) {}
        fn license<R: GmpRequest<Response = ModifyLicenseResponse>>(_: &R) {}
        fn setting<R: GmpRequest<Response = crate::responses::ModifyUserSettingResponse>>(_: &R) {}
        fn wizard<R: GmpRequest<Response = RunWizardResponse>>(_: &R) {}

        let auth_request = ModifyAuthRequest::new(
            "method:ldap_connect",
            [("enable".into(), "auth-secret".into())],
        );
        auth(&auth_request);

        let mut license_request = ModifyLicenseRequest::new("bGljZW5zZS1zZWNyZXQ=");
        license_request.allow_empty = Some(false);
        license(&license_request);

        let setting_request = ModifySettingRequest::new(id("setting-1"), "setting-secret");
        setting(&setting_request);

        let mut wizard_request = RunWizardRequest::new(
            "quick_first_scan",
            [("hosts".into(), "wizard-secret".into())],
        );
        wizard_request.mode = Some("step".into());
        wizard_request.read_only = Some(false);
        wizard(&wizard_request);
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

        for (debug, secret) in [
            (&auth, "auth-secret"),
            (&license, "license-secret"),
            (&setting, "setting-secret"),
            (&wizard, "wizard-secret"),
        ] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains(secret));
        }
    }
}
