// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical user-setting requests.

use base64::Engine as _;
use gvm_protocol::{Request as _, XmlCommand};

use crate::responses::{GetSettingsResponse, ModifyUserSettingResponse};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion, SortOrder};

/// A setting selector accepted by pinned gvmd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingSelector {
    /// Select an ordinary user setting by UUID.
    Id(EntityId),
    /// Select the special `Timezone` or `Password` setting by name.
    Name(String),
}

/// Canonical request for listing user settings.
#[derive(Debug, Clone, Default)]
pub struct GetUserSettingsRequest {
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

impl GetUserSettingsRequest {
    /// Create an unrestricted user-setting list request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filter_string: None,
            first: None,
            max: None,
            sort_field: None,
            sort_order: None,
        }
    }
}

impl GmpRequestCodec for GetUserSettingsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            self.filter_string.as_deref(),
            self.first,
            self.max,
            self.sort_field.as_deref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_settings"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(encode_get_settings(
            None,
            self.filter_string.as_deref(),
            self.first,
            self.max,
            self.sort_field.as_deref(),
            self.sort_order,
        ))
    }
}

impl GmpRequest for GetUserSettingsRequest {
    type Response = GetSettingsResponse;
}

/// Canonical request for one user setting.
#[derive(Debug, Clone)]
pub struct GetUserSettingRequest {
    /// Required setting identifier.
    pub setting_id: EntityId,
}

impl GetUserSettingRequest {
    /// Create a detailed single-setting request.
    #[must_use]
    pub fn new(setting_id: EntityId) -> Self {
        Self { setting_id }
    }
}

impl GmpRequestCodec for GetUserSettingRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_settings",
            "get_user_setting",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(encode_get_settings(
            Some(&self.setting_id),
            None,
            None,
            None,
            None,
            None,
        ))
    }
}

impl GmpRequest for GetUserSettingRequest {
    type Response = GetSettingsResponse;
}

/// Canonical request for modifying a user setting.
#[derive(Clone)]
pub struct ModifyUserSettingRequest {
    /// Setting selected by identifier or one of gvmd's name-addressable names.
    pub setting: SettingSelector,
    /// UTF-8 value to apply. An empty string requests an explicit clear.
    pub value: String,
}

impl std::fmt::Debug for ModifyUserSettingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyUserSettingRequest")
            .field("setting", &self.setting)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ModifyUserSettingRequest {
    /// Create a user-setting modification selected by identifier.
    #[must_use]
    pub fn new(setting_id: EntityId, value: impl Into<String>) -> Self {
        Self {
            setting: SettingSelector::Id(setting_id),
            value: value.into(),
        }
    }

    /// Create a user-setting modification selected by gvmd's setting name.
    #[must_use]
    pub fn by_name(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            setting: SettingSelector::Name(name.into()),
            value: value.into(),
        }
    }
}

impl GmpRequestCodec for ModifyUserSettingRequest {
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

impl GmpRequest for ModifyUserSettingRequest {
    type Response = ModifyUserSettingResponse;
}

fn encode_get_settings(
    setting_id: Option<&EntityId>,
    filter_string: Option<&str>,
    first: Option<u32>,
    max: Option<i32>,
    sort_field: Option<&str>,
    sort_order: Option<SortOrder>,
) -> Vec<u8> {
    let mut command = XmlCommand::new("get_settings");
    if let Some(setting_id) = setting_id {
        command.set_attribute("setting_id", setting_id.as_str());
    }
    if let Some(filter_string) = filter_string {
        command.set_attribute("filter", filter_string);
    }
    if let Some(first) = first {
        command.set_attribute("first", &first.to_string());
    }
    if let Some(max) = max {
        command.set_attribute("max", &max.to_string());
    }
    if let Some(sort_field) = sort_field {
        command.set_attribute("sort_field", sort_field);
    }
    if let Some(sort_order) = sort_order {
        command.set_attribute("sort_order", sort_order.as_gmp_str());
    }
    command.to_bytes()
}

pub(crate) fn validate_setting_modification(
    setting: &SettingSelector,
) -> Result<(), GmpRequestError> {
    match setting {
        SettingSelector::Id(_) => Ok(()),
        SettingSelector::Name(name) if matches!(name.as_str(), "Timezone" | "Password") => Ok(()),
        SettingSelector::Name(_) => Err(GmpRequestError::invalid_field(
            "setting",
            "name selection supports only Timezone or Password",
        )),
    }
}

pub(crate) fn encode_setting_modification(setting: &SettingSelector, value: &str) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    let mut command = XmlCommand::new("modify_setting");
    match setting {
        SettingSelector::Id(setting_id) => {
            command.set_attribute("setting_id", setting_id.as_str());
        }
        SettingSelector::Name(name) => {
            command.add_element_with_text("name", name);
        }
    }
    command.add_element_with_text("value", &encoded);
    command.to_bytes()
}

fn validate_query(
    filter_string: Option<&str>,
    first: Option<u32>,
    max: Option<i32>,
    sort_field: Option<&str>,
) -> Result<(), GmpRequestError> {
    if first == Some(0) {
        return Err(GmpRequestError::invalid_field(
            "first",
            "must be at least 1",
        ));
    }
    if max.is_some_and(|value| value == 0 || value < -1) {
        return Err(GmpRequestError::invalid_field(
            "max",
            "must be positive or -1",
        ));
    }
    if let Some(filter_string) = filter_string {
        validate_xml_text(filter_string, "filter_string")?;
    }
    if let Some(sort_field) = sort_field {
        if sort_field.trim().is_empty() {
            return Err(GmpRequestError::invalid_field(
                "sort_field",
                "must not be empty",
            ));
        }
        validate_xml_text(sort_field, "sort_field")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn canonical_user_setting_requests_encode_complete_values() {
        let version = GmpVersion(22, 8);
        let list = GetUserSettingsRequest {
            filter_string: Some("name=timezone".into()),
            first: Some(2),
            max: Some(-1),
            sort_field: Some("name".into()),
            sort_order: Some(SortOrder::Descending),
        };
        assert_eq!(
            list.encode(version).expect("valid list"),
            b"<get_settings filter=\"name=timezone\" first=\"2\" max=\"-1\" sort_field=\"name\" sort_order=\"descending\"/>"
        );
        assert_eq!(
            GetUserSettingRequest::new(id("s1"))
                .encode(version)
                .expect("valid detail"),
            b"<get_settings setting_id=\"s1\"/>"
        );
        assert_eq!(
            ModifyUserSettingRequest::new(id("s1"), "UTC")
                .encode(version)
                .expect("valid modify"),
            b"<modify_setting setting_id=\"s1\"><value>VVRD</value></modify_setting>"
        );
        assert_eq!(
            ModifyUserSettingRequest::by_name("Timezone", "")
                .encode(version)
                .expect("valid clear"),
            b"<modify_setting><name>Timezone</name><value></value></modify_setting>"
        );
    }

    #[test]
    fn validations_are_value_independent_and_values_are_redacted() {
        let invalid = GetUserSettingsRequest {
            first: Some(0),
            ..Default::default()
        }
        .validate()
        .expect_err("zero first must fail");
        assert_eq!(
            invalid,
            GmpRequestError::invalid_field("first", "must be at least 1")
        );

        let invalid_name = ModifyUserSettingRequest::by_name("secret-name", "secret-value")
            .validate()
            .expect_err("unsupported name must fail");
        for secret in ["secret-name", "secret-value"] {
            assert!(!invalid_name.to_string().contains(secret));
        }

        let request = ModifyUserSettingRequest::new(id("setting-1"), "setting-secret");
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("setting-secret"));
    }
}
