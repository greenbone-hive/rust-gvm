// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical NVT discovery requests.
//!
//! Canonical requests encode through [`crate::GmpRequestCodec`] and do not use
//! the transitional raw [`gvm_protocol::Request`] adapter:
//!
//! ```compile_fail
//! use gvm_gmp::commands::nvts::GetNvtsRequest;
//! use gvm_protocol::Request;
//!
//! fn require_raw_request<R: Request>(_: R) {}
//! require_raw_request(GetNvtsRequest::default());
//! ```

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::set_optional_bool_attr;
use crate::responses::{GetNvtFamiliesResponse, GetNvtsResponse, GetScanConfigPreferencesResponse};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion, SortOrder};

/// Request for listing NVTs from the feed.
#[derive(Debug, Clone, Default)]
pub struct GetNvtsRequest {
    /// Optional family restriction.
    pub family: Option<String>,
    /// Optional scan-configuration membership and preference context.
    pub config_id: Option<EntityId>,
    /// Optional preference-value context without a membership restriction.
    pub preferences_config_id: Option<EntityId>,
    /// Request detailed NVT data.
    pub details: Option<bool>,
    /// Include NVT preferences. Requires effective `details=true`.
    pub preferences: Option<bool>,
    /// Include the preference count. Requires effective `details=true`.
    pub preference_count: Option<bool>,
    /// Include configured/default timeout values. Requires details and a config context.
    pub timeout: Option<bool>,
    /// Request the lean detail projection. Requires effective `details=true`.
    pub lean: Option<bool>,
    /// Omit CERT references from details. Requires effective `details=true`.
    pub skip_cert_refs: Option<bool>,
    /// Omit tags from details. Requires effective `details=true`.
    pub skip_tags: Option<bool>,
    /// Optional opaque gvmd NVT sort column.
    pub sort_field: Option<String>,
    /// Optional NVT sort direction.
    pub sort_order: Option<SortOrder>,
}

impl GmpRequestCodec for GetNvtsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_nvt_query(
            None,
            self.family.as_deref(),
            self.config_id.as_ref(),
            self.preferences_config_id.as_ref(),
            flags(self),
            self.sort_field.as_deref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_nvts"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(nvt_command(
            None,
            self.family.as_deref(),
            self.config_id.as_ref(),
            self.preferences_config_id.as_ref(),
            flags(self),
            self.sort_field.as_deref(),
            self.sort_order,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetNvtsRequest {
    type Response = GetNvtsResponse;
}

/// Request for retrieving one NVT.
#[derive(Debug, Clone)]
pub struct GetNvtRequest {
    /// Required NVT OID. OIDs remain opaque strings rather than UUIDs.
    pub nvt_oid: String,
    /// Optional scan-configuration preference context.
    pub config_id: Option<EntityId>,
    /// Optional preference-value context without membership checking.
    pub preferences_config_id: Option<EntityId>,
    /// Request detailed NVT data. Defaults to `Some(true)`.
    pub details: Option<bool>,
    /// Include NVT preferences.
    pub preferences: Option<bool>,
    /// Include the preference count.
    pub preference_count: Option<bool>,
    /// Include configured/default timeout values.
    pub timeout: Option<bool>,
    /// Request the lean detail projection.
    pub lean: Option<bool>,
    /// Omit CERT references from details.
    pub skip_cert_refs: Option<bool>,
    /// Omit tags from details.
    pub skip_tags: Option<bool>,
    /// Optional opaque gvmd NVT sort column.
    pub sort_field: Option<String>,
    /// Optional NVT sort direction.
    pub sort_order: Option<SortOrder>,
}

impl GetNvtRequest {
    /// Create a detailed request for one NVT.
    #[must_use]
    pub fn new(nvt_oid: impl Into<String>) -> Self {
        Self {
            nvt_oid: nvt_oid.into(),
            config_id: None,
            preferences_config_id: None,
            details: Some(true),
            preferences: None,
            preference_count: None,
            timeout: None,
            lean: None,
            skip_cert_refs: None,
            skip_tags: None,
            sort_field: None,
            sort_order: None,
        }
    }
}

impl GmpRequestCodec for GetNvtRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_nvt_query(
            Some(&self.nvt_oid),
            None,
            self.config_id.as_ref(),
            self.preferences_config_id.as_ref(),
            flags_detail(self),
            self.sort_field.as_deref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_nvts", "get_nvt"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(nvt_command(
            Some(&self.nvt_oid),
            None,
            self.config_id.as_ref(),
            self.preferences_config_id.as_ref(),
            flags_detail(self),
            self.sort_field.as_deref(),
            self.sort_order,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetNvtRequest {
    type Response = GetNvtsResponse;
}

/// Request for listing NVT membership in one scan configuration and family.
#[derive(Debug, Clone)]
pub struct GetScanConfigNvtsRequest {
    /// Required scan-configuration membership and preference context.
    pub config_id: EntityId,
    /// Required family for the pinned config-list implementation.
    pub family: String,
    /// Request detailed NVT data.
    pub details: Option<bool>,
    /// Include NVT preferences.
    pub preferences: Option<bool>,
    /// Include the preference count.
    pub preference_count: Option<bool>,
    /// Include configured/default timeout values.
    pub timeout: Option<bool>,
    /// Request the lean detail projection.
    pub lean: Option<bool>,
    /// Omit CERT references from details.
    pub skip_cert_refs: Option<bool>,
    /// Omit tags from details.
    pub skip_tags: Option<bool>,
    /// Optional opaque gvmd NVT sort column.
    pub sort_field: Option<String>,
    /// Optional NVT sort direction.
    pub sort_order: Option<SortOrder>,
}

impl GetScanConfigNvtsRequest {
    /// Create a config-and-family scoped NVT-list request.
    #[must_use]
    pub fn new(config_id: EntityId, family: impl Into<String>) -> Self {
        Self {
            config_id,
            family: family.into(),
            details: None,
            preferences: None,
            preference_count: None,
            timeout: None,
            lean: None,
            skip_cert_refs: None,
            skip_tags: None,
            sort_field: None,
            sort_order: None,
        }
    }
}

impl GmpRequestCodec for GetScanConfigNvtsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_nvt_query(
            None,
            Some(&self.family),
            Some(&self.config_id),
            None,
            flags_scan_config_list(self),
            self.sort_field.as_deref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_nvts",
            "get_scan_config_nvts",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(nvt_command(
            None,
            Some(&self.family),
            Some(&self.config_id),
            None,
            flags_scan_config_list(self),
            self.sort_field.as_deref(),
            self.sort_order,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetScanConfigNvtsRequest {
    type Response = GetNvtsResponse;
}

/// Request for preference-expanded details of one NVT.
///
/// A config selector changes observed preference values; it is not a membership
/// check. Without a selector, gvmd returns default values.
#[derive(Debug, Clone)]
pub struct GetScanConfigNvtRequest {
    /// Required NVT OID.
    pub nvt_oid: String,
    /// Optional configuration preference context.
    pub config_id: Option<EntityId>,
    /// Optional preference-only configuration context.
    pub preferences_config_id: Option<EntityId>,
    /// Request detailed NVT data. Defaults to `Some(true)`.
    pub details: Option<bool>,
    /// Include preferences. Defaults to `Some(true)`.
    pub preferences: Option<bool>,
    /// Include the preference count. Defaults to `Some(true)`.
    pub preference_count: Option<bool>,
    /// Include configured/default timeout values.
    pub timeout: Option<bool>,
    /// Request the lean detail projection.
    pub lean: Option<bool>,
    /// Omit CERT references from details.
    pub skip_cert_refs: Option<bool>,
    /// Omit tags from details.
    pub skip_tags: Option<bool>,
    /// Optional opaque gvmd NVT sort column.
    pub sort_field: Option<String>,
    /// Optional NVT sort direction.
    pub sort_order: Option<SortOrder>,
}

impl GetScanConfigNvtRequest {
    /// Create preference-expanded NVT detail using default preference values.
    #[must_use]
    pub fn new(nvt_oid: impl Into<String>) -> Self {
        Self {
            nvt_oid: nvt_oid.into(),
            config_id: None,
            preferences_config_id: None,
            details: Some(true),
            preferences: Some(true),
            preference_count: Some(true),
            timeout: None,
            lean: None,
            skip_cert_refs: None,
            skip_tags: None,
            sort_field: None,
            sort_order: None,
        }
    }
}

impl GmpRequestCodec for GetScanConfigNvtRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_nvt_query(
            Some(&self.nvt_oid),
            None,
            self.config_id.as_ref(),
            self.preferences_config_id.as_ref(),
            flags_scan_config_detail(self),
            self.sort_field.as_deref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_nvts",
            "get_scan_config_nvt",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(nvt_command(
            Some(&self.nvt_oid),
            None,
            self.config_id.as_ref(),
            self.preferences_config_id.as_ref(),
            flags_scan_config_detail(self),
            self.sort_field.as_deref(),
            self.sort_order,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetScanConfigNvtRequest {
    type Response = GetNvtsResponse;
}

/// Request for default/unconfigured NVT preference discovery.
#[derive(Debug, Clone, Default)]
pub struct GetNvtPreferencesRequest {
    /// Optional NVT OID restriction.
    pub nvt_oid: Option<String>,
}

impl GmpRequestCodec for GetNvtPreferencesRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_nonempty(self.nvt_oid.as_deref(), "nvt_oid")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_preferences",
            "get_nvt_preferences",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(preferences_command(None, self.nvt_oid.as_deref()).to_bytes())
    }
}

impl GmpRequest for GetNvtPreferencesRequest {
    type Response = GetScanConfigPreferencesResponse;
}

/// Request for the first preference whose stored key suffix equals `preference`.
#[derive(Debug, Clone)]
pub struct GetNvtPreferenceRequest {
    /// Opaque `TYPE:NAME` selector compared after the stored key's second colon.
    pub preference: String,
    /// Optional NVT OID restriction.
    pub nvt_oid: Option<String>,
}

impl GetNvtPreferenceRequest {
    /// Create a preference-detail request without an NVT restriction.
    #[must_use]
    pub fn new(preference: impl Into<String>) -> Self {
        Self {
            preference: preference.into(),
            nvt_oid: None,
        }
    }
}

impl GmpRequestCodec for GetNvtPreferenceRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required(&self.preference, "preference")?;
        validate_optional_nonempty(self.nvt_oid.as_deref(), "nvt_oid")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_preferences",
            "get_nvt_preference",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(preferences_command(Some(&self.preference), self.nvt_oid.as_deref()).to_bytes())
    }
}

impl GmpRequest for GetNvtPreferenceRequest {
    type Response = GetScanConfigPreferencesResponse;
}

/// Request for NVT-family discovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetNvtFamiliesRequest {
    /// Optional family sort direction.
    pub sort_order: Option<SortOrder>,
}

impl GetNvtFamiliesRequest {
    /// Create an NVT-family request with the server's default ordering.
    #[must_use]
    pub const fn new() -> Self {
        Self { sort_order: None }
    }
}

impl GmpRequestCodec for GetNvtFamiliesRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_nvt_families"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("get_nvt_families");
        if let Some(sort_order) = self.sort_order {
            command.set_attribute("sort_order", sort_order.as_gmp_str());
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetNvtFamiliesRequest {
    type Response = GetNvtFamiliesResponse;
}

#[derive(Clone, Copy)]
struct Flags {
    details: Option<bool>,
    preferences: Option<bool>,
    preference_count: Option<bool>,
    timeout: Option<bool>,
    lean: Option<bool>,
    skip_cert_refs: Option<bool>,
    skip_tags: Option<bool>,
}

macro_rules! flags {
    ($request:expr) => {
        Flags {
            details: $request.details,
            preferences: $request.preferences,
            preference_count: $request.preference_count,
            timeout: $request.timeout,
            lean: $request.lean,
            skip_cert_refs: $request.skip_cert_refs,
            skip_tags: $request.skip_tags,
        }
    };
}

fn flags(request: &GetNvtsRequest) -> Flags {
    flags!(request)
}
fn flags_detail(request: &GetNvtRequest) -> Flags {
    flags!(request)
}
fn flags_scan_config_list(request: &GetScanConfigNvtsRequest) -> Flags {
    flags!(request)
}
fn flags_scan_config_detail(request: &GetScanConfigNvtRequest) -> Flags {
    flags!(request)
}

#[allow(clippy::too_many_arguments)]
fn nvt_command(
    nvt_oid: Option<&str>,
    family: Option<&str>,
    config_id: Option<&EntityId>,
    preferences_config_id: Option<&EntityId>,
    flags: Flags,
    sort_field: Option<&str>,
    sort_order: Option<SortOrder>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_nvts");
    if let Some(value) = nvt_oid {
        command.set_attribute("nvt_oid", value);
    }
    if let Some(value) = family {
        command.set_attribute("family", value);
    }
    if let Some(value) = config_id {
        command.set_attribute("config_id", value.as_str());
    }
    if let Some(value) = preferences_config_id {
        command.set_attribute("preferences_config_id", value.as_str());
    }
    set_optional_bool_attr(&mut command, "details", flags.details);
    set_optional_bool_attr(&mut command, "preferences", flags.preferences);
    set_optional_bool_attr(&mut command, "preference_count", flags.preference_count);
    set_optional_bool_attr(&mut command, "timeout", flags.timeout);
    set_optional_bool_attr(&mut command, "lean", flags.lean);
    set_optional_bool_attr(&mut command, "skip_cert_refs", flags.skip_cert_refs);
    set_optional_bool_attr(&mut command, "skip_tags", flags.skip_tags);
    if let Some(value) = sort_field {
        command.set_attribute("sort_field", value);
    }
    if let Some(value) = sort_order {
        command.set_attribute("sort_order", value.as_gmp_str());
    }
    command
}

fn preferences_command(preference: Option<&str>, nvt_oid: Option<&str>) -> XmlCommand {
    let mut command = XmlCommand::new("get_preferences");
    if let Some(value) = preference {
        command.set_attribute("preference", value);
    }
    if let Some(value) = nvt_oid {
        command.set_attribute("nvt_oid", value);
    }
    command
}

fn validate_nvt_query(
    nvt_oid: Option<&str>,
    family: Option<&str>,
    config_id: Option<&EntityId>,
    preferences_config_id: Option<&EntityId>,
    flags: Flags,
    sort_field: Option<&str>,
) -> Result<(), GmpRequestError> {
    validate_optional_nonempty(nvt_oid, "nvt_oid")?;
    validate_optional_nonempty(family, "family")?;
    validate_optional_nonempty(sort_field, "sort_field")?;
    validate_optional_id(config_id, "config_id")?;
    validate_optional_id(preferences_config_id, "preferences_config_id")?;
    if config_id.is_some() && preferences_config_id.is_some() {
        return Err(GmpRequestError::invalid_combination(
            &["config_id", "preferences_config_id"],
            "must not both be supplied",
        ));
    }
    if nvt_oid.is_none() && config_id.is_some() && family.is_none() {
        return Err(GmpRequestError::invalid_combination(
            &["config_id", "family"],
            "a config-scoped list requires a family",
        ));
    }
    require_details(
        flags.details,
        flags.preferences,
        &["details", "preferences"],
    )?;
    require_details(
        flags.details,
        flags.preference_count,
        &["details", "preference_count"],
    )?;
    require_details(flags.details, flags.lean, &["details", "lean"])?;
    require_details(
        flags.details,
        flags.skip_cert_refs,
        &["details", "skip_cert_refs"],
    )?;
    require_details(flags.details, flags.skip_tags, &["details", "skip_tags"])?;
    if flags.timeout == Some(true) {
        if flags.details != Some(true) {
            return Err(GmpRequestError::invalid_combination(
                &["timeout", "details"],
                "timeout=true requires details=true",
            ));
        }
        if config_id.is_none() && preferences_config_id.is_none() {
            return Err(GmpRequestError::invalid_combination(
                &["timeout", "config_id", "preferences_config_id"],
                "timeout=true requires a configuration context",
            ));
        }
    }
    Ok(())
}

fn require_details(
    details: Option<bool>,
    enabled: Option<bool>,
    fields: &'static [&'static str],
) -> Result<(), GmpRequestError> {
    if enabled == Some(true) && details != Some(true) {
        Err(GmpRequestError::invalid_combination(
            fields,
            "requires details=true",
        ))
    } else {
        Ok(())
    }
}

fn validate_required(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.trim().is_empty() {
        return Err(GmpRequestError::invalid_field(field, "must not be empty"));
    }
    if !value.chars().all(is_xml_1_0_character) {
        return Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ));
    }
    Ok(())
}

fn validate_optional_nonempty(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    if let Some(value) = value {
        validate_required(value, field)?;
    }
    Ok(())
}

fn validate_optional_id(
    value: Option<&EntityId>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    if value.is_some_and(|value| EntityId::new(value.as_str()).is_err()) {
        return Err(GmpRequestError::invalid_field(
            field,
            "must be a valid entity identifier",
        ));
    }
    Ok(())
}

const fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(character as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }
    fn xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(request.encode(GmpVersion(22, 4)).expect("valid request")).expect("XML")
    }

    #[test]
    fn defaults_and_metadata_are_exact() {
        assert_eq!(xml(&GetNvtsRequest::default()), "<get_nvts/>");
        assert_eq!(
            xml(&GetNvtRequest::new("1.3.6.1")),
            "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\"/>"
        );
        assert_eq!(
            xml(&GetScanConfigNvtsRequest::new(id("config-1"), "General")),
            "<get_nvts config_id=\"config-1\" family=\"General\"/>"
        );
        assert_eq!(xml(&GetScanConfigNvtRequest::new("1.3.6.1")), "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\" preference_count=\"1\" preferences=\"1\"/>");
        assert_eq!(
            xml(&GetNvtPreferencesRequest::default()),
            "<get_preferences/>"
        );
        assert_eq!(
            xml(&GetNvtPreferenceRequest::new("entry:Example option")),
            "<get_preferences preference=\"entry:Example option\"/>"
        );
        assert_eq!(xml(&GetNvtFamiliesRequest::new()), "<get_nvt_families/>");
        assert_eq!(
            GetNvtRequest::new("1.3.6.1").command(),
            Some(GmpCommand::with_semantic_name("get_nvts", "get_nvt"))
        );
    }

    #[test]
    fn complete_fields_preserve_false_true_sorting_and_escaping() {
        let request = GetNvtsRequest {
            family: Some("General & tests".into()),
            config_id: Some(id("config-1")),
            details: Some(true),
            preferences: Some(true),
            preference_count: Some(false),
            timeout: Some(true),
            lean: Some(false),
            skip_cert_refs: Some(false),
            skip_tags: Some(true),
            sort_field: Some("name".into()),
            sort_order: Some(SortOrder::Descending),
            ..Default::default()
        };
        assert_eq!(xml(&request), "<get_nvts config_id=\"config-1\" details=\"1\" family=\"General &amp; tests\" lean=\"0\" preference_count=\"0\" preferences=\"1\" skip_cert_refs=\"0\" skip_tags=\"1\" sort_field=\"name\" sort_order=\"descending\" timeout=\"1\"/>");
        assert_eq!(
            xml(&GetNvtFamiliesRequest {
                sort_order: Some(SortOrder::Descending)
            }),
            "<get_nvt_families sort_order=\"descending\"/>"
        );
    }

    #[test]
    fn final_mutated_values_and_flag_dependencies_are_validated_by_encode() {
        for field in [
            "preferences",
            "preference_count",
            "lean",
            "skip_cert_refs",
            "skip_tags",
        ] {
            let mut request = GetNvtsRequest::default();
            match field {
                "preferences" => request.preferences = Some(true),
                "preference_count" => request.preference_count = Some(true),
                "lean" => request.lean = Some(true),
                "skip_cert_refs" => request.skip_cert_refs = Some(true),
                _ => request.skip_tags = Some(true),
            }
            assert!(request.encode(GmpVersion(22, 4)).is_err(), "{field}");
        }
        let mut timeout = GetNvtRequest::new("1.3.6.1");
        timeout.timeout = Some(true);
        assert!(timeout.encode(GmpVersion(22, 4)).is_err());
        timeout.preferences_config_id = Some(id("config-1"));
        assert!(timeout.encode(GmpVersion(22, 4)).is_ok());
        timeout.config_id = Some(id("config-2"));
        assert!(timeout.encode(GmpVersion(22, 4)).is_err());
        let invalid_list = GetNvtsRequest {
            config_id: Some(id("config-1")),
            ..Default::default()
        };
        assert!(invalid_list.encode(GmpVersion(22, 4)).is_err());
    }

    #[test]
    fn invalid_selectors_are_static_and_redacted() {
        let request = GetNvtPreferenceRequest::new("secret\u{0}");
        let error = request.validate().expect_err("invalid XML");
        assert!(!error.to_string().contains("secret"));
        assert!(GetNvtPreferencesRequest {
            nvt_oid: Some("  ".into())
        }
        .encode(GmpVersion(22, 4))
        .is_err());
        let mut request = GetScanConfigNvtsRequest::new(id("config-1"), "General");
        request.family.clear();
        assert!(request.encode(GmpVersion(22, 4)).is_err());
    }
}
