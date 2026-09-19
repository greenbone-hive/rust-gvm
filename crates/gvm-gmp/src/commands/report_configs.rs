// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical report-configuration lifecycle requests.

use std::fmt;

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{
    CreateReportConfigResponse, DeleteReportConfigResponse, GetReportConfigsResponse,
    ModifyReportConfigResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// One report-configuration parameter update.
#[derive(Clone, PartialEq, Eq)]
pub struct ReportConfigParam {
    /// Parameter name. gvmd strips surrounding ASCII whitespace when applying it.
    pub name: String,
    /// Literal assignment or a request to use the report-format default.
    pub value: ReportConfigParamValue,
}

impl fmt::Debug for ReportConfigParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReportConfigParam")
            .field("name", &"<redacted>")
            .field("value", &self.value)
            .finish()
    }
}

/// Value carried by a report-configuration parameter update.
#[derive(Clone, PartialEq, Eq)]
pub enum ReportConfigParamValue {
    /// Set an explicit value. An empty string remains an explicit empty override.
    Value(String),
    /// Remove the stored override and use the report-format value/default.
    UseDefault,
}

impl fmt::Debug for ReportConfigParamValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(_) => f.write_str("Value(<redacted>)"),
            Self::UseDefault => f.write_str("UseDefault"),
        }
    }
}

/// Request for listing report configurations, optionally selecting one by ID.
#[derive(Debug, Clone, Default)]
pub struct GetReportConfigsRequest {
    /// Optional report-configuration identifier selector.
    pub report_config_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select trashed rather than active report configurations.
    pub trash: Option<bool>,
    /// Request common detailed response expansion.
    pub details: Option<bool>,
    /// Ignore pagination terms from the selected filter.
    pub ignore_pagination: Option<bool>,
}

impl GetReportConfigsRequest {
    /// Create an unfiltered report-configuration list request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            report_config_id: None,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: None,
            ignore_pagination: None,
        }
    }
}

impl GmpRequestCodec for GetReportConfigsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            self.report_config_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_report_configs"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_report_configs_command(
            self.report_config_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.ignore_pagination,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetReportConfigsRequest {
    type Response = GetReportConfigsResponse;
}

/// Request for retrieving one report configuration through the shared list root.
#[derive(Debug, Clone)]
pub struct GetReportConfigRequest {
    /// Required report-configuration identifier selector.
    pub report_config_id: EntityId,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select a trashed rather than active report configuration.
    pub trash: Option<bool>,
    /// Request common detailed response expansion.
    pub details: Option<bool>,
    /// Ignore pagination terms from the selected filter.
    pub ignore_pagination: Option<bool>,
}

impl GetReportConfigRequest {
    /// Create an ID-only detail request with no implicit query controls.
    #[must_use]
    pub fn new(report_config_id: EntityId) -> Self {
        Self {
            report_config_id,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: None,
            ignore_pagination: None,
        }
    }
}

impl GmpRequestCodec for GetReportConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            Some(&self.report_config_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_report_configs",
            "get_report_config",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_report_configs_command(
            Some(&self.report_config_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.ignore_pagination,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetReportConfigRequest {
    type Response = GetReportConfigsResponse;
}

/// Request for directly creating a report configuration.
#[derive(Debug, Clone)]
pub struct CreateReportConfigRequest {
    /// Required configuration name.
    pub name: String,
    /// Required configurable report-format reference.
    pub report_format_id: EntityId,
    /// Optional comment. An empty string is emitted explicitly.
    pub comment: Option<String>,
    /// Ordered parameter assignments and default requests.
    pub params: Vec<ReportConfigParam>,
}

impl CreateReportConfigRequest {
    /// Create a direct report-configuration request.
    #[must_use]
    pub fn new(name: impl Into<String>, report_format_id: EntityId) -> Self {
        Self {
            name: name.into(),
            report_format_id,
            comment: None,
            params: Vec::new(),
        }
    }
}

impl GmpRequestCodec for CreateReportConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_non_empty_xml_text(&self.name, "name")?;
        validate_id(&self.report_format_id, "report_format_id")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")?;
        validate_params(&self.params)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_report_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_report_config_command(self).to_bytes())
    }
}

impl GmpRequest for CreateReportConfigRequest {
    type Response = CreateReportConfigResponse;
}

/// Request for cloning a report configuration through `create_report_config`.
#[derive(Debug, Clone)]
pub struct CloneReportConfigRequest {
    /// Existing report configuration to copy.
    pub report_config_id: EntityId,
    /// Optional exact name override. An empty value requests automatic naming.
    pub name: Option<String>,
}

impl CloneReportConfigRequest {
    /// Create a report-configuration clone request.
    #[must_use]
    pub fn new(report_config_id: EntityId) -> Self {
        Self {
            report_config_id,
            name: None,
        }
    }
}

impl GmpRequestCodec for CloneReportConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.report_config_id, "report_config_id")?;
        validate_optional_xml_text(self.name.as_deref(), "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_report_config",
            "clone_report_config",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(clone_report_config_command(self).to_bytes())
    }
}

impl GmpRequest for CloneReportConfigRequest {
    type Response = CreateReportConfigResponse;
}

/// Request for modifying a report configuration.
#[derive(Debug, Clone)]
pub struct ModifyReportConfigRequest {
    /// Report configuration to modify.
    pub report_config_id: EntityId,
    /// Optional exact replacement name. An explicit empty value is invalid.
    pub name: Option<String>,
    /// Optional replacement comment. An empty string clears the comment.
    pub comment: Option<String>,
    /// Ordered per-name parameter assignments and resets.
    pub params: Vec<ReportConfigParam>,
}

impl ModifyReportConfigRequest {
    /// Create a no-change report-configuration modification request.
    #[must_use]
    pub fn new(report_config_id: EntityId) -> Self {
        Self {
            report_config_id,
            name: None,
            comment: None,
            params: Vec::new(),
        }
    }
}

impl GmpRequestCodec for ModifyReportConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.report_config_id, "report_config_id")?;
        if self.name.as_deref() == Some("") {
            return Err(GmpRequestError::invalid_field("name", "must not be empty"));
        }
        validate_optional_xml_text(self.name.as_deref(), "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")?;
        validate_params(&self.params)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_report_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_report_config_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyReportConfigRequest {
    type Response = ModifyReportConfigResponse;
}

/// Request for deleting a report configuration.
#[derive(Debug, Clone)]
pub struct DeleteReportConfigRequest {
    /// Report configuration to delete.
    pub report_config_id: EntityId,
    /// Whether to remove it permanently instead of moving it to trash.
    pub ultimate: Option<bool>,
}

impl DeleteReportConfigRequest {
    /// Create a non-ultimate report-configuration deletion request.
    #[must_use]
    pub fn new(report_config_id: EntityId) -> Self {
        Self {
            report_config_id,
            ultimate: None,
        }
    }
}

impl GmpRequestCodec for DeleteReportConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.report_config_id, "report_config_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_report_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("delete_report_config");
        command.set_attribute("report_config_id", self.report_config_id.as_str());
        set_optional_bool_attr(&mut command, "ultimate", self.ultimate);
        Ok(command.to_bytes())
    }
}

impl GmpRequest for DeleteReportConfigRequest {
    type Response = DeleteReportConfigResponse;
}

fn get_report_configs_command(
    report_config_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    trash: Option<bool>,
    details: Option<bool>,
    ignore_pagination: Option<bool>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_report_configs");
    if let Some(report_config_id) = report_config_id {
        command.set_attribute("report_config_id", report_config_id.as_str());
    }
    add_filter_attrs(&mut command, filter_string, filter_id);
    set_optional_bool_attr(&mut command, "trash", trash);
    set_optional_bool_attr(&mut command, "details", details);
    set_optional_bool_attr(&mut command, "ignore_pagination", ignore_pagination);
    command
}

fn create_report_config_command(request: &CreateReportConfigRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_report_config");
    command.add_element_with_text("name", &request.name);
    command
        .add_element("report_format")
        .set_attribute("id", request.report_format_id.as_str());
    if let Some(comment) = &request.comment {
        command.add_element_with_text("comment", comment);
    }
    add_params(&mut command, &request.params);
    command
}

fn clone_report_config_command(request: &CloneReportConfigRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_report_config");
    command.add_element_with_text("copy", request.report_config_id.as_str());
    if let Some(name) = &request.name {
        command.add_element_with_text("name", name);
    }
    command
}

fn modify_report_config_command(request: &ModifyReportConfigRequest) -> XmlCommand {
    let mut command = XmlCommand::new("modify_report_config");
    command.set_attribute("report_config_id", request.report_config_id.as_str());
    if let Some(name) = &request.name {
        command.add_element_with_text("name", name);
    }
    if let Some(comment) = &request.comment {
        command.add_element_with_text("comment", comment);
    }
    add_params(&mut command, &request.params);
    command
}

fn add_params(command: &mut XmlCommand, params: &[ReportConfigParam]) {
    for param in params {
        let element = command.add_element("param");
        element.add_child_with_text("name", &param.name);
        match &param.value {
            ReportConfigParamValue::Value(value) => {
                element.add_child_with_text("value", value);
            }
            ReportConfigParamValue::UseDefault => {
                element
                    .add_child("value")
                    .set_text("")
                    .set_attribute("use_default", "1");
            }
        }
    }
}

fn validate_query(
    report_config_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> Result<(), GmpRequestError> {
    validate_optional_id(report_config_id, "report_config_id")?;
    validate_optional_id(filter_id, "filter_id")?;
    validate_optional_xml_text(filter_string, "filter_string")
}

fn validate_params(params: &[ReportConfigParam]) -> Result<(), GmpRequestError> {
    for param in params {
        if param
            .name
            .trim_matches(|character: char| character.is_ascii_whitespace())
            .is_empty()
        {
            return Err(GmpRequestError::invalid_field(
                "params.name",
                "must not be empty after stripping surrounding ASCII whitespace",
            ));
        }
        validate_xml_text(&param.name, "params.name")?;
        if let ReportConfigParamValue::Value(value) = &param.value {
            validate_xml_text(value, "params.value")?;
        }
    }
    Ok(())
}

fn validate_non_empty_xml_text(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        return Err(GmpRequestError::invalid_field(field, "must not be empty"));
    }
    validate_xml_text(value, field)
}

fn validate_optional_xml_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    value.map_or(Ok(()), |value| validate_xml_text(value, field))
}

fn validate_xml_text(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.chars().all(is_xml_1_0_character) {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ))
    }
}

fn validate_optional_id(id: Option<&EntityId>, field: &'static str) -> Result<(), GmpRequestError> {
    id.map_or(Ok(()), |id| validate_id(id, field))
}

fn validate_id(id: &EntityId, field: &'static str) -> Result<(), GmpRequestError> {
    if EntityId::new(id.as_str()).is_ok() {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must be a valid entity identifier",
        ))
    }
}

const fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(character as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}
