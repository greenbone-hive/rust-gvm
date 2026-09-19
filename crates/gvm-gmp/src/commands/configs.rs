// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical generic configuration lifecycle requests.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{
    CreateConfigResponse, DeleteConfigResponse, GetConfigsResponse, ModifyConfigResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Typed configuration usage values accepted by canonical requests.
///
/// gvmd configurations are either scan configurations or policies. Audit is a
/// task usage, while raw custom query strings remain available through the raw
/// protocol APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigUsageType {
    /// Standard scan configuration.
    Scan,
    /// Policy configuration.
    Policy,
}

impl ConfigUsageType {
    /// Return the GMP wire spelling.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Policy => "policy",
        }
    }
}

/// Request for listing generic configurations, optionally selecting one by ID.
#[derive(Debug, Clone, Default)]
pub struct GetConfigsRequest {
    /// Optional configuration identifier selector.
    pub config_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select trashed rather than active configurations.
    pub trash: Option<bool>,
    /// Request detailed output.
    pub details: Option<bool>,
    /// Request family expansion independently of details.
    pub families: Option<bool>,
    /// Request preference expansion independently of details.
    pub preferences: Option<bool>,
    /// Request associated tasks.
    pub tasks: Option<bool>,
    /// Optional exact typed usage filter.
    pub usage_type: Option<ConfigUsageType>,
}

impl GetConfigsRequest {
    /// Create an unfiltered generic-configuration list request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config_id: None,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: None,
            families: None,
            preferences: None,
            tasks: None,
            usage_type: None,
        }
    }
}

impl GmpRequestCodec for GetConfigsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            self.config_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_configs"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_query_command(
            self.config_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.families,
            self.preferences,
            self.tasks,
            self.usage_type,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetConfigsRequest {
    type Response = GetConfigsResponse;
}

/// Request for one generic configuration through the shared collection root.
#[derive(Debug, Clone)]
pub struct GetConfigRequest {
    /// Required configuration identifier selector.
    pub config_id: EntityId,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select a trashed rather than active configuration.
    pub trash: Option<bool>,
    /// Request detailed output. Defaults to `Some(true)`.
    pub details: Option<bool>,
    /// Request family expansion independently of details.
    pub families: Option<bool>,
    /// Request preference expansion independently of details.
    pub preferences: Option<bool>,
    /// Request associated tasks.
    pub tasks: Option<bool>,
    /// Optional exact typed usage filter. ID selection bypasses this list predicate in gvmd.
    pub usage_type: Option<ConfigUsageType>,
}

impl GetConfigRequest {
    /// Create an ID-selected detail request with details enabled.
    #[must_use]
    pub fn new(config_id: EntityId) -> Self {
        Self {
            config_id,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: Some(true),
            families: None,
            preferences: None,
            tasks: None,
            usage_type: None,
        }
    }
}

impl GmpRequestCodec for GetConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            Some(&self.config_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_configs", "get_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_query_command(
            Some(&self.config_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.families,
            self.preferences,
            self.tasks,
            self.usage_type,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetConfigRequest {
    type Response = GetConfigsResponse;
}

/// Request for creating a named configuration by copying an existing configuration.
#[derive(Debug, Clone)]
pub struct CreateConfigRequest {
    /// Required nonempty name for the copy.
    pub name: String,
    /// Required active source configuration identifier.
    pub base_id: EntityId,
    /// Optional comment override. An empty value inherits the source comment in gvmd.
    pub comment: Option<String>,
    /// Optional usage override. Omission inherits the source usage.
    pub usage_type: Option<ConfigUsageType>,
}

impl CreateConfigRequest {
    /// Create a named copy request without comment or usage overrides.
    #[must_use]
    pub fn new(name: impl Into<String>, base_id: EntityId) -> Self {
        Self {
            name: name.into(),
            base_id,
            comment: None,
            usage_type: None,
        }
    }
}

impl GmpRequestCodec for CreateConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_named_copy(
            &self.name,
            &self.base_id,
            self.comment.as_deref(),
            "base_id",
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_copy_command(
            &self.base_id,
            Some(&self.name),
            self.comment.as_deref(),
            self.usage_type,
        )
        .to_bytes())
    }
}

impl GmpRequest for CreateConfigRequest {
    type Response = CreateConfigResponse;
}

/// Request for cloning a configuration through `create_config`.
#[derive(Debug, Clone)]
pub struct CloneConfigRequest {
    /// Required active source configuration identifier.
    pub config_id: EntityId,
    /// Optional name override. Omitted or empty requests generated clone naming.
    pub name: Option<String>,
    /// Optional comment override. Omitted or empty inherits the source comment.
    pub comment: Option<String>,
    /// Optional usage override. Omission inherits the source usage.
    pub usage_type: Option<ConfigUsageType>,
}

impl CloneConfigRequest {
    /// Create a clone request that inherits source metadata and usage.
    #[must_use]
    pub fn new(config_id: EntityId) -> Self {
        Self {
            config_id,
            name: None,
            comment: None,
            usage_type: None,
        }
    }
}

impl GmpRequestCodec for CloneConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.config_id, "config_id")?;
        validate_optional_xml_text(self.name.as_deref(), "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_config",
            "clone_config",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_copy_command(
            &self.config_id,
            self.name.as_deref(),
            self.comment.as_deref(),
            self.usage_type,
        )
        .to_bytes())
    }
}

impl GmpRequest for CloneConfigRequest {
    type Response = CreateConfigResponse;
}

/// Request for modifying configuration metadata.
#[derive(Debug, Clone)]
pub struct ModifyConfigRequest {
    /// Required configuration identifier.
    pub config_id: EntityId,
    /// Optional name update. An explicit empty value is a server-side no-op.
    pub name: Option<String>,
    /// Optional comment update. An explicit empty value is a server-side no-op.
    pub comment: Option<String>,
}

impl ModifyConfigRequest {
    /// Create a metadata no-op request for a configuration.
    #[must_use]
    pub fn new(config_id: EntityId) -> Self {
        Self {
            config_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for ModifyConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_metadata(
            &self.config_id,
            self.name.as_deref(),
            self.comment.as_deref(),
            "config_id",
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_modify_command(
            &self.config_id,
            self.name.as_deref(),
            self.comment.as_deref(),
        )
        .to_bytes())
    }
}

impl GmpRequest for ModifyConfigRequest {
    type Response = ModifyConfigResponse;
}

/// Request for trashing or permanently deleting a configuration.
#[derive(Debug, Clone)]
pub struct DeleteConfigRequest {
    /// Required configuration identifier.
    pub config_id: EntityId,
    /// Optional permanent-deletion flag. Omission uses trash semantics.
    pub ultimate: Option<bool>,
}

impl DeleteConfigRequest {
    /// Create a trash-by-default deletion request.
    #[must_use]
    pub fn new(config_id: EntityId) -> Self {
        Self {
            config_id,
            ultimate: None,
        }
    }
}

impl GmpRequestCodec for DeleteConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.config_id, "config_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_delete_command(&self.config_id, self.ultimate).to_bytes())
    }
}

impl GmpRequest for DeleteConfigRequest {
    type Response = DeleteConfigResponse;
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn config_query_command(
    config_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    trash: Option<bool>,
    details: Option<bool>,
    families: Option<bool>,
    preferences: Option<bool>,
    tasks: Option<bool>,
    usage_type: Option<ConfigUsageType>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_configs");
    if let Some(config_id) = config_id {
        command.set_attribute("config_id", config_id.as_str());
    }
    add_filter_attrs(&mut command, filter_string, filter_id);
    set_optional_bool_attr(&mut command, "trash", trash);
    set_optional_bool_attr(&mut command, "details", details);
    set_optional_bool_attr(&mut command, "families", families);
    set_optional_bool_attr(&mut command, "preferences", preferences);
    set_optional_bool_attr(&mut command, "tasks", tasks);
    if let Some(usage_type) = usage_type {
        command.set_attribute("usage_type", usage_type.as_gmp_str());
    }
    command
}

pub(crate) fn config_copy_command(
    base_id: &EntityId,
    name: Option<&str>,
    comment: Option<&str>,
    usage_type: Option<ConfigUsageType>,
) -> XmlCommand {
    let mut command = XmlCommand::new("create_config");
    command.add_element_with_text("copy", base_id.as_str());
    if let Some(name) = name {
        command.add_element_with_text("name", name);
    }
    if let Some(comment) = comment {
        command.add_element_with_text("comment", comment);
    }
    if let Some(usage_type) = usage_type {
        command.add_element_with_text("usage_type", usage_type.as_gmp_str());
    }
    command
}

pub(crate) fn config_modify_command(
    config_id: &EntityId,
    name: Option<&str>,
    comment: Option<&str>,
) -> XmlCommand {
    let mut command = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    if let Some(name) = name {
        command.add_element_with_text("name", name);
    }
    if let Some(comment) = comment {
        command.add_element_with_text("comment", comment);
    }
    command
}

pub(crate) fn config_delete_command(config_id: &EntityId, ultimate: Option<bool>) -> XmlCommand {
    let mut command = XmlCommand::new("delete_config").attribute("config_id", config_id.as_str());
    set_optional_bool_attr(&mut command, "ultimate", ultimate);
    command
}

pub(crate) fn validate_query(
    config_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> Result<(), GmpRequestError> {
    validate_optional_id(config_id, "config_id")?;
    validate_optional_id(filter_id, "filter_id")?;
    validate_optional_xml_text(filter_string, "filter_string")
}

pub(crate) fn validate_named_copy(
    name: &str,
    base_id: &EntityId,
    comment: Option<&str>,
    id_field: &'static str,
) -> Result<(), GmpRequestError> {
    if name.is_empty() {
        return Err(GmpRequestError::invalid_field("name", "must not be empty"));
    }
    validate_xml_text(name, "name")?;
    validate_id(base_id, id_field)?;
    validate_optional_xml_text(comment, "comment")
}

pub(crate) fn validate_metadata(
    config_id: &EntityId,
    name: Option<&str>,
    comment: Option<&str>,
    id_field: &'static str,
) -> Result<(), GmpRequestError> {
    validate_id(config_id, id_field)?;
    validate_optional_xml_text(name, "name")?;
    validate_optional_xml_text(comment, "comment")
}

pub(crate) fn validate_optional_xml_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    value.map_or(Ok(()), |value| validate_xml_text(value, field))
}

pub(crate) fn validate_xml_text(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.chars().all(is_xml_1_0_character) {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ))
    }
}

pub(crate) fn validate_optional_id(
    id: Option<&EntityId>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    id.map_or(Ok(()), |id| validate_id(id, field))
}

pub(crate) fn validate_id(id: &EntityId, field: &'static str) -> Result<(), GmpRequestError> {
    if EntityId::new(id.as_str()).is_ok() {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must be a valid entity identifier",
        ))
    }
}

pub(crate) const fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(character as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}
