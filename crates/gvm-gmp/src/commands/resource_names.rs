// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical resource-name list and detail requests.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::GetResourceNamesResponse;
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

pub use crate::enums::ResourceType;

/// Canonical request for listing names and IDs for one resource type.
#[derive(Debug, Clone)]
pub struct GetResourceNamesRequest {
    /// Required resource type.
    pub resource_type: ResourceType,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier accepted by the gvmd common-get parser.
    pub filter_id: Option<EntityId>,
    /// Optional filter column whose saved-filter term gvmd replaces.
    pub filter_replace: Option<String>,
    /// Whether to select trashcan resources where the type supports them.
    pub trash: Option<bool>,
    /// Whether to request detailed common-get selection.
    pub details: Option<bool>,
    /// Whether filter pagination controls should be ignored.
    pub ignore_pagination: Option<bool>,
}

impl GetResourceNamesRequest {
    /// Create a resource-name list request for the selected type.
    #[must_use]
    pub const fn new(resource_type: ResourceType) -> Self {
        Self {
            resource_type,
            filter_string: None,
            filter_id: None,
            filter_replace: None,
            trash: None,
            details: None,
            ignore_pagination: None,
        }
    }
}

impl GmpRequestCodec for GetResourceNamesRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if let Some(filter) = self.filter_string.as_deref() {
            validate_xml(filter, "filter_string")?;
        }
        if let Some(filter_replace) = self.filter_replace.as_deref() {
            if filter_replace.trim().is_empty() {
                return Err(GmpRequestError::invalid_field(
                    "filter_replace",
                    "must not be empty",
                ));
            }
            validate_xml(filter_replace, "filter_replace")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_resource_names"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("get_resource_names");
        command.set_attribute("type", self.resource_type.as_gmp_str());
        add_filter_attrs(
            &mut command,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        );
        if let Some(filter_replace) = self.filter_replace.as_deref() {
            command.set_attribute("filter_replace", filter_replace);
        }
        set_optional_bool_attr(&mut command, "trash", self.trash);
        set_optional_bool_attr(&mut command, "details", self.details);
        set_optional_bool_attr(&mut command, "ignore_pagination", self.ignore_pagination);
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetResourceNamesRequest {
    type Response = GetResourceNamesResponse;
}

/// Canonical semantic detail request for one resource name.
#[derive(Debug, Clone)]
pub struct GetResourceNameRequest {
    /// Required resource identifier.
    pub resource_id: EntityId,
    /// Required resource type.
    pub resource_type: ResourceType,
}

impl GetResourceNameRequest {
    /// Create a single-resource name request.
    #[must_use]
    pub const fn new(resource_id: EntityId, resource_type: ResourceType) -> Self {
        Self {
            resource_id,
            resource_type,
        }
    }
}

impl GmpRequestCodec for GetResourceNameRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_resource_names",
            "get_resource_name",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        let mut command = XmlCommand::new("get_resource_names");
        command.set_attribute("resource_id", self.resource_id.as_str());
        command.set_attribute("type", self.resource_type.as_gmp_str());
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetResourceNameRequest {
    type Response = GetResourceNamesResponse;
}

fn validate_xml(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
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
    fn list_owns_filters_and_common_query_controls() {
        let mut request = GetResourceNamesRequest::new(ResourceType::Target);
        request.filter_string = Some("first=2 rows=5".into());
        request.filter_id = Some(id("filter-1"));
        request.filter_replace = Some("owner".into());
        request.details = Some(true);
        request.ignore_pagination = Some(false);
        request.trash = Some(false);
        assert_eq!(
            request.encode(GmpVersion(22, 8)).expect("valid request"),
            b"<get_resource_names details=\"1\" filt_id=\"filter-1\" filter=\"first=2 rows=5\" filter_replace=\"owner\" ignore_pagination=\"0\" trash=\"0\" type=\"TARGET\"/>"
        );
    }

    #[test]
    fn detail_has_a_distinct_semantic_identity() {
        let request = GetResourceNameRequest::new(id("task-1"), ResourceType::Task);
        assert_eq!(
            request.encode(GmpVersion(22, 4)).expect("valid request"),
            b"<get_resource_names resource_id=\"task-1\" type=\"TASK\"/>"
        );
        assert_eq!(
            request.command().and_then(GmpCommand::semantic_name),
            Some("get_resource_name")
        );
    }
}
