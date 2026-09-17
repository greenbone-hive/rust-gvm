// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for filter operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, bool_str, set_optional_bool_attr};
use crate::enums::FilterType;
use crate::responses::{
    CreateFilterResponse, DeleteFilterResponse, GetFiltersResponse, ModifyFilterResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Semantic request for listing filters.
#[derive(Debug, Clone, Default)]
pub struct GetFiltersRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to include alerts that use each filter.
    pub alerts: Option<bool>,
}

impl GmpRequestCodec for GetFiltersRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_filters"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_filters_command(self).to_bytes())
    }
}

impl GmpRequest for GetFiltersRequest {
    type Response = GetFiltersResponse;
}

/// Semantic request for one detailed filter.
#[derive(Debug, Clone)]
pub struct GetFilterRequest {
    /// Filter identifier to retrieve.
    pub filter_id: EntityId,
    /// Whether to include alerts that use the filter.
    pub alerts: Option<bool>,
}

impl GetFilterRequest {
    /// Create a single-filter request.
    #[must_use]
    pub fn new(filter_id: EntityId) -> Self {
        Self {
            filter_id,
            alerts: None,
        }
    }
}

impl GmpRequestCodec for GetFilterRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_filters", "get_filter"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_filter_command(self).to_bytes())
    }
}

impl GmpRequest for GetFilterRequest {
    type Response = GetFiltersResponse;
}

/// Semantic request for creating a filter.
#[derive(Debug, Clone)]
pub struct CreateFilterRequest {
    /// Filter name.
    pub name: String,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional filter term expression.
    pub term: Option<String>,
    /// Optional resource type the filter applies to.
    pub filter_type: Option<FilterType>,
}

impl CreateFilterRequest {
    /// Create a filter-creation request.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            term: None,
            filter_type: None,
        }
    }
}

impl GmpRequestCodec for CreateFilterRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_filter"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_filter_command(self).to_bytes())
    }
}

impl GmpRequest for CreateFilterRequest {
    type Response = CreateFilterResponse;
}

/// Semantic request for cloning a filter through `create_filter`.
#[derive(Debug, Clone)]
pub struct CloneFilterRequest {
    /// Existing filter identifier to copy.
    pub filter_id: EntityId,
    /// Optional name override. Omission copies the existing name.
    pub name: Option<String>,
    /// Optional comment override. Omission copies the existing comment.
    pub comment: Option<String>,
}

impl CloneFilterRequest {
    /// Create a filter-clone request.
    #[must_use]
    pub fn new(filter_id: EntityId) -> Self {
        Self {
            filter_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneFilterRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_filter",
            "clone_filter",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_filter_command(self).to_bytes())
    }
}

impl GmpRequest for CloneFilterRequest {
    type Response = CreateFilterResponse;
}

/// Semantic request for modifying a filter.
#[derive(Debug, Clone)]
pub struct ModifyFilterRequest {
    /// Filter identifier to modify.
    pub filter_id: EntityId,
    /// Optional replacement name.
    pub name: Option<String>,
    /// Optional replacement comment.
    pub comment: Option<String>,
    /// Optional replacement filter term.
    pub term: Option<String>,
    /// Optional replacement resource type.
    pub filter_type: Option<FilterType>,
}

impl ModifyFilterRequest {
    /// Create a filter-modification request.
    #[must_use]
    pub fn new(filter_id: EntityId) -> Self {
        Self {
            filter_id,
            name: None,
            comment: None,
            term: None,
            filter_type: None,
        }
    }
}

impl GmpRequestCodec for ModifyFilterRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_filter"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_filter_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyFilterRequest {
    type Response = ModifyFilterResponse;
}

/// Semantic request for deleting a filter.
#[derive(Debug, Clone)]
pub struct DeleteFilterRequest {
    /// Filter identifier to delete.
    pub filter_id: EntityId,
    /// Whether to delete permanently instead of moving the filter to trash.
    pub ultimate: bool,
}

impl DeleteFilterRequest {
    /// Create a filter-deletion request.
    #[must_use]
    pub fn new(filter_id: EntityId, ultimate: bool) -> Self {
        Self {
            filter_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteFilterRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_filter"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_filter_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteFilterRequest {
    type Response = DeleteFilterResponse;
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_optional_name(name: &Option<String>) -> Result<(), GmpRequestError> {
    if name.as_ref().is_some_and(String::is_empty) {
        Err(GmpRequestError::invalid_field("name", "must not be empty"))
    } else {
        Ok(())
    }
}

fn add_optional_text_element(cmd: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        cmd.add_element_with_text(name, value);
    }
}

fn get_filters_command(request: &GetFiltersRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_filters");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    set_optional_bool_attr(&mut cmd, "alerts", request.alerts);
    cmd
}

fn get_filter_command(request: &GetFilterRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_filters")
        .attribute("filter_id", request.filter_id.as_str())
        .attribute("details", "1");
    set_optional_bool_attr(&mut cmd, "alerts", request.alerts);
    cmd
}

fn create_filter_command(request: &CreateFilterRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_filter");
    cmd.add_element_with_text("name", &request.name);
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_optional_text_element(&mut cmd, "term", request.term.as_deref());
    if let Some(filter_type) = request.filter_type {
        cmd.add_element_with_text("type", filter_type.as_gmp_str());
    }
    cmd
}

fn clone_filter_command(request: &CloneFilterRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_filter");
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element_with_text("copy", request.filter_id.as_str());
    cmd
}

fn modify_filter_command(request: &ModifyFilterRequest) -> XmlCommand {
    let mut cmd =
        XmlCommand::new("modify_filter").attribute("filter_id", request.filter_id.as_str());
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_optional_text_element(&mut cmd, "term", request.term.as_deref());
    if let Some(filter_type) = request.filter_type {
        cmd.add_element_with_text("type", filter_type.as_gmp_str());
    }
    cmd
}

fn delete_filter_command(request: &DeleteFilterRequest) -> XmlCommand {
    XmlCommand::new("delete_filter")
        .attribute("filter_id", request.filter_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GmpResponse;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn request_xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(
            request
                .encode(GmpVersion(22, 8))
                .expect("valid filter request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetFiltersRequest {
                filter_string: Some("name=web".into()),
                filter_id: Some(id("saved-filter")),
                trash: Some(true),
                details: Some(false),
                alerts: Some(true),
            }),
            "<get_filters alerts=\"1\" details=\"0\" filt_id=\"saved-filter\" filter=\"name=web\" trash=\"1\"/>"
        );

        let mut get = GetFilterRequest::new(id("filter-1"));
        get.alerts = Some(true);
        assert_eq!(
            request_xml(&get),
            "<get_filters alerts=\"1\" details=\"1\" filter_id=\"filter-1\"/>"
        );

        let mut create = CreateFilterRequest::new("web");
        create.comment = Some("web tasks".into());
        create.term = Some("rows=10".into());
        create.filter_type = Some(FilterType::Task);
        assert_eq!(
            request_xml(&create),
            "<create_filter><name>web</name><comment>web tasks</comment><term>rows=10</term><type>task</type></create_filter>"
        );

        let mut clone = CloneFilterRequest::new(id("filter-1"));
        clone.name = Some("web copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            request_xml(&clone),
            "<create_filter><name>web copy</name><comment></comment><copy>filter-1</copy></create_filter>"
        );

        let mut modify = ModifyFilterRequest::new(id("filter-1"));
        modify.name = Some("renamed".into());
        modify.comment = Some(String::new());
        modify.term = Some("rows=-1".into());
        modify.filter_type = Some(FilterType::Result);
        assert_eq!(
            request_xml(&modify),
            "<modify_filter filter_id=\"filter-1\"><name>renamed</name><comment></comment><term>rows=-1</term><type>result</type></modify_filter>"
        );

        assert_eq!(
            request_xml(&DeleteFilterRequest::new(id("filter-1"), true)),
            "<delete_filter filter_id=\"filter-1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn requests_keep_static_response_associations() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: GmpResponse,
        {
        }

        associated::<_, GetFiltersResponse>(&GetFiltersRequest::default());
        associated::<_, GetFiltersResponse>(&GetFilterRequest::new(id("filter-1")));
        associated::<_, CreateFilterResponse>(&CreateFilterRequest::new("filter"));
        associated::<_, CreateFilterResponse>(&CloneFilterRequest::new(id("filter-1")));
        associated::<_, ModifyFilterResponse>(&ModifyFilterRequest::new(id("filter-1")));
        associated::<_, DeleteFilterResponse>(&DeleteFilterRequest::new(id("filter-1"), false));
    }

    #[test]
    fn empty_names_fail_final_value_validation() {
        let mut create = CreateFilterRequest::new("filter");
        create.name.clear();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut clone = CloneFilterRequest::new(id("filter-1"));
        clone.name = Some(String::new());
        assert!(matches!(
            clone.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut modify = ModifyFilterRequest::new(id("filter-1"));
        modify.name = Some(String::new());
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));
    }

    #[test]
    fn aliases_have_distinct_semantic_names() {
        assert_eq!(
            GetFilterRequest::new(id("filter-1"))
                .command()
                .expect("semantic command")
                .semantic_name(),
            Some("get_filter")
        );
        assert_eq!(
            CloneFilterRequest::new(id("filter-1"))
                .command()
                .expect("semantic command")
                .semantic_name(),
            Some("clone_filter")
        );
    }
}
