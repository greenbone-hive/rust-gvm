// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for tag operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, bool_str, set_optional_bool_attr};
use crate::enums::EntityType;
use crate::responses::{CreateTagResponse, DeleteTagResponse, GetTagsResponse, ModifyTagResponse};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Resources selected when a tag is created or modified.
#[derive(Debug, Clone)]
pub struct TagResources {
    /// Resource type to which the tag applies.
    pub resource_type: EntityType,
    /// Individual resource identifiers to select.
    pub resource_ids: Vec<EntityId>,
    /// Optional gvmd filter used to select resources of `resource_type`.
    pub filter: Option<String>,
}

impl TagResources {
    /// Create an empty resource selection for the given type.
    #[must_use]
    pub fn new(resource_type: EntityType) -> Self {
        Self {
            resource_type,
            resource_ids: Vec::new(),
            filter: None,
        }
    }

    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.resource_type == EntityType::Tag {
            Err(GmpRequestError::invalid_field(
                "resources.resource_type",
                "tag resources cannot themselves be tags",
            ))
        } else {
            Ok(())
        }
    }

    fn wire_type(&self) -> EntityType {
        match self.resource_type {
            EntityType::Policy => EntityType::Config,
            other => other,
        }
    }
}

/// How a modify request changes the resources attached to a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagResourceAction {
    /// Add the selected resources to the current selection.
    Add,
    /// Replace the current selection with the selected resources.
    Set,
    /// Remove the selected resources from the current selection.
    Remove,
}

impl TagResourceAction {
    const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Set => "set",
            Self::Remove => "remove",
        }
    }
}

/// Resource change carried by a tag modification.
#[derive(Debug, Clone)]
pub struct TagResourceUpdate {
    /// Resources to add, replace, or remove.
    pub resources: TagResources,
    /// Optional edit action. Omission has gvmd's replacement semantics.
    pub action: Option<TagResourceAction>,
}

impl TagResourceUpdate {
    /// Create a resource update using gvmd's default replacement semantics.
    #[must_use]
    pub fn new(resources: TagResources) -> Self {
        Self {
            resources,
            action: None,
        }
    }
}

/// Semantic request for listing tags.
#[derive(Debug, Clone, Default)]
pub struct GetTagsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to return names only.
    pub names_only: Option<bool>,
}

impl GmpRequestCodec for GetTagsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_tags"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_tags_command(self).to_bytes())
    }
}

impl GmpRequest for GetTagsRequest {
    type Response = GetTagsResponse;
}

/// Semantic request for one detailed tag.
#[derive(Debug, Clone)]
pub struct GetTagRequest {
    /// Tag identifier to retrieve.
    pub tag_id: EntityId,
}

impl GetTagRequest {
    /// Create a single-tag request.
    #[must_use]
    pub fn new(tag_id: EntityId) -> Self {
        Self { tag_id }
    }
}

impl GmpRequestCodec for GetTagRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_tags", "get_tag"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_tag_command(self).to_bytes())
    }
}

impl GmpRequest for GetTagRequest {
    type Response = GetTagsResponse;
}

/// Semantic request for creating a tag.
#[derive(Debug, Clone)]
pub struct CreateTagRequest {
    /// Tag name.
    pub name: String,
    /// Resources to which the tag applies.
    pub resources: TagResources,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional free-form tag value.
    pub value: Option<String>,
    /// Whether the tag should be active.
    pub active: Option<bool>,
}

impl CreateTagRequest {
    /// Create a tag-creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, resources: TagResources) -> Self {
        Self {
            name: name.into(),
            resources,
            comment: None,
            value: None,
            active: None,
        }
    }
}

impl GmpRequestCodec for CreateTagRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        self.resources.validate()
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_tag"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_tag_command(self).to_bytes())
    }
}

impl GmpRequest for CreateTagRequest {
    type Response = CreateTagResponse;
}

/// Semantic request for cloning a tag through `create_tag`.
#[derive(Debug, Clone)]
pub struct CloneTagRequest {
    /// Existing tag identifier to copy.
    pub tag_id: EntityId,
    /// Optional name override. Omission copies the existing name.
    pub name: Option<String>,
    /// Optional comment override. Omission copies the existing comment.
    pub comment: Option<String>,
}

impl CloneTagRequest {
    /// Create a tag-clone request.
    #[must_use]
    pub fn new(tag_id: EntityId) -> Self {
        Self {
            tag_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneTagRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("create_tag", "clone_tag"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_tag_command(self).to_bytes())
    }
}

impl GmpRequest for CloneTagRequest {
    type Response = CreateTagResponse;
}

/// Semantic request for modifying a tag.
#[derive(Debug, Clone)]
pub struct ModifyTagRequest {
    /// Tag identifier to modify.
    pub tag_id: EntityId,
    /// Optional replacement name.
    pub name: Option<String>,
    /// Optional replacement comment. An empty string clears the comment.
    pub comment: Option<String>,
    /// Optional replacement value. An empty string clears the value.
    pub value: Option<String>,
    /// Optional resource selection update.
    pub resource_update: Option<TagResourceUpdate>,
    /// Whether the tag should be active.
    pub active: Option<bool>,
}

impl ModifyTagRequest {
    /// Create a tag-modification request.
    #[must_use]
    pub fn new(tag_id: EntityId) -> Self {
        Self {
            tag_id,
            name: None,
            comment: None,
            value: None,
            resource_update: None,
            active: None,
        }
    }
}

impl GmpRequestCodec for ModifyTagRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_name(&self.name)?;
        if let Some(update) = &self.resource_update {
            update.resources.validate()?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_tag"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_tag_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyTagRequest {
    type Response = ModifyTagResponse;
}

/// Semantic request for deleting a tag.
#[derive(Debug, Clone)]
pub struct DeleteTagRequest {
    /// Tag identifier to delete.
    pub tag_id: EntityId,
    /// Whether to delete permanently instead of moving the tag to trash.
    pub ultimate: bool,
}

impl DeleteTagRequest {
    /// Create a tag-deletion request.
    #[must_use]
    pub fn new(tag_id: EntityId, ultimate: bool) -> Self {
        Self { tag_id, ultimate }
    }
}

impl GmpRequestCodec for DeleteTagRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_tag"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_tag_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteTagRequest {
    type Response = DeleteTagResponse;
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

fn add_resources(
    cmd: &mut XmlCommand,
    resources: &TagResources,
    action: Option<TagResourceAction>,
) {
    let resources_element = cmd.add_element("resources");
    if let Some(filter) = resources.filter.as_deref() {
        resources_element.set_attribute("filter", filter);
    }
    if let Some(action) = action {
        resources_element.set_attribute("action", action.as_gmp_str());
    }
    for resource_id in &resources.resource_ids {
        resources_element
            .add_child("resource")
            .set_attribute("id", resource_id.as_str());
    }
    resources_element
        .add_child("type")
        .set_text(resources.wire_type().as_gmp_str());
}

fn get_tags_command(request: &GetTagsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_tags");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    set_optional_bool_attr(&mut cmd, "names_only", request.names_only);
    cmd
}

fn get_tag_command(request: &GetTagRequest) -> XmlCommand {
    XmlCommand::new("get_tags")
        .attribute("tag_id", request.tag_id.as_str())
        .attribute("details", "1")
}

fn create_tag_command(request: &CreateTagRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_tag");
    cmd.add_element_with_text("name", &request.name);
    add_resources(&mut cmd, &request.resources, None);
    add_optional_text_element(&mut cmd, "value", request.value.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    if let Some(active) = request.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    cmd
}

fn clone_tag_command(request: &CloneTagRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_tag");
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element_with_text("copy", request.tag_id.as_str());
    cmd
}

fn modify_tag_command(request: &ModifyTagRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_tag").attribute("tag_id", request.tag_id.as_str());
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    if let Some(update) = &request.resource_update {
        add_resources(&mut cmd, &update.resources, update.action);
    }
    add_optional_text_element(&mut cmd, "value", request.value.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    if let Some(active) = request.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    cmd
}

fn delete_tag_command(request: &DeleteTagRequest) -> XmlCommand {
    XmlCommand::new("delete_tag")
        .attribute("tag_id", request.tag_id.as_str())
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
                .expect("valid tag request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetTagsRequest {
                filter_string: Some("name=web".into()),
                filter_id: Some(id("saved-filter")),
                trash: Some(true),
                details: Some(false),
                names_only: Some(true),
            }),
            "<get_tags details=\"0\" filt_id=\"saved-filter\" filter=\"name=web\" names_only=\"1\" trash=\"1\"/>"
        );

        assert_eq!(
            request_xml(&GetTagRequest::new(id("tag-1"))),
            "<get_tags details=\"1\" tag_id=\"tag-1\"/>"
        );

        let mut resources = TagResources::new(EntityType::Policy);
        resources.resource_ids = vec![id("policy-1"), id("policy-2")];
        resources.filter = Some("name=baseline".into());
        let mut create = CreateTagRequest::new("baseline", resources);
        create.value = Some("blue".into());
        create.comment = Some("policies".into());
        create.active = Some(true);
        assert_eq!(
            request_xml(&create),
            "<create_tag><name>baseline</name><resources filter=\"name=baseline\"><resource id=\"policy-1\"/><resource id=\"policy-2\"/><type>config</type></resources><value>blue</value><comment>policies</comment><active>1</active></create_tag>"
        );

        let mut clone = CloneTagRequest::new(id("tag-1"));
        clone.name = Some("copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            request_xml(&clone),
            "<create_tag><name>copy</name><comment></comment><copy>tag-1</copy></create_tag>"
        );

        let mut resources = TagResources::new(EntityType::Task);
        resources.resource_ids = vec![id("task-1"), id("task-2")];
        resources.filter = Some("status=Running".into());
        let mut modify = ModifyTagRequest::new(id("tag-1"));
        modify.name = Some("renamed".into());
        modify.comment = Some(String::new());
        modify.value = Some(String::new());
        modify.resource_update = Some(TagResourceUpdate {
            resources,
            action: Some(TagResourceAction::Remove),
        });
        modify.active = Some(false);
        assert_eq!(
            request_xml(&modify),
            "<modify_tag tag_id=\"tag-1\"><name>renamed</name><resources action=\"remove\" filter=\"status=Running\"><resource id=\"task-1\"/><resource id=\"task-2\"/><type>task</type></resources><value></value><comment></comment><active>0</active></modify_tag>"
        );

        assert_eq!(
            request_xml(&DeleteTagRequest::new(id("tag-1"), true)),
            "<delete_tag tag_id=\"tag-1\" ultimate=\"1\"/>"
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

        associated::<_, GetTagsResponse>(&GetTagsRequest::default());
        associated::<_, GetTagsResponse>(&GetTagRequest::new(id("tag-1")));
        associated::<_, CreateTagResponse>(&CreateTagRequest::new(
            "tag",
            TagResources::new(EntityType::Task),
        ));
        associated::<_, CreateTagResponse>(&CloneTagRequest::new(id("tag-1")));
        associated::<_, ModifyTagResponse>(&ModifyTagRequest::new(id("tag-1")));
        associated::<_, DeleteTagResponse>(&DeleteTagRequest::new(id("tag-1"), false));
    }

    #[test]
    fn invalid_final_values_are_rejected() {
        let mut create = CreateTagRequest::new("tag", TagResources::new(EntityType::Task));
        create.name.clear();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut clone = CloneTagRequest::new(id("tag-1"));
        clone.name = Some(String::new());
        assert!(matches!(
            clone.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let create = CreateTagRequest::new("tag", TagResources::new(EntityType::Tag));
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField {
                field: "resources.resource_type",
                ..
            })
        ));
    }

    #[test]
    fn semantic_aliases_keep_wire_and_capability_names() {
        let get = GetTagRequest::new(id("tag-1"));
        let get_command = get.command().expect("typed command");
        assert_eq!(get_command.wire_name(), "get_tags");
        assert_eq!(get_command.semantic_name(), Some("get_tag"));

        let clone = CloneTagRequest::new(id("tag-1"));
        let clone_command = clone.command().expect("typed command");
        assert_eq!(clone_command.wire_name(), "create_tag");
        assert_eq!(clone_command.semantic_name(), Some("clone_tag"));
    }
}
