// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for group operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateGroupResponse, DeleteGroupResponse, GetGroupsResponse, ModifyGroupResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing groups.
#[derive(Debug, Clone, Default)]
pub struct GetGroupsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetGroupsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_groups"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_groups_command(self).to_bytes())
    }
}

impl GmpRequest for GetGroupsRequest {
    type Response = GetGroupsResponse;
}

/// Request for one detailed group.
#[derive(Debug, Clone)]
pub struct GetGroupRequest {
    /// Group identifier to retrieve.
    pub group_id: EntityId,
}

impl GetGroupRequest {
    /// Create a detailed single-group request.
    #[must_use]
    pub fn new(group_id: EntityId) -> Self {
        Self { group_id }
    }
}

impl GmpRequestCodec for GetGroupRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_groups", "get_group"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_group_command(self).to_bytes())
    }
}

impl GmpRequest for GetGroupRequest {
    type Response = GetGroupsResponse;
}

/// Request for creating a group.
#[derive(Debug, Clone)]
pub struct CreateGroupRequest {
    /// Group name.
    pub name: String,
    /// Optional comment text.
    pub comment: Option<String>,
    /// User names assigned to the group.
    pub users: Vec<String>,
    /// Whether members receive full access to each other's resources.
    pub special_full: bool,
}

impl CreateGroupRequest {
    /// Create a group request with the required group name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            users: Vec::new(),
            special_full: false,
        }
    }
}

impl GmpRequestCodec for CreateGroupRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        validate_user_names(&self.users)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_group"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_group_command(self).to_bytes())
    }
}

impl GmpRequest for CreateGroupRequest {
    type Response = CreateGroupResponse;
}

/// Request for cloning a group through `create_group`.
#[derive(Debug, Clone)]
pub struct CloneGroupRequest {
    /// Existing group identifier to copy.
    pub group_id: EntityId,
    /// Optional name override. Omission copies the existing name.
    pub name: Option<String>,
    /// Optional comment override. Omission copies the existing comment.
    pub comment: Option<String>,
}

impl CloneGroupRequest {
    /// Create a group-clone request.
    #[must_use]
    pub fn new(group_id: EntityId) -> Self {
        Self {
            group_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneGroupRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_non_empty(self.name.as_deref(), "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_group",
            "clone_group",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(clone_group_command(self).to_bytes())
    }
}

impl GmpRequest for CloneGroupRequest {
    type Response = CreateGroupResponse;
}

/// Request for modifying a group.
#[derive(Debug, Clone)]
pub struct ModifyGroupRequest {
    /// Group identifier to modify.
    pub group_id: EntityId,
    /// Final group name. gvmd replaces this value even when the child is omitted.
    pub name: String,
    /// Final comment. An empty string clears the comment.
    pub comment: String,
    /// Final user membership. An empty vector clears all users.
    pub users: Vec<String>,
}

impl ModifyGroupRequest {
    /// Create a complete group-modification request.
    ///
    /// gvmd replaces the name, comment, and membership on every
    /// `modify_group` command, so callers must provide the final values for
    /// all three fields.
    #[must_use]
    pub fn new(
        group_id: EntityId,
        name: impl Into<String>,
        comment: impl Into<String>,
        users: Vec<String>,
    ) -> Self {
        Self {
            group_id,
            name: name.into(),
            comment: comment.into(),
            users,
        }
    }
}

impl GmpRequestCodec for ModifyGroupRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        validate_user_names(&self.users)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_group"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_group_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyGroupRequest {
    type Response = ModifyGroupResponse;
}

/// Request for deleting a group.
#[derive(Debug, Clone)]
pub struct DeleteGroupRequest {
    /// Group identifier to delete.
    pub group_id: EntityId,
    /// Whether to delete permanently instead of moving the group to trash.
    pub ultimate: bool,
}

impl DeleteGroupRequest {
    /// Create a group-deletion request.
    #[must_use]
    pub fn new(group_id: EntityId, ultimate: bool) -> Self {
        Self { group_id, ultimate }
    }
}

impl GmpRequestCodec for DeleteGroupRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_group"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_group_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteGroupRequest {
    type Response = DeleteGroupResponse;
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_optional_non_empty(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    if value.is_some_and(str::is_empty) {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_user_names(users: &[String]) -> Result<(), GmpRequestError> {
    if users.iter().any(String::is_empty) {
        Err(GmpRequestError::invalid_field(
            "users",
            "user names must not be empty",
        ))
    } else {
        Ok(())
    }
}

fn get_groups_command(request: &GetGroupsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_groups");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_group_command(request: &GetGroupRequest) -> XmlCommand {
    XmlCommand::new("get_groups")
        .attribute("group_id", request.group_id.as_str())
        .attribute("details", "1")
}

fn create_group_command(request: &CreateGroupRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_group");
    cmd.add_element_with_text("name", &request.name);
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    if request.special_full {
        cmd.add_element("specials").add_child("full");
    }
    if !request.users.is_empty() {
        cmd.add_element_with_text("users", &request.users.join(","));
    }
    cmd
}

fn clone_group_command(request: &CloneGroupRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_group");
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element_with_text("copy", request.group_id.as_str());
    cmd
}

fn modify_group_command(request: &ModifyGroupRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_group").attribute("group_id", request.group_id.as_str());
    cmd.add_element_with_text("name", &request.name);
    cmd.add_element_with_text("comment", &request.comment);
    cmd.add_element_with_text("users", &request.users.join(","));
    cmd
}

fn add_optional_text_element(cmd: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        cmd.add_element_with_text(name, value);
    }
}

fn delete_group_command(request: &DeleteGroupRequest) -> XmlCommand {
    XmlCommand::new("delete_group")
        .attribute("group_id", request.group_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GmpResponse;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(request.encode(GmpVersion(22, 8)).expect("valid request"))
            .expect("valid UTF-8")
    }

    #[test]
    fn requests_encode_independent_exact_wire_shapes() {
        let mut create = CreateGroupRequest::new("operators");
        create.comment = Some("team".into());
        create.users = vec!["alice".into(), "bob".into()];
        create.special_full = true;
        assert_eq!(
            xml(&create),
            "<create_group><name>operators</name><comment>team</comment><specials><full/></specials><users>alice,bob</users></create_group>"
        );

        let mut clone = CloneGroupRequest::new(id("group-1"));
        clone.name = Some("operators-copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            xml(&clone),
            "<create_group><name>operators-copy</name><comment></comment><copy>group-1</copy></create_group>"
        );

        assert_eq!(
            xml(&GetGroupRequest::new(id("group-1"))),
            "<get_groups details=\"1\" group_id=\"group-1\"/>"
        );

        let modify = ModifyGroupRequest::new(id("group-1"), "renamed", "", Vec::new());
        assert_eq!(
            xml(&modify),
            "<modify_group group_id=\"group-1\"><name>renamed</name><comment></comment><users></users></modify_group>"
        );

        assert_eq!(
            xml(&DeleteGroupRequest::new(id("group-1"), true)),
            "<delete_group group_id=\"group-1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn requests_validate_mutated_final_values() {
        let mut create = CreateGroupRequest::new("operators");
        create.name.clear();
        assert!(matches!(
            create.encode(GmpVersion(22, 8)),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let modify =
            ModifyGroupRequest::new(id("group-1"), "operators", "team", vec![String::new()]);
        assert!(matches!(
            modify.encode(GmpVersion(22, 8)),
            Err(GmpRequestError::InvalidField { field: "users", .. })
        ));
    }

    #[test]
    fn requests_expose_semantic_metadata_and_response_associations() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_eq!(
            GetGroupRequest::new(id("group-1")).command(),
            Some(GmpCommand::with_semantic_name("get_groups", "get_group"))
        );
        assert_eq!(
            CloneGroupRequest::new(id("group-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "create_group",
                "clone_group"
            ))
        );
        assert_response::<_, GetGroupsResponse>(&GetGroupsRequest::default());
        assert_response::<_, GetGroupsResponse>(&GetGroupRequest::new(id("group-1")));
        assert_response::<_, CreateGroupResponse>(&CreateGroupRequest::new("operators"));
        assert_response::<_, CreateGroupResponse>(&CloneGroupRequest::new(id("group-1")));
        assert_response::<_, ModifyGroupResponse>(&ModifyGroupRequest::new(
            id("group-1"),
            "operators",
            "team",
            Vec::new(),
        ));
        assert_response::<_, DeleteGroupResponse>(&DeleteGroupRequest::new(id("group-1"), false));
    }
}
