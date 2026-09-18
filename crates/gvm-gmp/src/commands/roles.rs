// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for role operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateRoleResponse, DeleteRoleResponse, GetRolesResponse, ModifyRoleResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing roles.
#[derive(Debug, Clone, Default)]
pub struct GetRolesRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetRolesRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_roles"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_roles_command(self).to_bytes())
    }
}

impl GmpRequest for GetRolesRequest {
    type Response = GetRolesResponse;
}

/// Request for one detailed role.
#[derive(Debug, Clone)]
pub struct GetRoleRequest {
    /// Role identifier to retrieve.
    pub role_id: EntityId,
}

impl GetRoleRequest {
    /// Create a detailed single-role request.
    #[must_use]
    pub fn new(role_id: EntityId) -> Self {
        Self { role_id }
    }
}

impl GmpRequestCodec for GetRoleRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_roles", "get_role"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_role_command(self).to_bytes())
    }
}

impl GmpRequest for GetRoleRequest {
    type Response = GetRolesResponse;
}

/// Request for creating a role.
#[derive(Debug, Clone)]
pub struct CreateRoleRequest {
    /// Role name.
    pub name: String,
    /// Optional comment text.
    pub comment: Option<String>,
    /// User names assigned to the role.
    pub users: Vec<String>,
}

impl CreateRoleRequest {
    /// Create a role request with the required role name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            users: Vec::new(),
        }
    }
}

impl GmpRequestCodec for CreateRoleRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        validate_user_names(&self.users)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_role"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_role_command(self).to_bytes())
    }
}

impl GmpRequest for CreateRoleRequest {
    type Response = CreateRoleResponse;
}

/// Request for cloning a role through `create_role`.
#[derive(Debug, Clone)]
pub struct CloneRoleRequest {
    /// Existing role identifier to copy.
    pub role_id: EntityId,
    /// Optional name override.
    ///
    /// When omitted, gvmd chooses the first available
    /// `<existing name> Clone <number>` name, starting at 1.
    pub name: Option<String>,
    /// Optional comment override. Omission or empty text preserves the existing comment.
    pub comment: Option<String>,
}

impl CloneRoleRequest {
    /// Create a role-clone request.
    #[must_use]
    pub fn new(role_id: EntityId) -> Self {
        Self {
            role_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneRoleRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_non_empty(self.name.as_deref(), "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("create_role", "clone_role"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(clone_role_command(self).to_bytes())
    }
}

impl GmpRequest for CloneRoleRequest {
    type Response = CreateRoleResponse;
}

/// Request for modifying a role.
#[derive(Debug, Clone)]
pub struct ModifyRoleRequest {
    /// Role identifier to modify.
    pub role_id: EntityId,
    /// Final role name. gvmd replaces this value even when the child is omitted.
    pub name: String,
    /// Final comment. An empty string clears the comment.
    pub comment: String,
    /// Final user membership. An empty vector clears all users.
    pub users: Vec<String>,
}

impl ModifyRoleRequest {
    /// Create a complete role-modification request.
    ///
    /// gvmd replaces the name, comment, and membership on every
    /// `modify_role` command, so callers must provide the final values for
    /// all three fields.
    #[must_use]
    pub fn new(
        role_id: EntityId,
        name: impl Into<String>,
        comment: impl Into<String>,
        users: Vec<String>,
    ) -> Self {
        Self {
            role_id,
            name: name.into(),
            comment: comment.into(),
            users,
        }
    }
}

impl GmpRequestCodec for ModifyRoleRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        validate_user_names(&self.users)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_role"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_role_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyRoleRequest {
    type Response = ModifyRoleResponse;
}

/// Request for deleting a role.
#[derive(Debug, Clone)]
pub struct DeleteRoleRequest {
    /// Role identifier to delete.
    pub role_id: EntityId,
    /// Whether to delete permanently instead of moving the role to trash.
    pub ultimate: bool,
}

impl DeleteRoleRequest {
    /// Create a role-deletion request.
    #[must_use]
    pub fn new(role_id: EntityId, ultimate: bool) -> Self {
        Self { role_id, ultimate }
    }
}

impl GmpRequestCodec for DeleteRoleRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_role"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_role_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteRoleRequest {
    type Response = DeleteRoleResponse;
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

fn get_roles_command(request: &GetRolesRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_roles");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_role_command(request: &GetRoleRequest) -> XmlCommand {
    XmlCommand::new("get_roles")
        .attribute("role_id", request.role_id.as_str())
        .attribute("details", "1")
}

fn create_role_command(request: &CreateRoleRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_role");
    cmd.add_element_with_text("name", &request.name);
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    if !request.users.is_empty() {
        cmd.add_element_with_text("users", &request.users.join(","));
    }
    cmd
}

fn clone_role_command(request: &CloneRoleRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_role");
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element_with_text("copy", request.role_id.as_str());
    cmd
}

fn modify_role_command(request: &ModifyRoleRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_role").attribute("role_id", request.role_id.as_str());
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

fn delete_role_command(request: &DeleteRoleRequest) -> XmlCommand {
    XmlCommand::new("delete_role")
        .attribute("role_id", request.role_id.as_str())
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
        let mut create = CreateRoleRequest::new("operators");
        create.comment = Some("team".into());
        create.users = vec!["alice".into(), "bob".into()];
        assert_eq!(
            xml(&create),
            "<create_role><name>operators</name><comment>team</comment><users>alice,bob</users></create_role>"
        );

        let mut clone = CloneRoleRequest::new(id("role-1"));
        clone.name = Some("operators-copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            xml(&clone),
            "<create_role><name>operators-copy</name><copy>role-1</copy></create_role>"
        );

        assert_eq!(
            xml(&GetRoleRequest::new(id("role-1"))),
            "<get_roles details=\"1\" role_id=\"role-1\"/>"
        );

        let modify = ModifyRoleRequest::new(id("role-1"), "renamed", "", Vec::new());
        assert_eq!(
            xml(&modify),
            "<modify_role role_id=\"role-1\"><name>renamed</name><comment></comment><users></users></modify_role>"
        );

        assert_eq!(
            xml(&DeleteRoleRequest::new(id("role-1"), true)),
            "<delete_role role_id=\"role-1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn requests_validate_mutated_final_values() {
        let mut create = CreateRoleRequest::new("operators");
        create.name.clear();
        assert!(matches!(
            create.encode(GmpVersion(22, 8)),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let modify = ModifyRoleRequest::new(id("role-1"), "operators", "team", vec![String::new()]);
        assert!(matches!(
            modify.encode(GmpVersion(22, 8)),
            Err(GmpRequestError::InvalidField { field: "users", .. })
        ));
    }

    #[test]
    fn requests_expose_semantic_metadata_and_response_associations() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_eq!(
            GetRoleRequest::new(id("role-1")).command(),
            Some(GmpCommand::with_semantic_name("get_roles", "get_role"))
        );
        assert_eq!(
            CloneRoleRequest::new(id("role-1")).command(),
            Some(GmpCommand::with_semantic_name("create_role", "clone_role"))
        );
        assert_response::<_, GetRolesResponse>(&GetRolesRequest::default());
        assert_response::<_, GetRolesResponse>(&GetRoleRequest::new(id("role-1")));
        assert_response::<_, CreateRoleResponse>(&CreateRoleRequest::new("operators"));
        assert_response::<_, CreateRoleResponse>(&CloneRoleRequest::new(id("role-1")));
        assert_response::<_, ModifyRoleResponse>(&ModifyRoleRequest::new(
            id("role-1"),
            "operators",
            "team",
            Vec::new(),
        ));
        assert_response::<_, DeleteRoleResponse>(&DeleteRoleRequest::new(id("role-1"), false));
    }
}
