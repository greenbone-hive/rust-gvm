// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for user operations.

use std::fmt;

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, set_optional_bool_attr};
use crate::enums::UserAuthType;
use crate::responses::{
    CreateUserResponse, DeleteUserResponse, GetUsersResponse, ModifyUserResponse,
};
use crate::types::{CollectionUpdate, EntityId};
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// User host-access restrictions.
///
/// `hosts` is the comma-separated GMP host expression accepted by gvmd. It
/// may contain individual hosts, ranges, or CIDR expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserHostAccess {
    /// If true, allow only the listed hosts; otherwise forbid the listed hosts.
    pub allow: bool,
    /// Comma-separated GMP host expression list.
    pub hosts: String,
}

impl UserHostAccess {
    /// Create user host-access restrictions.
    #[must_use]
    pub fn new(allow: bool, hosts: impl Into<String>) -> Self {
        Self {
            allow,
            hosts: hosts.into(),
        }
    }

    /// Create an allow-list host-access restriction.
    #[must_use]
    pub fn allow(hosts: impl Into<String>) -> Self {
        Self::new(true, hosts)
    }

    /// Create a deny-list host-access restriction.
    #[must_use]
    pub fn deny(hosts: impl Into<String>) -> Self {
        Self::new(false, hosts)
    }
}

impl From<String> for UserHostAccess {
    fn from(hosts: String) -> Self {
        Self::allow(hosts)
    }
}

impl From<&str> for UserHostAccess {
    fn from(hosts: &str) -> Self {
        Self::allow(hosts)
    }
}

/// Request for listing users.
#[derive(Debug, Clone, Default)]
pub struct GetUsersRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetUsersRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_users"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_users_command(self).to_bytes())
    }
}

impl GmpRequest for GetUsersRequest {
    type Response = GetUsersResponse;
}

/// Request for one detailed user.
#[derive(Debug, Clone)]
pub struct GetUserRequest {
    /// User identifier to retrieve.
    pub user_id: EntityId,
}

impl GetUserRequest {
    /// Create a detailed single-user request.
    #[must_use]
    pub fn new(user_id: EntityId) -> Self {
        Self { user_id }
    }
}

impl GmpRequestCodec for GetUserRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_users", "get_user"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_user_command(self).to_bytes())
    }
}

impl GmpRequest for GetUserRequest {
    type Response = GetUsersResponse;
}

/// Request for creating a user.
#[derive(Clone)]
pub struct CreateUserRequest {
    /// User name.
    pub name: String,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional password. Debug output always redacts this value.
    pub password: Option<String>,
    /// Optional host-access restriction.
    pub host_access: Option<UserHostAccess>,
    /// Roles assigned to the user.
    pub role_ids: Vec<EntityId>,
    /// Groups assigned to the user.
    pub group_ids: Vec<EntityId>,
    /// Authentication source accepted for the user.
    pub auth_source: Option<UserAuthType>,
}

impl CreateUserRequest {
    /// Create a user request with the required user name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            password: None,
            host_access: None,
            role_ids: Vec::new(),
            group_ids: Vec::new(),
            auth_source: None,
        }
    }
}

impl fmt::Debug for CreateUserRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateUserRequest")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("password", &redacted(&self.password))
            .field("host_access", &self.host_access)
            .field("role_ids", &self.role_ids)
            .field("group_ids", &self.group_ids)
            .field("auth_source", &self.auth_source)
            .finish()
    }
}

impl GmpRequestCodec for CreateUserRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_user"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_user_command(self).to_bytes())
    }
}

impl GmpRequest for CreateUserRequest {
    type Response = CreateUserResponse;
}

/// Request for cloning a user through `create_user`.
#[derive(Debug, Clone)]
pub struct CloneUserRequest {
    /// Existing user identifier to copy.
    pub user_id: EntityId,
    /// Optional name override. Omission copies the existing name.
    pub name: Option<String>,
    /// Optional comment override. Omission copies the existing comment.
    pub comment: Option<String>,
}

impl CloneUserRequest {
    /// Create a user-clone request.
    #[must_use]
    pub fn new(user_id: EntityId) -> Self {
        Self {
            user_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneUserRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_non_empty(self.name.as_deref(), "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("create_user", "clone_user"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(clone_user_command(self).to_bytes())
    }
}

impl GmpRequest for CloneUserRequest {
    type Response = CreateUserResponse;
}

/// Request for modifying a user.
#[derive(Clone)]
pub struct ModifyUserRequest {
    /// User identifier selector. Exactly one of this and `name` must be set.
    pub user_id: Option<EntityId>,
    /// User-name selector. Exactly one of this and `user_id` must be set.
    pub name: Option<String>,
    /// Optional replacement name.
    pub new_name: Option<String>,
    /// Optional replacement comment. An empty string clears the comment.
    pub comment: Option<String>,
    /// Optional replacement password. Debug output always redacts this value.
    pub password: Option<String>,
    /// Final host-access restriction.
    ///
    /// gvmd replaces host access on every `modify_user` command, including
    /// when the `<hosts>` child is omitted, so this value is required.
    pub host_access: UserHostAccess,
    /// Role update: preserve, replace, or clear.
    pub role_ids: CollectionUpdate<EntityId>,
    /// Group update: preserve, replace, or clear.
    pub group_ids: CollectionUpdate<EntityId>,
    /// Optional authentication-source replacement. Omission preserves it.
    pub auth_source: Option<UserAuthType>,
}

impl ModifyUserRequest {
    /// Create a user-modification request selected by identifier.
    #[must_use]
    pub fn new(user_id: EntityId, host_access: UserHostAccess) -> Self {
        Self {
            user_id: Some(user_id),
            name: None,
            new_name: None,
            comment: None,
            password: None,
            host_access,
            role_ids: CollectionUpdate::Omitted,
            group_ids: CollectionUpdate::Omitted,
            auth_source: None,
        }
    }

    /// Create a user-modification request selected by user name.
    #[must_use]
    pub fn by_name(name: impl Into<String>, host_access: UserHostAccess) -> Self {
        Self {
            user_id: None,
            name: Some(name.into()),
            new_name: None,
            comment: None,
            password: None,
            host_access,
            role_ids: CollectionUpdate::Omitted,
            group_ids: CollectionUpdate::Omitted,
            auth_source: None,
        }
    }
}

impl fmt::Debug for ModifyUserRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModifyUserRequest")
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("new_name", &self.new_name)
            .field("comment", &self.comment)
            .field("password", &redacted(&self.password))
            .field("host_access", &self.host_access)
            .field("role_ids", &self.role_ids)
            .field("group_ids", &self.group_ids)
            .field("auth_source", &self.auth_source)
            .finish()
    }
}

impl GmpRequestCodec for ModifyUserRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        match (&self.user_id, &self.name) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => {
                return Err(GmpRequestError::invalid_combination(
                    &["user_id", "name"],
                    "exactly one of user_id or name must select the user to modify",
                ));
            }
        }
        validate_optional_non_empty(self.name.as_deref(), "name")?;
        validate_optional_non_empty(self.new_name.as_deref(), "new_name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_user"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_user_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyUserRequest {
    type Response = ModifyUserResponse;
}

/// Request for deleting a user and optionally transferring owned resources.
#[derive(Debug, Clone)]
pub struct DeleteUserRequest {
    /// User identifier to delete. This takes precedence over `name` in gvmd.
    pub user_id: Option<EntityId>,
    /// User name selector used when `user_id` is omitted.
    pub name: Option<String>,
    /// Identifier of the user inheriting owned resources. The value `self` is supported.
    pub inheritor_id: Option<EntityId>,
    /// Name of the inheriting user when `inheritor_id` is omitted.
    pub inheritor_name: Option<String>,
}

impl DeleteUserRequest {
    /// Create a user-deletion request selected by identifier.
    #[must_use]
    pub fn new(user_id: EntityId) -> Self {
        Self {
            user_id: Some(user_id),
            name: None,
            inheritor_id: None,
            inheritor_name: None,
        }
    }

    /// Create a user-deletion request selected by name.
    #[must_use]
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            user_id: None,
            name: Some(name.into()),
            inheritor_id: None,
            inheritor_name: None,
        }
    }
}

impl GmpRequestCodec for DeleteUserRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        match (&self.user_id, &self.name) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => {
                return Err(GmpRequestError::invalid_combination(
                    &["user_id", "name"],
                    "exactly one of user_id or name must select the user to delete",
                ));
            }
        }
        if self.inheritor_id.is_some() && self.inheritor_name.is_some() {
            return Err(GmpRequestError::invalid_combination(
                &["inheritor_id", "inheritor_name"],
                "at most one inheritor selector may be set",
            ));
        }
        validate_optional_non_empty(self.name.as_deref(), "name")?;
        validate_optional_non_empty(self.inheritor_name.as_deref(), "inheritor_name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_user"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(delete_user_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteUserRequest {
    type Response = DeleteUserResponse;
}

fn redacted(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
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

fn get_users_command(request: &GetUsersRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_users");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_user_command(request: &GetUserRequest) -> XmlCommand {
    XmlCommand::new("get_users")
        .attribute("user_id", request.user_id.as_str())
        .attribute("details", "1")
}

fn create_user_command(request: &CreateUserRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_user");
    cmd.add_element_with_text("name", &request.name);
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_text_element(&mut cmd, "password", request.password.as_deref());
    if let Some(host_access) = request.host_access.as_ref() {
        add_host_access(&mut cmd, host_access);
    }
    add_roles(&mut cmd, &request.role_ids);
    add_groups(&mut cmd, &request.group_ids);
    add_source(&mut cmd, request.auth_source);
    cmd
}

fn clone_user_command(request: &CloneUserRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_user");
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element_with_text("copy", request.user_id.as_str());
    cmd
}

fn modify_user_command(request: &ModifyUserRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_user");
    if let Some(user_id) = request.user_id.as_ref() {
        cmd.set_attribute("user_id", user_id.as_str());
    }
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "new_name", request.new_name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_text_element(&mut cmd, "password", request.password.as_deref());
    add_host_access(&mut cmd, &request.host_access);
    add_role_update(&mut cmd, &request.role_ids);
    add_group_update(&mut cmd, &request.group_ids);
    add_source(&mut cmd, request.auth_source);
    cmd
}

fn delete_user_command(request: &DeleteUserRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("delete_user");
    if let Some(user_id) = request.user_id.as_ref() {
        cmd.set_attribute("user_id", user_id.as_str());
    }
    if let Some(name) = request.name.as_deref() {
        cmd.set_attribute("name", name);
    }
    if let Some(inheritor_id) = request.inheritor_id.as_ref() {
        cmd.set_attribute("inheritor_id", inheritor_id.as_str());
    }
    if let Some(inheritor_name) = request.inheritor_name.as_deref() {
        cmd.set_attribute("inheritor_name", inheritor_name);
    }
    cmd
}

fn add_host_access(cmd: &mut XmlCommand, host_access: &UserHostAccess) {
    cmd.add_element("hosts")
        .set_attribute("allow", if host_access.allow { "1" } else { "0" })
        .set_text(&host_access.hosts);
}

fn add_roles(cmd: &mut XmlCommand, role_ids: &[EntityId]) {
    for role_id in role_ids {
        cmd.add_element("role")
            .set_attribute("id", role_id.as_str());
    }
}

fn add_role_update(cmd: &mut XmlCommand, role_ids: &CollectionUpdate<EntityId>) {
    match role_ids {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(role_ids) if !role_ids.is_empty() => add_roles(cmd, role_ids),
        CollectionUpdate::Replace(_) | CollectionUpdate::Clear => {
            cmd.add_element("role").set_attribute("id", "0");
        }
    }
}

fn add_groups(cmd: &mut XmlCommand, group_ids: &[EntityId]) {
    if group_ids.is_empty() {
        return;
    }
    let groups = cmd.add_element("groups");
    for group_id in group_ids {
        groups
            .add_child("group")
            .set_attribute("id", group_id.as_str());
    }
}

fn add_group_update(cmd: &mut XmlCommand, group_ids: &CollectionUpdate<EntityId>) {
    match group_ids {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(group_ids) if !group_ids.is_empty() => {
            add_groups(cmd, group_ids);
        }
        CollectionUpdate::Replace(_) | CollectionUpdate::Clear => {
            cmd.add_element("groups");
        }
    }
}

fn add_source(cmd: &mut XmlCommand, source: Option<UserAuthType>) {
    let Some(source) = source else {
        return;
    };
    let source_element = cmd.add_element("sources");
    source_element.add_child_with_text("source", source.as_gmp_str());
}

fn add_optional_text_element(cmd: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        cmd.add_element_with_text(name, value);
    }
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
        let mut create = CreateUserRequest::new("alice");
        create.comment = Some("operator".into());
        create.password = Some("secret".into());
        create.host_access = Some(UserHostAccess::deny("192.0.2.0/24"));
        create.role_ids = vec![id("role-1")];
        create.group_ids = vec![id("group-1")];
        create.auth_source = Some(UserAuthType::File);
        assert_eq!(
            xml(&create),
            "<create_user><name>alice</name><comment>operator</comment><password>secret</password><hosts allow=\"0\">192.0.2.0/24</hosts><role id=\"role-1\"/><groups><group id=\"group-1\"/></groups><sources><source>file</source></sources></create_user>"
        );

        let mut clone = CloneUserRequest::new(id("user-1"));
        clone.name = Some("alice-copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            xml(&clone),
            "<create_user><name>alice-copy</name><comment></comment><copy>user-1</copy></create_user>"
        );

        assert_eq!(
            xml(&GetUserRequest::new(id("user-1"))),
            "<get_users details=\"1\" user_id=\"user-1\"/>"
        );

        let mut modify = ModifyUserRequest::new(id("user-1"), UserHostAccess::allow(""));
        modify.new_name = Some("alice-renamed".into());
        modify.comment = Some(String::new());
        modify.password = Some("replacement".into());
        modify.role_ids = CollectionUpdate::Clear;
        modify.group_ids = CollectionUpdate::replace([id("group-2")]);
        modify.auth_source = Some(UserAuthType::File);
        assert_eq!(
            xml(&modify),
            "<modify_user user_id=\"user-1\"><new_name>alice-renamed</new_name><comment></comment><password>replacement</password><hosts allow=\"1\"></hosts><role id=\"0\"/><groups><group id=\"group-2\"/></groups><sources><source>file</source></sources></modify_user>"
        );

        let mut delete = DeleteUserRequest::new(id("user-1"));
        delete.inheritor_id = Some(id("self"));
        assert_eq!(
            xml(&delete),
            "<delete_user inheritor_id=\"self\" user_id=\"user-1\"/>"
        );
    }

    #[test]
    fn requests_validate_mutated_final_values() {
        let mut create = CreateUserRequest::new("alice");
        create.name.clear();
        assert!(matches!(
            create.encode(GmpVersion(22, 8)),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut delete = DeleteUserRequest::by_name("alice");
        delete.name = None;
        assert!(matches!(
            delete.encode(GmpVersion(22, 8)),
            Err(GmpRequestError::InvalidCombination { .. })
        ));
    }

    #[test]
    fn password_debug_output_is_redacted() {
        let mut create = CreateUserRequest::new("alice");
        create.password = Some("create-secret".into());
        let create_debug = format!("{create:?}");
        assert!(create_debug.contains("<redacted>"));
        assert!(!create_debug.contains("create-secret"));

        let mut modify = ModifyUserRequest::new(id("user-1"), UserHostAccess::allow(""));
        modify.password = Some("modify-secret".into());
        let modify_debug = format!("{modify:?}");
        assert!(modify_debug.contains("<redacted>"));
        assert!(!modify_debug.contains("modify-secret"));
    }

    #[test]
    fn requests_expose_semantic_metadata_and_response_associations() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_eq!(
            GetUserRequest::new(id("user-1")).command(),
            Some(GmpCommand::with_semantic_name("get_users", "get_user"))
        );
        assert_eq!(
            CloneUserRequest::new(id("user-1")).command(),
            Some(GmpCommand::with_semantic_name("create_user", "clone_user"))
        );
        assert_response::<_, GetUsersResponse>(&GetUsersRequest::default());
        assert_response::<_, GetUsersResponse>(&GetUserRequest::new(id("user-1")));
        assert_response::<_, CreateUserResponse>(&CreateUserRequest::new("alice"));
        assert_response::<_, CreateUserResponse>(&CloneUserRequest::new(id("user-1")));
        assert_response::<_, ModifyUserResponse>(&ModifyUserRequest::new(
            id("user-1"),
            UserHostAccess::allow(""),
        ));
        assert_response::<_, DeleteUserResponse>(&DeleteUserRequest::new(id("user-1")));
    }
}
