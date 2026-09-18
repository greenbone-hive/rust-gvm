// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for permission operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreatePermissionResponse, DeletePermissionResponse, GetPermissionsResponse,
    ModifyPermissionResponse,
};
use crate::{
    EntityId, GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion,
    PermissionSubjectType, ScalarUpdate,
};

/// Subject receiving a permission. Both identifier and type are required on creation.
#[derive(Debug, Clone)]
pub struct PermissionSubject {
    /// User, group, or role identifier.
    pub id: EntityId,
    /// Kind of subject receiving the permission.
    pub subject_type: PermissionSubjectType,
}

impl PermissionSubject {
    /// Construct a complete subject reference.
    #[must_use]
    pub fn new(id: EntityId, subject_type: PermissionSubjectType) -> Self {
        Self { id, subject_type }
    }
}

/// Resource to which a permission applies.
#[derive(Debug, Clone)]
pub struct PermissionResource {
    /// Resource identifier. Use `ScalarUpdate::Clear` to remove a resource on modification.
    pub id: EntityId,
    /// Optional type. Normal commands infer this from the permission name;
    /// `Super` requires `user`, `group`, or `role`.
    pub resource_type: Option<String>,
}

impl PermissionResource {
    /// Construct a reference whose type is inferred from the permission name.
    #[must_use]
    pub fn new(id: EntityId) -> Self {
        Self {
            id,
            resource_type: None,
        }
    }
}

/// Request for listing permissions.
#[derive(Debug, Clone, Default)]
pub struct GetPermissionsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetPermissionsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_permissions"))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        let mut cmd = XmlCommand::new("get_permissions");
        add_filter_attrs(
            &mut cmd,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        );
        set_optional_bool_attr(&mut cmd, "trash", self.trash);
        set_optional_bool_attr(&mut cmd, "details", self.details);
        Ok(cmd.to_bytes())
    }
}
impl GmpRequest for GetPermissionsRequest {
    type Response = GetPermissionsResponse;
}

/// Request for one detailed permission.
#[derive(Debug, Clone)]
pub struct GetPermissionRequest {
    /// Permission identifier to retrieve.
    pub permission_id: EntityId,
}
impl GetPermissionRequest {
    /// Construct a detail request.
    #[must_use]
    pub fn new(permission_id: EntityId) -> Self {
        Self { permission_id }
    }
}
impl GmpRequestCodec for GetPermissionRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_permissions",
            "get_permission",
        ))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_permissions")
            .attribute("permission_id", self.permission_id.as_str())
            .attribute("details", "1")
            .to_bytes())
    }
}
impl GmpRequest for GetPermissionRequest {
    type Response = GetPermissionsResponse;
}

/// Request for creating a permission. Command names and resource existence are
/// checked authoritatively by gvmd, allowing new commands without a client update.
#[derive(Debug, Clone)]
pub struct CreatePermissionRequest {
    /// Permission name (a GMP command or `Super`).
    pub name: String,
    /// Required subject receiving the permission.
    pub subject: PermissionSubject,
    /// Optional comment. Empty text has the same effect as omission on creation.
    pub comment: Option<String>,
    /// Optional resource; omission creates a command-level permission.
    pub resource: Option<PermissionResource>,
}
impl CreatePermissionRequest {
    /// Construct a permission with its required name and complete subject.
    #[must_use]
    pub fn new(name: impl Into<String>, subject: PermissionSubject) -> Self {
        Self {
            name: name.into(),
            subject,
            comment: None,
            resource: None,
        }
    }
}
impl GmpRequestCodec for CreatePermissionRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_name(&self.name)?;
        validate_reference_id(&self.subject.id, "subject.id")?;
        if let Some(resource) = &self.resource {
            validate_resource(resource)?;
        }
        validate_resource_for_name(&self.name, self.resource.as_ref())
    }
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_permission"))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut cmd = XmlCommand::new("create_permission");
        add_text_element(&mut cmd, "comment", self.comment.as_deref());
        cmd.add_element_with_text("name", &self.name);
        if let Some(resource) = &self.resource {
            add_resource(&mut cmd, resource);
        }
        add_subject(
            &mut cmd,
            Some(&self.subject.id),
            Some(self.subject.subject_type),
        );
        Ok(cmd.to_bytes())
    }
}
impl GmpRequest for CreatePermissionRequest {
    type Response = CreatePermissionResponse;
}

/// Request for copying a permission. gvmd copies the name, subject, and resource;
/// only a comment override is accepted by its copy handler.
#[derive(Debug, Clone)]
pub struct ClonePermissionRequest {
    /// Existing permission identifier to copy.
    pub permission_id: EntityId,
    /// Optional comment override. Omission or empty text preserves the comment.
    pub comment: Option<String>,
}
impl ClonePermissionRequest {
    /// Construct a clone request.
    #[must_use]
    pub fn new(permission_id: EntityId) -> Self {
        Self {
            permission_id,
            comment: None,
        }
    }
}
impl GmpRequestCodec for ClonePermissionRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_permission",
            "clone_permission",
        ))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        let mut cmd = XmlCommand::new("create_permission");
        add_text_element(&mut cmd, "comment", self.comment.as_deref());
        cmd.add_element_with_text("copy", self.permission_id.as_str());
        Ok(cmd.to_bytes())
    }
}
impl GmpRequest for ClonePermissionRequest {
    type Response = CreatePermissionResponse;
}

/// Request for modifying a permission. Omitted values preserve existing state.
#[derive(Debug, Clone)]
pub struct ModifyPermissionRequest {
    /// Permission identifier to modify.
    pub permission_id: EntityId,
    /// Optional replacement permission name.
    pub name: Option<String>,
    /// Optional replacement comment. Empty text clears the comment.
    pub comment: Option<String>,
    /// Preserve, replace, or clear the resource (`id="0"`).
    pub resource_id: ScalarUpdate<EntityId>,
    /// Optional resource type. Omission preserves an existing identity type for
    /// `Super`; ordinary commands infer their type from the final name.
    pub resource_type: Option<String>,
    /// Optional subject identifier. Omission preserves the current identifier.
    pub subject_id: Option<EntityId>,
    /// Optional subject type. Omission preserves the current type.
    pub subject_type: Option<PermissionSubjectType>,
}
impl ModifyPermissionRequest {
    /// Construct a modification preserving all optional values.
    #[must_use]
    pub fn new(permission_id: EntityId) -> Self {
        Self {
            permission_id,
            name: None,
            comment: None,
            resource_id: ScalarUpdate::Omitted,
            resource_type: None,
            subject_id: None,
            subject_type: None,
        }
    }
}
impl GmpRequestCodec for ModifyPermissionRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if let Some(name) = &self.name {
            validate_name(name)?;
        }
        if let Some(id) = &self.subject_id {
            validate_reference_id(id, "subject.id")?;
        }
        if let ScalarUpdate::Set(id) = &self.resource_id {
            validate_reference_id(id, "resource.id")?;
        }
        if self.resource_type.as_deref() == Some("") {
            return Err(GmpRequestError::invalid_field(
                "resource.type",
                "must not be empty when supplied",
            ));
        }
        // Combinations involving omitted values need stored state. gvmd remains
        // authoritative for the final permission name and resource type.
        if self
            .name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("super"))
            && (matches!(self.resource_id, ScalarUpdate::Clear)
                || (matches!(self.resource_id, ScalarUpdate::Set(_))
                    && self
                        .resource_type
                        .as_deref()
                        .is_some_and(|kind| !matches!(kind, "user" | "group" | "role"))))
        {
            return Err(GmpRequestError::invalid_field(
                "resource",
                "Super requires a resource with type user, group, or role",
            ));
        }
        Ok(())
    }
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_permission"))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut cmd = XmlCommand::new("modify_permission")
            .attribute("permission_id", self.permission_id.as_str());
        if let Some(comment) = &self.comment {
            cmd.add_element_with_text("comment", comment);
        }
        add_text_element(&mut cmd, "name", self.name.as_deref());
        if !matches!(self.resource_id, ScalarUpdate::Omitted) || self.resource_type.is_some() {
            let resource = cmd.add_element("resource");
            match &self.resource_id {
                ScalarUpdate::Omitted => {}
                ScalarUpdate::Set(id) => {
                    resource.set_attribute("id", id.as_str());
                }
                ScalarUpdate::Clear => {
                    resource.set_attribute("id", "0");
                }
            }
            if let Some(kind) = &self.resource_type {
                resource.add_child_with_text("type", kind);
            }
        }
        add_subject(&mut cmd, self.subject_id.as_ref(), self.subject_type);
        Ok(cmd.to_bytes())
    }
}
impl GmpRequest for ModifyPermissionRequest {
    type Response = ModifyPermissionResponse;
}

/// Request for deleting a permission.
#[derive(Debug, Clone)]
pub struct DeletePermissionRequest {
    /// Permission identifier to delete.
    pub permission_id: EntityId,
    /// Whether to delete permanently instead of moving to trash.
    pub ultimate: bool,
}
impl DeletePermissionRequest {
    /// Construct a deletion request.
    #[must_use]
    pub fn new(permission_id: EntityId, ultimate: bool) -> Self {
        Self {
            permission_id,
            ultimate,
        }
    }
}
impl GmpRequestCodec for DeletePermissionRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_permission"))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("delete_permission")
            .attribute("permission_id", self.permission_id.as_str())
            .attribute("ultimate", bool_str(self.ultimate))
            .to_bytes())
    }
}
impl GmpRequest for DeletePermissionRequest {
    type Response = DeletePermissionResponse;
}

fn validate_name(name: &str) -> Result<(), GmpRequestError> {
    if name.is_empty() || name.eq_ignore_ascii_case("get_version") {
        return Err(GmpRequestError::invalid_field(
            "name",
            "must be a non-empty permission command other than get_version",
        ));
    }
    Ok(())
}
fn validate_reference_id(id: &EntityId, field: &'static str) -> Result<(), GmpRequestError> {
    if id.as_str() == "0" {
        return Err(GmpRequestError::invalid_field(
            field,
            "must identify a resource, not a clear sentinel",
        ));
    }
    Ok(())
}
fn validate_resource(resource: &PermissionResource) -> Result<(), GmpRequestError> {
    validate_reference_id(&resource.id, "resource.id")?;
    if resource.resource_type.as_deref() == Some("") {
        return Err(GmpRequestError::invalid_field(
            "resource.type",
            "must not be empty when supplied",
        ));
    }
    Ok(())
}
fn validate_resource_for_name(
    name: &str,
    resource: Option<&PermissionResource>,
) -> Result<(), GmpRequestError> {
    if name.eq_ignore_ascii_case("super")
        && !resource
            .is_some_and(|r| matches!(r.resource_type.as_deref(), Some("user" | "group" | "role")))
    {
        return Err(GmpRequestError::invalid_field(
            "resource",
            "Super requires a resource with type user, group, or role",
        ));
    }
    Ok(())
}
fn add_resource(cmd: &mut XmlCommand, resource: &PermissionResource) {
    let element = cmd.add_element("resource");
    element.set_attribute("id", resource.id.as_str());
    if let Some(kind) = &resource.resource_type {
        element.add_child_with_text("type", kind);
    }
}
fn add_subject(cmd: &mut XmlCommand, id: Option<&EntityId>, kind: Option<PermissionSubjectType>) {
    if id.is_none() && kind.is_none() {
        return;
    }
    let element = cmd.add_element("subject");
    if let Some(id) = id {
        element.set_attribute("id", id.as_str());
    }
    if let Some(kind) = kind {
        element.add_child_with_text("type", kind.as_gmp_str());
    }
}
