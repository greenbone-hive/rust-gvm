// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for OCI image target operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::responses::{
    CreateOciImageTargetResponse, DeleteOciImageTargetResponse, GetOciImageTargetsResponse,
    ModifyOciImageTargetResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Semantic request for cloning an OCI image target.
#[derive(Debug, Clone)]
pub struct CloneOciImageTargetRequest {
    /// Existing OCI image target identifier to copy.
    pub oci_image_target_id: EntityId,
}

impl CloneOciImageTargetRequest {
    /// Create an OCI-image-target clone request.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId) -> Self {
        Self {
            oci_image_target_id,
        }
    }
}

impl GmpRequestCodec for CloneOciImageTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_oci_image_target",
            "clone_oci_image_target",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_oci_image_target_command(&self.oci_image_target_id).to_bytes())
    }
}

impl GmpRequest for CloneOciImageTargetRequest {
    type Response = CreateOciImageTargetResponse;
}

/// Semantic request for creating an OCI image target.
#[derive(Debug, Clone)]
pub struct CreateOciImageTargetRequest {
    /// Resource name.
    pub name: String,
    /// OCI image references to scan.
    pub image_references: Vec<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

impl CreateOciImageTargetRequest {
    /// Create an OCI-image-target creation request with its required fields.
    #[must_use]
    pub fn new(name: impl Into<String>, image_references: Vec<String>) -> Self {
        Self {
            name: name.into(),
            image_references,
            comment: None,
            credential_id: None,
        }
    }
}

impl GmpRequestCodec for CreateOciImageTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_oci_image_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_oci_image_target_command(self).to_bytes())
    }
}

impl GmpRequest for CreateOciImageTargetRequest {
    type Response = CreateOciImageTargetResponse;
}

/// Semantic request for listing OCI image targets.
#[derive(Debug, Clone, Default)]
pub struct GetOciImageTargetsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to include tasks that use the target.
    pub tasks: Option<bool>,
}

impl GmpRequestCodec for GetOciImageTargetsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_oci_image_targets"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_oci_image_targets_command(self).to_bytes())
    }
}

impl GmpRequest for GetOciImageTargetsRequest {
    type Response = GetOciImageTargetsResponse;
}

/// Semantic request for one detailed OCI image target.
#[derive(Debug, Clone)]
pub struct GetOciImageTargetRequest {
    /// OCI image target identifier to retrieve.
    pub oci_image_target_id: EntityId,
    /// Whether to include tasks that use the target.
    pub tasks: Option<bool>,
}

impl GetOciImageTargetRequest {
    /// Create a detailed OCI-image-target request.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId) -> Self {
        Self {
            oci_image_target_id,
            tasks: None,
        }
    }
}

impl GmpRequestCodec for GetOciImageTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_oci_image_targets",
            "get_oci_image_target",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_oci_image_target_command(self).to_bytes())
    }
}

impl GmpRequest for GetOciImageTargetRequest {
    type Response = GetOciImageTargetsResponse;
}

/// Semantic request for modifying an OCI image target.
#[derive(Debug, Clone)]
pub struct ModifyOciImageTargetRequest {
    /// OCI image target identifier to modify.
    pub oci_image_target_id: EntityId,
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// OCI image references to scan. An empty list omits the element.
    pub image_references: Vec<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

impl ModifyOciImageTargetRequest {
    /// Create an OCI-image-target modification request with no field updates.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId) -> Self {
        Self {
            oci_image_target_id,
            name: None,
            comment: None,
            image_references: Vec::new(),
            credential_id: None,
        }
    }
}

impl GmpRequestCodec for ModifyOciImageTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_oci_image_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_oci_image_target_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyOciImageTargetRequest {
    type Response = ModifyOciImageTargetResponse;
}

/// Semantic request for deleting an OCI image target.
#[derive(Debug, Clone)]
pub struct DeleteOciImageTargetRequest {
    /// OCI image target identifier to delete.
    pub oci_image_target_id: EntityId,
    /// Whether to delete permanently instead of moving the target to trash.
    pub ultimate: bool,
}

impl DeleteOciImageTargetRequest {
    /// Create an OCI-image-target deletion request.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId, ultimate: bool) -> Self {
        Self {
            oci_image_target_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteOciImageTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_oci_image_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_oci_image_target_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteOciImageTargetRequest {
    type Response = DeleteOciImageTargetResponse;
}

fn clone_oci_image_target_command(oci_image_target_id: &EntityId) -> XmlCommand {
    XmlCommand::new("create_oci_image_target").child_with_text("copy", oci_image_target_id.as_str())
}

fn create_oci_image_target_command(request: &CreateOciImageTargetRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_oci_image_target");
    cmd.add_element_with_text("name", &request.name);
    cmd.add_element_with_text("image_references", &request.image_references.join(","));
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_optional_id_element(&mut cmd, "credential", request.credential_id.as_ref());
    cmd
}

fn get_oci_image_targets_command(request: &GetOciImageTargetsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_oci_image_targets");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "tasks", request.tasks);
    cmd
}

fn get_oci_image_target_command(request: &GetOciImageTargetRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_oci_image_targets")
        .attribute("oci_image_target_id", request.oci_image_target_id.as_str());
    set_optional_bool_attr(&mut cmd, "tasks", request.tasks);
    cmd
}

fn modify_oci_image_target_command(request: &ModifyOciImageTargetRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_oci_image_target")
        .attribute("oci_image_target_id", request.oci_image_target_id.as_str());
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_text_element(&mut cmd, "name", request.name.as_deref());
    add_string_list_text(&mut cmd, "image_references", &request.image_references);
    add_optional_id_element(&mut cmd, "credential", request.credential_id.as_ref());
    cmd
}

fn delete_oci_image_target_command(request: &DeleteOciImageTargetRequest) -> XmlCommand {
    XmlCommand::new("delete_oci_image_target")
        .attribute("oci_image_target_id", request.oci_image_target_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn add_string_list_text(cmd: &mut XmlCommand, name: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    cmd.add_element_with_text(name, &values.join(","));
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
                .expect("valid OCI image target request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        let mut create = CreateOciImageTargetRequest::new(
            "oci",
            vec![
                "registry.example/image:1".into(),
                "registry.example/image:2".into(),
            ],
        );
        create.comment = Some("note".into());
        create.credential_id = Some(id("cred-1"));
        assert_eq!(
            request_xml(&create),
            "<create_oci_image_target><name>oci</name><image_references>registry.example/image:1,registry.example/image:2</image_references><comment>note</comment><credential id=\"cred-1\"/></create_oci_image_target>"
        );
        assert_eq!(
            request_xml(&CloneOciImageTargetRequest::new(id("target-1"))),
            "<create_oci_image_target><copy>target-1</copy></create_oci_image_target>"
        );
        assert_eq!(
            request_xml(&GetOciImageTargetsRequest {
                filter_string: Some("name=oci".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(false),
                tasks: Some(true),
            }),
            "<get_oci_image_targets filt_id=\"filter-1\" filter=\"name=oci\" tasks=\"1\" trash=\"0\"/>"
        );
        let mut detail = GetOciImageTargetRequest::new(id("target-1"));
        detail.tasks = Some(false);
        assert_eq!(
            request_xml(&detail),
            "<get_oci_image_targets oci_image_target_id=\"target-1\" tasks=\"0\"/>"
        );
        let mut modify = ModifyOciImageTargetRequest::new(id("target-1"));
        modify.name = Some("updated".into());
        modify.comment = Some("changed".into());
        modify.image_references = vec!["registry.example/image:latest".into()];
        modify.credential_id = Some(id("cred-1"));
        assert_eq!(
            request_xml(&modify),
            "<modify_oci_image_target oci_image_target_id=\"target-1\"><comment>changed</comment><name>updated</name><image_references>registry.example/image:latest</image_references><credential id=\"cred-1\"/></modify_oci_image_target>"
        );
        assert_eq!(
            request_xml(&DeleteOciImageTargetRequest::new(id("target-1"), true)),
            "<delete_oci_image_target oci_image_target_id=\"target-1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn requests_expose_semantic_capability_metadata() {
        assert_eq!(
            CloneOciImageTargetRequest::new(id("target-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "create_oci_image_target",
                "clone_oci_image_target"
            ))
        );
        assert_eq!(
            CreateOciImageTargetRequest::new("oci", vec![]).command(),
            Some(GmpCommand::new("create_oci_image_target"))
        );
        assert_eq!(
            GetOciImageTargetsRequest::default().command(),
            Some(GmpCommand::new("get_oci_image_targets"))
        );
        assert_eq!(
            GetOciImageTargetRequest::new(id("target-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "get_oci_image_targets",
                "get_oci_image_target"
            ))
        );
        assert_eq!(
            ModifyOciImageTargetRequest::new(id("target-1")).command(),
            Some(GmpCommand::new("modify_oci_image_target"))
        );
        assert_eq!(
            DeleteOciImageTargetRequest::new(id("target-1"), false).command(),
            Some(GmpCommand::new("delete_oci_image_target"))
        );
    }

    #[test]
    fn requests_remain_statically_associated_with_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_response::<_, CreateOciImageTargetResponse>(&CloneOciImageTargetRequest::new(id(
            "target-1",
        )));
        assert_response::<_, CreateOciImageTargetResponse>(&CreateOciImageTargetRequest::new(
            "oci",
            vec![],
        ));
        assert_response::<_, GetOciImageTargetsResponse>(&GetOciImageTargetsRequest::default());
        assert_response::<_, GetOciImageTargetsResponse>(&GetOciImageTargetRequest::new(id(
            "target-1",
        )));
        assert_response::<_, ModifyOciImageTargetResponse>(&ModifyOciImageTargetRequest::new(id(
            "target-1",
        )));
        assert_response::<_, DeleteOciImageTargetResponse>(&DeleteOciImageTargetRequest::new(
            id("target-1"),
            false,
        ));
    }
}
