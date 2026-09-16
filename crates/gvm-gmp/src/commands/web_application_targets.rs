// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for web application target operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::responses::{
    CreateWebApplicationTargetResponse, DeleteWebApplicationTargetResponse,
    GetWebApplicationTargetsResponse, ModifyWebApplicationTargetResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Semantic request for cloning a web application target.
#[derive(Debug, Clone)]
pub struct CloneWebApplicationTargetRequest {
    /// Existing web application target identifier to copy.
    pub web_application_target_id: EntityId,
}

impl CloneWebApplicationTargetRequest {
    /// Create a web-application-target clone request.
    #[must_use]
    pub fn new(web_application_target_id: EntityId) -> Self {
        Self {
            web_application_target_id,
        }
    }
}

impl GmpRequestCodec for CloneWebApplicationTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_web_application_target",
            "clone_web_application_target",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_web_application_target_command(&self.web_application_target_id).to_bytes())
    }
}

impl GmpRequest for CloneWebApplicationTargetRequest {
    type Response = CreateWebApplicationTargetResponse;
}

/// Semantic request for creating a web application target.
#[derive(Debug, Clone)]
pub struct CreateWebApplicationTargetRequest {
    /// Resource name.
    pub name: String,
    /// URLs to scan.
    pub urls: Vec<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// URLs to exclude from the scan.
    pub exclude_urls: Vec<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

impl CreateWebApplicationTargetRequest {
    /// Create a web-application-target request with its required fields.
    #[must_use]
    pub fn new(name: impl Into<String>, urls: Vec<String>) -> Self {
        Self {
            name: name.into(),
            urls,
            comment: None,
            exclude_urls: Vec::new(),
            credential_id: None,
        }
    }
}

impl GmpRequestCodec for CreateWebApplicationTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_web_application_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_web_application_target_command(self).to_bytes())
    }
}

impl GmpRequest for CreateWebApplicationTargetRequest {
    type Response = CreateWebApplicationTargetResponse;
}

/// Semantic request for listing web application targets.
#[derive(Debug, Clone, Default)]
pub struct GetWebApplicationTargetsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to include tasks that use the target.
    pub tasks: Option<bool>,
}

impl GmpRequestCodec for GetWebApplicationTargetsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_web_application_targets"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_web_application_targets_command(self).to_bytes())
    }
}

impl GmpRequest for GetWebApplicationTargetsRequest {
    type Response = GetWebApplicationTargetsResponse;
}

/// Semantic request for one detailed web application target.
#[derive(Debug, Clone)]
pub struct GetWebApplicationTargetRequest {
    /// Web application target identifier to retrieve.
    pub web_application_target_id: EntityId,
    /// Whether to include tasks that use the target.
    pub tasks: Option<bool>,
}

impl GetWebApplicationTargetRequest {
    /// Create a detailed web-application-target request.
    #[must_use]
    pub fn new(web_application_target_id: EntityId) -> Self {
        Self {
            web_application_target_id,
            tasks: None,
        }
    }
}

impl GmpRequestCodec for GetWebApplicationTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_web_application_targets",
            "get_web_application_target",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_web_application_target_command(self).to_bytes())
    }
}

impl GmpRequest for GetWebApplicationTargetRequest {
    type Response = GetWebApplicationTargetsResponse;
}

/// Semantic request for modifying a web application target.
#[derive(Debug, Clone)]
pub struct ModifyWebApplicationTargetRequest {
    /// Web application target identifier to modify.
    pub web_application_target_id: EntityId,
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// URLs to scan. An empty list omits the element.
    pub urls: Vec<String>,
    /// URLs to exclude from the scan. An empty list omits the element.
    pub exclude_urls: Vec<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

impl ModifyWebApplicationTargetRequest {
    /// Create a web-application-target modification request with no field updates.
    #[must_use]
    pub fn new(web_application_target_id: EntityId) -> Self {
        Self {
            web_application_target_id,
            name: None,
            comment: None,
            urls: Vec::new(),
            exclude_urls: Vec::new(),
            credential_id: None,
        }
    }
}

impl GmpRequestCodec for ModifyWebApplicationTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_web_application_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_web_application_target_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyWebApplicationTargetRequest {
    type Response = ModifyWebApplicationTargetResponse;
}

/// Semantic request for deleting a web application target.
#[derive(Debug, Clone)]
pub struct DeleteWebApplicationTargetRequest {
    /// Web application target identifier to delete.
    pub web_application_target_id: EntityId,
    /// Whether to delete permanently instead of moving the target to trash.
    pub ultimate: bool,
}

impl DeleteWebApplicationTargetRequest {
    /// Create a web-application-target deletion request.
    #[must_use]
    pub fn new(web_application_target_id: EntityId, ultimate: bool) -> Self {
        Self {
            web_application_target_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteWebApplicationTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_web_application_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_web_application_target_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteWebApplicationTargetRequest {
    type Response = DeleteWebApplicationTargetResponse;
}

fn clone_web_application_target_command(web_application_target_id: &EntityId) -> XmlCommand {
    XmlCommand::new("create_web_application_target")
        .child_with_text("copy", web_application_target_id.as_str())
}

fn create_web_application_target_command(
    request: &CreateWebApplicationTargetRequest,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_web_application_target");
    cmd.add_element_with_text("name", &request.name);
    cmd.add_element_with_text("urls", &request.urls.join(","));
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_string_list_text(&mut cmd, "exclude_urls", &request.exclude_urls);
    add_optional_id_element(&mut cmd, "credential", request.credential_id.as_ref());
    cmd
}

fn get_web_application_targets_command(request: &GetWebApplicationTargetsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_web_application_targets");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "tasks", request.tasks);
    cmd
}

fn get_web_application_target_command(request: &GetWebApplicationTargetRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_web_application_targets").attribute(
        "web_application_target_id",
        request.web_application_target_id.as_str(),
    );
    set_optional_bool_attr(&mut cmd, "tasks", request.tasks);
    cmd
}

fn modify_web_application_target_command(
    request: &ModifyWebApplicationTargetRequest,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_web_application_target").attribute(
        "web_application_target_id",
        request.web_application_target_id.as_str(),
    );
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_text_element(&mut cmd, "name", request.name.as_deref());
    add_string_list_text(&mut cmd, "urls", &request.urls);
    add_string_list_text(&mut cmd, "exclude_urls", &request.exclude_urls);
    add_optional_id_element(&mut cmd, "credential", request.credential_id.as_ref());
    cmd
}

fn delete_web_application_target_command(
    request: &DeleteWebApplicationTargetRequest,
) -> XmlCommand {
    XmlCommand::new("delete_web_application_target")
        .attribute(
            "web_application_target_id",
            request.web_application_target_id.as_str(),
        )
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
                .expect("valid web application target request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        let mut create = CreateWebApplicationTargetRequest::new(
            "web",
            vec![
                "https://example.com".into(),
                "https://example.com/app".into(),
            ],
        );
        create.comment = Some("note".into());
        create.exclude_urls = vec!["https://example.com/logout".into()];
        create.credential_id = Some(id("cred-1"));
        assert_eq!(
            request_xml(&create),
            "<create_web_application_target><name>web</name><urls>https://example.com,https://example.com/app</urls><comment>note</comment><exclude_urls>https://example.com/logout</exclude_urls><credential id=\"cred-1\"/></create_web_application_target>"
        );
        assert_eq!(
            request_xml(&CloneWebApplicationTargetRequest::new(id("target-1"))),
            "<create_web_application_target><copy>target-1</copy></create_web_application_target>"
        );
        assert_eq!(
            request_xml(&GetWebApplicationTargetsRequest {
                filter_string: Some("name=web".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(false),
                tasks: Some(true),
            }),
            "<get_web_application_targets filt_id=\"filter-1\" filter=\"name=web\" tasks=\"1\" trash=\"0\"/>"
        );
        let mut detail = GetWebApplicationTargetRequest::new(id("target-1"));
        detail.tasks = Some(false);
        assert_eq!(
            request_xml(&detail),
            "<get_web_application_targets tasks=\"0\" web_application_target_id=\"target-1\"/>"
        );
        let mut modify = ModifyWebApplicationTargetRequest::new(id("target-1"));
        modify.name = Some("updated".into());
        modify.comment = Some("changed".into());
        modify.urls = vec!["https://example.com".into()];
        modify.exclude_urls = vec!["https://example.com/logout".into()];
        modify.credential_id = Some(id("cred-1"));
        assert_eq!(
            request_xml(&modify),
            "<modify_web_application_target web_application_target_id=\"target-1\"><comment>changed</comment><name>updated</name><urls>https://example.com</urls><exclude_urls>https://example.com/logout</exclude_urls><credential id=\"cred-1\"/></modify_web_application_target>"
        );
        assert_eq!(
            request_xml(&DeleteWebApplicationTargetRequest::new(id("target-1"), true)),
            "<delete_web_application_target ultimate=\"1\" web_application_target_id=\"target-1\"/>"
        );
    }

    #[test]
    fn requests_expose_semantic_capability_metadata() {
        assert_eq!(
            CloneWebApplicationTargetRequest::new(id("target-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "create_web_application_target",
                "clone_web_application_target"
            ))
        );
        assert_eq!(
            CreateWebApplicationTargetRequest::new("web", vec![]).command(),
            Some(GmpCommand::new("create_web_application_target"))
        );
        assert_eq!(
            GetWebApplicationTargetsRequest::default().command(),
            Some(GmpCommand::new("get_web_application_targets"))
        );
        assert_eq!(
            GetWebApplicationTargetRequest::new(id("target-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "get_web_application_targets",
                "get_web_application_target"
            ))
        );
        assert_eq!(
            ModifyWebApplicationTargetRequest::new(id("target-1")).command(),
            Some(GmpCommand::new("modify_web_application_target"))
        );
        assert_eq!(
            DeleteWebApplicationTargetRequest::new(id("target-1"), false).command(),
            Some(GmpCommand::new("delete_web_application_target"))
        );
    }

    #[test]
    fn requests_remain_statically_associated_with_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_response::<_, CreateWebApplicationTargetResponse>(
            &CloneWebApplicationTargetRequest::new(id("target-1")),
        );
        assert_response::<_, CreateWebApplicationTargetResponse>(
            &CreateWebApplicationTargetRequest::new("web", vec![]),
        );
        assert_response::<_, GetWebApplicationTargetsResponse>(
            &GetWebApplicationTargetsRequest::default(),
        );
        assert_response::<_, GetWebApplicationTargetsResponse>(
            &GetWebApplicationTargetRequest::new(id("target-1")),
        );
        assert_response::<_, ModifyWebApplicationTargetResponse>(
            &ModifyWebApplicationTargetRequest::new(id("target-1")),
        );
        assert_response::<_, DeleteWebApplicationTargetResponse>(
            &DeleteWebApplicationTargetRequest::new(id("target-1"), false),
        );
    }
}
