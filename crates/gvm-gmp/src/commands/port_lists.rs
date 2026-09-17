// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for port-list and port-range operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::PortRangeType;
use crate::responses::{
    CreatePortListResponse, CreatePortRangeResponse, DeletePortListResponse,
    DeletePortRangeResponse, GetPortListsResponse, ModifyPortListResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Semantic request for listing port lists.
#[derive(Debug, Clone, Default)]
pub struct GetPortListsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetPortListsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_port_lists"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_port_lists_command(self).to_bytes())
    }
}

impl GmpRequest for GetPortListsRequest {
    type Response = GetPortListsResponse;
}

/// Semantic request for one port list.
#[derive(Debug, Clone)]
pub struct GetPortListRequest {
    /// Port-list identifier to retrieve.
    pub port_list_id: EntityId,
}

impl GetPortListRequest {
    /// Create a single port-list request.
    #[must_use]
    pub fn new(port_list_id: EntityId) -> Self {
        Self { port_list_id }
    }
}

impl GmpRequestCodec for GetPortListRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_port_lists",
            "get_port_list",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_port_list_command(&self.port_list_id).to_bytes())
    }
}

impl GmpRequest for GetPortListRequest {
    type Response = GetPortListsResponse;
}

/// Semantic request for creating a port list.
#[derive(Debug, Clone)]
pub struct CreatePortListRequest {
    /// Resource name.
    pub name: String,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional GMP port-range expression used to initialize the list.
    pub port_range: Option<String>,
}

impl CreatePortListRequest {
    /// Create a port-list creation request.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            port_range: None,
        }
    }
}

impl GmpRequestCodec for CreatePortListRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_port_list"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_port_list_command(self).to_bytes())
    }
}

impl GmpRequest for CreatePortListRequest {
    type Response = CreatePortListResponse;
}

/// Semantic request for cloning a port list.
#[derive(Debug, Clone)]
pub struct ClonePortListRequest {
    /// Existing port-list identifier to copy.
    pub port_list_id: EntityId,
}

impl ClonePortListRequest {
    /// Create a port-list clone request.
    #[must_use]
    pub fn new(port_list_id: EntityId) -> Self {
        Self { port_list_id }
    }
}

impl GmpRequestCodec for ClonePortListRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_port_list",
            "clone_port_list",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_port_list_command(&self.port_list_id).to_bytes())
    }
}

impl GmpRequest for ClonePortListRequest {
    type Response = CreatePortListResponse;
}

/// Semantic request for replacing a port list's mutable fields.
///
/// gvmd stores an empty value for each omitted field. Port ranges are changed
/// separately with [`CreatePortRangeRequest`] and [`DeletePortRangeRequest`].
#[derive(Debug, Clone)]
pub struct ModifyPortListRequest {
    /// Port-list identifier to modify.
    pub port_list_id: EntityId,
    /// Replacement name. Omission clears the current name.
    pub name: Option<String>,
    /// Replacement comment. Omission clears the current comment.
    pub comment: Option<String>,
}

impl ModifyPortListRequest {
    /// Create a port-list replacement request.
    #[must_use]
    pub fn new(port_list_id: EntityId) -> Self {
        Self {
            port_list_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for ModifyPortListRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_port_list"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_port_list_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyPortListRequest {
    type Response = ModifyPortListResponse;
}

/// Semantic request for deleting a port list.
#[derive(Debug, Clone)]
pub struct DeletePortListRequest {
    /// Port-list identifier to delete.
    pub port_list_id: EntityId,
    /// Whether to delete permanently instead of moving the list to trash.
    pub ultimate: bool,
}

impl DeletePortListRequest {
    /// Create a port-list deletion request.
    #[must_use]
    pub fn new(port_list_id: EntityId, ultimate: bool) -> Self {
        Self {
            port_list_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeletePortListRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_port_list"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_port_list_command(self).to_bytes())
    }
}

impl GmpRequest for DeletePortListRequest {
    type Response = DeletePortListResponse;
}

/// Semantic request for adding a range to a port list.
#[derive(Debug, Clone)]
pub struct CreatePortRangeRequest {
    /// Port-list identifier that receives the range.
    pub port_list_id: EntityId,
    /// Optional comment attached to the range.
    pub comment: Option<String>,
    /// Transport protocol represented by the range.
    pub range_type: PortRangeType,
    /// First port in the inclusive range.
    pub start: u16,
    /// Last port in the inclusive range.
    pub end: u16,
}

impl CreatePortRangeRequest {
    /// Create a port-range creation request.
    #[must_use]
    pub fn new(port_list_id: EntityId, range_type: PortRangeType, start: u16, end: u16) -> Self {
        Self {
            port_list_id,
            comment: None,
            range_type,
            start,
            end,
        }
    }
}

impl GmpRequestCodec for CreatePortRangeRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.start == 0 {
            return Err(GmpRequestError::invalid_field(
                "start",
                "must be between 1 and 65535",
            ));
        }
        if self.end == 0 {
            return Err(GmpRequestError::invalid_field(
                "end",
                "must be between 1 and 65535",
            ));
        }
        if self.start > self.end {
            return Err(GmpRequestError::invalid_combination(
                &["start", "end"],
                "start must not exceed end",
            ));
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_port_range"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_port_range_command(self).to_bytes())
    }
}

impl GmpRequest for CreatePortRangeRequest {
    type Response = CreatePortRangeResponse;
}

/// Semantic request for deleting a port range.
#[derive(Debug, Clone)]
pub struct DeletePortRangeRequest {
    /// Port-range identifier to delete.
    pub port_range_id: EntityId,
}

impl DeletePortRangeRequest {
    /// Create a port-range deletion request.
    #[must_use]
    pub fn new(port_range_id: EntityId) -> Self {
        Self { port_range_id }
    }
}

impl GmpRequestCodec for DeletePortRangeRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_port_range"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_port_range_command(&self.port_range_id).to_bytes())
    }
}

impl GmpRequest for DeletePortRangeRequest {
    type Response = DeletePortRangeResponse;
}

fn get_port_lists_command(request: &GetPortListsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_port_lists");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_port_list_command(port_list_id: &EntityId) -> XmlCommand {
    XmlCommand::new("get_port_lists")
        .attribute("port_list_id", port_list_id.as_str())
        .attribute("details", "1")
}

fn create_port_list_command(request: &CreatePortListRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_port_list");
    cmd.add_element_with_text("name", &request.name);
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_text_element(&mut cmd, "port_range", request.port_range.as_deref());
    cmd
}

fn clone_port_list_command(port_list_id: &EntityId) -> XmlCommand {
    XmlCommand::new("create_port_list").child_with_text("copy", port_list_id.as_str())
}

fn modify_port_list_command(request: &ModifyPortListRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_port_list")
        .attribute("port_list_id", request.port_list_id.as_str());
    add_text_element(&mut cmd, "name", request.name.as_deref());
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd
}

fn delete_port_list_command(request: &DeletePortListRequest) -> XmlCommand {
    XmlCommand::new("delete_port_list")
        .attribute("port_list_id", request.port_list_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn create_port_range_command(request: &CreatePortRangeRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_port_range");
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element("port_list")
        .set_attribute("id", request.port_list_id.as_str());
    cmd.add_element_with_text("start", &request.start.to_string());
    cmd.add_element_with_text("end", &request.end.to_string());
    cmd.add_element_with_text("type", request.range_type.as_port_range_type());
    cmd
}

fn delete_port_range_command(port_range_id: &EntityId) -> XmlCommand {
    XmlCommand::new("delete_port_range").attribute("port_range_id", port_range_id.as_str())
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
                .expect("valid port-list request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetPortListsRequest {
                filter_string: Some("name=web".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(true),
                details: Some(false),
            }),
            "<get_port_lists details=\"0\" filt_id=\"filter-1\" filter=\"name=web\" trash=\"1\"/>"
        );
        assert_eq!(
            request_xml(&GetPortListRequest::new(id("port-list-1"))),
            "<get_port_lists details=\"1\" port_list_id=\"port-list-1\"/>"
        );

        let mut create = CreatePortListRequest::new("web");
        create.comment = Some("web services".into());
        create.port_range = Some("T:80,443".into());
        assert_eq!(
            request_xml(&create),
            "<create_port_list><name>web</name><comment>web services</comment><port_range>T:80,443</port_range></create_port_list>"
        );
        assert_eq!(
            request_xml(&ClonePortListRequest::new(id("port-list-1"))),
            "<create_port_list><copy>port-list-1</copy></create_port_list>"
        );

        let mut modify = ModifyPortListRequest::new(id("port-list-1"));
        modify.name = Some("renamed".into());
        modify.comment = Some(String::new());
        assert_eq!(
            request_xml(&modify),
            "<modify_port_list port_list_id=\"port-list-1\"><name>renamed</name></modify_port_list>"
        );
        assert_eq!(
            request_xml(&ModifyPortListRequest::new(id("port-list-1"))),
            "<modify_port_list port_list_id=\"port-list-1\"/>"
        );
        assert_eq!(
            request_xml(&DeletePortListRequest::new(id("port-list-1"), false)),
            "<delete_port_list port_list_id=\"port-list-1\" ultimate=\"0\"/>"
        );
        let mut create_range =
            CreatePortRangeRequest::new(id("port-list-1"), PortRangeType::Tcp, 80, 443);
        create_range.comment = Some("web ports".into());
        assert_eq!(
            request_xml(&create_range),
            "<create_port_range><comment>web ports</comment><port_list id=\"port-list-1\"/><start>80</start><end>443</end><type>TCP</type></create_port_range>"
        );
        assert_eq!(
            request_xml(&DeletePortRangeRequest::new(id("port-range-1"))),
            "<delete_port_range port_range_id=\"port-range-1\"/>"
        );
    }

    #[test]
    fn create_port_range_validates_the_final_value() {
        assert_eq!(
            CreatePortRangeRequest::new(id("port-list-1"), PortRangeType::Tcp, 1, 65_535)
                .validate(),
            Ok(())
        );
        assert!(matches!(
            CreatePortRangeRequest::new(id("port-list-1"), PortRangeType::Tcp, 0, 443).validate(),
            Err(GmpRequestError::InvalidField { field: "start", .. })
        ));
        assert!(matches!(
            CreatePortRangeRequest::new(id("port-list-1"), PortRangeType::Tcp, 80, 0).validate(),
            Err(GmpRequestError::InvalidField { field: "end", .. })
        ));
        assert!(matches!(
            CreatePortRangeRequest::new(id("port-list-1"), PortRangeType::Tcp, 443, 80).validate(),
            Err(GmpRequestError::InvalidCombination {
                fields: &["start", "end"],
                ..
            })
        ));
    }

    #[test]
    fn requests_expose_semantic_capability_metadata() {
        assert_eq!(
            GetPortListsRequest::default().command(),
            Some(GmpCommand::new("get_port_lists"))
        );
        assert_eq!(
            GetPortListRequest::new(id("port-list-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "get_port_lists",
                "get_port_list"
            ))
        );
        assert_eq!(
            CreatePortListRequest::new("web").command(),
            Some(GmpCommand::new("create_port_list"))
        );
        assert_eq!(
            ClonePortListRequest::new(id("port-list-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "create_port_list",
                "clone_port_list"
            ))
        );
        assert_eq!(
            ModifyPortListRequest::new(id("port-list-1")).command(),
            Some(GmpCommand::new("modify_port_list"))
        );
        assert_eq!(
            DeletePortListRequest::new(id("port-list-1"), false).command(),
            Some(GmpCommand::new("delete_port_list"))
        );
        assert_eq!(
            CreatePortRangeRequest::new(id("port-list-1"), PortRangeType::Udp, 53, 53).command(),
            Some(GmpCommand::new("create_port_range"))
        );
        assert_eq!(
            DeletePortRangeRequest::new(id("port-range-1")).command(),
            Some(GmpCommand::new("delete_port_range"))
        );
    }

    #[test]
    fn requests_remain_statically_associated_with_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_response::<_, GetPortListsResponse>(&GetPortListsRequest::default());
        assert_response::<_, GetPortListsResponse>(&GetPortListRequest::new(id("port-list-1")));
        assert_response::<_, CreatePortListResponse>(&CreatePortListRequest::new("web"));
        assert_response::<_, CreatePortListResponse>(&ClonePortListRequest::new(id("port-list-1")));
        assert_response::<_, ModifyPortListResponse>(&ModifyPortListRequest::new(id(
            "port-list-1",
        )));
        assert_response::<_, DeletePortListResponse>(&DeletePortListRequest::new(
            id("port-list-1"),
            false,
        ));
        assert_response::<_, CreatePortRangeResponse>(&CreatePortRangeRequest::new(
            id("port-list-1"),
            PortRangeType::Tcp,
            80,
            443,
        ));
        assert_response::<_, DeletePortRangeResponse>(&DeletePortRangeRequest::new(id(
            "port-range-1",
        )));
    }
}
