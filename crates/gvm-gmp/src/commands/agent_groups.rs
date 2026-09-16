// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for agent-group operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CloneAgentGroupResponse, CreateAgentGroupResponse, DeleteAgentGroupResponse,
    GetAgentGroupsResponse, ModifyAgentGroupResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Semantic request for cloning an agent group.
#[derive(Debug, Clone)]
pub struct CloneAgentGroupRequest {
    /// Existing agent-group identifier to copy.
    pub agent_group_id: EntityId,
}

impl CloneAgentGroupRequest {
    /// Create an agent-group clone request.
    #[must_use]
    pub fn new(agent_group_id: EntityId) -> Self {
        Self { agent_group_id }
    }
}

impl GmpRequestCodec for CloneAgentGroupRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_agent_group",
            "clone_agent_group",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_agent_group_command(&self.agent_group_id).to_bytes())
    }
}

impl GmpRequest for CloneAgentGroupRequest {
    type Response = CloneAgentGroupResponse;
}

/// Semantic request for creating an agent group.
#[derive(Debug, Clone)]
pub struct CreateAgentGroupRequest {
    /// Resource name.
    pub name: String,
    /// Agents assigned to the group.
    pub agent_ids: Vec<EntityId>,
    /// Scheduler cron expression used to synchronize the group.
    pub scheduler_cron_time: String,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
}

impl CreateAgentGroupRequest {
    /// Create an agent-group creation request with its required fields.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        agent_ids: Vec<EntityId>,
        scheduler_cron_time: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            agent_ids,
            scheduler_cron_time: scheduler_cron_time.into(),
            comment: None,
        }
    }
}

impl GmpRequestCodec for CreateAgentGroupRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_agent_group"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_agent_group_command(self).to_bytes())
    }
}

impl GmpRequest for CreateAgentGroupRequest {
    type Response = CreateAgentGroupResponse;
}

/// Semantic request for listing agent groups.
#[derive(Debug, Clone, Default)]
pub struct GetAgentGroupsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
}

impl GmpRequestCodec for GetAgentGroupsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_agent_groups"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_agent_groups_command(self).to_bytes())
    }
}

impl GmpRequest for GetAgentGroupsRequest {
    type Response = GetAgentGroupsResponse;
}

/// Semantic request for one agent group.
#[derive(Debug, Clone)]
pub struct GetAgentGroupRequest {
    /// Agent-group identifier to retrieve.
    pub agent_group_id: EntityId,
}

impl GetAgentGroupRequest {
    /// Create a single agent-group request.
    #[must_use]
    pub fn new(agent_group_id: EntityId) -> Self {
        Self { agent_group_id }
    }
}

impl GmpRequestCodec for GetAgentGroupRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_agent_groups",
            "get_agent_group",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_agent_group_command(&self.agent_group_id).to_bytes())
    }
}

impl GmpRequest for GetAgentGroupRequest {
    type Response = GetAgentGroupsResponse;
}

/// Semantic request for modifying an agent group.
#[derive(Debug, Clone)]
pub struct ModifyAgentGroupRequest {
    /// Agent-group identifier to modify.
    pub agent_group_id: EntityId,
    /// Scheduler cron expression used to synchronize the group.
    pub scheduler_cron_time: String,
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Agents assigned to the group. An empty list omits the element.
    pub agent_ids: Vec<EntityId>,
}

impl ModifyAgentGroupRequest {
    /// Create an agent-group modification request with its required fields.
    #[must_use]
    pub fn new(agent_group_id: EntityId, scheduler_cron_time: impl Into<String>) -> Self {
        Self {
            agent_group_id,
            scheduler_cron_time: scheduler_cron_time.into(),
            name: None,
            comment: None,
            agent_ids: Vec::new(),
        }
    }
}

impl GmpRequestCodec for ModifyAgentGroupRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_agent_group"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_agent_group_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyAgentGroupRequest {
    type Response = ModifyAgentGroupResponse;
}

/// Semantic request for deleting an agent group.
#[derive(Debug, Clone)]
pub struct DeleteAgentGroupRequest {
    /// Agent-group identifier to delete.
    pub agent_group_id: EntityId,
    /// Whether to delete permanently instead of moving the group to trash.
    pub ultimate: bool,
}

impl DeleteAgentGroupRequest {
    /// Create an agent-group deletion request.
    #[must_use]
    pub fn new(agent_group_id: EntityId, ultimate: bool) -> Self {
        Self {
            agent_group_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteAgentGroupRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_agent_group"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_agent_group_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteAgentGroupRequest {
    type Response = DeleteAgentGroupResponse;
}

fn clone_agent_group_command(agent_group_id: &EntityId) -> XmlCommand {
    XmlCommand::new("create_agent_group").child_with_text("copy", agent_group_id.as_str())
}

fn create_agent_group_command(request: &CreateAgentGroupRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_agent_group");
    cmd.add_element_with_text("name", &request.name);
    cmd.add_element_with_text("scheduler_cron_time", &request.scheduler_cron_time);
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_agent_elements(&mut cmd, &request.agent_ids);
    cmd
}

fn get_agent_groups_command(request: &GetAgentGroupsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_agent_groups");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    cmd
}

fn get_agent_group_command(agent_group_id: &EntityId) -> XmlCommand {
    XmlCommand::new("get_agent_groups").attribute("agent_group_id", agent_group_id.as_str())
}

fn modify_agent_group_command(request: &ModifyAgentGroupRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_agent_group")
        .attribute("agent_group_id", request.agent_group_id.as_str());
    cmd.add_element_with_text("scheduler_cron_time", &request.scheduler_cron_time);
    add_text_element(&mut cmd, "name", request.name.as_deref());
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_agent_elements(&mut cmd, &request.agent_ids);
    cmd
}

fn delete_agent_group_command(request: &DeleteAgentGroupRequest) -> XmlCommand {
    XmlCommand::new("delete_agent_group")
        .attribute("agent_group_id", request.agent_group_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn add_agent_elements(cmd: &mut XmlCommand, agent_ids: &[EntityId]) {
    if agent_ids.is_empty() {
        return;
    }

    let agents = cmd.add_element("agents");
    for agent_id in agent_ids {
        agents
            .add_child("agent")
            .set_attribute("id", agent_id.as_str());
    }
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
                .expect("valid agent-group request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        let mut create = CreateAgentGroupRequest::new(
            "agents",
            vec![id("agent-1"), id("agent-2")],
            "0 */5 * * *",
        );
        create.comment = Some("scheduled".into());
        assert_eq!(
            request_xml(&create),
            "<create_agent_group><name>agents</name><scheduler_cron_time>0 */5 * * *</scheduler_cron_time><comment>scheduled</comment><agents><agent id=\"agent-1\"/><agent id=\"agent-2\"/></agents></create_agent_group>"
        );
        assert_eq!(
            request_xml(&CloneAgentGroupRequest::new(id("group-1"))),
            "<create_agent_group><copy>group-1</copy></create_agent_group>"
        );
        assert_eq!(
            request_xml(&GetAgentGroupsRequest {
                filter_string: Some("name=agents".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(true),
            }),
            "<get_agent_groups filt_id=\"filter-1\" filter=\"name=agents\" trash=\"1\"/>"
        );
        assert_eq!(
            request_xml(&GetAgentGroupRequest::new(id("group-1"))),
            "<get_agent_groups agent_group_id=\"group-1\"/>"
        );
        let mut modify = ModifyAgentGroupRequest::new(id("group-1"), "0 */10 * * *");
        modify.name = Some("updated".into());
        modify.comment = Some("changed".into());
        modify.agent_ids = vec![id("agent-3")];
        assert_eq!(
            request_xml(&modify),
            "<modify_agent_group agent_group_id=\"group-1\"><scheduler_cron_time>0 */10 * * *</scheduler_cron_time><name>updated</name><comment>changed</comment><agents><agent id=\"agent-3\"/></agents></modify_agent_group>"
        );
        assert_eq!(
            request_xml(&DeleteAgentGroupRequest::new(id("group-1"), false)),
            "<delete_agent_group agent_group_id=\"group-1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn requests_expose_semantic_capability_metadata() {
        assert_eq!(
            CloneAgentGroupRequest::new(id("group-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "create_agent_group",
                "clone_agent_group"
            ))
        );
        assert_eq!(
            CreateAgentGroupRequest::new("agents", vec![], "0 */5 * * *").command(),
            Some(GmpCommand::new("create_agent_group"))
        );
        assert_eq!(
            GetAgentGroupsRequest::default().command(),
            Some(GmpCommand::new("get_agent_groups"))
        );
        assert_eq!(
            GetAgentGroupRequest::new(id("group-1")).command(),
            Some(GmpCommand::with_semantic_name(
                "get_agent_groups",
                "get_agent_group"
            ))
        );
        assert_eq!(
            ModifyAgentGroupRequest::new(id("group-1"), "0 */5 * * *").command(),
            Some(GmpCommand::new("modify_agent_group"))
        );
        assert_eq!(
            DeleteAgentGroupRequest::new(id("group-1"), false).command(),
            Some(GmpCommand::new("delete_agent_group"))
        );
    }

    #[test]
    fn requests_remain_statically_associated_with_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_response::<_, CloneAgentGroupResponse>(&CloneAgentGroupRequest::new(id("group-1")));
        assert_response::<_, CreateAgentGroupResponse>(&CreateAgentGroupRequest::new(
            "agents",
            vec![],
            "0 */5 * * *",
        ));
        assert_response::<_, GetAgentGroupsResponse>(&GetAgentGroupsRequest::default());
        assert_response::<_, GetAgentGroupsResponse>(&GetAgentGroupRequest::new(id("group-1")));
        assert_response::<_, ModifyAgentGroupResponse>(&ModifyAgentGroupRequest::new(
            id("group-1"),
            "0 */5 * * *",
        ));
        assert_response::<_, DeleteAgentGroupResponse>(&DeleteAgentGroupRequest::new(
            id("group-1"),
            false,
        ));
    }
}
