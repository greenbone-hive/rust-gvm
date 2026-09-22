// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for standard target operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_scalar_id_update, add_text_element, bool_str,
    set_optional_bool_attr,
};
use crate::enums::AliveTest;
use crate::responses::{
    CreateTargetResponse, DeleteTargetResponse, GetTargetsResponse, ModifyTargetResponse,
};
use crate::target::{TargetHost, TargetHosts, TargetPortSelection};
use crate::types::{EntityId, ScalarUpdate, ServicePort};
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Semantic request for listing targets.
#[derive(Debug, Clone, Default)]
pub struct GetTargetsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetTargetsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_targets"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_targets_command(self).to_bytes())
    }
}

impl GmpRequest for GetTargetsRequest {
    type Response = GetTargetsResponse;
}

/// Semantic request for one detailed target.
#[derive(Debug, Clone)]
pub struct GetTargetRequest {
    /// Target identifier to retrieve.
    pub target_id: EntityId,
}

impl GetTargetRequest {
    /// Create a detailed single-target request.
    #[must_use]
    pub fn new(target_id: EntityId) -> Self {
        Self { target_id }
    }
}

impl GmpRequestCodec for GetTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_targets", "get_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_target_command(&self.target_id).to_bytes())
    }
}

impl GmpRequest for GetTargetRequest {
    type Response = GetTargetsResponse;
}

/// Semantic request for creating a target.
#[derive(Debug, Clone)]
pub struct CreateTargetRequest {
    /// Resource name.
    pub name: String,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Validated included and excluded target hosts.
    pub hosts: TargetHosts,
    /// Optional alive-test strategy.
    pub alive_test: Option<AliveTest>,
    /// Required port list or direct port range.
    pub ports: TargetPortSelection,
    /// Optional SSH credential identifier.
    pub ssh_credential_id: Option<EntityId>,
    /// Optional SSH service port nested below the SSH credential.
    pub ssh_credential_port: Option<ServicePort>,
    /// Optional SSH privilege-escalation credential identifier.
    pub ssh_elevate_credential_id: Option<EntityId>,
    /// Optional SMB credential identifier.
    pub smb_credential_id: Option<EntityId>,
    /// Optional Kerberos 5 credential identifier.
    pub krb5_credential_id: Option<EntityId>,
    /// Optional `ESXi` credential identifier.
    pub esxi_credential_id: Option<EntityId>,
    /// Optional SNMP credential identifier.
    pub snmp_credential_id: Option<EntityId>,
    /// Whether reverse lookup only should be enabled.
    pub reverse_lookup_only: Option<bool>,
    /// Whether reverse-lookup unification should be enabled.
    pub reverse_lookup_unify: Option<bool>,
    /// Whether multiple IP addresses of one host may be scanned simultaneously.
    pub allow_simultaneous_ips: Option<bool>,
}

impl CreateTargetRequest {
    /// Create a target request with its required fields.
    #[must_use]
    pub fn new(name: impl Into<String>, hosts: TargetHosts, ports: TargetPortSelection) -> Self {
        Self {
            name: name.into(),
            comment: None,
            hosts,
            alive_test: None,
            ports,
            ssh_credential_id: None,
            ssh_credential_port: None,
            ssh_elevate_credential_id: None,
            smb_credential_id: None,
            krb5_credential_id: None,
            esxi_credential_id: None,
            snmp_credential_id: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            allow_simultaneous_ips: None,
        }
    }
}

impl GmpRequestCodec for CreateTargetRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_create_target(self)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_target_command(self).to_bytes())
    }
}

impl GmpRequest for CreateTargetRequest {
    type Response = CreateTargetResponse;
}

/// Semantic request for modifying a target.
#[derive(Debug, Clone)]
pub struct ModifyTargetRequest {
    /// Target identifier to modify.
    pub target_id: EntityId,
    /// Optional resource name.
    pub name: Option<String>,
    /// Comment update: `None` preserves it, while `Some("")` clears it.
    pub comment: Option<String>,
    /// Atomic replacement of included and excluded hosts, or `None` to omit.
    pub hosts: Option<TargetHosts>,
    /// Optional alive-test strategy.
    pub alive_test: Option<AliveTest>,
    /// Port-list relationship update: omit or set/replace.
    ///
    /// Current gvmd versions do not support detaching an existing port list.
    pub port_list_id: ScalarUpdate<EntityId>,
    /// SSH credential relationship update: omit, set, or detach.
    pub ssh_credential_id: ScalarUpdate<EntityId>,
    /// SSH service-port update: omit, set/replace, or reset to gvmd's default.
    ///
    /// Setting or clearing the port requires [`Self::ssh_credential_id`] to
    /// contain [`ScalarUpdate::Set`] because GMP nests the port below a
    /// credential element carrying the credential identifier.
    pub ssh_credential_port: ScalarUpdate<ServicePort>,
    /// SSH privilege-escalation credential relationship update: omit, set, or detach.
    pub ssh_elevate_credential_id: ScalarUpdate<EntityId>,
    /// SMB credential relationship update: omit, set, or detach.
    pub smb_credential_id: ScalarUpdate<EntityId>,
    /// Kerberos 5 credential relationship update: omit, set, or detach.
    pub krb5_credential_id: ScalarUpdate<EntityId>,
    /// `ESXi` credential relationship update: omit, set, or detach.
    pub esxi_credential_id: ScalarUpdate<EntityId>,
    /// SNMP credential relationship update: omit, set, or detach.
    pub snmp_credential_id: ScalarUpdate<EntityId>,
    /// Whether reverse lookup only should be enabled.
    pub reverse_lookup_only: Option<bool>,
    /// Whether reverse-lookup unification should be enabled.
    pub reverse_lookup_unify: Option<bool>,
    /// Whether multiple IP addresses of one host may be scanned simultaneously.
    pub allow_simultaneous_ips: Option<bool>,
}

impl ModifyTargetRequest {
    /// Create a target-modification request with no field updates.
    #[must_use]
    pub fn new(target_id: EntityId) -> Self {
        Self {
            target_id,
            name: None,
            comment: None,
            hosts: None,
            alive_test: None,
            port_list_id: ScalarUpdate::Omitted,
            ssh_credential_id: ScalarUpdate::Omitted,
            ssh_credential_port: ScalarUpdate::Omitted,
            ssh_elevate_credential_id: ScalarUpdate::Omitted,
            smb_credential_id: ScalarUpdate::Omitted,
            krb5_credential_id: ScalarUpdate::Omitted,
            esxi_credential_id: ScalarUpdate::Omitted,
            snmp_credential_id: ScalarUpdate::Omitted,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            allow_simultaneous_ips: None,
        }
    }
}

impl GmpRequestCodec for ModifyTargetRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_modify_target(self)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_target_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyTargetRequest {
    type Response = ModifyTargetResponse;
}

/// Semantic request for deleting a target.
#[derive(Debug, Clone)]
pub struct DeleteTargetRequest {
    /// Target identifier to delete.
    pub target_id: EntityId,
    /// Whether to delete permanently instead of moving the target to trash.
    pub ultimate: bool,
}

impl DeleteTargetRequest {
    /// Create a target-deletion request.
    #[must_use]
    pub fn new(target_id: EntityId, ultimate: bool) -> Self {
        Self {
            target_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_target"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_target_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteTargetRequest {
    type Response = DeleteTargetResponse;
}

/// Semantic request for cloning a target.
#[derive(Debug, Clone)]
pub struct CloneTargetRequest {
    /// Existing target identifier to copy.
    pub target_id: EntityId,
}

impl CloneTargetRequest {
    /// Create a target-clone request.
    #[must_use]
    pub fn new(target_id: EntityId) -> Self {
        Self { target_id }
    }
}

impl GmpRequestCodec for CloneTargetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_target",
            "clone_target",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_target_command(&self.target_id).to_bytes())
    }
}

impl GmpRequest for CloneTargetRequest {
    type Response = CreateTargetResponse;
}

fn clone_target_command(target_id: &EntityId) -> XmlCommand {
    XmlCommand::new("create_target").child_with_text("copy", target_id.as_str())
}

fn validate_create_target(request: &CreateTargetRequest) -> Result<(), GmpRequestError> {
    if request.ssh_credential_port.is_some() && request.ssh_credential_id.is_none() {
        return Err(GmpRequestError::invalid_combination(
            &["ssh_credential_port", "ssh_credential_id"],
            "setting an SSH credential port requires an SSH credential identifier",
        ));
    }
    if request.ssh_elevate_credential_id.is_some() && request.ssh_credential_id.is_none() {
        return Err(GmpRequestError::invalid_combination(
            &["ssh_elevate_credential_id", "ssh_credential_id"],
            "setting an SSH elevation credential requires an SSH credential",
        ));
    }
    if request.ssh_elevate_credential_id == request.ssh_credential_id
        && request.ssh_elevate_credential_id.is_some()
    {
        return Err(GmpRequestError::invalid_combination(
            &["ssh_credential_id", "ssh_elevate_credential_id"],
            "the SSH elevation credential must differ from the SSH credential",
        ));
    }
    // gvmd enforces this in the GMP create-target handler in gmp.c, before
    // dispatching to the SQL-layer create_target implementation.
    if request.smb_credential_id.is_some() && request.krb5_credential_id.is_some() {
        return Err(GmpRequestError::invalid_combination(
            &["smb_credential_id", "krb5_credential_id"],
            "SMB and Kerberos credentials are mutually exclusive",
        ));
    }
    Ok(())
}

fn create_target_command(request: &CreateTargetRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_target");
    cmd.add_element_with_text("name", &request.name);
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element_with_text("hosts", &join_hosts(request.hosts.included()));
    cmd.add_element_with_text("exclude_hosts", &join_hosts(request.hosts.excluded()));
    if let Some(alive_test) = request.alive_test {
        cmd.add_element_with_text("alive_tests", alive_test.as_target_name());
    }
    match &request.ports {
        TargetPortSelection::PortList(port_list_id) => {
            add_optional_id_element(&mut cmd, "port_list", Some(port_list_id));
        }
        TargetPortSelection::PortRange(port_range) => {
            cmd.add_element_with_text("port_range", port_range.as_str());
        }
    }
    add_create_target_credentials(&mut cmd, request);
    if let Some(value) = request.reverse_lookup_only {
        cmd.add_element_with_text("reverse_lookup_only", bool_str(value));
    }
    if let Some(value) = request.reverse_lookup_unify {
        cmd.add_element_with_text("reverse_lookup_unify", bool_str(value));
    }
    if let Some(value) = request.allow_simultaneous_ips {
        cmd.add_element_with_text("allow_simultaneous_ips", bool_str(value));
    }
    cmd
}

fn get_targets_command(request: &GetTargetsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_targets");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_target_command(target_id: &EntityId) -> XmlCommand {
    XmlCommand::new("get_targets")
        .attribute("target_id", target_id.as_str())
        .attribute("details", "1")
}

fn validate_modify_target(request: &ModifyTargetRequest) -> Result<(), GmpRequestError> {
    if matches!(request.port_list_id, ScalarUpdate::Clear) {
        return Err(GmpRequestError::invalid_field(
            "port_list_id",
            "gvmd does not support clearing a target port-list relationship",
        ));
    }
    match (&request.ssh_credential_id, &request.ssh_credential_port) {
        (ScalarUpdate::Omitted, ScalarUpdate::Set(_) | ScalarUpdate::Clear) => {
            return Err(GmpRequestError::invalid_combination(
                &["ssh_credential_port", "ssh_credential_id"],
                "updating an SSH credential port requires setting the SSH credential identifier",
            ));
        }
        (ScalarUpdate::Clear, ScalarUpdate::Set(_) | ScalarUpdate::Clear) => {
            return Err(GmpRequestError::invalid_combination(
                &["ssh_credential_port", "ssh_credential_id"],
                "an SSH credential port cannot be updated while detaching the SSH credential",
            ));
        }
        _ => {}
    }
    if matches!(request.ssh_elevate_credential_id, ScalarUpdate::Set(_))
        && matches!(request.ssh_credential_id, ScalarUpdate::Clear)
    {
        return Err(GmpRequestError::invalid_combination(
            &["ssh_elevate_credential_id", "ssh_credential_id"],
            "setting an SSH elevation credential requires an SSH credential",
        ));
    }
    if let (ScalarUpdate::Set(ssh), ScalarUpdate::Set(elevate)) = (
        &request.ssh_credential_id,
        &request.ssh_elevate_credential_id,
    ) {
        if ssh == elevate {
            return Err(GmpRequestError::invalid_combination(
                &["ssh_credential_id", "ssh_elevate_credential_id"],
                "the SSH elevation credential must differ from the SSH credential",
            ));
        }
    }
    if matches!(request.smb_credential_id, ScalarUpdate::Set(_))
        && matches!(request.krb5_credential_id, ScalarUpdate::Set(_))
    {
        return Err(GmpRequestError::invalid_combination(
            &["smb_credential_id", "krb5_credential_id"],
            "SMB and Kerberos credentials are mutually exclusive",
        ));
    }
    Ok(())
}

fn modify_target_command(request: &ModifyTargetRequest) -> XmlCommand {
    let mut cmd =
        XmlCommand::new("modify_target").attribute("target_id", request.target_id.as_str());
    add_text_element(&mut cmd, "name", request.name.as_deref());
    if let Some(comment) = request.comment.as_deref() {
        cmd.add_element_with_text("comment", comment);
    }
    if let Some(hosts) = &request.hosts {
        cmd.add_element_with_text("hosts", &join_hosts(hosts.included()));
        cmd.add_element_with_text("exclude_hosts", &join_hosts(hosts.excluded()));
    }
    if let Some(alive_test) = request.alive_test {
        cmd.add_element_with_text("alive_tests", alive_test.as_target_name());
    }
    if let ScalarUpdate::Set(port_list_id) = &request.port_list_id {
        add_optional_id_element(&mut cmd, "port_list", Some(port_list_id));
    }
    add_modify_target_credentials(&mut cmd, request);
    if let Some(value) = request.reverse_lookup_only {
        cmd.add_element_with_text("reverse_lookup_only", bool_str(value));
    }
    if let Some(value) = request.reverse_lookup_unify {
        cmd.add_element_with_text("reverse_lookup_unify", bool_str(value));
    }
    if let Some(value) = request.allow_simultaneous_ips {
        cmd.add_element_with_text("allow_simultaneous_ips", bool_str(value));
    }
    cmd
}

fn delete_target_command(request: &DeleteTargetRequest) -> XmlCommand {
    XmlCommand::new("delete_target")
        .attribute("target_id", request.target_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn add_create_target_credentials(cmd: &mut XmlCommand, request: &CreateTargetRequest) {
    add_ssh_credential(
        cmd,
        request.ssh_credential_id.as_ref(),
        request.ssh_credential_port,
    );
    add_optional_id_element(
        cmd,
        "ssh_elevate_credential",
        request.ssh_elevate_credential_id.as_ref(),
    );
    add_optional_id_element(cmd, "smb_credential", request.smb_credential_id.as_ref());
    add_optional_id_element(cmd, "krb5_credential", request.krb5_credential_id.as_ref());
    add_optional_id_element(cmd, "esxi_credential", request.esxi_credential_id.as_ref());
    add_optional_id_element(cmd, "snmp_credential", request.snmp_credential_id.as_ref());
}

fn add_modify_target_credentials(cmd: &mut XmlCommand, request: &ModifyTargetRequest) {
    match &request.ssh_credential_id {
        ScalarUpdate::Omitted => {}
        ScalarUpdate::Set(id) => {
            let credential = add_credential(cmd, "ssh_credential", id);
            match request.ssh_credential_port {
                ScalarUpdate::Omitted => {}
                ScalarUpdate::Set(port) => {
                    credential.add_child_with_text("port", &port.to_string());
                }
                ScalarUpdate::Clear => {
                    // gvmd treats zero on modify as a request to restore port 22.
                    credential.add_child_with_text("port", "0");
                }
            }
        }
        ScalarUpdate::Clear => {
            add_scalar_id_update(cmd, "ssh_credential", &ScalarUpdate::<EntityId>::Clear);
        }
    }
    add_scalar_id_update(
        cmd,
        "ssh_elevate_credential",
        &request.ssh_elevate_credential_id,
    );
    add_scalar_id_update(cmd, "smb_credential", &request.smb_credential_id);
    add_scalar_id_update(cmd, "krb5_credential", &request.krb5_credential_id);
    add_scalar_id_update(cmd, "esxi_credential", &request.esxi_credential_id);
    add_scalar_id_update(cmd, "snmp_credential", &request.snmp_credential_id);
}

fn add_ssh_credential(cmd: &mut XmlCommand, id: Option<&EntityId>, port: Option<ServicePort>) {
    let Some(id) = id else {
        return;
    };
    let credential = add_credential(cmd, "ssh_credential", id);
    if let Some(port) = port {
        credential.add_child_with_text("port", &port.to_string());
    }
}

fn add_credential<'a>(
    cmd: &'a mut XmlCommand,
    element: &str,
    id: &EntityId,
) -> &'a mut gvm_protocol::xml_command::XmlElement {
    let credential = cmd.add_element(element);
    credential.set_attribute("id", id.as_str());
    credential
}

fn join_hosts(hosts: &[TargetHost]) -> String {
    hosts
        .iter()
        .map(TargetHost::as_str)
        .collect::<Vec<_>>()
        .join(",")
}
