// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for override operations.

use gvm_protocol::{Request as _, XmlCommand};

use super::notes::{
    validate_days_active, validate_hosts, validate_optional_port, validate_optional_severity,
    validate_required,
};
use crate::common::{add_filter_attrs, add_optional_id_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateOverrideResponse, DeleteOverrideResponse, GetOverridesResponse, ModifyOverrideResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing overrides.
#[derive(Debug, Clone, Default)]
pub struct GetOverridesRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to include associated result references.
    pub result: Option<bool>,
}

impl GmpRequestCodec for GetOverridesRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_overrides"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_overrides_command(self).to_bytes())
    }
}

impl GmpRequest for GetOverridesRequest {
    type Response = GetOverridesResponse;
}

/// Request for one detailed override.
#[derive(Debug, Clone)]
pub struct GetOverrideRequest {
    /// Override identifier to retrieve.
    pub override_id: EntityId,
}

impl GetOverrideRequest {
    /// Create a detailed single-override request.
    #[must_use]
    pub fn new(override_id: EntityId) -> Self {
        Self { override_id }
    }
}

impl GmpRequestCodec for GetOverrideRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_overrides",
            "get_override",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_override_command(self).to_bytes())
    }
}

impl GmpRequest for GetOverrideRequest {
    type Response = GetOverridesResponse;
}

/// Request for creating an override.
#[derive(Debug, Clone)]
pub struct CreateOverrideRequest {
    /// OID of the NVT to which the override applies.
    pub nvt_oid: String,
    /// Override text.
    pub text: String,
    /// Host restrictions. An empty list means any host.
    pub hosts: Vec<String>,
    /// Optional result-port restriction such as `22/tcp` or `general/tcp`.
    pub port: Option<String>,
    /// Optional original-severity restriction in `0..=10`, or `-1` for log.
    pub severity: Option<f64>,
    /// Required replacement severity in `0..=10`, `-1` for log, or `-3` for false positive.
    pub new_severity: f64,
    /// Optional task restriction.
    pub task_id: Option<EntityId>,
    /// Optional result restriction.
    pub result_id: Option<EntityId>,
    /// Optional activation duration: `-1` forever, `0` disabled, or positive days.
    pub days_active: Option<i32>,
}

impl CreateOverrideRequest {
    /// Create an override request with gvmd's required values.
    #[must_use]
    pub fn new(nvt_oid: impl Into<String>, text: impl Into<String>, new_severity: f64) -> Self {
        Self {
            nvt_oid: nvt_oid.into(),
            text: text.into(),
            hosts: Vec::new(),
            port: None,
            severity: None,
            new_severity,
            task_id: None,
            result_id: None,
            days_active: None,
        }
    }
}

impl GmpRequestCodec for CreateOverrideRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required(&self.nvt_oid, "nvt_oid")?;
        validate_required(&self.text, "text")?;
        validate_hosts(&self.hosts)?;
        validate_optional_port(self.port.as_deref())?;
        validate_optional_severity(self.severity, "severity", false)?;
        validate_optional_severity(Some(self.new_severity), "new_severity", true)?;
        validate_days_active(self.days_active)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_override"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_override_command(self).to_bytes())
    }
}

impl GmpRequest for CreateOverrideRequest {
    type Response = CreateOverrideResponse;
}

/// Request for cloning an override through `create_override`.
#[derive(Debug, Clone)]
pub struct CloneOverrideRequest {
    /// Existing override identifier to copy.
    pub override_id: EntityId,
}

impl CloneOverrideRequest {
    /// Create an override-clone request.
    #[must_use]
    pub fn new(override_id: EntityId) -> Self {
        Self { override_id }
    }
}

impl GmpRequestCodec for CloneOverrideRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_override",
            "clone_override",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_override_command(self).to_bytes())
    }
}

impl GmpRequest for CloneOverrideRequest {
    type Response = CreateOverrideResponse;
}

/// Request for modifying an override.
///
/// gvmd requires [`Self::text`] and [`Self::new_severity`] on every
/// modification. Omitted hosts, port, severity, task, and result values clear
/// those restrictions. Omitted [`Self::nvt_oid`] and [`Self::days_active`]
/// preserve their current values.
#[derive(Debug, Clone)]
pub struct ModifyOverrideRequest {
    /// Override identifier to modify.
    pub override_id: EntityId,
    /// Required replacement override text.
    pub text: String,
    /// Required replacement severity.
    pub new_severity: f64,
    /// Optional replacement NVT OID; omission preserves the current NVT.
    pub nvt_oid: Option<String>,
    /// Replacement host restrictions. An empty list clears the restriction.
    pub hosts: Vec<String>,
    /// Replacement result-port restriction; omission clears it.
    pub port: Option<String>,
    /// Replacement original-severity restriction; omission clears it.
    pub severity: Option<f64>,
    /// Replacement task restriction; omission clears it.
    pub task_id: Option<EntityId>,
    /// Replacement result restriction; omission clears it.
    pub result_id: Option<EntityId>,
    /// Optional activation update; omission preserves the current activation.
    pub days_active: Option<i32>,
}

impl ModifyOverrideRequest {
    /// Create an override-modification request with cleared restrictions.
    #[must_use]
    pub fn new(override_id: EntityId, text: impl Into<String>, new_severity: f64) -> Self {
        Self {
            override_id,
            text: text.into(),
            new_severity,
            nvt_oid: None,
            hosts: Vec::new(),
            port: None,
            severity: None,
            task_id: None,
            result_id: None,
            days_active: None,
        }
    }
}

impl GmpRequestCodec for ModifyOverrideRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required(&self.text, "text")?;
        validate_optional_severity(Some(self.new_severity), "new_severity", true)?;
        if let Some(nvt_oid) = self.nvt_oid.as_deref() {
            validate_required(nvt_oid, "nvt_oid")?;
        }
        validate_hosts(&self.hosts)?;
        validate_optional_port(self.port.as_deref())?;
        validate_optional_severity(self.severity, "severity", false)?;
        validate_days_active(self.days_active)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_override"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_override_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyOverrideRequest {
    type Response = ModifyOverrideResponse;
}

/// Request for deleting an override.
#[derive(Debug, Clone)]
pub struct DeleteOverrideRequest {
    /// Override identifier to delete.
    pub override_id: EntityId,
    /// Whether to delete permanently instead of moving to the trashcan.
    pub ultimate: bool,
}

impl DeleteOverrideRequest {
    /// Create an override-deletion request.
    #[must_use]
    pub fn new(override_id: EntityId, ultimate: bool) -> Self {
        Self {
            override_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteOverrideRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_override"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_override_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteOverrideRequest {
    type Response = DeleteOverrideResponse;
}

fn add_optional_text(command: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        command.add_element_with_text(name, value);
    }
}

fn add_restrictions(
    command: &mut XmlCommand,
    hosts: &[String],
    port: Option<&str>,
    severity: Option<f64>,
    new_severity: f64,
    task_id: Option<&EntityId>,
    result_id: Option<&EntityId>,
) {
    if !hosts.is_empty() {
        command.add_element_with_text("hosts", &hosts.join(","));
    }
    add_optional_text(command, "port", port);
    if let Some(severity) = severity {
        command.add_element_with_text("severity", &severity.to_string());
    }
    command.add_element_with_text("new_severity", &new_severity.to_string());
    add_optional_id_element(command, "task", task_id);
    add_optional_id_element(command, "result", result_id);
}

fn get_overrides_command(request: &GetOverridesRequest) -> XmlCommand {
    let mut command = XmlCommand::new("get_overrides");
    add_filter_attrs(
        &mut command,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut command, "trash", request.trash);
    set_optional_bool_attr(&mut command, "details", request.details);
    set_optional_bool_attr(&mut command, "result", request.result);
    command
}

fn get_override_command(request: &GetOverrideRequest) -> XmlCommand {
    XmlCommand::new("get_overrides")
        .attribute("override_id", request.override_id.as_str())
        .attribute("details", "1")
}

fn create_override_command(request: &CreateOverrideRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_override");
    command
        .add_element("nvt")
        .set_attribute("oid", &request.nvt_oid);
    command.add_element_with_text("text", &request.text);
    add_restrictions(
        &mut command,
        &request.hosts,
        request.port.as_deref(),
        request.severity,
        request.new_severity,
        request.task_id.as_ref(),
        request.result_id.as_ref(),
    );
    if let Some(days_active) = request.days_active {
        command.add_element_with_text("active", &days_active.to_string());
    }
    command
}

fn clone_override_command(request: &CloneOverrideRequest) -> XmlCommand {
    XmlCommand::new("create_override").child_with_text("copy", request.override_id.as_str())
}

fn modify_override_command(request: &ModifyOverrideRequest) -> XmlCommand {
    let mut command =
        XmlCommand::new("modify_override").attribute("override_id", request.override_id.as_str());
    command.add_element_with_text("text", &request.text);
    if let Some(nvt_oid) = request.nvt_oid.as_deref() {
        command.add_element("nvt").set_attribute("oid", nvt_oid);
    }
    add_restrictions(
        &mut command,
        &request.hosts,
        request.port.as_deref(),
        request.severity,
        request.new_severity,
        request.task_id.as_ref(),
        request.result_id.as_ref(),
    );
    if let Some(days_active) = request.days_active {
        command.add_element_with_text("active", &days_active.to_string());
    }
    command
}

fn delete_override_command(request: &DeleteOverrideRequest) -> XmlCommand {
    XmlCommand::new("delete_override")
        .attribute("override_id", request.override_id.as_str())
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
        String::from_utf8(request.encode(GmpVersion(22, 8)).expect("valid request"))
            .expect("valid UTF-8")
    }

    #[test]
    fn override_requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetOverridesRequest {
                filter_string: Some("text=body".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(false),
                details: Some(true),
                result: Some(true),
            }),
            "<get_overrides details=\"1\" filt_id=\"filter-1\" filter=\"text=body\" result=\"1\" trash=\"0\"/>"
        );
        assert_eq!(
            request_xml(&GetOverrideRequest::new(id("override-1"))),
            "<get_overrides details=\"1\" override_id=\"override-1\"/>"
        );

        let mut create = CreateOverrideRequest::new("1.3.6.1", "body", 5.0);
        create.hosts = vec!["192.0.2.1".into()];
        create.port = Some("443/tcp".into());
        create.severity = Some(7.5);
        create.task_id = Some(id("task-1"));
        create.result_id = Some(id("result-1"));
        create.days_active = Some(-1);
        assert_eq!(
            request_xml(&create),
            "<create_override><nvt oid=\"1.3.6.1\"/><text>body</text><hosts>192.0.2.1</hosts><port>443/tcp</port><severity>7.5</severity><new_severity>5</new_severity><task id=\"task-1\"/><result id=\"result-1\"/><active>-1</active></create_override>"
        );

        assert_eq!(
            request_xml(&CloneOverrideRequest::new(id("override-1"))),
            "<create_override><copy>override-1</copy></create_override>"
        );

        let mut modify = ModifyOverrideRequest::new(id("override-1"), "updated", -3.0);
        modify.nvt_oid = Some("1.3.6.2".into());
        modify.days_active = Some(0);
        assert_eq!(
            request_xml(&modify),
            "<modify_override override_id=\"override-1\"><text>updated</text><nvt oid=\"1.3.6.2\"/><new_severity>-3</new_severity><active>0</active></modify_override>"
        );

        assert_eq!(
            request_xml(&DeleteOverrideRequest::new(id("override-1"), false)),
            "<delete_override override_id=\"override-1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn invalid_final_override_values_are_rejected() {
        let mut create = CreateOverrideRequest::new("1.3.6.1", "body", 11.0);
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField {
                field: "new_severity",
                ..
            })
        ));

        create.new_severity = 5.0;
        create.hosts = vec![String::new()];
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "hosts", .. })
        ));

        let mut modify = ModifyOverrideRequest::new(id("override-1"), "", 5.0);
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField { field: "text", .. })
        ));

        modify.text = "body".into();
        modify.severity = Some(-3.0);
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField {
                field: "severity",
                ..
            })
        ));
    }

    #[test]
    fn override_requests_keep_static_response_associations() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: GmpResponse,
        {
        }

        associated::<_, GetOverridesResponse>(&GetOverridesRequest::default());
        associated::<_, GetOverridesResponse>(&GetOverrideRequest::new(id("override-1")));
        associated::<_, CreateOverrideResponse>(&CreateOverrideRequest::new(
            "1.3.6.1", "body", 5.0,
        ));
        associated::<_, CreateOverrideResponse>(&CloneOverrideRequest::new(id("override-1")));
        associated::<_, ModifyOverrideResponse>(&ModifyOverrideRequest::new(
            id("override-1"),
            "body",
            5.0,
        ));
        associated::<_, DeleteOverrideResponse>(&DeleteOverrideRequest::new(
            id("override-1"),
            false,
        ));
    }

    #[test]
    fn override_aliases_keep_wire_and_capability_names() {
        let detail = GetOverrideRequest::new(id("override-1"));
        let detail_command = detail.command().expect("typed command");
        assert_eq!(detail_command.wire_name(), "get_overrides");
        assert_eq!(detail_command.semantic_name(), Some("get_override"));

        let clone = CloneOverrideRequest::new(id("override-1"));
        let clone_command = clone.command().expect("typed command");
        assert_eq!(clone_command.wire_name(), "create_override");
        assert_eq!(clone_command.semantic_name(), Some("clone_override"));
    }
}
