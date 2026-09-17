// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for alert operations.

use std::fmt;

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, bool_str, set_optional_bool_attr};
use crate::enums::{AlertCondition, AlertEvent, AlertMethod};
use crate::responses::{
    ActionResponse, CreateAlertResponse, DeleteAlertResponse, GetAlertsResponse,
    GetReportsResponse, ModifyAlertResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// A name/value entry nested below an alert event, condition, or method.
#[derive(Clone, PartialEq, Eq)]
pub struct AlertData {
    /// Protocol-defined data name.
    pub name: String,
    /// Data value.
    pub value: String,
}

impl AlertData {
    /// Create an alert data entry.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    fn validate(&self, field: &'static str) -> Result<(), GmpRequestError> {
        if self.name.is_empty() {
            Err(GmpRequestError::invalid_field(
                field,
                "data name must not be empty",
            ))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for AlertData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlertData")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Semantic request for listing alerts.
#[derive(Debug, Clone, Default)]
pub struct GetAlertsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetAlertsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_alerts"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_alerts_command(self).to_bytes())
    }
}

impl GmpRequest for GetAlertsRequest {
    type Response = GetAlertsResponse;
}

/// Semantic request for one detailed alert.
#[derive(Debug, Clone)]
pub struct GetAlertRequest {
    /// Alert identifier to retrieve.
    pub alert_id: EntityId,
}

impl GetAlertRequest {
    /// Create a detailed single-alert request.
    #[must_use]
    pub fn new(alert_id: EntityId) -> Self {
        Self { alert_id }
    }
}

impl GmpRequestCodec for GetAlertRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_alerts", "get_alert"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_alert_command(self).to_bytes())
    }
}

impl GmpRequest for GetAlertRequest {
    type Response = GetAlertsResponse;
}

/// Semantic request for creating an alert.
#[derive(Debug, Clone)]
pub struct CreateAlertRequest {
    /// Alert name.
    pub name: String,
    /// Alert event.
    pub event: AlertEvent,
    /// Data entries for `event`.
    pub event_data: Vec<AlertData>,
    /// Alert condition.
    pub condition: AlertCondition,
    /// Data entries for `condition`.
    pub condition_data: Vec<AlertData>,
    /// Alert delivery method.
    pub method: AlertMethod,
    /// Data entries for `method`.
    pub method_data: Vec<AlertData>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional saved result-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether the alert is enabled.
    pub active: Option<bool>,
}

impl CreateAlertRequest {
    /// Create an alert-creation request with gvmd's required final values.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        event: AlertEvent,
        condition: AlertCondition,
        method: AlertMethod,
    ) -> Self {
        Self {
            name: name.into(),
            event,
            event_data: Vec::new(),
            condition,
            condition_data: Vec::new(),
            method,
            method_data: Vec::new(),
            comment: None,
            filter_id: None,
            active: None,
        }
    }
}

impl GmpRequestCodec for CreateAlertRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        validate_data(&self.event_data, "event_data")?;
        validate_data(&self.condition_data, "condition_data")?;
        validate_data(&self.method_data, "method_data")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_alert"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_alert_command(self).to_bytes())
    }
}

impl GmpRequest for CreateAlertRequest {
    type Response = CreateAlertResponse;
}

/// Semantic request for cloning an alert through `create_alert`.
#[derive(Debug, Clone)]
pub struct CloneAlertRequest {
    /// Existing alert identifier to copy.
    pub alert_id: EntityId,
    /// Optional name override. Omission copies the existing name.
    pub name: Option<String>,
    /// Optional comment override. Omission copies the existing comment.
    pub comment: Option<String>,
}

impl CloneAlertRequest {
    /// Create an alert-clone request.
    #[must_use]
    pub fn new(alert_id: EntityId) -> Self {
        Self {
            alert_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneAlertRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_alert",
            "clone_alert",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_alert_command(self).to_bytes())
    }
}

impl GmpRequest for CloneAlertRequest {
    type Response = CreateAlertResponse;
}

/// Semantic request for modifying an alert.
#[derive(Debug, Clone)]
pub struct ModifyAlertRequest {
    /// Alert identifier to modify.
    pub alert_id: EntityId,
    /// Optional replacement name.
    pub name: Option<String>,
    /// Optional replacement comment. An empty string clears the comment.
    pub comment: Option<String>,
    /// Optional replacement event.
    pub event: Option<AlertEvent>,
    /// Replacement event data, applied only when `event` is present.
    pub event_data: Vec<AlertData>,
    /// Optional replacement condition.
    pub condition: Option<AlertCondition>,
    /// Replacement condition data, applied only when `condition` is present.
    pub condition_data: Vec<AlertData>,
    /// Optional replacement delivery method.
    pub method: Option<AlertMethod>,
    /// Replacement method data, applied only when `method` is present.
    pub method_data: Vec<AlertData>,
    /// Saved result-filter identifier.
    ///
    /// Pinned gvmd clears the current filter binding when this is omitted. Pass
    /// the existing identifier to preserve the binding.
    pub filter_id: Option<EntityId>,
    /// Whether the alert is enabled. Omission preserves the current state.
    pub active: Option<bool>,
}

impl ModifyAlertRequest {
    /// Create an alert-modification request.
    #[must_use]
    pub fn new(alert_id: EntityId) -> Self {
        Self {
            alert_id,
            name: None,
            comment: None,
            event: None,
            event_data: Vec::new(),
            condition: None,
            condition_data: Vec::new(),
            method: None,
            method_data: Vec::new(),
            filter_id: None,
            active: None,
        }
    }
}

impl GmpRequestCodec for ModifyAlertRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_name(&self.name)?;
        validate_optional_data(self.event.is_some(), &self.event_data, "event_data")?;
        validate_optional_data(
            self.condition.is_some(),
            &self.condition_data,
            "condition_data",
        )?;
        validate_optional_data(self.method.is_some(), &self.method_data, "method_data")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_alert"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_alert_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyAlertRequest {
    type Response = ModifyAlertResponse;
}

/// Semantic request for deleting an alert.
#[derive(Debug, Clone)]
pub struct DeleteAlertRequest {
    /// Alert identifier to delete.
    pub alert_id: EntityId,
    /// Whether to delete permanently instead of moving the alert to trash.
    pub ultimate: bool,
}

impl DeleteAlertRequest {
    /// Create an alert-deletion request.
    #[must_use]
    pub fn new(alert_id: EntityId, ultimate: bool) -> Self {
        Self { alert_id, ultimate }
    }
}

impl GmpRequestCodec for DeleteAlertRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_alert"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_alert_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteAlertRequest {
    type Response = DeleteAlertResponse;
}

/// Semantic request for testing an alert.
#[derive(Debug, Clone)]
pub struct TestAlertRequest {
    /// Alert identifier to test.
    pub alert_id: EntityId,
}

impl TestAlertRequest {
    /// Create an alert-test request.
    #[must_use]
    pub fn new(alert_id: EntityId) -> Self {
        Self { alert_id }
    }
}

impl GmpRequestCodec for TestAlertRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("test_alert"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(test_alert_command(self).to_bytes())
    }
}

impl GmpRequest for TestAlertRequest {
    type Response = ActionResponse;
}

/// Semantic request for triggering an alert for a report through `get_reports`.
#[derive(Debug, Clone)]
pub struct TriggerAlertRequest {
    /// Alert identifier to trigger.
    pub alert_id: EntityId,
    /// Report identifier supplied to the alert.
    pub report_id: EntityId,
    /// Optional inline result filter.
    pub filter_string: Option<String>,
    /// Optional saved result-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Optional report format identifier.
    pub report_format_id: Option<EntityId>,
    /// Optional delta report identifier.
    pub delta_report_id: Option<EntityId>,
}

impl TriggerAlertRequest {
    /// Create an alert-trigger request.
    #[must_use]
    pub fn new(alert_id: EntityId, report_id: EntityId) -> Self {
        Self {
            alert_id,
            report_id,
            filter_string: None,
            filter_id: None,
            report_format_id: None,
            delta_report_id: None,
        }
    }
}

impl GmpRequestCodec for TriggerAlertRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_reports",
            "trigger_alert",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(trigger_alert_command(self).to_bytes())
    }
}

impl GmpRequest for TriggerAlertRequest {
    type Response = GetReportsResponse;
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_optional_name(name: &Option<String>) -> Result<(), GmpRequestError> {
    if name.as_ref().is_some_and(String::is_empty) {
        Err(GmpRequestError::invalid_field("name", "must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_data(data: &[AlertData], field: &'static str) -> Result<(), GmpRequestError> {
    data.iter().try_for_each(|entry| entry.validate(field))
}

fn validate_optional_data(
    parent_present: bool,
    data: &[AlertData],
    field: &'static str,
) -> Result<(), GmpRequestError> {
    if !parent_present && !data.is_empty() {
        return Err(GmpRequestError::invalid_field(
            field,
            "requires the corresponding alert field",
        ));
    }
    validate_data(data, field)
}

fn add_optional_text_element(cmd: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        cmd.add_element_with_text(name, value);
    }
}

fn add_alert_field(cmd: &mut XmlCommand, name: &str, value: &str, data: &[AlertData]) {
    let field = cmd.add_element(name);
    field.set_text(value);
    for entry in data {
        let data_element = field.add_child("data");
        data_element.set_text(&entry.value);
        data_element.add_child_with_text("name", &entry.name);
    }
}

fn add_filter_element(cmd: &mut XmlCommand, filter_id: Option<&EntityId>) {
    if let Some(filter_id) = filter_id {
        cmd.add_element("filter")
            .set_attribute("id", filter_id.as_str());
    }
}

fn get_alerts_command(request: &GetAlertsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_alerts");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_alert_command(request: &GetAlertRequest) -> XmlCommand {
    XmlCommand::new("get_alerts")
        .attribute("alert_id", request.alert_id.as_str())
        .attribute("details", "1")
}

fn create_alert_command(request: &CreateAlertRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_alert");
    cmd.add_element_with_text("name", &request.name);
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_alert_field(
        &mut cmd,
        "event",
        request.event.as_alert_name(),
        &request.event_data,
    );
    add_alert_field(
        &mut cmd,
        "condition",
        request.condition.as_alert_name(),
        &request.condition_data,
    );
    add_alert_field(
        &mut cmd,
        "method",
        request.method.as_alert_name(),
        &request.method_data,
    );
    add_filter_element(&mut cmd, request.filter_id.as_ref());
    if let Some(active) = request.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    cmd
}

fn clone_alert_command(request: &CloneAlertRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_alert");
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    cmd.add_element_with_text("copy", request.alert_id.as_str());
    cmd
}

fn modify_alert_command(request: &ModifyAlertRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_alert").attribute("alert_id", request.alert_id.as_str());
    add_optional_text_element(&mut cmd, "name", request.name.as_deref());
    add_optional_text_element(&mut cmd, "comment", request.comment.as_deref());
    if let Some(event) = request.event {
        add_alert_field(
            &mut cmd,
            "event",
            event.as_alert_name(),
            &request.event_data,
        );
    }
    if let Some(condition) = request.condition {
        add_alert_field(
            &mut cmd,
            "condition",
            condition.as_alert_name(),
            &request.condition_data,
        );
    }
    if let Some(method) = request.method {
        add_alert_field(
            &mut cmd,
            "method",
            method.as_alert_name(),
            &request.method_data,
        );
    }
    add_filter_element(&mut cmd, request.filter_id.as_ref());
    if let Some(active) = request.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    cmd
}

fn delete_alert_command(request: &DeleteAlertRequest) -> XmlCommand {
    XmlCommand::new("delete_alert")
        .attribute("alert_id", request.alert_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn test_alert_command(request: &TestAlertRequest) -> XmlCommand {
    XmlCommand::new("test_alert").attribute("alert_id", request.alert_id.as_str())
}

fn trigger_alert_command(request: &TriggerAlertRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_reports")
        .attribute("report_id", request.report_id.as_str())
        .attribute("alert_id", request.alert_id.as_str());
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    if let Some(report_format_id) = request.report_format_id.as_ref() {
        cmd = cmd.attribute("format_id", report_format_id.as_str());
    }
    if let Some(delta_report_id) = request.delta_report_id.as_ref() {
        cmd = cmd.attribute("delta_report_id", delta_report_id.as_str());
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GmpResponse;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn create_request() -> CreateAlertRequest {
        CreateAlertRequest::new(
            "alert",
            AlertEvent::TaskRunStatusChanged,
            AlertCondition::Always,
            AlertMethod::Email,
        )
    }

    fn request_xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(
            request
                .encode(GmpVersion(22, 8))
                .expect("valid alert request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetAlertsRequest {
                filter_string: Some("name=mail".into()),
                filter_id: Some(id("saved-filter")),
                trash: Some(true),
                details: Some(false),
            }),
            "<get_alerts details=\"0\" filt_id=\"saved-filter\" filter=\"name=mail\" trash=\"1\"/>"
        );
        assert_eq!(
            request_xml(&GetAlertRequest::new(id("alert-1"))),
            "<get_alerts alert_id=\"alert-1\" details=\"1\"/>"
        );

        let mut create = create_request();
        create.comment = Some("typed".into());
        create.event_data = vec![AlertData::new("status", "Done")];
        create.method_data = vec![AlertData::new("to_address", "ops@example.com")];
        create.filter_id = Some(id("filter-1"));
        create.active = Some(true);
        assert_eq!(
            request_xml(&create),
            "<create_alert><name>alert</name><comment>typed</comment><event>Task run status changed<data>Done<name>status</name></data></event><condition>Always</condition><method>Email<data>ops@example.com<name>to_address</name></data></method><filter id=\"filter-1\"/><active>1</active></create_alert>"
        );

        let mut clone = CloneAlertRequest::new(id("alert-1"));
        clone.name = Some("copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            request_xml(&clone),
            "<create_alert><name>copy</name><comment></comment><copy>alert-1</copy></create_alert>"
        );

        let mut modify = ModifyAlertRequest::new(id("alert-1"));
        modify.name = Some("Renamed & Escaped".into());
        modify.comment = Some(String::new());
        modify.event = Some(AlertEvent::TaskRunStatusChanged);
        modify.event_data = vec![AlertData::new("key&name", "value <&>")];
        modify.method = Some(AlertMethod::SysLog);
        modify.active = Some(false);
        assert_eq!(
            request_xml(&modify),
            "<modify_alert alert_id=\"alert-1\"><name>Renamed &amp; Escaped</name><comment></comment><event>Task run status changed<data>value &lt;&amp;&gt;<name>key&amp;name</name></data></event><method>Syslog</method><active>0</active></modify_alert>"
        );
        assert_eq!(
            request_xml(&DeleteAlertRequest::new(id("alert-1"), true)),
            "<delete_alert alert_id=\"alert-1\" ultimate=\"1\"/>"
        );
        assert_eq!(
            request_xml(&TestAlertRequest::new(id("alert-1"))),
            "<test_alert alert_id=\"alert-1\"/>"
        );

        let mut trigger = TriggerAlertRequest::new(id("alert-1"), id("report-1"));
        trigger.filter_string = Some("severity>5".into());
        trigger.filter_id = Some(id("filter-1"));
        trigger.report_format_id = Some(id("format-1"));
        trigger.delta_report_id = Some(id("delta-1"));
        assert_eq!(
            request_xml(&trigger),
            "<get_reports alert_id=\"alert-1\" delta_report_id=\"delta-1\" filt_id=\"filter-1\" filter=\"severity&gt;5\" format_id=\"format-1\" report_id=\"report-1\"/>"
        );
    }

    #[test]
    fn requests_keep_static_response_associations() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: GmpResponse,
        {
        }

        associated::<_, GetAlertsResponse>(&GetAlertsRequest::default());
        associated::<_, GetAlertsResponse>(&GetAlertRequest::new(id("alert-1")));
        associated::<_, CreateAlertResponse>(&create_request());
        associated::<_, CreateAlertResponse>(&CloneAlertRequest::new(id("alert-1")));
        associated::<_, ModifyAlertResponse>(&ModifyAlertRequest::new(id("alert-1")));
        associated::<_, DeleteAlertResponse>(&DeleteAlertRequest::new(id("alert-1"), false));
        associated::<_, ActionResponse>(&TestAlertRequest::new(id("alert-1")));
        associated::<_, GetReportsResponse>(&TriggerAlertRequest::new(
            id("alert-1"),
            id("report-1"),
        ));
    }

    #[test]
    fn invalid_final_values_are_rejected() {
        let mut create = create_request();
        create.name.clear();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut clone = CloneAlertRequest::new(id("alert-1"));
        clone.name = Some(String::new());
        assert!(matches!(
            clone.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut modify = ModifyAlertRequest::new(id("alert-1"));
        modify.method_data = vec![AlertData::new("password", "secret")];
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField {
                field: "method_data",
                ..
            })
        ));
    }

    #[test]
    fn semantic_aliases_keep_wire_and_capability_names() {
        let detail = GetAlertRequest::new(id("alert-1"));
        let detail_command = detail.command().expect("typed command");
        assert_eq!(detail_command.wire_name(), "get_alerts");
        assert_eq!(detail_command.semantic_name(), Some("get_alert"));

        let clone = CloneAlertRequest::new(id("alert-1"));
        let clone_command = clone.command().expect("typed command");
        assert_eq!(clone_command.wire_name(), "create_alert");
        assert_eq!(clone_command.semantic_name(), Some("clone_alert"));

        let trigger = TriggerAlertRequest::new(id("alert-1"), id("report-1"));
        let trigger_command = trigger.command().expect("typed command");
        assert_eq!(trigger_command.wire_name(), "get_reports");
        assert_eq!(trigger_command.semantic_name(), Some("trigger_alert"));
    }

    #[test]
    fn alert_data_debug_redacts_values() {
        let data = AlertData::new("password", "do-not-log");
        let rendered = format!("{data:?}");
        assert!(rendered.contains("password"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("do-not-log"));
    }
}
