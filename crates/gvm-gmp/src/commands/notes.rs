// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for note operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_optional_id_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateNoteResponse, DeleteNoteResponse, GetNotesResponse, ModifyNoteResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing notes.
#[derive(Debug, Clone, Default)]
pub struct GetNotesRequest {
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

impl GmpRequestCodec for GetNotesRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_notes"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_notes_command(self).to_bytes())
    }
}

impl GmpRequest for GetNotesRequest {
    type Response = GetNotesResponse;
}

/// Request for one detailed note.
#[derive(Debug, Clone)]
pub struct GetNoteRequest {
    /// Note identifier to retrieve.
    pub note_id: EntityId,
}

impl GetNoteRequest {
    /// Create a detailed single-note request.
    #[must_use]
    pub fn new(note_id: EntityId) -> Self {
        Self { note_id }
    }
}

impl GmpRequestCodec for GetNoteRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_notes", "get_note"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_note_command(self).to_bytes())
    }
}

impl GmpRequest for GetNoteRequest {
    type Response = GetNotesResponse;
}

/// Request for creating a note.
#[derive(Debug, Clone)]
pub struct CreateNoteRequest {
    /// OID of the NVT to which the note applies.
    pub nvt_oid: String,
    /// Note text.
    pub text: String,
    /// Host restrictions. An empty list means any host.
    pub hosts: Vec<String>,
    /// Optional result-port restriction such as `22/tcp` or `general/tcp`.
    pub port: Option<String>,
    /// Optional result-severity restriction in `0..=10`, or `-1` for log.
    pub severity: Option<f64>,
    /// Optional task restriction.
    pub task_id: Option<EntityId>,
    /// Optional result restriction.
    pub result_id: Option<EntityId>,
    /// Optional activation duration: `-1` forever, `0` disabled, or positive days.
    pub days_active: Option<i32>,
}

impl CreateNoteRequest {
    /// Create a note request with gvmd's required NVT and text values.
    #[must_use]
    pub fn new(nvt_oid: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            nvt_oid: nvt_oid.into(),
            text: text.into(),
            hosts: Vec::new(),
            port: None,
            severity: None,
            task_id: None,
            result_id: None,
            days_active: None,
        }
    }
}

impl GmpRequestCodec for CreateNoteRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required(&self.nvt_oid, "nvt_oid")?;
        validate_required(&self.text, "text")?;
        validate_hosts(&self.hosts)?;
        validate_optional_port(self.port.as_deref())?;
        validate_optional_severity(self.severity, "severity", false)?;
        validate_days_active(self.days_active)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_note"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_note_command(self).to_bytes())
    }
}

impl GmpRequest for CreateNoteRequest {
    type Response = CreateNoteResponse;
}

/// Request for cloning a note through `create_note`.
#[derive(Debug, Clone)]
pub struct CloneNoteRequest {
    /// Existing note identifier to copy.
    pub note_id: EntityId,
}

impl CloneNoteRequest {
    /// Create a note-clone request.
    #[must_use]
    pub fn new(note_id: EntityId) -> Self {
        Self { note_id }
    }
}

impl GmpRequestCodec for CloneNoteRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("create_note", "clone_note"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_note_command(self).to_bytes())
    }
}

impl GmpRequest for CloneNoteRequest {
    type Response = CreateNoteResponse;
}

/// Request for modifying a note.
///
/// gvmd requires [`Self::text`] on every modification. Omitted hosts, port,
/// severity, task, and result values clear those restrictions. Omitted
/// [`Self::nvt_oid`] and [`Self::days_active`] preserve their current values.
#[derive(Debug, Clone)]
pub struct ModifyNoteRequest {
    /// Note identifier to modify.
    pub note_id: EntityId,
    /// Required replacement note text.
    pub text: String,
    /// Optional replacement NVT OID; omission preserves the current NVT.
    pub nvt_oid: Option<String>,
    /// Replacement host restrictions. An empty list clears the restriction.
    pub hosts: Vec<String>,
    /// Replacement result-port restriction; omission clears it.
    pub port: Option<String>,
    /// Replacement result-severity restriction; omission clears it.
    pub severity: Option<f64>,
    /// Replacement task restriction; omission clears it.
    pub task_id: Option<EntityId>,
    /// Replacement result restriction; omission clears it.
    pub result_id: Option<EntityId>,
    /// Optional activation update; omission preserves the current activation.
    pub days_active: Option<i32>,
}

impl ModifyNoteRequest {
    /// Create a note-modification request with cleared restrictions.
    #[must_use]
    pub fn new(note_id: EntityId, text: impl Into<String>) -> Self {
        Self {
            note_id,
            text: text.into(),
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

impl GmpRequestCodec for ModifyNoteRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required(&self.text, "text")?;
        if let Some(nvt_oid) = self.nvt_oid.as_deref() {
            validate_required(nvt_oid, "nvt_oid")?;
        }
        validate_hosts(&self.hosts)?;
        validate_optional_port(self.port.as_deref())?;
        validate_optional_severity(self.severity, "severity", false)?;
        validate_days_active(self.days_active)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_note"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_note_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyNoteRequest {
    type Response = ModifyNoteResponse;
}

/// Request for deleting a note.
#[derive(Debug, Clone)]
pub struct DeleteNoteRequest {
    /// Note identifier to delete.
    pub note_id: EntityId,
    /// Whether to delete permanently instead of moving to the trashcan.
    pub ultimate: bool,
}

impl DeleteNoteRequest {
    /// Create a note-deletion request.
    #[must_use]
    pub fn new(note_id: EntityId, ultimate: bool) -> Self {
        Self { note_id, ultimate }
    }
}

impl GmpRequestCodec for DeleteNoteRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_note"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_note_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteNoteRequest {
    type Response = DeleteNoteResponse;
}

pub(crate) fn validate_required(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.trim().is_empty() {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_hosts(hosts: &[String]) -> Result<(), GmpRequestError> {
    if hosts.iter().any(|host| host.trim().is_empty()) {
        Err(GmpRequestError::invalid_field(
            "hosts",
            "must not contain empty entries",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_optional_port(port: Option<&str>) -> Result<(), GmpRequestError> {
    let Some(port) = port else {
        return Ok(());
    };
    let valid_cpe = port
        .strip_prefix("cpe:")
        .is_some_and(|value| !value.is_empty() && !value.chars().any(char::is_whitespace));
    let valid_service = port.split_once('/').is_some_and(|(number, protocol)| {
        let valid_number = number == "general"
            || (number.len() <= 5
                && number
                    .starts_with(|character: char| character.is_ascii_digit() && character != '0')
                && number.chars().all(|character| character.is_ascii_digit()));
        valid_number
            && !protocol.is_empty()
            && protocol
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
    });
    if valid_cpe || valid_service {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            "port",
            "must be cpe:<value>, general/<protocol>, or 1-5 digits/<protocol>",
        ))
    }
}

pub(crate) fn validate_optional_severity(
    severity: Option<f64>,
    field: &'static str,
    allow_false_positive: bool,
) -> Result<(), GmpRequestError> {
    let Some(severity) = severity else {
        return Ok(());
    };
    let special = severity == -1.0 || (allow_false_positive && severity == -3.0);
    if severity.is_finite() && ((0.0..=10.0).contains(&severity) || special) {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            if allow_false_positive {
                "must be finite and in 0..=10, -1 (log), or -3 (false positive)"
            } else {
                "must be finite and in 0..=10 or -1 (log)"
            },
        ))
    }
}

pub(crate) fn validate_days_active(days_active: Option<i32>) -> Result<(), GmpRequestError> {
    if days_active.is_some_and(|days| days < -1) {
        Err(GmpRequestError::invalid_field(
            "days_active",
            "must be -1 (forever), 0 (disabled), or positive days",
        ))
    } else {
        Ok(())
    }
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
    task_id: Option<&EntityId>,
    result_id: Option<&EntityId>,
    days_active: Option<i32>,
) {
    if !hosts.is_empty() {
        command.add_element_with_text("hosts", &hosts.join(","));
    }
    add_optional_text(command, "port", port);
    if let Some(severity) = severity {
        command.add_element_with_text("severity", &severity.to_string());
    }
    add_optional_id_element(command, "task", task_id);
    add_optional_id_element(command, "result", result_id);
    if let Some(days_active) = days_active {
        command.add_element_with_text("active", &days_active.to_string());
    }
}

fn get_notes_command(request: &GetNotesRequest) -> XmlCommand {
    let mut command = XmlCommand::new("get_notes");
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

fn get_note_command(request: &GetNoteRequest) -> XmlCommand {
    XmlCommand::new("get_notes")
        .attribute("note_id", request.note_id.as_str())
        .attribute("details", "1")
}

fn create_note_command(request: &CreateNoteRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_note");
    command
        .add_element("nvt")
        .set_attribute("oid", &request.nvt_oid);
    command.add_element_with_text("text", &request.text);
    add_restrictions(
        &mut command,
        &request.hosts,
        request.port.as_deref(),
        request.severity,
        request.task_id.as_ref(),
        request.result_id.as_ref(),
        request.days_active,
    );
    command
}

fn clone_note_command(request: &CloneNoteRequest) -> XmlCommand {
    XmlCommand::new("create_note").child_with_text("copy", request.note_id.as_str())
}

fn modify_note_command(request: &ModifyNoteRequest) -> XmlCommand {
    let mut command = XmlCommand::new("modify_note").attribute("note_id", request.note_id.as_str());
    command.add_element_with_text("text", &request.text);
    if let Some(nvt_oid) = request.nvt_oid.as_deref() {
        command.add_element("nvt").set_attribute("oid", nvt_oid);
    }
    add_restrictions(
        &mut command,
        &request.hosts,
        request.port.as_deref(),
        request.severity,
        request.task_id.as_ref(),
        request.result_id.as_ref(),
        request.days_active,
    );
    command
}

fn delete_note_command(request: &DeleteNoteRequest) -> XmlCommand {
    XmlCommand::new("delete_note")
        .attribute("note_id", request.note_id.as_str())
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
    fn note_requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetNotesRequest {
                filter_string: Some("text=body".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(false),
                details: Some(true),
                result: Some(true),
            }),
            "<get_notes details=\"1\" filt_id=\"filter-1\" filter=\"text=body\" result=\"1\" trash=\"0\"/>"
        );
        assert_eq!(
            request_xml(&GetNoteRequest::new(id("note-1"))),
            "<get_notes details=\"1\" note_id=\"note-1\"/>"
        );

        let mut create = CreateNoteRequest::new("1.3.6.1", "body");
        create.hosts = vec!["192.0.2.1".into(), "192.0.2.2".into()];
        create.port = Some("22/tcp".into());
        create.severity = Some(7.5);
        create.task_id = Some(id("task-1"));
        create.result_id = Some(id("result-1"));
        create.days_active = Some(-1);
        assert_eq!(
            request_xml(&create),
            "<create_note><nvt oid=\"1.3.6.1\"/><text>body</text><hosts>192.0.2.1,192.0.2.2</hosts><port>22/tcp</port><severity>7.5</severity><task id=\"task-1\"/><result id=\"result-1\"/><active>-1</active></create_note>"
        );
        assert!(!request_xml(&create).contains("orphan"));

        assert_eq!(
            request_xml(&CloneNoteRequest::new(id("note-1"))),
            "<create_note><copy>note-1</copy></create_note>"
        );

        let mut modify = ModifyNoteRequest::new(id("note-1"), "updated");
        modify.nvt_oid = Some("1.3.6.2".into());
        modify.days_active = Some(0);
        assert_eq!(
            request_xml(&modify),
            "<modify_note note_id=\"note-1\"><text>updated</text><nvt oid=\"1.3.6.2\"/><active>0</active></modify_note>"
        );

        assert_eq!(
            request_xml(&DeleteNoteRequest::new(id("note-1"), true)),
            "<delete_note note_id=\"note-1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn invalid_final_note_values_are_rejected() {
        let mut create = CreateNoteRequest::new("", "body");
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField {
                field: "nvt_oid",
                ..
            })
        ));

        create.nvt_oid = "1.3.6.1".into();
        create.text.clear();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "text", .. })
        ));

        let mut modify = ModifyNoteRequest::new(id("note-1"), "body");
        modify.port = Some("ssh".into());
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField { field: "port", .. })
        ));

        modify.port = None;
        modify.severity = Some(f64::NAN);
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField {
                field: "severity",
                ..
            })
        ));

        modify.severity = None;
        modify.days_active = Some(-2);
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField {
                field: "days_active",
                ..
            })
        ));
    }

    #[test]
    fn note_requests_keep_static_response_associations() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: GmpResponse,
        {
        }

        associated::<_, GetNotesResponse>(&GetNotesRequest::default());
        associated::<_, GetNotesResponse>(&GetNoteRequest::new(id("note-1")));
        associated::<_, CreateNoteResponse>(&CreateNoteRequest::new("1.3.6.1", "body"));
        associated::<_, CreateNoteResponse>(&CloneNoteRequest::new(id("note-1")));
        associated::<_, ModifyNoteResponse>(&ModifyNoteRequest::new(id("note-1"), "body"));
        associated::<_, DeleteNoteResponse>(&DeleteNoteRequest::new(id("note-1"), false));
    }

    #[test]
    fn note_aliases_keep_wire_and_capability_names() {
        let detail = GetNoteRequest::new(id("note-1"));
        let detail_command = detail.command().expect("typed command");
        assert_eq!(detail_command.wire_name(), "get_notes");
        assert_eq!(detail_command.semantic_name(), Some("get_note"));

        let clone = CloneNoteRequest::new(id("note-1"));
        let clone_command = clone.command().expect("typed command");
        assert_eq!(clone_command.wire_name(), "create_note");
        assert_eq!(clone_command.semantic_name(), Some("clone_note"));
    }
}
