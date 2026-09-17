// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for schedule operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateScheduleResponse, DeleteScheduleResponse, GetSchedulesResponse, ModifyScheduleResponse,
};
use crate::schedule::{to_icalendar, ScheduleInput};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing schedules.
#[derive(Debug, Clone, Default)]
pub struct GetSchedulesRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to include tasks using the schedules.
    pub tasks: Option<bool>,
}

impl GmpRequestCodec for GetSchedulesRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_schedules"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_schedules_command(self).to_bytes())
    }
}

impl GmpRequest for GetSchedulesRequest {
    type Response = GetSchedulesResponse;
}

/// Request for one detailed schedule.
#[derive(Debug, Clone)]
pub struct GetScheduleRequest {
    /// Schedule identifier to retrieve.
    pub schedule_id: EntityId,
}

impl GetScheduleRequest {
    /// Create a detailed single-schedule request.
    #[must_use]
    pub fn new(schedule_id: EntityId) -> Self {
        Self { schedule_id }
    }
}

impl GmpRequestCodec for GetScheduleRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_schedules",
            "get_schedule",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_schedule_command(self).to_bytes())
    }
}

impl GmpRequest for GetScheduleRequest {
    type Response = GetSchedulesResponse;
}

/// Request for creating a schedule.
#[derive(Debug, Clone)]
pub struct CreateScheduleRequest {
    /// Schedule name.
    pub name: String,
    /// iCalendar (RFC 5545) payload describing the schedule.
    pub icalendar: String,
    /// Optional timezone applied to the calendar.
    ///
    /// Omission lets gvmd use the current user's timezone and then UTC as its
    /// fallback.
    pub timezone: Option<String>,
    /// Optional resource comment.
    pub comment: Option<String>,
}

impl CreateScheduleRequest {
    /// Create a schedule request from a raw iCalendar payload.
    #[must_use]
    pub fn new(name: impl Into<String>, icalendar: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            icalendar: icalendar.into(),
            timezone: None,
            comment: None,
        }
    }

    /// Create a schedule request from validated typed recurrence input.
    #[must_use]
    pub fn from_input(name: impl Into<String>, input: ScheduleInput) -> Self {
        Self {
            name: name.into(),
            icalendar: to_icalendar(&input.definition),
            timezone: Some(input.timezone.to_string()),
            comment: input.comment,
        }
    }
}

impl GmpRequestCodec for CreateScheduleRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        require_non_empty(&self.icalendar, "icalendar")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_schedule"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(create_schedule_command(self).to_bytes())
    }
}

impl GmpRequest for CreateScheduleRequest {
    type Response = CreateScheduleResponse;
}

/// Request for cloning a schedule through `create_schedule`.
#[derive(Debug, Clone)]
pub struct CloneScheduleRequest {
    /// Existing schedule identifier to copy.
    pub schedule_id: EntityId,
    /// Optional name override. Omission copies the existing name.
    pub name: Option<String>,
    /// Optional comment override. Omission copies the existing comment.
    pub comment: Option<String>,
}

impl CloneScheduleRequest {
    /// Create a schedule-clone request.
    #[must_use]
    pub fn new(schedule_id: EntityId) -> Self {
        Self {
            schedule_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneScheduleRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_schedule",
            "clone_schedule",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_schedule_command(self).to_bytes())
    }
}

impl GmpRequest for CloneScheduleRequest {
    type Response = CreateScheduleResponse;
}

/// Request for modifying a schedule.
#[derive(Debug, Clone)]
pub struct ModifyScheduleRequest {
    /// Schedule identifier to modify.
    pub schedule_id: EntityId,
    /// Replacement iCalendar (RFC 5545) payload.
    ///
    /// Pinned gvmd requires this value for every modify operation, including
    /// name- or comment-only changes.
    pub icalendar: String,
    /// Optional replacement timezone. Omission preserves the current value.
    pub timezone: Option<String>,
    /// Optional replacement name.
    pub name: Option<String>,
    /// Optional replacement comment. An empty string clears the comment.
    pub comment: Option<String>,
}

impl ModifyScheduleRequest {
    /// Create a schedule-modification request from raw iCalendar data.
    #[must_use]
    pub fn new(schedule_id: EntityId, icalendar: impl Into<String>) -> Self {
        Self {
            schedule_id,
            icalendar: icalendar.into(),
            timezone: None,
            name: None,
            comment: None,
        }
    }

    /// Create a schedule-modification request from typed recurrence input.
    #[must_use]
    pub fn from_input(schedule_id: EntityId, input: ScheduleInput) -> Self {
        Self {
            schedule_id,
            icalendar: to_icalendar(&input.definition),
            timezone: Some(input.timezone.to_string()),
            name: input.name,
            comment: input.comment,
        }
    }
}

impl GmpRequestCodec for ModifyScheduleRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.icalendar, "icalendar")?;
        validate_optional_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_schedule"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_schedule_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyScheduleRequest {
    type Response = ModifyScheduleResponse;
}

/// Request for deleting a schedule.
#[derive(Debug, Clone)]
pub struct DeleteScheduleRequest {
    /// Schedule identifier to delete.
    pub schedule_id: EntityId,
    /// Whether to delete permanently instead of moving to the trashcan.
    pub ultimate: bool,
}

impl DeleteScheduleRequest {
    /// Create a schedule-deletion request.
    #[must_use]
    pub fn new(schedule_id: EntityId, ultimate: bool) -> Self {
        Self {
            schedule_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteScheduleRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_schedule"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_schedule_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteScheduleRequest {
    type Response = DeleteScheduleResponse;
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

fn add_optional_text_element(command: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        command.add_element_with_text(name, value);
    }
}

fn get_schedules_command(request: &GetSchedulesRequest) -> XmlCommand {
    let mut command = XmlCommand::new("get_schedules");
    add_filter_attrs(
        &mut command,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut command, "trash", request.trash);
    set_optional_bool_attr(&mut command, "details", request.details);
    set_optional_bool_attr(&mut command, "tasks", request.tasks);
    command
}

fn get_schedule_command(request: &GetScheduleRequest) -> XmlCommand {
    XmlCommand::new("get_schedules")
        .attribute("schedule_id", request.schedule_id.as_str())
        .attribute("details", "1")
}

fn create_schedule_command(request: &CreateScheduleRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_schedule");
    command.add_element_with_text("name", &request.name);
    add_optional_text_element(&mut command, "comment", request.comment.as_deref());
    command.add_element_with_text("icalendar", &request.icalendar);
    add_optional_text_element(&mut command, "timezone", request.timezone.as_deref());
    command
}

fn clone_schedule_command(request: &CloneScheduleRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_schedule");
    add_optional_text_element(&mut command, "name", request.name.as_deref());
    add_optional_text_element(&mut command, "comment", request.comment.as_deref());
    command.add_element_with_text("copy", request.schedule_id.as_str());
    command
}

fn modify_schedule_command(request: &ModifyScheduleRequest) -> XmlCommand {
    let mut command =
        XmlCommand::new("modify_schedule").attribute("schedule_id", request.schedule_id.as_str());
    add_optional_text_element(&mut command, "name", request.name.as_deref());
    add_optional_text_element(&mut command, "comment", request.comment.as_deref());
    command.add_element_with_text("icalendar", &request.icalendar);
    add_optional_text_element(&mut command, "timezone", request.timezone.as_deref());
    command
}

fn delete_schedule_command(request: &DeleteScheduleRequest) -> XmlCommand {
    XmlCommand::new("delete_schedule")
        .attribute("schedule_id", request.schedule_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GmpResponse, ScheduleDefinition, ScheduleRecurrence, ScheduleTimestamp, ScheduleTimezone,
    };

    const ICALENDAR: &str = "BEGIN:VCALENDAR\r\nEND:VCALENDAR";

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn typed_input() -> ScheduleInput {
        ScheduleInput::new(
            ScheduleDefinition {
                first_run: ScheduleTimestamp::parse("2030-01-01T00:00:00Z")
                    .expect("valid timestamp"),
                recurrence: ScheduleRecurrence::Daily,
            },
            ScheduleTimezone::new("UTC").expect("valid timezone"),
        )
    }

    fn request_xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(
            request
                .encode(GmpVersion(22, 8))
                .expect("valid schedule request"),
        )
        .expect("valid UTF-8")
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetSchedulesRequest {
                filter_string: Some("name=weekly".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(true),
                details: Some(false),
                tasks: Some(true),
            }),
            "<get_schedules details=\"0\" filt_id=\"filter-1\" filter=\"name=weekly\" tasks=\"1\" trash=\"1\"/>"
        );
        assert_eq!(
            request_xml(&GetScheduleRequest::new(id("schedule-1"))),
            "<get_schedules details=\"1\" schedule_id=\"schedule-1\"/>"
        );

        let mut create = CreateScheduleRequest::new("weekly", ICALENDAR);
        create.comment = Some("comment".into());
        create.timezone = Some("Europe/Berlin".into());
        assert_eq!(
            request_xml(&create),
            "<create_schedule><name>weekly</name><comment>comment</comment><icalendar>BEGIN:VCALENDAR\r\nEND:VCALENDAR</icalendar><timezone>Europe/Berlin</timezone></create_schedule>"
        );

        let mut clone = CloneScheduleRequest::new(id("schedule-1"));
        clone.name = Some("copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            request_xml(&clone),
            "<create_schedule><name>copy</name><comment></comment><copy>schedule-1</copy></create_schedule>"
        );

        let mut modify = ModifyScheduleRequest::new(id("schedule-1"), ICALENDAR);
        modify.name = Some("renamed".into());
        modify.comment = Some(String::new());
        modify.timezone = Some("UTC".into());
        assert_eq!(
            request_xml(&modify),
            "<modify_schedule schedule_id=\"schedule-1\"><name>renamed</name><comment></comment><icalendar>BEGIN:VCALENDAR\r\nEND:VCALENDAR</icalendar><timezone>UTC</timezone></modify_schedule>"
        );

        assert_eq!(
            request_xml(&DeleteScheduleRequest::new(id("schedule-1"), true)),
            "<delete_schedule schedule_id=\"schedule-1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn typed_inputs_build_the_same_canonical_requests() {
        let create = CreateScheduleRequest::from_input("typed", typed_input());
        assert_eq!(create.name, "typed");
        assert_eq!(create.timezone.as_deref(), Some("UTC"));
        assert!(create.icalendar.contains("BEGIN:VCALENDAR"));
        assert!(create.icalendar.contains("RRULE:FREQ=DAILY"));

        let mut input = typed_input();
        input.name = Some("renamed".into());
        input.comment = Some(String::new());
        let modify = ModifyScheduleRequest::from_input(id("schedule-1"), input);
        assert_eq!(modify.name.as_deref(), Some("renamed"));
        assert_eq!(modify.comment.as_deref(), Some(""));
        assert_eq!(modify.timezone.as_deref(), Some("UTC"));
        assert!(modify.icalendar.contains("RRULE:FREQ=DAILY"));
    }

    #[test]
    fn requests_keep_static_response_associations() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: GmpResponse,
        {
        }

        associated::<_, GetSchedulesResponse>(&GetSchedulesRequest::default());
        associated::<_, GetSchedulesResponse>(&GetScheduleRequest::new(id("schedule-1")));
        associated::<_, CreateScheduleResponse>(&CreateScheduleRequest::new("name", ICALENDAR));
        associated::<_, CreateScheduleResponse>(&CloneScheduleRequest::new(id("schedule-1")));
        associated::<_, ModifyScheduleResponse>(&ModifyScheduleRequest::new(
            id("schedule-1"),
            ICALENDAR,
        ));
        associated::<_, DeleteScheduleResponse>(&DeleteScheduleRequest::new(
            id("schedule-1"),
            false,
        ));
    }

    #[test]
    fn invalid_final_values_are_rejected() {
        let mut create = CreateScheduleRequest::new("name", ICALENDAR);
        create.name.clear();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let create = CreateScheduleRequest::new("name", "");
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField {
                field: "icalendar",
                ..
            })
        ));

        let modify = ModifyScheduleRequest::new(id("schedule-1"), "");
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField {
                field: "icalendar",
                ..
            })
        ));

        let mut clone = CloneScheduleRequest::new(id("schedule-1"));
        clone.name = Some(String::new());
        assert!(matches!(
            clone.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));
    }

    #[test]
    fn semantic_aliases_keep_wire_and_capability_names() {
        let detail = GetScheduleRequest::new(id("schedule-1"));
        let detail_command = detail.command().expect("typed command");
        assert_eq!(detail_command.wire_name(), "get_schedules");
        assert_eq!(detail_command.semantic_name(), Some("get_schedule"));

        let clone = CloneScheduleRequest::new(id("schedule-1"));
        let clone_command = clone.command().expect("typed command");
        assert_eq!(clone_command.wire_name(), "create_schedule");
        assert_eq!(clone_command.semantic_name(), Some("clone_schedule"));
    }
}
