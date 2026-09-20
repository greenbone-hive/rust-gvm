// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical standard-task requests and transitional specialized-task builders.

use std::fmt;

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{
    add_filter_attrs, add_id_element, add_optional_id_element, add_preferences,
    add_scalar_id_update, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::responses::{
    CreateTaskResponse, DeleteTaskResponse, GetTasksResponse, ModifyTaskResponse, MoveTaskResponse,
    ResumeTaskResponse, StartTaskResponse, StopTaskResponse,
};
use crate::types::{CollectionUpdate, EntityId, ScalarUpdate};
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Transitional options retained for audit creation until #660.
#[derive(Debug, Clone, Default)]
pub struct CreateTaskOpts {
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Optional fields for `create_agent_group_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateAgentGroupTaskOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Optional fields for `create_oci_image_target_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateOciImageTargetTaskOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Optional fields for web application target `create_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateWebApplicationTaskOpts {
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Transitional options retained for audit listing until #660.
#[derive(Debug, Clone, Default)]
pub struct GetTasksOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to limit results to scheduled tasks.
    pub schedules_only: Option<bool>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
}

/// Transitional options retained for audit modification until #660.
#[derive(Debug, Clone, Default)]
pub struct ModifyTaskOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Schedule relationship update: omit, set, or detach.
    pub schedule_id: ScalarUpdate<EntityId>,
    /// Optional schedule period count.
    pub schedule_periods: Option<u32>,
    /// Optional target identifier.
    pub target_id: Option<EntityId>,
    /// Optional scan configuration identifier.
    pub config_id: Option<EntityId>,
    /// Optional scanner identifier.
    pub scanner_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Option<Vec<EntityId>>,
    /// Observer-user update: omit, replace, or clear.
    ///
    /// An explicit clear emits an empty `<observers>` element, which gvmd
    /// interprets as removing every user observer.
    pub observers: CollectionUpdate<String>,
    /// Observer-group update: omit, replace, or clear.
    ///
    /// gvmd accepts group children on `modify_task` even though the published
    /// GMP grammar documents only observer-user text. Because opening the
    /// shared `<observers>` container also updates the user list, a group
    /// update requires [`Self::observers`] to explicitly replace or clear the
    /// users. Clearing groups is encoded with gvmd's `group id="0"` sentinel.
    pub observer_group_ids: CollectionUpdate<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Errors raised while building a `modify_task` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModifyTaskError {
    /// A group update would otherwise clear users implicitly on gvmd.
    #[error(
        "updating task observer groups requires explicitly replacing or clearing observer users"
    )]
    ObserverGroupsWithoutUserUpdate,
}

/// A task preference assignment.
///
/// Preference values can contain scanner credentials and are therefore
/// redacted from diagnostics. The decoded value is encoded exactly once as
/// XML text when the request is sent.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TaskPreference {
    /// Scanner preference name.
    pub name: String,
    /// Scanner preference value.
    pub value: String,
}

impl TaskPreference {
    /// Create a task preference assignment.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl fmt::Debug for TaskPreference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskPreference")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Semantic request for listing standard scan tasks.
///
/// The associated response is fixed at compile time:
///
/// ```compile_fail
/// use gvm_gmp::commands::tasks::GetTasksRequest;
/// use gvm_gmp::responses::CreateTaskResponse;
/// use gvm_gmp::GmpRequest;
///
/// fn require_create<R: GmpRequest<Response = CreateTaskResponse>>(_: R) {}
/// require_create(GetTasksRequest::default());
/// ```
#[derive(Debug, Clone, Default)]
pub struct GetTasksRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to limit results to scheduled tasks.
    pub schedules_only: Option<bool>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
}

impl GmpRequestCodec for GetTasksRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_xml_text(self.filter_string.as_deref(), "filter_string")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_tasks"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_tasks_command(self).to_bytes())
    }
}

impl GmpRequest for GetTasksRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for one detailed standard scan task.
#[derive(Debug, Clone)]
pub struct GetTaskRequest {
    /// Task identifier to retrieve.
    pub task_id: EntityId,
}

impl GetTaskRequest {
    /// Create a detailed single-task request.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self { task_id }
    }
}

impl GmpRequestCodec for GetTaskRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_tasks", "get_task"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_task_command(&self.task_id).to_bytes())
    }
}

impl GmpRequest for GetTaskRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for creating a standard scan task.
#[derive(Debug, Clone)]
pub struct CreateTaskRequest {
    /// Task name.
    pub name: String,
    /// Scan configuration relationship.
    pub config_id: EntityId,
    /// Target relationship.
    pub target_id: EntityId,
    /// Scanner relationship.
    pub scanner_id: EntityId,
    /// Optional task comment.
    pub comment: Option<String>,
    /// Whether the new task is alterable.
    pub alterable: Option<bool>,
    /// Optional schedule relationship.
    pub schedule_id: Option<EntityId>,
    /// Number of schedule periods, or zero for no limit.
    ///
    /// gvmd accepts this independently of `schedule_id`; when a schedule is
    /// present omission defaults the stored value to zero.
    pub schedule_periods: Option<u32>,
    /// Alerts to associate with the task.
    pub alert_ids: Vec<EntityId>,
    /// Observer user names.
    pub observers: Vec<String>,
    /// Observer group relationships.
    pub observer_group_ids: Vec<EntityId>,
    /// Task preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl CreateTaskRequest {
    /// Create a standard scan-task creation request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        config_id: EntityId,
        target_id: EntityId,
        scanner_id: EntityId,
    ) -> Self {
        Self {
            name: name.into(),
            config_id,
            target_id,
            scanner_id,
            comment: None,
            alterable: None,
            schedule_id: None,
            schedule_periods: None,
            alert_ids: Vec::new(),
            observers: Vec::new(),
            observer_group_ids: Vec::new(),
            preferences: Vec::new(),
        }
    }
}

impl GmpRequestCodec for CreateTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_create_task(self)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_task"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_task_command(self).to_bytes())
    }
}

impl GmpRequest for CreateTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for cloning a standard scan task.
#[derive(Debug, Clone)]
pub struct CloneTaskRequest {
    /// Existing task identifier to copy.
    pub task_id: EntityId,
    /// Optional non-empty comment override. Empty and omitted comments inherit.
    pub comment: Option<String>,
    /// Optional alterable override.
    pub alterable: Option<bool>,
}

impl CloneTaskRequest {
    /// Create a task-clone request.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self {
            task_id,
            comment: None,
            alterable: None,
        }
    }
}

impl GmpRequestCodec for CloneTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("create_task", "clone_task"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(clone_task_command(self).to_bytes())
    }
}

impl GmpRequest for CloneTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for modifying a standard scan task.
#[derive(Debug, Clone)]
pub struct ModifyTaskRequest {
    /// Task identifier to modify.
    pub task_id: EntityId,
    /// Optional non-empty replacement name.
    pub name: Option<String>,
    /// Optional comment replacement; an empty value clears the comment.
    pub comment: Option<String>,
    /// Whether the task is alterable.
    pub alterable: Option<bool>,
    /// Schedule update: preserve, set/replace, or detach.
    pub schedule_id: ScalarUpdate<EntityId>,
    /// Schedule-period update. With a schedule set/clear, omission resets to zero.
    pub schedule_periods: Option<u32>,
    /// Optional target replacement.
    pub target_id: Option<EntityId>,
    /// Optional scan-configuration replacement.
    pub config_id: Option<EntityId>,
    /// Optional scanner replacement.
    pub scanner_id: Option<EntityId>,
    /// Alert update: preserve, replace, or clear.
    pub alert_ids: CollectionUpdate<EntityId>,
    /// Observer-user update: preserve, replace, or clear.
    pub observers: CollectionUpdate<String>,
    /// Observer-group update: preserve, replace, or clear.
    ///
    /// A group update requires an explicit user replacement or clear because
    /// opening gvmd's shared `<observers>` container otherwise clears users.
    pub observer_group_ids: CollectionUpdate<EntityId>,
    /// Ordered task preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl ModifyTaskRequest {
    /// Create a task-modification request with no field updates.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self {
            task_id,
            name: None,
            comment: None,
            alterable: None,
            schedule_id: ScalarUpdate::Omitted,
            schedule_periods: None,
            target_id: None,
            config_id: None,
            scanner_id: None,
            alert_ids: CollectionUpdate::Omitted,
            observers: CollectionUpdate::Omitted,
            observer_group_ids: CollectionUpdate::Omitted,
            preferences: Vec::new(),
        }
    }
}

impl GmpRequestCodec for ModifyTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_modify_task(self)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_task"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_task_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyTaskRequest {
    type Response = ModifyTaskResponse;
}

/// Semantic request for deleting a standard scan task.
#[derive(Debug, Clone)]
pub struct DeleteTaskRequest {
    /// Task identifier to delete.
    pub task_id: EntityId,
    /// Whether to delete permanently instead of moving to trash.
    pub ultimate: bool,
}

impl DeleteTaskRequest {
    /// Create a task-deletion request.
    #[must_use]
    pub fn new(task_id: EntityId, ultimate: bool) -> Self {
        Self { task_id, ultimate }
    }
}

impl GmpRequestCodec for DeleteTaskRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_task"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_task_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteTaskRequest {
    type Response = DeleteTaskResponse;
}

macro_rules! impl_canonical_task_action_request {
    ($request:ident, $response:ty, $wire_name:literal) => {
        impl GmpRequestCodec for $request {
            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::new($wire_name))
            }

            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                Ok(task_action_command($wire_name, &self.task_id).to_bytes())
            }
        }

        impl GmpRequest for $request {
            type Response = $response;
        }
    };
}

/// Semantic request for starting a standard scan task.
#[derive(Debug, Clone)]
pub struct StartTaskRequest {
    /// Task identifier to start.
    pub task_id: EntityId,
}

impl StartTaskRequest {
    /// Create a task-start request.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self { task_id }
    }
}

/// Semantic request for stopping a standard scan task.
#[derive(Debug, Clone)]
pub struct StopTaskRequest {
    /// Task identifier to stop.
    pub task_id: EntityId,
}

impl StopTaskRequest {
    /// Create a task-stop request.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self { task_id }
    }
}

/// Semantic request for resuming a standard scan task.
#[derive(Debug, Clone)]
pub struct ResumeTaskRequest {
    /// Task identifier to resume.
    pub task_id: EntityId,
}

impl ResumeTaskRequest {
    /// Create a task-resume request.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self { task_id }
    }
}

impl_canonical_task_action_request!(StartTaskRequest, StartTaskResponse, "start_task");
impl_canonical_task_action_request!(StopTaskRequest, StopTaskResponse, "stop_task");
impl_canonical_task_action_request!(ResumeTaskRequest, ResumeTaskResponse, "resume_task");

fn validate_create_task(request: &CreateTaskRequest) -> Result<(), GmpRequestError> {
    validate_required_xml_text(&request.name, "name")?;
    validate_optional_xml_text(request.comment.as_deref(), "comment")?;
    validate_relationship_id(&request.config_id, "config_id")?;
    validate_relationship_id(&request.target_id, "target_id")?;
    validate_relationship_id(&request.scanner_id, "scanner_id")?;
    if let Some(schedule_id) = &request.schedule_id {
        validate_relationship_id(schedule_id, "schedule_id")?;
    }
    validate_relationship_ids(&request.alert_ids, "alert_ids")?;
    validate_observer_names(&request.observers)?;
    validate_relationship_ids(&request.observer_group_ids, "observer_group_ids")?;
    validate_preferences(&request.preferences)
}

fn validate_modify_task(request: &ModifyTaskRequest) -> Result<(), GmpRequestError> {
    if let Some(name) = request.name.as_deref() {
        validate_required_xml_text(name, "name")?;
    }
    validate_optional_xml_text(request.comment.as_deref(), "comment")?;
    if let ScalarUpdate::Set(schedule_id) = &request.schedule_id {
        validate_relationship_id(schedule_id, "schedule_id")?;
    }
    for (id, field) in [
        (request.target_id.as_ref(), "target_id"),
        (request.config_id.as_ref(), "config_id"),
        (request.scanner_id.as_ref(), "scanner_id"),
    ] {
        if let Some(id) = id {
            validate_relationship_id(id, field)?;
        }
    }
    if let CollectionUpdate::Replace(alert_ids) = &request.alert_ids {
        validate_relationship_ids(alert_ids, "alert_ids")?;
    }
    if !matches!(request.observer_group_ids, CollectionUpdate::Omitted)
        && matches!(request.observers, CollectionUpdate::Omitted)
    {
        return Err(GmpRequestError::invalid_combination(
            &["observer_group_ids", "observers"],
            "updating observer groups requires explicitly replacing or clearing observer users",
        ));
    }
    if let CollectionUpdate::Replace(observers) = &request.observers {
        validate_observer_names(observers)?;
    }
    if let CollectionUpdate::Replace(group_ids) = &request.observer_group_ids {
        validate_relationship_ids(group_ids, "observer_group_ids")?;
    }
    validate_preferences(&request.preferences)
}

fn validate_relationship_ids(ids: &[EntityId], field: &'static str) -> Result<(), GmpRequestError> {
    for id in ids {
        validate_relationship_id(id, field)?;
    }
    Ok(())
}

fn validate_relationship_id(id: &EntityId, field: &'static str) -> Result<(), GmpRequestError> {
    if id.as_str() == "0" {
        return Err(GmpRequestError::invalid_field(
            field,
            "must identify a relationship, not a protocol sentinel",
        ));
    }
    Ok(())
}

fn validate_preferences(preferences: &[TaskPreference]) -> Result<(), GmpRequestError> {
    for preference in preferences {
        validate_required_xml_text(&preference.name, "preferences.name")?;
        validate_xml_text(&preference.value, "preferences.value")?;
        match preference.name.as_str() {
            "auto_delete" if !matches!(preference.value.as_str(), "keep" | "no") => {
                return Err(GmpRequestError::invalid_field(
                    "preferences.value",
                    "auto_delete must be 'keep' or 'no'",
                ));
            }
            "auto_delete_data"
                if preference
                    .value
                    .parse::<u32>()
                    .map_or(true, |value| !(2..=1200).contains(&value)) =>
            {
                return Err(GmpRequestError::invalid_field(
                    "preferences.value",
                    "auto_delete_data must be an integer from 2 through 1200",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_observer_names(observers: &[String]) -> Result<(), GmpRequestError> {
    for observer in observers {
        validate_required_xml_text(observer, "observers")?;
        if observer.chars().any(char::is_whitespace) {
            return Err(GmpRequestError::invalid_field(
                "observers",
                "each observer must be one user name without whitespace",
            ));
        }
    }
    Ok(())
}

fn validate_required_xml_text(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        return Err(GmpRequestError::invalid_field(field, "must not be empty"));
    }
    validate_xml_text(value, field)
}

fn validate_optional_xml_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    value.map_or(Ok(()), |value| validate_xml_text(value, field))
}

fn validate_xml_text(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.chars().any(|character| {
        !matches!(
            character,
            '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
        )
    }) {
        return Err(GmpRequestError::invalid_field(
            field,
            "contains a forbidden XML 1.0 character",
        ));
    }
    Ok(())
}

fn get_tasks_command(request: &GetTasksRequest) -> XmlCommand {
    let mut command =
        XmlCommand::new("get_tasks").attribute("usage_type", UsageType::Scan.as_gmp_str());
    add_filter_attrs(
        &mut command,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut command, "trash", request.trash);
    set_optional_bool_attr(&mut command, "details", request.details);
    set_optional_bool_attr(&mut command, "schedules_only", request.schedules_only);
    set_optional_bool_attr(&mut command, "ignore_pagination", request.ignore_pagination);
    command
}

fn get_task_command(task_id: &EntityId) -> XmlCommand {
    XmlCommand::new("get_tasks")
        .attribute("task_id", task_id.as_str())
        .attribute("usage_type", UsageType::Scan.as_gmp_str())
        .attribute("details", "1")
}

fn create_task_command(request: &CreateTaskRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_task");
    command.add_element_with_text("name", &request.name);
    command.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(&mut command, "config", &request.config_id);
    add_id_element(&mut command, "target", &request.target_id);
    add_id_element(&mut command, "scanner", &request.scanner_id);
    add_text_element(&mut command, "comment", request.comment.as_deref());
    if let Some(alterable) = request.alterable {
        command.add_element_with_text("alterable", bool_str(alterable));
    }
    add_optional_id_element(&mut command, "schedule", request.schedule_id.as_ref());
    if let Some(schedule_periods) = request.schedule_periods {
        command.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    for alert_id in &request.alert_ids {
        add_id_element(&mut command, "alert", alert_id);
    }
    add_task_observers(
        &mut command,
        &request.observers,
        &request.observer_group_ids,
    );
    add_task_preferences(&mut command, &request.preferences);
    command
}

fn clone_task_command(request: &CloneTaskRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_task");
    add_text_element(&mut command, "comment", request.comment.as_deref());
    command.add_element_with_text("copy", request.task_id.as_str());
    if let Some(alterable) = request.alterable {
        command.add_element_with_text("alterable", bool_str(alterable));
    }
    command
}

fn modify_task_command(request: &ModifyTaskRequest) -> XmlCommand {
    let mut command = XmlCommand::new("modify_task").attribute("task_id", request.task_id.as_str());
    add_text_element(&mut command, "name", request.name.as_deref());
    if let Some(comment) = request.comment.as_deref() {
        command.add_element_with_text("comment", comment);
    }
    if let Some(alterable) = request.alterable {
        command.add_element_with_text("alterable", bool_str(alterable));
    }
    add_scalar_id_update(&mut command, "schedule", &request.schedule_id);
    if let Some(schedule_periods) = request.schedule_periods {
        command.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    add_optional_id_element(&mut command, "target", request.target_id.as_ref());
    add_optional_id_element(&mut command, "config", request.config_id.as_ref());
    add_optional_id_element(&mut command, "scanner", request.scanner_id.as_ref());
    match &request.alert_ids {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(alert_ids) if !alert_ids.is_empty() => {
            for alert_id in alert_ids {
                add_id_element(&mut command, "alert", alert_id);
            }
        }
        CollectionUpdate::Replace(_) | CollectionUpdate::Clear => {
            command.add_element("alert").set_attribute("id", "0");
        }
    }
    add_task_observer_update(
        &mut command,
        &request.observers,
        &request.observer_group_ids,
    );
    add_task_preferences(&mut command, &request.preferences);
    command
}

fn add_task_preferences(command: &mut XmlCommand, preferences: &[TaskPreference]) {
    if preferences.is_empty() {
        return;
    }
    let container = command.add_element("preferences");
    for preference in preferences {
        let element = container.add_child("preference");
        element.add_child("scanner_name").set_text(&preference.name);
        element.add_child("value").set_text(&preference.value);
    }
}

fn delete_task_command(request: &DeleteTaskRequest) -> XmlCommand {
    XmlCommand::new("delete_task")
        .attribute("task_id", request.task_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn task_action_command(name: &'static str, task_id: &EntityId) -> XmlCommand {
    XmlCommand::new(name).attribute("task_id", task_id.as_str())
}

macro_rules! transitional_task_action_request {
    ($request:ident, $response:ty, $builder:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            task_id: EntityId,
        }

        impl $request {
            /// Create the task-action request.
            #[must_use]
            pub fn new(task_id: EntityId) -> Self {
                Self { task_id }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.task_id).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = $response;
        }
    };
}

/// Semantic request for creating an import task.
#[derive(Debug, Clone)]
pub struct CreateImportTaskRequest {
    name: String,
    comment: Option<String>,
}

impl CreateImportTaskRequest {
    /// Create an import-task request.
    #[must_use]
    pub fn new(name: impl Into<String>, comment: Option<String>) -> Self {
        Self {
            name: name.into(),
            comment,
        }
    }
}

impl Request for CreateImportTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_import_task(&self.name, self.comment.as_deref()).to_bytes()
    }
}

impl GmpRequest for CreateImportTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic compatibility-alias request for creating a container/import task.
#[derive(Debug, Clone)]
pub struct CreateContainerTaskRequest {
    name: String,
    comment: Option<String>,
}

impl CreateContainerTaskRequest {
    /// Create a container/import-task request.
    #[must_use]
    pub fn new(name: impl Into<String>, comment: Option<String>) -> Self {
        Self {
            name: name.into(),
            comment,
        }
    }
}

impl Request for CreateContainerTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_container_task(&self.name, self.comment.as_deref()).to_bytes()
    }
}

impl GmpRequest for CreateContainerTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating an agent-group scan task.
#[derive(Debug, Clone)]
pub struct CreateAgentGroupTaskRequest {
    name: String,
    agent_group_id: EntityId,
    scanner_id: EntityId,
    opts: CreateAgentGroupTaskOpts,
}

impl CreateAgentGroupTaskRequest {
    /// Create an agent-group task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        agent_group_id: EntityId,
        scanner_id: EntityId,
        opts: CreateAgentGroupTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            agent_group_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateAgentGroupTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_agent_group_task(
            &self.name,
            &self.agent_group_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_agent_group_task")
    }
}

impl GmpRequest for CreateAgentGroupTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating an OCI image-target scan task.
#[derive(Debug, Clone)]
pub struct CreateOciImageTargetTaskRequest {
    name: String,
    oci_image_target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateOciImageTargetTaskOpts,
}

impl CreateOciImageTargetTaskRequest {
    /// Create an OCI image-target task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        oci_image_target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            oci_image_target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateOciImageTargetTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_oci_image_target_task(
            &self.name,
            &self.oci_image_target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_oci_image_target_task")
    }
}

impl GmpRequest for CreateOciImageTargetTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic compatibility-alias request for creating a container-image task.
#[derive(Debug, Clone)]
pub struct CreateContainerImageTaskRequest {
    name: String,
    oci_image_target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateOciImageTargetTaskOpts,
}

impl CreateContainerImageTaskRequest {
    /// Create a container-image task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        oci_image_target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            oci_image_target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateContainerImageTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_container_image_task(
            &self.name,
            &self.oci_image_target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_oci_image_target_task")
    }
}

impl GmpRequest for CreateContainerImageTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating a web-application-target scan task.
#[derive(Debug, Clone)]
pub struct CreateWebApplicationTaskRequest {
    name: String,
    web_application_target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateWebApplicationTaskOpts,
}

impl CreateWebApplicationTaskRequest {
    /// Create a web-application task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        web_application_target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateWebApplicationTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            web_application_target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateWebApplicationTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_web_application_task(
            &self.name,
            &self.web_application_target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_web_application_task")
    }
}

impl GmpRequest for CreateWebApplicationTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for moving a task to or from a remote slave.
#[derive(Debug, Clone)]
pub struct MoveTaskRequest {
    task_id: EntityId,
    slave_id: Option<EntityId>,
}

impl MoveTaskRequest {
    /// Create a task-move request.
    #[must_use]
    pub fn new(task_id: EntityId, slave_id: Option<EntityId>) -> Self {
        Self { task_id, slave_id }
    }
}

impl Request for MoveTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        move_task(&self.task_id, self.slave_id.as_ref()).to_bytes()
    }
}

impl GmpRequest for MoveTaskRequest {
    type Response = MoveTaskResponse;
}

/// Semantic request for listing audit tasks.
#[derive(Debug, Clone, Default)]
pub struct GetAuditsRequest {
    opts: GetTasksOpts,
}

impl GetAuditsRequest {
    /// Create an audit-list request.
    #[must_use]
    pub fn new(opts: GetTasksOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetAuditsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_audits(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetAuditsRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for creating an audit task.
#[derive(Debug, Clone)]
pub struct CreateAuditRequest {
    name: String,
    config_id: EntityId,
    target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateTaskOpts,
}

impl CreateAuditRequest {
    /// Create an audit-task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        config_id: EntityId,
        target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            config_id,
            target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateAuditRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_audit(
            &self.name,
            &self.config_id,
            &self.target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }
}

impl GmpRequest for CreateAuditRequest {
    type Response = CreateTaskResponse;
}

transitional_task_action_request!(
    GetAuditRequest,
    GetTasksResponse,
    get_audit,
    "Semantic request for one detailed audit task."
);
transitional_task_action_request!(
    CloneAuditRequest,
    CreateTaskResponse,
    clone_audit,
    "Semantic request for cloning an audit task."
);

/// Semantic request for modifying an audit task.
#[derive(Debug, Clone)]
pub struct ModifyAuditRequest {
    task_id: EntityId,
    opts: ModifyTaskOpts,
}

impl ModifyAuditRequest {
    /// Validate and create an audit-modification request.
    ///
    /// # Errors
    /// Returns the same construction errors as [`modify_audit`].
    pub fn new(task_id: EntityId, opts: ModifyTaskOpts) -> Result<Self, ModifyTaskError> {
        validate_modify_task_opts(&opts)?;
        Ok(Self { task_id, opts })
    }
}

impl Request for ModifyAuditRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_task_with_usage(&self.task_id, self.opts.clone(), Some(UsageType::Audit)).to_bytes()
    }
}

impl GmpRequest for ModifyAuditRequest {
    type Response = ModifyTaskResponse;
}

transitional_task_action_request!(
    DeleteAuditRequest,
    DeleteTaskResponse,
    delete_audit,
    "Semantic request for deleting an audit task."
);
transitional_task_action_request!(
    StartAuditRequest,
    StartTaskResponse,
    start_audit,
    "Semantic request for starting an audit task."
);
transitional_task_action_request!(
    StopAuditRequest,
    StopTaskResponse,
    stop_audit,
    "Semantic request for stopping an audit task."
);
transitional_task_action_request!(
    ResumeAuditRequest,
    ResumeTaskResponse,
    resume_audit,
    "Semantic request for resuming an audit task."
);

/// Build a `create_task` request for an import task.
#[must_use]
pub fn create_import_task(name: &str, comment: Option<&str>) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element("target").set_attribute("id", "0");
    add_text_element(&mut cmd, "comment", comment);
    cmd
}

/// Build a `create_task` request for an import task.
///
/// This is a compatibility alias for [`create_import_task`].
#[must_use]
pub fn create_container_task(name: &str, comment: Option<&str>) -> impl Request {
    create_import_task(name, comment)
}

/// Build a `create_task` request for an agent-group scan task.
#[must_use]
pub fn create_agent_group_task(
    name: &str,
    agent_group_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateAgentGroupTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(&mut cmd, "agent_group", agent_group_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    if let Some(schedule_id) = opts.schedule_id.as_ref() {
        add_id_element(&mut cmd, "schedule", schedule_id);
        if let Some(schedule_periods) = opts.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `create_task` request for an OCI image target scan task.
#[must_use]
pub fn create_oci_image_target_task(
    name: &str,
    oci_image_target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateOciImageTargetTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(&mut cmd, "oci_image_target", oci_image_target_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    if let Some(schedule_id) = opts.schedule_id.as_ref() {
        add_id_element(&mut cmd, "schedule", schedule_id);
        if let Some(schedule_periods) = opts.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `create_task` request for an OCI image target scan task.
///
/// This compatibility alias uses python-gvm's historic "container image"
/// helper name for the same GMP Next OCI image target task shape.
#[must_use]
pub fn create_container_image_task(
    name: &str,
    oci_image_target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateOciImageTargetTaskOpts,
) -> impl Request {
    create_oci_image_target_task(name, oci_image_target_id, scanner_id, opts)
}

fn create_task_with_usage(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
    usage_type: UsageType,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
    add_id_element(&mut cmd, "config", config_id);
    add_id_element(&mut cmd, "target", target_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    add_optional_id_element(&mut cmd, "schedule", opts.schedule_id.as_ref());
    if let Some(schedule_periods) = opts.schedule_periods {
        cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `create_task` request for a web application target.
#[must_use]
pub fn create_web_application_task(
    name: &str,
    web_application_target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateWebApplicationTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(
        &mut cmd,
        "web_application_target",
        web_application_target_id,
    );
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    if let Some(schedule_id) = opts.schedule_id.as_ref() {
        add_id_element(&mut cmd, "schedule", schedule_id);
        if let Some(schedule_periods) = opts.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

fn get_tasks_with_usage(opts: GetTasksOpts, usage_type: UsageType) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_tasks").attribute("usage_type", usage_type.as_gmp_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "schedules_only", opts.schedules_only);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    cmd
}

fn validate_modify_task_opts(opts: &ModifyTaskOpts) -> Result<(), ModifyTaskError> {
    if !matches!(opts.observer_group_ids, CollectionUpdate::Omitted)
        && matches!(opts.observers, CollectionUpdate::Omitted)
    {
        return Err(ModifyTaskError::ObserverGroupsWithoutUserUpdate);
    }
    Ok(())
}

fn modify_task_with_usage(
    task_id: &EntityId,
    opts: ModifyTaskOpts,
    usage_type: Option<UsageType>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_task").attribute("task_id", task_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(usage_type) = usage_type {
        cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
    }
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    add_scalar_id_update(&mut cmd, "schedule", &opts.schedule_id);
    if let Some(schedule_periods) = opts.schedule_periods {
        cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    add_optional_id_element(&mut cmd, "target", opts.target_id.as_ref());
    add_optional_id_element(&mut cmd, "config", opts.config_id.as_ref());
    add_optional_id_element(&mut cmd, "scanner", opts.scanner_id.as_ref());
    if let Some(alert_ids) = opts.alert_ids.as_ref() {
        if alert_ids.is_empty() {
            cmd.add_element("alert").set_attribute("id", "0");
        } else {
            for alert_id in alert_ids {
                add_id_element(&mut cmd, "alert", alert_id);
            }
        }
    }
    add_task_observer_update(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

fn add_task_observers(cmd: &mut XmlCommand, observers: &[String], observer_group_ids: &[EntityId]) {
    if observers.is_empty() && observer_group_ids.is_empty() {
        return;
    }
    let element = cmd.add_element("observers");
    if !observers.is_empty() {
        element.set_text(&observers.join(" "));
    }
    for group_id in observer_group_ids {
        element
            .add_child("group")
            .set_attribute("id", group_id.as_str());
    }
}

fn add_task_observer_update(
    cmd: &mut XmlCommand,
    observers: &CollectionUpdate<String>,
    observer_group_ids: &CollectionUpdate<EntityId>,
) {
    debug_assert!(
        matches!(observer_group_ids, CollectionUpdate::Omitted)
            || !matches!(observers, CollectionUpdate::Omitted),
        "task observer-group updates must be validated before encoding"
    );
    if matches!(observers, CollectionUpdate::Omitted)
        && matches!(observer_group_ids, CollectionUpdate::Omitted)
    {
        return;
    }

    let element = cmd.add_element("observers");
    if let CollectionUpdate::Replace(observers) = observers {
        if !observers.is_empty() {
            element.set_text(&observers.join(" "));
        }
    }
    match observer_group_ids {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(group_ids) if !group_ids.is_empty() => {
            for group_id in group_ids {
                element
                    .add_child("group")
                    .set_attribute("id", group_id.as_str());
            }
        }
        CollectionUpdate::Replace(_) | CollectionUpdate::Clear => {
            element.add_child("group").set_attribute("id", "0");
        }
    }
}

/// Build a `move_task` request.
#[must_use]
pub fn move_task(task_id: &EntityId, slave_id: Option<&EntityId>) -> impl Request {
    let mut cmd = XmlCommand::new("move_task").attribute("task_id", task_id.as_str());
    if let Some(slave_id) = slave_id {
        cmd.set_attribute("slave_id", slave_id.as_str());
    }
    cmd
}

/// Build a `create_task` request for an audit.
#[must_use]
pub fn create_audit(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
) -> impl Request {
    create_task_with_usage(
        name,
        config_id,
        target_id,
        scanner_id,
        opts,
        UsageType::Audit,
    )
}

/// Build a `get_tasks` request scoped to audits.
#[must_use]
pub fn get_audits(opts: GetTasksOpts) -> impl Request {
    get_tasks_with_usage(opts, UsageType::Audit)
}

/// Build a clone request for an existing audit.
#[must_use]
pub fn clone_audit(task_id: &EntityId) -> impl Request {
    XmlCommand::new("create_task").child_with_text("copy", task_id.as_str())
}

/// Build a `get_tasks` request for a single audit.
#[must_use]
pub fn get_audit(task_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tasks")
        .attribute("task_id", task_id.as_str())
        .attribute("usage_type", UsageType::Audit.as_gmp_str())
        .attribute("details", "1")
}

/// Build a `start_task` request for an audit.
#[must_use]
pub fn start_audit(task_id: &EntityId) -> impl Request {
    task_action_command("start_task", task_id)
}

/// Build a `stop_task` request for an audit.
#[must_use]
pub fn stop_audit(task_id: &EntityId) -> impl Request {
    task_action_command("stop_task", task_id)
}

/// Build a `resume_task` request for an audit.
#[must_use]
pub fn resume_audit(task_id: &EntityId) -> impl Request {
    task_action_command("resume_task", task_id)
}

/// Build a `modify_task` request scoped to audits.
///
/// # Errors
/// Returns [`ModifyTaskError::ObserverGroupsWithoutUserUpdate`] when observer
/// groups are updated without an explicit observer-user replacement or clear.
pub fn modify_audit(
    task_id: &EntityId,
    opts: ModifyTaskOpts,
) -> Result<impl Request, ModifyTaskError> {
    validate_modify_task_opts(&opts)?;
    Ok(modify_task_with_usage(
        task_id,
        opts,
        Some(UsageType::Audit),
    ))
}

/// Build a `delete_task` request for an audit.
#[must_use]
pub fn delete_audit(task_id: &EntityId) -> impl Request {
    XmlCommand::new("delete_task")
        .attribute("task_id", task_id.as_str())
        .attribute("ultimate", "0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn encoded(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(
            request
                .encode(GmpVersion(22, 8))
                .expect("valid canonical request"),
        )
        .expect("request XML is UTF-8")
    }

    #[test]
    fn canonical_task_requests_encode_exact_wire_xml() {
        let list = GetTasksRequest {
            filter_string: Some("name=production".into()),
            filter_id: Some(id("filter-1")),
            trash: Some(true),
            details: Some(true),
            schedules_only: Some(false),
            ignore_pagination: Some(true),
        };
        assert_eq!(
            encoded(&list),
            "<get_tasks details=\"1\" filt_id=\"filter-1\" filter=\"name=production\" ignore_pagination=\"1\" schedules_only=\"0\" trash=\"1\" usage_type=\"scan\"/>"
        );

        let task_id = id("task-1");
        assert_eq!(
            encoded(&GetTaskRequest::new(task_id.clone())),
            "<get_tasks details=\"1\" task_id=\"task-1\" usage_type=\"scan\"/>"
        );

        let mut create = CreateTaskRequest::new(
            "production",
            id("config-1"),
            id("target-1"),
            id("scanner-1"),
        );
        create.alterable = Some(true);
        create.schedule_id = Some(id("schedule-1"));
        create.alert_ids = vec![id("alert-1")];
        create.comment = Some("production scan".into());
        create.schedule_periods = Some(3);
        create.observers = vec!["alice".into()];
        create.observer_group_ids = vec![id("group-1")];
        create.preferences = vec![TaskPreference::new("max_hosts", "10")];
        assert_eq!(
            encoded(&create),
            "<create_task><name>production</name><usage_type>scan</usage_type><config id=\"config-1\"/><target id=\"target-1\"/><scanner id=\"scanner-1\"/><comment>production scan</comment><alterable>1</alterable><schedule id=\"schedule-1\"/><schedule_periods>3</schedule_periods><alert id=\"alert-1\"/><observers>alice<group id=\"group-1\"/></observers><preferences><preference><scanner_name>max_hosts</scanner_name><value>10</value></preference></preferences></create_task>"
        );

        let mut clone = CloneTaskRequest::new(task_id.clone());
        clone.comment = Some("copy comment".into());
        clone.alterable = Some(false);
        assert_eq!(
            encoded(&clone),
            "<create_task><comment>copy comment</comment><copy>task-1</copy><alterable>0</alterable></create_task>"
        );

        let mut modify = ModifyTaskRequest::new(task_id.clone());
        modify.name = Some("renamed".into());
        modify.schedule_id = ScalarUpdate::set(id("schedule-2"));
        modify.observers = CollectionUpdate::replace(["bob".into()]);
        modify.observer_group_ids = CollectionUpdate::replace([id("group-2")]);
        assert_eq!(
            encoded(&modify),
            "<modify_task task_id=\"task-1\"><name>renamed</name><schedule id=\"schedule-2\"/><observers>bob<group id=\"group-2\"/></observers></modify_task>"
        );

        assert_eq!(
            encoded(&DeleteTaskRequest::new(task_id.clone(), true)),
            "<delete_task task_id=\"task-1\" ultimate=\"1\"/>"
        );
        assert_eq!(
            encoded(&StartTaskRequest::new(task_id.clone())),
            "<start_task task_id=\"task-1\"/>"
        );
        assert_eq!(
            encoded(&StopTaskRequest::new(task_id.clone())),
            "<stop_task task_id=\"task-1\"/>"
        );
        assert_eq!(
            encoded(&ResumeTaskRequest::new(task_id)),
            "<resume_task task_id=\"task-1\"/>"
        );
    }

    #[test]
    fn canonical_task_final_values_validate_and_preferences_redact() {
        let secret = "credential-like preference secret";
        let preference = TaskPreference::new("custom", secret);
        let debug = format!("{preference:?}");
        assert!(debug.contains("custom"));
        assert!(!debug.contains(secret));
        assert!(debug.contains("<redacted>"));

        let mut create = CreateTaskRequest::new("valid", id("config"), id("target"), id("scanner"));
        create.name.clear();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut modify = ModifyTaskRequest::new(id("task"));
        modify.preferences = vec![TaskPreference::new("auto_delete", "yes")];
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField {
                field: "preferences.value",
                ..
            })
        ));
        modify.preferences = vec![TaskPreference::new("auto_delete_data", "1")];
        assert!(modify.validate().is_err());
        modify.preferences = vec![TaskPreference::new("auto_delete_data", "1200")];
        assert!(modify.validate().is_ok());
    }

    #[test]
    fn semantic_specialized_task_requests_match_legacy_builder_bytes() {
        let task_id = id("task-1");
        let scanner_id = id("scanner-1");
        assert_eq!(
            CreateImportTaskRequest::new("import", Some("comment".into())).to_bytes(),
            create_import_task("import", Some("comment")).to_bytes()
        );
        assert_eq!(
            CreateContainerTaskRequest::new("container", Some("comment".into())).to_bytes(),
            create_container_task("container", Some("comment")).to_bytes()
        );

        let agent_opts = CreateAgentGroupTaskOpts {
            comment: Some("agents".into()),
            alterable: Some(true),
            schedule_id: Some(id("schedule-1")),
            alert_ids: vec![id("alert-1")],
            schedule_periods: Some(2),
            observers: vec!["alice".into()],
            observer_group_ids: vec![id("group-1")],
            preferences: vec![("key".into(), "value".into())],
        };
        assert_eq!(
            CreateAgentGroupTaskRequest::new(
                "agent task",
                id("agent-group-1"),
                scanner_id.clone(),
                agent_opts.clone(),
            )
            .to_bytes(),
            create_agent_group_task("agent task", &id("agent-group-1"), &scanner_id, agent_opts,)
                .to_bytes()
        );

        let oci_opts = CreateOciImageTargetTaskOpts {
            comment: Some("images".into()),
            alterable: Some(true),
            schedule_id: Some(id("schedule-1")),
            alert_ids: vec![id("alert-1")],
            schedule_periods: Some(2),
            observers: vec!["alice".into()],
            observer_group_ids: vec![id("group-1")],
            preferences: vec![("key".into(), "value".into())],
        };
        assert_eq!(
            CreateOciImageTargetTaskRequest::new(
                "oci task",
                id("oci-target-1"),
                scanner_id.clone(),
                oci_opts.clone(),
            )
            .to_bytes(),
            create_oci_image_target_task(
                "oci task",
                &id("oci-target-1"),
                &scanner_id,
                oci_opts.clone(),
            )
            .to_bytes()
        );
        assert_eq!(
            CreateContainerImageTaskRequest::new(
                "container image task",
                id("oci-target-1"),
                scanner_id.clone(),
                oci_opts.clone(),
            )
            .to_bytes(),
            create_container_image_task(
                "container image task",
                &id("oci-target-1"),
                &scanner_id,
                oci_opts,
            )
            .to_bytes()
        );

        let web_opts = CreateWebApplicationTaskOpts {
            alterable: Some(true),
            schedule_id: Some(id("schedule-1")),
            alert_ids: vec![id("alert-1")],
            comment: Some("web".into()),
            schedule_periods: Some(2),
            observers: vec!["alice".into()],
            observer_group_ids: vec![id("group-1")],
            preferences: vec![("key".into(), "value".into())],
        };
        assert_eq!(
            CreateWebApplicationTaskRequest::new(
                "web task",
                id("web-target-1"),
                scanner_id.clone(),
                web_opts.clone(),
            )
            .to_bytes(),
            create_web_application_task("web task", &id("web-target-1"), &scanner_id, web_opts,)
                .to_bytes()
        );
        assert_eq!(
            MoveTaskRequest::new(task_id.clone(), Some(id("slave-1"))).to_bytes(),
            move_task(&task_id, Some(&id("slave-1"))).to_bytes()
        );
    }

    #[test]
    fn semantic_audit_requests_match_legacy_builder_bytes() {
        let task_id = id("task-1");
        let scanner_id = id("scanner-1");
        let list_opts = GetTasksOpts {
            details: Some(true),
            ..Default::default()
        };
        assert_eq!(
            GetAuditsRequest::new(list_opts.clone()).to_bytes(),
            get_audits(list_opts).to_bytes()
        );
        assert_eq!(
            GetAuditRequest::new(task_id.clone()).to_bytes(),
            get_audit(&task_id).to_bytes()
        );
        let audit_create_opts = CreateTaskOpts::default();
        assert_eq!(
            CreateAuditRequest::new(
                "audit",
                id("config-1"),
                id("target-1"),
                scanner_id.clone(),
                audit_create_opts.clone(),
            )
            .to_bytes(),
            create_audit(
                "audit",
                &id("config-1"),
                &id("target-1"),
                &scanner_id,
                audit_create_opts,
            )
            .to_bytes()
        );
        assert_eq!(
            CloneAuditRequest::new(task_id.clone()).to_bytes(),
            clone_audit(&task_id).to_bytes()
        );
        let audit_modify_opts = ModifyTaskOpts {
            comment: Some("updated".into()),
            ..Default::default()
        };
        assert_eq!(
            ModifyAuditRequest::new(task_id.clone(), audit_modify_opts.clone())
                .expect("valid semantic audit modification")
                .to_bytes(),
            modify_audit(&task_id, audit_modify_opts)
                .expect("valid builder audit modification")
                .to_bytes()
        );
        assert_eq!(
            DeleteAuditRequest::new(task_id.clone()).to_bytes(),
            delete_audit(&task_id).to_bytes()
        );
        assert_eq!(
            StartAuditRequest::new(task_id.clone()).to_bytes(),
            start_audit(&task_id).to_bytes()
        );
        assert_eq!(
            StopAuditRequest::new(task_id.clone()).to_bytes(),
            stop_audit(&task_id).to_bytes()
        );
        assert_eq!(
            ResumeAuditRequest::new(task_id.clone()).to_bytes(),
            resume_audit(&task_id).to_bytes()
        );
    }

    #[test]
    fn canonical_modify_task_rejects_implicit_observer_user_clear() {
        let mut request = ModifyTaskRequest::new(id("task-1"));
        request.observer_group_ids = CollectionUpdate::replace([id("group-1")]);
        assert!(matches!(
            request.validate(),
            Err(GmpRequestError::InvalidCombination { .. })
        ));
        let audit_opts = ModifyTaskOpts {
            observer_group_ids: CollectionUpdate::replace([id("group-1")]),
            ..Default::default()
        };
        assert_eq!(
            ModifyAuditRequest::new(id("audit-1"), audit_opts.clone()).err(),
            Some(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
        );
        assert_eq!(
            modify_audit(&id("audit-1"), audit_opts).err(),
            Some(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
        );
    }

    #[test]
    fn semantic_task_requests_have_the_expected_response_associations() {
        fn assert_response<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let task_id = id("task-1");
        assert_response::<_, GetTasksResponse>(&GetTasksRequest::default());
        assert_response::<_, GetTasksResponse>(&GetTaskRequest::new(task_id.clone()));
        assert_response::<_, CreateTaskResponse>(&CreateTaskRequest::new(
            "scan",
            id("config-1"),
            id("target-1"),
            id("scanner-1"),
        ));
        assert_response::<_, CreateTaskResponse>(&CloneTaskRequest::new(task_id.clone()));
        assert_response::<_, ModifyTaskResponse>(&ModifyTaskRequest::new(task_id.clone()));
        assert_response::<_, DeleteTaskResponse>(&DeleteTaskRequest::new(task_id.clone(), false));
        assert_response::<_, StartTaskResponse>(&StartTaskRequest::new(task_id.clone()));
        assert_response::<_, StopTaskResponse>(&StopTaskRequest::new(task_id.clone()));
        assert_response::<_, ResumeTaskResponse>(&ResumeTaskRequest::new(task_id.clone()));
        assert_response::<_, CreateTaskResponse>(&CreateImportTaskRequest::new("import", None));
        assert_response::<_, CreateTaskResponse>(&CreateContainerTaskRequest::new(
            "container",
            None,
        ));
        assert_response::<_, CreateTaskResponse>(&CreateAgentGroupTaskRequest::new(
            "agents",
            id("agent-group-1"),
            id("scanner-1"),
            CreateAgentGroupTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CreateOciImageTargetTaskRequest::new(
            "oci",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CreateContainerImageTaskRequest::new(
            "container image",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CreateWebApplicationTaskRequest::new(
            "web",
            id("web-target-1"),
            id("scanner-1"),
            CreateWebApplicationTaskOpts::default(),
        ));
        assert_response::<_, MoveTaskResponse>(&MoveTaskRequest::new(task_id.clone(), None));
        assert_response::<_, GetTasksResponse>(&GetAuditsRequest::default());
        assert_response::<_, GetTasksResponse>(&GetAuditRequest::new(task_id.clone()));
        assert_response::<_, CreateTaskResponse>(&CreateAuditRequest::new(
            "audit",
            id("config-1"),
            id("target-1"),
            id("scanner-1"),
            CreateTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CloneAuditRequest::new(task_id.clone()));
        assert_response::<_, ModifyTaskResponse>(
            &ModifyAuditRequest::new(task_id.clone(), ModifyTaskOpts::default())
                .expect("valid audit modification"),
        );
        assert_response::<_, DeleteTaskResponse>(&DeleteAuditRequest::new(task_id.clone()));
        assert_response::<_, StartTaskResponse>(&StartAuditRequest::new(task_id.clone()));
        assert_response::<_, StopTaskResponse>(&StopAuditRequest::new(task_id.clone()));
        assert_response::<_, ResumeTaskResponse>(&ResumeAuditRequest::new(task_id));
    }

    #[test]
    fn specialized_task_requests_preserve_next_only_semantic_names() {
        let agent = CreateAgentGroupTaskRequest::new(
            "agents",
            id("agent-group-1"),
            id("scanner-1"),
            CreateAgentGroupTaskOpts::default(),
        );
        assert_eq!(
            agent.semantic_command_name(),
            Some("create_agent_group_task")
        );

        let oci = CreateOciImageTargetTaskRequest::new(
            "oci",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        );
        assert_eq!(
            oci.semantic_command_name(),
            Some("create_oci_image_target_task")
        );
        let alias = CreateContainerImageTaskRequest::new(
            "container image",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        );
        assert_eq!(
            alias.semantic_command_name(),
            Some("create_oci_image_target_task")
        );

        let web = CreateWebApplicationTaskRequest::new(
            "web",
            id("web-target-1"),
            id("scanner-1"),
            CreateWebApplicationTaskOpts::default(),
        );
        assert_eq!(
            web.semantic_command_name(),
            Some("create_web_application_task")
        );
    }

    #[test]
    fn create_task_builds_full_xml() {
        let mut request = CreateTaskRequest::new("foo", id("c1"), id("t1"), id("s1"));
        request.alterable = Some(true);
        request.schedule_id = Some(id("sched1"));
        request.alert_ids = vec![id("a1"), id("a2")];
        request.comment = Some("bar".into());
        request.schedule_periods = Some(5);
        request.observers = vec!["alice".into(), "bob".into()];
        request.observer_group_ids = vec![id("group-1")];
        request.preferences = vec![TaskPreference::new("k", "v")];
        let rendered = encoded(&request);
        assert!(rendered.contains("<usage_type>scan</usage_type>"));
        assert!(rendered.contains("<config id=\"c1\"/>"));
        assert!(!rendered.contains("hosts_ordering"));
        assert!(rendered.contains("<schedule id=\"sched1\"/>"));
        assert!(rendered.contains("<alert id=\"a1\"/>"));
        assert!(rendered.contains("<observers>alice bob<group id=\"group-1\"/></observers>"));
        assert!(rendered.contains("<scanner_name>k</scanner_name><value>v</value>"));
    }

    #[test]
    fn create_web_application_task_builds_full_xml() {
        let rendered = xml(create_web_application_task(
            "web task",
            &id("wt1"),
            &id("s1"),
            CreateWebApplicationTaskOpts {
                alterable: Some(true),
                schedule_id: Some(id("sched1")),
                alert_ids: vec![id("a1"), id("a2")],
                comment: Some("scan web app".into()),
                schedule_periods: Some(5),
                observers: vec!["alice".into(), "bob".into()],
                observer_group_ids: vec![id("group-1")],
                preferences: vec![("k".into(), "v".into())],
            },
        ));
        assert_eq!(
            rendered,
            "<create_task><name>web task</name><usage_type>scan</usage_type><web_application_target id=\"wt1\"/><scanner id=\"s1\"/><comment>scan web app</comment><alterable>1</alterable><alert id=\"a1\"/><alert id=\"a2\"/><schedule id=\"sched1\"/><schedule_periods>5</schedule_periods><observers>alice bob<group id=\"group-1\"/></observers><preferences><preference><scanner_name>k</scanner_name><value>v</value></preference></preferences></create_task>"
        );
    }

    #[test]
    fn create_web_application_task_omits_schedule_periods_without_schedule() {
        assert_eq!(
            xml(create_web_application_task(
                "web task",
                &id("wt1"),
                &id("s1"),
                CreateWebApplicationTaskOpts {
                    schedule_periods: Some(5),
                    ..Default::default()
                },
            )),
            "<create_task><name>web task</name><usage_type>scan</usage_type><web_application_target id=\"wt1\"/><scanner id=\"s1\"/></create_task>"
        );
    }

    #[test]
    fn get_and_delete_task_commands_build_attributes() {
        assert_eq!(
            encoded(&GetTaskRequest::new(id("a1"))),
            "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"scan\"/>"
        );
        assert_eq!(
            encoded(&DeleteTaskRequest::new(id("a1"), true)),
            "<delete_task task_id=\"a1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn modify_and_action_commands_build_xml() {
        let mut request = ModifyTaskRequest::new(id("t1"));
        request.name = Some("foo".into());
        request.alert_ids = CollectionUpdate::Clear;
        let rendered = encoded(&request);
        assert_eq!(
            rendered,
            "<modify_task task_id=\"t1\"><name>foo</name><alert id=\"0\"/></modify_task>"
        );
        assert_eq!(
            xml(move_task(&id("a1"), Some(&id("s1")))),
            "<move_task slave_id=\"s1\" task_id=\"a1\"/>"
        );
        assert_eq!(
            encoded(&StartTaskRequest::new(id("a1"))),
            "<start_task task_id=\"a1\"/>"
        );
        assert_eq!(
            encoded(&ResumeTaskRequest::new(id("a1"))),
            "<resume_task task_id=\"a1\"/>"
        );
        assert_eq!(
            encoded(&StopTaskRequest::new(id("a1"))),
            "<stop_task task_id=\"a1\"/>"
        );
    }

    #[test]
    fn modify_task_builds_observer_user_list_text() {
        let mut request = ModifyTaskRequest::new(id("t1"));
        request.observers = CollectionUpdate::replace(["alice".into(), "bob".into()]);
        assert_eq!(
            encoded(&request),
            "<modify_task task_id=\"t1\"><observers>alice bob</observers></modify_task>"
        );
    }

    #[test]
    fn modify_task_distinguishes_omitted_replaced_and_cleared_observers() {
        assert_eq!(
            encoded(&ModifyTaskRequest::new(id("t1"))),
            "<modify_task task_id=\"t1\"/>"
        );
        let mut replace = ModifyTaskRequest::new(id("t1"));
        replace.observers = CollectionUpdate::replace(["alice".into()]);
        replace.observer_group_ids = CollectionUpdate::replace([id("group-1")]);
        assert_eq!(
            encoded(&replace),
            "<modify_task task_id=\"t1\"><observers>alice<group id=\"group-1\"/></observers></modify_task>"
        );
        let mut clear = ModifyTaskRequest::new(id("t1"));
        clear.observers = CollectionUpdate::Clear;
        assert_eq!(
            encoded(&clear),
            "<modify_task task_id=\"t1\"><observers/></modify_task>"
        );
        let mut clear_groups = ModifyTaskRequest::new(id("t1"));
        clear_groups.observers = CollectionUpdate::replace(["alice".into()]);
        clear_groups.observer_group_ids = CollectionUpdate::Clear;
        assert_eq!(
            encoded(&clear_groups),
            "<modify_task task_id=\"t1\"><observers>alice<group id=\"0\"/></observers></modify_task>"
        );
    }

    #[test]
    fn modify_task_rejects_group_update_without_explicit_users() {
        let mut request = ModifyTaskRequest::new(id("t1"));
        request.observer_group_ids = CollectionUpdate::replace([id("group-1")]);
        assert!(matches!(
            request.validate(),
            Err(GmpRequestError::InvalidCombination { .. })
        ));
    }

    #[test]
    fn modify_task_distinguishes_omitted_set_and_cleared_schedule() {
        assert_eq!(
            encoded(&ModifyTaskRequest::new(id("t1"))),
            "<modify_task task_id=\"t1\"/>"
        );
        let mut set = ModifyTaskRequest::new(id("t1"));
        set.schedule_id = ScalarUpdate::set(id("schedule-1"));
        assert_eq!(
            encoded(&set),
            "<modify_task task_id=\"t1\"><schedule id=\"schedule-1\"/></modify_task>"
        );
        let mut clear = ModifyTaskRequest::new(id("t1"));
        clear.schedule_id = ScalarUpdate::Clear;
        assert_eq!(
            encoded(&clear),
            "<modify_task task_id=\"t1\"><schedule id=\"0\"/></modify_task>"
        );
    }

    #[test]
    fn get_tasks_builds_optional_attributes() {
        let rendered = encoded(&GetTasksRequest {
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
            trash: Some(true),
            details: Some(true),
            schedules_only: Some(true),
            ignore_pagination: Some(true),
        });
        assert!(rendered.contains("usage_type=\"scan\""));
        assert!(rendered.contains("filter=\"name=foo\""));
        assert!(rendered.contains("filt_id=\"f1\""));
        assert!(rendered.contains("trash=\"1\""));
        assert!(rendered.contains("details=\"1\""));
        assert!(rendered.contains("schedules_only=\"1\""));
        assert!(rendered.contains("ignore_pagination=\"1\""));
    }

    #[test]
    fn audit_commands_build_xml() {
        assert!(xml(create_audit(
            "audit",
            &id("c1"),
            &id("t1"),
            &id("s1"),
            CreateTaskOpts::default(),
        ))
        .contains("<usage_type>audit</usage_type>"));
        assert_eq!(
            xml(get_audits(GetTasksOpts::default())),
            "<get_tasks usage_type=\"audit\"/>"
        );
        assert_eq!(
            xml(clone_audit(&id("a1"))),
            "<create_task><copy>a1</copy></create_task>"
        );
        assert_eq!(
            xml(get_audit(&id("a1"))),
            "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"audit\"/>"
        );
        assert_eq!(
            xml(
                modify_audit(
                    &id("a1"),
                    ModifyTaskOpts {
                        comment: Some("updated".into()),
                        ..Default::default()
                    },
                )
                .expect("valid audit update"),
            ),
            "<modify_task task_id=\"a1\"><comment>updated</comment><usage_type>audit</usage_type></modify_task>"
        );
        assert_eq!(xml(start_audit(&id("a1"))), "<start_task task_id=\"a1\"/>");
        assert_eq!(xml(stop_audit(&id("a1"))), "<stop_task task_id=\"a1\"/>");
        assert_eq!(
            xml(resume_audit(&id("a1"))),
            "<resume_task task_id=\"a1\"/>"
        );
        assert_eq!(
            xml(delete_audit(&id("a1"))),
            "<delete_task task_id=\"a1\" ultimate=\"0\"/>"
        );
    }
}
