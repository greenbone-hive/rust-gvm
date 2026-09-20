// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical task and audit requests.

use std::fmt;

use gvm_protocol::{Request as _, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{
    add_filter_attrs, add_id_element, add_optional_id_element, add_scalar_id_update,
    add_text_element, bool_str, set_optional_bool_attr,
};
use crate::responses::{
    CreateTaskResponse, DeleteTaskResponse, GetTasksResponse, ModifyTaskResponse, MoveTaskResponse,
    ResumeTaskResponse, StartTaskResponse, StopTaskResponse,
};
use crate::types::{CollectionUpdate, EntityId, ScalarUpdate};
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

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

/// Semantic request for creating an import task.
#[derive(Debug, Clone)]
pub struct CreateImportTaskRequest {
    /// Import-task name.
    pub name: String,
    /// Optional import-task comment.
    pub comment: Option<String>,
}

impl CreateImportTaskRequest {
    /// Create an import-task request.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
        }
    }
}

impl GmpRequestCodec for CreateImportTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required_xml_text(&self.name, "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_task",
            "create_import_task",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(import_task_command(&self.name, self.comment.as_deref()).to_bytes())
    }
}

impl GmpRequest for CreateImportTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic compatibility-alias request for creating a container/import task.
#[derive(Debug, Clone)]
pub struct CreateContainerTaskRequest {
    /// Container/import-task name.
    pub name: String,
    /// Optional container/import-task comment.
    pub comment: Option<String>,
}

impl CreateContainerTaskRequest {
    /// Create a container/import-task request.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
        }
    }
}

impl GmpRequestCodec for CreateContainerTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required_xml_text(&self.name, "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_task",
            "create_container_task",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(import_task_command(&self.name, self.comment.as_deref()).to_bytes())
    }
}

impl GmpRequest for CreateContainerTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating an agent-group scan task.
#[derive(Debug, Clone)]
pub struct CreateAgentGroupTaskRequest {
    /// Task name.
    pub name: String,
    /// Agent-group relationship.
    pub agent_group_id: EntityId,
    /// Optional scanner relationship. When omitted, gvmd uses the scanner of
    /// the agent group; when present, gvmd requires the two to match.
    pub scanner_id: Option<EntityId>,
    /// Optional task comment.
    pub comment: Option<String>,
    /// Whether the task is alterable.
    pub alterable: Option<bool>,
    /// Optional schedule relationship.
    pub schedule_id: Option<EntityId>,
    /// Number of scheduled runs, or zero for no limit.
    pub schedule_periods: Option<u32>,
    /// Alert relationships.
    pub alert_ids: Vec<EntityId>,
    /// Observer user names.
    pub observers: Vec<String>,
    /// Observer group relationships.
    pub observer_group_ids: Vec<EntityId>,
    /// Ordered scanner preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl CreateAgentGroupTaskRequest {
    /// Create an agent-group task request.
    #[must_use]
    pub fn new(name: impl Into<String>, agent_group_id: EntityId) -> Self {
        Self {
            name: name.into(),
            agent_group_id,
            scanner_id: None,
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

impl GmpRequestCodec for CreateAgentGroupTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_specialized_task_common(
            &self.name,
            self.comment.as_deref(),
            self.schedule_id.as_ref(),
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
            SpecializedPreferenceKind::Agent,
        )?;
        validate_relationship_id(&self.agent_group_id, "agent_group_id")?;
        if let Some(scanner_id) = &self.scanner_id {
            validate_relationship_id(scanner_id, "scanner_id")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_task",
            "create_agent_group_task",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(specialized_task_command(
            &self.name,
            "agent_group",
            &self.agent_group_id,
            self.scanner_id.as_ref(),
            self.comment.as_deref(),
            self.alterable,
            self.schedule_id.as_ref(),
            self.schedule_periods,
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
        )
        .to_bytes())
    }
}

impl GmpRequest for CreateAgentGroupTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating an OCI image-target scan task.
#[derive(Debug, Clone)]
pub struct CreateOciImageTargetTaskRequest {
    /// Task name.
    pub name: String,
    /// OCI-image-target relationship.
    pub oci_image_target_id: EntityId,
    /// Container-image scanner relationship.
    pub scanner_id: EntityId,
    /// Optional task comment.
    pub comment: Option<String>,
    /// Whether the task is alterable.
    pub alterable: Option<bool>,
    /// Optional schedule relationship.
    pub schedule_id: Option<EntityId>,
    /// Number of scheduled runs, or zero for no limit.
    pub schedule_periods: Option<u32>,
    /// Alert relationships.
    pub alert_ids: Vec<EntityId>,
    /// Observer user names.
    pub observers: Vec<String>,
    /// Observer group relationships.
    pub observer_group_ids: Vec<EntityId>,
    /// Ordered scanner preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl CreateOciImageTargetTaskRequest {
    /// Create an OCI image-target task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        oci_image_target_id: EntityId,
        scanner_id: EntityId,
    ) -> Self {
        Self {
            name: name.into(),
            oci_image_target_id,
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

impl GmpRequestCodec for CreateOciImageTargetTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_specialized_task_common(
            &self.name,
            self.comment.as_deref(),
            self.schedule_id.as_ref(),
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
            SpecializedPreferenceKind::Container,
        )?;
        validate_relationship_id(&self.oci_image_target_id, "oci_image_target_id")?;
        validate_relationship_id(&self.scanner_id, "scanner_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_task",
            "create_oci_image_target_task",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(specialized_task_command(
            &self.name,
            "oci_image_target",
            &self.oci_image_target_id,
            Some(&self.scanner_id),
            self.comment.as_deref(),
            self.alterable,
            self.schedule_id.as_ref(),
            self.schedule_periods,
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
        )
        .to_bytes())
    }
}

impl GmpRequest for CreateOciImageTargetTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic compatibility-alias request for creating a container-image task.
#[derive(Debug, Clone)]
pub struct CreateContainerImageTaskRequest {
    /// Task name.
    pub name: String,
    /// OCI-image-target relationship.
    pub oci_image_target_id: EntityId,
    /// Container-image scanner relationship.
    pub scanner_id: EntityId,
    /// Optional task comment.
    pub comment: Option<String>,
    /// Whether the task is alterable.
    pub alterable: Option<bool>,
    /// Optional schedule relationship.
    pub schedule_id: Option<EntityId>,
    /// Number of scheduled runs, or zero for no limit.
    pub schedule_periods: Option<u32>,
    /// Alert relationships.
    pub alert_ids: Vec<EntityId>,
    /// Observer user names.
    pub observers: Vec<String>,
    /// Observer group relationships.
    pub observer_group_ids: Vec<EntityId>,
    /// Ordered scanner preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl CreateContainerImageTaskRequest {
    /// Create a container-image task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        oci_image_target_id: EntityId,
        scanner_id: EntityId,
    ) -> Self {
        Self {
            name: name.into(),
            oci_image_target_id,
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

impl GmpRequestCodec for CreateContainerImageTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_specialized_task_common(
            &self.name,
            self.comment.as_deref(),
            self.schedule_id.as_ref(),
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
            SpecializedPreferenceKind::Container,
        )?;
        validate_relationship_id(&self.oci_image_target_id, "oci_image_target_id")?;
        validate_relationship_id(&self.scanner_id, "scanner_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_task",
            "create_oci_image_target_task",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(specialized_task_command(
            &self.name,
            "oci_image_target",
            &self.oci_image_target_id,
            Some(&self.scanner_id),
            self.comment.as_deref(),
            self.alterable,
            self.schedule_id.as_ref(),
            self.schedule_periods,
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
        )
        .to_bytes())
    }
}

impl GmpRequest for CreateContainerImageTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating a web-application-target scan task.
#[derive(Debug, Clone)]
pub struct CreateWebApplicationTaskRequest {
    /// Task name.
    pub name: String,
    /// Web-application-target relationship.
    pub web_application_target_id: EntityId,
    /// Web-application scanner relationship.
    pub scanner_id: EntityId,
    /// Optional task comment.
    pub comment: Option<String>,
    /// Whether the task is alterable.
    pub alterable: Option<bool>,
    /// Optional schedule relationship.
    pub schedule_id: Option<EntityId>,
    /// Number of scheduled runs, or zero for no limit.
    pub schedule_periods: Option<u32>,
    /// Alert relationships.
    pub alert_ids: Vec<EntityId>,
    /// Observer user names.
    pub observers: Vec<String>,
    /// Observer group relationships.
    pub observer_group_ids: Vec<EntityId>,
    /// Ordered scanner preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl CreateWebApplicationTaskRequest {
    /// Create a web-application task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        web_application_target_id: EntityId,
        scanner_id: EntityId,
    ) -> Self {
        Self {
            name: name.into(),
            web_application_target_id,
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

impl GmpRequestCodec for CreateWebApplicationTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_specialized_task_common(
            &self.name,
            self.comment.as_deref(),
            self.schedule_id.as_ref(),
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
            SpecializedPreferenceKind::WebApplication,
        )?;
        validate_relationship_id(&self.web_application_target_id, "web_application_target_id")?;
        validate_relationship_id(&self.scanner_id, "scanner_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_task",
            "create_web_application_task",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(specialized_task_command(
            &self.name,
            "web_application_target",
            &self.web_application_target_id,
            Some(&self.scanner_id),
            self.comment.as_deref(),
            self.alterable,
            self.schedule_id.as_ref(),
            self.schedule_periods,
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
        )
        .to_bytes())
    }
}

impl GmpRequest for CreateWebApplicationTaskRequest {
    type Response = CreateTaskResponse;
}

/// Destination for a task move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskMoveDestination {
    /// Move the task back to gvmd's default master scanner.
    Master,
    /// Move the task to this slave scanner.
    Slave(EntityId),
}

/// Semantic request for moving a task to a slave scanner or back to the master.
#[derive(Debug, Clone)]
pub struct MoveTaskRequest {
    /// Task identifier to move.
    pub task_id: EntityId,
    /// Final scanner destination.
    pub destination: TaskMoveDestination,
}

impl MoveTaskRequest {
    /// Create a task-move request.
    #[must_use]
    pub fn new(task_id: EntityId, destination: TaskMoveDestination) -> Self {
        Self {
            task_id,
            destination,
        }
    }
}

impl GmpRequestCodec for MoveTaskRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if let TaskMoveDestination::Slave(scanner_id) = &self.destination {
            validate_relationship_id(scanner_id, "destination")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("move_task"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let destination = match &self.destination {
            TaskMoveDestination::Master => "",
            TaskMoveDestination::Slave(scanner_id) => scanner_id.as_str(),
        };
        Ok(XmlCommand::new("move_task")
            .attribute("task_id", self.task_id.as_str())
            .attribute("slave_id", destination)
            .to_bytes())
    }
}

impl GmpRequest for MoveTaskRequest {
    type Response = MoveTaskResponse;
}

/// Semantic request for listing audit tasks.
#[derive(Debug, Clone, Default)]
pub struct GetAuditsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan audits.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to limit results to scheduled audits.
    pub schedules_only: Option<bool>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
}

impl GmpRequestCodec for GetAuditsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_xml_text(self.filter_string.as_deref(), "filter_string")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_tasks", "get_audits"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut cmd = XmlCommand::new("get_tasks").attribute("usage_type", "audit");
        add_filter_attrs(
            &mut cmd,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        );
        set_optional_bool_attr(&mut cmd, "trash", self.trash);
        set_optional_bool_attr(&mut cmd, "details", self.details);
        set_optional_bool_attr(&mut cmd, "schedules_only", self.schedules_only);
        set_optional_bool_attr(&mut cmd, "ignore_pagination", self.ignore_pagination);
        Ok(cmd.to_bytes())
    }
}

impl GmpRequest for GetAuditsRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for creating an audit task.
#[derive(Debug, Clone)]
pub struct CreateAuditRequest {
    /// Audit name.
    pub name: String,
    /// Audit-policy relationship, encoded as gvmd's `config` element.
    pub policy_id: EntityId,
    /// Target relationship.
    pub target_id: EntityId,
    /// Scanner relationship.
    pub scanner_id: EntityId,
    /// Optional audit comment.
    pub comment: Option<String>,
    /// Whether the audit is alterable.
    pub alterable: Option<bool>,
    /// Optional schedule relationship.
    pub schedule_id: Option<EntityId>,
    /// Number of scheduled runs, or zero for no limit.
    pub schedule_periods: Option<u32>,
    /// Alert relationships.
    pub alert_ids: Vec<EntityId>,
    /// Observer user names.
    pub observers: Vec<String>,
    /// Observer group relationships.
    pub observer_group_ids: Vec<EntityId>,
    /// Ordered scanner preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl CreateAuditRequest {
    /// Create an audit-task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        policy_id: EntityId,
        target_id: EntityId,
        scanner_id: EntityId,
    ) -> Self {
        Self {
            name: name.into(),
            policy_id,
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

impl GmpRequestCodec for CreateAuditRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_required_xml_text(&self.name, "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")?;
        validate_relationship_id(&self.policy_id, "policy_id")?;
        validate_relationship_id(&self.target_id, "target_id")?;
        validate_relationship_id(&self.scanner_id, "scanner_id")?;
        if let Some(schedule_id) = &self.schedule_id {
            validate_relationship_id(schedule_id, "schedule_id")?;
        }
        validate_relationship_ids(&self.alert_ids, "alert_ids")?;
        validate_observer_names(&self.observers)?;
        validate_relationship_ids(&self.observer_group_ids, "observer_group_ids")?;
        validate_preferences(&self.preferences)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_task",
            "create_audit",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut cmd = XmlCommand::new("create_task");
        cmd.add_element_with_text("name", &self.name);
        cmd.add_element_with_text("usage_type", UsageType::Audit.as_gmp_str());
        add_id_element(&mut cmd, "config", &self.policy_id);
        add_id_element(&mut cmd, "target", &self.target_id);
        add_id_element(&mut cmd, "scanner", &self.scanner_id);
        add_task_create_values(
            &mut cmd,
            self.comment.as_deref(),
            self.alterable,
            self.schedule_id.as_ref(),
            self.schedule_periods,
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
        );
        Ok(cmd.to_bytes())
    }
}

impl GmpRequest for CreateAuditRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for one detailed audit task.
#[derive(Debug, Clone)]
pub struct GetAuditRequest {
    /// Audit identifier to retrieve.
    pub audit_id: EntityId,
}

impl GetAuditRequest {
    /// Create a detailed single-audit request.
    #[must_use]
    pub fn new(audit_id: EntityId) -> Self {
        Self { audit_id }
    }
}

impl GmpRequestCodec for GetAuditRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_tasks", "get_audit"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_tasks")
            .attribute("task_id", self.audit_id.as_str())
            .attribute("usage_type", UsageType::Audit.as_gmp_str())
            .attribute("details", "1")
            .to_bytes())
    }
}

impl GmpRequest for GetAuditRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for cloning an audit task.
#[derive(Debug, Clone)]
pub struct CloneAuditRequest {
    /// Existing audit identifier to copy.
    pub audit_id: EntityId,
    /// Optional non-empty comment override. Empty and omitted comments inherit.
    pub comment: Option<String>,
    /// Optional alterable override.
    pub alterable: Option<bool>,
}

impl CloneAuditRequest {
    /// Create an audit-clone request.
    #[must_use]
    pub fn new(audit_id: EntityId) -> Self {
        Self {
            audit_id,
            comment: None,
            alterable: None,
        }
    }
}

impl GmpRequestCodec for CloneAuditRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("create_task", "clone_audit"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut cmd = XmlCommand::new("create_task");
        add_text_element(&mut cmd, "comment", self.comment.as_deref());
        cmd.add_element_with_text("copy", self.audit_id.as_str());
        if let Some(alterable) = self.alterable {
            cmd.add_element_with_text("alterable", bool_str(alterable));
        }
        Ok(cmd.to_bytes())
    }
}

impl GmpRequest for CloneAuditRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for modifying an audit task.
#[derive(Debug, Clone)]
pub struct ModifyAuditRequest {
    /// Audit identifier to modify.
    pub audit_id: EntityId,
    /// Optional non-empty replacement name.
    pub name: Option<String>,
    /// Optional comment replacement; an empty value clears the comment.
    pub comment: Option<String>,
    /// Whether the audit is alterable.
    pub alterable: Option<bool>,
    /// Schedule update: preserve, set/replace, or detach.
    pub schedule_id: ScalarUpdate<EntityId>,
    /// Schedule-period update. With a schedule set/clear, omission resets to zero.
    pub schedule_periods: Option<u32>,
    /// Optional target replacement.
    pub target_id: Option<EntityId>,
    /// Optional policy replacement, encoded as gvmd's `config` element.
    pub policy_id: Option<EntityId>,
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
    /// Ordered scanner preference assignments.
    pub preferences: Vec<TaskPreference>,
}

impl ModifyAuditRequest {
    /// Create an audit-modification request with no field updates.
    #[must_use]
    pub fn new(audit_id: EntityId) -> Self {
        Self {
            audit_id,
            name: None,
            comment: None,
            alterable: None,
            schedule_id: ScalarUpdate::Omitted,
            schedule_periods: None,
            target_id: None,
            policy_id: None,
            scanner_id: None,
            alert_ids: CollectionUpdate::Omitted,
            observers: CollectionUpdate::Omitted,
            observer_group_ids: CollectionUpdate::Omitted,
            preferences: Vec::new(),
        }
    }
}

impl GmpRequestCodec for ModifyAuditRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_task_update_values(
            self.name.as_deref(),
            self.comment.as_deref(),
            &self.schedule_id,
            self.target_id.as_ref(),
            self.policy_id.as_ref(),
            self.scanner_id.as_ref(),
            &self.alert_ids,
            &self.observers,
            &self.observer_group_ids,
            &self.preferences,
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "modify_task",
            "modify_audit",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut cmd = XmlCommand::new("modify_task").attribute("task_id", self.audit_id.as_str());
        add_text_element(&mut cmd, "name", self.name.as_deref());
        if let Some(comment) = self.comment.as_deref() {
            cmd.add_element_with_text("comment", comment);
        }
        if let Some(alterable) = self.alterable {
            cmd.add_element_with_text("alterable", bool_str(alterable));
        }
        add_scalar_id_update(&mut cmd, "schedule", &self.schedule_id);
        if let Some(schedule_periods) = self.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
        add_optional_id_element(&mut cmd, "target", self.target_id.as_ref());
        add_optional_id_element(&mut cmd, "config", self.policy_id.as_ref());
        add_optional_id_element(&mut cmd, "scanner", self.scanner_id.as_ref());
        add_task_alert_update(&mut cmd, &self.alert_ids);
        add_task_observer_update(&mut cmd, &self.observers, &self.observer_group_ids);
        add_task_preferences(&mut cmd, &self.preferences);
        Ok(cmd.to_bytes())
    }
}

impl GmpRequest for ModifyAuditRequest {
    type Response = ModifyTaskResponse;
}

/// Semantic request for deleting an audit task.
#[derive(Debug, Clone)]
pub struct DeleteAuditRequest {
    /// Audit identifier to delete.
    pub audit_id: EntityId,
    /// Whether to delete permanently instead of moving to trash.
    pub ultimate: bool,
}

impl DeleteAuditRequest {
    /// Create an audit-deletion request.
    #[must_use]
    pub fn new(audit_id: EntityId, ultimate: bool) -> Self {
        Self { audit_id, ultimate }
    }
}

impl GmpRequestCodec for DeleteAuditRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "delete_task",
            "delete_audit",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("delete_task")
            .attribute("task_id", self.audit_id.as_str())
            .attribute("ultimate", bool_str(self.ultimate))
            .to_bytes())
    }
}

impl GmpRequest for DeleteAuditRequest {
    type Response = DeleteTaskResponse;
}

/// Semantic request for starting an audit task.
#[derive(Debug, Clone)]
pub struct StartAuditRequest {
    /// Audit identifier to start.
    pub audit_id: EntityId,
}

impl StartAuditRequest {
    /// Create an audit-start request.
    #[must_use]
    pub fn new(audit_id: EntityId) -> Self {
        Self { audit_id }
    }
}

impl GmpRequestCodec for StartAuditRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("start_task", "start_audit"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(task_action_command("start_task", &self.audit_id).to_bytes())
    }
}

impl GmpRequest for StartAuditRequest {
    type Response = StartTaskResponse;
}

/// Semantic request for stopping an audit task.
#[derive(Debug, Clone)]
pub struct StopAuditRequest {
    /// Audit identifier to stop.
    pub audit_id: EntityId,
}

impl StopAuditRequest {
    /// Create an audit-stop request.
    #[must_use]
    pub fn new(audit_id: EntityId) -> Self {
        Self { audit_id }
    }
}

impl GmpRequestCodec for StopAuditRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("stop_task", "stop_audit"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(task_action_command("stop_task", &self.audit_id).to_bytes())
    }
}

impl GmpRequest for StopAuditRequest {
    type Response = StopTaskResponse;
}

/// Semantic request for resuming an audit task.
#[derive(Debug, Clone)]
pub struct ResumeAuditRequest {
    /// Audit identifier to resume.
    pub audit_id: EntityId,
}

impl ResumeAuditRequest {
    /// Create an audit-resume request.
    #[must_use]
    pub fn new(audit_id: EntityId) -> Self {
        Self { audit_id }
    }
}

impl GmpRequestCodec for ResumeAuditRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "resume_task",
            "resume_audit",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(task_action_command("resume_task", &self.audit_id).to_bytes())
    }
}

impl GmpRequest for ResumeAuditRequest {
    type Response = ResumeTaskResponse;
}

fn import_task_command(name: &str, comment: Option<&str>) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element("target").set_attribute("id", "0");
    add_text_element(&mut cmd, "comment", comment);
    cmd
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecializedPreferenceKind {
    Agent,
    Container,
    WebApplication,
}

#[allow(clippy::too_many_arguments)]
fn validate_specialized_task_common(
    name: &str,
    comment: Option<&str>,
    schedule_id: Option<&EntityId>,
    alert_ids: &[EntityId],
    observers: &[String],
    observer_group_ids: &[EntityId],
    preferences: &[TaskPreference],
    kind: SpecializedPreferenceKind,
) -> Result<(), GmpRequestError> {
    validate_required_xml_text(name, "name")?;
    validate_optional_xml_text(comment, "comment")?;
    if let Some(schedule_id) = schedule_id {
        validate_relationship_id(schedule_id, "schedule_id")?;
    }
    validate_relationship_ids(alert_ids, "alert_ids")?;
    validate_observer_names(observers)?;
    validate_relationship_ids(observer_group_ids, "observer_group_ids")?;
    validate_preferences(preferences)?;
    for preference in preferences {
        if matches!(
            kind,
            SpecializedPreferenceKind::Container | SpecializedPreferenceKind::WebApplication
        ) && preference.name == "in_assets"
        {
            return Err(GmpRequestError::invalid_field(
                "preferences.value",
                "in_assets is not supported by this task scanner type",
            ));
        }
        if kind == SpecializedPreferenceKind::WebApplication
            && preference.name == "scan_mode"
            && !matches!(preference.value.as_str(), "active" | "safe")
        {
            return Err(GmpRequestError::invalid_field(
                "preferences.value",
                "scan_mode must be active or safe",
            ));
        }
        if kind == SpecializedPreferenceKind::WebApplication
            && preference.name == "ajax_spider_timeout"
            && preference.value.parse::<i64>().is_err()
        {
            return Err(GmpRequestError::invalid_field(
                "preferences.value",
                "ajax_spider_timeout must be a non-negative integer",
            ));
        }
        if kind == SpecializedPreferenceKind::WebApplication
            && preference.name == "ajax_spider_timeout"
            && preference.value.parse::<i64>().is_ok_and(|value| value < 0)
        {
            return Err(GmpRequestError::invalid_field(
                "preferences.value",
                "ajax_spider_timeout must be a non-negative integer",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn specialized_task_command(
    name: &str,
    target_element: &'static str,
    target_id: &EntityId,
    scanner_id: Option<&EntityId>,
    comment: Option<&str>,
    alterable: Option<bool>,
    schedule_id: Option<&EntityId>,
    schedule_periods: Option<u32>,
    alert_ids: &[EntityId],
    observers: &[String],
    observer_group_ids: &[EntityId],
    preferences: &[TaskPreference],
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(&mut cmd, target_element, target_id);
    add_optional_id_element(&mut cmd, "scanner", scanner_id);
    add_task_create_values(
        &mut cmd,
        comment,
        alterable,
        schedule_id,
        schedule_periods,
        alert_ids,
        observers,
        observer_group_ids,
        preferences,
    );
    cmd
}

#[allow(clippy::too_many_arguments)]
fn add_task_create_values(
    cmd: &mut XmlCommand,
    comment: Option<&str>,
    alterable: Option<bool>,
    schedule_id: Option<&EntityId>,
    schedule_periods: Option<u32>,
    alert_ids: &[EntityId],
    observers: &[String],
    observer_group_ids: &[EntityId],
    preferences: &[TaskPreference],
) {
    add_text_element(cmd, "comment", comment);
    if let Some(alterable) = alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    add_optional_id_element(cmd, "schedule", schedule_id);
    if let Some(schedule_periods) = schedule_periods {
        cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    for alert_id in alert_ids {
        add_id_element(cmd, "alert", alert_id);
    }
    add_task_observers(cmd, observers, observer_group_ids);
    add_task_preferences(cmd, preferences);
}

#[allow(clippy::too_many_arguments)]
fn validate_task_update_values(
    name: Option<&str>,
    comment: Option<&str>,
    schedule_id: &ScalarUpdate<EntityId>,
    target_id: Option<&EntityId>,
    config_id: Option<&EntityId>,
    scanner_id: Option<&EntityId>,
    alert_ids: &CollectionUpdate<EntityId>,
    observers: &CollectionUpdate<String>,
    observer_group_ids: &CollectionUpdate<EntityId>,
    preferences: &[TaskPreference],
) -> Result<(), GmpRequestError> {
    if let Some(name) = name {
        validate_required_xml_text(name, "name")?;
    }
    validate_optional_xml_text(comment, "comment")?;
    if let ScalarUpdate::Set(schedule_id) = schedule_id {
        validate_relationship_id(schedule_id, "schedule_id")?;
    }
    for (id, field) in [
        (target_id, "target_id"),
        (config_id, "config_id"),
        (scanner_id, "scanner_id"),
    ] {
        if let Some(id) = id {
            validate_relationship_id(id, field)?;
        }
    }
    if let CollectionUpdate::Replace(alert_ids) = alert_ids {
        validate_relationship_ids(alert_ids, "alert_ids")?;
    }
    if let CollectionUpdate::Replace(observers) = observers {
        validate_observer_names(observers)?;
    }
    if let CollectionUpdate::Replace(group_ids) = observer_group_ids {
        validate_relationship_ids(group_ids, "observer_group_ids")?;
    }
    if !matches!(observer_group_ids, CollectionUpdate::Omitted)
        && matches!(observers, CollectionUpdate::Omitted)
    {
        return Err(GmpRequestError::invalid_combination(
            &["observers", "observer_group_ids"],
            "observer-group updates require an explicit observer-user replacement or clear",
        ));
    }
    validate_preferences(preferences)
}

fn add_task_alert_update(cmd: &mut XmlCommand, alert_ids: &CollectionUpdate<EntityId>) {
    match alert_ids {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(alert_ids) if !alert_ids.is_empty() => {
            for alert_id in alert_ids {
                add_id_element(cmd, "alert", alert_id);
            }
        }
        CollectionUpdate::Replace(_) | CollectionUpdate::Clear => {
            cmd.add_element("alert").set_attribute("id", "0");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
