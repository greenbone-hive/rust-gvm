// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::alerts::{
    AlertOpts, CloneAlertRequest, CreateAlertRequest, DeleteAlertRequest, GetAlertRequest,
    GetAlertsOpts, GetAlertsRequest, ModifyAlertRequest, TestAlertRequest, TriggerAlertOpts,
    TriggerAlertRequest,
};
use gvm_gmp::commands::filters::{
    CloneFilterRequest, CreateFilterRequest, DeleteFilterRequest, GetFilterRequest,
    GetFiltersRequest, ModifyFilterRequest,
};
use gvm_gmp::commands::notes::{
    CloneNoteRequest, CreateNoteRequest, DeleteNoteRequest, GetNoteRequest, GetNotesOpts,
    GetNotesRequest, ModifyNoteOpts, ModifyNoteRequest, NoteOpts,
};
use gvm_gmp::commands::overrides::{
    CloneOverrideRequest, CreateOverrideRequest, DeleteOverrideRequest, GetOverrideRequest,
    GetOverridesOpts, GetOverridesRequest, ModifyOverrideOpts, ModifyOverrideRequest, OverrideOpts,
};
use gvm_gmp::commands::tags::{
    CloneTagRequest, CreateTagRequest, DeleteTagRequest, GetTagRequest, GetTagsRequest,
    ModifyTagRequest,
};
use gvm_gmp::responses::{
    ActionResponse, CreateAlertResponse, CreateFilterResponse, CreateNoteResponse,
    CreateOverrideResponse, CreateTagResponse, DeleteAlertResponse, DeleteFilterResponse,
    DeleteNoteResponse, DeleteOverrideResponse, DeleteTagResponse, GetAlertsResponse,
    GetFiltersResponse, GetNotesResponse, GetOverridesResponse, GetReportsResponse,
    GetTagsResponse, ModifyAlertResponse, ModifyFilterResponse, ModifyNoteResponse,
    ModifyOverrideResponse, ModifyTagResponse,
};
use gvm_gmp::types::EntityId;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Alerts ────────────────────────────────────────────────────────────────

    /// Send a `get_alerts` request and return a typed [`GetAlertsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_alerts(&mut self, opts: GetAlertsOpts) -> Result<GetAlertsResponse, GvmError> {
        self.execute(GetAlertsRequest::new(opts)).await
    }

    /// Send a detailed single-alert `get_alerts` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_alert(&mut self, alert_id: &EntityId) -> Result<GetAlertsResponse, GvmError> {
        self.execute(GetAlertRequest::new(alert_id.clone())).await
    }

    /// Send a `create_alert` request and return a typed [`CreateAlertResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_alert(
        &mut self,
        name: &str,
        opts: AlertOpts,
    ) -> Result<CreateAlertResponse, GvmError> {
        self.execute(CreateAlertRequest::new(name, opts)).await
    }

    /// Send an alert-copy `create_alert` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_alert(
        &mut self,
        alert_id: &EntityId,
    ) -> Result<CreateAlertResponse, GvmError> {
        self.execute(CloneAlertRequest::new(alert_id.clone())).await
    }

    /// Send a `modify_alert` request and return a typed [`ModifyAlertResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_alert(
        &mut self,
        alert_id: &EntityId,
        opts: AlertOpts,
    ) -> Result<ModifyAlertResponse, GvmError> {
        self.execute(ModifyAlertRequest::new(alert_id.clone(), opts))
            .await
    }

    /// Send a `delete_alert` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_alert(
        &mut self,
        alert_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteAlertResponse, GvmError> {
        self.execute(DeleteAlertRequest::new(alert_id.clone(), ultimate))
            .await
    }

    /// Send a `test_alert` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn test_alert(&mut self, alert_id: &EntityId) -> Result<ActionResponse, GvmError> {
        self.execute(TestAlertRequest::new(alert_id.clone())).await
    }

    /// Trigger an alert for a report through the report query command.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn trigger_alert(
        &mut self,
        alert_id: &EntityId,
        report_id: &EntityId,
        opts: TriggerAlertOpts,
    ) -> Result<GetReportsResponse, GvmError> {
        self.execute(TriggerAlertRequest::new(
            alert_id.clone(),
            report_id.clone(),
            opts,
        ))
        .await
    }

    // ── Filters ───────────────────────────────────────────────────────────────

    /// Send a `get_filters` request and return a typed [`GetFiltersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_filters(
        &mut self,
        request: GetFiltersRequest,
    ) -> Result<GetFiltersResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed single-filter request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_filter(
        &mut self,
        request: GetFilterRequest,
    ) -> Result<GetFiltersResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_filter` request and return a typed [`CreateFilterResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_filter(
        &mut self,
        request: CreateFilterRequest,
    ) -> Result<CreateFilterResponse, GvmError> {
        self.execute(request).await
    }

    /// Clone a filter through `create_filter`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_filter(
        &mut self,
        request: CloneFilterRequest,
    ) -> Result<CreateFilterResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_filter` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_filter(
        &mut self,
        request: ModifyFilterRequest,
    ) -> Result<ModifyFilterResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_filter` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_filter(
        &mut self,
        request: DeleteFilterRequest,
    ) -> Result<DeleteFilterResponse, GvmError> {
        self.execute(request).await
    }

    // ── Notes ─────────────────────────────────────────────────────────────────

    /// Send a `get_notes` request and return a typed [`GetNotesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_notes(&mut self, opts: GetNotesOpts) -> Result<GetNotesResponse, GvmError> {
        self.execute(GetNotesRequest::new(opts)).await
    }

    /// Send a detailed single-note request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_note(&mut self, note_id: &EntityId) -> Result<GetNotesResponse, GvmError> {
        self.execute(GetNoteRequest::new(note_id.clone())).await
    }

    /// Send a `create_note` request and return a typed [`CreateNoteResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_note(
        &mut self,
        nvt_oid: &str,
        opts: NoteOpts,
    ) -> Result<CreateNoteResponse, GvmError> {
        self.execute(CreateNoteRequest::new(nvt_oid, opts)).await
    }

    /// Clone a note through `create_note`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_note(&mut self, note_id: &EntityId) -> Result<CreateNoteResponse, GvmError> {
        self.execute(CloneNoteRequest::new(note_id.clone())).await
    }

    /// Send a `modify_note` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_note(
        &mut self,
        note_id: &EntityId,
        opts: ModifyNoteOpts,
    ) -> Result<ModifyNoteResponse, GvmError> {
        self.execute(ModifyNoteRequest::new(note_id.clone(), opts))
            .await
    }

    /// Send a `delete_note` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_note(
        &mut self,
        note_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteNoteResponse, GvmError> {
        self.execute(DeleteNoteRequest::new(note_id.clone(), ultimate))
            .await
    }

    // ── Overrides ─────────────────────────────────────────────────────────────

    /// Send a `get_overrides` request and return a typed [`GetOverridesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_overrides(
        &mut self,
        opts: GetOverridesOpts,
    ) -> Result<GetOverridesResponse, GvmError> {
        self.execute(GetOverridesRequest::new(opts)).await
    }

    /// Send a detailed single-override request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_override(
        &mut self,
        override_id: &EntityId,
    ) -> Result<GetOverridesResponse, GvmError> {
        self.execute(GetOverrideRequest::new(override_id.clone()))
            .await
    }

    /// Send a `create_override` request and return a typed [`CreateOverrideResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_override(
        &mut self,
        nvt_oid: &str,
        opts: OverrideOpts,
    ) -> Result<CreateOverrideResponse, GvmError> {
        self.execute(CreateOverrideRequest::new(nvt_oid, opts))
            .await
    }

    /// Clone an override through `create_override`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_override(
        &mut self,
        override_id: &EntityId,
    ) -> Result<CreateOverrideResponse, GvmError> {
        self.execute(CloneOverrideRequest::new(override_id.clone()))
            .await
    }

    /// Send a `modify_override` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_override(
        &mut self,
        override_id: &EntityId,
        opts: ModifyOverrideOpts,
    ) -> Result<ModifyOverrideResponse, GvmError> {
        self.execute(ModifyOverrideRequest::new(override_id.clone(), opts))
            .await
    }

    /// Send a `delete_override` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_override(
        &mut self,
        override_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteOverrideResponse, GvmError> {
        self.execute(DeleteOverrideRequest::new(override_id.clone(), ultimate))
            .await
    }

    // ── Tags ──────────────────────────────────────────────────────────────────

    /// Send a `get_tags` request and return a typed [`GetTagsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tags(&mut self, request: GetTagsRequest) -> Result<GetTagsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed single-tag request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tag(&mut self, request: GetTagRequest) -> Result<GetTagsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_tag` request and return a typed [`CreateTagResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_tag(
        &mut self,
        request: CreateTagRequest,
    ) -> Result<CreateTagResponse, GvmError> {
        self.execute(request).await
    }

    /// Clone a tag through `create_tag`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_tag(
        &mut self,
        request: CloneTagRequest,
    ) -> Result<CreateTagResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_tag` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_tag(
        &mut self,
        request: ModifyTagRequest,
    ) -> Result<ModifyTagResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_tag` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_tag(
        &mut self,
        request: DeleteTagRequest,
    ) -> Result<DeleteTagResponse, GvmError> {
        self.execute(request).await
    }
}
