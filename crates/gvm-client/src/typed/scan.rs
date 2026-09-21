// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::scan_configs::{
    CloneScanConfigRequest, CreateScanConfigRequest, DeleteScanConfigRequest, GetPoliciesRequest,
    GetPolicyRequest, GetScanConfigRequest, GetScanConfigsRequest, ImportPolicyRequest,
    ImportScanConfigRequest, ModifyPolicySetCommentRequest, ModifyPolicySetNameRequest,
    ModifyScanConfigRequest, ModifyScanConfigSetCommentRequest, ModifyScanConfigSetNameRequest,
};
use gvm_gmp::commands::scanners::{
    CloneScannerRequest, CreateScannerRequest, DeleteScannerRequest, GetScannerRequest,
    GetScannersRequest, ModifyScannerRequest, VerifyScannerRequest,
};
use gvm_gmp::commands::schedules::{
    CloneScheduleRequest, CreateScheduleRequest, DeleteScheduleRequest, GetScheduleRequest,
    GetSchedulesRequest, ModifyScheduleRequest,
};
use gvm_gmp::commands::tasks::{
    CloneAuditRequest, CloneTaskRequest, CreateAgentGroupTaskRequest, CreateAuditRequest,
    CreateContainerImageTaskRequest, CreateContainerTaskRequest, CreateImportTaskRequest,
    CreateOciImageTargetTaskRequest, CreateTaskRequest, CreateWebApplicationTaskRequest,
    DeleteAuditRequest, DeleteTaskRequest, GetAuditRequest, GetAuditsRequest, GetTaskRequest,
    GetTasksRequest, ModifyAuditRequest, ModifyTaskRequest, MoveTaskRequest, ResumeAuditRequest,
    ResumeTaskRequest, StartAuditRequest, StartTaskRequest, StopAuditRequest, StopTaskRequest,
};
use gvm_gmp::commands::trashcan::{EmptyTrashcanRequest, RestoreRequest};
use gvm_gmp::responses::{
    CreateScanConfigResponse, CreateScannerResponse, CreateScheduleResponse, CreateTaskResponse,
    DeleteScanConfigResponse, DeleteScannerResponse, DeleteScheduleResponse, DeleteTaskResponse,
    EmptyTrashcanResponse, GetScanConfigsResponse, GetScannersResponse, GetSchedulesResponse,
    GetTasksResponse, ModifyScanConfigResponse, ModifyScannerResponse, ModifyScheduleResponse,
    ModifyTaskResponse, MoveTaskResponse, RestoreResponse, ResumeTaskResponse, StartTaskResponse,
    StopTaskResponse, VerifyScannerResponse,
};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Scan Configs ──────────────────────────────────────────────────────────

    /// Send a `get_scan_configs` request and return a typed [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_configs(
        &mut self,
        request: GetScanConfigsRequest,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_scan_config` request and return a typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_scan_config(
        &mut self,
        request: CreateScanConfigRequest,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_config` request that imports scan-config XML and return a
    /// typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the import XML is invalid, the request fails, or
    /// response parsing fails.
    pub async fn import_scan_config(
        &mut self,
        request: ImportScanConfigRequest,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_scan_config` request and return a typed [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config(
        &mut self,
        request: GetScanConfigRequest,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a policy-scoped `get_configs` request and return a typed
    /// [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_policies(
        &mut self,
        request: GetPoliciesRequest,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_configs` request for a single policy and return a typed
    /// [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_policy(
        &mut self,
        request: GetPolicyRequest,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_config` request that imports policy XML and return a
    /// typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the import XML is invalid, request sending fails, or
    /// response parsing fails.
    pub async fn import_policy(
        &mut self,
        request: ImportPolicyRequest,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_scan_config` request and return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config(
        &mut self,
        request: ModifyScanConfigRequest,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_config` request to set a scan-config name and return a
    /// typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config_set_name(
        &mut self,
        request: ModifyScanConfigSetNameRequest,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_config` request to set or clear a scan-config comment and
    /// return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config_set_comment(
        &mut self,
        request: ModifyScanConfigSetCommentRequest,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_config` request to set a policy name and return a typed
    /// [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_policy_set_name(
        &mut self,
        request: ModifyPolicySetNameRequest,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_config` request to set or clear a policy comment and
    /// return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_policy_set_comment(
        &mut self,
        request: ModifyPolicySetCommentRequest,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_scan_config` request and return a typed [`DeleteScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_scan_config(
        &mut self,
        request: DeleteScanConfigRequest,
    ) -> Result<DeleteScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_scan_config` request and return a typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scan_config(
        &mut self,
        request: CloneScanConfigRequest,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(request).await
    }

    // ── Scanners ──────────────────────────────────────────────────────────────

    /// Send a `get_scanners` request and return a typed [`GetScannersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scanners(
        &mut self,
        request: GetScannersRequest,
    ) -> Result<GetScannersResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_scanner` request and return a typed [`CreateScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_scanner(
        &mut self,
        request: CreateScannerRequest,
    ) -> Result<CreateScannerResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `get_scanner` request and return a typed [`GetScannersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scanner(
        &mut self,
        request: GetScannerRequest,
    ) -> Result<GetScannersResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_scanner` request and return a typed [`ModifyScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scanner(
        &mut self,
        request: ModifyScannerRequest,
    ) -> Result<ModifyScannerResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_scanner` request and return a typed [`DeleteScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_scanner(
        &mut self,
        request: DeleteScannerRequest,
    ) -> Result<DeleteScannerResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `verify_scanner` request and return a typed [`VerifyScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_scanner(
        &mut self,
        request: VerifyScannerRequest,
    ) -> Result<VerifyScannerResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_scanner` request and return a typed [`CreateScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scanner(
        &mut self,
        request: CloneScannerRequest,
    ) -> Result<CreateScannerResponse, GvmError> {
        self.execute(request).await
    }

    // ── Tasks ─────────────────────────────────────────────────────────────────

    /// Send a `get_tasks` request and return a typed [`GetTasksResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tasks(
        &mut self,
        request: GetTasksRequest,
    ) -> Result<GetTasksResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed single-task `get_tasks` request and return a typed
    /// [`GetTasksResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_task(
        &mut self,
        request: GetTaskRequest,
    ) -> Result<GetTasksResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_task` request and return a typed [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_task(
        &mut self,
        request: CreateTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a task-copy `create_task` request and return a typed
    /// [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_task(
        &mut self,
        request: CloneTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_task` import-task request and return a typed [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_import_task(
        &mut self,
        request: CreateImportTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send the compatibility-alias container/import `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_container_task(
        &mut self,
        request: CreateContainerTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an agent-group `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_agent_group_task(
        &mut self,
        request: CreateAgentGroupTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an OCI image-target `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_oci_image_target_task(
        &mut self,
        request: CreateOciImageTargetTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send the compatibility-alias container-image `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_container_image_task(
        &mut self,
        request: CreateContainerImageTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a web-application-target `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_web_application_task(
        &mut self,
        request: CreateWebApplicationTaskRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `move_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn move_task(
        &mut self,
        request: MoveTaskRequest,
    ) -> Result<MoveTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit-scoped `get_tasks` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audits(
        &mut self,
        request: GetAuditsRequest,
    ) -> Result<GetTasksResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed single-audit `get_tasks` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit(
        &mut self,
        request: GetAuditRequest,
    ) -> Result<GetTasksResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_audit(
        &mut self,
        request: CreateAuditRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit-copy `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_audit(
        &mut self,
        request: CloneAuditRequest,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit-scoped `modify_task` request.
    ///
    /// # Errors
    /// Returns an error if request construction, transmission, or response parsing fails.
    pub async fn modify_audit(
        &mut self,
        request: ModifyAuditRequest,
    ) -> Result<ModifyTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit `delete_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_audit(
        &mut self,
        request: DeleteAuditRequest,
    ) -> Result<DeleteTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit `start_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn start_audit(
        &mut self,
        request: StartAuditRequest,
    ) -> Result<StartTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit `stop_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn stop_audit(
        &mut self,
        request: StopAuditRequest,
    ) -> Result<StopTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an audit `resume_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn resume_audit(
        &mut self,
        request: ResumeAuditRequest,
    ) -> Result<ResumeTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `start_task` request and return a typed [`StartTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn start_task(
        &mut self,
        request: StartTaskRequest,
    ) -> Result<StartTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `resume_task` request and return a typed [`ResumeTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn resume_task(
        &mut self,
        request: ResumeTaskRequest,
    ) -> Result<ResumeTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_task` request and return a typed [`ModifyTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_task(
        &mut self,
        request: ModifyTaskRequest,
    ) -> Result<ModifyTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `stop_task` request and return a typed [`StopTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn stop_task(
        &mut self,
        request: StopTaskRequest,
    ) -> Result<StopTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_task` request and return a typed [`DeleteTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_task(
        &mut self,
        request: DeleteTaskRequest,
    ) -> Result<DeleteTaskResponse, GvmError> {
        self.execute(request).await
    }

    /// Send an `empty_trashcan` request and return a typed [`EmptyTrashcanResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn empty_trashcan(
        &mut self,
        request: EmptyTrashcanRequest,
    ) -> Result<EmptyTrashcanResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `restore` request through its baseline helper name.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn restore(&mut self, request: RestoreRequest) -> Result<RestoreResponse, GvmError> {
        self.execute(request).await
    }

    // ── Schedules ─────────────────────────────────────────────────────────────

    /// Send a `get_schedules` request and return a typed [`GetSchedulesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_schedules(
        &mut self,
        request: GetSchedulesRequest,
    ) -> Result<GetSchedulesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a detailed single-schedule `get_schedules` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_schedule(
        &mut self,
        request: GetScheduleRequest,
    ) -> Result<GetSchedulesResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_schedule` request and return a typed [`CreateScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_schedule(
        &mut self,
        request: CreateScheduleRequest,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a schedule-copy `create_schedule` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_schedule(
        &mut self,
        request: CloneScheduleRequest,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_schedule` request and return a typed
    /// [`ModifyScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_schedule(
        &mut self,
        request: ModifyScheduleRequest,
    ) -> Result<ModifyScheduleResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_schedule` request and return a typed
    /// [`DeleteScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_schedule(
        &mut self,
        request: DeleteScheduleRequest,
    ) -> Result<DeleteScheduleResponse, GvmError> {
        self.execute(request).await
    }
}
