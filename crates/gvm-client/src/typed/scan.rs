// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::scan_configs::{
    CloneScanConfigRequest, ConfigOpts, CreateScanConfigRequest, DeleteScanConfigRequest,
    GetPoliciesRequest, GetPolicyOpts, GetPolicyRequest, GetScanConfigRequest, GetScanConfigsOpts,
    GetScanConfigsRequest, ImportPolicyRequest, ImportScanConfigRequest,
    ModifyPolicySetCommentRequest, ModifyPolicySetNameRequest, ModifyScanConfigRequest,
    ModifyScanConfigSetCommentRequest, ModifyScanConfigSetNameRequest, SyncConfigRequest,
};
use gvm_gmp::commands::scanners::{
    CloneScannerRequest, CreateScannerRequest, DeleteScannerRequest, GetScannerRequest,
    GetScannersOpts, GetScannersRequest, ModifyScannerRequest, ScannerOpts, VerifyScannerRequest,
};
use gvm_gmp::commands::schedules::{
    CloneScheduleRequest, CreateScheduleRequest, CreateTypedScheduleRequest, DeleteScheduleRequest,
    GetScheduleRequest, GetSchedulesOpts, GetSchedulesRequest, ModifyScheduleRequest,
    ModifyTypedScheduleRequest, ScheduleOpts,
};
use gvm_gmp::commands::tasks::{
    CloneAuditRequest, CloneTaskRequest, CreateAgentGroupTaskOpts, CreateAgentGroupTaskRequest,
    CreateAuditRequest, CreateContainerImageTaskRequest, CreateContainerTaskRequest,
    CreateImportTaskRequest, CreateOciImageTargetTaskOpts, CreateOciImageTargetTaskRequest,
    CreateTaskOpts, CreateTaskRequest, CreateWebApplicationTaskOpts,
    CreateWebApplicationTaskRequest, DeleteAuditRequest, DeleteTaskRequest, GetAuditRequest,
    GetAuditsRequest, GetTaskRequest, GetTasksOpts, GetTasksRequest, ModifyAuditRequest,
    ModifyTaskOpts, ModifyTaskRequest, MoveTaskRequest, ResumeAuditRequest, ResumeTaskRequest,
    StartAuditRequest, StartTaskRequest, StopAuditRequest, StopTaskRequest,
};
use gvm_gmp::commands::trashcan::{
    EmptyTrashcanRequest, RestoreFromTrashcanRequest, RestoreRequest,
};
use gvm_gmp::responses::{
    CreateScanConfigResponse, CreateScannerResponse, CreateScheduleResponse, CreateTaskResponse,
    DeleteScanConfigResponse, DeleteScannerResponse, DeleteScheduleResponse, DeleteTaskResponse,
    EmptyTrashcanResponse, GetScanConfigsResponse, GetScannersResponse, GetSchedulesResponse,
    GetTasksResponse, ModifyScanConfigResponse, ModifyScannerResponse, ModifyScheduleResponse,
    ModifyTaskResponse, MoveTaskResponse, RestoreResponse, ResumeTaskResponse, StartTaskResponse,
    StopTaskResponse, SyncConfigResponse, VerifyScannerResponse,
};
use gvm_gmp::types::EntityId;
use gvm_gmp::ScheduleInput;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Scan Configs ──────────────────────────────────────────────────────────

    /// Send a `get_scan_configs` request and return a typed [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_configs(
        &mut self,
        opts: GetScanConfigsOpts,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetScanConfigsRequest::new(opts)).await
    }

    /// Send a `create_scan_config` request and return a typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_scan_config(
        &mut self,
        name: &str,
        base_id: Option<&EntityId>,
        opts: ConfigOpts,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(CreateScanConfigRequest::new(name, base_id.cloned(), opts))
            .await
    }

    /// Send a `create_config` request that imports scan-config XML and return a
    /// typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the import XML is invalid, the request fails, or
    /// response parsing fails.
    pub async fn import_scan_config(
        &mut self,
        scan_config_xml: &str,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(ImportScanConfigRequest::new(scan_config_xml)?)
            .await
    }

    /// Send a `get_scan_config` request and return a typed [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config(
        &mut self,
        config_id: &EntityId,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetScanConfigRequest::new(config_id.clone()))
            .await
    }

    /// Send a policy-scoped `get_configs` request and return a typed
    /// [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_policies(
        &mut self,
        opts: GetScanConfigsOpts,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetPoliciesRequest::new(opts)).await
    }

    /// Send a `get_configs` request for a single policy and return a typed
    /// [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_policy(
        &mut self,
        policy_id: &EntityId,
        opts: GetPolicyOpts,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetPolicyRequest::new(policy_id.clone(), opts))
            .await
    }

    /// Send a `create_config` request that imports policy XML and return a
    /// typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the import XML is invalid, request sending fails, or
    /// response parsing fails.
    pub async fn import_policy(
        &mut self,
        policy_xml: &str,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(ImportPolicyRequest::new(policy_xml)?).await
    }

    /// Send a `modify_scan_config` request and return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config(
        &mut self,
        config_id: &EntityId,
        opts: ConfigOpts,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyScanConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a `modify_config` request to set a scan-config name and return a
    /// typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config_set_name(
        &mut self,
        config_id: &EntityId,
        name: &str,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyScanConfigSetNameRequest::new(config_id.clone(), name))
            .await
    }

    /// Send a `modify_config` request to set or clear a scan-config comment and
    /// return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config_set_comment(
        &mut self,
        config_id: &EntityId,
        comment: Option<&str>,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyScanConfigSetCommentRequest::new(
            config_id.clone(),
            comment.map(str::to_string),
        ))
        .await
    }

    /// Send a `modify_config` request to set a policy name and return a typed
    /// [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_policy_set_name(
        &mut self,
        policy_id: &EntityId,
        name: &str,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyPolicySetNameRequest::new(policy_id.clone(), name))
            .await
    }

    /// Send a `modify_config` request to set or clear a policy comment and
    /// return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_policy_set_comment(
        &mut self,
        policy_id: &EntityId,
        comment: Option<&str>,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyPolicySetCommentRequest::new(
            policy_id.clone(),
            comment.map(str::to_string),
        ))
        .await
    }

    /// Send a `delete_scan_config` request and return a typed [`DeleteScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_scan_config(
        &mut self,
        config_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteScanConfigResponse, GvmError> {
        self.execute(DeleteScanConfigRequest::new(config_id.clone(), ultimate))
            .await
    }

    /// Send a `clone_scan_config` request and return a typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scan_config(
        &mut self,
        config_id: &EntityId,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(CloneScanConfigRequest::new(config_id.clone()))
            .await
    }

    /// Send the global `sync_config` request and return a typed
    /// [`SyncConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn sync_config(&mut self) -> Result<SyncConfigResponse, GvmError> {
        self.execute(SyncConfigRequest::new()).await
    }

    /// Send the global `sync_config` request and return a typed
    /// [`SyncConfigResponse`].
    ///
    /// The GMP command synchronizes all configs and does not accept a config
    /// identifier. The argument is retained temporarily for source
    /// compatibility and is ignored.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    #[deprecated(note = "use sync_config(), which has global semantics")]
    pub async fn sync_scan_config(
        &mut self,
        _config_id: &EntityId,
    ) -> Result<SyncConfigResponse, GvmError> {
        self.sync_config().await
    }

    // ── Scanners ──────────────────────────────────────────────────────────────

    /// Send a `get_scanners` request and return a typed [`GetScannersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scanners(
        &mut self,
        opts: GetScannersOpts,
    ) -> Result<GetScannersResponse, GvmError> {
        self.execute(GetScannersRequest::new(opts)).await
    }

    /// Send a `create_scanner` request and return a typed [`CreateScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_scanner(
        &mut self,
        name: &str,
        opts: ScannerOpts,
    ) -> Result<CreateScannerResponse, GvmError> {
        self.execute(CreateScannerRequest::new(name, opts)).await
    }

    /// Send a `get_scanner` request and return a typed [`GetScannersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<GetScannersResponse, GvmError> {
        self.execute(GetScannerRequest::new(scanner_id.clone()))
            .await
    }

    /// Send a `modify_scanner` request and return a typed [`ModifyScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scanner(
        &mut self,
        scanner_id: &EntityId,
        opts: ScannerOpts,
    ) -> Result<ModifyScannerResponse, GvmError> {
        self.execute(ModifyScannerRequest::new(scanner_id.clone(), opts))
            .await
    }

    /// Send a `delete_scanner` request and return a typed [`DeleteScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_scanner(
        &mut self,
        scanner_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteScannerResponse, GvmError> {
        self.execute(DeleteScannerRequest::new(scanner_id.clone(), ultimate))
            .await
    }

    /// Send a `verify_scanner` request and return a typed [`VerifyScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<VerifyScannerResponse, GvmError> {
        self.execute(VerifyScannerRequest::new(scanner_id.clone()))
            .await
    }

    /// Send a `clone_scanner` request and return a typed [`CreateScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<CreateScannerResponse, GvmError> {
        self.execute(CloneScannerRequest::new(scanner_id.clone()))
            .await
    }

    // ── Tasks ─────────────────────────────────────────────────────────────────

    /// Send a `get_tasks` request and return a typed [`GetTasksResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tasks(&mut self, opts: GetTasksOpts) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetTasksRequest::new(opts)).await
    }

    /// Send a detailed single-task `get_tasks` request and return a typed
    /// [`GetTasksResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_task(&mut self, task_id: &EntityId) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetTaskRequest::new(task_id.clone())).await
    }

    /// Send a `create_task` request and return a typed [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_task(
        &mut self,
        name: &str,
        config_id: &EntityId,
        target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateTaskRequest::new(
            name,
            config_id.clone(),
            target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a task-copy `create_task` request and return a typed
    /// [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_task(&mut self, task_id: &EntityId) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CloneTaskRequest::new(task_id.clone())).await
    }

    /// Send a `create_task` import-task request and return a typed [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_import_task(
        &mut self,
        name: &str,
        comment: Option<&str>,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateImportTaskRequest::new(
            name,
            comment.map(str::to_owned),
        ))
        .await
    }

    /// Send the compatibility-alias container/import `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_container_task(
        &mut self,
        name: &str,
        comment: Option<&str>,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateContainerTaskRequest::new(
            name,
            comment.map(str::to_owned),
        ))
        .await
    }

    /// Send an agent-group `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_agent_group_task(
        &mut self,
        name: &str,
        agent_group_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateAgentGroupTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateAgentGroupTaskRequest::new(
            name,
            agent_group_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send an OCI image-target `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_oci_image_target_task(
        &mut self,
        name: &str,
        oci_image_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateOciImageTargetTaskRequest::new(
            name,
            oci_image_target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send the compatibility-alias container-image `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_container_image_task(
        &mut self,
        name: &str,
        oci_image_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateContainerImageTaskRequest::new(
            name,
            oci_image_target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a web-application-target `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_web_application_task(
        &mut self,
        name: &str,
        web_application_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateWebApplicationTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateWebApplicationTaskRequest::new(
            name,
            web_application_target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `move_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn move_task(
        &mut self,
        task_id: &EntityId,
        slave_id: Option<&EntityId>,
    ) -> Result<MoveTaskResponse, GvmError> {
        self.execute(MoveTaskRequest::new(task_id.clone(), slave_id.cloned()))
            .await
    }

    /// Send an audit-scoped `get_tasks` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audits(&mut self, opts: GetTasksOpts) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetAuditsRequest::new(opts)).await
    }

    /// Send a detailed single-audit `get_tasks` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit(&mut self, audit_id: &EntityId) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_audit(
        &mut self,
        name: &str,
        config_id: &EntityId,
        target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateAuditRequest::new(
            name,
            config_id.clone(),
            target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send an audit-copy `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CloneAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit-scoped `modify_task` request.
    ///
    /// # Errors
    /// Returns an error if request construction, transmission, or response parsing fails.
    pub async fn modify_audit(
        &mut self,
        audit_id: &EntityId,
        opts: ModifyTaskOpts,
    ) -> Result<ModifyTaskResponse, GvmError> {
        self.execute(ModifyAuditRequest::new(audit_id.clone(), opts)?)
            .await
    }

    /// Send an audit `delete_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<DeleteTaskResponse, GvmError> {
        self.execute(DeleteAuditRequest::new(audit_id.clone()))
            .await
    }

    /// Send an audit `start_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn start_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<StartTaskResponse, GvmError> {
        self.execute(StartAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit `stop_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn stop_audit(&mut self, audit_id: &EntityId) -> Result<StopTaskResponse, GvmError> {
        self.execute(StopAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit `resume_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn resume_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<ResumeTaskResponse, GvmError> {
        self.execute(ResumeAuditRequest::new(audit_id.clone()))
            .await
    }

    /// Send a `start_task` request and return a typed [`StartTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn start_task(&mut self, task_id: &EntityId) -> Result<StartTaskResponse, GvmError> {
        self.execute(StartTaskRequest::new(task_id.clone())).await
    }

    /// Send a `resume_task` request and return a typed [`ResumeTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn resume_task(
        &mut self,
        task_id: &EntityId,
    ) -> Result<ResumeTaskResponse, GvmError> {
        self.execute(ResumeTaskRequest::new(task_id.clone())).await
    }

    /// Send a `modify_task` request and return a typed [`ModifyTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_task(
        &mut self,
        task_id: &EntityId,
        opts: ModifyTaskOpts,
    ) -> Result<ModifyTaskResponse, GvmError> {
        self.execute(ModifyTaskRequest::new(task_id.clone(), opts)?)
            .await
    }

    /// Send a `stop_task` request and return a typed [`StopTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn stop_task(&mut self, task_id: &EntityId) -> Result<StopTaskResponse, GvmError> {
        self.execute(StopTaskRequest::new(task_id.clone())).await
    }

    /// Send a `delete_task` request and return a typed [`DeleteTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_task(
        &mut self,
        task_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteTaskResponse, GvmError> {
        self.execute(DeleteTaskRequest::new(task_id.clone(), ultimate))
            .await
    }

    /// Send an `empty_trashcan` request and return a typed [`EmptyTrashcanResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn empty_trashcan(&mut self) -> Result<EmptyTrashcanResponse, GvmError> {
        self.execute(EmptyTrashcanRequest::new()).await
    }

    /// Send a `restore` request through its baseline helper name.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn restore(&mut self, resource_id: &EntityId) -> Result<RestoreResponse, GvmError> {
        self.execute(RestoreRequest::new(resource_id.clone())).await
    }

    /// Send a `restore` request and return a typed [`RestoreResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn restore_from_trashcan(
        &mut self,
        resource_id: &EntityId,
    ) -> Result<RestoreResponse, GvmError> {
        self.execute(RestoreFromTrashcanRequest::new(resource_id.clone()))
            .await
    }

    // ── Schedules ─────────────────────────────────────────────────────────────

    /// Send a `get_schedules` request and return a typed [`GetSchedulesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_schedules(
        &mut self,
        opts: GetSchedulesOpts,
    ) -> Result<GetSchedulesResponse, GvmError> {
        self.execute(GetSchedulesRequest::new(opts)).await
    }

    /// Send a detailed single-schedule `get_schedules` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_schedule(
        &mut self,
        schedule_id: &EntityId,
    ) -> Result<GetSchedulesResponse, GvmError> {
        self.execute(GetScheduleRequest::new(schedule_id.clone()))
            .await
    }

    /// Send a `create_schedule` request and return a typed [`CreateScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_schedule(
        &mut self,
        name: &str,
        opts: ScheduleOpts,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(CreateScheduleRequest::new(name, opts)).await
    }

    /// Send a `create_schedule` request from typed recurrence input.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_typed_schedule(
        &mut self,
        name: &str,
        input: ScheduleInput,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(CreateTypedScheduleRequest::new(name, input))
            .await
    }

    /// Send a schedule-copy `create_schedule` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_schedule(
        &mut self,
        schedule_id: &EntityId,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(CloneScheduleRequest::new(schedule_id.clone()))
            .await
    }

    /// Send a `modify_schedule` request using raw compatibility options and
    /// return a typed [`ModifyScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_schedule(
        &mut self,
        schedule_id: &EntityId,
        opts: ScheduleOpts,
    ) -> Result<ModifyScheduleResponse, GvmError> {
        self.execute(ModifyScheduleRequest::new(schedule_id.clone(), opts))
            .await
    }

    /// Send a `modify_schedule` request from typed recurrence input.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_typed_schedule(
        &mut self,
        schedule_id: &EntityId,
        input: ScheduleInput,
    ) -> Result<ModifyScheduleResponse, GvmError> {
        self.execute(ModifyTypedScheduleRequest::new(schedule_id.clone(), input))
            .await
    }

    /// Send a `delete_schedule` request and return a typed
    /// [`DeleteScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_schedule(
        &mut self,
        schedule_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteScheduleResponse, GvmError> {
        self.execute(DeleteScheduleRequest::new(schedule_id.clone(), ultimate))
            .await
    }
}
