// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::groups::{
    CloneGroupRequest, CreateGroupRequest, DeleteGroupRequest, GetGroupRequest, GetGroupsRequest,
    ModifyGroupRequest,
};
use gvm_gmp::commands::permissions::{
    ClonePermissionRequest, CreatePermissionRequest, DeletePermissionRequest, GetPermissionRequest,
    GetPermissionsOpts, GetPermissionsRequest, ModifyPermissionRequest, PermissionOpts,
};
use gvm_gmp::commands::roles::{
    CloneRoleRequest, CreateRoleRequest, DeleteRoleRequest, GetRoleRequest, GetRolesOpts,
    GetRolesRequest, ModifyRoleRequest, RoleOpts,
};
use gvm_gmp::commands::users::{
    CloneUserRequest, CreateUserRequest, DeleteUserRequest, GetUserRequest, GetUsersRequest,
    ModifyUserRequest,
};
use gvm_gmp::responses::{
    CreateGroupResponse, CreatePermissionResponse, CreateRoleResponse, CreateUserResponse,
    DeleteGroupResponse, DeletePermissionResponse, DeleteRoleResponse, DeleteUserResponse,
    GetGroupsResponse, GetPermissionsResponse, GetRolesResponse, GetUsersResponse,
    ModifyGroupResponse, ModifyPermissionResponse, ModifyRoleResponse, ModifyUserResponse,
};
use gvm_gmp::types::EntityId;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Users ─────────────────────────────────────────────────────────────────

    /// Send a `get_users` request and return a typed [`GetUsersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_users(
        &mut self,
        request: GetUsersRequest,
    ) -> Result<GetUsersResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a single-user `get_users` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_user(
        &mut self,
        request: GetUserRequest,
    ) -> Result<GetUsersResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_user` request and return a typed [`CreateUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_user(
        &mut self,
        request: CreateUserRequest,
    ) -> Result<CreateUserResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_user` request and return a typed [`CreateUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_user(
        &mut self,
        request: CloneUserRequest,
    ) -> Result<CreateUserResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_user` request and return a typed [`ModifyUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_user(
        &mut self,
        request: ModifyUserRequest,
    ) -> Result<ModifyUserResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_user` request and return a typed [`DeleteUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_user(
        &mut self,
        request: DeleteUserRequest,
    ) -> Result<DeleteUserResponse, GvmError> {
        self.execute(request).await
    }

    // ── Groups ────────────────────────────────────────────────────────────────

    /// Send a `get_groups` request and return a typed [`GetGroupsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_groups(
        &mut self,
        request: GetGroupsRequest,
    ) -> Result<GetGroupsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a single-group `get_groups` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_group(
        &mut self,
        request: GetGroupRequest,
    ) -> Result<GetGroupsResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `create_group` request and return a typed [`CreateGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_group(
        &mut self,
        request: CreateGroupRequest,
    ) -> Result<CreateGroupResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `clone_group` request and return a typed [`CreateGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_group(
        &mut self,
        request: CloneGroupRequest,
    ) -> Result<CreateGroupResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `modify_group` request and return a typed [`ModifyGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_group(
        &mut self,
        request: ModifyGroupRequest,
    ) -> Result<ModifyGroupResponse, GvmError> {
        self.execute(request).await
    }

    /// Send a `delete_group` request and return a typed [`DeleteGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_group(
        &mut self,
        request: DeleteGroupRequest,
    ) -> Result<DeleteGroupResponse, GvmError> {
        self.execute(request).await
    }

    // ── Roles ─────────────────────────────────────────────────────────────────

    /// Send a `get_roles` request and return a typed [`GetRolesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_roles(&mut self, opts: GetRolesOpts) -> Result<GetRolesResponse, GvmError> {
        self.execute(GetRolesRequest::new(opts)).await
    }

    /// Send a single-role `get_roles` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_role(&mut self, role_id: &EntityId) -> Result<GetRolesResponse, GvmError> {
        self.execute(GetRoleRequest::new(role_id.clone())).await
    }

    /// Send a `create_role` request and return a typed [`CreateRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_role(
        &mut self,
        name: &str,
        opts: RoleOpts,
    ) -> Result<CreateRoleResponse, GvmError> {
        self.execute(CreateRoleRequest::new(name, opts)).await
    }

    /// Send a `clone_role` request and return a typed [`CreateRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_role(&mut self, role_id: &EntityId) -> Result<CreateRoleResponse, GvmError> {
        self.execute(CloneRoleRequest::new(role_id.clone())).await
    }

    /// Send a `modify_role` request and return a typed [`ModifyRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_role(
        &mut self,
        role_id: &EntityId,
        opts: RoleOpts,
    ) -> Result<ModifyRoleResponse, GvmError> {
        self.execute(ModifyRoleRequest::new(role_id.clone(), opts))
            .await
    }

    /// Send a `delete_role` request and return a typed [`DeleteRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_role(
        &mut self,
        role_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteRoleResponse, GvmError> {
        self.execute(DeleteRoleRequest::new(role_id.clone(), ultimate))
            .await
    }

    // ── Permissions ───────────────────────────────────────────────────────────

    /// Send a `get_permissions` request and return a typed [`GetPermissionsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_permissions(
        &mut self,
        opts: GetPermissionsOpts,
    ) -> Result<GetPermissionsResponse, GvmError> {
        self.execute(GetPermissionsRequest::new(opts)).await
    }

    /// Send a single-permission `get_permissions` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_permission(
        &mut self,
        permission_id: &EntityId,
    ) -> Result<GetPermissionsResponse, GvmError> {
        self.execute(GetPermissionRequest::new(permission_id.clone()))
            .await
    }

    /// Send a `create_permission` request and return a typed [`CreatePermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_permission(
        &mut self,
        opts: PermissionOpts,
    ) -> Result<CreatePermissionResponse, GvmError> {
        self.execute(CreatePermissionRequest::new(opts)).await
    }

    /// Send a `clone_permission` request and return a typed [`CreatePermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_permission(
        &mut self,
        permission_id: &EntityId,
    ) -> Result<CreatePermissionResponse, GvmError> {
        self.execute(ClonePermissionRequest::new(permission_id.clone()))
            .await
    }

    /// Send a `modify_permission` request and return a typed [`ModifyPermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_permission(
        &mut self,
        permission_id: &EntityId,
        opts: PermissionOpts,
    ) -> Result<ModifyPermissionResponse, GvmError> {
        self.execute(ModifyPermissionRequest::new(permission_id.clone(), opts))
            .await
    }

    /// Send a `delete_permission` request and return a typed [`DeletePermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_permission(
        &mut self,
        permission_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeletePermissionResponse, GvmError> {
        self.execute(DeletePermissionRequest::new(
            permission_id.clone(),
            ultimate,
        ))
        .await
    }
}
