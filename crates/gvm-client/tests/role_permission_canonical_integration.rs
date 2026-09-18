// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{CommandSupport, GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::permissions::*;
use gvm_gmp::commands::roles::*;
use gvm_gmp::{EntityId, GmpRequestError, PermissionSubjectType, ScalarUpdate};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid id")
}
async fn setup(version: MockVersion) -> (MockGmpServer, GmpClient<UnixSocketConnection>) {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts");
    let mut client = GmpClient::connect(UnixSocketConnection::with_path(
        server.socket_path().expect("socket"),
    ))
    .await
    .expect("connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate");
    (server, client)
}

#[tokio::test]
async fn mutated_requests_fail_before_transport_with_safe_diagnostics() {
    let (server, mut client) = setup(MockVersion::V22_4).await;
    server.clear_history();
    let mut create_role = CreateRoleRequest::new("role");
    create_role.name.clear();
    let errors = [
        client
            .create_role(create_role)
            .await
            .expect_err("invalid role"),
        client
            .modify_role(ModifyRoleRequest::new(
                id("r1"),
                "",
                "private-marker",
                Vec::new(),
            ))
            .await
            .expect_err("invalid modify"),
        client
            .clone_role(CloneRoleRequest {
                role_id: id("r1"),
                name: Some(String::new()),
                comment: None,
            })
            .await
            .expect_err("invalid clone"),
        client
            .create_permission(CreatePermissionRequest::new(
                "",
                PermissionSubject::new(id("s1"), PermissionSubjectType::User),
            ))
            .await
            .expect_err("invalid permission"),
        client
            .modify_permission(ModifyPermissionRequest {
                name: Some(String::new()),
                comment: Some("private-marker".into()),
                ..ModifyPermissionRequest::new(id("p1"))
            })
            .await
            .expect_err("invalid modify"),
    ];
    for error in errors {
        assert!(matches!(
            error,
            GvmError::Request(GmpRequestError::InvalidField { .. })
        ));
        assert!(!format!("{error:?} {error}").contains("private-marker"));
    }
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn permission_lifecycle_preserves_replaces_clears_and_clones() {
    let (server, mut client) = setup(MockVersion::V22_8).await;
    let role = client
        .create_role(CreateRoleRequest::new("operators"))
        .await
        .expect("role")
        .id;
    let subject = PermissionSubject::new(role.clone(), PermissionSubjectType::Role);
    let mut create = CreatePermissionRequest::new("get_roles", subject);
    create.comment = Some("original".into());
    create.resource = Some(PermissionResource::new(role.clone()));
    let permission = client
        .create_permission(create)
        .await
        .expect("permission")
        .id;
    let listed = client
        .get_permissions(GetPermissionsRequest::default())
        .await
        .expect("list");
    let original = listed
        .items
        .iter()
        .find(|p| p.meta.id == permission)
        .expect("original");
    assert_eq!(original.resource_type.as_deref(), Some("role"));
    assert_eq!(original.subject_type.as_deref(), Some("role"));

    client
        .modify_permission(ModifyPermissionRequest::new(permission.clone()))
        .await
        .expect("preserve");
    let preserved = client
        .get_permission(GetPermissionRequest::new(permission.clone()))
        .await
        .expect("detail");
    assert_eq!(preserved.items[0].meta.comment.as_deref(), Some("original"));
    assert_eq!(
        preserved.items[0].resource.as_ref().expect("resource").id,
        role
    );

    let mut clone = ClonePermissionRequest::new(permission.clone());
    clone.comment = Some("copied".into());
    let copied = client.clone_permission(clone).await.expect("clone").id;
    let clone = client
        .get_permission(GetPermissionRequest::new(copied.clone()))
        .await
        .expect("clone detail");
    assert_eq!(clone.items[0].meta.name, "get_roles");
    assert_eq!(clone.items[0].meta.comment.as_deref(), Some("copied"));
    assert_eq!(clone.items[0].subject, original.subject);
    assert_eq!(clone.items[0].resource, original.resource);

    client
        .modify_permission(ModifyPermissionRequest {
            comment: Some(String::new()),
            resource_id: ScalarUpdate::Clear,
            ..ModifyPermissionRequest::new(permission.clone())
        })
        .await
        .expect("clear");
    let cleared = client
        .get_permission(GetPermissionRequest::new(permission.clone()))
        .await
        .expect("cleared");
    assert_eq!(cleared.items[0].meta.comment, None);
    assert_eq!(cleared.items[0].resource, None);
    assert_eq!(cleared.items[0].resource_type, None);
    assert_eq!(cleared.items[0].subject, original.subject);

    client
        .modify_permission(ModifyPermissionRequest {
            name: Some("Super".into()),
            resource_id: ScalarUpdate::Set(role.clone()),
            resource_type: Some("role".into()),
            subject_id: Some(role.clone()),
            ..ModifyPermissionRequest::new(permission.clone())
        })
        .await
        .expect("replace");
    // A type-only resource update must preserve the identifier.
    client
        .modify_permission(ModifyPermissionRequest {
            resource_type: Some("role".into()),
            subject_type: Some(PermissionSubjectType::Role),
            ..ModifyPermissionRequest::new(permission.clone())
        })
        .await
        .expect("partial references");
    let replaced = client
        .get_permission(GetPermissionRequest::new(permission.clone()))
        .await
        .expect("replaced");
    assert_eq!(replaced.items[0].meta.name, "Super");
    assert_eq!(
        replaced.items[0].resource.as_ref().expect("resource").id,
        role
    );

    for identifier in [permission, copied] {
        client
            .delete_permission(DeletePermissionRequest::new(identifier.clone(), true))
            .await
            .expect("delete");
        let error = client
            .get_permission(GetPermissionRequest::new(identifier))
            .await
            .expect_err("missing");
        assert!(matches!(error, GvmError::Server { status: 404, .. }));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn baseline_support_aliases_and_raw_access_are_preserved() {
    let (server, mut client) = setup(MockVersion::V22_4).await;
    for command in [
        "get_roles",
        "create_role",
        "modify_role",
        "delete_role",
        "get_permissions",
        "create_permission",
        "modify_permission",
        "delete_permission",
    ] {
        assert_eq!(client.command_support(command), CommandSupport::Supported);
    }
    server.clear_history();
    let role = client
        .execute(CreateRoleRequest::new("role"))
        .await
        .expect("execute")
        .id;
    client
        .execute(GetRoleRequest::new(role.clone()))
        .await
        .expect("detail alias");
    client
        .execute(CloneRoleRequest::new(role))
        .await
        .expect("clone alias");
    client.call(b"<get_roles/>".as_slice()).await.expect("raw");
    let names = server
        .command_history()
        .iter()
        .map(|r| r.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        ["create_role", "get_roles", "create_role", "get_roles"]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn role_clone_copies_command_permissions_without_user_membership() {
    let (server, mut client) = setup(MockVersion::V22_8).await;
    let mut create = CreateRoleRequest::new("operators");
    create.users = vec!["alice".into()];
    create.comment = Some("original".into());
    let role = client.create_role(create).await.expect("role").id;
    let subject = PermissionSubject::new(role.clone(), PermissionSubjectType::Role);
    client
        .create_permission(CreatePermissionRequest::new("get_tasks", subject.clone()))
        .await
        .expect("command permission");
    let mut scoped = CreatePermissionRequest::new("get_roles", subject);
    scoped.resource = Some(PermissionResource::new(role.clone()));
    client
        .create_permission(scoped)
        .await
        .expect("resource permission");
    let first_automatic_clone = client
        .clone_role(CloneRoleRequest::new(role.clone()))
        .await
        .expect("first automatic copy")
        .id;
    let first_automatic_detail = client
        .get_role(GetRoleRequest::new(first_automatic_clone.clone()))
        .await
        .expect("first automatic copy detail");
    assert_eq!(
        first_automatic_detail.items[0].meta.name,
        "operators Clone 1"
    );
    assert!(first_automatic_detail.items[0].users.is_empty());
    assert_eq!(
        first_automatic_detail.items[0].meta.comment.as_deref(),
        Some("original")
    );

    let second_automatic_clone = client
        .clone_role(CloneRoleRequest::new(role.clone()))
        .await
        .expect("second automatic copy")
        .id;
    let second_automatic_detail = client
        .get_role(GetRoleRequest::new(second_automatic_clone))
        .await
        .expect("second automatic copy detail");
    assert_eq!(
        second_automatic_detail.items[0].meta.name,
        "operators Clone 2"
    );

    let explicit_clone = client
        .clone_role(CloneRoleRequest {
            role_id: role.clone(),
            name: Some("copy".into()),
            comment: Some(String::new()),
        })
        .await
        .expect("copy")
        .id;
    let detail = client
        .get_role(GetRoleRequest::new(explicit_clone.clone()))
        .await
        .expect("detail");
    assert_eq!(detail.items[0].meta.name, "copy");
    assert!(detail.items[0].users.is_empty());
    assert_eq!(detail.items[0].meta.comment.as_deref(), Some("original"));
    let permissions = client
        .get_permissions(GetPermissionsRequest::default())
        .await
        .expect("permissions");
    let copied = permissions
        .items
        .iter()
        .filter(|p| p.subject.as_ref().is_some_and(|s| s.id == explicit_clone))
        .collect::<Vec<_>>();
    assert_eq!(copied.len(), 1);
    assert_eq!(copied[0].meta.name, "get_tasks");
    assert!(copied[0].resource.is_none());

    // Raw omission has replacement semantics for role fields too.
    client
        .call(format!("<modify_role role_id=\"{role}\"/>").as_bytes())
        .await
        .expect("raw replacement");
    let replaced = client
        .get_role(GetRoleRequest::new(role))
        .await
        .expect("replaced");
    assert!(replaced.items[0].meta.name.is_empty());
    assert!(replaced.items[0].meta.comment.is_none());
    assert!(replaced.items[0].users.is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn explicit_role_clone_collision_is_atomic_and_trash_name_is_reusable() {
    let (server, mut client) = setup(MockVersion::V22_8).await;
    let role = client
        .create_role(CreateRoleRequest::new("operators"))
        .await
        .expect("role")
        .id;
    client
        .create_permission(CreatePermissionRequest::new(
            "get_tasks",
            PermissionSubject::new(role.clone(), PermissionSubjectType::Role),
        ))
        .await
        .expect("command permission");
    let first_copy = client
        .clone_role(CloneRoleRequest {
            role_id: role.clone(),
            name: Some("copy".into()),
            comment: None,
        })
        .await
        .expect("first explicit clone")
        .id;
    let role_count = client
        .get_roles(GetRolesRequest::default())
        .await
        .expect("roles before collision")
        .items
        .len();
    let permission_count = client
        .get_permissions(GetPermissionsRequest::default())
        .await
        .expect("permissions before collision")
        .items
        .len();

    let collision = client
        .clone_role(CloneRoleRequest {
            role_id: role.clone(),
            name: Some("copy".into()),
            comment: None,
        })
        .await
        .expect_err("active explicit clone name must collide");
    assert!(matches!(collision, GvmError::Server { status: 400, .. }));
    assert_eq!(
        client
            .get_roles(GetRolesRequest::default())
            .await
            .expect("roles after collision")
            .items
            .len(),
        role_count
    );
    assert_eq!(
        client
            .get_permissions(GetPermissionsRequest::default())
            .await
            .expect("permissions after collision")
            .items
            .len(),
        permission_count
    );

    client
        .delete_role(DeleteRoleRequest::new(first_copy, false))
        .await
        .expect("trash explicit clone");
    let reused = client
        .clone_role(CloneRoleRequest {
            role_id: role,
            name: Some("copy".into()),
            comment: None,
        })
        .await
        .expect("trashed role name is reusable")
        .id;
    let reused = client
        .get_role(GetRoleRequest::new(reused))
        .await
        .expect("reused-name clone detail");
    assert_eq!(reused.items[0].meta.name, "copy");
    server.shutdown().await;
}

#[tokio::test]
async fn server_state_dependent_permission_validation_is_atomic() {
    let (server, mut client) = setup(MockVersion::V22_8).await;
    for raw in [
        "<create_permission><name>get_tasks</name></create_permission>",
        "<create_permission><name>get_version</name><subject id=\"s1\"><type>user</type></subject></create_permission>",
    ] {
        assert!(matches!(client.call(raw.as_bytes()).await, Err(GvmError::Server {status: 400, ..})));
    }
    assert!(matches!(
        client
            .call(
                b"<create_permission><name>Super</name><subject id=\"s1\"><type>user</type></subject></create_permission>"
                    .as_slice()
            )
            .await,
        Err(GvmError::Server { status: 404, .. })
    ));
    assert!(matches!(
        client
            .call(
                b"<create_permission><name>Super</name><resource id=\"r1\"><type>task</type></resource><subject id=\"s1\"><type>user</type></subject></create_permission>"
                    .as_slice()
            )
            .await,
        Err(GvmError::Server { status: 400, .. })
    ));
    let role = client
        .create_role(CreateRoleRequest::new("operators"))
        .await
        .expect("role")
        .id;
    let mut create = CreatePermissionRequest::new(
        "Super",
        PermissionSubject::new(role.clone(), PermissionSubjectType::Role),
    );
    create.resource = Some(PermissionResource {
        id: role.clone(),
        resource_type: Some("role".into()),
    });
    create.comment = Some("preserve on error".into());
    let permission = client.create_permission(create).await.expect("Super").id;
    let error = client
        .modify_permission(ModifyPermissionRequest {
            comment: Some("must roll back".into()),
            resource_id: ScalarUpdate::Clear,
            resource_type: Some("task".into()),
            ..ModifyPermissionRequest::new(permission.clone())
        })
        .await
        .expect_err("invalid supplied type is checked before cleared resource");
    assert!(matches!(error, GvmError::Server { status: 400, .. }));
    let rolled_back = client
        .get_permission(GetPermissionRequest::new(permission.clone()))
        .await
        .expect("detail after malformed clear");
    assert_eq!(
        rolled_back.items[0].meta.comment.as_deref(),
        Some("preserve on error")
    );
    assert_eq!(rolled_back.items[0].resource_type.as_deref(), Some("role"));
    assert_eq!(
        rolled_back.items[0].resource.as_ref().expect("resource").id,
        role
    );

    let error = client
        .modify_permission(ModifyPermissionRequest {
            comment: Some("must also roll back".into()),
            resource_id: ScalarUpdate::Clear,
            ..ModifyPermissionRequest::new(permission.clone())
        })
        .await
        .expect_err("stored Super cannot be cleared without a replacement type");
    assert!(matches!(error, GvmError::Server { status: 404, .. }));
    // In the pinned implementation a type-only update retains the stored
    // identity type. Explicit replacement requires both ID and type.
    client
        .modify_permission(ModifyPermissionRequest {
            resource_type: Some("user".into()),
            ..ModifyPermissionRequest::new(permission.clone())
        })
        .await
        .expect("partial update");
    let detail = client
        .get_permission(GetPermissionRequest::new(permission))
        .await
        .expect("detail");
    assert_eq!(
        detail.items[0].meta.comment.as_deref(),
        Some("preserve on error")
    );
    assert_eq!(detail.items[0].resource_type.as_deref(), Some("role"));
    assert_eq!(
        detail.items[0].resource.as_ref().expect("resource").id,
        role
    );
    server.shutdown().await;
}
