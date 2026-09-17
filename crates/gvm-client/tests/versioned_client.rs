// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stderr, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{
    AgentInstallerLanguage, CommandSupport, CreateAgentGroupTaskOpts, CreateOciImageTargetTaskOpts,
    CreateWebApplicationTaskOpts, CredentialStoreCredentialOpts, CredentialStoreCredentialType,
    ExportScanReportOpts, GetCredentialStoresOpts, Gmp226Commands, GmpNextCommands, GmpVersioned,
    GvmError, ModifyCredentialStoreCredentialOpts,
};
use gvm_client::{GmpClient, GmpNext};
use gvm_connection::{GvmConnection, UnixSocketConnection};
use gvm_gmp::commands::agent_groups::{
    CloneAgentGroupRequest, CreateAgentGroupRequest, DeleteAgentGroupRequest, GetAgentGroupRequest,
    GetAgentGroupsRequest, ModifyAgentGroupRequest,
};
use gvm_gmp::commands::agents::{
    DeleteAgentRequest, GetAgentInstallerInstructionRequest, GetAgentRequest,
    GetAgentSupportBundleRequest, GetAgentsRequest, ModifyAgentControlScanConfigRequest,
    ModifyAgentRequest, SyncAgentsRequest,
};
use gvm_gmp::commands::credentials::{create_credential, verify_credential_store, CredentialOpts};
use gvm_gmp::commands::oci_image_targets::{
    CloneOciImageTargetRequest, CreateOciImageTargetRequest, DeleteOciImageTargetRequest,
    GetOciImageTargetRequest, GetOciImageTargetsRequest, ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::reports::{get_scan_report, GetScanReportOpts};
use gvm_gmp::commands::targets::GetTargetsRequest;
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, CreateWebApplicationTargetRequest,
    DeleteWebApplicationTargetRequest, GetWebApplicationTargetRequest,
    GetWebApplicationTargetsRequest, ModifyWebApplicationTargetRequest,
};
use gvm_gmp::{EntityId, GmpVersion};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

async fn stateful_server(version: MockVersion) -> Option<MockGmpServer> {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => server,
        Err(error)
            if error.to_string().contains("Permission denied")
                || error.to_string().contains("Operation not permitted") =>
        {
            eprintln!("Skipping: sandbox restriction");
            return None;
        }
        Err(error) => panic!("Failed to start server: {error}"),
    };

    Some(server)
}

fn unix_connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("unix socket path"))
}

async fn authenticated_next_client(server: &MockGmpServer) -> GmpNext<UnixSocketConnection> {
    let mut client = GmpVersioned::connect(unix_connection(server))
        .await
        .expect("client should connect");
    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");
    match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    }
}

async fn typed_task_by_id(server: &MockGmpServer, task_id: &EntityId) -> gvm_gmp::responses::Task {
    let mut client = GmpClient::connect(unix_connection(server))
        .await
        .expect("typed task client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("typed task authentication should succeed");
    client
        .get_tasks(Default::default())
        .await
        .expect("typed get_tasks should succeed")
        .items
        .into_iter()
        .find(|task| task.meta.id == *task_id)
        .expect("created task should be returned")
}

async fn delete_task(server: &MockGmpServer, task_id: &EntityId) {
    let mut client = GmpClient::connect(unix_connection(server))
        .await
        .expect("task cleanup client should connect");
    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("task cleanup authentication should succeed");
    client
        .call(gvm_gmp::commands::tasks::delete_task(task_id, true))
        .await
        .expect("delete referencing task should succeed");
}

async fn assert_create_agent_group_task_round_trip<C>(
    client: &mut GmpNext<C>,
    server: &MockGmpServer,
    agent_group_id: &EntityId,
) -> EntityId
where
    C: GvmConnection + Send,
{
    server.clear_history();

    let scanner_id = EntityId::new("08b69003-5fc2-4037-a479-93b440211c73").expect("valid id");
    let task_response = client
        .create_agent_group_task(
            "Client Agent Group Task",
            agent_group_id,
            &scanner_id,
            CreateAgentGroupTaskOpts {
                comment: Some("task through client".into()),
                alterable: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("create_agent_group_task should succeed");
    assert_eq!(task_response.status_code(), Some(201));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create_task command recorded");
    assert_eq!(command.command_name(), "create_task");
    assert_eq!(
        String::from_utf8(command.raw_xml().to_vec()).expect("history should be UTF-8"),
        format!(
            "<create_task><name>Client Agent Group Task</name><usage_type>scan</usage_type><agent_group id=\"{}\"/><scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/><comment>task through client</comment><alterable>1</alterable></create_task>",
            agent_group_id.as_str()
        )
    );
    let task_id =
        EntityId::new(task_response.id().expect("created task id")).expect("valid task id");
    let task = typed_task_by_id(server, &task_id).await;
    assert_eq!(
        task.agent_group.as_ref().map(|target| &target.id),
        Some(agent_group_id)
    );
    assert_eq!(task.target, None);
    task_id
}

async fn assert_create_oci_image_target_task_round_trip<C>(
    client: &mut GmpNext<C>,
    server: &MockGmpServer,
    oci_image_target_id: &EntityId,
) -> EntityId
where
    C: GvmConnection + Send,
{
    server.clear_history();

    let scanner_id = id("08b69003-5fc2-4037-a479-93b440211c73");
    let task_response = client
        .create_container_image_task(
            "Client OCI Target Task",
            oci_image_target_id,
            &scanner_id,
            CreateOciImageTargetTaskOpts {
                comment: Some("task through client".into()),
                alterable: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("create_container_image_task should succeed");
    assert_eq!(task_response.status_code(), Some(201));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create_task command recorded");
    assert_eq!(command.command_name(), "create_task");
    assert_eq!(
        String::from_utf8(command.raw_xml().to_vec()).expect("history should be UTF-8"),
        format!(
            "<create_task><name>Client OCI Target Task</name><usage_type>scan</usage_type><oci_image_target id=\"{}\"/><scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/><comment>task through client</comment><alterable>1</alterable></create_task>",
            oci_image_target_id.as_str()
        )
    );
    let task_id =
        EntityId::new(task_response.id().expect("created task id")).expect("valid task id");
    let task = typed_task_by_id(server, &task_id).await;
    assert_eq!(
        task.oci_image_target.as_ref().map(|target| &target.id),
        Some(oci_image_target_id)
    );
    assert_eq!(task.target, None);
    task_id
}

async fn assert_create_web_application_task_round_trip(
    client: &mut GmpNext<UnixSocketConnection>,
    server: &MockGmpServer,
    target_id: &EntityId,
) -> EntityId {
    server.clear_history();
    let scanner_id = EntityId::new("08b69003-5fc2-4037-a479-93b440211c73").expect("valid id");
    let task_response = client
        .create_web_application_task(
            "Client Web Task",
            target_id,
            &scanner_id,
            CreateWebApplicationTaskOpts {
                comment: Some("created from versioned client".into()),
                ..Default::default()
            },
        )
        .await
        .expect("create_web_application_task should succeed");
    assert_eq!(task_response.status_code(), Some(201));
    let history = server.command_history();
    let command = history.last().expect("create task command recorded");
    assert_eq!(command.command_name(), "create_task");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("history should be utf8");
    assert_eq!(
        raw_xml,
        format!(
            "<create_task><name>Client Web Task</name><usage_type>scan</usage_type><web_application_target id=\"{target_id}\"/><scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/><comment>created from versioned client</comment></create_task>"
        )
    );
    let task_id =
        EntityId::new(task_response.id().expect("created task id")).expect("valid task id");
    let task = typed_task_by_id(server, &task_id).await;
    assert_eq!(
        task.web_application_target
            .as_ref()
            .map(|target| &target.id),
        Some(target_id)
    );
    assert_eq!(task.target, None);
    task_id
}

#[tokio::test]
async fn versioned_client_resolves_correct_variant() {
    for (version, expected) in [
        (MockVersion::V22_4, 224_u16),
        (MockVersion::V22_5, 225_u16),
        (MockVersion::V22_6, 226_u16),
        (MockVersion::V22_7, 227_u16),
        (MockVersion::V22_8, 228_u16),
    ] {
        let Some(server) = stateful_server(version).await else {
            return;
        };
        let connection = unix_connection(&server);
        let client = GmpVersioned::connect(connection)
            .await
            .expect("client should connect");

        match (expected, client) {
            (224, GmpVersioned::V224(_))
            | (225, GmpVersioned::V225(_))
            | (226, GmpVersioned::V226(_))
            | (227, GmpVersioned::V227(_))
            | (228, GmpVersioned::Next(_)) => {}
            (_, other) => panic!("unexpected versioned client: {other:?}"),
        }

        server.shutdown().await;
    }
}

#[tokio::test]
async fn next_client_exposes_next_trait_methods() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let response = client
        .get_integration_configs(Default::default())
        .await
        .expect("next-only command should succeed");
    assert_eq!(response.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_verify_credential_store_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    server.clear_history();
    let credential_store_id = EntityId::new("credential-store-1").expect("valid id");
    let response = client
        .verify_credential_store(&credential_store_id)
        .await
        .expect("verify_credential_store should succeed");
    assert_eq!(response.status_code(), Some(200));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "verify_credential_store");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("valid UTF-8 request"),
        "<verify_credential_store credential_store_id=\"credential-store-1\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_credential_store_helpers_send_expected_commands() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    server.clear_history();
    let credential_store_id = EntityId::new("local").expect("valid id");
    let response = client
        .get_credential_store(&credential_store_id, Some(true))
        .await
        .expect("get_credential_store should succeed");
    assert_eq!(response.status_code(), Some(200));
    assert!(response
        .as_str()
        .expect("valid UTF-8 XML")
        .contains("Local credential store"));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "get_credential_stores");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("valid UTF-8 request"),
        "<get_credential_stores details=\"1\"><credential_store_id>local</credential_store_id></get_credential_stores>"
    );

    server.clear_history();
    let response = client
        .get_credential_stores_with_opts(GetCredentialStoresOpts {
            filter_string: Some("name=Local".into()),
            filter_id: Some(EntityId::new("filter-1").expect("valid id")),
            details: Some(false),
        })
        .await
        .expect("get_credential_stores_with_opts should succeed");
    assert_eq!(response.status_code(), Some(200));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "get_credential_stores");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("valid UTF-8 request"),
        "<get_credential_stores details=\"0\" filt_id=\"filter-1\" filter=\"name=Local\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_create_credential_store_credential_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    server.clear_history();
    let create_response = client
        .create_credential_store_credential(
            "Client Store Credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts {
                comment: Some("stored credential".into()),
                credential_store_id: Some(id("credential-store-1")),
            },
        )
        .await
        .expect("create_credential_store_credential should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create command recorded");
    assert_eq!(command.command_name(), "create_credential");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("valid utf8");
    assert_eq!(
        raw_xml,
        "<create_credential><name>Client Store Credential</name><type>cs_up</type><comment>stored credential</comment><credential_store_id>credential-store-1</credential_store_id><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_modify_credential_store_credential_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let create_response = client
        .call(create_credential(
            "Next Store Credential",
            CredentialOpts::default(),
        ))
        .await
        .expect("create credential should succeed");
    let credential_id = id(&create_response.id().expect("created id"));

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    server.clear_history();

    let response = client
        .modify_credential_store_credential(
            &credential_id,
            ModifyCredentialStoreCredentialOpts {
                name: Some("Next Updated Store Credential".into()),
                credential_store_id: Some(id("credential-store-next")),
                vault_id: Some("vault-next".into()),
                host_identifier: Some("host-next".into()),
                ..Default::default()
            },
        )
        .await
        .expect("modify_credential_store_credential should succeed");
    assert_eq!(response.status_code(), Some(200));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("modify command recorded");
    assert_eq!(command.command_name(), "modify_credential");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("valid utf8");
    assert_eq!(
        raw_xml,
        format!(
            "<modify_credential credential_id=\"{}\"><name>Next Updated Store Credential</name><credential_store_id>credential-store-next</credential_store_id><vault_id>vault-next</vault_id><host_identifier>host-next</host_identifier></modify_credential>",
            credential_id.as_str()
        )
    );

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_agent_groups_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let agent_ids = [
        EntityId::new("agent-1").expect("valid id"),
        EntityId::new("agent-2").expect("valid id"),
    ];
    let mut create_request =
        CreateAgentGroupRequest::new("Client Agent Group", agent_ids.to_vec(), "0 */5 * * *");
    create_request.comment = Some("created through client".into());
    let create_response = client
        .create_agent_group(create_request)
        .await
        .expect("create_agent_group should succeed");
    assert_eq!(create_response.status, 201);
    let agent_group_id = create_response.id;

    let task_id =
        assert_create_agent_group_task_round_trip(&mut client, &server, &agent_group_id).await;

    let clone_response = client
        .clone_agent_group(CloneAgentGroupRequest::new(agent_group_id.clone()))
        .await
        .expect("clone_agent_group should succeed");
    assert_eq!(clone_response.status, 201);

    let get_response = client
        .get_agent_group(GetAgentGroupRequest::new(agent_group_id.clone()))
        .await
        .expect("get_agent_group should succeed");
    assert_eq!(get_response.items.len(), 1);
    assert_eq!(get_response.items[0].meta.name, "Client Agent Group");
    assert_eq!(
        get_response.items[0].scheduler_cron_time.as_deref(),
        Some("0 */5 * * *")
    );

    let list_response = client
        .get_agent_groups(GetAgentGroupsRequest::default())
        .await
        .expect("get_agent_groups should succeed");
    assert_eq!(list_response.status, 200);
    assert_eq!(list_response.counts.total, Some(2));

    let mut modify_request = ModifyAgentGroupRequest::new(agent_group_id.clone(), "0 */10 * * *");
    modify_request.name = Some("Updated Agent Group".into());
    modify_request.comment = Some("modified through client".into());
    modify_request.agent_ids = vec![EntityId::new("agent-3").expect("valid id")];
    let modify_response = client
        .modify_agent_group(modify_request)
        .await
        .expect("modify_agent_group should succeed");
    assert_eq!(modify_response.status, 200);

    let updated_response = client
        .get_agent_group(GetAgentGroupRequest::new(agent_group_id.clone()))
        .await
        .expect("updated get_agent_group should succeed");
    assert_eq!(updated_response.items[0].meta.name, "Updated Agent Group");
    assert_eq!(
        updated_response.items[0].meta.comment.as_deref(),
        Some("modified through client")
    );
    assert_eq!(
        updated_response.items[0].scheduler_cron_time.as_deref(),
        Some("0 */10 * * *")
    );

    delete_task(&server, &task_id).await;
    let delete_response = client
        .delete_agent_group(DeleteAgentGroupRequest::new(agent_group_id.clone(), true))
        .await
        .expect("delete_agent_group should succeed");
    assert_eq!(delete_response.status, 200);

    let error = client
        .get_agent_group(GetAgentGroupRequest::new(agent_group_id.clone()))
        .await
        .expect_err("deleted agent group should not be found");
    assert!(matches!(error, GvmError::Server { status: 404, .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_client_rejects_oci_image_targets_before_next() {
    let Some(server) = stateful_server(MockVersion::V22_7).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let error = client
        .execute(GetOciImageTargetsRequest::default())
        .await
        .expect_err("22.7 should reject next-only OCI image target command");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_oci_image_targets"
    ));

    let credential_store_id = EntityId::new("credential-store-1").expect("valid id");
    let error = client
        .call(verify_credential_store(&credential_store_id))
        .await
        .expect_err("22.7 should reject next-only credential store verify command");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "verify_credential_store"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_client_rejects_agent_commands_before_next() {
    let Some(server) = stateful_server(MockVersion::V22_7).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let error = client
        .execute(GetAgentsRequest::default())
        .await
        .expect_err("22.7 should reject next-only agent commands");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_agents"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_client_rejects_get_scan_report_before_next() {
    let Some(server) = stateful_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = GmpVersioned::connect(unix_connection(&server))
        .await
        .expect("client should connect");
    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let report_id = EntityId::new("10000000-0000-4000-8000-000000000001").expect("valid report ID");
    let error = client
        .call(get_scan_report(&report_id, GetScanReportOpts::default()))
        .await
        .expect_err("22.7 should reject get_scan_report");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_scan_report"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_scan_report_export_requires_then_uses_help_discovery() {
    let Some(server) = stateful_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = GmpVersioned::connect(unix_connection(&server))
        .await
        .expect("client should connect");
    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");
    let report_id = EntityId::new("11111111-1111-1111-1111-111111111111").expect("valid report ID");

    let error = client
        .export_scan_report(&report_id, ExportScanReportOpts::default())
        .await
        .expect_err("undiscovered export should fail");
    assert!(matches!(
        error,
        GvmError::CommandDiscoveryRequired { command }
            if command == "export_scan_report"
    ));
    assert_eq!(
        client.command_support("export_scan_report"),
        CommandSupport::RequiresDiscovery
    );

    let help = client.discover_commands().await.expect("help discovery");
    assert_eq!(help.supports_command("export_scan_report"), Some(true));
    assert_eq!(
        client.command_support("export_scan_report"),
        CommandSupport::Supported
    );
    let error = client
        .export_scan_report(&report_id, ExportScanReportOpts::default())
        .await
        .expect_err("missing report should reach the mock");
    assert!(matches!(error, GvmError::Server { status: 404, .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_execute_forwards_and_decodes_the_associated_response() {
    let Some(server) = stateful_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = GmpVersioned::connect(unix_connection(&server))
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");
    let response = client
        .execute(GetTargetsRequest::default())
        .await
        .expect("versioned execute should decode targets");

    assert_eq!(response.status, 200);
    assert!(response.items.is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn next_client_agent_commands_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let agents = client
        .get_agents(GetAgentsRequest {
            filter_string: Some("scanner=agent-controller".into()),
            ..Default::default()
        })
        .await
        .expect("get_agents should succeed");
    assert_eq!(agents.status, 200);

    let missing_agent = client
        .get_agent(GetAgentRequest::new(id(
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        )))
        .await
        .expect_err("unseeded agent should not be found");
    assert!(matches!(
        missing_agent,
        GvmError::Server { status: 404, .. }
    ));

    let agent_ids = vec![id("00000000-0000-0000-0000-000000000002")];
    let mut modify_request = ModifyAgentRequest::new(agent_ids.clone());
    modify_request.authorized = Some(true);
    modify_request.update_to_latest = Some(true);
    modify_request.comment = Some("managed from versioned client".into());
    let modify = client
        .modify_agent(modify_request)
        .await
        .expect("modify_agent should succeed");
    assert_eq!(modify.status, 200);

    let sync = client
        .sync_agents(SyncAgentsRequest)
        .await
        .expect("sync_agents should succeed");
    assert_eq!(sync.status, 200);

    let mut control_request =
        ModifyAgentControlScanConfigRequest::new(id("00000000-0000-0000-0000-000000000003"));
    control_request.update_to_latest = Some(true);
    let control_config = client
        .modify_agent_control_scan_config(control_request)
        .await
        .expect("modify_agent_control_scan_config should succeed");
    assert_eq!(control_config.status, 200);

    let instruction = client
        .get_agent_installer_instruction(GetAgentInstallerInstructionRequest::new(
            id("00000000-0000-0000-0000-000000000004"),
            AgentInstallerLanguage::En,
            "https://gvmd.example",
        ))
        .await
        .expect("get_agent_installer_instruction should succeed");
    assert_eq!(instruction.language, "en");
    assert!(instruction.instruction.contains("mock agent"));

    let bundle = client
        .get_agent_support_bundle(GetAgentSupportBundleRequest::new(
            agent_ids[0].clone(),
            Some(7),
        ))
        .await
        .expect("get_agent_support_bundle should succeed");
    assert_eq!(
        bundle.file.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(bundle.file.content, b"hello-mock");

    let delete = client
        .delete_agent(DeleteAgentRequest::new(agent_ids))
        .await
        .expect("delete_agent should succeed");
    assert_eq!(delete.status, 200);

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_oci_image_targets_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let mut client = authenticated_next_client(&server).await;

    let create_response = client
        .create_oci_image_target(CreateOciImageTargetRequest {
            name: "Client OCI Target".into(),
            image_references: vec![
                "registry.example/app:1".into(),
                "registry.example/app:2".into(),
            ],
            comment: Some("created from versioned client".into()),
            credential_id: Some(id("credential-oci-1")),
        })
        .await
        .expect("create_oci_image_target should succeed");
    assert_eq!(create_response.status, 201);
    let target_id = create_response.id;

    let task_id =
        assert_create_oci_image_target_task_round_trip(&mut client, &server, &target_id).await;

    let mut get_request = GetOciImageTargetRequest::new(target_id.clone());
    get_request.tasks = Some(true);
    let get_response = client
        .get_oci_image_target(get_request)
        .await
        .expect("get_oci_image_target should succeed");
    assert_eq!(get_response.items.len(), 1);
    assert_eq!(get_response.items[0].meta.name, "Client OCI Target");
    assert_eq!(
        get_response.items[0].image_references,
        ["registry.example/app:1", "registry.example/app:2"]
    );

    let clone_response = client
        .clone_oci_image_target(CloneOciImageTargetRequest::new(target_id.clone()))
        .await
        .expect("clone_oci_image_target should succeed");
    assert_eq!(clone_response.status, 201);

    let list_response = client
        .get_oci_image_targets(GetOciImageTargetsRequest::default())
        .await
        .expect("get_oci_image_targets should succeed");
    assert_eq!(list_response.items.len(), 2);
    assert_eq!(list_response.counts.total, Some(2));
    assert_eq!(list_response.counts.filtered, Some(2));

    let modify_response = client
        .modify_oci_image_target(ModifyOciImageTargetRequest {
            oci_image_target_id: target_id.clone(),
            name: Some("Updated OCI Target".into()),
            comment: Some("updated from versioned client".into()),
            image_references: vec!["registry.example/app:latest".into()],
            credential_id: Some(id("credential-oci-2")),
        })
        .await
        .expect("modify_oci_image_target should succeed");
    assert_eq!(modify_response.status, 200);

    let modified_response = client
        .get_oci_image_target(GetOciImageTargetRequest::new(target_id.clone()))
        .await
        .expect("modified OCI image target should be readable");
    assert_eq!(modified_response.items[0].meta.name, "Updated OCI Target");
    assert_eq!(
        modified_response.items[0].meta.comment,
        Some("updated from versioned client".into())
    );
    assert_eq!(
        modified_response.items[0].image_references,
        ["registry.example/app:latest"]
    );

    delete_task(&server, &task_id).await;
    let delete_response = client
        .delete_oci_image_target(DeleteOciImageTargetRequest::new(target_id.clone(), true))
        .await
        .expect("delete_oci_image_target should succeed");
    assert_eq!(delete_response.status, 200);

    let deleted_error = client
        .get_oci_image_target(GetOciImageTargetRequest::new(target_id))
        .await
        .expect_err("deleted OCI image target should be gone");
    assert!(matches!(
        deleted_error,
        GvmError::Server { status: 404, .. }
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_web_application_targets_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let mut client = authenticated_next_client(&server).await;

    let create_response = client
        .create_web_application_target(CreateWebApplicationTargetRequest {
            name: "Client Web Target".into(),
            urls: vec![
                "https://example.com".into(),
                "https://example.com/app".into(),
            ],
            comment: Some("created from versioned client".into()),
            exclude_urls: vec!["https://example.com/logout".into()],
            credential_id: Some(id("credential-web-1")),
        })
        .await
        .expect("create_web_application_target should succeed");
    assert_eq!(create_response.status, 201);
    let target_id = create_response.id;

    let mut get_request = GetWebApplicationTargetRequest::new(target_id.clone());
    get_request.tasks = Some(true);
    let get_response = client
        .get_web_application_target(get_request)
        .await
        .expect("get_web_application_target should succeed");
    assert_eq!(get_response.items.len(), 1);
    assert_eq!(get_response.items[0].meta.name, "Client Web Target");
    assert_eq!(
        get_response.items[0].urls,
        ["https://example.com", "https://example.com/app"]
    );
    assert_eq!(
        get_response.items[0].exclude_urls,
        ["https://example.com/logout"]
    );

    let task_id =
        assert_create_web_application_task_round_trip(&mut client, &server, &target_id).await;

    let clone_response = client
        .clone_web_application_target(CloneWebApplicationTargetRequest::new(target_id.clone()))
        .await
        .expect("clone_web_application_target should succeed");
    assert_eq!(clone_response.status, 201);

    let list_response = client
        .get_web_application_targets(GetWebApplicationTargetsRequest::default())
        .await
        .expect("get_web_application_targets should succeed");
    assert_eq!(list_response.items.len(), 2);
    assert_eq!(list_response.counts.total, Some(2));
    assert_eq!(list_response.counts.filtered, Some(2));

    let modify_response = client
        .modify_web_application_target(ModifyWebApplicationTargetRequest {
            web_application_target_id: target_id.clone(),
            name: Some("Updated Web Target".into()),
            comment: Some("updated from versioned client".into()),
            urls: vec!["https://updated.example".into()],
            exclude_urls: vec!["https://updated.example/logout".into()],
            credential_id: Some(id("credential-web-2")),
        })
        .await
        .expect("modify_web_application_target should succeed");
    assert_eq!(modify_response.status, 200);

    let modified_response = client
        .get_web_application_target(GetWebApplicationTargetRequest::new(target_id.clone()))
        .await
        .expect("modified web application target should be readable");
    assert_eq!(modified_response.items[0].meta.name, "Updated Web Target");
    assert_eq!(
        modified_response.items[0].meta.comment,
        Some("updated from versioned client".into())
    );
    assert_eq!(modified_response.items[0].urls, ["https://updated.example"]);
    assert_eq!(
        modified_response.items[0].exclude_urls,
        ["https://updated.example/logout"]
    );

    delete_task(&server, &task_id).await;
    let delete_response = client
        .delete_web_application_target(DeleteWebApplicationTargetRequest::new(
            target_id.clone(),
            true,
        ))
        .await
        .expect("delete_web_application_target should succeed");
    assert_eq!(delete_response.status, 200);

    let deleted_error = client
        .get_web_application_target(GetWebApplicationTargetRequest::new(target_id))
        .await
        .expect_err("deleted web application target should be gone");
    assert!(matches!(
        deleted_error,
        GvmError::Server { status: 404, .. }
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn gmp226_commands_work_on_v226() {
    let Some(server) = stateful_server(MockVersion::V22_6).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    let auth_response = client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");
    assert_eq!(auth_response.status_code(), Some(200));

    let mut client = match client {
        GmpVersioned::V226(client) => client,
        other => panic!("expected V226 client, got {other:?}"),
    };

    let features_response = client
        .get_features()
        .await
        .expect("get_features should succeed");
    assert_eq!(features_response.status_code(), Some(200));

    let create_response = client
        .create_report_config("Client Report Config", "report-format-1")
        .await
        .expect("create_report_config should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    server.shutdown().await;
}

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid id")
}
