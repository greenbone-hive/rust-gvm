// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use std::error::Error as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use gvm_client::{CommandSupport, GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::agent_groups::{
    CloneAgentGroupRequest, CreateAgentGroupRequest, DeleteAgentGroupRequest, GetAgentGroupRequest,
    GetAgentGroupsRequest, ModifyAgentGroupRequest,
};
use gvm_gmp::commands::agents::{
    AgentInstallerLanguage, DeleteAgentRequest, GetAgentInstallerInstructionRequest,
    GetAgentRequest, GetAgentSupportBundleRequest, GetAgentsRequest,
    ModifyAgentControlScanConfigRequest, ModifyAgentRequest, SyncAgentsRequest,
};
use gvm_gmp::commands::credentials::CreateCredentialStoreCredentialRequest;
use gvm_gmp::commands::filters::CreateFilterRequest;
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, GetIntegrationConfigsRequest, ModifyIntegrationConfigRequest,
};
use gvm_gmp::commands::oci_image_targets::{
    CloneOciImageTargetRequest, CreateOciImageTargetRequest, DeleteOciImageTargetRequest,
    GetOciImageTargetRequest, GetOciImageTargetsRequest, ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::port_lists::CreatePortRangeRequest;
use gvm_gmp::commands::targets::CreateTargetRequest;
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, CreateWebApplicationTargetRequest,
    DeleteWebApplicationTargetRequest, GetWebApplicationTargetRequest,
    GetWebApplicationTargetsRequest, ModifyWebApplicationTargetRequest,
};
use gvm_gmp::responses::ActionResponse;
use gvm_gmp::{
    GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion, ServicePort, TargetHost,
    TargetHosts, TargetPortSelection,
};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

struct CanonicalProbeRequest {
    value: String,
    command: GmpCommand,
    encode_attempted: Arc<AtomicBool>,
    fail_encoding: bool,
}

impl GmpRequestCodec for CanonicalProbeRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.value.is_empty() {
            return Err(GmpRequestError::invalid_field("value", "must not be empty"));
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(self.command)
    }

    fn encode(&self, version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.encode_attempted.store(true, Ordering::SeqCst);
        if self.fail_encoding {
            return Err(GmpRequestError::encoding(version, "probe encoder failed"));
        }
        Ok(format!("<{} />", self.command.wire_name()).into_bytes())
    }
}

impl GmpRequest for CanonicalProbeRequest {
    type Response = ActionResponse;
}

async fn fixture_server(version: MockVersion) -> Option<MockGmpServer> {
    fixture_server_with_overrides(version, &[]).await
}

async fn fixture_server_with_overrides(
    version: MockVersion,
    overrides: &[(&str, &str)],
) -> Option<MockGmpServer> {
    let mut builder = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto();
    for (command, response) in overrides {
        builder = builder.override_response(command, response);
    }

    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn client(server: &MockGmpServer) -> GmpClient<UnixSocketConnection> {
    GmpClient::connect(UnixSocketConnection::with_path(
        server.socket_path().expect("Unix socket path"),
    ))
    .await
    .expect("client should connect")
}

async fn assert_unsupported_22_8_request<R: GmpRequest>(
    client: &mut GmpClient<UnixSocketConnection>,
    request: R,
    expected_command: &str,
) {
    let error = match client.execute(request).await {
        Ok(_) => panic!("{expected_command} should be rejected on GMP 22.7"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == expected_command
    ));
}

#[tokio::test]
async fn every_alternate_target_request_is_version_gated_before_transport() {
    let Some(server) = fixture_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let oci_id = gvm_gmp::EntityId::new("oci-1").expect("valid id");
    let web_id = gvm_gmp::EntityId::new("web-1").expect("valid id");

    assert_unsupported_22_8_request(
        &mut client,
        CreateOciImageTargetRequest::new("oci", vec!["registry.example/image:1".into()]),
        "create_oci_image_target",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        CloneOciImageTargetRequest::new(oci_id.clone()),
        "create_oci_image_target",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetOciImageTargetRequest::new(oci_id.clone()),
        "get_oci_image_targets",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetOciImageTargetsRequest::default(),
        "get_oci_image_targets",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        ModifyOciImageTargetRequest::new(oci_id.clone()),
        "modify_oci_image_target",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        DeleteOciImageTargetRequest::new(oci_id, false),
        "delete_oci_image_target",
    )
    .await;

    assert_unsupported_22_8_request(
        &mut client,
        CreateWebApplicationTargetRequest::new("web", vec!["https://example.com".into()]),
        "create_web_application_target",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        CloneWebApplicationTargetRequest::new(web_id.clone()),
        "create_web_application_target",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetWebApplicationTargetRequest::new(web_id.clone()),
        "get_web_application_targets",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetWebApplicationTargetsRequest::default(),
        "get_web_application_targets",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        ModifyWebApplicationTargetRequest::new(web_id.clone()),
        "modify_web_application_target",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        DeleteWebApplicationTargetRequest::new(web_id, false),
        "delete_web_application_target",
    )
    .await;

    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn every_agent_group_request_is_version_gated_before_transport() {
    let Some(server) = fixture_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let group_id = gvm_gmp::EntityId::new("group-1").expect("valid id");

    assert_unsupported_22_8_request(
        &mut client,
        CreateAgentGroupRequest::new(
            "agents",
            vec![gvm_gmp::EntityId::new("agent-1").expect("valid id")],
            "0 */5 * * *",
        ),
        "create_agent_group",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        CloneAgentGroupRequest::new(group_id.clone()),
        "create_agent_group",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetAgentGroupRequest::new(group_id.clone()),
        "get_agent_groups",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetAgentGroupsRequest::default(),
        "get_agent_groups",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        ModifyAgentGroupRequest::new(group_id.clone(), "0 */5 * * *"),
        "modify_agent_group",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        DeleteAgentGroupRequest::new(group_id, false),
        "delete_agent_group",
    )
    .await;

    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn every_agent_request_is_version_gated_before_transport() {
    let Some(server) = fixture_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let agent_id = gvm_gmp::EntityId::new("agent-1").expect("valid id");
    let scanner_id = gvm_gmp::EntityId::new("scanner-1").expect("valid id");

    assert_unsupported_22_8_request(&mut client, GetAgentsRequest::default(), "get_agents").await;
    assert_unsupported_22_8_request(
        &mut client,
        GetAgentRequest::new(agent_id.clone()),
        "get_agents",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        ModifyAgentRequest::new(vec![agent_id.clone()]),
        "modify_agent",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        DeleteAgentRequest::new(vec![agent_id.clone()]),
        "delete_agent",
    )
    .await;
    assert_unsupported_22_8_request(&mut client, SyncAgentsRequest, "sync_agents").await;
    assert_unsupported_22_8_request(
        &mut client,
        ModifyAgentControlScanConfigRequest::new(scanner_id.clone()),
        "modify_agent_control_scan_config",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetAgentInstallerInstructionRequest::new(
            scanner_id,
            AgentInstallerLanguage::En,
            "https://gvmd.example",
        ),
        "get_agent_installer_instruction",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetAgentSupportBundleRequest::new(agent_id, Some(7)),
        "get_agent_support_bundle",
    )
    .await;

    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn every_integration_configuration_request_is_version_gated_before_transport() {
    let Some(server) = fixture_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let config_id = gvm_gmp::EntityId::new("integration-1").expect("valid id");

    assert_unsupported_22_8_request(
        &mut client,
        GetIntegrationConfigsRequest::default(),
        "get_integration_configs",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        GetIntegrationConfigRequest::new(config_id.clone(), Some(true)),
        "get_integration_configs",
    )
    .await;
    assert_unsupported_22_8_request(
        &mut client,
        ModifyIntegrationConfigRequest::new(config_id),
        "modify_integration_config",
    )
    .await;

    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn partial_integration_configuration_replacement_fails_before_support_and_transport() {
    let Some(server) = fixture_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let mut request = ModifyIntegrationConfigRequest::new(
        gvm_gmp::EntityId::new("integration-1").expect("valid id"),
    );
    request.service_url = Some("https://service.example".into());

    let error = client
        .execute(request)
        .await
        .expect_err("partial replacement should fail before the GMP 22.8 gate");

    assert!(matches!(
        error,
        GvmError::Request(GmpRequestError::InvalidCombination {
            fields: &[
                "service_url",
                "oidc_provider_url",
                "oidc_provider_client_id",
                "oidc_provider_client_secret",
            ],
            ..
        })
    ));
    assert!(!error.to_string().contains("https://service.example"));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn invalid_port_range_fails_before_transport() {
    let Some(server) = fixture_server(MockVersion::V22_4).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let request = CreatePortRangeRequest::new(
        gvm_gmp::EntityId::new("port-list-1").expect("valid id"),
        gvm_gmp::PortRangeType::Tcp,
        443,
        80,
    );

    let error = client
        .execute(request)
        .await
        .expect_err("descending range should fail before transport");

    assert!(matches!(
        error,
        GvmError::Request(GmpRequestError::InvalidCombination {
            fields: &["start", "end"],
            ..
        })
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn mutated_filter_name_fails_before_support_and_transport() {
    let Some(server) = fixture_server(MockVersion::V22_4).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let mut request = CreateFilterRequest::new("filter");
    request.name.clear();

    let error = client
        .execute(request)
        .await
        .expect_err("empty final name should fail before transport");

    assert!(matches!(
        error,
        GvmError::Request(GmpRequestError::InvalidField {
            field: "name",
            reason: "must not be empty",
        })
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn final_value_validation_precedes_support_encoding_and_transport() {
    let Some(server) = fixture_server(MockVersion::V22_5).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let encode_attempted = Arc::new(AtomicBool::new(false));

    let error = client
        .execute(CanonicalProbeRequest {
            value: String::new(),
            command: GmpCommand::new("get_features"),
            encode_attempted: Arc::clone(&encode_attempted),
            fail_encoding: false,
        })
        .await
        .expect_err("validation should reject the final value");

    assert!(matches!(
        error,
        GvmError::Request(GmpRequestError::InvalidField { field: "value", reason })
            if reason == "must not be empty"
    ));
    assert!(!encode_attempted.load(Ordering::SeqCst));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn mutated_target_request_is_revalidated_before_transport() {
    let Some(server) = fixture_server(MockVersion::V22_5).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let hosts = TargetHosts::new(["192.0.2.1".parse::<TargetHost>().expect("valid host")], [])
        .expect("valid host selection");
    let ports = TargetPortSelection::PortRange("T:1-65535".parse().expect("valid port range"));
    let mut request = CreateTargetRequest::new("mutated", hosts, ports);
    request.ssh_credential_port = Some(ServicePort::new(2222).expect("valid port"));

    let error = client
        .execute(request)
        .await
        .expect_err("final mutated value should be rejected");

    assert!(matches!(
        error,
        GvmError::Request(GmpRequestError::InvalidCombination {
            fields: &["ssh_credential_port", "ssh_credential_id"],
            ..
        })
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn mutated_credential_request_validation_precedes_version_gate_and_transport() {
    let Some(server) = fixture_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let mut request = CreateCredentialStoreCredentialRequest::new(
        "stored",
        gvm_gmp::CredentialStoreCredentialType::PasswordOnly,
        "vault-1",
        "host-1",
    );
    request.host_identifier = "outer-error-host-sentinel".into();
    request.vault_id.clear();

    let error = client
        .execute(request)
        .await
        .expect_err("final mutated value should fail before the GMP 22.8 gate");

    let mut error_paths = format!("{error:?}\n{error}");
    let mut source = error.source();
    while let Some(current) = source {
        error_paths.push_str(&format!("\n{current:?}\n{current}"));
        source = current.source();
    }
    assert!(!error_paths.contains("outer-error-host-sentinel"));

    assert!(matches!(
        &error,
        GvmError::Request(GmpRequestError::InvalidField {
            field: "vault_id",
            reason: "must not be empty",
        })
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn semantic_metadata_support_check_precedes_encoding_and_transport() {
    let Some(server) = fixture_server(MockVersion::V22_5).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let encode_attempted = Arc::new(AtomicBool::new(false));

    let error = client
        .execute(CanonicalProbeRequest {
            value: "valid".to_string(),
            command: GmpCommand::new("get_features"),
            encode_attempted: Arc::clone(&encode_attempted),
            fail_encoding: false,
        })
        .await
        .expect_err("semantic metadata should reject the negotiated version");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 5),
            required: "22.6",
        } if command == "get_features"
    ));
    assert!(!encode_attempted.load(Ordering::SeqCst));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn encoding_failure_is_a_request_error_before_transport() {
    let Some(server) = fixture_server(MockVersion::V22_6).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let encode_attempted = Arc::new(AtomicBool::new(false));

    let error = client
        .execute(CanonicalProbeRequest {
            value: "valid".to_string(),
            command: GmpCommand::new("get_features"),
            encode_attempted: Arc::clone(&encode_attempted),
            fail_encoding: true,
        })
        .await
        .expect_err("encoding should fail before transport");

    assert!(matches!(
        error,
        GvmError::Request(GmpRequestError::Encoding {
            version: GmpVersion(22, 6),
            reason: "probe encoder failed",
        })
    ));
    assert!(encode_attempted.load(Ordering::SeqCst));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn semantic_alias_metadata_is_checked_without_encoding_xml() {
    let Some(server) = fixture_server(MockVersion::V22_7).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let encode_attempted = Arc::new(AtomicBool::new(false));

    let error = client
        .execute(CanonicalProbeRequest {
            value: "valid".to_string(),
            command: GmpCommand::with_semantic_name("get_reports", "get_report_export"),
            encode_attempted: Arc::clone(&encode_attempted),
            fail_encoding: false,
        })
        .await
        .expect_err("semantic alias should apply its own version policy");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_report_export"
    ));
    assert!(!encode_attempted.load(Ordering::SeqCst));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn semantic_metadata_preserves_pending_discovery_before_encoding() {
    let Some(server) = fixture_server(MockVersion::V22_8).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let encode_attempted = Arc::new(AtomicBool::new(false));

    assert_eq!(
        client.command_support("export_scan_report"),
        CommandSupport::RequiresDiscovery
    );
    let error = client
        .execute(CanonicalProbeRequest {
            value: "valid".to_string(),
            command: GmpCommand::new("export_scan_report"),
            encode_attempted: Arc::clone(&encode_attempted),
            fail_encoding: false,
        })
        .await
        .expect_err("pending discovery should reject before encoding");

    assert!(matches!(
        error,
        GvmError::CommandDiscoveryRequired { command }
            if command == "export_scan_report"
    ));
    assert!(!encode_attempted.load(Ordering::SeqCst));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn semantic_metadata_preserves_negative_discovery_before_encoding() {
    let Some(server) = fixture_server_with_overrides(
        MockVersion::V22_8,
        &[(
            "help",
            r#"<help_response status="200" status_text="OK"><schema format="XML"><command><name>get_targets</name></command></schema></help_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;
    client
        .discover_commands()
        .await
        .expect("negative help discovery should parse");
    server.clear_history();
    let encode_attempted = Arc::new(AtomicBool::new(false));

    assert_eq!(
        client.command_support("export_scan_report"),
        CommandSupport::NotAdvertised
    );
    let error = client
        .execute(CanonicalProbeRequest {
            value: "valid".to_string(),
            command: GmpCommand::new("export_scan_report"),
            encode_attempted: Arc::clone(&encode_attempted),
            fail_encoding: false,
        })
        .await
        .expect_err("negative discovery should reject before encoding");

    assert!(matches!(
        error,
        GvmError::CommandNotAdvertised { command }
            if command == "export_scan_report"
    ));
    assert!(!encode_attempted.load(Ordering::SeqCst));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn supported_and_unknown_custom_metadata_reach_transport() {
    let Some(server) = fixture_server_with_overrides(
        MockVersion::V22_8,
        &[
            (
                "get_targets",
                r#"<get_targets_response status="200" status_text="OK"/>"#,
            ),
            (
                "unknown_future_command",
                r#"<unknown_future_command_response status="200" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_eq!(
        client.command_support("get_targets"),
        CommandSupport::Supported
    );
    assert_eq!(
        client.command_support("unknown_future_command"),
        CommandSupport::UnknownCommand
    );

    for command in ["get_targets", "unknown_future_command"] {
        let encode_attempted = Arc::new(AtomicBool::new(false));
        client
            .execute(CanonicalProbeRequest {
                value: "valid".to_string(),
                command: GmpCommand::new(command),
                encode_attempted: Arc::clone(&encode_attempted),
                fail_encoding: false,
            })
            .await
            .expect("supported and custom commands should reach transport");
        assert!(encode_attempted.load(Ordering::SeqCst));
    }

    let commands = server
        .command_history()
        .into_iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(commands, ["get_targets", "unknown_future_command"]);
    server.shutdown().await;
}
