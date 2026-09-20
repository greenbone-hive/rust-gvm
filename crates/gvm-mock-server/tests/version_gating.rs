// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_gmp::commands::agent_groups::{CreateAgentGroupRequest, GetAgentGroupsRequest};
use gvm_gmp::commands::credentials::{
    CreateCredentialStoreCredentialRequest, ModifyCredentialStoreCredentialRequest,
    VerifyCredentialStoreRequest,
};
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, GetIntegrationConfigsRequest, ModifyIntegrationConfigRequest,
};
use gvm_gmp::commands::oci_image_targets::{
    CreateOciImageTargetRequest, DeleteOciImageTargetRequest, GetOciImageTargetsRequest,
    ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::report_configs::{
    CloneReportConfigRequest, CreateReportConfigRequest, DeleteReportConfigRequest,
    GetReportConfigRequest, GetReportConfigsRequest, ModifyReportConfigRequest,
};
use gvm_gmp::commands::reports::{GetReportCvesRequest, GetReportHostsRequest};
use gvm_gmp::commands::tasks::CreateWebApplicationTaskRequest;
use gvm_gmp::commands::web_application_targets::{
    CreateWebApplicationTargetRequest, GetWebApplicationTargetsRequest,
};
use gvm_gmp::{CredentialStoreCredentialType, EntityId, GmpRequestCodec};
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response, XmlCommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn stateful_server(version: GmpVersion) -> Option<MockGmpServer> {
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

async fn connect(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

async fn send_recv(stream: &mut UnixStream, request: impl Request) -> Response {
    send_recv_bytes(stream, &request.to_bytes()).await
}

async fn send_recv_bytes(stream: &mut UnixStream, bytes: &[u8]) -> Response {
    stream.write_all(bytes).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0_u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

fn encode(request: &impl GmpRequestCodec, version: GmpVersion) -> Vec<u8> {
    request
        .encode(version.into())
        .expect("request should encode")
}

async fn authenticate_admin(stream: &mut UnixStream) {
    let response = send_recv(stream, b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>".as_slice()).await;
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_version_gated_rejected(version: GmpVersion) {
    let Some(server) = stateful_server(version).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let report_config_id = EntityId::new("00000000-0000-0000-0000-000000000300").unwrap();
    let report_format_id = EntityId::new("00000000-0000-0000-0000-000000000200").unwrap();
    let requests = vec![
        (
            encode(&GetReportConfigsRequest::default(), version),
            "get_report_configs",
        ),
        (
            encode(
                &GetReportConfigRequest::new(report_config_id.clone()),
                version,
            ),
            "get_report_configs",
        ),
        (
            encode(
                &CreateReportConfigRequest::new("Version Gated Config", report_format_id),
                version,
            ),
            "create_report_config",
        ),
        (
            encode(
                &CloneReportConfigRequest::new(report_config_id.clone()),
                version,
            ),
            "create_report_config",
        ),
        (
            encode(
                &ModifyReportConfigRequest::new(report_config_id.clone()),
                version,
            ),
            "modify_report_config",
        ),
        (
            encode(&DeleteReportConfigRequest::new(report_config_id), version),
            "delete_report_config",
        ),
    ];
    for (request, command) in requests {
        let response = send_recv_bytes(&mut stream, &request).await;
        assert_eq!(response.status_code(), Some(400));
        let status = response.status_text().unwrap();
        assert!(
            status.contains(command),
            "expected {command} in status_text, got: {status}"
        );
    }

    let features_response = send_recv(&mut stream, b"<get_features/>".as_slice()).await;
    assert_eq!(features_response.status_code(), Some(400));
    let features_text = features_response.status_text().unwrap();
    assert!(
        features_text.contains("get_features"),
        "expected get_features in status_text, got: {features_text}"
    );

    server.shutdown().await;
}

async fn assert_version_gated_accepted(version: GmpVersion) {
    let Some(server) = stateful_server(version).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let create = CreateReportConfigRequest::new(
        "Version Gated Config",
        EntityId::new("00000000-0000-0000-0000-000000000200").unwrap(),
    );
    let create_response = send_recv_bytes(&mut stream, &encode(&create, version)).await;
    assert_eq!(create_response.status_code(), Some(201));
    let created_id =
        EntityId::new(create_response.id().expect("created report config ID")).unwrap();

    let list_response = send_recv_bytes(
        &mut stream,
        &encode(&GetReportConfigsRequest::default(), version),
    )
    .await;
    assert_eq!(list_response.status_code(), Some(200));
    let list_text = list_response.as_str().expect("valid utf8");
    assert!(list_text.contains("Version Gated Config"));

    let detail_response = send_recv_bytes(
        &mut stream,
        &encode(&GetReportConfigRequest::new(created_id.clone()), version),
    )
    .await;
    assert_eq!(detail_response.status_code(), Some(200));

    let clone_response = send_recv_bytes(
        &mut stream,
        &encode(&CloneReportConfigRequest::new(created_id.clone()), version),
    )
    .await;
    assert_eq!(clone_response.status_code(), Some(201));
    let clone_id = EntityId::new(clone_response.id().expect("cloned report config ID")).unwrap();

    let modify_response = send_recv_bytes(
        &mut stream,
        &encode(&ModifyReportConfigRequest::new(created_id.clone()), version),
    )
    .await;
    assert_eq!(modify_response.status_code(), Some(200));

    let delete_response = send_recv_bytes(
        &mut stream,
        &encode(&DeleteReportConfigRequest::new(clone_id), version),
    )
    .await;
    assert_eq!(delete_response.status_code(), Some(200));

    let features_response = send_recv(&mut stream, b"<get_features/>".as_slice()).await;
    assert_eq!(features_response.status_code(), Some(200));
    let features_text = features_response.as_str().expect("valid UTF-8");
    assert!(features_text.contains(
        "<feature compiled_in=\"0\" enabled=\"0\"><name>ENABLE_OPENVASD</name></feature>"
    ));
    assert!(features_text.contains("<name>ENABLE_WEB_APPLICATION_SCANNING</name>"));

    server.shutdown().await;
}

#[tokio::test]
async fn version_22_4_rejects_report_config() {
    assert_version_gated_rejected(GmpVersion::V22_4).await;
}

#[tokio::test]
async fn version_22_5_rejects_report_config() {
    assert_version_gated_rejected(GmpVersion::V22_5).await;
}

#[tokio::test]
async fn version_22_6_accepts_report_config() {
    assert_version_gated_accepted(GmpVersion::V22_6).await;
}

#[tokio::test]
async fn version_22_7_accepts_report_config() {
    assert_version_gated_accepted(GmpVersion::V22_7).await;
}

#[tokio::test]
async fn next_version_accepts_report_config() {
    assert_version_gated_accepted(GmpVersion::V22_8).await;
}

#[tokio::test]
async fn base_commands_work_on_all_versions() {
    for version in [
        GmpVersion::V22_4,
        GmpVersion::V22_5,
        GmpVersion::V22_6,
        GmpVersion::V22_7,
        GmpVersion::V22_8,
    ] {
        let Some(server) = stateful_server(version).await else {
            return;
        };
        let mut stream = connect(&server).await;
        authenticate_admin(&mut stream).await;

        let response = send_recv(
            &mut stream,
            XmlCommand::new("create_target")
                .child_with_text("name", &format!("Base Target {}", version.as_str()))
                .child_with_text("hosts", "127.0.0.1")
                .child_with_text("exclude_hosts", "")
                .child_with_text("port_range", "T:1-65535"),
        )
        .await;
        assert_eq!(response.status_code(), Some(201));

        server.shutdown().await;
    }
}

#[tokio::test]
async fn version_22_7_rejects_next_commands() {
    let Some(server) = stateful_server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let response = send_recv(
        &mut stream,
        encode(&GetIntegrationConfigsRequest::default(), GmpVersion::V22_7),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("get_integration_configs"));

    let response = send_recv(
        &mut stream,
        encode(&GetAgentGroupsRequest::default(), GmpVersion::V22_7),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("get_agent_groups"));

    let response = send_recv_bytes(
        &mut stream,
        &encode(
            &GetReportHostsRequest::new(id("00000000-0000-0000-0000-000000000200")),
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("get_report_hosts"));

    let response = send_recv(
        &mut stream,
        encode(
            &GetWebApplicationTargetsRequest::default(),
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("get_web_application_targets"));

    let response = send_recv(
        &mut stream,
        encode(&GetOciImageTargetsRequest::default(), GmpVersion::V22_7),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("get_oci_image_targets"));

    assert_credential_store_verify_rejected_before_next(&mut stream).await;

    let response = send_recv(
        &mut stream,
        encode(
            &CreateOciImageTargetRequest::new(
                "Rejected OCI Target",
                vec!["registry.example/app:1".to_string()],
            ),
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("create_oci_image_target"));

    let response = send_recv(
        &mut stream,
        encode(
            &CreateWebApplicationTaskRequest::new(
                "Rejected Web Application Task",
                id("web-target-1"),
                id("00000000-0000-4000-8000-000000000011"),
            ),
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("Specialized task variants"));

    assert_credential_store_credentials_rejected_before_next(&mut stream).await;

    server.shutdown().await;
}

#[tokio::test]
async fn version_22_7_rejects_every_specialized_task_shape() {
    let Some(server) = stateful_server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    for request in [
        br#"<create_task><name>Rejected agent task</name><agent_group id="00000000-0000-4000-8000-000000000001"/></create_task>"#.as_slice(),
        br#"<create_task><name>Rejected OCI task</name><oci_image_target id="00000000-0000-4000-8000-000000000002"/><scanner id="00000000-0000-4000-8000-000000000010"/></create_task>"#.as_slice(),
    ] {
        let response = send_recv(&mut stream, request.to_vec()).await;
        assert_eq!(response.status_code(), Some(400));
        assert!(response
            .status_text()
            .unwrap()
            .contains("Specialized task variants"));
    }

    server.shutdown().await;
}

async fn assert_credential_store_credentials_rejected_before_next(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        encode(
            &CreateCredentialStoreCredentialRequest::new(
                "Rejected Store Credential",
                CredentialStoreCredentialType::UsernamePassword,
                "vault-1",
                "host-1",
            ),
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));

    let response = send_recv(
        stream,
        encode(
            &{
                let mut request = ModifyCredentialStoreCredentialRequest::new(id("credential-1"));
                request.vault_id = Some("vault-1".into());
                request
            },
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));

    let response = send_recv(
        stream,
        encode(
            &{
                let mut request = ModifyCredentialStoreCredentialRequest::new(id("credential-1"));
                request.host_identifier = Some("host-1".into());
                request
            },
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));

    let response = send_recv(
        stream,
        &b"<modify_credential credential_id=\"credential-1\"><vault_id/></modify_credential>"[..],
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));
}

async fn assert_credential_store_verify_rejected_before_next(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        encode(
            &VerifyCredentialStoreRequest::new(id("credential-store-1")),
            GmpVersion::V22_7,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("verify_credential_store"));
}

#[tokio::test]
async fn version_22_8_accepts_next_commands() {
    let Some(server) = stateful_server(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    assert_integration_configs_work_on_next(&mut stream).await;

    let agent_group_response = send_recv(
        &mut stream,
        encode(
            &CreateAgentGroupRequest::new(
                "Version Gated Agent Group",
                vec![id("agent-1")],
                "0 */5 * * *",
            ),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(agent_group_response.status_code(), Some(201));

    let agent_groups_response = send_recv(
        &mut stream,
        encode(&GetAgentGroupsRequest::default(), GmpVersion::V22_8),
    )
    .await;
    assert_eq!(agent_groups_response.status_code(), Some(200));
    assert!(agent_groups_response
        .as_str()
        .expect("utf8")
        .contains("Version Gated Agent Group"));

    let report_response = send_recv_bytes(
        &mut stream,
        &encode(
            &GetReportCvesRequest::new(id("00000000-0000-0000-0000-000000000200")),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(report_response.status_code(), Some(404));

    assert_credential_store_verify_works_on_next(&mut stream).await;
    assert_credential_store_credentials_work_on_next(&mut stream).await;
    assert_web_application_targets_and_tasks_work_on_next(&mut stream).await;
    assert_oci_image_targets_work_on_next(&mut stream).await;

    server.shutdown().await;
}

async fn assert_integration_configs_work_on_next(stream: &mut UnixStream) {
    let integration_config_id = id("00000000-0000-0000-0000-000000000100");
    let get_response = send_recv(
        stream,
        encode(
            &GetIntegrationConfigRequest::new(integration_config_id.clone(), Some(true)),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(get_response.status_code(), Some(200));

    let list_response = send_recv(
        stream,
        encode(&GetIntegrationConfigsRequest::default(), GmpVersion::V22_8),
    )
    .await;
    assert_eq!(list_response.status_code(), Some(200));
    assert!(list_response
        .as_str()
        .expect("utf8")
        .contains("Default Integration Config"));

    let mut modify_request = ModifyIntegrationConfigRequest::new(integration_config_id.clone());
    modify_request.service_url = Some("https://updated.example".into());
    modify_request.service_cacert = Some("UPDATED-CA".into());
    modify_request.oidc_provider_url = Some("https://updated-oidc.example".into());
    modify_request.oidc_provider_client_id = Some("updated-client".into());
    modify_request.oidc_provider_client_secret = Some("updated-secret".into());
    let modify_response = send_recv(stream, encode(&modify_request, GmpVersion::V22_8)).await;
    assert_eq!(modify_response.status_code(), Some(200));

    let modified_get_response = send_recv(
        stream,
        encode(
            &GetIntegrationConfigRequest::new(integration_config_id.clone(), Some(true)),
            GmpVersion::V22_8,
        ),
    )
    .await;
    let modified_xml = modified_get_response.as_str().expect("utf8");
    assert!(modified_xml.contains("<service><url>https://updated.example</url></service>"));
    assert!(modified_xml.contains(
        "<oidc><url>https://updated-oidc.example</url><client><id>updated-client</id></client></oidc>"
    ));
    assert!(!modified_xml.contains("MOCK-CA-CERT"));
    assert!(!modified_xml.contains("mock-client-secret"));

    let missing_uuid_response =
        send_recv(stream, XmlCommand::new("modify_integration_config")).await;
    assert_eq!(missing_uuid_response.status_code(), Some(400));
    assert!(missing_uuid_response
        .status_text()
        .expect("status text")
        .contains("uuid"));

    let malformed_modify = send_recv(
        stream,
        XmlCommand::new("modify_integration_config")
            .attribute("uuid", "00000000-0000-0000-0000-000000000100"),
    )
    .await;
    assert_eq!(malformed_modify.status_code(), Some(400));
    assert!(malformed_modify
        .status_text()
        .expect("status text")
        .contains("service"));

    let mut partial_command = XmlCommand::new("modify_integration_config")
        .attribute("uuid", integration_config_id.as_str());
    let service = partial_command.add_element("service");
    service.add_child_with_text("url", "https://partial.example");
    service.add_child_with_text("cacert", "");
    let oidc = partial_command.add_element("oidc");
    oidc.add_child_with_text("url", "");
    let client = oidc.add_child("client");
    client.add_child_with_text("id", "");
    client.add_child_with_text("secret", "");
    let partial_modify = send_recv(stream, partial_command).await;
    assert_eq!(partial_modify.status_code(), Some(400));
    assert!(partial_modify
        .status_text()
        .expect("status text")
        .contains("oidc"));

    let clear_response = send_recv(
        stream,
        encode(
            &ModifyIntegrationConfigRequest::new(integration_config_id),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(clear_response.status_code(), Some(200));
}

async fn assert_web_application_targets_and_tasks_work_on_next(stream: &mut UnixStream) {
    let web_target_response = send_recv(
        stream,
        encode(
            &CreateWebApplicationTargetRequest {
                name: "Version Gated Web Target".into(),
                urls: vec!["https://example.com".to_string()],
                comment: Some("accepted on 22.8".into()),
                exclude_urls: vec!["https://example.com/logout".into()],
                credential_id: Some(id("credential-web-gate")),
            },
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(web_target_response.status_code(), Some(201));

    let web_target_list = send_recv(
        stream,
        encode(
            &GetWebApplicationTargetsRequest::default(),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(web_target_list.status_code(), Some(200));
    let web_target_xml = web_target_list.as_str().expect("utf8");
    assert!(web_target_xml.contains("Version Gated Web Target"));
    assert!(web_target_xml.contains("<urls>https://example.com</urls>"));
    assert!(web_target_xml.contains("<credential_id>credential-web-gate</credential_id>"));

    let web_target_id = id(&web_target_response.id().expect("created web target id"));
    let web_task_response = send_recv(
        stream,
        encode(
            &CreateWebApplicationTaskRequest::new(
                "Version Gated Web Task",
                web_target_id,
                id("00000000-0000-4000-8000-000000000011"),
            ),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(web_task_response.status_code(), Some(201));
}

async fn assert_credential_store_verify_works_on_next(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        encode(
            &VerifyCredentialStoreRequest::new(id("credential-store-1")),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_credential_store_credentials_work_on_next(stream: &mut UnixStream) {
    let create = send_recv(
        stream,
        encode(
            &CreateCredentialStoreCredentialRequest::new(
                "Version Gated Store Credential",
                CredentialStoreCredentialType::PasswordOnly,
                "vault-1",
                "host-1",
            ),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(create.status_code(), Some(201));
    let credential_id = id(&create.id().expect("created id"));

    let response = send_recv(
        stream,
        encode(
            &{
                let mut request = ModifyCredentialStoreCredentialRequest::new(credential_id);
                request.credential_store_id = Some(id("credential-store-gate"));
                request.vault_id = Some("vault-gate".into());
                request.host_identifier = Some("host-gate".into());
                request
            },
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_oci_image_targets_work_on_next(stream: &mut UnixStream) {
    let oci_target_response = send_recv(
        stream,
        encode(
            &CreateOciImageTargetRequest {
                name: "Version Gated OCI Target".into(),
                image_references: vec!["registry.example/app:1".to_string()],
                comment: Some("accepted on 22.8".into()),
                credential_id: Some(id("credential-oci-gate")),
            },
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(oci_target_response.status_code(), Some(201));
    let oci_target_id = id(&oci_target_response.id().expect("created OCI target id"));

    let oci_target_list = send_recv(
        stream,
        encode(&GetOciImageTargetsRequest::default(), GmpVersion::V22_8),
    )
    .await;
    assert_eq!(oci_target_list.status_code(), Some(200));
    let oci_target_xml = oci_target_list.as_str().expect("utf8");
    assert!(oci_target_xml.contains("Version Gated OCI Target"));
    assert!(oci_target_xml.contains("<image_references>registry.example/app:1</image_references>"));
    assert!(oci_target_xml.contains("<credential_id>credential-oci-gate</credential_id>"));

    let modify_response = send_recv(
        stream,
        encode(
            &ModifyOciImageTargetRequest {
                oci_image_target_id: oci_target_id.clone(),
                name: Some("Updated Version Gated OCI Target".into()),
                comment: None,
                image_references: vec!["registry.example/app:latest".into()],
                credential_id: Some(id("credential-oci-updated")),
            },
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(modify_response.status_code(), Some(200));

    let modified_list = send_recv(
        stream,
        encode(&GetOciImageTargetsRequest::default(), GmpVersion::V22_8),
    )
    .await;
    let modified_xml = modified_list.as_str().expect("utf8");
    assert!(modified_xml.contains("Updated Version Gated OCI Target"));
    assert!(
        modified_xml.contains("<image_references>registry.example/app:latest</image_references>")
    );
    assert!(modified_xml.contains("<credential_id>credential-oci-updated</credential_id>"));

    let delete_response = send_recv(
        stream,
        encode(
            &DeleteOciImageTargetRequest::new(oci_target_id, true),
            GmpVersion::V22_8,
        ),
    )
    .await;
    assert_eq!(delete_response.status_code(), Some(200));
}

fn id(value: &str) -> gvm_gmp::EntityId {
    gvm_gmp::EntityId::new(value).expect("valid id")
}
