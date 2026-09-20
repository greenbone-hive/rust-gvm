// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration coverage for the newly added command-surface gaps.

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use base64::Engine;
use gvm_gmp::commands::agents::{
    AgentInstallerLanguage, DeleteAgentRequest, GetAgentInstallerInstructionRequest,
    GetAgentSupportBundleRequest, GetAgentsRequest, ModifyAgentControlScanConfigRequest,
    ModifyAgentRequest, SyncAgentsRequest,
};
use gvm_gmp::commands::credentials::{
    CreateCredentialRequest, CreateCredentialStoreCredentialRequest, GetCredentialRequest,
    ModifyCredentialStoreCredentialRequest, ModifyCredentialStoreRequest,
    VerifyCredentialStoreRequest,
};
use gvm_gmp::commands::hosts::{CreateHostRequest, GetHostRequest, GetHostsRequest};
use gvm_gmp::commands::system::{
    modify_auth, modify_license, modify_license_with_opts, run_wizard_with_opts, ModifyLicenseOpts,
    RunWizardOpts,
};
use gvm_gmp::types::EntityId;
use gvm_gmp::{CredentialStoreCredentialType, GmpRequestCodec};
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn send_request(stream: &mut UnixStream, request: impl Request) -> Response {
    send_recv(stream, &request.to_bytes()).await
}

async fn send_typed_request(stream: &mut UnixStream, request: impl GmpRequestCodec) -> Response {
    let bytes = request
        .encode(gvm_gmp::GmpVersion(22, 8))
        .expect("valid typed request");
    send_recv(stream, &bytes).await
}

async fn stateful_server() -> Option<MockGmpServer> {
    stateful_server_with_version(GmpVersion::V22_6).await
}

async fn stateful_server_with_version(version: GmpVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

async fn auth_admin(stream: &mut UnixStream) {
    let resp = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
}

fn extract_id(resp: &Response) -> String {
    resp.id().expect("response should contain id")
}

async fn create_task(stream: &mut UnixStream, name: &str, usage_type: &str) -> String {
    let target = send_recv(
        stream,
        format!(
            "<create_target><name>{name} Target</name><hosts>127.0.0.1</hosts><port_range>T:1-65535</port_range></create_target>"
        )
        .as_bytes(),
    )
    .await;
    let target_id = extract_id(&target);
    let task = send_recv(
        stream,
        format!(
            "<create_task><name>{name}</name><usage_type>{usage_type}</usage_type><target id=\"{target_id}\"/></create_task>"
        )
        .as_bytes(),
    )
    .await;
    extract_id(&task)
}

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid id")
}

fn text_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = text.find(start).expect("start marker") + start.len();
    let end_index = text[start_index..].find(end).expect("end marker") + start_index;
    &text[start_index..end_index]
}

#[tokio::test]
async fn stateful_agent_commands_use_gvmd_builder_shapes() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let agents = send_typed_request(
        &mut stream,
        GetAgentsRequest {
            filter_string: Some("scanner=agent-controller".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(agents.status_code(), Some(200));

    let mut modify_request = ModifyAgentRequest::new(vec![id("agent-1")]);
    modify_request.authorized = Some(true);
    modify_request.update_to_latest = Some(true);
    modify_request.comment = Some("managed".into());
    let modify = send_typed_request(&mut stream, modify_request).await;
    assert_eq!(modify.status_code(), Some(200));

    let delete =
        send_typed_request(&mut stream, DeleteAgentRequest::new(vec![id("agent-1")])).await;
    assert_eq!(delete.status_code(), Some(200));

    let sync = send_typed_request(&mut stream, SyncAgentsRequest).await;
    assert_eq!(sync.status_code(), Some(200));

    let mut control_request = ModifyAgentControlScanConfigRequest::new(id("scanner-1"));
    control_request.update_to_latest = Some(true);
    let control_config = send_typed_request(&mut stream, control_request).await;
    assert_eq!(control_config.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_agent_download_helpers_return_fixture_shapes() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let instruction = send_typed_request(
        &mut stream,
        GetAgentInstallerInstructionRequest::new(
            id("scanner-1"),
            AgentInstallerLanguage::En,
            "https://gvmd.example",
        ),
    )
    .await;
    assert_eq!(instruction.status_code(), Some(200));
    let instruction_text = instruction.as_str().expect("utf8");
    assert!(instruction_text.contains("<language>en</language>"));
    assert!(instruction_text.contains("<instruction>"));

    let bundle = send_typed_request(
        &mut stream,
        GetAgentSupportBundleRequest::new(id("agent-1"), Some(7)),
    )
    .await;
    assert_eq!(bundle.status_code(), Some(200));
    let bundle_text = bundle.as_str().expect("utf8");
    assert!(bundle_text.contains("<content_type>application/octet-stream</content_type>"));
    assert!(bundle_text.contains("<content encoding=\"base64\">"));
    let declared_size: usize = text_between(bundle_text, "<size>", "</size>")
        .parse()
        .expect("size");
    let encoded_content = text_between(bundle_text, "<content encoding=\"base64\">", "</content>");
    let decoded_content = base64::engine::general_purpose::STANDARD
        .decode(encoded_content)
        .expect("base64 content");
    assert_eq!(decoded_content.len(), declared_size);

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_modify_uses_gvmd_builder_shape() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let modify = send_typed_request(&mut stream, {
        let mut request = ModifyCredentialStoreRequest::new(id("credential-store-1"));
        request.active = Some(true);
        request.host = Some("store.example".into());
        request.path = Some("/vault".into());
        request.port = Some(8200);
        request.comment = Some("primary".into());
        request
    })
    .await;
    assert_eq!(modify.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_verify_uses_gvmd_builder_shape() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let verify = send_typed_request(
        &mut stream,
        VerifyCredentialStoreRequest::new(id("credential-store-1")),
    )
    .await;
    assert_eq!(verify.status_code(), Some(200));

    let missing_id = send_recv(&mut stream, b"<verify_credential_store/>").await;
    assert_eq!(missing_id.status_code(), Some(400));
    assert!(missing_id
        .status_text()
        .expect("status text")
        .contains("credential_store_id"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_create_credential_uses_gvmd_builder_shape() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create = send_typed_request(&mut stream, {
        let mut request = CreateCredentialStoreCredentialRequest::new(
            "Store Credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
        );
        request.comment = Some("from credential store".into());
        request.credential_store_id = Some(id("credential-store-1"));
        request
    })
    .await;
    assert_eq!(create.status_code(), Some(201));

    let missing_vault = send_recv(
        &mut stream,
        b"<create_credential><name>Missing Vault</name><type>cs_up</type><host_identifier>host-1</host_identifier></create_credential>",
    )
    .await;
    assert_eq!(missing_vault.status_code(), Some(400));
    assert!(missing_vault.status_text().unwrap().contains("vault_id"));

    let empty_vault = send_recv(
        &mut stream,
        b"<create_credential><name>Empty Vault</name><type>cs_up</type><vault_id/><host_identifier>host-1</host_identifier></create_credential>",
    )
    .await;
    assert_eq!(empty_vault.status_code(), Some(400));
    assert!(empty_vault.status_text().unwrap().contains("vault_id"));

    let missing_host = send_recv(
        &mut stream,
        b"<create_credential><name>Missing Host</name><type>cs_up</type><vault_id>vault-1</vault_id></create_credential>",
    )
    .await;
    assert_eq!(missing_host.status_code(), Some(400));
    assert!(missing_host
        .status_text()
        .unwrap()
        .contains("host_identifier"));

    let empty_host = send_recv(
        &mut stream,
        b"<create_credential><name>Empty Host</name><type>cs_up</type><vault_id>vault-1</vault_id><host_identifier>  </host_identifier></create_credential>",
    )
    .await;
    assert_eq!(empty_host.status_code(), Some(400));
    assert!(empty_host
        .status_text()
        .unwrap()
        .contains("host_identifier"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_kerberos_round_trips_and_validates_required_fields() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create = send_typed_request(&mut stream, {
        let mut request = CreateCredentialStoreCredentialRequest::new(
            "Store Kerberos Credential",
            CredentialStoreCredentialType::Kerberos5,
            "vault-1",
            "host-1",
        );
        request.credential_store_id = Some(id("credential-store-1"));
        request.kdcs = vec!["kdc1.example".into(), "kdc2.example".into()];
        request.realm = Some("EXAMPLE.COM".into());
        request
    })
    .await;
    assert_eq!(create.status_code(), Some(201));
    let credential_id = EntityId::new(extract_id(&create)).expect("created credential id");

    let get = send_typed_request(
        &mut stream,
        GetCredentialRequest::new(credential_id.clone()),
    )
    .await;
    assert_eq!(get.status_code(), Some(200));
    let get_xml = get.as_str().expect("utf8");
    assert!(get_xml.contains("<type>cs_krb5</type>"));
    assert!(get_xml.contains("<kdc>kdc1.example,kdc2.example</kdc>"));
    assert!(get_xml.contains("<realm>EXAMPLE.COM</realm>"));

    let modify = send_typed_request(&mut stream, {
        let mut request = ModifyCredentialStoreCredentialRequest::new(credential_id.clone());
        request.kdcs = vec!["new-kdc.example".into()];
        request.realm = Some("NEW.EXAMPLE.COM".into());
        request
    })
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let get = send_typed_request(&mut stream, GetCredentialRequest::new(credential_id)).await;
    assert_eq!(get.status_code(), Some(200));
    let get_xml = get.as_str().expect("utf8");
    assert!(get_xml.contains("<type>cs_krb5</type>"));
    assert!(get_xml.contains("<kdc>new-kdc.example</kdc>"));
    assert!(get_xml.contains("<realm>NEW.EXAMPLE.COM</realm>"));
    assert!(!get_xml.contains("kdc1.example"));
    assert!(!get_xml.contains("<realm>EXAMPLE.COM</realm>"));

    let missing_kdc = send_recv(
        &mut stream,
        b"<create_credential><name>Missing KDC</name><type>cs_krb5</type><realm>EXAMPLE.COM</realm><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>",
    )
    .await;
    assert_eq!(missing_kdc.status_code(), Some(400));
    assert!(missing_kdc.status_text().unwrap().contains("kdc or kdcs"));

    let missing_realm = send_recv(
        &mut stream,
        b"<create_credential><name>Missing Realm</name><type>cs_krb5</type><kdc>kdc.example</kdc><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>",
    )
    .await;
    assert_eq!(missing_realm.status_code(), Some(400));
    assert!(missing_realm.status_text().unwrap().contains("realm"));

    let unsupported_client_certificate = send_recv(
        &mut stream,
        b"<create_credential><name>Unsupported Store Certificate</name><type>cs_cc</type><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>",
    )
    .await;
    assert_eq!(unsupported_client_certificate.status_code(), Some(400));
    assert!(unsupported_client_certificate
        .status_text()
        .unwrap()
        .contains("Invalid credential type"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_modify_credential_uses_gvmd_builder_shape() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create = send_typed_request(
        &mut stream,
        CreateCredentialRequest::new("Store Credential"),
    )
    .await;
    assert_eq!(create.status_code(), Some(201));
    let credential_id = EntityId::new(extract_id(&create)).expect("created credential id");

    let modify = send_typed_request(&mut stream, {
        let mut request = ModifyCredentialStoreCredentialRequest::new(credential_id.clone());
        request.name = Some("Updated Store Credential".into());
        request.comment = Some("from credential store".into());
        request.credential_store_id = Some(id("credential-store-1"));
        request.vault_id = Some("vault-1".into());
        request.host_identifier = Some("host-1".into());
        request
    })
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let get = send_typed_request(&mut stream, GetCredentialRequest::new(credential_id)).await;
    assert_eq!(get.status_code(), Some(200));
    let get_xml = get.as_str().expect("utf8");
    assert!(get_xml.contains("Updated Store Credential"));
    assert!(get_xml.contains("<comment>from credential store</comment>"));
    assert!(get_xml.contains("<credential_store_id>credential-store-1</credential_store_id>"));
    assert!(get_xml.contains("<vault_id>vault-1</vault_id>"));
    assert!(get_xml.contains("<host_identifier>host-1</host_identifier>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_host_asset_uses_canonical_request_shape() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create = send_typed_request(&mut stream, CreateHostRequest::new("1.1.1.1")).await;
    assert_eq!(create.status_code(), Some(201));
    let host_id = extract_id(&create);
    let host_entity_id = EntityId::new(host_id.clone()).expect("valid host id");

    let hosts = send_typed_request(&mut stream, GetHostsRequest::default()).await;
    let hosts_text = hosts.as_str().expect("utf8");
    assert!(hosts_text.contains(&host_id));
    assert!(hosts_text.contains("<type>host</type>"));
    assert!(hosts_text.contains("<name>ip</name><value>1.1.1.1</value>"));
    assert!(hosts_text.contains("<host><severity>"));

    let host = send_typed_request(&mut stream, GetHostRequest::new(host_entity_id)).await;
    let host_text = host.as_str().expect("utf8");
    assert!(host_text.contains(&host_id));
    assert!(host_text.contains("<type>host</type>"));
    assert!(host_text.contains("<name>ip</name><value>1.1.1.1</value>"));
    assert!(host_text.contains("<host><severity>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_auth_and_license_modifiers_use_gmp_builder_shape() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let auth = send_request(
        &mut stream,
        modify_auth("method:ldap_connect", &[("enable".into(), "true".into())]),
    )
    .await;
    assert_eq!(auth.status_code(), Some(200));

    for invalid in [
        br#"<modify_auth enabled="1"/>"#.as_slice(),
        br#"<modify_auth><group name="method:ldap_connect"/><group name="method:radius_connect"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting></group></modify_auth>"#.as_slice(),
        br#"<modify_auth><group><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting></group></modify_auth>"#.as_slice(),
        br#"<modify_auth><group name="method:ldap_connect"/></modify_auth>"#.as_slice(),
        br#"<modify_auth><group name="method:ldap_connect"><auth_conf_setting><value>true</value></auth_conf_setting></group></modify_auth>"#.as_slice(),
        br#"<modify_auth><group name="method:ldap_connect"><auth_conf_setting><key>enable</key></auth_conf_setting></group></modify_auth>"#.as_slice(),
    ] {
        let response = send_recv(&mut stream, invalid).await;
        assert_eq!(response.status_code(), Some(400));
    }

    let license = send_request(&mut stream, modify_license("YWJj")).await;
    assert_eq!(license.status_code(), Some(200));

    let empty_license = send_request(
        &mut stream,
        modify_license_with_opts(
            "",
            ModifyLicenseOpts {
                allow_empty: Some(true),
            },
        ),
    )
    .await;
    assert_eq!(empty_license.status_code(), Some(200));

    for invalid in [
        br#"<modify_license><key>legacy</key></modify_license>"#.as_slice(),
        br#"<modify_license><file></file></modify_license>"#.as_slice(),
        br#"<modify_license allow_empty="0"><file></file></modify_license>"#.as_slice(),
        br#"<modify_license allow_empty="invalid"><file>YWJj</file></modify_license>"#.as_slice(),
    ] {
        let response = send_recv(&mut stream, invalid).await;
        assert_eq!(response.status_code(), Some(400));
    }

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_run_wizard_validates_current_gvmd_shape() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let response = send_request(
        &mut stream,
        run_wizard_with_opts(
            "quick_first_scan",
            &[("hosts".into(), "localhost".into())],
            RunWizardOpts {
                mode: Some("step".into()),
                read_only: Some(false),
            },
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(202));
    assert!(response
        .as_str()
        .expect("utf8")
        .contains("<response><start_task_response"));

    for invalid in [
        br#"<run_wizard name="quick"><param name="hosts">localhost</param></run_wizard>"#.as_slice(),
        br#"<run_wizard><name>quick</name></run_wizard>"#.as_slice(),
        br#"<run_wizard><name>quick</name><params><param><name>hosts</name></param></params></run_wizard>"#.as_slice(),
        br#"<run_wizard read_only="invalid"><name>quick</name><params/></run_wizard>"#.as_slice(),
        br#"<run_wizard><name>not valid</name><params/></run_wizard>"#.as_slice(),
    ] {
        let response = send_recv(&mut stream, invalid).await;
        assert_eq!(response.status_code(), Some(400));
    }

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_get_feeds_returns_canonical_entries() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, b"<get_feeds/>").await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<feed_owner_set>1</feed_owner_set>"));
    assert!(text.contains("<name>Greenbone Security Feed</name>"));
    assert!(text.contains("<type>SCAP</type>"));
    assert!(text.contains("<type>GVMD_DATA</type>"));
    assert!(text.contains("<currently_syncing><timestamp>"));
    assert!(text.contains("<sync_not_available><error>"));
    assert!(!text.contains("<feed_count>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_policies_round_trip_with_usage_type_filtering() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let policy_resp = send_recv(
        &mut stream,
        b"<create_config><name>Policy One</name><usage_type>policy</usage_type></create_config>",
    )
    .await;
    let policy_id = extract_id(&policy_resp);
    send_recv(
        &mut stream,
        b"<create_config><name>Scan Config One</name><usage_type>scan</usage_type></create_config>",
    )
    .await;

    let policies = send_recv(&mut stream, br#"<get_configs usage_type="policy"/>"#).await;
    let policies_text = policies.as_str().expect("utf8");
    assert!(policies_text.contains("Policy One"));
    assert!(!policies_text.contains("Scan Config One"));

    let modify = send_recv(
        &mut stream,
        format!(
            "<modify_config config_id=\"{policy_id}\"><comment>updated</comment><usage_type>policy</usage_type></modify_config>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let get_one = send_recv(
        &mut stream,
        format!("<get_configs config_id=\"{policy_id}\" usage_type=\"policy\"/>").as_bytes(),
    )
    .await;
    let get_one_text = get_one.as_str().expect("utf8");
    assert!(get_one_text.contains("<usage_type>policy</usage_type>"));
    assert!(get_one_text.contains("<comment>updated</comment>"));

    let wrong_usage_type = send_recv(
        &mut stream,
        format!("<get_configs config_id=\"{policy_id}\" usage_type=\"scan\"/>").as_bytes(),
    )
    .await;
    assert_eq!(wrong_usage_type.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_audits_round_trip_with_usage_type_filtering() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let audit_id = create_task(&mut stream, "Audit One", "audit").await;
    create_task(&mut stream, "Scan One", "scan").await;

    let audits = send_recv(&mut stream, br#"<get_tasks usage_type="audit"/>"#).await;
    let audits_text = audits.as_str().expect("utf8");
    assert!(audits_text.contains("Audit One"));
    assert!(!audits_text.contains("Scan One"));

    let modify = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{audit_id}\"><comment>updated</comment><usage_type>audit</usage_type></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let start = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{audit_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start.status_code(), Some(202));

    let get_one = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{audit_id}\" usage_type=\"audit\"/>").as_bytes(),
    )
    .await;
    let get_one_text = get_one.as_str().expect("utf8");
    assert!(get_one_text.contains("<usage_type>audit</usage_type>"));
    assert!(get_one_text.contains("<comment>updated</comment>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_help_returns_command_listing() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, br#"<help format="xml" type="brief"/>"#).await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<schema format=\"XML\""));
    assert!(text.contains("<command><name>get_feeds</name>"));
    assert!(text.contains("<command><name>get_tasks</name>"));

    let plain = send_recv(&mut stream, br#"<help/>"#).await;
    assert_eq!(plain.status_code(), Some(200));
    assert!(plain
        .as_str()
        .expect("utf8")
        .contains("get_tasks - Get tasks"));

    let invalid = send_recv(&mut stream, br#"<help format="brief"/>"#).await;
    assert_eq!(invalid.status_code(), Some(404));

    let invalid_type = send_recv(&mut stream, br#"<help type="full"/>"#).await;
    assert_eq!(invalid_type.status_code(), Some(400));

    let invalid_brief_format =
        send_recv(&mut stream, br#"<help format="html" type="brief"/>"#).await;
    assert_eq!(invalid_brief_format.status_code(), Some(400));

    let missing_brief_format = send_recv(&mut stream, br#"<help type="brief"/>"#).await;
    assert_eq!(missing_brief_format.status_code(), Some(400));

    let full_xml = send_recv(&mut stream, br#"<help format="xml"/>"#).await;
    assert_eq!(full_xml.status_code(), Some(200));
    let full_xml_text = full_xml.as_str().expect("utf8");
    assert!(full_xml_text.contains("<protocol>"));
    assert!(full_xml_text.contains("<command><name>get_tasks</name>"));

    let html = send_recv(&mut stream, br#"<help format="html"/>"#).await;
    assert_eq!(html.status_code(), Some(200));
    assert!(html
        .as_str()
        .expect("utf8")
        .contains("<schema format=\"html\""));

    let rnc = send_recv(&mut stream, br#"<help format="rnc"/>"#).await;
    assert_eq!(rnc.status_code(), Some(200));
    assert!(rnc
        .as_str()
        .expect("utf8")
        .contains("<schema format=\"rnc\""));

    server.shutdown().await;
}

async fn assert_aggregate_column_precedence(stream: &mut UnixStream) {
    let conflicting_columns = send_recv(
        stream,
        br#"<get_aggregates type="task" data_column="singular" data_columns="legacy-data" text_columns="legacy-text"><data_column>current-data</data_column><text_column>current-text</text_column></get_aggregates>"#,
    )
    .await;
    let conflicting_text = conflicting_columns.as_str().expect("utf8");
    assert!(conflicting_text.contains("<data_column>current-data</data_column>"));
    assert!(conflicting_text.contains("<text_column>current-text</text_column>"));
    assert!(!conflicting_text.contains("singular"));
    assert!(!conflicting_text.contains("legacy-data"));
    assert!(!conflicting_text.contains("legacy-text"));

    let singular_precedence = send_recv(
        stream,
        br#"<get_aggregates type="task" data_column="singular" data_columns="legacy-data"/>"#,
    )
    .await;
    let singular_text = singular_precedence.as_str().expect("utf8");
    assert!(singular_text.contains("<data_column>singular</data_column>"));
    assert!(!singular_text.contains("legacy-data"));
}

#[tokio::test]
async fn stateful_aggregates_returns_fixture_response() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(
        &mut stream,
        br#"<get_aggregates type="task&amp;&lt;" group_column="severity&lt;&amp;"><data_column>qod&amp;&lt;</data_column><text_column>name&amp;&lt;</text_column></get_aggregates>"#,
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<data_type>task&amp;&lt;</data_type>"));
    assert!(text.contains("<group_column>severity&lt;&amp;</group_column>"));
    assert!(text.contains("<data_column>qod&amp;&lt;</data_column>"));
    assert!(text.contains("<group><value>High</value><count>3</count><c_count>3</c_count>"));
    assert!(text.contains("<stats column=\"qod&amp;&lt;\">"));
    assert!(text.contains("<text column=\"name&amp;&lt;\">High</text>"));
    assert!(!text.contains("task&<"));

    assert_aggregate_column_precedence(&mut stream).await;

    let no_columns = send_recv(
        &mut stream,
        br#"<get_aggregates type="task" group_column="severity"/>"#,
    )
    .await;
    assert_eq!(no_columns.status_code(), Some(200));
    assert!(no_columns
        .as_str()
        .expect("utf8")
        .contains("<group><value>High</value><count>3</count><c_count>3</c_count></group>"));

    let missing_type = send_recv(&mut stream, br#"<get_aggregates/>"#).await;
    assert_eq!(missing_type.status_code(), Some(400));

    let missing_group = send_recv(
        &mut stream,
        br#"<get_aggregates type="task" subgroup_column="status"/>"#,
    )
    .await;
    assert_eq!(missing_group.status_code(), Some(400));

    let subgroup = send_recv(
        &mut stream,
        br#"<get_aggregates type="task" group_column="status" subgroup_column="owner"><data_column>qod</data_column></get_aggregates>"#,
    )
    .await;
    assert_eq!(subgroup.status_code(), Some(200));
    let subgroup_text = subgroup.as_str().expect("utf8");
    assert!(subgroup_text
        .contains("<subgroup><value>Primary</value><count>3</count><c_count>3</c_count>"));
    assert!(subgroup_text.contains(
        "<subgroup><value>Secondary</value><count>5</count><c_count>5</c_count>\
         <stats column=\"qod\"><min>1</min><max>5</max><mean>2</mean><sum>5</sum>\
         <c_sum>5</c_sum></stats></subgroup>"
    ));
    assert!(subgroup_text.contains(
        "<aggregate_column><name>subgroup_value</name><stat>value</stat>\
         <type>task</type><column>owner</column><data_type>text</data_type>"
    ));

    let overall = send_recv(
        &mut stream,
        br#"<get_aggregates type="task" data_column="severity" filt_id="filter-1" filter="owner=me"/>"#,
    )
    .await;
    assert_eq!(overall.status_code(), Some(200));
    let overall_text = overall.as_str().expect("utf8");
    assert!(overall_text
        .contains("<overall><count>8</count><c_count>8</c_count><stats column=\"severity\">"));
    assert!(overall_text
        .contains("<filters id=\"filter-1\"><term>owner=me</term><keywords/></filters>"));

    let word_counts = send_recv(
        &mut stream,
        br#"<get_aggregates type="task" group_column="comment" mode="word_counts"/>"#,
    )
    .await;
    assert_eq!(word_counts.status_code(), Some(200));
    let word_counts_text = word_counts.as_str().expect("utf8");
    assert!(word_counts_text.contains("<group><value>security</value><count>3</count></group>"));
    assert!(!word_counts_text.contains("<c_count>"));

    let word_counts_without_group = send_recv(
        &mut stream,
        br#"<get_aggregates type="task" mode="word_counts"/>"#,
    )
    .await;
    assert_eq!(word_counts_without_group.status_code(), Some(400));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_user_settings_get_and_modify() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let list = send_recv(&mut stream, b"<get_settings/>").await;
    assert_eq!(list.status_code(), Some(200));
    let list_text = list.as_str().expect("utf8");
    assert!(list_text.contains("timezone"));
    assert!(list_text.contains("<value>UTC</value>"));

    let setting_id = "00000000-0000-0000-0000-000000000001";
    let modify = send_recv(
        &mut stream,
        format!(
            "<modify_setting setting_id=\"{setting_id}\"><value>RXVyb3BlL0Jlcmxpbg==</value></modify_setting>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let get_one = send_recv(
        &mut stream,
        format!("<get_settings setting_id=\"{setting_id}\"/>").as_bytes(),
    )
    .await;
    let get_one_text = get_one.as_str().expect("utf8");
    assert!(get_one_text.contains("<value>Europe/Berlin</value>"));

    for invalid_value in ["not-valid-base64!", "//8="] {
        let invalid = send_recv(
            &mut stream,
            format!(
                "<modify_setting setting_id=\"{setting_id}\"><value>{invalid_value}</value></modify_setting>"
            )
            .as_bytes(),
        )
        .await;
        assert_eq!(invalid.status_code(), Some(400));
        assert!(invalid
            .as_str()
            .expect("utf8")
            .contains("Value cannot be decoded to valid UTF-8"));
    }

    let unchanged = send_recv(
        &mut stream,
        format!("<get_settings setting_id=\"{setting_id}\"/>").as_bytes(),
    )
    .await;
    assert!(unchanged
        .as_str()
        .expect("utf8")
        .contains("<value>Europe/Berlin</value>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_system_reports_follow_gvmd_request_and_response_shapes() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, b"<get_system_reports/>").await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<name>proc</name><title>Processes</title>"));
    assert!(text.contains("<name>load</name><title>System Load</title>"));
    assert!(
        text.contains("<report format=\"png\" start_time=\"\" end_time=\"\" duration=\"86400\">")
    );
    assert!(!text.contains("<system_report_count>"));

    let brief = send_recv(
        &mut stream,
        b"<get_system_reports name=\"load\" brief=\"true\"/>",
    )
    .await;
    assert_eq!(brief.status_code(), Some(200));
    let brief_text = brief.as_str().expect("utf8");
    assert!(!brief_text.contains("<name>proc</name>"));
    assert!(brief_text.contains("<name>load</name>"));
    assert!(!brief_text.contains("<report "));

    let not_brief = send_recv(
        &mut stream,
        b"<get_system_reports name=\"load\" brief=\"false\"/>",
    )
    .await;
    assert_eq!(not_brief.status_code(), Some(200));
    assert!(not_brief.as_str().expect("utf8").contains("<report "));

    let invalid_brief = send_recv(&mut stream, b"<get_system_reports brief=\"sometimes\"/>").await;
    assert_eq!(invalid_brief.status_code(), Some(400));

    let invalid = send_recv(
        &mut stream,
        b"<get_system_reports duration=\"not-a-number\"/>",
    )
    .await;
    assert_eq!(invalid.status_code(), Some(400));

    let unknown = send_recv(&mut stream, b"<get_system_reports name=\"unknown\"/>").await;
    assert_eq!(unknown.status_code(), Some(404));

    let interval = send_recv(
        &mut stream,
        b"<get_system_reports name=\"load\" start_time=\"2026-07-23T12:00:00Z\" end_time=\"2026-07-23T13:00:00Z\"/>",
    )
    .await;
    assert_eq!(interval.status_code(), Some(200));
    assert!(interval.as_str().expect("utf8").contains(
        "start_time=\"2026-07-23T12:00:00Z\" end_time=\"2026-07-23T13:00:00Z\" duration=\"\""
    ));

    let unknown_slave = send_recv(
        &mut stream,
        b"<get_system_reports slave_id=\"00000000-0000-0000-0000-000000000404\"/>",
    )
    .await;
    assert_eq!(unknown_slave.status_code(), Some(404));

    let invalid_slave = send_recv(&mut stream, b"<get_system_reports slave_id=\"invalid\"/>").await;
    assert_eq!(invalid_slave.status_code(), Some(400));

    let scanner = send_recv(
        &mut stream,
        b"<create_scanner><name>System Report Scanner</name><host>scanner.example</host><port>9390</port><type>2</type></create_scanner>",
    )
    .await;
    assert_eq!(scanner.status_code(), Some(201));
    let scanner_id = extract_id(&scanner);
    let scanner_report = send_recv(
        &mut stream,
        format!("<get_system_reports slave_id=\"{scanner_id}\" brief=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(scanner_report.status_code(), Some(200));
    assert!(!scanner_report.as_str().expect("utf8").contains("<report "));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_secinfo_rejects_get_info_vulnerability_alias() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, br#"<get_info type="vuln"/>"#).await;
    assert_eq!(resp.status_code(), Some(400));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_secinfo_accepts_uppercase_type_and_info_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(
        &mut stream,
        br#"<get_info details="1" info_id="CVE-2026-1000" type="CVE"/>"#,
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<info id=\"CVE-2026-1000\">"));
    assert!(text.contains("<cve><raw_data>"));
    assert!(text.contains("Mock CVE one"));
    assert!(text.contains("<info_count>2<filtered>1</filtered><page>1</page></info_count>"));
    assert!(!text.contains("CVE-2026-1001"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_secinfo_renders_nvt_and_rejects_ovaldef() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let nvt = send_recv(
        &mut stream,
        br#"<get_info details="0" name="Mock NVT one" type="NVT"/>"#,
    )
    .await;
    assert_eq!(nvt.status_code(), Some(200));
    let text = nvt.as_str().expect("utf8");
    assert!(text.contains("<info id=\"1.3.6.1.4.1.25623.1\">"));
    assert!(text.contains("Mock NVT one"));
    assert!(text.contains("<info_count>2<filtered>1</filtered><page>1</page></info_count>"));
    assert!(!text.contains("Mock NVT two"));

    let oval = send_recv(
        &mut stream,
        br#"<get_info details="1" info_id="oval:org.example:def:1" type="OVALDEF"/>"#,
    )
    .await;
    assert_eq!(oval.status_code(), Some(400));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_audit_reports_filter_by_usage_type() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let audit_task_id = create_task(&mut stream, "Audit Task", "audit").await;
    let scan_task_id = create_task(&mut stream, "Scan Task", "scan").await;

    let audit_report = send_recv(
        &mut stream,
        format!("<create_report><task id=\"{audit_task_id}\"/></create_report>").as_bytes(),
    )
    .await;
    let _scan_report = send_recv(
        &mut stream,
        format!("<create_report><task id=\"{scan_task_id}\"/></create_report>").as_bytes(),
    )
    .await;
    let audit_report_id = extract_id(&audit_report);

    let reports = send_recv(&mut stream, br#"<get_reports usage_type="audit"/>"#).await;
    let reports_text = reports.as_str().expect("utf8");
    assert!(reports_text.contains(&audit_report_id));
    assert!(reports_text.contains("<usage_type>audit</usage_type>"));
    assert!(!reports_text.contains("Scan Task"));

    let delete = send_recv(
        &mut stream,
        format!("<delete_report report_id=\"{audit_report_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_import_report_persists_task_and_in_assets() {
    let Some(server) = stateful_server().await else {
        return;
    };

    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task(&mut stream, "Imported Report Task", "scan").await;

    let create = send_recv(
        &mut stream,
        format!(
            "<create_report><task id=\"{task_id}\"/><report id=\"imported-report\"><name>Imported</name><in_assets>0</in_assets></report><in_assets>1</in_assets></create_report>"
        )
        .as_bytes(),
    )
    .await;
    let create_text = create.as_str().expect("response XML should be UTF-8");
    assert!(create_text.contains(r#"status="201""#), "{create_text}");

    let report_id = extract_id(&create);
    let listed = send_recv(&mut stream, br#"<get_reports details="1"/>"#).await;
    let listed_text = listed.as_str().expect("response XML should be UTF-8");

    assert!(
        listed_text.contains(&format!("<task_id>{task_id}</task_id>")),
        "{listed_text}"
    );
    assert!(
        listed_text.contains(&format!(r#"id="{report_id}""#)),
        "{listed_text}"
    );
    assert!(
        listed_text.contains("<in_assets>1</in_assets>"),
        "{listed_text}"
    );

    server.shutdown().await;
}
