// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::too_many_lines, clippy::unwrap_used, missing_docs)]

use gvm_client::{GmpClient, GmpVersioned, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::configs::{
    CloneConfigRequest, CreateConfigRequest, DeleteConfigRequest, GetConfigRequest,
    GetConfigsRequest, ModifyConfigRequest,
};
use gvm_gmp::commands::scan_configs::{
    ClonePolicyRequest, CloneScanConfigRequest, CreatePolicyRequest, CreateScanConfigRequest,
    DeletePolicyRequest, DeleteScanConfigRequest, GetPoliciesRequest, GetPolicyRequest,
    GetScanConfigPreferenceRequest, GetScanConfigPreferencesRequest, GetScanConfigRequest,
    GetScanConfigsRequest, ImportPolicyRequest, ImportScanConfigRequest, ModifyPolicyRequest,
    ModifyPolicySetCommentRequest, ModifyPolicySetFamilySelectionRequest,
    ModifyPolicySetNameRequest, ModifyPolicySetNvtPreferenceRequest,
    ModifyPolicySetNvtSelectionRequest, ModifyPolicySetScannerPreferenceRequest,
    ModifyScanConfigRequest, ModifyScanConfigSetCommentRequest,
    ModifyScanConfigSetFamilySelectionRequest, ModifyScanConfigSetNameRequest,
    ModifyScanConfigSetNvtPreferenceRequest, ModifyScanConfigSetNvtSelectionRequest,
    ModifyScanConfigSetScannerPreferenceRequest, NvtFamilySelection,
};
use gvm_gmp::EntityId;
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};

const ID: &str = "11111111-1111-1111-1111-111111111111";
const CREATED: &str = "22222222-2222-2222-2222-222222222222";

fn id() -> EntityId {
    EntityId::new(ID).expect("valid test ID")
}

fn import_xml(name: &str) -> String {
    format!(
        "<get_configs_response status=\"200\" status_text=\"OK\"><config id=\"{ID}\"><name>{name}</name><nvt_selectors/><preferences/></config></get_configs_response>"
    )
}

async fn server(version: GmpVersion) -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto()
        .override_response(
            "get_configs",
            &format!(
                "<get_configs_response status=\"200\" status_text=\"OK\"><config id=\"{ID}\"><owner><name>admin</name></owner><name>Fixture config</name><comment>fixture</comment><usage_type>scan</usage_type><type>0</type><family_count>2<growing>1</growing></family_count><nvt_count>3<growing>0</growing></nvt_count><families><family><name>ignored</name></family></families><preferences><preference><value>ignored secret</value></preference></preferences><tasks><task id=\"{ID}\"/></tasks></config><config_count>1<filtered>1</filtered><page>1</page></config_count></get_configs_response>"
            ),
        )
        .override_response(
            "create_config",
            &format!(
                "<create_config_response status=\"201\" status_text=\"OK\" id=\"{CREATED}\"><config><name>extra tolerated payload</name></config></create_config_response>"
            ),
        )
        .override_response(
            "modify_config",
            r#"<modify_config_response status="200" status_text="OK"/>"#,
        )
        .override_response(
            "get_preferences",
            r#"<get_preferences_response status="200" status_text="OK"><preference><nvt oid="1.3.6.1.4.1.25623.1.0.100000"><name>Fixture NVT</name></nvt><name>1.3.6.1.4.1.25623.1.0.100000:1:entry:Timeout</name><hr_name>Timeout</hr_name><id>1</id><type>entry</type><value>30</value><default>10</default></preference></get_preferences_response>"#,
        )
        .override_response(
            "delete_config",
            r#"<delete_config_response status="200" status_text="OK"/>"#,
        )
        .build()
        .await
        .expect("fixture server starts")
}

fn connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("Unix socket"))
}

#[tokio::test]
async fn all_thirty_four_requests_execute_with_static_associations_at_baseline() {
    let server = server(GmpVersion::V22_4).await;
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    server.clear_history();

    client
        .execute(GetConfigsRequest::new())
        .await
        .expect("generic list");
    client
        .execute(GetConfigRequest::new(id()))
        .await
        .expect("generic detail");
    client
        .execute(CreateConfigRequest::new("create", id()))
        .await
        .expect("generic create");
    client
        .execute(CloneConfigRequest::new(id()))
        .await
        .expect("generic clone");
    client
        .execute(ModifyConfigRequest::new(id()))
        .await
        .expect("generic modify");
    client
        .execute(DeleteConfigRequest::new(id()))
        .await
        .expect("generic delete");

    client
        .execute(GetScanConfigsRequest::new())
        .await
        .expect("scan list");
    client
        .execute(GetScanConfigRequest::new(id()))
        .await
        .expect("scan detail");
    client
        .execute(GetPoliciesRequest::new())
        .await
        .expect("policy list");
    client
        .execute(GetPolicyRequest::new(id()))
        .await
        .expect("policy detail");
    client
        .execute(CreateScanConfigRequest::new("scan", id()))
        .await
        .expect("scan create");
    client
        .execute(CreatePolicyRequest::new("policy", id()))
        .await
        .expect("policy create");
    client
        .execute(CloneScanConfigRequest::new(id()))
        .await
        .expect("scan clone");
    client
        .execute(ClonePolicyRequest::new(id()))
        .await
        .expect("policy clone");
    client
        .execute(ImportScanConfigRequest::new(import_xml("scan import")))
        .await
        .expect("scan import");
    client
        .execute(ImportPolicyRequest::new(import_xml("policy import")))
        .await
        .expect("policy import");
    client
        .execute(ModifyScanConfigRequest::new(id()))
        .await
        .expect("scan modify");
    client
        .execute(ModifyPolicyRequest::new(id()))
        .await
        .expect("policy modify");
    client
        .execute(ModifyScanConfigSetNameRequest::new(id(), "name"))
        .await
        .expect("scan name");
    client
        .execute(ModifyScanConfigSetCommentRequest::new(
            id(),
            Some("comment".into()),
        ))
        .await
        .expect("scan comment");
    client
        .execute(ModifyPolicySetNameRequest::new(id(), "name"))
        .await
        .expect("policy name");
    client
        .execute(ModifyPolicySetCommentRequest::new(
            id(),
            Some("comment".into()),
        ))
        .await
        .expect("policy comment");
    client
        .execute(DeleteScanConfigRequest::new(id()))
        .await
        .expect("scan delete");
    client
        .execute(DeletePolicyRequest::new(id()))
        .await
        .expect("policy delete");

    let mut list_preferences = GetScanConfigPreferencesRequest::new();
    list_preferences.config_id = Some(id());
    client
        .execute(list_preferences)
        .await
        .expect("preference list");
    let mut one_preference = GetScanConfigPreferenceRequest::new("entry:Timeout");
    one_preference.config_id = Some(id());
    client
        .execute(one_preference)
        .await
        .expect("single preference");
    client
        .execute(ModifyScanConfigSetNvtPreferenceRequest::new(
            id(),
            "1.3.6.1.4.1.25623.1.0.100000:1:entry:Timeout",
            "1.3.6.1.4.1.25623.1.0.100000",
            Some("30".into()),
        ))
        .await
        .expect("scan NVT preference");
    client
        .execute(ModifyScanConfigSetScannerPreferenceRequest::new(
            id(),
            "max_checks",
            Some("4".into()),
        ))
        .await
        .expect("scan scanner preference");
    client
        .execute(ModifyScanConfigSetNvtSelectionRequest::new(
            id(),
            "General",
            vec!["1.3.6.1.4.1.25623.1.0.100000".into()],
        ))
        .await
        .expect("scan NVT selection");
    client
        .execute(ModifyScanConfigSetFamilySelectionRequest::new(
            id(),
            vec![NvtFamilySelection {
                name: "General".into(),
                growing: true,
                all: false,
            }],
            true,
        ))
        .await
        .expect("scan family selection");
    client
        .execute(ModifyPolicySetNvtPreferenceRequest::new(
            id(),
            "1.3.6.1.4.1.25623.1.0.100000:1:entry:Timeout",
            "1.3.6.1.4.1.25623.1.0.100000",
            None,
        ))
        .await
        .expect("policy NVT preference delete");
    client
        .execute(ModifyPolicySetScannerPreferenceRequest::new(
            id(),
            "max_checks",
            Some(String::new()),
        ))
        .await
        .expect("policy scanner preference empty value");
    client
        .execute(ModifyPolicySetNvtSelectionRequest::new(
            id(),
            "General",
            Vec::new(),
        ))
        .await
        .expect("policy NVT selection clear");
    client
        .execute(ModifyPolicySetFamilySelectionRequest::new(
            id(),
            Vec::new(),
            false,
        ))
        .await
        .expect("policy family selection clear");

    let history = server.command_history();
    assert_eq!(history.len(), 34);
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_configs")
            .count(),
        6
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "create_config")
            .count(),
        8
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "modify_config")
            .count(),
        15
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "get_preferences")
            .count(),
        2
    );
    assert_eq!(
        history
            .iter()
            .filter(|record| record.command_name() == "delete_config")
            .count(),
        3
    );
    server.shutdown().await;
}

#[tokio::test]
async fn all_twenty_retained_facades_accept_complete_requests_by_value() {
    let server = server(GmpVersion::V22_4).await;
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    server.clear_history();

    client.get_configs(GetConfigsRequest::new()).await.unwrap();
    client
        .get_config(GetConfigRequest::new(id()))
        .await
        .unwrap();
    client
        .create_config(CreateConfigRequest::new("create", id()))
        .await
        .unwrap();
    client
        .clone_config(CloneConfigRequest::new(id()))
        .await
        .unwrap();
    client
        .modify_config(ModifyConfigRequest::new(id()))
        .await
        .unwrap();
    client
        .delete_config(DeleteConfigRequest::new(id()))
        .await
        .unwrap();

    client
        .get_scan_configs(GetScanConfigsRequest::new())
        .await
        .unwrap();
    client
        .get_scan_config(GetScanConfigRequest::new(id()))
        .await
        .unwrap();
    client
        .get_policies(GetPoliciesRequest::new())
        .await
        .unwrap();
    client
        .get_policy(GetPolicyRequest::new(id()))
        .await
        .unwrap();
    client
        .create_scan_config(CreateScanConfigRequest::new("scan", id()))
        .await
        .unwrap();
    client
        .import_scan_config(ImportScanConfigRequest::new(import_xml("scan import")))
        .await
        .unwrap();
    client
        .import_policy(ImportPolicyRequest::new(import_xml("policy import")))
        .await
        .unwrap();
    client
        .modify_scan_config(ModifyScanConfigRequest::new(id()))
        .await
        .unwrap();
    client
        .modify_scan_config_set_name(ModifyScanConfigSetNameRequest::new(id(), "name"))
        .await
        .unwrap();
    client
        .modify_scan_config_set_comment(ModifyScanConfigSetCommentRequest::new(id(), None))
        .await
        .unwrap();
    client
        .modify_policy_set_name(ModifyPolicySetNameRequest::new(id(), "name"))
        .await
        .unwrap();
    client
        .modify_policy_set_comment(ModifyPolicySetCommentRequest::new(id(), None))
        .await
        .unwrap();
    client
        .delete_scan_config(DeleteScanConfigRequest::new(id()))
        .await
        .unwrap();
    client
        .clone_scan_config(CloneScanConfigRequest::new(id()))
        .await
        .unwrap();

    assert_eq!(server.command_history().len(), 20);
    server.shutdown().await;
}

#[tokio::test]
async fn invalid_mutated_import_fails_before_transport_without_exposing_xml() {
    let server = server(GmpVersion::V22_4).await;
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    server.clear_history();

    let secret = "do-not-leak-649";
    let mut request = ImportPolicyRequest::new(import_xml("initial"));
    request.xml = format!(
        "<get_configs_response><config><name>{secret}</name><preferences/></config></get_configs_response>"
    );
    let error = client
        .import_policy(request)
        .await
        .expect_err("missing selectors must fail before send");
    assert!(matches!(error, GvmError::Request(_)));
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains(secret));
    assert!(server.command_history().is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn invalid_final_preference_value_wins_before_capability_and_transport() {
    let server = server(GmpVersion::V22_4).await;
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    server.clear_history();

    let secret = "do-not-leak-658";
    let mut request = ModifyPolicySetNvtPreferenceRequest::new(
        id(),
        "1.3.6.1.4.1.25623.1.0.100000:1:radio:Mode",
        "1.3.6.1.4.1.25623.1.0.100000",
        Some(secret.into()),
    );
    request.value = Some(String::new());
    let error = client
        .execute(request)
        .await
        .expect_err("mutated empty radio value must fail before send");
    assert!(matches!(error, GvmError::Request(_)));
    assert!(!format!("{error:?} {error}").contains(secret));
    assert!(server.command_history().is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn lifecycle_requests_are_inherited_by_every_versioned_client_family() {
    for version in [
        GmpVersion::V22_4,
        GmpVersion::V22_5,
        GmpVersion::V22_6,
        GmpVersion::V22_7,
        GmpVersion::V22_8,
    ] {
        let server = server(version).await;
        let mut client = GmpVersioned::connect(connection(&server))
            .await
            .expect("versioned client connects");
        server.clear_history();

        let response = client
            .execute(GetScanConfigPreferenceRequest::new("entry:Timeout"))
            .await
            .expect("canonical preference request executes");
        assert!(response.item.is_some());
        assert_eq!(server.command_history().len(), 1);

        server.shutdown().await;
    }
}
