// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use std::sync::{Arc, Mutex};

use gvm_client::{GmpClient, GmpVersioned, GvmError, WireTraceDirection, WireTraceEvent};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::tls_certificates::{
    CloneTlsCertificateRequest, CreateTlsCertificateRequest, DeleteTlsCertificateRequest,
    GetTlsCertificateRequest, GetTlsCertificatesRequest, ModifyTlsCertificateRequest,
};
use gvm_gmp::{EntityId, GmpRequestError};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

const TLS_ID: &str = "11111111-1111-1111-1111-111111111111";
const CREATED_ID: &str = "22222222-2222-2222-2222-222222222222";

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid fixture ID")
}

fn fixture_builder(version: MockVersion) -> gvm_mock_server::MockGmpServerBuilder {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto()
        .override_response(
            "get_tls_certificates",
            &format!(
                r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate id="{TLS_ID}"><owner><name>admin</name></owner><name>Fixture</name><certificate format="PEM">Y2VydA==</certificate><valid>1</valid></tls_certificate><tls_certificates start="1" max="1"/><tls_certificate_count>1<filtered>1</filtered><page>1</page></tls_certificate_count></get_tls_certificates_response>"#
            ),
        )
        .override_response(
            "create_tls_certificate",
            &format!(
                r#"<create_tls_certificate_response status="201" status_text="OK" id="{CREATED_ID}"/>"#
            ),
        )
        .override_response(
            "modify_tls_certificate",
            r#"<modify_tls_certificate_response status="200" status_text="OK"/>"#,
        )
        .override_response(
            "delete_tls_certificate",
            r#"<delete_tls_certificate_response status="200" status_text="OK"/>"#,
        )
}

async fn fixture_server(version: MockVersion) -> MockGmpServer {
    fixture_builder(version)
        .build()
        .await
        .expect("fixture server starts")
}

fn connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("Unix socket"))
}

fn assert_canonical_history(server: &MockGmpServer) {
    let history = server
        .command_history()
        .iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("request UTF-8"))
        .collect::<Vec<_>>();
    assert_eq!(history.len(), 12);
    assert_eq!(history[0], "<get_tls_certificates/>");
    assert_eq!(
        history[1],
        format!("<get_tls_certificates details=\"1\" tls_certificate_id=\"{TLS_ID}\"/>")
    );
    assert_eq!(
        history[2],
        "<create_tls_certificate><certificate>Y2VydA==</certificate></create_tls_certificate>"
    );
    assert_eq!(
        history[3],
        format!("<create_tls_certificate><copy>{TLS_ID}</copy></create_tls_certificate>")
    );
    assert_eq!(
        history[4],
        format!("<modify_tls_certificate tls_certificate_id=\"{TLS_ID}\"/>")
    );
    assert_eq!(
        history[5],
        format!("<delete_tls_certificate tls_certificate_id=\"{TLS_ID}\"/>")
    );
    assert_eq!(&history[..6], &history[6..]);
}

async fn exercise_direct_and_facade_paths(version: MockVersion) {
    let server = fixture_server(version).await;
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    server.clear_history();

    assert_eq!(
        client
            .execute(GetTlsCertificatesRequest::new())
            .await
            .expect("direct list")
            .items[0]
            .meta
            .name,
        "Fixture"
    );
    client
        .execute(GetTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("direct detail");
    assert_eq!(
        client
            .execute(CreateTlsCertificateRequest::new(b"cert".to_vec()))
            .await
            .expect("direct create")
            .id,
        id(CREATED_ID)
    );
    client
        .execute(CloneTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("direct clone");
    client
        .execute(ModifyTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("direct modify");
    client
        .execute(DeleteTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("direct delete");

    client
        .get_tls_certificates(GetTlsCertificatesRequest::new())
        .await
        .expect("list facade");
    client
        .get_tls_certificate(GetTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("detail facade");
    client
        .create_tls_certificate(CreateTlsCertificateRequest::new(b"cert".to_vec()))
        .await
        .expect("create facade");
    client
        .clone_tls_certificate(CloneTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("clone facade");
    client
        .modify_tls_certificate(ModifyTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("modify facade");
    client
        .delete_tls_certificate(DeleteTlsCertificateRequest::new(id(TLS_ID)))
        .await
        .expect("delete facade");

    assert_canonical_history(&server);
    server.shutdown().await;
}

#[tokio::test]
async fn six_direct_requests_and_facades_work_on_baseline_and_newer_versions() {
    exercise_direct_and_facade_paths(MockVersion::V22_4).await;
    exercise_direct_and_facade_paths(MockVersion::V22_8).await;
}

#[tokio::test]
async fn semantic_aliases_work_from_baseline_through_next() {
    for version in [
        MockVersion::V22_4,
        MockVersion::V22_5,
        MockVersion::V22_6,
        MockVersion::V22_7,
        MockVersion::V22_8,
    ] {
        let server = fixture_server(version).await;
        let mut client = GmpVersioned::connect(connection(&server))
            .await
            .expect("versioned client connects");
        server.clear_history();
        client
            .execute(GetTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect("detail alias is supported");
        client
            .execute(CloneTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect("clone alias is supported");
        assert_eq!(server.command_count(), 2);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn final_request_errors_precede_transport_without_payload_leakage() {
    let server = fixture_server(MockVersion::V22_4).await;
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    server.clear_history();

    let mut create = CreateTlsCertificateRequest::new(b"private-certificate".to_vec());
    create.certificate.clear();
    let mut query = GetTlsCertificatesRequest::new();
    query.filter_string = Some("private-filter\0value".into());

    for error in [
        client.execute(create).await.expect_err("empty certificate"),
        client.execute(query).await.expect_err("invalid filter"),
    ] {
        assert!(matches!(
            error,
            GvmError::Request(GmpRequestError::InvalidField { .. })
        ));
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("private-certificate"));
        assert!(!diagnostic.contains("private-filter"));
    }
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn every_facade_normalizes_server_errors() {
    let error = r#"<response status="409" status_text="certificate conflict"/>"#;
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .override_response("get_tls_certificates", error)
        .override_response("create_tls_certificate", error)
        .override_response("modify_tls_certificate", error)
        .override_response("delete_tls_certificate", error)
        .build()
        .await
        .expect("server starts");
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");

    let errors = [
        client
            .get_tls_certificates(GetTlsCertificatesRequest::new())
            .await
            .expect_err("list server error"),
        client
            .get_tls_certificate(GetTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("detail server error"),
        client
            .create_tls_certificate(CreateTlsCertificateRequest::new(b"cert".to_vec()))
            .await
            .expect_err("create server error"),
        client
            .clone_tls_certificate(CloneTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("clone server error"),
        client
            .modify_tls_certificate(ModifyTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("modify server error"),
        client
            .delete_tls_certificate(DeleteTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("delete server error"),
    ];
    for error in errors {
        assert!(matches!(
            error,
            GvmError::Server { status: 409, message } if message == "certificate conflict"
        ));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn direct_execution_and_every_facade_preserve_structural_parse_errors() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .override_response(
            "get_tls_certificates",
            r#"<get_tls_certificates_response status="not-a-number" status_text="broken"/>"#,
        )
        .override_response(
            "create_tls_certificate",
            r#"<create_tls_certificate_response status="not-a-number" status_text="broken"/>"#,
        )
        .override_response(
            "modify_tls_certificate",
            r#"<modify_tls_certificate_response status="not-a-number" status_text="broken"/>"#,
        )
        .override_response(
            "delete_tls_certificate",
            r#"<delete_tls_certificate_response status="not-a-number" status_text="broken"/>"#,
        )
        .build()
        .await
        .expect("server starts");
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");

    assert!(matches!(
        client
            .execute(GetTlsCertificatesRequest::new())
            .await
            .expect_err("direct parse error"),
        GvmError::Parse(_)
    ));
    let errors = [
        client
            .get_tls_certificates(GetTlsCertificatesRequest::new())
            .await
            .expect_err("list parse error"),
        client
            .get_tls_certificate(GetTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("detail parse error"),
        client
            .create_tls_certificate(CreateTlsCertificateRequest::new(b"cert".to_vec()))
            .await
            .expect_err("create parse error"),
        client
            .clone_tls_certificate(CloneTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("clone parse error"),
        client
            .modify_tls_certificate(ModifyTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("modify parse error"),
        client
            .delete_tls_certificate(DeleteTlsCertificateRequest::new(id(TLS_ID)))
            .await
            .expect_err("delete parse error"),
    ];
    for error in errors {
        assert!(matches!(error, GvmError::Parse(_)));
    }
    server.shutdown().await;
}

fn trace_text(event: &WireTraceEvent) -> String {
    String::from_utf8(event.bytes.clone()).expect("trace UTF-8")
}

#[tokio::test]
async fn request_response_debug_and_wire_trace_redact_certificate_data() {
    let server = fixture_server(MockVersion::V22_8).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let trace_events = Arc::clone(&events);
    let mut client = GmpClient::connect_with_wire_trace(connection(&server), move |event| {
        trace_events.lock().expect("trace lock").push(event);
    })
    .await
    .expect("client connects");
    events.lock().expect("trace lock").clear();

    let create = CreateTlsCertificateRequest::new(b"do-not-log-certificate".to_vec());
    assert!(!format!("{create:?}").contains("do-not-log"));
    client
        .create_tls_certificate(create)
        .await
        .expect("create succeeds");
    let response = client
        .get_tls_certificates(GetTlsCertificatesRequest::new())
        .await
        .expect("list succeeds");
    assert!(!format!("{response:?}").contains("Y2VydA=="));

    {
        let events = events.lock().expect("trace lock");
        let requests = events
            .iter()
            .filter(|event| event.direction == WireTraceDirection::Request)
            .map(trace_text)
            .collect::<Vec<_>>();
        let responses = events
            .iter()
            .filter(|event| event.direction == WireTraceDirection::Response)
            .map(trace_text)
            .collect::<Vec<_>>();
        assert!(requests[0].contains("<certificate><redacted/></certificate>"));
        assert!(!requests[0].contains("ZG8tbm90LWxvZy1jZXJ0aWZpY2F0ZQ=="));
        assert!(responses[1].contains("<certificate format=\"PEM\"><redacted/></certificate>"));
        assert!(!responses[1].contains("Y2VydA=="));
    }
    server.shutdown().await;
}
