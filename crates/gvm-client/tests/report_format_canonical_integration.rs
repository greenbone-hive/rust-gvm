// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use std::sync::{Arc, Mutex};

use gvm_client::{GmpClient, GmpVersioned, GvmError, WireTraceDirection, WireTraceEvent};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::report_formats::{
    CloneReportFormatRequest, DeleteReportFormatRequest, GetReportFormatRequest,
    GetReportFormatsRequest, ImportReportFormatRequest, ModifyReportFormatRequest,
    ReportFormatParamUpdate, VerifyReportFormatRequest,
};
use gvm_gmp::{EntityId, GmpRequestError};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

const FORMAT_ID: &str = "11111111-1111-1111-1111-111111111111";
const CREATED_ID: &str = "22222222-2222-2222-2222-222222222222";
const EXPORTED: &str = r#"<get_report_formats_response status="200" status_text="OK"><report_format id="11111111-1111-1111-1111-111111111111"><name>Imported</name><file name="script.sh">do-not-log-file</file></report_format></get_report_formats_response>"#;

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid fixture ID")
}

fn fixture_builder(version: MockVersion) -> gvm_mock_server::MockGmpServerBuilder {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto()
        .override_response(
            "get_report_formats",
            &format!(
                r#"<get_report_formats_response status="200" status_text="OK"><report_format id="{FORMAT_ID}"><name>Fixture</name><trust>yes<time>2026-09-19T00:00:00Z</time></trust><active>1</active><predefined>0</predefined></report_format><report_formats start="1" max="1"/><report_format_count>1<filtered>1</filtered><page>1</page></report_format_count></get_report_formats_response>"#
            ),
        )
        .override_response(
            "create_report_format",
            &format!(
                r#"<create_report_format_response status="201" status_text="OK" id="{CREATED_ID}"/>"#
            ),
        )
        .override_response(
            "modify_report_format",
            r#"<modify_report_format_response status="200" status_text="OK"/>"#,
        )
        .override_response(
            "delete_report_format",
            r#"<delete_report_format_response status="200" status_text="OK"/>"#,
        )
        .override_response(
            "verify_report_format",
            r#"<verify_report_format_response status="200" status_text="OK"/>"#,
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
    assert_eq!(history.len(), 14);
    assert_eq!(history[0], "<get_report_formats/>");
    assert_eq!(
        history[1],
        format!("<get_report_formats details=\"1\" report_format_id=\"{FORMAT_ID}\"/>")
    );
    assert_eq!(
        history[2],
        format!("<create_report_format>{EXPORTED}</create_report_format>")
    );
    assert_eq!(
        history[3],
        format!("<create_report_format><copy>{FORMAT_ID}</copy></create_report_format>")
    );
    assert_eq!(
        history[4],
        format!("<modify_report_format report_format_id=\"{FORMAT_ID}\"/>")
    );
    assert_eq!(
        history[5],
        format!("<delete_report_format report_format_id=\"{FORMAT_ID}\"/>")
    );
    assert_eq!(
        history[6],
        format!("<verify_report_format report_format_id=\"{FORMAT_ID}\"/>")
    );
    assert_eq!(&history[..7], &history[7..]);
}

async fn exercise_direct_and_facade_paths(version: MockVersion) {
    let server = fixture_server(version).await;
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    server.clear_history();

    assert_eq!(
        client
            .execute(GetReportFormatsRequest::new())
            .await
            .expect("direct list")
            .items[0]
            .meta
            .name,
        "Fixture"
    );
    client
        .execute(GetReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("direct detail");
    assert_eq!(
        client
            .execute(ImportReportFormatRequest::new(EXPORTED))
            .await
            .expect("direct import")
            .id,
        id(CREATED_ID)
    );
    client
        .execute(CloneReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("direct clone");
    client
        .execute(ModifyReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("direct modify");
    client
        .execute(DeleteReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("direct delete");
    client
        .execute(VerifyReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("direct verify");

    client
        .get_report_formats(GetReportFormatsRequest::new())
        .await
        .expect("list facade");
    client
        .get_report_format(GetReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("detail facade");
    client
        .import_report_format(ImportReportFormatRequest::new(EXPORTED))
        .await
        .expect("import facade");
    client
        .clone_report_format(CloneReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("clone facade");
    client
        .modify_report_format(ModifyReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("modify facade");
    client
        .delete_report_format(DeleteReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("delete facade");
    client
        .verify_report_format(VerifyReportFormatRequest::new(id(FORMAT_ID)))
        .await
        .expect("verify facade");

    assert_canonical_history(&server);
    server.shutdown().await;
}

#[tokio::test]
async fn seven_direct_requests_and_facades_work_on_baseline_and_newer_versions() {
    exercise_direct_and_facade_paths(MockVersion::V22_4).await;
    exercise_direct_and_facade_paths(MockVersion::V22_8).await;
}

#[tokio::test]
async fn versioned_wrappers_execute_semantic_aliases_on_baseline_and_next() {
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
            .execute(GetReportFormatRequest::new(id(FORMAT_ID)))
            .await
            .expect("detail alias is supported");
        client
            .execute(ImportReportFormatRequest::new(EXPORTED))
            .await
            .expect("import alias is supported");
        client
            .execute(CloneReportFormatRequest::new(id(FORMAT_ID)))
            .await
            .expect("clone alias is supported");
        assert_eq!(server.command_count(), 3);
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

    let query = GetReportFormatsRequest {
        trash: Some(true),
        params: Some(true),
        ..GetReportFormatsRequest::new()
    };
    let import = ImportReportFormatRequest::new(
        "<get_report_formats_response><report_format id=\"private-id\"><name>private-name</name>",
    );
    let mut modify = ModifyReportFormatRequest::new(id(FORMAT_ID));
    modify.param = Some(ReportFormatParamUpdate {
        name: "private-name".into(),
        value: Some("private-value\0tail".into()),
    });

    for error in [
        client.execute(query).await.expect_err("invalid query"),
        client.execute(import).await.expect_err("invalid import"),
        client.execute(modify).await.expect_err("invalid parameter"),
    ] {
        assert!(matches!(
            error,
            GvmError::Request(GmpRequestError::InvalidField { .. })
        ));
        let diagnostic = format!("{error:?} {error}");
        for secret in ["private-id", "private-name", "private-value"] {
            assert!(!diagnostic.contains(secret));
        }
    }
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn every_facade_normalizes_server_errors() {
    let error = r#"<response status="409" status_text="format conflict"/>"#;
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .override_response("get_report_formats", error)
        .override_response("create_report_format", error)
        .override_response("modify_report_format", error)
        .override_response("delete_report_format", error)
        .override_response("verify_report_format", error)
        .build()
        .await
        .expect("server starts");
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");

    let errors = [
        client
            .get_report_formats(GetReportFormatsRequest::new())
            .await
            .expect_err("list server error"),
        client
            .get_report_format(GetReportFormatRequest::new(id(FORMAT_ID)))
            .await
            .expect_err("detail server error"),
        client
            .import_report_format(ImportReportFormatRequest::new(EXPORTED))
            .await
            .expect_err("import server error"),
        client
            .clone_report_format(CloneReportFormatRequest::new(id(FORMAT_ID)))
            .await
            .expect_err("clone server error"),
        client
            .modify_report_format(ModifyReportFormatRequest::new(id(FORMAT_ID)))
            .await
            .expect_err("modify server error"),
        client
            .delete_report_format(DeleteReportFormatRequest::new(id(FORMAT_ID)))
            .await
            .expect_err("delete server error"),
        client
            .verify_report_format(VerifyReportFormatRequest::new(id(FORMAT_ID)))
            .await
            .expect_err("verify server error"),
    ];
    for error in errors {
        assert!(matches!(
            error,
            GvmError::Server { status: 409, message } if message == "format conflict"
        ));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn read_and_create_facades_preserve_structural_parse_context() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .override_response(
            "get_report_formats",
            r#"<get_report_formats_response status="200" status_text="OK"><report_format><name>missing ID</name></report_format></get_report_formats_response>"#,
        )
        .override_response(
            "create_report_format",
            r#"<create_report_format_response status="201" status_text="OK"/>"#,
        )
        .build()
        .await
        .expect("server starts");
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    for error in [
        client
            .get_report_formats(GetReportFormatsRequest::new())
            .await
            .expect_err("read parse error"),
        client
            .import_report_format(ImportReportFormatRequest::new(EXPORTED))
            .await
            .expect_err("create parse error"),
    ] {
        assert!(matches!(error, GvmError::Parse(_)));
    }
    server.shutdown().await;
}

fn trace_text(event: &WireTraceEvent) -> String {
    String::from_utf8(event.bytes.clone()).expect("trace UTF-8")
}

#[tokio::test]
async fn request_debug_and_wire_trace_redact_import_files_and_parameter_values() {
    let server = fixture_server(MockVersion::V22_8).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let trace_events = Arc::clone(&events);
    let mut client = GmpClient::connect_with_wire_trace(connection(&server), move |event| {
        trace_events.lock().expect("trace lock").push(event);
    })
    .await
    .expect("client connects");
    events.lock().expect("trace lock").clear();

    let import = ImportReportFormatRequest::new(EXPORTED);
    assert!(!format!("{import:?}").contains("do-not-log-file"));
    client
        .import_report_format(import)
        .await
        .expect("import succeeds");

    let mut modify = ModifyReportFormatRequest::new(id(FORMAT_ID));
    modify.param = Some(ReportFormatParamUpdate {
        name: "do-not-log-name".into(),
        value: Some("do-not-log-value".into()),
    });
    assert!(!format!("{modify:?}").contains("do-not-log"));
    client
        .modify_report_format(modify)
        .await
        .expect("modify succeeds");

    let requests = events
        .lock()
        .expect("trace lock")
        .iter()
        .filter(|event| event.direction == WireTraceDirection::Request)
        .map(trace_text)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("<file name=\"script.sh\"><redacted/></file>"));
    assert!(requests[1].contains("<param><redacted/></param>"));
    for request in requests {
        assert!(!request.contains("do-not-log"));
    }
    server.shutdown().await;
}
