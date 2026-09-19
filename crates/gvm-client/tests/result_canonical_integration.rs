// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{CommandSupport, GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::results::{GetResultRequest, GetResultsRequest};
use gvm_gmp::responses::ParseError;
use gvm_gmp::{EntityId, GmpRequestError};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

const RESULT_RESPONSE: &str = r#"<get_results_response status="200" status_text="OK">
    <result id="result-1"><host>192.0.2.10</host><severity>8.0</severity></result>
    <results start="1" max="1"/>
    <result_count>7<filtered>3</filtered><page>1</page></result_count>
</get_results_response>"#;

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid id")
}

async fn fixture_server(version: MockVersion, response: &str) -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .override_response("get_results", response)
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts")
}

async fn client(server: &MockGmpServer) -> GmpClient<UnixSocketConnection> {
    GmpClient::connect(UnixSocketConnection::with_path(
        server.socket_path().expect("Unix socket"),
    ))
    .await
    .expect("client connects")
}

async fn exercise_direct_and_facade_paths(version: MockVersion) {
    let server = fixture_server(version, RESULT_RESPONSE).await;
    let mut client = client(&server).await;
    server.clear_history();

    let direct = client
        .execute(GetResultsRequest::default())
        .await
        .expect("direct execution succeeds");
    assert_eq!(direct.items[0].meta.name, "");
    assert_eq!(direct.counts.total, Some(7));
    assert_eq!(direct.counts.filtered, Some(3));
    assert_eq!(direct.counts.page, Some(1));

    let direct_singular = client
        .execute(GetResultRequest::new(id("result-direct")))
        .await
        .expect("direct singular execution succeeds");
    assert_eq!(direct_singular.items.len(), 1);

    let list = GetResultsRequest {
        filter_string: Some(String::new()),
        get_counts: Some(false),
        ..GetResultsRequest::default()
    };
    client
        .get_results(list)
        .await
        .expect("list facade succeeds");

    let mut detail = GetResultRequest::new(id("result-1"));
    detail.details = Some(false);
    detail.notes_details = Some(true);
    client
        .get_result(detail)
        .await
        .expect("detail facade succeeds");

    let requests = server
        .command_history()
        .iter()
        .map(|record| {
            std::str::from_utf8(record.raw_xml())
                .expect("request UTF-8")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        requests,
        [
            "<get_results/>",
            "<get_results details=\"1\" result_id=\"result-direct\"/>",
            "<get_results filter=\"\" get_counts=\"0\"/>",
            "<get_results details=\"0\" notes_details=\"1\" result_id=\"result-1\"/>",
        ]
    );
    assert_eq!(
        client.command_support("get_results"),
        CommandSupport::Supported
    );
    assert_eq!(
        client.command_support("get_result"),
        CommandSupport::UnknownCommand
    );
    server.shutdown().await;
}

#[tokio::test]
async fn direct_and_both_facades_work_on_baseline_and_newer_versions() {
    exercise_direct_and_facade_paths(MockVersion::V22_4).await;
    exercise_direct_and_facade_paths(MockVersion::V22_8).await;
}

#[tokio::test]
async fn invalid_final_filter_is_a_safe_request_error_before_transport() {
    let server = fixture_server(MockVersion::V22_4, RESULT_RESPONSE).await;
    let mut client = client(&server).await;
    server.clear_history();

    let direct = GetResultsRequest {
        filter_string: Some("private\u{0}filter".into()),
        ..GetResultsRequest::default()
    };
    let direct_error = client
        .execute(direct)
        .await
        .expect_err("direct invalid request fails");

    let mut facade = GetResultRequest::new(id("result-1"));
    facade.filter_string = Some("second\u{1}private".into());
    let facade_error = client
        .get_result(facade)
        .await
        .expect_err("facade invalid request fails");

    for error in [direct_error, facade_error] {
        assert!(matches!(
            error,
            GvmError::Request(GmpRequestError::InvalidField {
                field: "filter_string",
                ..
            })
        ));
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("private"));
    }
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn both_facades_normalize_server_errors() {
    let server = fixture_server(
        MockVersion::V22_8,
        r#"<get_results_response status="404" status_text="Result missing"/>"#,
    )
    .await;
    let mut client = client(&server).await;

    for error in [
        client
            .get_results(GetResultsRequest::default())
            .await
            .expect_err("list server error"),
        client
            .get_result(GetResultRequest::new(id("result-1")))
            .await
            .expect_err("detail server error"),
    ] {
        assert!(matches!(
            error,
            GvmError::Server { status: 404, message } if message == "Result missing"
        ));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn both_facades_preserve_result_parse_context() {
    let server = fixture_server(
        MockVersion::V22_8,
        r#"<get_results_response status="200" status_text="OK"><result/></get_results_response>"#,
    )
    .await;
    let mut client = client(&server).await;

    for error in [
        client
            .get_results(GetResultsRequest::default())
            .await
            .expect_err("list parse error"),
        client
            .get_result(GetResultRequest::new(id("result-1")))
            .await
            .expect_err("detail parse error"),
    ] {
        assert!(matches!(
            error,
            GvmError::Parse(ParseError::MissingElement(field)) if field == "result.id"
        ));
    }
    server.shutdown().await;
}
