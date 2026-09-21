// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded gvmd-shaped report lifecycle conformance coverage.

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::unwrap_used, missing_docs)]

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(|store| {
            let mut audit = Resource::with_id(
                "report",
                "Seeded audit report",
                "10000000-0000-4000-8000-000000000661"
                    .parse()
                    .expect("audit UUID"),
            );
            audit.set_attr("usage_type", "audit");
            audit.set_attr("status", "Done");
            store.seed(audit);
        })
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}

async fn send_recv(stream: &mut UnixStream, xml: impl AsRef<[u8]>) -> Response {
    stream.write_all(xml.as_ref()).await.expect("request write");
    let mut bytes = vec![0; 256 * 1024];
    let length = stream.read(&mut bytes).await.expect("response read");
    bytes.truncate(length);
    Response::new(bytes)
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().expect("Unix socket"))
        .await
        .expect("connect");
    let response = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    stream
}

fn response_id(response: &Response) -> String {
    response.id().expect("response ID")
}

async fn import_task(stream: &mut UnixStream) -> String {
    let response = send_recv(
        stream,
        b"<create_task><name>Report import</name><target id=\"0\"/></create_task>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    response_id(&response)
}

async fn report_count(stream: &mut UnixStream) -> usize {
    let response = send_recv(stream, b"<get_reports usage_type=\"scan\"/>").await;
    let xml = response.as_str().expect("UTF-8 response");
    xml.split("<report id=").count().saturating_sub(1)
}

#[tokio::test]
async fn import_owns_task_payload_results_and_host_asset_behavior() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    let task_id = import_task(&mut stream).await;

    let response = send_recv(
        &mut stream,
        format!(
            "<create_report><report id=\"export-envelope\"><report><name>Imported A</name><comment>opaque</comment><results><result><name>First</name><host>192.0.2.61</host><severity>8.1</severity></result><result><name>Second</name><host>192.0.2.62</host><severity>2.0</severity></result></results></report></report><task id=\"{task_id}\"/><in_assets>1</in_assets></create_report>"
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let report_id = response_id(&response);

    let detail = send_recv(
        &mut stream,
        format!(
            "<get_reports report_id=\"{report_id}\" usage_type=\"scan\" details=\"1\" filter=\"host=192.0.2.62 rows=1\"/>"
        ),
    )
    .await;
    let detail = detail.as_str().expect("UTF-8 detail");
    assert!(detail.contains("<name>Imported A</name>"));
    assert!(detail.contains(&format!("<task id=\"{task_id}\"")));
    assert!(detail.contains("<full>2</full><filtered>1</filtered>"));
    assert!(detail.contains("192.0.2.62"));
    assert!(!detail.contains("192.0.2.61</host>"));

    let assets = send_recv(&mut stream, b"<get_assets type=\"host\"/>").await;
    let assets = assets.as_str().expect("UTF-8 assets");
    assert!(assets.contains("192.0.2.61"));
    assert!(assets.contains("192.0.2.62"));

    let updated = send_recv(
        &mut stream,
        format!(
            "<create_report><report><name>Asset update</name><results><result><host>192.0.2.61</host></result></results></report><task id=\"{task_id}\"/><in_assets>1</in_assets></create_report>"
        ),
    )
    .await;
    assert_eq!(updated.status_code(), Some(201));
    let one_asset = send_recv(
        &mut stream,
        b"<get_assets type=\"host\" filter=\"name=192.0.2.61\"/>",
    )
    .await;
    assert!(one_asset
        .as_str()
        .expect("UTF-8 filtered assets")
        .contains("<asset_count>2<filtered>1</filtered>"));

    server.shutdown().await;
}

#[tokio::test]
async fn invalid_imports_and_asset_failures_roll_back_the_entire_graph() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    let task_id = import_task(&mut stream).await;
    let before = report_count(&mut stream).await;

    for request in [
        format!("<create_report><task id=\"{task_id}\"/></create_report>"),
        format!(
            "<create_report><report/><report/><task id=\"{task_id}\"/></create_report>"
        ),
        format!(
            "<create_report><report><name>Invalid host</name><results><result><host>secret.invalid</host></result></results></report><task id=\"{task_id}\"/><in_assets>1</in_assets></create_report>"
        ),
    ] {
        let response = send_recv(&mut stream, request).await;
        assert_eq!(response.status_code(), Some(400));
        assert_eq!(report_count(&mut stream).await, before);
    }

    let assets = send_recv(&mut stream, b"<get_assets type=\"host\"/>").await;
    assert!(!assets
        .as_str()
        .expect("UTF-8 assets")
        .contains("secret.invalid"));
    server.shutdown().await;
}

#[tokio::test]
async fn list_filters_pagination_details_counts_and_usage_are_independent() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    let task_id = import_task(&mut stream).await;

    for name in ["Alpha scan", "Beta scan"] {
        let response = send_recv(
            &mut stream,
            format!(
                "<create_report><report><name>{name}</name></report><task id=\"{task_id}\"/></create_report>"
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(201));
    }

    let page = send_recv(
        &mut stream,
        b"<get_reports usage_type=\"scan\" report_filter=\"sort=name first=2 rows=1\"/>",
    )
    .await;
    let page = page.as_str().expect("UTF-8 page");
    assert!(!page.contains("Alpha scan"));
    assert!(page.contains("Beta scan"));
    assert!(page.contains("<report_count>2<filtered>2</filtered></report_count>"));
    assert!(!page.contains("<results"));

    let unpaged = send_recv(
        &mut stream,
        b"<get_reports usage_type=\"scan\" report_filter=\"rows=1\" ignore_pagination=\"1\" details=\"1\"/>",
    )
    .await;
    let unpaged = unpaged.as_str().expect("UTF-8 unpaged response");
    assert!(unpaged.contains("Alpha scan"));
    assert!(unpaged.contains("Beta scan"));
    assert!(unpaged.contains("<results"));

    let audit = send_recv(&mut stream, b"<get_reports usage_type=\"audit\"/>").await;
    let audit = audit.as_str().expect("UTF-8 audit response");
    assert!(audit.contains("Seeded audit report"));
    assert!(!audit.contains("Alpha scan"));
    server.shutdown().await;
}

#[tokio::test]
async fn report_deletion_is_permanent_and_keeps_active_dependencies_atomic() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect(&server).await;

    let target = send_recv(
        &mut stream,
        b"<create_target><name>Lifecycle target</name><hosts>192.0.2.1</hosts><port_range>T:1-2</port_range></create_target>",
    )
    .await;
    let target_id = response_id(&target);
    let task = send_recv(
        &mut stream,
        format!(
            "<create_task><name>Lifecycle task</name><target id=\"{target_id}\"/></create_task>"
        ),
    )
    .await;
    let task_id = response_id(&task);
    let started = send_recv(&mut stream, format!("<start_task task_id=\"{task_id}\"/>")).await;
    let report_id = started.child_text("report_id").expect("started report ID");

    let in_use = send_recv(
        &mut stream,
        format!("<delete_report report_id=\"{report_id}\"/>"),
    )
    .await;
    assert_eq!(in_use.status_code(), Some(409));
    let still_present = send_recv(
        &mut stream,
        format!("<get_reports report_id=\"{report_id}\"/>"),
    )
    .await;
    assert_eq!(still_present.status_code(), Some(200));

    assert_eq!(
        send_recv(&mut stream, format!("<stop_task task_id=\"{task_id}\"/>"))
            .await
            .status_code(),
        Some(200)
    );
    assert_eq!(
        send_recv(
            &mut stream,
            format!("<delete_report report_id=\"{report_id}\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert_eq!(
        send_recv(
            &mut stream,
            format!("<get_reports report_id=\"{report_id}\"/>")
        )
        .await
        .status_code(),
        Some(404)
    );

    let audit_id = "10000000-0000-4000-8000-000000000661";
    assert_eq!(
        send_recv(
            &mut stream,
            format!("<delete_report report_id=\"{audit_id}\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    let audit_list = send_recv(&mut stream, b"<get_reports usage_type=\"audit\"/>").await;
    assert!(!audit_list
        .as_str()
        .expect("UTF-8 audit list")
        .contains(audit_id));

    server.shutdown().await;
}
