// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Focused stateful task lifecycle coverage.

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
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

async fn auth_admin(stream: &mut UnixStream) {
    let resp = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(resp.status_code(), Some(200), "admin auth should succeed");
}

async fn create_and_get_id(
    stream: &mut UnixStream,
    create_xml: &[u8],
    create_cmd_name: &str,
) -> String {
    let resp = send_recv(stream, create_xml).await;
    assert_eq!(
        resp.status_code(),
        Some(201),
        "{create_cmd_name} should return 201"
    );

    let text = resp.as_str().expect("create response should be valid utf8");
    let marker = "id=\"";
    let start = text
        .find(marker)
        .expect("response should contain id attribute")
        + marker.len();
    let rest = &text[start..];
    let end = rest.find('"').expect("id attribute should be terminated");
    rest[..end].to_string()
}

async fn create_task_id(stream: &mut UnixStream, name: &str) -> String {
    let target_id = create_and_get_id(
        stream,
        format!(
            "<create_target><name>{name} Target</name><hosts>127.0.0.1</hosts><port_range>T:1-65535</port_range></create_target>"
        )
        .as_bytes(),
        "create_target",
    )
    .await;
    create_and_get_id(
        stream,
        format!("<create_task><name>{name}</name><target id=\"{target_id}\"/></create_task>")
            .as_bytes(),
        "create_task",
    )
    .await
}

async fn stateful_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
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

fn extract_report_id(text: &str) -> &str {
    let start_marker = "<report_id>";
    let end_marker = "</report_id>";
    let start = text
        .find(start_marker)
        .expect("response should contain <report_id>")
        + start_marker.len();
    let rest = &text[start..];
    let end = rest
        .find(end_marker)
        .expect("report_id should be terminated");
    &rest[..end]
}

#[tokio::test]
async fn task_start_new_task() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Lifecycle Start").await;

    let start_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start_resp.status_code(), Some(202));
    let start_text = start_resp.as_str().expect("valid utf8");
    assert!(start_text.contains("<report_id>"));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    assert!(
        get_resp.as_str().expect("valid utf8").contains("Running"),
        "task should be Running after start_task"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn task_stop_running_task() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Lifecycle Stop").await;

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let stop_resp = send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(stop_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    assert!(
        get_resp.as_str().expect("valid utf8").contains("Stopped"),
        "task should be Stopped after stop_task"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn task_resume_stopped_task() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Lifecycle Resume").await;

    let start_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let started_report_id = extract_report_id(start_resp.as_str().expect("valid utf8")).to_string();
    send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let stopped_report = send_recv(
        &mut stream,
        format!("<get_reports report_id=\"{started_report_id}\"/>").as_bytes(),
    )
    .await;
    assert!(stopped_report
        .as_str()
        .expect("valid utf8")
        .contains("<status>Stopped</status>"));

    let resume_resp = send_recv(
        &mut stream,
        format!("<resume_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resume_resp.status_code(), Some(202));
    assert_eq!(
        extract_report_id(resume_resp.as_str().expect("valid utf8")),
        started_report_id,
        "resume_task should continue the stopped report"
    );

    let reports = send_recv(&mut stream, b"<get_reports/>").await;
    assert!(reports
        .as_str()
        .expect("valid utf8")
        .contains("<report_count>1"));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    assert!(
        get_resp.as_str().expect("valid utf8").contains("Running"),
        "task should be Running after resume_task"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn task_start_already_running_returns_409() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Lifecycle Start Conflict").await;

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let start_again_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start_again_resp.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn task_stop_already_stopped_returns_409() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Lifecycle Stop Conflict").await;

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let stop_again_resp = send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(stop_again_resp.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn task_resume_non_stopped_returns_409() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Lifecycle Resume Conflict").await;

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;

    let resume_resp = send_recv(
        &mut stream,
        format!("<resume_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resume_resp.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn task_get_shows_current_status() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Status Progression").await;

    let new_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(new_resp.status_code(), Some(200));
    assert!(new_resp.as_str().expect("valid utf8").contains("New"));

    send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let running_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(running_resp.status_code(), Some(200));
    assert!(running_resp
        .as_str()
        .expect("valid utf8")
        .contains("Running"));

    send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let stopped_resp = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(stopped_resp.status_code(), Some(200));
    assert!(stopped_resp
        .as_str()
        .expect("valid utf8")
        .contains("Stopped"));

    server.shutdown().await;
}

#[tokio::test]
async fn task_start_returns_report_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let task_id = create_task_id(&mut stream, "Report Id").await;

    let start_resp = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start_resp.status_code(), Some(202));

    let start_text = start_resp.as_str().expect("valid utf8");
    let report_id = extract_report_id(start_text);
    assert_eq!(report_id.len(), 36, "report_id should be a UUID string");
    assert_eq!(
        report_id.chars().filter(|&ch| ch == '-').count(),
        4,
        "report_id should contain UUID hyphens"
    );

    println!("TASK_LIFECYCLE_DONE");

    server.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn task_create_clone_modify_and_failed_updates_are_atomic() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let target_id = create_and_get_id(
        &mut stream,
        b"<create_target><name>Canonical Target</name><hosts>127.0.0.1</hosts><port_range>T:1-65535</port_range></create_target>",
        "create_target",
    )
    .await;
    let alert_id = create_and_get_id(
        &mut stream,
        b"<create_alert><name>Canonical Alert</name></create_alert>",
        "create_alert",
    )
    .await;
    let group_id = create_and_get_id(
        &mut stream,
        b"<create_group><name>Canonical Group</name><users>alice</users></create_group>",
        "create_group",
    )
    .await;
    let task_id = create_and_get_id(
        &mut stream,
        format!(
            "<create_task><name>Canonical Task</name><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><target id=\"{target_id}\"/><scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/><alterable>1</alterable><alert id=\"{alert_id}\"/><observers>alice<group id=\"{group_id}\"/></observers><preferences><preference><scanner_name>auto_delete</scanner_name><value>keep</value></preference><preference><scanner_name>auto_delete_data</scanner_name><value>5</value></preference></preferences></create_task>"
        )
        .as_bytes(),
        "create_task",
    )
    .await;

    let created = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    let created = created.as_str().expect("UTF-8 task response");
    assert!(created.contains("<alterable>1</alterable>"));
    assert!(created.contains(&format!("<alert id=\"{alert_id}\">")));
    assert!(created.contains(&format!("<group id=\"{group_id}\">")));
    assert!(created.contains("<scanner_name>auto_delete</scanner_name><value>keep</value>"));

    let clone_id = create_and_get_id(
        &mut stream,
        format!(
            "<create_task><comment>clone override</comment><copy>{task_id}</copy><alterable>0</alterable></create_task>"
        )
        .as_bytes(),
        "create_task",
    )
    .await;
    let cloned = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{clone_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    let cloned = cloned.as_str().expect("UTF-8 cloned task response");
    assert!(cloned.contains("<comment>clone override</comment>"));
    assert!(cloned.contains("<alterable>0</alterable>"));
    assert!(cloned.contains(&format!("<alert id=\"{alert_id}\">")));
    assert!(cloned.contains("<scanner_name>auto_delete_data</scanner_name><value>5</value>"));
    assert!(cloned.contains("<status>New</status>"));

    let invalid_preference = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><name>Must Roll Back</name><preferences><preference><scanner_name>auto_delete_data</scanner_name><value>1</value></preference></preferences></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(invalid_preference.status_code(), Some(400));

    let missing_alert = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><comment>also rollback</comment><alert id=\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"/></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(missing_alert.status_code(), Some(404));

    let after_failures = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    let after_failures = after_failures.as_str().expect("UTF-8 task response");
    assert!(after_failures.contains("<name>Canonical Task</name>"));
    assert!(!after_failures.contains("Must Roll Back"));
    assert!(!after_failures.contains("also rollback"));
    assert!(after_failures.contains(&format!("<alert id=\"{alert_id}\">")));
    assert!(
        after_failures.contains("<scanner_name>auto_delete_data</scanner_name><value>5</value>")
    );

    let clear = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><alert id=\"0\"/><observers><group id=\"0\"/></observers><preferences><preference><scanner_name>auto_delete</scanner_name><value>no</value></preference></preferences></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(clear.status_code(), Some(200));
    let cleared = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    let cleared = cleared.as_str().expect("UTF-8 task response");
    assert!(!cleared.contains("<alert id="));
    assert!(!cleared.contains("<group id="));
    assert!(cleared.contains("<observers></observers>"));
    assert!(cleared.contains("<scanner_name>auto_delete</scanner_name><value>no</value>"));

    server.shutdown().await;
}
