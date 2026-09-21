// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Stateful conformance coverage for specialized tasks and audit lifecycles.

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::unwrap_used, missing_docs)]

use std::sync::{Arc, Mutex};

use gvm_mock_server::{GmpVersion, MockGmpServer, ResourceStore, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const MASTER: &str = "08b69003-5fc2-4037-a479-93b440211c73";
const CONTAINER_SCANNER: &str = "00000000-0000-4000-8000-000000000010";
const WEB_SCANNER: &str = "00000000-0000-4000-8000-000000000011";

async fn send(stream: &mut UnixStream, xml: impl AsRef<[u8]>) -> Response {
    stream.write_all(xml.as_ref()).await.expect("write request");
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let mut bytes = vec![0_u8; 128 * 1024];
    let read = stream.read(&mut bytes).await.expect("read response");
    bytes.truncate(read);
    Response::new(bytes)
}

async fn server() -> (MockGmpServer, ResourceStore) {
    let slot = Arc::new(Mutex::new(None));
    let seed_slot = Arc::clone(&slot);
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "secret")
        .seed(move |store| {
            *seed_slot.lock().expect("store slot") = Some(store.clone());
        })
        .unix_socket_auto()
        .build()
        .await
        .expect("stateful server starts");
    let store = slot
        .lock()
        .expect("store slot")
        .clone()
        .expect("seed closure ran");
    (server, store)
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect");
    let response = send(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>secret</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    stream
}

async fn create(stream: &mut UnixStream, xml: String) -> String {
    let response = send(stream, xml).await;
    assert_eq!(response.status_code(), Some(201), "{response:?}");
    response.id().expect("created id")
}

#[tokio::test]
async fn every_specialized_creation_shape_validates_relationships_atomically() {
    let (server, store) = server().await;
    let mut stream = connect(&server).await;

    let agent_group = create(
        &mut stream,
        "<create_agent_group><name>Agents</name></create_agent_group>".into(),
    )
    .await;
    let oci_target = create(
        &mut stream,
        "<create_oci_image_target><name>OCI</name></create_oci_image_target>".into(),
    )
    .await;
    let web_target = create(
        &mut stream,
        "<create_web_application_target><name>Web</name></create_web_application_target>".into(),
    )
    .await;

    let import = create(
        &mut stream,
        "<create_task><name>Import</name><target id=\"0\"/><comment>reports</comment></create_task>"
            .into(),
    )
    .await;
    let container = create(
        &mut stream,
        "<create_task><name>Container</name><target id=\"0\"/></create_task>".into(),
    )
    .await;
    let agent = create(
        &mut stream,
        format!(
            "<create_task><name>Agent task</name><usage_type>scan</usage_type><agent_group id=\"{agent_group}\"/></create_task>"
        ),
    )
    .await;
    let oci = create(
        &mut stream,
        format!(
            "<create_task><name>OCI task</name><usage_type>scan</usage_type><oci_image_target id=\"{oci_target}\"/><scanner id=\"{CONTAINER_SCANNER}\"/></create_task>"
        ),
    )
    .await;
    let container_image = create(
        &mut stream,
        format!(
            "<create_task><name>Container image alias</name><usage_type>scan</usage_type><oci_image_target id=\"{oci_target}\"/><scanner id=\"{CONTAINER_SCANNER}\"/></create_task>"
        ),
    )
    .await;
    let web = create(
        &mut stream,
        format!(
            "<create_task><name>Web task</name><usage_type>scan</usage_type><web_application_target id=\"{web_target}\"/><scanner id=\"{WEB_SCANNER}\"/><preferences><preference><scanner_name>scan_mode</scanner_name><value>safe</value></preference></preferences></create_task>"
        ),
    )
    .await;

    for id in [&import, &container, &agent, &oci, &container_image, &web] {
        let task = store
            .get(&Uuid::parse_str(id).expect("task UUID"))
            .expect("created task stored");
        assert_eq!(task.attr("usage_type"), Some("scan"));
    }
    assert_eq!(
        store
            .get(&Uuid::parse_str(&agent).unwrap())
            .unwrap()
            .attr("scanner_id"),
        Some(MASTER)
    );

    let before = store.count("task");
    for invalid in [
        format!(
            "<create_task><name>Wrong OCI scanner</name><oci_image_target id=\"{oci_target}\"/><scanner id=\"{MASTER}\"/></create_task>"
        ),
        format!(
            "<create_task><name>Wrong agent scanner</name><agent_group id=\"{agent_group}\"/><scanner id=\"{CONTAINER_SCANNER}\"/></create_task>"
        ),
        format!(
            "<create_task><name>Forbidden asset preference</name><web_application_target id=\"{web_target}\"/><scanner id=\"{WEB_SCANNER}\"/><preferences><preference><scanner_name>in_assets</scanner_name><value>yes</value></preference></preferences></create_task>"
        ),
    ] {
        assert_eq!(send(&mut stream, invalid).await.status_code(), Some(400));
        assert_eq!(store.count("task"), before, "failed creation must roll back");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn move_task_requires_and_applies_a_typed_destination_atomically() {
    let (server, store) = server().await;
    let mut stream = connect(&server).await;
    let target = create(
        &mut stream,
        "<create_target><name>Move target</name><hosts>127.0.0.1</hosts><port_range>T:22</port_range></create_target>".into(),
    )
    .await;
    let slave = create(
        &mut stream,
        "<create_scanner><name>Slave</name><host>127.0.0.2</host><port>9390</port><type>2</type></create_scanner>".into(),
    )
    .await;
    let task = create(
        &mut stream,
        format!("<create_task><name>Movable</name><target id=\"{target}\"/></create_task>"),
    )
    .await;
    let task_uuid = Uuid::parse_str(&task).unwrap();

    assert_eq!(
        send(
            &mut stream,
            format!("<move_task task_id=\"{task}\" slave_id=\"{slave}\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert_eq!(
        store.get(&task_uuid).unwrap().attr("scanner_id"),
        Some(slave.as_str())
    );

    assert_eq!(
        send(&mut stream, format!("<move_task task_id=\"{task}\"/>"))
            .await
            .status_code(),
        Some(400)
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<move_task task_id=\"{task}\" slave_id=\"{CONTAINER_SCANNER}\"/>")
        )
        .await
        .status_code(),
        Some(400)
    );
    assert_eq!(
        store.get(&task_uuid).unwrap().attr("scanner_id"),
        Some(slave.as_str())
    );

    assert_eq!(
        send(
            &mut stream,
            format!("<move_task task_id=\"{task}\" slave_id=\"\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert_eq!(
        store.get(&task_uuid).unwrap().attr("scanner_id"),
        Some(MASTER)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn audit_identity_and_lifecycle_survive_clone_modify_actions_and_delete() {
    let (server, store) = server().await;
    let mut stream = connect(&server).await;
    let target = create(
        &mut stream,
        "<create_target><name>Audit target</name><hosts>127.0.0.1</hosts><port_range>T:22</port_range></create_target>".into(),
    )
    .await;
    let group = create(
        &mut stream,
        "<create_group><name>Auditors</name><users>alice</users></create_group>".into(),
    )
    .await;
    let audit = create(
        &mut stream,
        format!(
            "<create_task><name>Audit</name><usage_type>audit</usage_type><config id=\"00000000-0000-0000-0000-000000000301\"/><target id=\"{target}\"/><scanner id=\"{MASTER}\"/><observers>alice<group id=\"{group}\"/></observers></create_task>"
        ),
    )
    .await;
    let audit_uuid = Uuid::parse_str(&audit).unwrap();

    let listed = send(&mut stream, b"<get_tasks usage_type=\"audit\"/>").await;
    assert_eq!(listed.status_code(), Some(200));
    assert!(listed
        .as_str()
        .unwrap()
        .contains(&format!("task id=\"{audit}\"")));
    let detail = send(
        &mut stream,
        format!("<get_tasks task_id=\"{audit}\" details=\"1\" usage_type=\"audit\"/>"),
    )
    .await;
    assert_eq!(detail.status_code(), Some(200));

    let clone = create(
        &mut stream,
        format!("<create_task><copy>{audit}</copy><comment>cloned</comment></create_task>"),
    )
    .await;
    assert_eq!(
        store
            .get(&Uuid::parse_str(&clone).unwrap())
            .unwrap()
            .attr("usage_type"),
        Some("audit")
    );

    let invalid = send(
        &mut stream,
        format!(
            "<modify_task task_id=\"{audit}\"><name>must not stick</name><observers>bob<group id=\"00000000-0000-4000-8000-00000000dead\"/></observers></modify_task>"
        ),
    )
    .await;
    assert_eq!(invalid.status_code(), Some(404));
    assert_eq!(store.get(&audit_uuid).unwrap().name, "Audit");

    let modified = send(
        &mut stream,
        format!(
            "<modify_task task_id=\"{audit}\"><name>Updated audit</name><comment>final</comment><usage_type>scan</usage_type><observers>bob<group id=\"{group}\"/></observers></modify_task>"
        ),
    )
    .await;
    assert_eq!(modified.status_code(), Some(200));
    let stored = store.get(&audit_uuid).unwrap();
    assert_eq!(stored.name, "Updated audit");
    assert_eq!(stored.attr("usage_type"), Some("audit"));

    let started = send(&mut stream, format!("<start_task task_id=\"{audit}\"/>")).await;
    assert_eq!(started.status_code(), Some(202));
    assert_eq!(
        send(&mut stream, format!("<stop_task task_id=\"{audit}\"/>"))
            .await
            .status_code(),
        Some(200)
    );
    assert_eq!(
        send(&mut stream, format!("<resume_task task_id=\"{audit}\"/>"))
            .await
            .status_code(),
        Some(202)
    );

    assert_eq!(
        send(
            &mut stream,
            format!("<delete_task task_id=\"{clone}\" ultimate=\"0\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert!(store.get(&Uuid::parse_str(&clone).unwrap()).is_none());
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_task task_id=\"{audit}\" ultimate=\"1\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert!(store.get(&audit_uuid).is_none());

    server.shutdown().await;
}
