// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::too_many_lines, clippy::unwrap_used, missing_docs)]

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const DEFAULT_CONFIG: &str = "daba56c8-73ec-11df-a475-002264764cea";
const SECOND_SCAN: &str = "00000000-0000-0000-0000-000000000300";
const FIRST_POLICY: &str = "00000000-0000-0000-0000-000000000301";
const SECOND_POLICY: &str = "00000000-0000-0000-0000-000000000302";
const PREDEFINED: &str = "00000000-0000-0000-0000-000000000303";
const SAVED_FILTER: &str = "00000000-0000-0000-0000-000000000304";

async fn server_with_task_references() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(|store| {
            let mut visible =
                Resource::with_id("task", "Visible active reference", Uuid::from_u128(0x6491));
            visible.set_attr("config_id", SECOND_SCAN);
            visible.set_attr("config_location", "active");
            visible.set_attr("visible", "1");
            store.create(visible);

            let mut hidden =
                Resource::with_id("task", "Hidden active reference", Uuid::from_u128(0x6492));
            hidden.set_attr("config_id", SECOND_POLICY);
            hidden.set_attr("config_location", "active");
            hidden.set_attr("visible", "0");
            store.create(hidden);

            let mut trash =
                Resource::with_id("task", "Trash-location reference", Uuid::from_u128(0x6493));
            trash.set_attr("config_id", FIRST_POLICY);
            trash.set_attr("config_location", "trash");
            trash.set_attr("visible", "0");
            store.create(trash);
        })
        .unix_socket_auto()
        .build()
        .await
        .expect("stateful server starts")
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    UnixStream::connect(server.socket_path().unwrap())
        .await
        .expect("connect")
}

async fn send(stream: &mut UnixStream, xml: impl AsRef<[u8]>) -> Response {
    stream.write_all(xml.as_ref()).await.expect("write request");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut bytes = vec![0; 256 * 1024];
    let read = stream.read(&mut bytes).await.expect("read response");
    bytes.truncate(read);
    Response::new(bytes)
}

async fn authenticate(stream: &mut UnixStream) {
    let response = send(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

fn response_id(response: &Response) -> String {
    response.id().expect("creation response ID").to_string()
}

#[tokio::test]
async fn copy_and_import_follow_source_branching_and_deep_state_rules() {
    let server = server_with_task_references().await;
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    assert_eq!(
        send(
            &mut stream,
            b"<create_config><name>No base</name></create_config>"
        )
        .await
        .status_code(),
        Some(400)
    );
    assert_eq!(
        send(
            &mut stream,
            b"<create_config><scanner id=\"scanner-1\"/><name>OSP</name></create_config>"
        )
        .await
        .status_code(),
        Some(400)
    );

    let copy = send(
        &mut stream,
        format!("<create_config><copy>{DEFAULT_CONFIG}</copy></create_config>"),
    )
    .await;
    assert_eq!(copy.status_code(), Some(201));
    let copy_id = response_id(&copy);
    let copied = send(
        &mut stream,
        format!("<get_configs config_id=\"{copy_id}\" details=\"1\" preferences=\"1\"/>"),
    )
    .await;
    let copied = copied.as_str().unwrap();
    assert!(copied.contains("<name>Full and fast Clone 1</name>"));
    assert!(copied.contains("1.3.6.1.4.1.25623.1"));
    assert!(copied.contains("configuration-secret"));
    assert!(copied.contains("<predefined>0</predefined>"));

    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{DEFAULT_CONFIG}\" ultimate=\"1\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<get_configs config_id=\"{copy_id}\" details=\"1\"/>")
        )
        .await
        .status_code(),
        Some(200),
        "the copy must not alias its deleted source"
    );

    let policy_copy = send(
        &mut stream,
        format!("<create_config><copy>{FIRST_POLICY}</copy></create_config>"),
    )
    .await;
    assert_eq!(policy_copy.status_code(), Some(201));
    let policy_copy = send(
        &mut stream,
        format!(
            "<get_configs config_id=\"{}\" preferences=\"1\"/>",
            response_id(&policy_copy)
        ),
    )
    .await;
    assert!(policy_copy
        .as_str()
        .unwrap()
        .contains("<id>0</id><name>table_driven_lsc</name><type>entry</type><value>1</value>"));

    let import = concat!(
        "<create_config><copy>missing-source</copy><get_configs_response>",
        "<config><name>Import wins</name><usage_type>scan</usage_type>",
        "<nvt_selectors><all_selector/></nvt_selectors><preferences>",
        "<preference><nvt oid=\"1.3.6.1.4.1.25623.1\"/><id>2</id>",
        "<value>before<![CDATA[<&secret>]]>after</value></preference>",
        "</preferences></config><config><name>Ignored second</name>",
        "<nvt_selectors/><preferences/></config></get_configs_response>",
        "<usage_type>policy</usage_type></create_config>"
    );
    let imported = send(&mut stream, import).await;
    assert_eq!(imported.status_code(), Some(201));
    let imported_id = response_id(&imported);
    let observed = send(
        &mut stream,
        format!("<get_configs config_id=\"{imported_id}\" details=\"1\"/>"),
    )
    .await;
    let observed = observed.as_str().unwrap();
    assert!(observed.contains("<name>Import wins</name>"));
    assert!(!observed.contains("Ignored second"));
    assert!(observed.contains("<usage_type>policy</usage_type>"));
    assert!(observed.contains("before&lt;&amp;secret&gt;after"));
    assert!(observed
        .contains("<id>0</id><name>table_driven_lsc</name><type>entry</type><value>0</value>"));
    assert!(observed.contains("<nvt_count>2<growing>0</growing></nvt_count>"));

    let duplicate_import = send(&mut stream, import).await;
    assert_eq!(duplicate_import.status_code(), Some(201));
    let duplicate_import = send(
        &mut stream,
        format!(
            "<get_configs config_id=\"{}\"/>",
            response_id(&duplicate_import)
        ),
    )
    .await;
    assert!(duplicate_import
        .as_str()
        .unwrap()
        .contains("<name>Import wins 1</name>"));

    let ordered = concat!(
        "<create_config><get_configs_response><config><name>Ordered selectors</name>",
        "<nvt_selectors>",
        "<nvt_selector><include>1</include><family_or_nvt>General</family_or_nvt></nvt_selector>",
        "<nvt_selector><include>0</include><family_or_nvt>1.3.6.1.4.1.25623.1</family_or_nvt></nvt_selector>",
        "<nvt_selector><include>1</include><family_or_nvt>1.3.6.1.4.1.25623.2</family_or_nvt></nvt_selector>",
        "</nvt_selectors><preferences/></config></get_configs_response></create_config>"
    );
    let ordered = send(&mut stream, ordered).await;
    assert_eq!(ordered.status_code(), Some(201));
    let ordered = send(
        &mut stream,
        format!(
            "<get_configs config_id=\"{}\" details=\"1\"/>",
            response_id(&ordered)
        ),
    )
    .await;
    let ordered = ordered.as_str().unwrap();
    assert!(ordered.contains("<nvt_count>1<growing>0</growing></nvt_count>"));
    assert!(ordered.contains("<family_or_nvt>1.3.6.1.4.1.25623.2</family_or_nvt>"));
    assert!(!ordered.contains("<family_or_nvt>1.3.6.1.4.1.25623.1</family_or_nvt>"));

    for invalid in [
        "<create_config><get_configs_response><config><name>Missing selectors</name><preferences/></config></get_configs_response></create_config>",
        "<create_config><get_configs_response><config><nvt_selectors/><preferences/></config></get_configs_response></create_config>",
        "<create_config><get_configs_response><config><name>Unknown selector</name><nvt_selectors><nvt_selector><include>1</include><family_or_nvt>Unknown family</family_or_nvt></nvt_selector></nvt_selectors><preferences/></config></get_configs_response></create_config>",
        "<create_config><get_configs_response><config><name>Missing preference ID</name><nvt_selectors/><preferences><preference><nvt oid=\"1.3.6.1.4.1.25623.1\"/><value>x</value></preference></preferences></config></get_configs_response></create_config>",
        "<create_config><get_configs_response><config><name>Unknown preference</name><nvt_selectors/><preferences><preference><nvt oid=\"1.3.6.1.4.1.25623.999\"/><id>1</id><value>x</value></preference></preferences></config></get_configs_response></create_config>",
    ] {
        assert_eq!(send(&mut stream, invalid).await.status_code(), Some(400));
    }

    server.shutdown().await;
}

#[tokio::test]
async fn list_detail_expansion_filtering_and_counts_are_bounded_and_deterministic() {
    let server = server_with_task_references().await;
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let filtered = send(
        &mut stream,
        format!("<get_configs filt_id=\"{SAVED_FILTER}\"/>"),
    )
    .await;
    let filtered = filtered.as_str().unwrap();
    assert!(filtered.contains("<config_count>5<filtered>2</filtered><page>1</page>"));

    let paged = send(
        &mut stream,
        b"<get_configs filter=\"usage_type=scan sort-reverse=name first=99 rows=1\"/>",
    )
    .await;
    let paged = paged.as_str().unwrap();
    assert!(paged.contains("<config_count>5<filtered>3</filtered><page>1</page>"));

    let detail = send(
        &mut stream,
        format!(
            "<get_configs config_id=\"{SECOND_SCAN}\" filter=\"name=never first=2 rows=0\" usage_type=\"policy\" families=\"1\" preferences=\"1\" tasks=\"1\"/>"
        ),
    )
    .await;
    let detail = detail.as_str().unwrap();
    assert!(detail.contains("<name>Discovery scan</name>"));
    assert!(detail.contains("<families>"));
    assert!(detail.contains("<preferences>"));
    assert!(detail.contains("<tasks><task"));
    assert!(!detail.contains("<audits>"));
    assert_eq!(detail.matches("<task id=").count(), 1);

    let repeated_detail = send(
        &mut stream,
        format!(
            "<get_configs config_id=\"{SECOND_SCAN}\" filter=\"name=never first=2 rows=0\" usage_type=\"policy\" families=\"1\" preferences=\"1\" tasks=\"1\"/>"
        ),
    )
    .await;
    assert_eq!(repeated_detail.as_str().unwrap(), detail);

    assert_eq!(
        send(
            &mut stream,
            b"<get_configs config_id=\"00000000-0000-0000-0000-00000000ffff\"/>"
        )
        .await
        .status_code(),
        Some(404)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn metadata_is_atomic_and_deferred_actions_never_claim_false_success() {
    let server = server_with_task_references().await;
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    assert_eq!(
        send(
            &mut stream,
            format!("<modify_config config_id=\"{SECOND_SCAN}\"><name>Full and fast</name><comment>must roll back</comment></modify_config>")
        )
        .await
        .status_code(),
        Some(400)
    );
    let unchanged = send(
        &mut stream,
        format!("<get_configs config_id=\"{SECOND_SCAN}\"/>"),
    )
    .await;
    let unchanged = unchanged.as_str().unwrap();
    assert!(unchanged.contains("Second seeded scan configuration"));
    assert!(!unchanged.contains("must roll back"));

    assert_eq!(
        send(
            &mut stream,
            format!("<modify_config config_id=\"{SECOND_SCAN}\"><name></name><comment></comment><usage_type>policy</usage_type></modify_config>")
        )
        .await
        .status_code(),
        Some(200)
    );
    let no_op = send(
        &mut stream,
        format!("<get_configs config_id=\"{SECOND_SCAN}\"/>"),
    )
    .await;
    let no_op = no_op.as_str().unwrap();
    assert!(no_op.contains("<name>Discovery scan</name>"));
    assert!(no_op.contains("<usage_type>scan</usage_type>"));

    assert_eq!(
        send(
            &mut stream,
            format!("<modify_config config_id=\"{SECOND_SCAN}\"><name>  </name><comment> edited while in use </comment></modify_config>")
        )
        .await
        .status_code(),
        Some(200)
    );
    let edited = send(
        &mut stream,
        format!("<get_configs config_id=\"{SECOND_SCAN}\"/>"),
    )
    .await;
    let edited = edited.as_str().unwrap();
    assert!(edited.contains("<name>  </name>"));
    assert!(edited.contains("<comment> edited while in use </comment>"));

    assert_eq!(
        send(
            &mut stream,
            format!("<modify_config config_id=\"{PREDEFINED}\"/>")
        )
        .await
        .status_code(),
        Some(400)
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<modify_config config_id=\"{SECOND_SCAN}\"><name>discarded</name><preference><name>x</name></preference></modify_config>")
        )
        .await
        .status_code(),
        Some(400)
    );
    assert!(!send(
        &mut stream,
        format!("<get_configs config_id=\"{SECOND_SCAN}\"/>")
    )
    .await
    .as_str()
    .unwrap()
    .contains("discarded"));

    server.shutdown().await;
}

#[tokio::test]
async fn deletion_locations_trash_limits_and_sync_rejection_match_the_bounded_contract() {
    let server = server_with_task_references().await;
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{SECOND_SCAN}\"/>")
        )
        .await
        .status_code(),
        Some(400),
        "visible active tasks block trashing"
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{SECOND_POLICY}\"/>")
        )
        .await
        .status_code(),
        Some(200),
        "hidden active references move to the trash location"
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{SECOND_POLICY}\"/>")
        )
        .await
        .status_code(),
        Some(200),
        "repeated nonultimate deletion succeeds"
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{SECOND_POLICY}\" ultimate=\"1\"/>")
        )
        .await
        .status_code(),
        Some(400),
        "trash-location references block ultimate deletion"
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{FIRST_POLICY}\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{FIRST_POLICY}\" ultimate=\"1\"/>")
        )
        .await
        .status_code(),
        Some(400)
    );
    assert_eq!(
        send(
            &mut stream,
            b"<delete_config config_id=\"00000000-0000-0000-0000-00000000ffff\"/>"
        )
        .await
        .status_code(),
        Some(404)
    );
    assert_eq!(
        send(&mut stream, b"<get_configs trash=\"1\" details=\"1\"/>")
            .await
            .status_code(),
        Some(400)
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{PREDEFINED}\"/>")
        )
        .await
        .status_code(),
        Some(200),
        "predefined modification protection must not become a deletion ban"
    );
    assert_eq!(
        send(
            &mut stream,
            format!("<delete_config config_id=\"{PREDEFINED}\" ultimate=\"1\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );

    let sync = send(&mut stream, b"<sync_config/>").await;
    assert_eq!(
        sync.as_str().unwrap(),
        r#"<gmp_response status="400" status_text="Bogus command name"/>"#
    );
    server.shutdown().await;

    let fixture = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_8)
        .unix_socket_auto()
        .build()
        .await
        .expect("fixture server starts");
    let mut stream = connect(&fixture).await;
    assert_eq!(
        send(&mut stream, b"<sync_config/>").await.as_str().unwrap(),
        r#"<gmp_response status="400" status_text="Bogus command name"/>"#
    );
    fixture.shutdown().await;
}
