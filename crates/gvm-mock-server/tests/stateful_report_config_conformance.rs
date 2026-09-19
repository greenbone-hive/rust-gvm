// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::authentication::authenticate;
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const FORMAT: &str = "00000000-0000-0000-0000-000000000200";
const NONCONFIGURABLE_FORMAT: &str = "00000000-0000-0000-0000-000000000201";
const SAVED_FILTER: &str = "00000000-0000-0000-0000-000000000202";

async fn server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_6)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().unwrap())
        .await
        .unwrap();
    let response = exchange(&mut stream, &authenticate("admin", "admin").to_bytes()).await;
    assert_eq!(response.status_code(), Some(200));
    stream
}

async fn exchange(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.unwrap();
    let mut bytes = vec![0; 128 * 1024];
    let size = stream.read(&mut bytes).await.unwrap();
    bytes.truncate(size);
    Response::new(bytes)
}

async fn send(stream: &mut UnixStream, xml: &str) -> Response {
    exchange(stream, xml.as_bytes()).await
}

fn body(response: &Response) -> &str {
    response.as_str().expect("UTF-8 response")
}

fn created_id(response: &Response) -> String {
    assert_eq!(response.status_code(), Some(201), "{}", body(response));
    response.id().expect("created ID")
}

fn direct_create(name: &str, comment: &str, params: &str) -> String {
    format!(
        "<create_report_config><name>{name}</name><report_format id=\"{FORMAT}\"/>\
         <comment>{comment}</comment>{params}</create_report_config>"
    )
}

#[tokio::test]
async fn direct_create_validates_dependencies_and_is_atomic() {
    let Some(server) = server().await else { return };
    let mut stream = connect(&server).await;

    let before = send(&mut stream, "<get_report_configs/>").await;
    assert!(body(&before).contains("<report_config_count>0"));

    for xml in [
        "<create_report_config><name>legacy</name><report_format_id>00000000-0000-0000-0000-000000000200</report_format_id></create_report_config>",
        "<create_report_config><get_report_configs_response><report_config><name>nested</name></report_config></get_report_configs_response></create_report_config>",
        "<create_report_config><name>missing</name><report_format id=\"00000000-0000-0000-0000-000000000999\"/></create_report_config>",
        &format!("<create_report_config><name>fixed</name><report_format id=\"{NONCONFIGURABLE_FORMAT}\"/></create_report_config>"),
        &direct_create("unknown", "", "<param><name>Unknown</name><value>x</value></param>"),
        &direct_create("invalid", "", "<param><name>Graph Type</name><value>pie</value></param>"),
    ] {
        let response = send(&mut stream, xml).await;
        assert!(matches!(response.status_code(), Some(400 | 404)), "{}", body(&response));
    }

    let create = send(
        &mut stream,
        &direct_create(
            "Config",
            "comment",
            "<param><name>Label</name><value>first</value></param>\
             <param><name>Label</name><value>second</value></param>\
             <param><name>Label</name><value use_default=\"1\"></value></param>\
             <param><name>Graph Type</name><value use_default=\"1\"></value></param>",
        ),
    )
    .await;
    let id = created_id(&create);

    let duplicate = send(&mut stream, &direct_create("Config", "other", "")).await;
    assert_eq!(duplicate.status_code(), Some(400));
    let list = send(&mut stream, "<get_report_configs details=\"0\"/>").await;
    assert!(body(&list).contains(&format!("<report_config id=\"{id}\"")));
    assert!(body(&list).contains("<value using_default=\"0\">second</value>"));
    assert!(body(&list).contains("<value using_default=\"1\">bar</value>"));
    assert!(body(&list).contains("<report_configs start=\"1\" max=\"1\"/>"));
    assert!(body(&list).contains("<report_config_count>1<filtered>1</filtered><page>1</page>"));

    server.shutdown().await;
}

#[tokio::test]
async fn modify_preserves_clears_resets_and_rolls_back_failures() {
    let Some(server) = server().await else { return };
    let mut stream = connect(&server).await;
    let create = send(
        &mut stream,
        &direct_create(
            "Original",
            "kept",
            "<param><name>Label</name><value>one</value></param><param><name>Graph Type</name><value>line</value></param>",
        ),
    )
    .await;
    let id = created_id(&create);

    let modify = send(
        &mut stream,
        &format!(
            "<modify_report_config report_config_id=\"{id}\"><comment></comment>\
             <param><name>Label</name><value>two</value></param>\
             <param><name>Label</name><value>three</value></param>\
             <param><name>Label</name><value use_default=\"1\"></value></param></modify_report_config>"
        ),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));
    let get = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{id}\"/>"),
    )
    .await;
    assert!(body(&get).contains("<name>Original</name><comment></comment>"));
    assert!(body(&get).contains("<value using_default=\"1\">Default label</value>"));
    assert!(body(&get).contains("<value using_default=\"0\">line</value>"));

    let empty_value = send(
        &mut stream,
        &format!(
            "<modify_report_config report_config_id=\"{id}\"><param><name>Label</name><value></value></param></modify_report_config>"
        ),
    )
    .await;
    assert_eq!(empty_value.status_code(), Some(200));
    let empty_observed = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{id}\"/>"),
    )
    .await;
    assert!(body(&empty_observed).contains("<value using_default=\"0\"></value>"));

    let padded_value = send(
        &mut stream,
        &format!(
            "<modify_report_config report_config_id=\"{id}\"><param><name>Label</name><value>  padded  </value></param></modify_report_config>"
        ),
    )
    .await;
    assert_eq!(padded_value.status_code(), Some(200));
    let padded_observed = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{id}\"/>"),
    )
    .await;
    assert!(body(&padded_observed).contains("<value using_default=\"0\">  padded  </value>"));

    let invalid = send(
        &mut stream,
        &format!(
            "<modify_report_config report_config_id=\"{id}\"><name>Rolled back</name><comment>bad</comment>\
             <param><name>Label</name><value>valid</value></param>\
             <param><name>Graph Type</name><value>invalid</value></param></modify_report_config>"
        ),
    )
    .await;
    assert_eq!(invalid.status_code(), Some(400));
    let unchanged = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{id}\" details=\"1\"/>"),
    )
    .await;
    assert!(body(&unchanged).contains("<name>Original</name><comment></comment>"));
    assert!(!body(&unchanged).contains("Rolled back"));
    assert_eq!(
        send(
            &mut stream,
            &format!("<modify_report_config report_config_id=\"{id}\"><name></name></modify_report_config>"),
        )
        .await
        .status_code(),
        Some(400)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn clone_naming_ignored_extras_and_orphan_quirk_match_the_pinned_source() {
    let Some(server) = server().await else { return };
    let mut stream = connect(&server).await;
    let source = created_id(
        &send(
            &mut stream,
            &direct_create(
                "Source",
                "copied",
                "<param><name>Label</name><value>source</value></param>",
            ),
        )
        .await,
    );
    let clone_one = created_id(
        &send(
            &mut stream,
            &format!("<create_report_config><copy>{source}</copy></create_report_config>"),
        )
        .await,
    );
    let clone_two = created_id(
        &send(
            &mut stream,
            &format!(
                "<create_report_config><copy>{source}</copy><name></name></create_report_config>"
            ),
        )
        .await,
    );
    let exact = created_id(
        &send(
            &mut stream,
            &format!(
                "<create_report_config><copy>{source}</copy><name>Exact</name><comment>ignored</comment>\
                 <report_format id=\"{NONCONFIGURABLE_FORMAT}\"/><param><name>Label</name><value>ignored</value></param></create_report_config>"
            ),
        )
        .await,
    );
    let collision = send(
        &mut stream,
        &format!(
            "<create_report_config><copy>{source}</copy><name>Exact</name></create_report_config>"
        ),
    )
    .await;
    assert_eq!(collision.status_code(), Some(400));
    let list = send(
        &mut stream,
        "<get_report_configs filter=\"sort=name rows=-1\"/>",
    )
    .await;
    for expected in ["Source Clone 1", "Source Clone 2", "Exact"] {
        assert!(body(&list).contains(expected));
    }
    assert!(body(&list).contains(&format!("id=\"{clone_one}\"")));
    assert!(body(&list).contains(&format!("id=\"{clone_two}\"")));
    assert!(body(&list).contains(&format!("id=\"{exact}\"")));
    assert!(body(&list).contains("<comment>copied</comment>"));
    assert!(!body(&list).contains("ignored"));

    let delete_format = send(
        &mut stream,
        &format!("<delete_report_format report_format_id=\"{FORMAT}\" ultimate=\"1\"/>"),
    )
    .await;
    assert_eq!(delete_format.status_code(), Some(200));
    let orphan_clone = send(
        &mut stream,
        &format!("<create_report_config><copy>{source}</copy><name>Orphan clone</name></create_report_config>"),
    )
    .await;
    assert_eq!(orphan_clone.status_code(), Some(201));
    let orphan_get = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{source}\"/>"),
    )
    .await;
    assert!(body(&orphan_get).contains(&format!("<report_format id=\"{FORMAT}\"></report_format>")));
    let orphan_modify = send(
        &mut stream,
        &format!("<modify_report_config report_config_id=\"{source}\"><comment>no</comment></modify_report_config>"),
    )
    .await;
    assert_eq!(orphan_modify.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn query_controls_counts_and_reads_are_observable_without_mutation() {
    let Some(server) = server().await else { return };
    let mut stream = connect(&server).await;
    let mut ids = Vec::new();
    for name in ["Alpha", "Saved A", "Saved B"] {
        let params = if name == "Saved A" {
            "<param><name>Label</name><value>stored</value></param>"
        } else {
            ""
        };
        ids.push(created_id(
            &send(&mut stream, &direct_create(name, "comment", params)).await,
        ));
    }
    let inline = send(
        &mut stream,
        "<get_report_configs filter=\"name~Saved first=2 rows=1 sort-reverse=name\"/>",
    )
    .await;
    assert!(body(&inline).contains("Saved A"));
    assert!(!body(&inline).contains("Saved B"));
    assert!(body(&inline).contains("<report_config_count>3<filtered>2</filtered><page>1</page>"));
    let restarted = send(
        &mut stream,
        "<get_report_configs filter=\"name~Saved first=99 rows=1 sort=name\"/>",
    )
    .await;
    assert!(body(&restarted).contains("Saved A"));
    let saved = send(
        &mut stream,
        &format!("<get_report_configs filt_id=\"{SAVED_FILTER}\" filter=\"name=Alpha\"/>"),
    )
    .await;
    assert!(body(&saved).contains("Saved A"));
    assert!(!body(&saved).contains("Alpha"));
    let sentinel = send(
        &mut stream,
        "<get_report_configs filt_id=\"0\" filter=\"name=Alpha\"/>",
    )
    .await;
    assert!(body(&sentinel).contains("Alpha"));
    assert!(!body(&sentinel).contains("Saved A"));
    let all = send(
        &mut stream,
        "<get_report_configs filter=\"rows=1\" ignore_pagination=\"1\"/>",
    )
    .await;
    assert!(body(&all).contains("<page>3</page>"));

    let selected = send(
        &mut stream,
        &format!(
            "<get_report_configs report_config_id=\"{}\" filter=\"name=none rows=0\"/>",
            ids[0]
        ),
    )
    .await;
    assert!(body(&selected).contains("Alpha"));
    let repeated_read = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{}\"/>", ids[0]),
    )
    .await;
    assert_eq!(
        body(&selected).replace(" filter=\"name=none rows=0\"", ""),
        body(&repeated_read)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn trash_lifecycle_preserves_overrides_and_ignores_alert_references() {
    let Some(server) = server().await else { return };
    let mut stream = connect(&server).await;
    let id = created_id(
        &send(
            &mut stream,
            &direct_create(
                "Saved A",
                "comment",
                "<param><name>Label</name><value>stored</value></param>",
            ),
        )
        .await,
    );

    let alert = send(
        &mut stream,
        &format!(
            "<create_alert><name>Reference</name><event>Task run status changed</event>\
             <condition>Always</condition><method>Email</method><report_config id=\"{}\"/></create_alert>",
            id
        ),
    )
    .await;
    assert_eq!(alert.status_code(), Some(201), "{}", body(&alert));

    let moved = send(
        &mut stream,
        &format!("<delete_report_config report_config_id=\"{id}\"/>"),
    )
    .await;
    assert_eq!(moved.status_code(), Some(200));
    assert_eq!(
        send(
            &mut stream,
            &format!("<delete_report_config report_config_id=\"{id}\" ultimate=\"0\"/>"),
        )
        .await
        .status_code(),
        Some(200)
    );
    let trash = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{id}\" trash=\"1\"/>"),
    )
    .await;
    assert!(body(&trash).contains("Saved A"));
    assert_eq!(
        send(&mut stream, &format!("<restore id=\"{id}\"/>"))
            .await
            .status_code(),
        Some(200)
    );
    let restored = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{id}\"/>"),
    )
    .await;
    assert!(body(&restored).contains("<value using_default=\"0\">stored</value>"));
    assert_eq!(
        send(
            &mut stream,
            &format!("<delete_report_config report_config_id=\"{id}\"/>"),
        )
        .await
        .status_code(),
        Some(200)
    );
    let ultimate = send(
        &mut stream,
        &format!("<delete_report_config report_config_id=\"{id}\" ultimate=\"1\"/>"),
    )
    .await;
    assert_eq!(ultimate.status_code(), Some(200));
    assert_eq!(
        send(
            &mut stream,
            &format!("<get_report_configs report_config_id=\"{id}\" trash=\"1\"/>"),
        )
        .await
        .status_code(),
        Some(404)
    );
    assert_eq!(
        send(
            &mut stream,
            &format!("<delete_report_config report_config_id=\"{id}\" ultimate=\"1\"/>"),
        )
        .await
        .status_code(),
        Some(404)
    );

    server.shutdown().await;
}
