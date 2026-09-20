// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(missing_docs, clippy::too_many_lines, clippy::unwrap_used)]

use base64::Engine as _;
use gvm_gmp::commands::authentication::authenticate;
use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ResourceStore, ServerMode};
use gvm_protocol::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const FORMAT: &str = "00000000-0000-0000-0000-000000000200";
const PREDEFINED_FORMAT: &str = "00000000-0000-0000-0000-000000000201";
const SAVED_FILTER: &str = "00000000-0000-0000-0000-000000000203";

async fn server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts")
}

async fn seeded_server(seed: impl FnOnce(&ResourceStore) + Send + 'static) -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(seed)
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts")
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
    let mut bytes = vec![0; 256 * 1024];
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

fn exported(id: &str, name: &str, extra: &str) -> String {
    format!(
        "<get_report_formats_response status=\"200\"><report_format id=\"{id}\"><name>{name}</name>{extra}</report_format></get_report_formats_response>"
    )
}

fn import(xml: &str) -> String {
    format!("<create_report_format>{xml}</create_report_format>")
}

#[tokio::test]
async fn import_requires_envelope_and_validates_definition_without_partial_creation() {
    let server = server().await;
    let mut stream = connect(&server).await;
    let before = send(&mut stream, "<get_report_formats/>").await;
    assert!(body(&before).contains("<report_format_count>2"));

    let invalid = [
        "<create_report_format><name>unsupported</name></create_report_format>".to_string(),
        "<create_report_format><report_format id=\"11111111-1111-1111-1111-111111111111\"><name>bare</name></report_format></create_report_format>".to_string(),
        "<create_report_format><get_report_formats_response/></create_report_format>".to_string(),
        import(&exported("not-a-uuid", "bad", "")),
        "<create_report_format><get_report_formats_response><report_format><name>missing id</name></report_format></get_report_formats_response></create_report_format>".to_string(),
        "<create_report_format><get_report_formats_response><report_format id=\"11111111-1111-1111-1111-111111111111\"/></get_report_formats_response></create_report_format>".to_string(),
        import(&exported("11111111-1111-1111-1111-111111111111", "missing type", "<param><name>Label</name><value>x</value><default>x</default></param>")),
        import(&exported("11111111-1111-1111-1111-111111111111", "missing default", "<param><name>Label</name><type>string</type><value>x</value></param>")),
        import(&exported("11111111-1111-1111-1111-111111111111", "duplicate", "<param><name>Label</name><type>string</type><value>x</value><default>x</default></param><param><name>Label</name><type>string</type><value>x</value><default>x</default></param>")),
        import(&exported("11111111-1111-1111-1111-111111111111", "invalid current", "<param><name>Choice</name><type>selection</type><value>no</value><default>yes</default><options><option>yes</option></options></param>")),
        import(&exported("11111111-1111-1111-1111-111111111111", "invalid default", "<param><name>Choice</name><type>selection</type><value>yes</value><default>no</default><options><option>yes</option></options></param>")),
    ];
    for xml in invalid {
        let response = send(&mut stream, &xml).await;
        assert!(
            matches!(response.status_code(), Some(400 | 404)),
            "{}",
            body(&response)
        );
    }
    let after = send(&mut stream, "<get_report_formats/>").await;
    assert!(body(&after).contains("<report_format_count>2"));

    let rich = exported(
        "11111111-1111-1111-1111-111111111111",
        "Imported",
        "<content_type>text/plain</content_type><extension>txt</extension><summary>summary</summary>\
         <active>1</active><predefined>1</predefined><trust>yes</trust><report_type>invalid</report_type>\
         <param><name>Choice</name><type> selection </type><value>red</value><default>blue</default><options><option>red</option><option>blue</option></options></param>\
         <file name=\"data.txt\">aGVsbG8=</file><signature>signature</signature>",
    );
    let first = created_id(&send(&mut stream, &import(&rich)).await);
    assert_eq!(first, "11111111-1111-1111-1111-111111111111");
    let detail = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{first}\" details=\"1\"/>"),
    )
    .await;
    for expected in [
        "<name>Imported</name>",
        "<active>0</active>",
        "<predefined>0</predefined>",
        "<trust>unknown",
        "<value>red</value>",
        "<default>blue</default>",
        "<option>red</option>",
        "<file name=\"data.txt\">aGVsbG8=</file>",
    ] {
        assert!(
            body(&detail).contains(expected),
            "missing {expected}: {}",
            body(&detail)
        );
    }

    let duplicate = created_id(&send(&mut stream, &import(&rich)).await);
    assert_ne!(duplicate, first);
    let duplicate_detail = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{duplicate}\"/>"),
    )
    .await;
    assert!(body(&duplicate_detail).contains("<name>Imported 2</name>"));

    let raw_multiple = "<create_report_format><get_report_formats_response><report_format id=\"22222222-2222-2222-2222-222222222222\"><name>First raw</name></report_format><report_format id=\"33333333-3333-3333-3333-333333333333\"><name>Second raw</name></report_format></get_report_formats_response></create_report_format>".to_string();
    let raw_id = created_id(&send(&mut stream, &raw_multiple).await);
    assert_eq!(raw_id, "22222222-2222-2222-2222-222222222222");
    let list = send(&mut stream, "<get_report_formats filter=\"name~raw\"/>").await;
    assert!(body(&list).contains("First raw"));
    assert!(!body(&list).contains("Second raw"));

    server.shutdown().await;
}

#[tokio::test]
async fn clone_copies_supported_state_but_not_parameter_options() {
    let server = server().await;
    let mut stream = connect(&server).await;

    let auto = created_id(
        &send(
            &mut stream,
            &format!("<create_report_format><copy>{FORMAT}</copy></create_report_format>"),
        )
        .await,
    );
    let empty = created_id(
        &send(
            &mut stream,
            &format!(
                "<create_report_format><copy>{FORMAT}</copy><name></name></create_report_format>"
            ),
        )
        .await,
    );
    let exact = created_id(
        &send(
            &mut stream,
            &format!("<create_report_format><copy>{FORMAT}</copy><name>Exact</name><active>0</active><get_report_formats_response/></create_report_format>"),
        )
        .await,
    );
    let collision = send(
        &mut stream,
        &format!(
            "<create_report_format><copy>{FORMAT}</copy><name>Exact</name></create_report_format>"
        ),
    )
    .await;
    assert_eq!(collision.status_code(), Some(400));

    let list = send(
        &mut stream,
        "<get_report_formats details=\"1\" filter=\"sort=name\"/>",
    )
    .await;
    for expected in [
        "Mock configurable format Clone 1",
        "Mock configurable format Clone 2",
        "Exact",
    ] {
        assert!(body(&list).contains(expected));
    }
    for id in [&auto, &empty, &exact] {
        let detail = send(
            &mut stream,
            &format!("<get_report_formats report_format_id=\"{id}\" details=\"1\"/>"),
        )
        .await;
        assert!(body(&detail).contains("<file name=\"template.txt\">"));
        assert!(body(&detail).contains("<name>Graph Type</name>"));
        assert!(!body(&detail).contains("<option>bar</option>"));
        assert!(body(&detail).contains("<active>1</active>"));
    }

    let predefined_clone = created_id(
        &send(
            &mut stream,
            &format!(
                "<create_report_format><copy>{PREDEFINED_FORMAT}</copy></create_report_format>"
            ),
        )
        .await,
    );
    let detail = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{predefined_clone}\"/>"),
    )
    .await;
    assert!(body(&detail).contains("<predefined>0</predefined>"));
    assert!(body(&detail).contains("<trust>yes"));

    server.shutdown().await;
}

#[tokio::test]
async fn modify_preserves_clears_base64_once_and_keeps_partial_metadata_effects() {
    let server = seeded_server(|store| {
        let mut other = Resource::new("report_format", "Cross-format parameter fixture");
        other.set_attr("active", "1");
        other.set_attr("predefined", "0");
        other.set_attr("report_format_param_type:Only elsewhere", "string");
        other.set_attr("report_format_param_value:Only elsewhere", "x");
        other.set_attr("report_format_param_default:Only elsewhere", "x");
        store.seed(other);
    })
    .await;
    let mut stream = connect(&server).await;

    let update = send(
        &mut stream,
        &format!(
            "<modify_report_format report_format_id=\"{FORMAT}\"><name>Renamed</name><summary></summary><active>0</active><param><name>Label</name><value>{}</value></param></modify_report_format>",
            base64::engine::general_purpose::STANDARD.encode("red")
        ),
    )
    .await;
    assert_eq!(update.status_code(), Some(200), "{}", body(&update));
    let detail = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{FORMAT}\" details=\"1\"/>"),
    )
    .await;
    assert!(body(&detail).contains("<name>Renamed</name>"));
    assert!(body(&detail).contains("<summary></summary>"));
    assert!(body(&detail).contains("<active>0</active>"));
    assert!(body(&detail).contains("<value>red</value>"));
    assert!(body(&detail).contains("<default>Default label</default>"));
    assert!(body(&detail).contains("<name>Graph Type</name>"));

    let literal_base64 = base64::engine::general_purpose::STANDARD.encode("cmVk");
    assert_eq!(
        send(
            &mut stream,
            &format!("<modify_report_format report_format_id=\"{FORMAT}\"><param><name>Label</name><value>{literal_base64}</value></param></modify_report_format>"),
        )
        .await
        .status_code(),
        Some(200)
    );
    let detail = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{FORMAT}\" params=\"1\"/>"),
    )
    .await;
    assert!(body(&detail).contains("<value>cmVk</value>"));
    assert!(!body(&detail).contains("<file "));

    for value in ["", "<value></value>"] {
        let value = if value.is_empty() {
            String::new()
        } else {
            value.to_string()
        };
        let response = send(
            &mut stream,
            &format!("<modify_report_format report_format_id=\"{FORMAT}\"><param><name>Label</name>{value}</param></modify_report_format>"),
        )
        .await;
        assert_eq!(response.status_code(), Some(200));
    }
    let detail = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{FORMAT}\" params=\"1\"/>"),
    )
    .await;
    assert!(body(&detail).contains("<name>Label</name><type>string</type><value></value>"));

    let partial = send(
        &mut stream,
        &format!("<modify_report_format report_format_id=\"{FORMAT}\"><summary>committed first</summary><param><name>Missing</name><value>eA==</value></param></modify_report_format>"),
    )
    .await;
    assert_eq!(partial.status_code(), Some(400));
    let detail = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{FORMAT}\"/>"),
    )
    .await;
    assert!(body(&detail).contains("<summary>committed first</summary>"));

    let cross_format_only = send(
        &mut stream,
        &format!("<modify_report_format report_format_id=\"{FORMAT}\"><param><name>Only elsewhere</name><value>eA==</value></param></modify_report_format>"),
    )
    .await;
    assert_eq!(cross_format_only.status_code(), Some(400));

    let predefined = send(
        &mut stream,
        &format!("<modify_report_format report_format_id=\"{PREDEFINED_FORMAT}\"><name>no</name></modify_report_format>"),
    )
    .await;
    assert_eq!(predefined.status_code(), Some(400));

    server.shutdown().await;
}

#[tokio::test]
async fn query_expansions_filters_counts_and_id_selection_are_independent() {
    let server = seeded_server(|store| {
        let mut visible = Resource::new("alert", "Visible alert");
        visible.set_attr("send_report_format", FORMAT);
        store.seed(visible);
        let mut invisible = Resource::new("alert", "Invisible alert");
        invisible.set_attr("notice_report_format", FORMAT);
        invisible.set_attr("visible", "0");
        store.seed(invisible);
        let mut config = Resource::new("report_config", "Associated config");
        config.set_attr("report_format_id", FORMAT);
        store.seed(config);
        let mut hidden_config = Resource::new("report_config", "Invisible config");
        hidden_config.set_attr("report_format_id", FORMAT);
        hidden_config.set_attr("visible", "0");
        store.seed(hidden_config);
    })
    .await;
    let mut stream = connect(&server).await;

    let inline = send(
        &mut stream,
        "<get_report_formats filter=\"name~Mock first=2 rows=1 sort=name\"/>",
    )
    .await;
    assert!(body(&inline).contains("Mock predefined report format"));
    assert!(body(&inline).contains("<report_format_count>2<filtered>2</filtered><page>1</page>"));
    let saved = send(
        &mut stream,
        &format!("<get_report_formats filt_id=\"{SAVED_FILTER}\" filter=\"name=none\"/>"),
    )
    .await;
    assert!(body(&saved).contains("Mock configurable format"));
    let sentinel = send(
        &mut stream,
        "<get_report_formats filt_id=\"0\" filter=\"name~nonconfigurable\"/>",
    )
    .await;
    assert!(body(&sentinel).contains("Mock nonconfigurable format"));
    let all = send(
        &mut stream,
        "<get_report_formats filter=\"rows=1\" ignore_pagination=\"1\"/>",
    )
    .await;
    assert!(body(&all).contains("<page>2</page>"));

    let selected = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{FORMAT}\" filter=\"name=none rows=0\" alerts=\"1\" report_configs=\"1\"/>"),
    )
    .await;
    for expected in [
        "Visible alert",
        "Associated config",
        "<alerts>",
        "<report_configs>",
        "<filtered>1</filtered>",
    ] {
        assert!(
            body(&selected).contains(expected),
            "missing {expected}: {}",
            body(&selected)
        );
    }
    assert!(!body(&selected).contains("Invisible alert"));
    assert!(!body(&selected).contains("Invisible config"));

    let params_only = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{FORMAT}\" params=\"1\"/>"),
    )
    .await;
    assert!(body(&params_only).contains("<param>"));
    assert!(!body(&params_only).contains("<file "));
    let details = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{FORMAT}\" params=\"0\" details=\"1\"/>"),
    )
    .await;
    assert!(body(&details).contains("<param>"));
    assert!(body(&details).contains("<file "));
    let invalid = send(
        &mut stream,
        "<get_report_formats params=\"1\" trash=\"1\"/>",
    )
    .await;
    assert_eq!(invalid.status_code(), Some(400));

    let first = body(&send(&mut stream, "<get_report_formats/>").await).to_string();
    let second = body(&send(&mut stream, "<get_report_formats/>").await).to_string();
    assert_eq!(first, second, "reads must not mutate state");

    server.shutdown().await;
}

#[tokio::test]
async fn trash_ids_alert_guards_and_orphaned_report_configs_follow_bounded_contract() {
    let server = server().await;
    let mut stream = connect(&server).await;
    let imported_xml = exported(
        "44444444-4444-4444-4444-444444444444",
        "Disposable",
        "<param><name>Label</name><type>string</type><value>x</value><default>d</default></param>",
    );
    let active_id = created_id(&send(&mut stream, &import(&imported_xml)).await);
    let config = send(
        &mut stream,
        &format!("<create_report_config><name>Will orphan</name><report_format id=\"{active_id}\"/></create_report_config>"),
    )
    .await;
    let config_id = created_id(&config);

    let deleted = send(
        &mut stream,
        &format!("<delete_report_format report_format_id=\"{active_id}\"/>"),
    )
    .await;
    assert_eq!(deleted.status_code(), Some(200));
    let old = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{active_id}\"/>"),
    )
    .await;
    assert_eq!(old.status_code(), Some(404));
    let trash = send(
        &mut stream,
        "<get_report_formats trash=\"1\" details=\"1\"/>",
    )
    .await;
    let trash_body = body(&trash);
    assert!(trash_body.contains("Disposable"));
    assert!(trash_body.contains("<name>Label</name>"));
    let marker = "<report_format id=\"";
    let start = trash_body.find(marker).unwrap() + marker.len();
    let end = start + trash_body[start..].find('"').unwrap();
    let trash_id = &trash_body[start..end];
    assert_ne!(trash_id, active_id);

    let orphan = send(
        &mut stream,
        &format!("<get_report_configs report_config_id=\"{config_id}\"/>"),
    )
    .await;
    assert!(body(&orphan).contains(&format!(
        "<report_format id=\"{active_id}\"></report_format>"
    )));
    let ultimate = send(
        &mut stream,
        &format!("<delete_report_format report_format_id=\"{trash_id}\" ultimate=\"1\"/>"),
    )
    .await;
    assert_eq!(ultimate.status_code(), Some(200));

    let predefined = send(
        &mut stream,
        &format!("<delete_report_format report_format_id=\"{PREDEFINED_FORMAT}\"/>"),
    )
    .await;
    assert_eq!(predefined.status_code(), Some(200));
    let predefined_trash = send(
        &mut stream,
        &format!("<get_report_formats report_format_id=\"{PREDEFINED_FORMAT}\" trash=\"1\"/>"),
    )
    .await;
    assert_eq!(predefined_trash.status_code(), Some(200));

    server.shutdown().await;

    let guarded = seeded_server(|store| {
        let mut active_alert = Resource::new("alert", "Blocks active deletion");
        active_alert.set_attr("send_report_format", FORMAT);
        store.seed(active_alert);
        let mut config = Resource::new("report_config", "Does not block");
        config.set_attr("report_format_id", PREDEFINED_FORMAT);
        store.seed(config);
    })
    .await;
    let mut stream = connect(&guarded).await;
    let blocked = send(
        &mut stream,
        &format!("<delete_report_format report_format_id=\"{FORMAT}\"/>"),
    )
    .await;
    assert_eq!(blocked.status_code(), Some(409));
    let config_only = send(
        &mut stream,
        &format!("<delete_report_format report_format_id=\"{PREDEFINED_FORMAT}\" ultimate=\"1\"/>"),
    )
    .await;
    assert_eq!(config_only.status_code(), Some(200));
    guarded.shutdown().await;
}

#[tokio::test]
async fn alert_guards_distinguish_active_trashed_notice_and_all_trash_fields() {
    let active_send = Uuid::from_u128(0x60000000000000000000000000000001);
    let active_notice = Uuid::from_u128(0x60000000000000000000000000000002);
    let stable_trash = Uuid::from_u128(0x60000000000000000000000000000003);
    let server = seeded_server(move |store| {
        for (id, predefined) in [
            (active_send, false),
            (active_notice, false),
            (stable_trash, true),
        ] {
            let mut format = Resource::with_id("report_format", &format!("Guard {id}"), id);
            format.set_attr("active", "1");
            format.set_attr("predefined", if predefined { "1" } else { "0" });
            store.seed(format);
        }
        let mut send = Resource::new("alert", "Trashed send reference");
        send.trashed = true;
        send.set_attr("send_report_format", &active_send.to_string());
        store.seed(send);
        let mut notice = Resource::new("alert", "Trashed notice reference");
        notice.trashed = true;
        notice.set_attr("notice_report_format", &active_notice.to_string());
        store.seed(notice);
        let mut trash_send = Resource::new("alert", "Trash all-fields reference");
        trash_send.trashed = true;
        trash_send.set_attr("send_report_format", &stable_trash.to_string());
        store.seed(trash_send);
    })
    .await;
    let mut stream = connect(&server).await;

    assert_eq!(
        send(
            &mut stream,
            &format!("<delete_report_format report_format_id=\"{active_send}\" ultimate=\"1\"/>"),
        )
        .await
        .status_code(),
        Some(200),
        "active ultimate checks only notice fields on trashed alerts"
    );
    assert_eq!(
        send(
            &mut stream,
            &format!("<delete_report_format report_format_id=\"{active_notice}\" ultimate=\"1\"/>"),
        )
        .await
        .status_code(),
        Some(409)
    );
    assert_eq!(
        send(
            &mut stream,
            &format!("<delete_report_format report_format_id=\"{stable_trash}\"/>")
        )
        .await
        .status_code(),
        Some(200)
    );
    assert_eq!(
        send(
            &mut stream,
            &format!("<delete_report_format report_format_id=\"{stable_trash}\" ultimate=\"1\"/>"),
        )
        .await
        .status_code(),
        Some(409),
        "trash deletion checks all six alert fields"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn verification_records_deterministic_trust_without_changing_active_state() {
    let ids = [
        Uuid::from_u128(0x50000000000000000000000000000001),
        Uuid::from_u128(0x50000000000000000000000000000002),
        Uuid::from_u128(0x50000000000000000000000000000003),
        Uuid::from_u128(0x50000000000000000000000000000004),
    ];
    let server = seeded_server(move |store| {
        for (index, (id, outcome)) in ids
            .into_iter()
            .zip([Some("yes"), Some("no"), Some("unknown"), None])
            .enumerate()
        {
            let mut format = Resource::with_id("report_format", &format!("Verify {index}"), id);
            format.set_attr("active", if index % 2 == 0 { "1" } else { "0" });
            format.set_attr("predefined", "0");
            format.set_attr("trust", "stale");
            if let Some(outcome) = outcome {
                format.set_attr("signature", "inert signature fixture");
                format.set_attr("verification_outcome", outcome);
            }
            store.seed(format);
        }
    })
    .await;
    let mut stream = connect(&server).await;

    for (index, (id, expected)) in ids
        .into_iter()
        .zip(["yes", "no", "unknown", "unknown"])
        .enumerate()
    {
        let verify = send(
            &mut stream,
            &format!("<verify_report_format report_format_id=\"{id}\"/>"),
        )
        .await;
        assert_eq!(verify.status_code(), Some(200));
        let detail = send(
            &mut stream,
            &format!("<get_report_formats report_format_id=\"{id}\"/>"),
        )
        .await;
        assert!(body(&detail).contains(&format!("<trust>{expected}<time>")));
        assert!(body(&detail).contains(if index % 2 == 0 {
            "<active>1</active>"
        } else {
            "<active>0</active>"
        }));
    }
    let missing = send(
        &mut stream,
        "<verify_report_format report_format_id=\"99999999-9999-9999-9999-999999999999\"/>",
    )
    .await;
    assert_eq!(missing.status_code(), Some(404));

    server.shutdown().await;
}
