// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::too_many_lines, clippy::unwrap_used, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ResourceStore, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const TASK_1: Uuid = Uuid::from_u128(0x10000000000000000000000000000001);
const TASK_2: Uuid = Uuid::from_u128(0x10000000000000000000000000000002);
const REPORT_1: Uuid = Uuid::from_u128(0x20000000000000000000000000000001);
const REPORT_2: Uuid = Uuid::from_u128(0x20000000000000000000000000000002);
const RESULT_1: Uuid = Uuid::from_u128(0x30000000000000000000000000000001);
const RESULT_2: Uuid = Uuid::from_u128(0x30000000000000000000000000000002);
const RESULT_LOW_QOD: Uuid = Uuid::from_u128(0x30000000000000000000000000000003);
const FILTER_1: Uuid = Uuid::from_u128(0x40000000000000000000000000000001);
const NOTE_1: Uuid = Uuid::from_u128(0x50000000000000000000000000000001);
const OVERRIDE_1: Uuid = Uuid::from_u128(0x60000000000000000000000000000001);
const OVERRIDE_2: Uuid = Uuid::from_u128(0x60000000000000000000000000000002);
const TIE_RESULT_1: Uuid = Uuid::from_u128(0x70000000000000000000000000000001);
const TIE_RESULT_2: Uuid = Uuid::from_u128(0x70000000000000000000000000000002);

async fn send_recv(stream: &mut UnixStream, xml: impl AsRef<[u8]>) -> Response {
    stream.write_all(xml.as_ref()).await.expect("write request");
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let mut bytes = vec![0; 128 * 1024];
    let read = stream.read(&mut bytes).await.expect("read response");
    bytes.truncate(read);
    Response::new(bytes)
}

async fn seeded_server() -> (MockGmpServer, ResourceStore) {
    let observed_store = Arc::new(Mutex::new(None));
    let seed_store = Arc::clone(&observed_store);
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(move |store| {
            seed_result_graph(store);
            *seed_store.lock().expect("store slot") = Some(store.clone());
        })
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts");
    let store = observed_store
        .lock()
        .expect("store slot")
        .clone()
        .expect("seed closure ran");
    (server, store)
}

async fn empty_server() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts")
}

async fn tied_results_server(reverse_insertion: bool) -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(move |store| {
            let ids = if reverse_insertion {
                [TIE_RESULT_2, TIE_RESULT_1]
            } else {
                [TIE_RESULT_1, TIE_RESULT_2]
            };
            for id in ids {
                let mut result = Resource::with_id("result", "Equal key", id);
                result.set_attr("severity", "7.0");
                result.set_attr("threat", "High");
                result.set_attr("qod", "100");
                store.seed(result);
            }
        })
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts")
}

fn seed_result_graph(store: &ResourceStore) {
    store.seed(Resource::with_id("task", "Task one", TASK_1));
    store.seed(Resource::with_id("task", "Task two", TASK_2));

    let mut report = Resource::with_id("report", "Report one", REPORT_1);
    report.set_attr("task_id", &TASK_1.to_string());
    store.seed(report);
    let mut report = Resource::with_id("report", "Report two", REPORT_2);
    report.set_attr("task_id", &TASK_2.to_string());
    store.seed(report);

    let mut result = Resource::with_id("result", "Alpha high", RESULT_1);
    set_result_fields(&mut result, REPORT_1, "192.0.2.10", "8.0", "95");
    result.set_attr("description", "high result");
    result.set_attr("nvt_oid", "1.3.6.1.4.1.25623.1.0.1");
    result.set_attr("nvt_name", "High NVT");
    result.set_attr("nvt_family", "General");
    result.set_attr("cves", "CVE-2026-0001,CVE-2026-0002");
    store.seed(result);

    let mut result = Resource::with_id("result", "Beta medium", RESULT_2);
    set_result_fields(&mut result, REPORT_2, "192.0.2.20", "5.0", "80");
    store.seed(result);

    let mut result = Resource::with_id("result", "Gamma low QoD", RESULT_LOW_QOD);
    set_result_fields(&mut result, REPORT_2, "192.0.2.30", "9.0", "20");
    store.seed(result);

    let mut filter = Resource::with_id("filter", "High results", FILTER_1);
    filter.set_attr("term", "severity>6 sort=name rows=1");
    store.seed(filter);

    let mut note = Resource::with_id("note", "Analyst note", NOTE_1);
    note.set_attr("result_id", &RESULT_1.to_string());
    note.set_attr("task_id", &TASK_1.to_string());
    note.set_attr("text", "expanded note text");
    store.seed(note);

    let mut override_ = Resource::with_id("override", "Raised severity", OVERRIDE_1);
    override_.set_attr("result_id", &RESULT_1.to_string());
    override_.set_attr("task_id", &TASK_1.to_string());
    override_.set_attr("new_severity", "9.5");
    override_.set_attr("text", "expanded override text");
    store.seed(override_);

    let mut override_ = Resource::with_id("override", "Raised beta severity", OVERRIDE_2);
    override_.set_attr("result_id", &RESULT_2.to_string());
    override_.set_attr("task_id", &TASK_2.to_string());
    override_.set_attr("new_severity", "9.8");
    store.seed(override_);
}

fn set_result_fields(
    result: &mut Resource,
    report_id: Uuid,
    host: &str,
    severity: &str,
    qod: &str,
) {
    result.set_attr("report_id", &report_id.to_string());
    result.set_attr("host", host);
    result.set_attr("port", "443/tcp");
    let severity_number = severity.parse::<f64>().expect("test severity");
    let threat = if severity_number >= 9.0 {
        "Critical"
    } else if severity_number >= 7.0 {
        "High"
    } else if severity_number >= 4.0 {
        "Medium"
    } else {
        "Low"
    };
    result.set_attr("threat", threat);
    result.set_attr("severity", severity);
    result.set_attr("qod", qod);
}

async fn connect_and_auth(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().expect("socket"))
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

fn text(response: &Response) -> &str {
    response.as_str().expect("response UTF-8")
}

#[derive(Debug, PartialEq, Eq)]
struct ResourceState {
    resource_type: String,
    name: String,
    comment: String,
    creation_time: String,
    modification_time: String,
    attrs: BTreeMap<String, String>,
    trashed: bool,
}

fn relevant_state_graph(store: &ResourceStore) -> BTreeMap<Uuid, ResourceState> {
    ["task", "report", "result", "filter", "note", "override"]
        .into_iter()
        .flat_map(|resource_type| store.list(resource_type))
        .map(|resource| {
            (
                resource.id,
                ResourceState {
                    resource_type: resource.resource_type,
                    name: resource.name,
                    comment: resource.comment,
                    creation_time: resource.creation_time,
                    modification_time: resource.modification_time,
                    attrs: resource.attrs,
                    trashed: resource.trashed,
                },
            )
        })
        .collect()
}

#[tokio::test]
async fn list_detail_context_and_id_selection_follow_result_semantics() {
    let (server, _) = seeded_server().await;
    let mut stream = connect_and_auth(&server).await;

    let list = send_recv(&mut stream, b"<get_results/>").await;
    let list = text(&list);
    assert!(list.contains(&RESULT_1.to_string()));
    assert!(list.contains(&RESULT_2.to_string()));
    assert!(!list.contains(&RESULT_LOW_QOD.to_string()));
    assert!(!list.contains("<task id="));
    assert!(!list.contains("</result>+"));
    assert!(list.contains("<result_count>3<filtered>2</filtered><page>2</page>"));
    assert!(list.contains("<results start=\"1\" max=\"100\"/>"));

    let detailed = send_recv(
        &mut stream,
        format!("<get_results details=\"1\" task_id=\"{TASK_1}\"/>"),
    )
    .await;
    let detailed = text(&detailed);
    assert!(detailed.contains(&RESULT_2.to_string()));
    assert!(detailed.contains(&format!("<task id=\"{TASK_1}\"><name>Task one</name>")));
    assert!(!detailed.contains(&format!("<task id=\"{TASK_2}\">")));
    assert!(detailed.contains(&format!("<report id=\"{REPORT_1}\">")));
    assert!(detailed.contains(&format!("<report id=\"{REPORT_2}\">")));

    let no_implicit_context = send_recv(
        &mut stream,
        b"<get_results filter=\"notes=1 overrides=1\"/>",
    )
    .await;
    let no_implicit_context = text(&no_implicit_context);
    assert!(!no_implicit_context.contains(&NOTE_1.to_string()));
    assert!(!no_implicit_context.contains(&OVERRIDE_1.to_string()));
    assert!(!no_implicit_context.contains(&OVERRIDE_2.to_string()));

    let id_inferred_context = send_recv(
        &mut stream,
        format!("<get_results result_id=\"{RESULT_1}\" filter=\"notes=1 overrides=1\"/>"),
    )
    .await;
    let id_inferred_context = text(&id_inferred_context);
    assert!(id_inferred_context.contains(&NOTE_1.to_string()));
    assert!(id_inferred_context.contains(&OVERRIDE_1.to_string()));

    let detailed_inferred_context = send_recv(
        &mut stream,
        b"<get_results details=\"1\" filter=\"notes=1 overrides=1\"/>",
    )
    .await;
    let detailed_inferred_context = text(&detailed_inferred_context);
    assert!(detailed_inferred_context.contains(&NOTE_1.to_string()));
    assert!(detailed_inferred_context.contains(&OVERRIDE_1.to_string()));
    assert!(detailed_inferred_context.contains(&OVERRIDE_2.to_string()));
    assert!(detailed_inferred_context.contains(&format!("<task id=\"{TASK_1}\">")));
    assert!(detailed_inferred_context.contains(&format!("<task id=\"{TASK_2}\">")));

    let matching_context = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_1}\" task_id=\"{TASK_1}\" filter=\"notes=1 overrides=1\"/>"
        ),
    )
    .await;
    assert!(text(&matching_context).contains(&NOTE_1.to_string()));
    assert!(text(&matching_context).contains(&OVERRIDE_1.to_string()));

    let mismatched_context = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_1}\" task_id=\"{TASK_2}\" details=\"1\" filter=\"notes=1 overrides=1\"/>"
        ),
    )
    .await;
    let mismatched_context = text(&mismatched_context);
    assert!(mismatched_context.contains(&RESULT_1.to_string()));
    assert!(mismatched_context.contains(&format!("<task id=\"{TASK_2}\">")));
    assert!(mismatched_context.contains(&format!("<report id=\"{REPORT_1}\">")));
    assert!(!mismatched_context.contains(&NOTE_1.to_string()));
    assert!(!mismatched_context.contains(&OVERRIDE_1.to_string()));

    for (filter, present, absent) in [
        (format!("task_id={TASK_1}"), RESULT_1, RESULT_2),
        (format!("report_id={REPORT_2}"), RESULT_2, RESULT_1),
    ] {
        let response = send_recv(
            &mut stream,
            format!("<get_results filter=\"{filter}\" min_qod=\"ignored\"/>"),
        )
        .await;
        let response = text(&response);
        assert!(response.contains(&present.to_string()));
        assert!(!response.contains(&absent.to_string()));
    }

    let selected = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_LOW_QOD}\" filter=\"severity&gt;99 first=9 rows=0\"/>"
        ),
    )
    .await;
    assert!(text(&selected).contains(&RESULT_LOW_QOD.to_string()));
    assert!(text(&selected).contains("<result_count>3<filtered>1</filtered><page>1</page>"));
    assert!(text(&selected).contains("<results start=\"9\" max=\"0\"/>"));

    for request in [
        format!("<get_results result_id=\"{}\"/>", Uuid::new_v4()),
        format!("<get_results task_id=\"{}\"/>", Uuid::new_v4()),
    ] {
        assert_eq!(
            send_recv(&mut stream, request).await.status_code(),
            Some(404)
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn saved_inline_sort_pagination_and_counts_controls_are_distinct() {
    let (server, _) = seeded_server().await;
    let mut stream = connect_and_auth(&server).await;

    let saved = send_recv(
        &mut stream,
        format!("<get_results filt_id=\"{FILTER_1}\" filter=\"severity&lt;6\"/>"),
    )
    .await;
    let saved = text(&saved);
    assert!(saved.contains(&RESULT_1.to_string()));
    assert!(!saved.contains(&RESULT_2.to_string()));
    assert!(saved.contains("<result_count>3<filtered>1</filtered><page>1</page>"));

    let inline = send_recv(
        &mut stream,
        b"<get_results filt_id=\"0\" filter=\"severity&lt;6\"/>",
    )
    .await;
    let inline = text(&inline);
    assert!(inline.contains(&RESULT_2.to_string()));
    assert!(!inline.contains(&RESULT_1.to_string()));

    let paged = send_recv(
        &mut stream,
        b"<get_results ignore_pagination=\"1\" filter=\"sort-reverse=severity first=2 rows=1\" get_counts=\"1\"/>",
    )
    .await;
    let paged = text(&paged);
    assert!(paged.contains(&RESULT_2.to_string()));
    assert!(!paged.contains(&RESULT_1.to_string()));
    assert!(paged.contains("<result_count>3<filtered>2</filtered><page>1</page>"));
    assert!(paged.contains("<results start=\"2\" max=\"1\"/>"));

    let no_counts = send_recv(
        &mut stream,
        b"<get_results filter=\"rows=-1\" get_counts=\"0\"/>",
    )
    .await;
    let no_counts = text(&no_counts);
    assert!(no_counts.contains("<result "));
    assert!(no_counts.contains("<results start=\"1\" max=\"100\"/>"));
    assert!(!no_counts.contains("<result_count>"));

    let empty_page = send_recv(&mut stream, b"<get_results filter=\"severity&gt;99\"/>").await;
    let empty_page = text(&empty_page);
    assert!(empty_page.contains("<result_count>3<filtered>0</filtered><page>0</page>"));
    assert!(empty_page.contains("<results start=\"1\" max=\"100\"/>"));

    let partial_page = send_recv(
        &mut stream,
        b"<get_results filter=\"first=2 rows=5 sort=id\"/>",
    )
    .await;
    let partial_page = text(&partial_page);
    assert!(partial_page.contains("<result_count>3<filtered>2</filtered><page>1</page>"));
    assert!(partial_page.contains("<results start=\"2\" max=\"5\"/>"));

    assert_eq!(
        send_recv(&mut stream, b"<get_results filt_id=\"-2\"/>")
            .await
            .status_code(),
        Some(400)
    );
    for request in [
        b"<get_results filter=\"unsupported=yes\"/>".as_slice(),
        b"<get_results filter=\"host&gt;192.0.2.1\"/>".as_slice(),
        b"<get_results filter=\"severity&gt;=5\"/>".as_slice(),
        b"<get_results filter=\"severity&gt;not-a-number\"/>".as_slice(),
        b"<get_results filter=\"severity=NaN\"/>".as_slice(),
        b"<get_results filter=\"severity==5\"/>".as_slice(),
        b"<get_results filter=\"sort=private-sort-value\"/>".as_slice(),
    ] {
        let response = send_recv(&mut stream, request).await;
        assert_eq!(response.status_code(), Some(400));
        assert!(text(&response).contains("result filter"));
        assert!(!text(&response).contains("not-a-number"));
        assert!(!text(&response).contains("private-sort-value"));
    }
    server.shutdown().await;

    let empty_server = empty_server().await;
    let mut empty_stream = connect_and_auth(&empty_server).await;
    for request in [
        b"<get_results filter=\"severity&gt;=5\"/>".as_slice(),
        b"<get_results filter=\"severity&gt;junk\"/>".as_slice(),
        b"<get_results filter=\"host&gt;192.0.2.1\"/>".as_slice(),
    ] {
        assert_eq!(
            send_recv(&mut empty_stream, request).await.status_code(),
            Some(400)
        );
    }
    empty_server.shutdown().await;
}

#[tokio::test]
async fn inclusion_detail_and_override_application_are_independent_and_read_only() {
    let (server, store) = seeded_server().await;
    let before = relevant_state_graph(&store);
    let mut stream = connect_and_auth(&server).await;

    let flags_only = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_1}\" notes_details=\"1\" overrides_details=\"1\"/>"
        ),
    )
    .await;
    let flags_only = text(&flags_only);
    assert!(!flags_only.contains("<notes>"));
    assert!(!flags_only.contains("<overrides>"));
    assert!(!flags_only.contains("<original_severity>"));
    assert!(!flags_only.contains("<original_threat>"));

    let summaries = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_1}\" filter=\"notes=1 overrides=1 apply_overrides=0\"/>"
        ),
    )
    .await;
    let summaries = text(&summaries);
    assert!(summaries.contains(&format!("<note id=\"{NOTE_1}\"><name>Analyst note</name>")));
    assert!(summaries.contains(&format!(
        "<override id=\"{OVERRIDE_1}\"><name>Raised severity</name>"
    )));
    assert!(!summaries.contains("expanded note text"));
    assert!(!summaries.contains("expanded override text"));
    assert!(summaries.contains("<severity>8.0</severity>"));
    assert!(summaries.contains("<original_severity>8.0</original_severity>"));
    assert!(summaries.contains("<original_threat>High</original_threat>"));

    let detailed = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_1}\" filter=\"notes=1 overrides=1 apply_overrides=0\" notes_details=\"1\" overrides_details=\"1\"/>"
        ),
    )
    .await;
    assert!(text(&detailed).contains("<text>expanded note text</text>"));
    assert!(text(&detailed).contains("<new_severity>9.5</new_severity>"));

    let applied_without_display = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_1}\" filter=\"notes=0 overrides=0 apply_overrides=1\"/>"
        ),
    )
    .await;
    let applied_without_display = text(&applied_without_display);
    assert!(applied_without_display.contains("<severity>9.5</severity>"));
    assert!(applied_without_display.contains("<threat>Critical</threat>"));
    assert!(!applied_without_display.contains("<overrides>"));
    assert!(!applied_without_display.contains("<original_severity>"));
    assert!(!applied_without_display.contains("<original_threat>"));

    let originals_without_associations = send_recv(
        &mut stream,
        format!(
            "<get_results result_id=\"{RESULT_LOW_QOD}\" filter=\"overrides=1 apply_overrides=0\"/>"
        ),
    )
    .await;
    let originals_without_associations = text(&originals_without_associations);
    assert!(originals_without_associations.contains("<overrides></overrides>"));
    assert!(originals_without_associations.contains("<original_severity>9.0</original_severity>"));
    assert!(originals_without_associations.contains("<original_threat>Critical</original_threat>"));

    let applied_filter = send_recv(
        &mut stream,
        b"<get_results filter=\"apply_overrides=1 severity&gt;9.6\"/>",
    )
    .await;
    let applied_filter = text(&applied_filter);
    assert!(applied_filter.contains(&RESULT_2.to_string()));
    assert!(!applied_filter.contains(&RESULT_1.to_string()));
    assert!(applied_filter.contains("<severity>9.8</severity>"));
    assert!(applied_filter.contains("<threat>Critical</threat>"));
    assert!(applied_filter.contains("<result_count>3<filtered>1</filtered><page>1</page>"));

    let applied_sort = send_recv(
        &mut stream,
        b"<get_results filter=\"apply_overrides=1 sort-reverse=severity rows=1\"/>",
    )
    .await;
    let applied_sort = text(&applied_sort);
    assert!(applied_sort.contains(&RESULT_2.to_string()));
    assert!(!applied_sort.contains(&RESULT_1.to_string()));

    let original_sort = send_recv(
        &mut stream,
        b"<get_results filter=\"apply_overrides=0 sort-reverse=severity rows=1\"/>",
    )
    .await;
    let original_sort = text(&original_sort);
    assert!(original_sort.contains(&RESULT_1.to_string()));
    assert!(!original_sort.contains(&RESULT_2.to_string()));

    let applied_threat = send_recv(
        &mut stream,
        b"<get_results filter=\"apply_overrides=1 threat=Critical\"/>",
    )
    .await;
    let applied_threat = text(&applied_threat);
    assert!(applied_threat.contains(&RESULT_1.to_string()));
    assert!(applied_threat.contains(&RESULT_2.to_string()));
    assert!(applied_threat.contains("<result_count>3<filtered>2</filtered><page>2</page>"));

    let original_threat = send_recv(
        &mut stream,
        b"<get_results filter=\"apply_overrides=0 threat=Critical\"/>",
    )
    .await;
    let original_threat = text(&original_threat);
    assert!(!original_threat.contains(&RESULT_1.to_string()));
    assert!(!original_threat.contains(&RESULT_2.to_string()));
    assert!(original_threat.contains("<result_count>3<filtered>0</filtered><page>0</page>"));

    assert_eq!(before, relevant_state_graph(&store));
    server.shutdown().await;
}

#[tokio::test]
async fn rejected_and_ignored_root_attributes_match_the_bounded_contract() {
    let (server, _) = seeded_server().await;
    let mut stream = connect_and_auth(&server).await;

    let trash = send_recv(&mut stream, b"<get_results trash=\"1\"/>").await;
    assert_eq!(trash.status_code(), Some(400));
    assert!(text(&trash).contains("Result trash retrieval is not supported"));

    let ignored = send_recv(
        &mut stream,
        b"<get_results report_id=\"ignored\" lean=\"1\" delta_report_id=\"ignored\" delta_states=\"c\" filter_replace=\"ignored\"/>",
    )
    .await;
    assert_eq!(ignored.status_code(), Some(200));
    let ignored = text(&ignored);
    assert!(ignored.contains(&RESULT_1.to_string()));
    assert!(ignored.contains(&RESULT_2.to_string()));
    assert!(!ignored.contains("delta_report"));
    server.shutdown().await;
}

#[tokio::test]
async fn equal_sort_keys_use_id_ties_across_insertion_orders_and_pages() {
    for reverse_insertion in [false, true] {
        let server = tied_results_server(reverse_insertion).await;
        let mut stream = connect_and_auth(&server).await;

        let first = send_recv(
            &mut stream,
            b"<get_results filter=\"sort-reverse=severity first=1 rows=1\"/>",
        )
        .await;
        let first = text(&first);
        assert!(first.contains(&TIE_RESULT_1.to_string()));
        assert!(!first.contains(&TIE_RESULT_2.to_string()));

        let second = send_recv(
            &mut stream,
            b"<get_results filter=\"sort-reverse=severity first=2 rows=1\"/>",
        )
        .await;
        let second = text(&second);
        assert!(second.contains(&TIE_RESULT_2.to_string()));
        assert!(!second.contains(&TIE_RESULT_1.to_string()));

        server.shutdown().await;
    }
}
