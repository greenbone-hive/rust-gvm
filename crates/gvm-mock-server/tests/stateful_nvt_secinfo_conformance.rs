// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::too_many_lines, clippy::unwrap_used, missing_docs)]

use std::sync::{Arc, Mutex};

use gvm_mock_server::{
    DiscoveryNvt, DiscoveryPreference, GmpVersion, MockGmpServer, ResourceStore, ServerMode,
};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const CONFIG_ID: &str = "daba56c8-73ec-11df-a475-002264764cea";
const NVT_ONE: &str = "1.3.6.1.4.1.25623.1";

async fn server() -> (MockGmpServer, ResourceStore) {
    let observed = Arc::new(Mutex::new(None));
    let seeded = Arc::clone(&observed);
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(move |store| {
            store.seed_discovery_filter("filter-1", "severity=9.8 sort=name rows=1");
            store.set_discovery_user_default_filter(Some("name='Mock CVE two'".to_string()));
            *seeded.lock().unwrap() = Some(store.clone());
        })
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts");
    let store = observed.lock().unwrap().clone().expect("seed ran");
    (server, store)
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    UnixStream::connect(server.socket_path().unwrap())
        .await
        .expect("connect")
}

async fn send_recv(stream: &mut UnixStream, xml: impl AsRef<[u8]>) -> Response {
    stream.write_all(xml.as_ref()).await.expect("write");
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let mut bytes = vec![0; 128 * 1024];
    let read = stream.read(&mut bytes).await.expect("read");
    bytes.truncate(read);
    Response::new(bytes)
}

async fn authenticate(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

#[tokio::test]
async fn nvt_queries_enforce_contexts_and_expand_only_requested_details() {
    let (server, store) = server().await;
    let mut stream = connect(&server).await;
    assert_eq!(
        send_recv(&mut stream, b"<get_nvts/>").await.status_code(),
        Some(401)
    );
    authenticate(&mut stream).await;

    for invalid in [
        "<get_nvts nvt_oid=\"x\" family=\"General\"/>".to_string(),
        format!("<get_nvts config_id=\"{CONFIG_ID}\"/>"),
        format!(
            "<get_nvts config_id=\"{CONFIG_ID}\" family=\"General\" preferences_config_id=\"{CONFIG_ID}\"/>"
        ),
        "<get_nvts preferences=\"1\"/>".to_string(),
        "<get_nvts details=\"1\" timeout=\"1\"/>".to_string(),
        "<get_nvts sort_field=\"unsupported\"/>".to_string(),
    ] {
        assert_eq!(
            send_recv(&mut stream, invalid.as_bytes())
                .await
                .status_code(),
            Some(400),
            "{invalid}"
        );
    }

    let compact = send_recv(&mut stream, b"<get_nvts/>").await;
    let compact = compact.as_str().unwrap();
    assert!(compact.contains("<name>Mock NVT one</name>"));
    assert!(!compact.contains("<family>"));

    let descending = send_recv(
        &mut stream,
        b"<get_nvts sort_field=\"name\" sort_order=\"descending\"/>",
    )
    .await;
    let descending = descending.as_str().unwrap();
    assert!(descending.find("Mock NVT two").unwrap() < descending.find("Mock NVT one").unwrap());

    let ignored_filter = send_recv(
        &mut stream,
        b"<get_nvts filter=\"name=Does-not-exist\" filt_id=\"missing\"/>",
    )
    .await;
    assert_eq!(ignored_filter.as_str().unwrap(), compact);

    let list = send_recv(
        &mut stream,
        format!("<get_nvts config_id=\"{CONFIG_ID}\" family=\"General\"/>").as_bytes(),
    )
    .await;
    assert!(list.as_str().unwrap().contains(NVT_ONE));
    assert!(!list.as_str().unwrap().contains("25623.2"));

    assert_eq!(
        send_recv(
            &mut stream,
            b"<get_nvts config_id=\"unknown\" family=\"General\"/>"
        )
        .await
        .status_code(),
        Some(404)
    );

    let preference_context = send_recv(
        &mut stream,
        format!(
            "<get_nvts preferences_config_id=\"{CONFIG_ID}\" family=\"Web application abuses\"/>"
        )
        .as_bytes(),
    )
    .await;
    assert!(preference_context.as_str().unwrap().contains("25623.2"));

    let detail = send_recv(
        &mut stream,
        format!("<get_nvts nvt_oid=\"1.3.6.1.4.1.25623.2\" config_id=\"{CONFIG_ID}\" details=\"1\" preferences=\"1\" preference_count=\"1\" timeout=\"1\" skip_tags=\"1\" skip_cert_refs=\"1\"/>").as_bytes(),
    )
    .await;
    let detail = detail.as_str().unwrap();
    assert!(
        detail.contains("25623.2"),
        "detail selectors bypass membership"
    );
    assert!(detail.contains("<family>Web application abuses</family>"));
    assert!(detail.contains("<preference_count>0</preference_count>"));
    assert!(detail.contains("<timeout>180</timeout><default_timeout>180</default_timeout>"));
    assert!(!detail.contains("<tags>"));
    assert!(!detail.contains("<refs>"));

    let configured_timeout = send_recv(
        &mut stream,
        format!(
            "<get_nvts nvt_oid=\"{NVT_ONE}\" config_id=\"{CONFIG_ID}\" details=\"1\" timeout=\"1\"/>"
        )
        .as_bytes(),
    )
    .await;
    assert!(configured_timeout
        .as_str()
        .unwrap()
        .contains("<timeout>120</timeout><default_timeout>300</default_timeout>"));

    assert_eq!(
        send_recv(&mut stream, b"<get_nvts nvt_oid=\"unknown\"/>")
            .await
            .status_code(),
        Some(404)
    );

    store.set_discovery_availability(false, true, true);
    for request in ["<get_nvts/>", "<get_nvt_families/>", "<get_preferences/>"] {
        assert_eq!(
            send_recv(&mut stream, request.as_bytes())
                .await
                .status_code(),
            Some(503),
            "{request}"
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn families_and_preferences_match_pinned_boundaries() {
    let (server, store) = server().await;
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    store.seed_discovery_nvt(DiscoveryNvt {
        oid: NVT_ONE.to_string(),
        name: "Mock NVT one".to_string(),
        family: "General".to_string(),
        cvss_base: 9.8,
        severity: "9.8".to_string(),
        tags: "solution=Update the affected package|summary=Mock finding".to_string(),
        solution_type: "VendorFix".to_string(),
        timeout: 300,
        preferences: vec![
            DiscoveryPreference {
                key: format!("{NVT_ONE}:9:entry:First match"),
                value: "later-value".to_string(),
                default: Some("later-default".to_string()),
                alternatives: Vec::new(),
            },
            DiscoveryPreference {
                key: format!("{NVT_ONE}:1:password:Password"),
                value: "mock-secret".to_string(),
                default: Some("default-secret".to_string()),
                alternatives: Vec::new(),
            },
            DiscoveryPreference {
                key: format!("{NVT_ONE}:2:radio:Mode"),
                value: "stale-current".to_string(),
                default: Some("safe".to_string()),
                alternatives: vec!["safe".to_string(), "fast".to_string()],
            },
            DiscoveryPreference {
                key: format!("{NVT_ONE}:3:entry:Retries:with:suffix"),
                value: "stale-current".to_string(),
                default: Some("1".to_string()),
                alternatives: Vec::new(),
            },
            DiscoveryPreference {
                key: format!("{NVT_ONE}:4:entry:First match"),
                value: "stale-current".to_string(),
                default: Some("first-default".to_string()),
                alternatives: Vec::new(),
            },
            DiscoveryPreference {
                key: format!("{NVT_ONE}:5:entry:Default fallback"),
                value: "stale-current".to_string(),
                default: Some("default-visible".to_string()),
                alternatives: Vec::new(),
            },
            DiscoveryPreference {
                key: format!("{NVT_ONE}:0:entry:timeout"),
                value: "300".to_string(),
                default: Some("300".to_string()),
                alternatives: Vec::new(),
            },
        ],
    });
    for key in [
        "cache_folder",
        "include_folders",
        "nasl_no_signature_check",
        "network_targets",
        "ntp_save_sessions",
        "SERVER_INFO_private",
        "max_checks",
        "max_hosts",
    ] {
        store.seed_discovery_scanner_preference(DiscoveryPreference {
            key: key.to_string(),
            value: format!("excluded-{key}"),
            default: None,
            alternatives: Vec::new(),
        });
    }

    let families = send_recv(
        &mut stream,
        b"<get_nvt_families sort_order=\"descending\"/>",
    )
    .await;
    let families = families.as_str().unwrap();
    assert!(families.contains("<families><family>"));
    assert!(families.contains("<max_nvt_count>1</max_nvt_count>"));
    assert!(families.find("Web application abuses").unwrap() < families.find("General").unwrap());

    let preferences = send_recv(
        &mut stream,
        format!("<get_preferences nvt_oid=\"{NVT_ONE}\" config_id=\"{CONFIG_ID}\"/>").as_bytes(),
    )
    .await;
    let preferences = preferences.as_str().unwrap();
    assert!(preferences.contains("<name>Password</name><type>password</type><value></value>"));
    assert!(preferences.contains("<name>Mode</name><type>radio</type><value>fast</value>"));
    assert!(preferences.contains("<default>safe</default><alt>safe</alt>"));
    assert!(preferences.contains("<name>Retries:with:suffix</name>"));
    assert!(!preferences.contains(":timeout"));

    let all_preferences = send_recv(&mut stream, b"<get_preferences/>").await;
    let all_preferences = all_preferences.as_str().unwrap();
    assert!(all_preferences.contains(
        "<nvt oid=\"\"><name></name></nvt><id>4</id><hr_name>Scanner option</hr_name><name>Scanner option</name>"
    ));
    for excluded in [
        "excluded-cache_folder",
        "excluded-include_folders",
        "excluded-nasl_no_signature_check",
        "excluded-network_targets",
        "excluded-ntp_save_sessions",
        "excluded-SERVER_INFO_private",
        "excluded-max_checks",
        "excluded-max_hosts",
    ] {
        assert!(!all_preferences.contains(excluded), "{excluded}");
    }

    let ignored_filter = send_recv(
        &mut stream,
        format!(
            "<get_preferences nvt_oid=\"{NVT_ONE}\" filter=\"name=Missing\" filt_id=\"missing\"/>"
        )
        .as_bytes(),
    )
    .await;
    let unfiltered = send_recv(
        &mut stream,
        format!("<get_preferences nvt_oid=\"{NVT_ONE}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(
        ignored_filter.as_str().unwrap(),
        unfiltered.as_str().unwrap()
    );

    let one = send_recv(
        &mut stream,
        format!("<get_preferences nvt_oid=\"{NVT_ONE}\" preference=\"radio:Mode\"/>").as_bytes(),
    )
    .await;
    let one = one.as_str().unwrap();
    assert!(one.contains("<name>Mode</name>"));
    assert!(one.contains("<value>safe</value>"));
    assert!(one.contains("<default>safe</default><alt>fast</alt>"));
    assert!(!one.contains("<name>Password</name>"));

    let first = send_recv(
        &mut stream,
        format!("<get_preferences nvt_oid=\"{NVT_ONE}\" preference=\"entry:First match\"/>")
            .as_bytes(),
    )
    .await;
    let first = first.as_str().unwrap();
    assert!(first.contains("<id>4</id>"));
    assert!(first.contains("<value>first-default</value>"));
    assert!(!first.contains("later-default"));

    let fallback = send_recv(
        &mut stream,
        format!("<get_preferences nvt_oid=\"{NVT_ONE}\" preference=\"entry:Default fallback\"/>")
            .as_bytes(),
    )
    .await;
    assert!(fallback
        .as_str()
        .unwrap()
        .contains("<value>default-visible</value><default>default-visible</default>"));

    let missing = send_recv(
        &mut stream,
        format!("<get_preferences nvt_oid=\"{NVT_ONE}\" preference=\"entry:Missing\"/>").as_bytes(),
    )
    .await;
    assert_eq!(missing.status_code(), Some(200));
    assert!(!missing.as_str().unwrap().contains("<preference>"));
    assert_eq!(
        send_recv(
            &mut stream,
            b"<get_preferences nvt_oid=\"unknown\" preference=\"entry:Missing\"/>"
        )
        .await
        .status_code(),
        Some(404)
    );
    server.shutdown().await;
}

#[tokio::test]
async fn secinfo_uses_authoritative_wrappers_and_bounded_filter_resolution() {
    let (server, store) = server().await;
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    for unsupported in [
        "<get_info/>",
        "<get_info type=\"os\"/>",
        "<get_info type=\"vuln\"/>",
        "<get_info type=\"vulnerability\"/>",
        "<get_info type=\"OVALDEF\"/>",
        "<get_info type=\"CVE\" info_id=\"x\" name=\"x\"/>",
    ] {
        assert_eq!(
            send_recv(&mut stream, unsupported.as_bytes())
                .await
                .status_code(),
            Some(400),
            "{unsupported}"
        );
    }

    let filtered = send_recv(
        &mut stream,
        b"<get_info type=\"cve\" filt_id=\"filter-1\" details=\"1\"/>",
    )
    .await;
    let filtered = filtered.as_str().unwrap();
    assert!(filtered.contains("<info id=\"CVE-2026-1000\">"));
    assert!(filtered.contains("<cve><raw_data>mock CVE-2026-1000</raw_data></cve>"));
    assert!(filtered.contains("<info_count>2<filtered>1</filtered><page>1</page>"));

    let default_filter = send_recv(&mut stream, b"<get_info type=\"CVE\" filt_id=\"-2\"/>").await;
    assert!(default_filter.as_str().unwrap().contains("CVE-2026-1001"));
    assert!(!default_filter.as_str().unwrap().contains("CVE-2026-1000"));

    let second_page = send_recv(
        &mut stream,
        b"<get_info type=\"CVE\" filter=\"sort=id first=2 rows=1\"/>",
    )
    .await;
    let second_page = second_page.as_str().unwrap();
    assert!(second_page.contains("CVE-2026-1001"));
    assert!(!second_page.contains("CVE-2026-1000"));
    assert!(second_page.contains("<info_count>2<filtered>2</filtered><page>1</page>"));

    let selected_name = send_recv(
        &mut stream,
        b"<get_info type=\"CVE\" name=\"Mock CVE one\" filter=\"name='Mock CVE two' first=2 rows=1\"/>",
    )
    .await;
    let selected_name = selected_name.as_str().unwrap();
    assert!(selected_name.contains("CVE-2026-1000"));
    assert!(!selected_name.contains("CVE-2026-1001"));
    assert!(selected_name.contains("<filtered>1</filtered><page>1</page>"));

    assert_eq!(
        send_recv(
            &mut stream,
            b"<get_info type=\"CVE\" info_id=\"CVE-2026-1000\" filter=\"malformed\"/>"
        )
        .await
        .status_code(),
        Some(400)
    );
    assert_eq!(
        send_recv(
            &mut stream,
            b"<get_info type=\"CVE\" info_id=\"CVE-2026-1000\" filt_id=\"missing\"/>"
        )
        .await
        .status_code(),
        Some(404)
    );

    store.set_discovery_user_default_filter(None);
    assert_eq!(
        send_recv(&mut stream, b"<get_info type=\"CVE\" filt_id=\"-2\"/>")
            .await
            .status_code(),
        Some(400)
    );
    store.set_discovery_user_default_filter(Some("name='Mock CVE two'".to_string()));

    store.set_secinfo_permitted(false);
    assert_eq!(
        send_recv(&mut stream, b"<get_info type=\"CVE\"/>")
            .await
            .status_code(),
        Some(403)
    );
    store.set_secinfo_permitted(true);
    store.set_discovery_availability(true, false, true);
    for request in [
        "<get_info type=\"CVE\"/>",
        "<get_info type=\"CERT_BUND_ADV\"/>",
        "<get_info type=\"unsupported\"/>",
        "<get_info/>",
    ] {
        assert_eq!(
            send_recv(&mut stream, request.as_bytes())
                .await
                .status_code(),
            Some(503),
            "SCAP prerequisite must precede dispatch: {request}"
        );
    }
    store.set_discovery_availability(true, true, false);
    for request in [
        "<get_info type=\"CVE\"/>",
        "<get_info type=\"unsupported\"/>",
    ] {
        assert_eq!(
            send_recv(&mut stream, request.as_bytes())
                .await
                .status_code(),
            Some(503),
            "CERT prerequisite must precede dispatch: {request}"
        );
    }
    store.set_discovery_availability(false, true, true);
    assert_eq!(
        send_recv(&mut stream, b"<get_info type=\"NVT\"/>")
            .await
            .status_code(),
        Some(503)
    );
    assert_eq!(
        send_recv(&mut stream, b"<get_info type=\"CVE\"/>")
            .await
            .status_code(),
        Some(200)
    );
    server.shutdown().await;
}

#[tokio::test]
async fn vulnerabilities_are_distinct_filterable_and_reads_are_immutable() {
    let (server, store) = server().await;
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let before = send_recv(&mut stream, b"<get_vulns/>").await;
    let before = before.as_str().unwrap().to_string();
    let resource_counts = ["config", "asset", "report"]
        .map(|resource_type| (resource_type, store.count(resource_type)));
    assert!(before.contains("<severity>9.8</severity><qod>95</qod>"));
    assert!(before.contains("<results><count>2</count></results>"));

    let filtered = send_recv(
        &mut stream,
        b"<get_vulns filter=\"min_qod=90 host=192.0.2.10 sort-reverse=severity rows=-1\"/>",
    )
    .await;
    let filtered = filtered.as_str().unwrap();
    assert!(filtered.contains("vuln-1"));
    assert!(!filtered.contains("vuln-2"));

    for context_filter in ["task_id=missing", "report_id=missing", "host=192.0.2.99"] {
        let response = send_recv(
            &mut stream,
            format!("<get_vulns filter=\"{context_filter}\"/>").as_bytes(),
        )
        .await;
        assert!(response
            .as_str()
            .unwrap()
            .contains("<filtered>0</filtered>"));
    }

    let page_one = send_recv(
        &mut stream,
        b"<get_vulns filter=\"sort=id first=1 rows=1\"/>",
    )
    .await;
    let page_two = send_recv(
        &mut stream,
        b"<get_vulns filter=\"sort=id first=2 rows=1\"/>",
    )
    .await;
    assert!(page_one.as_str().unwrap().contains("vuln-1"));
    assert!(!page_one.as_str().unwrap().contains("vuln-2"));
    assert!(page_two.as_str().unwrap().contains("vuln-2"));
    assert!(!page_two.as_str().unwrap().contains("vuln-1"));
    for page in [&page_one, &page_two] {
        assert!(page
            .as_str()
            .unwrap()
            .contains("<vuln_count>2<filtered>2</filtered><page>1</page>"));
    }

    let detail = send_recv(
        &mut stream,
        b"<get_vulns vuln_id=\"vuln-2\" filter=\"first=2 rows=1\"/>",
    )
    .await;
    assert!(detail.as_str().unwrap().contains("Weak configuration"));
    assert_eq!(
        send_recv(&mut stream, b"<get_vulns vuln_id=\"missing\"/>")
            .await
            .status_code(),
        Some(404)
    );
    assert_eq!(
        send_recv(&mut stream, b"<get_vulns filter=\"unsupported=x\"/>")
            .await
            .status_code(),
        Some(400)
    );

    let after = send_recv(&mut stream, b"<get_vulns/>").await;
    assert_eq!(after.as_str().unwrap(), before);
    for (resource_type, count) in resource_counts {
        assert_eq!(store.count(resource_type), count, "{resource_type}");
    }
    server.shutdown().await;
}
