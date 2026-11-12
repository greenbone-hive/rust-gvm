// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(
    missing_docs,
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use gvm_client::{GmpClient, GmpVersioned, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::nvts::{
    GetNvtFamiliesRequest, GetNvtPreferenceRequest, GetNvtPreferencesRequest, GetNvtRequest,
    GetNvtsRequest, GetScanConfigNvtRequest, GetScanConfigNvtsRequest,
};
use gvm_gmp::commands::secinfo::{
    GenericInfoType, GetCertBundAdvisoriesRequest, GetCertBundAdvisoryRequest, GetCpeRequest,
    GetCpesRequest, GetCveRequest, GetCvesRequest, GetDfnCertAdvisoriesRequest,
    GetDfnCertAdvisoryRequest, GetInfoListRequest, GetInfoRequest,
};
use gvm_gmp::commands::system::{GetVulnerabilityRequest, GetVulnsRequest};
use gvm_gmp::{EntityId, GmpRequestError};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

const CONFIG_ID: &str = "daba56c8-73ec-11df-a475-002264764cea";
const NVT_OID: &str = "1.3.6.1.4.1.25623.1";

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid ID")
}

fn connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("Unix socket"))
}

async fn fixture(version: MockVersion) -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto()
        .build()
        .await
        .expect("fixture server starts")
}

async fn epss_fixture() -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(MockVersion::V22_8)
        .override_response(
            "get_nvts",
            r#"<get_nvts_response status="200" status_text="OK">
                <nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>EPSS NVT</name><refs><ref type="dfn-cert" id="DFN-CERT-2026-0002"/><ref type="unknown" id="opaque-catalog-ref"/></refs><epss>
                    <max_severity><score>0.12345</score><percentile>98.76500</percentile><cve id="CVE-2026-0001"><severity>9.8</severity></cve></max_severity>
                    <max_epss><score>0.54321</score><percentile>99.50000</percentile><cve id="CVE-2026-0002"/></max_epss>
                </epss></nvt>
                <nvt oid="1.3.6.1.4.1.25623.1.0.2"><name>Older NVT</name></nvt>
                <nvt_count>2<filtered>2</filtered><page>2</page></nvt_count>
            </get_nvts_response>"#,
        )
        .unix_socket_auto()
        .build()
        .await
        .expect("EPSS fixture server starts")
}

async fn execute_all_direct(client: &mut GmpClient<UnixSocketConnection>) {
    client.execute(GetNvtsRequest::default()).await.unwrap();
    client.execute(GetNvtRequest::new(NVT_OID)).await.unwrap();
    client
        .execute(GetScanConfigNvtsRequest::new(id(CONFIG_ID), "General"))
        .await
        .unwrap();
    client
        .execute(GetScanConfigNvtRequest::new(NVT_OID))
        .await
        .unwrap();
    client
        .execute(GetNvtPreferencesRequest::default())
        .await
        .unwrap();
    client
        .execute(GetNvtPreferenceRequest::new("radio:Mode"))
        .await
        .unwrap();
    client.execute(GetNvtFamiliesRequest::new()).await.unwrap();
    client
        .execute(GetInfoListRequest::new(GenericInfoType::Nvt))
        .await
        .unwrap();
    client
        .execute(GetInfoRequest::new("CVE-2026-1000", GenericInfoType::Cve))
        .await
        .unwrap();
    client.execute(GetCpesRequest::default()).await.unwrap();
    client
        .execute(GetCpeRequest::new("cpe:/a:greenbone:gvm"))
        .await
        .unwrap();
    client.execute(GetCvesRequest::default()).await.unwrap();
    client
        .execute(GetCveRequest::new("CVE-2026-1000"))
        .await
        .unwrap();
    client
        .execute(GetCertBundAdvisoriesRequest::default())
        .await
        .unwrap();
    client
        .execute(GetCertBundAdvisoryRequest::new("CB-K26/001"))
        .await
        .unwrap();
    client
        .execute(GetDfnCertAdvisoriesRequest::default())
        .await
        .unwrap();
    client
        .execute(GetDfnCertAdvisoryRequest::new("DFN-2026-001"))
        .await
        .unwrap();
    client.execute(GetVulnsRequest::default()).await.unwrap();
    client
        .execute(GetVulnerabilityRequest::new("vuln-1"))
        .await
        .unwrap();
}

async fn execute_all_facades(client: &mut GmpClient<UnixSocketConnection>) {
    client.get_nvts(GetNvtsRequest::default()).await.unwrap();
    client.get_nvt(GetNvtRequest::new(NVT_OID)).await.unwrap();
    client
        .get_scan_config_nvts(GetScanConfigNvtsRequest::new(id(CONFIG_ID), "General"))
        .await
        .unwrap();
    client
        .get_scan_config_nvt(GetScanConfigNvtRequest::new(NVT_OID))
        .await
        .unwrap();
    client
        .get_nvt_preferences(GetNvtPreferencesRequest::default())
        .await
        .unwrap();
    client
        .get_nvt_preference(GetNvtPreferenceRequest::new("radio:Mode"))
        .await
        .unwrap();
    client
        .get_nvt_families(GetNvtFamiliesRequest::new())
        .await
        .unwrap();
    client
        .get_info_list(GetInfoListRequest::new(GenericInfoType::Nvt))
        .await
        .unwrap();
    client
        .get_info(GetInfoRequest::new("CVE-2026-1000", GenericInfoType::Cve))
        .await
        .unwrap();
    client.get_cpes(GetCpesRequest::default()).await.unwrap();
    client
        .get_cpe(GetCpeRequest::new("cpe:/a:greenbone:gvm"))
        .await
        .unwrap();
    client.get_cves(GetCvesRequest::default()).await.unwrap();
    client
        .get_cve(GetCveRequest::new("CVE-2026-1000"))
        .await
        .unwrap();
    client
        .get_cert_bund_advisories(GetCertBundAdvisoriesRequest::default())
        .await
        .unwrap();
    client
        .get_cert_bund_advisory(GetCertBundAdvisoryRequest::new("CB-K26/001"))
        .await
        .unwrap();
    client
        .get_dfn_cert_advisories(GetDfnCertAdvisoriesRequest::default())
        .await
        .unwrap();
    client
        .get_dfn_cert_advisory(GetDfnCertAdvisoryRequest::new("DFN-2026-001"))
        .await
        .unwrap();
    client
        .get_vulnerabilities(GetVulnsRequest::default())
        .await
        .unwrap();
    client
        .get_vulnerability(GetVulnerabilityRequest::new("vuln-1"))
        .await
        .unwrap();
}

#[tokio::test]
async fn nineteen_direct_requests_and_value_facades_emit_identical_wire() {
    for version in [MockVersion::V22_4, MockVersion::V22_8] {
        let server = fixture(version).await;
        let mut client = GmpClient::connect(connection(&server)).await.unwrap();
        server.clear_history();
        execute_all_direct(&mut client).await;
        execute_all_facades(&mut client).await;
        let history: Vec<_> = server
            .command_history()
            .iter()
            .map(|entry| entry.raw_xml().to_vec())
            .collect();
        assert_eq!(history.len(), 38);
        assert_eq!(&history[..19], &history[19..]);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn typed_client_projects_present_and_absent_nvt_epss() {
    let server = epss_fixture().await;
    let mut client = GmpClient::connect(connection(&server)).await.unwrap();
    let response = client
        .get_nvts(GetNvtsRequest {
            details: Some(true),
            ..GetNvtsRequest::default()
        })
        .await
        .unwrap();
    let epss = response.items[0].epss.as_ref().expect("EPSS is projected");

    assert_eq!(epss.max_severity.cve.id, "CVE-2026-0001");
    assert_eq!(epss.max_severity.percentile, "98.76500");
    assert_eq!(epss.max_epss.cve.id, "CVE-2026-0002");
    assert_eq!(epss.max_epss.cve.severity, None);
    assert_eq!(epss.max_epss.score_value(), Some(0.54321));
    assert_eq!(response.items[0].refs.len(), 2);
    assert_eq!(response.items[0].refs[0].type_, "dfn-cert");
    assert_eq!(response.items[0].refs[0].id, "DFN-CERT-2026-0002");
    assert_eq!(response.items[0].refs[1].type_, "unknown");
    assert_eq!(response.items[1].epss, None);
    assert!(response.items[1].refs.is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn all_semantic_aliases_are_supported_across_the_protected_range() {
    for version in [
        MockVersion::V22_4,
        MockVersion::V22_5,
        MockVersion::V22_6,
        MockVersion::V22_7,
        MockVersion::V22_8,
    ] {
        let server = fixture(version).await;
        let mut client = GmpVersioned::connect(connection(&server)).await.unwrap();
        server.clear_history();
        client.execute(GetNvtRequest::new(NVT_OID)).await.unwrap();
        client
            .execute(GetScanConfigNvtsRequest::new(id(CONFIG_ID), "General"))
            .await
            .unwrap();
        client
            .execute(GetScanConfigNvtRequest::new(NVT_OID))
            .await
            .unwrap();
        client
            .execute(GetNvtPreferencesRequest::default())
            .await
            .unwrap();
        client
            .execute(GetNvtPreferenceRequest::new("radio:Mode"))
            .await
            .unwrap();
        client
            .execute(GetInfoListRequest::new(GenericInfoType::Nvt))
            .await
            .unwrap();
        client.execute(GetCpesRequest::default()).await.unwrap();
        client
            .execute(GetCpeRequest::new("cpe:/a:greenbone:gvm"))
            .await
            .unwrap();
        client.execute(GetCvesRequest::default()).await.unwrap();
        client
            .execute(GetCveRequest::new("CVE-2026-1000"))
            .await
            .unwrap();
        client
            .execute(GetCertBundAdvisoriesRequest::default())
            .await
            .unwrap();
        client
            .execute(GetCertBundAdvisoryRequest::new("CB-K26/001"))
            .await
            .unwrap();
        client
            .execute(GetDfnCertAdvisoriesRequest::default())
            .await
            .unwrap();
        client
            .execute(GetDfnCertAdvisoryRequest::new("DFN-2026-001"))
            .await
            .unwrap();
        client.execute(GetVulnsRequest::default()).await.unwrap();
        client
            .execute(GetVulnerabilityRequest::new("vuln-1"))
            .await
            .unwrap();
        assert_eq!(server.command_count(), 16);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn final_value_mutations_fail_before_io_without_echoing_payloads() {
    let server = fixture(MockVersion::V22_8).await;
    let mut client = GmpClient::connect(connection(&server)).await.unwrap();
    server.clear_history();

    let mut nvt = GetNvtRequest::new("private-oid");
    nvt.nvt_oid.clear();
    let mut list = GetNvtsRequest::default();
    list.details = Some(false);
    list.preferences = Some(true);
    let mut info = GetInfoRequest::new("private-info-id", GenericInfoType::Cve);
    info.info_id.clear();
    let mut info_list = GetInfoListRequest::new(GenericInfoType::Cve);
    info_list.filter_string = Some("private-filter\0payload".to_string());
    let mut vulnerability = GetVulnerabilityRequest::new("private-vulnerability-id");
    vulnerability.vulnerability_id.clear();

    for error in [
        client.execute(nvt).await.unwrap_err(),
        client.execute(list).await.unwrap_err(),
        client.execute(info).await.unwrap_err(),
        client.execute(info_list).await.unwrap_err(),
        client.execute(vulnerability).await.unwrap_err(),
    ] {
        assert!(matches!(
            error,
            GvmError::Request(
                GmpRequestError::InvalidField { .. } | GmpRequestError::InvalidCombination { .. }
            )
        ));
        let diagnostic = format!("{error:?} {error}");
        for secret in [
            "private-oid",
            "private-info-id",
            "private-filter",
            "private-vulnerability-id",
        ] {
            assert!(!diagnostic.contains(secret));
        }
    }
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn all_facades_normalize_server_errors() {
    let error = |root: &str| {
        format!("<{root}_response status=\"409\" status_text=\"discovery conflict\"/>")
    };
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .override_response("get_nvts", &error("get_nvts"))
        .override_response("get_nvt_families", &error("get_nvt_families"))
        .override_response("get_preferences", &error("get_preferences"))
        .override_response("get_info", &error("get_info"))
        .override_response("get_vulns", &error("get_vulns"))
        .build()
        .await
        .unwrap();
    let mut client = GmpClient::connect(connection(&server)).await.unwrap();
    let errors = [
        client
            .get_nvts(GetNvtsRequest::default())
            .await
            .unwrap_err(),
        client
            .get_nvt(GetNvtRequest::new(NVT_OID))
            .await
            .unwrap_err(),
        client
            .get_scan_config_nvts(GetScanConfigNvtsRequest::new(id(CONFIG_ID), "General"))
            .await
            .unwrap_err(),
        client
            .get_scan_config_nvt(GetScanConfigNvtRequest::new(NVT_OID))
            .await
            .unwrap_err(),
        client
            .get_nvt_preferences(GetNvtPreferencesRequest::default())
            .await
            .unwrap_err(),
        client
            .get_nvt_preference(GetNvtPreferenceRequest::new("radio:Mode"))
            .await
            .unwrap_err(),
        client
            .get_nvt_families(GetNvtFamiliesRequest::new())
            .await
            .unwrap_err(),
        client
            .get_info_list(GetInfoListRequest::new(GenericInfoType::Nvt))
            .await
            .unwrap_err(),
        client
            .get_info(GetInfoRequest::new("CVE-2026-1000", GenericInfoType::Cve))
            .await
            .unwrap_err(),
        client
            .get_cpes(GetCpesRequest::default())
            .await
            .unwrap_err(),
        client
            .get_cpe(GetCpeRequest::new("cpe:/a:greenbone:gvm"))
            .await
            .unwrap_err(),
        client
            .get_cves(GetCvesRequest::default())
            .await
            .unwrap_err(),
        client
            .get_cve(GetCveRequest::new("CVE-2026-1000"))
            .await
            .unwrap_err(),
        client
            .get_cert_bund_advisories(GetCertBundAdvisoriesRequest::default())
            .await
            .unwrap_err(),
        client
            .get_cert_bund_advisory(GetCertBundAdvisoryRequest::new("CB-K26/001"))
            .await
            .unwrap_err(),
        client
            .get_dfn_cert_advisories(GetDfnCertAdvisoriesRequest::default())
            .await
            .unwrap_err(),
        client
            .get_dfn_cert_advisory(GetDfnCertAdvisoryRequest::new("DFN-2026-001"))
            .await
            .unwrap_err(),
        client
            .get_vulnerabilities(GetVulnsRequest::default())
            .await
            .unwrap_err(),
        client
            .get_vulnerability(GetVulnerabilityRequest::new("vuln-1"))
            .await
            .unwrap_err(),
    ];
    for error in errors {
        assert!(matches!(
            error,
            GvmError::Server { status: 409, message } if message == "discovery conflict"
        ));
    }
    server.shutdown().await;
}
