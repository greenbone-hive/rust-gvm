// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_gmp::commands::reports::{
    CancelReportExportRequest, DownloadReportExportRequest, ExportAuditReportRequest,
    ExportDeltaAuditReportRequest, ExportDeltaScanReportRequest, ExportScanReportRequest,
    GetReportExportsRequest,
};
use gvm_gmp::responses::{DownloadReportExportResponse, GetReportExportsResponse};
use gvm_gmp::{EntityId, GmpRequestCodec, GmpResponse};
use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const REPORT_ID: &str = "11111111-1111-1111-1111-111111111111";
const AUDIT_REPORT_ID: &str = "22222222-2222-2222-2222-222222222222";
const DELTA_REPORT_ID: &str = "33333333-3333-3333-3333-333333333333";
const SCAN_BASELINE_ID: &str = "55555555-5555-5555-5555-555555555555";
const AUDIT_BASELINE_ID: &str = "66666666-6666-6666-6666-666666666666";

async fn stateful_server(version: GmpVersion) -> Option<MockGmpServer> {
    let report_id = Uuid::parse_str(REPORT_ID).expect("valid UUID");
    let audit_report_id = Uuid::parse_str(AUDIT_REPORT_ID).expect("valid UUID");
    let delta_report_id = Uuid::parse_str(DELTA_REPORT_ID).expect("valid UUID");
    let scan_baseline_id = Uuid::parse_str(SCAN_BASELINE_ID).expect("valid UUID");
    let audit_baseline_id = Uuid::parse_str(AUDIT_BASELINE_ID).expect("valid UUID");
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .seed(move |store| {
            store.create(Resource::with_id("report", "Scan report", report_id));
            let mut audit_report = Resource::with_id("report", "Audit report", audit_report_id);
            audit_report.set_attr("usage_type", "audit");
            store.create(audit_report);
            let mut delta_report = Resource::with_id("report", "Delta report", delta_report_id);
            delta_report.set_attr("delta", "1");
            store.create(delta_report);
            store.create(Resource::with_id(
                "report",
                "Scan baseline",
                scan_baseline_id,
            ));
            let mut audit_baseline =
                Resource::with_id("report", "Audit baseline", audit_baseline_id);
            audit_baseline.set_attr("usage_type", "audit");
            store.create(audit_baseline);
        })
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error)
            if error.to_string().contains("Permission denied")
                || error.to_string().contains("Operation not permitted") =>
        {
            eprintln!("Skipping: sandbox restriction");
            None
        }
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn send_recv(stream: &mut UnixStream, request: impl Request) -> Response {
    stream
        .write_all(&request.to_bytes())
        .await
        .expect("request write");
    let mut bytes = vec![0; 16 * 1024];
    let size = stream.read(&mut bytes).await.expect("response read");
    bytes.truncate(size);
    Response::new(bytes)
}

async fn send_recv_export(stream: &mut UnixStream, request: &ExportScanReportRequest) -> Response {
    stream
        .write_all(&request.encode(gvm_gmp::GmpVersion(22, 8)).expect("encode"))
        .await
        .expect("request write");
    let mut bytes = vec![0; 16 * 1024];
    let size = stream.read(&mut bytes).await.expect("response read");
    bytes.truncate(size);
    Response::new(bytes)
}

async fn send_recv_codec(stream: &mut UnixStream, request: &impl GmpRequestCodec) -> Response {
    stream
        .write_all(&request.encode(gvm_gmp::GmpVersion(22, 8)).expect("encode"))
        .await
        .expect("request write");
    let mut bytes = vec![0; 16 * 1024];
    let size = stream.read(&mut bytes).await.expect("response read");
    bytes.truncate(size);
    Response::new(bytes)
}

async fn assert_created_and_reused(server: &MockGmpServer, stream: &mut UnixStream) {
    let help = send_recv(stream, b"<help format=\"xml\" type=\"brief\"/>".as_slice()).await;
    assert_eq!(help.status_code(), Some(200));
    assert!(help
        .as_str()
        .expect("help UTF-8")
        .contains("<name>export_scan_report</name>"));

    let report_id = EntityId::new(REPORT_ID).expect("valid entity id");
    let export_request = || ExportScanReportRequest {
        report_id: report_id.clone(),
        report_format_id: None,
        report_config_id: None,
        filter_string: Some("severity>5 & rows=10".into()),
        ignore_pagination: None,
        lean: None,
        notes_details: Some(true),
        overrides_details: None,
        result_tags: None,
    };
    let created = send_recv_export(stream, &export_request()).await;
    assert_eq!(created.status_code(), Some(201));
    assert!(created
        .as_str()
        .expect("created UTF-8")
        .contains("OK, resource created"));
    let created_id = created.id().expect("created export id");

    let reused = send_recv_export(stream, &export_request()).await;
    assert_eq!(reused.status_code(), Some(200));
    assert_eq!(reused.id().as_deref(), Some(created_id.as_str()));
    assert!(reused
        .as_str()
        .expect("reused UTF-8")
        .contains("export_status=\"pending\""));

    let request = server
        .command_history()
        .into_iter()
        .rev()
        .find(|record| record.command_name() == "export_scan_report")
        .expect("export request");
    let xml = std::str::from_utf8(request.raw_xml()).expect("request UTF-8");
    assert!(xml.contains(r#"filter="severity&gt;5 &amp; rows=10""#));
    assert!(xml.contains(r#"notes_details="1""#));
}

async fn assert_validation_errors(stream: &mut UnixStream) {
    let invalid = send_recv_export(
        stream,
        &ExportScanReportRequest::new(
            EntityId::new("not-a-uuid").expect("valid protocol entity id"),
        ),
    )
    .await;
    assert_eq!(invalid.status_code(), Some(400));
    assert_eq!(
        invalid.status_text().as_deref(),
        Some("Missing or invalid report_id")
    );

    let missing = send_recv_export(
        stream,
        &ExportScanReportRequest::new(
            EntityId::new("44444444-4444-4444-4444-444444444444").expect("valid entity id"),
        ),
    )
    .await;
    assert_eq!(missing.status_code(), Some(404));
    assert_eq!(
        missing.status_text().as_deref(),
        Some("Failed to find report")
    );

    for report_id in [AUDIT_REPORT_ID, DELTA_REPORT_ID] {
        let response = send_recv_export(
            stream,
            &ExportScanReportRequest::new(EntityId::new(report_id).expect("valid entity id")),
        )
        .await;
        assert_eq!(response.status_code(), Some(400));
        assert_eq!(
            response.status_text().as_deref(),
            Some("Report is not a scan report")
        );
    }
}

async fn assert_pre_22_7_unsupported() {
    let Some(server) = stateful_server(GmpVersion::V22_6).await else {
        return;
    };
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect");
    let _ = send_recv(&mut stream, b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>".as_slice()).await;
    let unsupported = send_recv_export(
        &mut stream,
        &ExportScanReportRequest::new(EntityId::new(REPORT_ID).expect("valid entity id")),
    )
    .await;
    assert_eq!(unsupported.status_code(), Some(400));
    assert!(unsupported
        .status_text()
        .expect("status text")
        .contains("not available in GMP 22.6"));
    server.shutdown().await;
}

#[tokio::test]
async fn stateful_mock_rejects_invalid_inputs_and_pre_22_7_command_use() {
    let Some(server) = stateful_server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect");
    assert_eq!(
        send_recv(&mut stream, b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>".as_slice())
            .await
            .status_code(),
        Some(200)
    );

    assert_created_and_reused(&server, &mut stream).await;
    assert_validation_errors(&mut stream).await;
    server.shutdown().await;
    assert_pre_22_7_unsupported().await;
}

#[tokio::test]
async fn stateful_mock_models_the_seven_command_export_lifecycle() {
    let Some(server) = stateful_server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect");
    assert_eq!(
        send_recv(&mut stream, b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>".as_slice())
            .await
            .status_code(),
        Some(200)
    );

    let scan = send_recv_codec(
        &mut stream,
        &ExportScanReportRequest::new(EntityId::new(REPORT_ID).expect("id")),
    )
    .await;
    assert_eq!(scan.status_code(), Some(201));
    let scan_export_id = EntityId::new(scan.id().expect("export id")).expect("id");

    let audit = send_recv_codec(
        &mut stream,
        &ExportAuditReportRequest::new(EntityId::new(AUDIT_REPORT_ID).expect("id")),
    )
    .await;
    assert_eq!(audit.status_code(), Some(201));
    assert!(audit
        .as_str()
        .expect("UTF-8")
        .contains("export_status=\"pending\""));

    let delta_scan = send_recv_codec(
        &mut stream,
        &ExportDeltaScanReportRequest::new(
            EntityId::new(REPORT_ID).expect("id"),
            EntityId::new(SCAN_BASELINE_ID).expect("id"),
        ),
    )
    .await;
    assert_eq!(delta_scan.status_code(), Some(201));

    let delta_audit = send_recv_codec(
        &mut stream,
        &ExportDeltaAuditReportRequest::new(
            EntityId::new(AUDIT_REPORT_ID).expect("id"),
            EntityId::new(AUDIT_BASELINE_ID).expect("id"),
        ),
    )
    .await;
    assert_eq!(delta_audit.status_code(), Some(201));

    let poll = GetReportExportsRequest::new(scan_export_id.clone());
    for expected in ["pending", "running", "done"] {
        let response = send_recv_codec(&mut stream, &poll).await;
        let parsed = GetReportExportsResponse::decode(&response, gvm_gmp::GmpVersion(22, 7))
            .expect("poll response");
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].status, expected);
    }

    let downloaded = send_recv_codec(
        &mut stream,
        &DownloadReportExportRequest::new(scan_export_id.clone()),
    )
    .await;
    let downloaded = DownloadReportExportResponse::decode(&downloaded, gvm_gmp::GmpVersion(22, 7))
        .expect("download response");
    assert_eq!(downloaded.report_export.status, "done");
    assert!(!downloaded.report_export.bytes.is_empty());
    assert_eq!(
        send_recv_codec(&mut stream, &poll).await.status_code(),
        Some(404),
        "successful download consumes the export"
    );

    let mut cancel_request =
        ExportAuditReportRequest::new(EntityId::new(AUDIT_REPORT_ID).expect("audit report id"));
    cancel_request.filter_string = Some("compliance_levels=y".into());
    let pending = send_recv_codec(&mut stream, &cancel_request).await;
    let pending_id = EntityId::new(pending.id().expect("pending id")).expect("id");
    assert_eq!(
        send_recv_codec(
            &mut stream,
            &CancelReportExportRequest::new(pending_id.clone())
        )
        .await
        .status_code(),
        Some(200)
    );
    let canceled = send_recv_codec(
        &mut stream,
        &GetReportExportsRequest::new(pending_id.clone()),
    )
    .await;
    let canceled = GetReportExportsResponse::decode(&canceled, gvm_gmp::GmpVersion(22, 7))
        .expect("canceled response");
    assert_eq!(canceled.items[0].status, "canceled");

    let mut running_request =
        ExportAuditReportRequest::new(EntityId::new(AUDIT_REPORT_ID).expect("audit report id"));
    running_request.filter_string = Some("compliance_levels=n".into());
    let running = send_recv_codec(&mut stream, &running_request).await;
    let running_id = EntityId::new(running.id().expect("running id")).expect("id");
    let running_poll = GetReportExportsRequest::new(running_id.clone());
    let _ = send_recv_codec(&mut stream, &running_poll).await;
    assert_eq!(
        send_recv_codec(
            &mut stream,
            &CancelReportExportRequest::new(running_id.clone())
        )
        .await
        .status_code(),
        Some(200)
    );
    for expected in ["cancel_requested", "canceled"] {
        let response = send_recv_codec(&mut stream, &running_poll).await;
        let parsed = GetReportExportsResponse::decode(&response, gvm_gmp::GmpVersion(22, 7))
            .expect("cancellation poll");
        assert_eq!(parsed.items[0].status, expected);
    }

    server.shutdown().await;
}
