// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::reports::*;
use gvm_gmp::{GmpRequestCodec, GmpVersion};

#[test]
fn test_import_report_basic() {
    let report_xml = r#"<report id="r1"><name>Imported</name></report>"#;
    let request = ImportReportRequest::new(id("t1"), report_xml);

    assert_eq!(
        String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap(),
        r#"<create_report><report id="r1"><name>Imported</name></report><task id="t1"/></create_report>"#
    );
}

#[test]
fn test_import_report_with_in_assets() {
    let report_xml = r#"<report id="r1"><name>Imported</name></report>"#;
    let mut request = ImportReportRequest::new(id("t1"), report_xml);
    request.in_assets = Some(false);
    assert_eq!(
        String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap(),
        r#"<create_report><report id="r1"><name>Imported</name></report><task id="t1"/><in_assets>0</in_assets></create_report>"#
    );
}

#[test]
fn test_import_report_preserves_original_envelope_bytes_and_redacts_debug() {
    let report_xml =
        b"<report id=\"r1\">\n  <!--opaque--><name><![CDATA[Private & exact]]></name>\n</report>";
    let request = ImportReportRequest::new(id("t1"), report_xml);
    let encoded = request.encode(GmpVersion(22, 8)).unwrap();
    assert_eq!(
        encoded,
        [
            b"<create_report>".as_slice(),
            report_xml.as_slice(),
            b"<task id=\"t1\"/></create_report>".as_slice(),
        ]
        .concat()
    );
    let debug = format!("{request:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("Private"));
}

#[test]
fn test_import_report_rejects_invalid_report_xml() {
    for invalid in [
        b"report".as_slice(),
        b"",
        b"<foo/>",
        br#"<?xml version="1.0"?><report id="r1"/>"#,
        br#"<!DOCTYPE report><report id="r1"/>"#,
        br#"<report id="r1"/><report id="r2"/>"#,
        b"\xff<report/>",
    ] {
        let request = ImportReportRequest::new(id("t1"), invalid);
        let error = request.validate().expect_err("invalid report envelope");
        assert!(!error.to_string().contains("r1"));
    }
}

#[test]
fn test_report_get_and_delete() {
    let report = GetReportRequest::new(id("r1"));
    assert_eq!(
        String::from_utf8(report.encode(GmpVersion(22, 6)).unwrap()).unwrap(),
        "<get_reports details=\"1\" report_id=\"r1\" usage_type=\"scan\"/>"
    );
    assert_eq!(
        xml(get_report_export(&id("r1"), &id("rf1"))),
        "<get_reports details=\"1\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
    let delete = DeleteReportRequest::new(id("r1"));
    assert_eq!(
        String::from_utf8(delete.encode(GmpVersion(22, 4)).unwrap()).unwrap(),
        "<delete_report report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_list_and_detail_own_every_source_query_control() {
    let list = GetReportsRequest {
        filter_string: Some("sort-reverse=date rows=20".into()),
        filter_id: Some(id("report-filter")),
        details: Some(true),
        ignore_pagination: Some(false),
        notes_details: Some(true),
        overrides_details: Some(false),
        result_tags: Some(true),
        lean: Some(false),
    };
    assert_eq!(
        String::from_utf8(list.encode(GmpVersion(22, 6)).unwrap()).unwrap(),
        "<get_reports details=\"1\" ignore_pagination=\"0\" lean=\"0\" notes_details=\"1\" overrides_details=\"0\" report_filt_id=\"report-filter\" report_filter=\"sort-reverse=date rows=20\" result_tags=\"1\" usage_type=\"scan\"/>"
    );
    assert_eq!(
        String::from_utf8(
            GetReportsRequest::default()
                .encode(GmpVersion(22, 5))
                .unwrap()
        )
        .unwrap(),
        "<get_reports/>"
    );

    let detail = GetReportRequest {
        report_id: id("report"),
        filter_string: Some("levels=hm rows=10".into()),
        filter_id: Some(id("result-filter")),
        details: Some(false),
        ignore_pagination: Some(true),
        lean: Some(true),
        notes_details: Some(false),
        overrides_details: Some(true),
        result_tags: Some(false),
    };
    assert_eq!(
        String::from_utf8(detail.encode(GmpVersion(22, 6)).unwrap()).unwrap(),
        "<get_reports details=\"0\" filt_id=\"result-filter\" filter=\"levels=hm rows=10\" ignore_pagination=\"1\" lean=\"1\" notes_details=\"0\" overrides_details=\"1\" report_id=\"report\" result_tags=\"0\" usage_type=\"scan\"/>"
    );
}

#[test]
fn test_audit_list_and_delete_have_distinct_semantics_without_ultimate() {
    let list = GetAuditReportsRequest {
        filter_string: Some("rows=-1".into()),
        details: Some(true),
        lean: Some(true),
        ..Default::default()
    };
    assert_eq!(
        list.command().and_then(gvm_gmp::GmpCommand::semantic_name),
        Some("get_audit_reports")
    );
    assert_eq!(
        String::from_utf8(list.encode(GmpVersion(22, 6)).unwrap()).unwrap(),
        "<get_reports details=\"1\" lean=\"1\" report_filter=\"rows=-1\" usage_type=\"audit\"/>"
    );

    let delete = DeleteAuditReportRequest::new(id("audit-report"));
    assert_eq!(
        delete
            .command()
            .and_then(gvm_gmp::GmpCommand::semantic_name),
        Some("delete_audit_report")
    );
    assert_eq!(
        String::from_utf8(delete.encode(GmpVersion(22, 6)).unwrap()).unwrap(),
        "<delete_report report_id=\"audit-report\"/>"
    );
}

#[test]
fn test_get_scan_report_with_filters() {
    let mut request = GetScanReportRequest::new(id("r1"));
    request.filter_string = Some("levels=chml min_qod=70".into());
    request.filter_id = Some(id("f1"));
    assert_eq!(
        String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap(),
        "<get_scan_report filt_id=\"f1\" filter=\"levels=chml min_qod=70\" scan_report_id=\"r1\"/>"
    );
}

#[test]
fn test_get_scan_report_without_filters() {
    assert_eq!(
        String::from_utf8(
            GetScanReportRequest::new(id("r1"))
                .encode(GmpVersion(22, 8))
                .unwrap()
        )
        .unwrap(),
        "<get_scan_report scan_report_id=\"r1\"/>"
    );
}

#[test]
fn test_get_audit_report_matches_current_schema_example() {
    let mut request = GetAuditReportRequest::new(id("c00e2b2b-6b3a-4be9-a6df-337f76262fe0"));
    request.filter_string = Some("compliance_levels=yniu min_qod=70".into());
    assert_eq!(
        String::from_utf8(request.encode(GmpVersion(22, 7)).unwrap()).unwrap(),
        "<get_audit_report audit_report_id=\"c00e2b2b-6b3a-4be9-a6df-337f76262fe0\" filter=\"compliance_levels=yniu min_qod=70\"/>"
    );
}

#[test]
fn test_get_audit_report_hosts_serializes_schema_attributes() {
    let mut request = GetAuditReportHostsRequest::new(id("6587438c-4787-41e6-a0a7-765193dcd44f"));
    request.filter_string =
        Some("levels=yniu rows=10 min_qod=70 first=1 sort-reverse=severity".into());
    request.filter_id = Some(id("f1"));
    request.lean = Some(true);
    request.details = Some(true);
    assert_eq!(
        String::from_utf8(request.encode(GmpVersion(22, 7)).unwrap()).unwrap(),
        "<get_audit_report_hosts details=\"1\" filt_id=\"f1\" filter=\"levels=yniu rows=10 min_qod=70 first=1 sort-reverse=severity\" lean=\"1\" report_id=\"6587438c-4787-41e6-a0a7-765193dcd44f\"/>"
    );
}

#[test]
fn test_report_export_with_report_config() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.report_config_id = Some(id("rc1"));

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports config_id=\"rc1\" details=\"1\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_export_with_filter_string() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.filter_string = Some("severity>5".into());

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports details=\"1\" filter=\"severity&gt;5\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_export_with_filter_id() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.filter_id = Some(id("f1"));

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports details=\"1\" filt_id=\"f1\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
}

#[test]
fn test_report_export_with_combined_options() {
    let mut opts = GetReportExportOpts::new(id("rf1"));
    opts.report_config_id = Some(id("rc1"));
    opts.filter_string = Some("severity>5".into());
    opts.filter_id = Some(id("f1"));

    assert_eq!(
        xml(get_report_export_with_opts(&id("r1"), opts)),
        "<get_reports config_id=\"rc1\" details=\"1\" filt_id=\"f1\" filter=\"severity&gt;5\" format_id=\"rf1\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
}

#[test]
fn test_export_scan_report_with_all_current_attributes_and_escaping() {
    assert_eq!(
        xml(export_scan_report(
            &id("11111111-1111-1111-1111-111111111111"),
            ExportScanReportOpts {
                format_id: Some(id("22222222-2222-2222-2222-222222222222")),
                config_id: Some(id("33333333-3333-3333-3333-333333333333")),
                filter_string: Some("severity>5 & name='quoted'".into()),
                ignore_pagination: Some(true),
                lean: Some(false),
                notes_details: Some(true),
                overrides_details: Some(false),
                result_tags: Some(true),
            },
        )),
        "<export_scan_report config_id=\"33333333-3333-3333-3333-333333333333\" filter=\"severity&gt;5 &amp; name=&apos;quoted&apos;\" format_id=\"22222222-2222-2222-2222-222222222222\" ignore_pagination=\"1\" lean=\"0\" notes_details=\"1\" overrides_details=\"0\" report_id=\"11111111-1111-1111-1111-111111111111\" result_tags=\"1\"/>"
    );
}

#[test]
fn test_export_scan_report_allows_source_default_format() {
    assert_eq!(
        xml(export_scan_report(
            &id("11111111-1111-1111-1111-111111111111"),
            ExportScanReportOpts::default(),
        )),
        "<export_scan_report report_id=\"11111111-1111-1111-1111-111111111111\"/>"
    );
}

#[test]
fn test_report_helper_commands() {
    assert_eq!(
        xml(get_report_hosts(
            &id("r1"),
            GetReportDetailsOpts {
                filter_string: Some("severity>5".into()),
                filter_id: Some(id("f1")),
                ignore_pagination: Some(true),
                details: Some(false),
            }
        )),
        "<get_report_hosts details=\"0\" filt_id=\"f1\" filter=\"severity&gt;5\" ignore_pagination=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_ports(
            &id("r1"),
            GetReportDetailsOpts {
                ignore_pagination: Some(false),
                details: Some(true),
                ..Default::default()
            }
        )),
        "<get_report_ports details=\"1\" ignore_pagination=\"0\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_applications(&id("r1"), Default::default())),
        "<get_report_applications details=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_operating_systems(&id("r1"), Default::default())),
        "<get_report_operating_systems details=\"1\" report_id=\"r1\"/>"
    );
    assert_eq!(
        xml(get_report_cves(&id("r1"), Default::default())),
        "<get_report_cves details=\"1\" report_id=\"r1\"/>"
    );
}
