// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::secinfo::*;
use gvm_gmp::{GmpRequestCodec, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

#[test]
fn all_ten_requests_encode_literal_expected_xml() {
    assert_eq!(
        xml(&GetInfoListRequest::new(GenericInfoType::Nvt)),
        "<get_info type=\"NVT\"/>"
    );
    assert_eq!(
        xml(&GetInfoRequest::new("CVE-2026-0001", GenericInfoType::Cve)),
        "<get_info details=\"1\" info_id=\"CVE-2026-0001\" type=\"CVE\"/>"
    );
    assert_eq!(xml(&GetCpesRequest::default()), "<get_info type=\"CPE\"/>");
    assert_eq!(
        xml(&GetCpeRequest::new("cpe:/a:example:app")),
        "<get_info details=\"1\" info_id=\"cpe:/a:example:app\" type=\"CPE\"/>"
    );
    assert_eq!(xml(&GetCvesRequest::default()), "<get_info type=\"CVE\"/>");
    assert_eq!(
        xml(&GetCveRequest::new("CVE-2026-0001")),
        "<get_info details=\"1\" info_id=\"CVE-2026-0001\" type=\"CVE\"/>"
    );
    assert_eq!(
        xml(&GetCertBundAdvisoriesRequest::default()),
        "<get_info type=\"CERT_BUND_ADV\"/>"
    );
    assert_eq!(
        xml(&GetCertBundAdvisoryRequest::new("CB-K26/001")),
        "<get_info details=\"1\" info_id=\"CB-K26/001\" type=\"CERT_BUND_ADV\"/>"
    );
    assert_eq!(
        xml(&GetDfnCertAdvisoriesRequest::default()),
        "<get_info type=\"DFN_CERT_ADV\"/>"
    );
    assert_eq!(
        xml(&GetDfnCertAdvisoryRequest::new("DFN-2026-001")),
        "<get_info details=\"1\" info_id=\"DFN-2026-001\" type=\"DFN_CERT_ADV\"/>"
    );
}

#[test]
fn filters_names_details_and_sentinels_are_independent() {
    let request = GetInfoListRequest {
        info_type: GenericInfoType::Nvt,
        name: Some("Example & test".into()),
        filter_string: Some("severity>7 rows=10".into()),
        filter_id: Some(id("0")),
        details: Some(false),
    };
    assert_eq!(xml(&request), "<get_info details=\"0\" filt_id=\"0\" filter=\"severity&gt;7 rows=10\" name=\"Example &amp; test\" type=\"NVT\"/>");

    let request = GetCvesRequest {
        filter_string: Some(String::new()),
        filter_id: Some(id("-2")),
        details: Some(false),
        ..Default::default()
    };
    assert_eq!(
        xml(&request),
        "<get_info details=\"0\" filt_id=\"-2\" filter=\"\" type=\"CVE\"/>"
    );
}

#[test]
fn final_value_validation_rejects_empty_selectors_and_bad_xml() {
    let mut request = GetCveRequest::new("CVE-2026-0001");
    request.info_id.clear();
    assert!(request.encode(GmpVersion(22, 4)).is_err());

    let request = GetCvesRequest {
        name: Some("  ".into()),
        ..Default::default()
    };
    assert!(request.encode(GmpVersion(22, 4)).is_err());

    let request = GetCpesRequest {
        filter_string: Some("visible\u{0}secret".into()),
        ..Default::default()
    };
    let error = request.validate().expect_err("invalid XML character");
    assert!(!error.to_string().contains("secret"));
}
