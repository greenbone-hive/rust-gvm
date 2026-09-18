// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::scanners::*;
use gvm_gmp::{GmpRequestCodec, GmpVersion, ScalarUpdate, ScannerType};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn canonical_scanner_requests_encode_exact_xml() {
    let mut create =
        CreateScannerRequest::new("scanner", "127.0.0.1", 9390, ScannerType::OpenVasScanner);
    create.comment = Some("c".into());
    create.ca_pub = Some("CA certificate".into());
    create.credential_id = Some(id("cred1"));
    create.relay_host = Some("relay.example".into());
    create.relay_port = Some(9391);
    assert_eq!(
        xml(&create),
        "<create_scanner><name>scanner</name><comment>c</comment><host>127.0.0.1</host><port>9390</port><type>2</type><ca_pub>CA certificate</ca_pub><credential id=\"cred1\"/><relay_host>relay.example</relay_host><relay_port>9391</relay_port></create_scanner>"
    );

    let mut modify = ModifyScannerRequest::new(id("s1"));
    modify.name = Some("renamed".into());
    modify.comment = Some(String::new());
    modify.host = Some("scanner.example".into());
    modify.port = Some(9392);
    modify.scanner_type = Some(ScannerType::GreenBoneSensorType);
    modify.ca_pub = Some(String::new());
    modify.credential_id = ScalarUpdate::Clear;
    modify.relay_host = Some(String::new());
    assert_eq!(
        xml(&modify),
        "<modify_scanner scanner_id=\"s1\"><name>renamed</name><comment></comment><host>scanner.example</host><port>9392</port><type>5</type><ca_pub></ca_pub><credential id=\"0\"/><relay_host></relay_host></modify_scanner>"
    );

    let mut clone = CloneScannerRequest::new(id("s1"));
    clone.name = Some("clone".into());
    clone.comment = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_scanner><name>clone</name><comment></comment><copy>s1</copy></create_scanner>"
    );
    assert_eq!(
        xml(&GetScannerRequest::new(id("s1"))),
        "<get_scanners details=\"1\" scanner_id=\"s1\"/>"
    );
    assert_eq!(
        xml(&VerifyScannerRequest::new(id("s1"))),
        "<verify_scanner scanner_id=\"s1\"/>"
    );
    assert_eq!(
        xml(&DeleteScannerRequest::new(id("s1"), true)),
        "<delete_scanner scanner_id=\"s1\" ultimate=\"1\"/>"
    );
}

#[test]
fn canonical_scanner_requests_reject_invalid_final_values() {
    let mut create =
        CreateScannerRequest::new("scanner", "127.0.0.1", 9390, ScannerType::OpenVasScanner);
    create.port = 0;
    assert!(create.encode(GmpVersion(22, 8)).is_err());

    let mut modify = ModifyScannerRequest::new(id("s1"));
    modify.relay_host = Some(String::new());
    modify.relay_port = Some(9391);
    assert!(modify.encode(GmpVersion(22, 8)).is_err());
}
