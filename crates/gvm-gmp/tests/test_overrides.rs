// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::overrides::*;
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn canonical_override_requests_encode_exact_xml() {
    let mut create = CreateOverrideRequest::new("oid", "body", 7.5);
    create.hosts = vec!["1.1.1.1".into()];
    create.port = Some("22/tcp".into());
    create.severity = Some(5.0);
    create.task_id = Some(id("t1"));
    create.result_id = Some(id("r1"));
    create.days_active = Some(-1);
    assert_eq!(
        xml(&create),
        "<create_override><nvt oid=\"oid\"/><text>body</text><hosts>1.1.1.1</hosts><port>22/tcp</port><severity>5</severity><new_severity>7.5</new_severity><task id=\"t1\"/><result id=\"r1\"/><active>-1</active></create_override>"
    );

    assert_eq!(
        xml(&CloneOverrideRequest::new(id("o1"))),
        "<create_override><copy>o1</copy></create_override>"
    );
    assert_eq!(
        xml(&GetOverrideRequest::new(id("o1"))),
        "<get_overrides details=\"1\" override_id=\"o1\"/>"
    );
    assert_eq!(
        xml(&DeleteOverrideRequest::new(id("o1"), false)),
        "<delete_override override_id=\"o1\" ultimate=\"0\"/>"
    );
    assert_eq!(
        xml(&GetOverridesRequest {
            details: Some(true),
            result: Some(true),
            ..Default::default()
        }),
        "<get_overrides details=\"1\" result=\"1\"/>"
    );
}

#[test]
fn canonical_override_validation_checks_final_values() {
    let request = ModifyOverrideRequest::new(id("o1"), "body", f64::INFINITY);
    assert!(matches!(
        request.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidField {
            field: "new_severity",
            ..
        })
    ));
}
