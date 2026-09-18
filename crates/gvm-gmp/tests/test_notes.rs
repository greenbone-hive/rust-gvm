// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::notes::*;
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn canonical_note_requests_encode_exact_xml() {
    let mut create = CreateNoteRequest::new("1.3.6.1", "body");
    create.hosts = vec!["1.1.1.1".into()];
    create.port = Some("22/tcp".into());
    create.severity = Some(7.5);
    create.task_id = Some(id("t1"));
    create.result_id = Some(id("r1"));
    create.days_active = Some(-1);
    assert_eq!(
        xml(&create),
        "<create_note><nvt oid=\"1.3.6.1\"/><text>body</text><hosts>1.1.1.1</hosts><port>22/tcp</port><severity>7.5</severity><task id=\"t1\"/><result id=\"r1\"/><active>-1</active></create_note>"
    );

    assert_eq!(
        xml(&CloneNoteRequest::new(id("n1"))),
        "<create_note><copy>n1</copy></create_note>"
    );
    assert_eq!(
        xml(&GetNoteRequest::new(id("n1"))),
        "<get_notes details=\"1\" note_id=\"n1\"/>"
    );
    assert_eq!(
        xml(&DeleteNoteRequest::new(id("n1"), true)),
        "<delete_note note_id=\"n1\" ultimate=\"1\"/>"
    );
    assert_eq!(
        xml(&GetNotesRequest {
            details: Some(true),
            result: Some(true),
            ..Default::default()
        }),
        "<get_notes details=\"1\" result=\"1\"/>"
    );
}

#[test]
fn canonical_note_validation_checks_final_values() {
    let mut request = ModifyNoteRequest::new(id("n1"), "body");
    request.port = Some("22".into());
    assert!(matches!(
        request.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidField { field: "port", .. })
    ));
}
