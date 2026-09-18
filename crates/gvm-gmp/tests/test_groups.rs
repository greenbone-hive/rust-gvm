// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::groups::*;
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn canonical_group_requests_encode_exact_xml() {
    let mut create = CreateGroupRequest::new("g");
    create.comment = Some("c".into());
    create.users = vec!["alice".into(), "bob".into()];
    create.special_full = true;
    assert_eq!(
        xml(&create),
        "<create_group><name>g</name><comment>c</comment><specials><full/></specials><users>alice,bob</users></create_group>"
    );

    let mut clone = CloneGroupRequest::new(id("g1"));
    clone.name = Some("copy".into());
    clone.comment = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_group><name>copy</name><comment></comment><copy>g1</copy></create_group>"
    );
    assert_eq!(
        xml(&GetGroupRequest::new(id("g1"))),
        "<get_groups details=\"1\" group_id=\"g1\"/>"
    );

    let modify = ModifyGroupRequest::new(id("g1"), "g", "", Vec::new());
    assert_eq!(
        xml(&modify),
        "<modify_group group_id=\"g1\"><name>g</name><comment></comment><users></users></modify_group>"
    );
    assert_eq!(
        xml(&DeleteGroupRequest::new(id("g1"), false)),
        "<delete_group group_id=\"g1\" ultimate=\"0\"/>"
    );
}

#[test]
fn canonical_group_requests_reject_invalid_final_values() {
    let mut create = CreateGroupRequest::new("g");
    create.users.push(String::new());
    assert!(matches!(
        create.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidField { field: "users", .. })
    ));

    let modify = ModifyGroupRequest::new(id("g1"), "", "comment", Vec::new());
    assert!(matches!(
        modify.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidField { field: "name", .. })
    ));
}
