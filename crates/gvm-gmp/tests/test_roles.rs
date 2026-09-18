// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::roles::*;
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn canonical_role_requests_encode_exact_xml() {
    let mut create = CreateRoleRequest::new("g");
    create.comment = Some("c".into());
    create.users = vec!["alice".into(), "bob".into()];
    assert_eq!(
        xml(&create),
        "<create_role><name>g</name><comment>c</comment><users>alice,bob</users></create_role>"
    );

    let mut clone = CloneRoleRequest::new(id("g1"));
    clone.name = Some("copy".into());
    clone.comment = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_role><name>copy</name><copy>g1</copy></create_role>"
    );
    assert_eq!(
        xml(&GetRoleRequest::new(id("g1"))),
        "<get_roles details=\"1\" role_id=\"g1\"/>"
    );

    let modify = ModifyRoleRequest::new(id("g1"), "g", "", Vec::new());
    assert_eq!(
        xml(&modify),
        "<modify_role role_id=\"g1\"><name>g</name><comment></comment><users></users></modify_role>"
    );
    assert_eq!(
        xml(&DeleteRoleRequest::new(id("g1"), false)),
        "<delete_role role_id=\"g1\" ultimate=\"0\"/>"
    );
}

#[test]
fn canonical_role_requests_reject_invalid_final_values() {
    let mut create = CreateRoleRequest::new("g");
    create.users.push(String::new());
    assert!(matches!(
        create.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidField { field: "users", .. })
    ));

    let modify = ModifyRoleRequest::new(id("g1"), "", "comment", Vec::new());
    assert!(matches!(
        modify.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidField { field: "name", .. })
    ));
}

#[test]
fn role_list_options_and_escaping_are_encoded() {
    let list = GetRolesRequest {
        filter_string: Some("name=a & b".into()),
        filter_id: Some(id("f1")),
        trash: Some(true),
        details: Some(false),
    };
    assert_eq!(
        xml(&list),
        "<get_roles details=\"0\" filt_id=\"f1\" filter=\"name=a &amp; b\" trash=\"1\"/>"
    );
    assert_eq!(xml(&GetRolesRequest::default()), "<get_roles/>");
    let mut create = CreateRoleRequest::new("a<&");
    assert_eq!(
        xml(&create),
        "<create_role><name>a&lt;&amp;</name></create_role>"
    );
    create.name.clear();
    assert!(create.validate().is_err());
    let mut clone = CloneRoleRequest::new(id("r1"));
    assert_eq!(xml(&clone), "<create_role><copy>r1</copy></create_role>");
    clone.name = Some(String::new());
    assert!(clone.encode(GmpVersion(22, 4)).is_err());
    assert!(
        ModifyRoleRequest::new(id("r1"), "role", "", vec![String::new()])
            .validate()
            .is_err()
    );
}
