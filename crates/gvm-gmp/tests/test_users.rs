// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::users::*;
use gvm_gmp::{CollectionUpdate, GmpRequestCodec, GmpRequestError, GmpVersion, UserAuthType};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn canonical_user_requests_encode_exact_xml() {
    let mut create = CreateUserRequest::new("alice");
    create.comment = Some("c".into());
    create.password = Some("secret".into());
    create.host_access = Some(UserHostAccess::allow("127.0.0.1"));
    create.role_ids = vec![id("r1"), id("r2")];
    create.group_ids = vec![id("g1")];
    create.auth_source = Some(UserAuthType::File);
    assert_eq!(
        xml(&create),
        "<create_user><name>alice</name><comment>c</comment><password>secret</password><hosts allow=\"1\">127.0.0.1</hosts><role id=\"r1\"/><role id=\"r2\"/><groups><group id=\"g1\"/></groups><sources><source>file</source></sources></create_user>"
    );

    let mut modify = ModifyUserRequest::new(id("u1"), UserHostAccess::deny(""));
    modify.new_name = Some("renamed".into());
    modify.comment = Some(String::new());
    modify.role_ids = CollectionUpdate::Clear;
    modify.group_ids = CollectionUpdate::Clear;
    modify.auth_source = Some(UserAuthType::LdapConnect);
    assert_eq!(
        xml(&modify),
        "<modify_user user_id=\"u1\"><new_name>renamed</new_name><comment></comment><hosts allow=\"0\"></hosts><role id=\"0\"/><groups/><sources><source>ldap_connect</source></sources></modify_user>"
    );

    let mut clone = CloneUserRequest::new(id("u1"));
    clone.name = Some("copy".into());
    assert_eq!(
        xml(&clone),
        "<create_user><name>copy</name><copy>u1</copy></create_user>"
    );
    assert_eq!(
        xml(&GetUserRequest::new(id("u1"))),
        "<get_users details=\"1\" user_id=\"u1\"/>"
    );

    let mut delete = DeleteUserRequest::by_name("alice");
    delete.inheritor_name = Some("admin".into());
    assert_eq!(
        xml(&delete),
        "<delete_user inheritor_name=\"admin\" name=\"alice\"/>"
    );
}

#[test]
fn canonical_user_requests_reject_invalid_final_values() {
    let mut create = CreateUserRequest::new("alice");
    create.name.clear();
    assert!(matches!(
        create.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidField { field: "name", .. })
    ));

    let request = DeleteUserRequest {
        user_id: None,
        name: None,
        inheritor_id: None,
        inheritor_name: None,
    };
    assert!(matches!(
        request.encode(GmpVersion(22, 8)),
        Err(GmpRequestError::InvalidCombination { .. })
    ));
}

#[test]
fn user_request_debug_output_redacts_passwords() {
    let mut create = CreateUserRequest::new("alice");
    create.password = Some("create-secret".into());
    let mut modify = ModifyUserRequest::new(id("u1"), UserHostAccess::allow(""));
    modify.password = Some("modify-secret".into());

    let create_debug = format!("{create:?}");
    let modify_debug = format!("{modify:?}");
    assert!(create_debug.contains("<redacted>"));
    assert!(!create_debug.contains("create-secret"));
    assert!(modify_debug.contains("<redacted>"));
    assert!(!modify_debug.contains("modify-secret"));
}
