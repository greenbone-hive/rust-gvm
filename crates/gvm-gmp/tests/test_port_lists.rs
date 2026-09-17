// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::port_lists::*;
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion, PortRangeType};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn test_port_list_create_clone_and_query_variants() {
    assert_eq!(
        xml(&CreatePortListRequest::new("ports")),
        "<create_port_list><name>ports</name></create_port_list>"
    );

    let mut create = CreatePortListRequest::new("ports");
    create.comment = Some("c".into());
    create.port_range = Some("T:1-5".into());
    assert_eq!(
        xml(&create),
        "<create_port_list><name>ports</name><comment>c</comment><port_range>T:1-5</port_range></create_port_list>"
    );
    assert_eq!(
        xml(&ClonePortListRequest::new(id("pl1"))),
        "<create_port_list><copy>pl1</copy></create_port_list>"
    );
    assert_eq!(
        xml(&GetPortListsRequest {
            details: Some(true),
            ..Default::default()
        }),
        "<get_port_lists details=\"1\"/>"
    );
    assert_eq!(
        xml(&GetPortListRequest::new(id("pl1"))),
        "<get_port_lists details=\"1\" port_list_id=\"pl1\"/>"
    );
}

#[test]
fn test_port_list_modify_delete_and_range_variants() {
    let mut modify = ModifyPortListRequest::new(id("pl1"));
    modify.name = Some("renamed".into());
    modify.comment = Some("replacement comment".into());
    assert_eq!(
        xml(&modify),
        "<modify_port_list port_list_id=\"pl1\"><name>renamed</name><comment>replacement comment</comment></modify_port_list>"
    );
    assert_eq!(
        xml(&ModifyPortListRequest::new(id("pl1"))),
        "<modify_port_list port_list_id=\"pl1\"/>"
    );
    assert_eq!(
        xml(&DeletePortListRequest::new(id("pl1"), false)),
        "<delete_port_list port_list_id=\"pl1\" ultimate=\"0\"/>"
    );
    let mut range = CreatePortRangeRequest::new(id("pl1"), PortRangeType::Tcp, 1, 5);
    range.comment = Some("well-known".into());
    assert_eq!(
        xml(&range),
        "<create_port_range><comment>well-known</comment><port_list id=\"pl1\"/><start>1</start><end>5</end><type>TCP</type></create_port_range>"
    );
    assert_eq!(
        xml(&DeletePortRangeRequest::new(id("pr1"))),
        "<delete_port_range port_range_id=\"pr1\"/>"
    );
}

#[test]
fn test_port_range_validation() {
    assert!(matches!(
        CreatePortRangeRequest::new(id("pl1"), PortRangeType::Tcp, 0, 5).validate(),
        Err(GmpRequestError::InvalidField { field: "start", .. })
    ));
    assert!(matches!(
        CreatePortRangeRequest::new(id("pl1"), PortRangeType::Tcp, 5, 1).validate(),
        Err(GmpRequestError::InvalidCombination { .. })
    ));
}
