// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::hosts::*;
use gvm_gmp::{GmpRequestCodec, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

#[test]
fn exact_host_alias_xml() {
    let list = GetHostsRequest {
        filter_string: Some("name=host".into()),
        filter_id: Some(id("f1")),
        ignore_pagination: Some(true),
        details: Some(false),
    };
    assert_eq!(
        xml(&list),
        "<get_assets details=\"0\" filt_id=\"f1\" filter=\"name=host\" ignore_pagination=\"1\" type=\"host\"/>"
    );
    assert_eq!(
        xml(&GetHostRequest::new(id("h1"))),
        "<get_assets asset_id=\"h1\" details=\"1\" type=\"host\"/>"
    );

    let mut create = CreateHostRequest::new("2001:db8::1");
    create.comment = Some("c".into());
    assert_eq!(
        xml(&create),
        "<create_asset><asset><type>host</type><name>2001:db8::1</name><comment>c</comment></asset></create_asset>"
    );
    assert_eq!(
        xml(&ModifyHostRequest::new(id("h1"), "updated")),
        "<modify_asset asset_id=\"h1\"><comment>updated</comment></modify_asset>"
    );
    assert_eq!(
        xml(&DeleteHostRequest::new(id("h1"))),
        "<delete_asset asset_id=\"h1\"/>"
    );
}

#[test]
fn default_host_list_has_only_its_fixed_type() {
    assert_eq!(
        xml(&GetHostsRequest::default()),
        "<get_assets type=\"host\"/>"
    );
}
