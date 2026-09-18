// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::assets::*;
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

#[test]
fn exact_generic_asset_xml() {
    let mut list = GetAssetsRequest::new(AssetType::custom("firmware"));
    list.asset_id = Some(id("a1"));
    list.filter_string = Some("name=foo".into());
    list.filter_id = Some(id("f1"));
    list.ignore_pagination = Some(false);
    list.details = Some(true);
    assert_eq!(
        xml(&list),
        "<get_assets asset_id=\"a1\" details=\"1\" filt_id=\"f1\" filter=\"name=foo\" ignore_pagination=\"0\" type=\"firmware\"/>"
    );

    assert_eq!(
        xml(&GetAssetRequest::new(id("a1"), AssetType::Host)),
        "<get_assets asset_id=\"a1\" details=\"1\" type=\"host\"/>"
    );

    let mut create = CreateAssetRequest::new("1.1.1.1");
    create.comment = Some("c & <d>".into());
    assert_eq!(
        xml(&create),
        "<create_asset><asset><type>host</type><name>1.1.1.1</name><comment>c &amp; &lt;d&gt;</comment></asset></create_asset>"
    );

    assert_eq!(
        xml(&ModifyAssetRequest::new(id("a1"), "")),
        "<modify_asset asset_id=\"a1\"><comment></comment></modify_asset>"
    );
    assert_eq!(
        xml(&DeleteAssetRequest::new(id("a1"))),
        "<delete_asset asset_id=\"a1\"/>"
    );
}

#[test]
fn invalid_final_values_are_rejected() {
    let invalid_names = [
        "",
        "host.example",
        "192.0.2.0/24",
        "192.0.2.1-192.0.2.2",
        "192.0.2.1,192.0.2.2",
        "999.0.0.1",
    ];
    for name in invalid_names {
        assert!(matches!(
            CreateAssetRequest::new(name).encode(GmpVersion(22, 4)),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));
    }

    assert!(matches!(
        GetAssetsRequest::new(AssetType::custom("")).encode(GmpVersion(22, 4)),
        Err(GmpRequestError::InvalidField {
            field: "asset_type",
            ..
        })
    ));
}

#[test]
fn expanded_ipv6_spelling_is_preserved() {
    assert_eq!(
        xml(&CreateAssetRequest::new("2001:0db8:0000:0000:0000:0000:0000:0001")),
        "<create_asset><asset><type>host</type><name>2001:0db8:0000:0000:0000:0000:0000:0001</name></asset></create_asset>"
    );
}
