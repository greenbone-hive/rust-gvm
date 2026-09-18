// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::operating_systems::*;
use gvm_gmp::{GmpRequestCodec, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

#[test]
fn exact_operating_system_asset_xml() {
    let list = GetOperatingSystemAssetsRequest {
        filter_string: Some("name=Debian".into()),
        filter_id: Some(id("f1")),
        ignore_pagination: Some(true),
        details: Some(true),
    };
    assert_eq!(
        xml(&list),
        "<get_assets details=\"1\" filt_id=\"f1\" filter=\"name=Debian\" ignore_pagination=\"1\" type=\"os\"/>"
    );

    let detail = GetOperatingSystemAssetRequest::new(id("os1"));
    assert_eq!(xml(&detail), "<get_assets asset_id=\"os1\" type=\"os\"/>");
    let detail = GetOperatingSystemAssetRequest {
        operating_system_id: id("os1"),
        details: Some(false),
    };
    assert_eq!(
        xml(&detail),
        "<get_assets asset_id=\"os1\" details=\"0\" type=\"os\"/>"
    );
    assert_eq!(
        xml(&DeleteOperatingSystemAssetRequest::new(id("os1"))),
        "<delete_asset asset_id=\"os1\"/>"
    );
}
