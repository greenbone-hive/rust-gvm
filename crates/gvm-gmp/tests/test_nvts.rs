// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::nvts::*;
use gvm_gmp::{GmpRequestCodec, GmpVersion, SortOrder};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

#[test]
fn exact_nvt_wire_contract() {
    assert_eq!(xml(&GetNvtsRequest::default()), "<get_nvts/>");
    assert_eq!(
        xml(&GetNvtRequest::new("1.3.6.1")),
        "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\"/>"
    );

    let mut scoped = GetScanConfigNvtsRequest::new(id("config-1"), "General");
    scoped.details = Some(true);
    scoped.preferences = Some(true);
    scoped.preference_count = Some(false);
    scoped.timeout = Some(true);
    scoped.sort_field = Some("name".into());
    scoped.sort_order = Some(SortOrder::Descending);
    assert_eq!(
        xml(&scoped),
        "<get_nvts config_id=\"config-1\" details=\"1\" family=\"General\" preference_count=\"0\" preferences=\"1\" sort_field=\"name\" sort_order=\"descending\" timeout=\"1\"/>"
    );

    let mut preference_context = GetNvtsRequest {
        family: Some("General".into()),
        preferences_config_id: Some(id("config-1")),
        details: Some(true),
        preferences: Some(true),
        ..Default::default()
    };
    assert_eq!(
        xml(&preference_context),
        "<get_nvts details=\"1\" family=\"General\" preferences=\"1\" preferences_config_id=\"config-1\"/>"
    );
    preference_context.family = Some("General & Web".into());
    assert!(xml(&preference_context).contains("General &amp; Web"));

    let mut detail = GetScanConfigNvtRequest::new("1.3.6.1");
    detail.preferences_config_id = Some(id("config-1"));
    detail.timeout = Some(true);
    assert_eq!(
        xml(&detail),
        "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\" preference_count=\"1\" preferences=\"1\" preferences_config_id=\"config-1\" timeout=\"1\"/>"
    );
}

#[test]
fn exact_preference_and_family_wire_contract() {
    assert_eq!(
        xml(&GetNvtPreferencesRequest::default()),
        "<get_preferences/>"
    );
    assert_eq!(
        xml(&GetNvtPreferencesRequest {
            nvt_oid: Some("1.3.6.1".into())
        }),
        "<get_preferences nvt_oid=\"1.3.6.1\"/>"
    );
    let mut detail = GetNvtPreferenceRequest::new("entry:Example option");
    detail.nvt_oid = Some("1.3.6.1".into());
    assert_eq!(
        xml(&detail),
        "<get_preferences nvt_oid=\"1.3.6.1\" preference=\"entry:Example option\"/>"
    );
    assert_eq!(xml(&GetNvtFamiliesRequest::new()), "<get_nvt_families/>");
    assert_eq!(
        xml(&GetNvtFamiliesRequest {
            sort_order: Some(SortOrder::Descending)
        }),
        "<get_nvt_families sort_order=\"descending\"/>"
    );
}

#[test]
fn invalid_mutated_final_values_fail_direct_encoding() {
    let mut detail = GetScanConfigNvtRequest::new("1.3.6.1");
    detail.details = Some(false);
    assert!(detail.encode(GmpVersion(22, 4)).is_err());

    let list = GetNvtsRequest {
        config_id: Some(id("config-1")),
        ..Default::default()
    };
    assert!(list.encode(GmpVersion(22, 4)).is_err());

    let mut list = GetNvtsRequest {
        details: Some(true),
        timeout: Some(true),
        ..Default::default()
    };
    assert!(list.encode(GmpVersion(22, 4)).is_err());
    list.preferences_config_id = Some(id("config-1"));
    assert!(list.encode(GmpVersion(22, 4)).is_ok());
    list.config_id = Some(id("config-2"));
    assert!(list.encode(GmpVersion(22, 4)).is_err());
}
