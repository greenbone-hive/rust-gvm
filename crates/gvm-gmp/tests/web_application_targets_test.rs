// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::web_application_targets::ModifyWebApplicationTargetRequest;
use gvm_gmp::{CollectionUpdate, GmpRequestCodec, GmpVersion};

fn request_xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn modify_web_target_exclude_urls_preserve_omits_element_exactly() {
    let request = ModifyWebApplicationTargetRequest::new(id("target-1"));

    assert_eq!(
        request_xml(&request),
        "<modify_web_application_target web_application_target_id=\"target-1\"/>"
    );
}

#[test]
fn modify_web_target_exclude_urls_replacement_emits_exact_comma_separated_text() {
    let mut request = ModifyWebApplicationTargetRequest::new(id("target-1"));
    request.exclude_urls = CollectionUpdate::replace([
        "https://example.com/logout".into(),
        "https://example.com/private?a=1&b=2".into(),
    ]);

    assert_eq!(
        request_xml(&request),
        "<modify_web_application_target web_application_target_id=\"target-1\"><exclude_urls>https://example.com/logout,https://example.com/private?a=1&amp;b=2</exclude_urls></modify_web_application_target>"
    );
}

#[test]
fn modify_web_target_exclude_urls_clear_emits_exact_sql_null_form() {
    // gvmd maps a present empty element to an empty string and then sets the
    // exclude_urls column to SQL NULL.
    for update in [CollectionUpdate::Clear, CollectionUpdate::Replace(vec![])] {
        let mut request = ModifyWebApplicationTargetRequest::new(id("target-1"));
        request.exclude_urls = update;

        assert_eq!(
            request_xml(&request),
            "<modify_web_application_target web_application_target_id=\"target-1\"><exclude_urls/></modify_web_application_target>"
        );
    }
}
