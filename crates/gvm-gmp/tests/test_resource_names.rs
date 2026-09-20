// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::resource_names::{
    GetResourceNameRequest, GetResourceNamesRequest, ResourceType,
};
use gvm_gmp::{GmpRequestCodec, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn test_get_resource_names_basic() {
    assert_eq!(
        xml(&GetResourceNamesRequest::new(ResourceType::Task)),
        "<get_resource_names type=\"TASK\"/>"
    );
}

#[test]
fn test_get_resource_names_with_options() {
    let mut request = GetResourceNamesRequest::new(ResourceType::Task);
    request.filter_string = Some("name=foo".into());
    request.filter_id = Some(id("f1"));
    request.details = Some(true);
    assert_eq!(
        xml(&request),
        "<get_resource_names details=\"1\" filt_id=\"f1\" filter=\"name=foo\" type=\"TASK\"/>"
    );
}

#[test]
fn test_get_resource_name() {
    assert_eq!(
        xml(&GetResourceNameRequest::new(id("t1"), ResourceType::Task)),
        "<get_resource_names resource_id=\"t1\" type=\"TASK\"/>"
    );
}
