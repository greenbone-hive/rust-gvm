// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::filters::*;
use gvm_gmp::{FilterType, GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn test_create_and_clone_filter() {
    assert_eq!(
        xml(&CreateFilterRequest::new("f")),
        "<create_filter><name>f</name></create_filter>"
    );

    let mut create = CreateFilterRequest::new("f");
    create.comment = Some("c".into());
    create.term = Some("rows=10".into());
    create.filter_type = Some(FilterType::Task);
    assert_eq!(
        xml(&create),
        "<create_filter><name>f</name><comment>c</comment><term>rows=10</term><type>task</type></create_filter>"
    );

    let mut clone = CloneFilterRequest::new(id("f1"));
    clone.name = Some("copy".into());
    clone.comment = Some("clone comment".into());
    assert_eq!(
        xml(&clone),
        "<create_filter><name>copy</name><comment>clone comment</comment><copy>f1</copy></create_filter>"
    );
}

#[test]
fn test_filter_get_modify_delete() {
    let mut get = GetFilterRequest::new(id("f1"));
    get.alerts = Some(true);
    assert_eq!(
        xml(&get),
        "<get_filters alerts=\"1\" details=\"1\" filter_id=\"f1\"/>"
    );

    let mut modify = ModifyFilterRequest::new(id("f1"));
    modify.name = Some("renamed".into());
    modify.term = Some("rows=-1".into());
    assert_eq!(
        xml(&modify),
        "<modify_filter filter_id=\"f1\"><name>renamed</name><term>rows=-1</term></modify_filter>"
    );

    assert_eq!(
        xml(&DeleteFilterRequest::new(id("f1"), false)),
        "<delete_filter filter_id=\"f1\" ultimate=\"0\"/>"
    );
}

#[test]
fn test_empty_names_are_rejected() {
    let mut create = CreateFilterRequest::new("f");
    create.name.clear();
    assert!(matches!(
        create.validate(),
        Err(GmpRequestError::InvalidField { field: "name", .. })
    ));
}
