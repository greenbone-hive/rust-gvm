// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::tags::*;
use gvm_gmp::{EntityType, GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn test_create_and_clone_tag() {
    let mut resources = TagResources::new(EntityType::Task);
    resources.resource_ids = vec![id("t1"), id("t2")];
    resources.filter = Some("status=Running".into());
    let mut create = CreateTagRequest::new("tag", resources);
    create.comment = Some("c".into());
    create.value = Some("blue".into());
    create.active = Some(true);
    assert_eq!(
        xml(&create),
        r#"<create_tag><name>tag</name><resources filter="status=Running"><resource id="t1"/><resource id="t2"/><type>task</type></resources><value>blue</value><comment>c</comment><active>1</active></create_tag>"#
    );

    let mut clone = CloneTagRequest::new(id("tg1"));
    clone.name = Some("copy".into());
    clone.comment = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_tag><name>copy</name><comment></comment><copy>tg1</copy></create_tag>"
    );
}

#[test]
fn test_tag_get_modify_delete() {
    assert_eq!(
        xml(&GetTagRequest::new(id("tg1"))),
        "<get_tags details=\"1\" tag_id=\"tg1\"/>"
    );

    let mut modify = ModifyTagRequest::new(id("tg1"));
    modify.name = Some("renamed".into());
    modify.comment = Some(String::new());
    modify.value = Some(String::new());
    modify.resource_update = Some(TagResourceUpdate {
        resources: TagResources::new(EntityType::Policy),
        action: Some(TagResourceAction::Set),
    });
    assert_eq!(
        xml(&modify),
        "<modify_tag tag_id=\"tg1\"><name>renamed</name><resources action=\"set\"><type>config</type></resources><value></value><comment></comment></modify_tag>"
    );

    assert_eq!(
        xml(&DeleteTagRequest::new(id("tg1"), false)),
        "<delete_tag tag_id=\"tg1\" ultimate=\"0\"/>"
    );
}

#[test]
fn test_invalid_tag_values_are_rejected() {
    let mut create = CreateTagRequest::new("tag", TagResources::new(EntityType::Task));
    create.name.clear();
    assert!(matches!(
        create.validate(),
        Err(GmpRequestError::InvalidField { field: "name", .. })
    ));

    let invalid = CreateTagRequest::new("tag", TagResources::new(EntityType::Tag));
    assert!(matches!(
        invalid.validate(),
        Err(GmpRequestError::InvalidField {
            field: "resources.resource_type",
            ..
        })
    ));
}
