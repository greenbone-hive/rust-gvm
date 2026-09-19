// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::configs::*;
use gvm_gmp::responses::{
    CreateConfigResponse, DeleteConfigResponse, GetConfigsResponse, ModifyConfigResponse,
};
use gvm_gmp::{GmpRequest, GmpRequestCodec, GmpResponse, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

fn assert_response<R, T>(_: &R)
where
    R: GmpRequest<Response = T>,
    T: GmpResponse,
{
}

#[test]
fn generic_query_requests_encode_every_field_and_boolean_state() {
    assert_eq!(xml(&GetConfigsRequest::new()), "<get_configs/>");

    let request = GetConfigsRequest {
        config_id: Some(id("config-1")),
        filter_string: Some(String::new()),
        filter_id: Some(id("-2")),
        trash: Some(false),
        details: Some(true),
        families: Some(false),
        preferences: Some(true),
        tasks: Some(false),
        usage_type: Some(ConfigUsageType::Policy),
    };
    assert_eq!(
        xml(&request),
        "<get_configs config_id=\"config-1\" details=\"1\" families=\"0\" filt_id=\"-2\" filter=\"\" preferences=\"1\" tasks=\"0\" trash=\"0\" usage_type=\"policy\"/>"
    );

    let mut detail = GetConfigRequest::new(id("config-1"));
    detail.usage_type = Some(ConfigUsageType::Scan);
    detail.tasks = Some(true);
    assert_eq!(
        xml(&detail),
        "<get_configs config_id=\"config-1\" details=\"1\" tasks=\"1\" usage_type=\"scan\"/>"
    );
    detail.details = None;
    assert_eq!(
        xml(&detail),
        "<get_configs config_id=\"config-1\" tasks=\"1\" usage_type=\"scan\"/>"
    );
}

#[test]
fn generic_copy_requests_have_source_backed_deterministic_bytes() {
    let mut create = CreateConfigRequest::new("Baseline & audit", id("base-1"));
    create.comment = Some("Copied".into());
    create.usage_type = Some(ConfigUsageType::Policy);
    assert_eq!(
        xml(&create),
        "<create_config><copy>base-1</copy><name>Baseline &amp; audit</name><comment>Copied</comment><usage_type>policy</usage_type></create_config>"
    );

    let mut clone = CloneConfigRequest::new(id("base-1"));
    assert_eq!(
        xml(&clone),
        "<create_config><copy>base-1</copy></create_config>"
    );
    clone.name = Some(String::new());
    clone.comment = Some(String::new());
    clone.usage_type = Some(ConfigUsageType::Scan);
    assert_eq!(
        xml(&clone),
        "<create_config><copy>base-1</copy><name></name><comment></comment><usage_type>scan</usage_type></create_config>"
    );
}

#[test]
fn generic_metadata_and_delete_requests_preserve_explicit_empty_values() {
    let mut modify = ModifyConfigRequest::new(id("config-1"));
    assert_eq!(xml(&modify), "<modify_config config_id=\"config-1\"/>");
    modify.name = Some(String::new());
    modify.comment = Some(String::new());
    assert_eq!(
        xml(&modify),
        "<modify_config config_id=\"config-1\"><name></name><comment></comment></modify_config>"
    );
    modify.name = Some("Renamed".into());
    modify.comment = Some("Updated & reviewed".into());
    assert_eq!(
        xml(&modify),
        "<modify_config config_id=\"config-1\"><name>Renamed</name><comment>Updated &amp; reviewed</comment></modify_config>"
    );

    let mut delete = DeleteConfigRequest::new(id("config-1"));
    assert_eq!(xml(&delete), "<delete_config config_id=\"config-1\"/>");
    delete.ultimate = Some(false);
    assert_eq!(
        xml(&delete),
        "<delete_config config_id=\"config-1\" ultimate=\"0\"/>"
    );
    delete.ultimate = Some(true);
    assert_eq!(
        xml(&delete),
        "<delete_config config_id=\"config-1\" ultimate=\"1\"/>"
    );
}

#[test]
fn generic_requests_validate_final_mutable_values_without_leaking_them() {
    let mut create = CreateConfigRequest::new("valid", id("base-1"));
    create.name.clear();
    let error = create.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid request field 'name': must not be empty"
    );
    assert_eq!(create.encode(GmpVersion(22, 4)), Err(error));

    create.name = "secret\u{0}name".into();
    let display = create.validate().unwrap_err().to_string();
    assert!(!display.contains("secret"));

    let mut query = GetConfigsRequest::new();
    query.filter_string = Some("hidden\u{1}filter".into());
    let display = query.validate().unwrap_err().to_string();
    assert!(!display.contains("hidden"));
}

#[test]
fn generic_requests_expose_static_metadata_and_responses() {
    let list = GetConfigsRequest::new();
    let detail = GetConfigRequest::new(id("config-1"));
    let create = CreateConfigRequest::new("name", id("base-1"));
    let clone = CloneConfigRequest::new(id("config-1"));
    let modify = ModifyConfigRequest::new(id("config-1"));
    let delete = DeleteConfigRequest::new(id("config-1"));

    assert_eq!(list.command().unwrap().wire_name(), "get_configs");
    assert_eq!(
        detail.command().unwrap().semantic_name(),
        Some("get_config")
    );
    assert_eq!(
        clone.command().unwrap().semantic_name(),
        Some("clone_config")
    );
    assert_response::<_, GetConfigsResponse>(&list);
    assert_response::<_, GetConfigsResponse>(&detail);
    assert_response::<_, CreateConfigResponse>(&create);
    assert_response::<_, CreateConfigResponse>(&clone);
    assert_response::<_, ModifyConfigResponse>(&modify);
    assert_response::<_, DeleteConfigResponse>(&delete);
}
