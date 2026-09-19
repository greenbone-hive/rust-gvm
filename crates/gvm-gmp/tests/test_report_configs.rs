// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::report_configs::*;
use gvm_gmp::responses::{
    CreateReportConfigResponse, DeleteReportConfigResponse, GetReportConfigsResponse,
    ModifyReportConfigResponse,
};
use gvm_gmp::{EntityId, GmpCommand, GmpRequest, GmpRequestCodec, GmpVersion};

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid entity identifier")
}

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 6)).expect("valid request"))
        .expect("valid UTF-8")
}

fn value(name: &str, value: &str) -> ReportConfigParam {
    ReportConfigParam {
        name: name.into(),
        value: ReportConfigParamValue::Value(value.into()),
    }
}

fn reset(name: &str) -> ReportConfigParam {
    ReportConfigParam {
        name: name.into(),
        value: ReportConfigParamValue::UseDefault,
    }
}

#[test]
fn exact_xml_and_response_associations_are_independent() {
    fn associated<R, T>(_: &R)
    where
        R: GmpRequest<Response = T>,
        T: gvm_gmp::GmpResponse,
    {
    }

    let list = GetReportConfigsRequest::new();
    assert_eq!(xml(&list), "<get_report_configs/>");
    associated::<_, GetReportConfigsResponse>(&list);

    let detail = GetReportConfigRequest::new(id("rc-1"));
    assert_eq!(
        xml(&detail),
        "<get_report_configs report_config_id=\"rc-1\"/>"
    );
    associated::<_, GetReportConfigsResponse>(&detail);

    let create = CreateReportConfigRequest::new("cfg", id("rf-1"));
    assert_eq!(
        xml(&create),
        "<create_report_config><name>cfg</name><report_format id=\"rf-1\"/></create_report_config>"
    );
    associated::<_, CreateReportConfigResponse>(&create);

    let clone = CloneReportConfigRequest::new(id("rc-1"));
    assert_eq!(
        xml(&clone),
        "<create_report_config><copy>rc-1</copy></create_report_config>"
    );
    associated::<_, CreateReportConfigResponse>(&clone);

    let modify = ModifyReportConfigRequest::new(id("rc-1"));
    assert_eq!(
        xml(&modify),
        "<modify_report_config report_config_id=\"rc-1\"/>"
    );
    associated::<_, ModifyReportConfigResponse>(&modify);

    let delete = DeleteReportConfigRequest::new(id("rc-1"));
    assert_eq!(
        xml(&delete),
        "<delete_report_config report_config_id=\"rc-1\"/>"
    );
    associated::<_, DeleteReportConfigResponse>(&delete);
}

#[test]
fn query_controls_have_exact_attributes_and_preserve_empty_filters() {
    let request = GetReportConfigsRequest {
        report_config_id: Some(id("rc-1")),
        filter_string: Some("name=cfg first=2 rows=1 sort=name".into()),
        filter_id: Some(id("filter-1")),
        trash: Some(false),
        details: Some(false),
        ignore_pagination: Some(true),
    };
    assert_eq!(
        xml(&request),
        "<get_report_configs details=\"0\" filt_id=\"filter-1\" filter=\"name=cfg first=2 rows=1 sort=name\" ignore_pagination=\"1\" report_config_id=\"rc-1\" trash=\"0\"/>"
    );

    for filter_id in ["0", "-2"] {
        let request = GetReportConfigsRequest {
            filter_string: Some(String::new()),
            filter_id: Some(id(filter_id)),
            ..Default::default()
        };
        assert_eq!(
            xml(&request),
            format!("<get_report_configs filt_id=\"{filter_id}\" filter=\"\"/>")
        );
    }

    for value in [false, true] {
        let request = GetReportConfigsRequest {
            trash: Some(value),
            details: Some(value),
            ignore_pagination: Some(value),
            ..Default::default()
        };
        let bit = if value { "1" } else { "0" };
        assert_eq!(
            xml(&request),
            format!("<get_report_configs details=\"{bit}\" ignore_pagination=\"{bit}\" trash=\"{bit}\"/>")
        );
    }
}

#[test]
fn create_clone_modify_and_delete_encode_all_distinctions() {
    let mut create = CreateReportConfigRequest::new("A & B", id("rf-1"));
    create.comment = Some(String::new());
    create.params = vec![value("Label", "<x>&"), reset("Graph Type")];
    assert_eq!(
        xml(&create),
        "<create_report_config><name>A &amp; B</name><report_format id=\"rf-1\"/><comment></comment><param><name>Label</name><value>&lt;x&gt;&amp;</value></param><param><name>Graph Type</name><value use_default=\"1\"></value></param></create_report_config>"
    );

    let mut clone = CloneReportConfigRequest::new(id("rc-1"));
    clone.name = Some("Copy".into());
    assert_eq!(
        xml(&clone),
        "<create_report_config><copy>rc-1</copy><name>Copy</name></create_report_config>"
    );
    clone.name = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_report_config><copy>rc-1</copy><name></name></create_report_config>"
    );

    let mut modify = ModifyReportConfigRequest::new(id("rc-1"));
    modify.name = Some("renamed".into());
    modify.comment = Some(String::new());
    modify.params = vec![value("Label", ""), reset("Graph Type")];
    assert_eq!(
        xml(&modify),
        "<modify_report_config report_config_id=\"rc-1\"><name>renamed</name><comment></comment><param><name>Label</name><value></value></param><param><name>Graph Type</name><value use_default=\"1\"></value></param></modify_report_config>"
    );

    let mut delete = DeleteReportConfigRequest::new(id("rc-1"));
    delete.ultimate = Some(false);
    assert_eq!(
        xml(&delete),
        "<delete_report_config report_config_id=\"rc-1\" ultimate=\"0\"/>"
    );
    delete.ultimate = Some(true);
    assert_eq!(
        xml(&delete),
        "<delete_report_config report_config_id=\"rc-1\" ultimate=\"1\"/>"
    );
}

#[test]
fn parameter_order_duplicates_and_final_value_mutation_are_preserved() {
    let mut request = CreateReportConfigRequest::new("initial", id("rf-1"));
    request.name = "final".into();
    request.params = vec![value("Label", "one"), value("Label", "two"), reset("Label")];
    assert_eq!(
        xml(&request),
        "<create_report_config><name>final</name><report_format id=\"rf-1\"/><param><name>Label</name><value>one</value></param><param><name>Label</name><value>two</value></param><param><name>Label</name><value use_default=\"1\"></value></param></create_report_config>"
    );
}

#[test]
fn validates_final_values_and_redacts_parameter_payloads() {
    let mut create = CreateReportConfigRequest::new("cfg", id("rf-1"));
    create.name.clear();
    assert!(create.validate().unwrap_err().to_string().contains("name"));
    assert!(create.encode(GmpVersion(22, 6)).is_err());

    let mut modify = ModifyReportConfigRequest::new(id("rc-1"));
    modify.name = Some(String::new());
    assert!(modify.validate().is_err());
    modify.name = None;
    modify.params.push(value(" \t\r\n ", "hidden-secret"));
    let error = modify.validate().unwrap_err();
    assert!(error.to_string().contains("params.name"));
    assert!(!error.to_string().contains("hidden-secret"));

    modify.params[0].name = "Label".into();
    modify.params[0].value = ReportConfigParamValue::Value("hidden\u{0}secret".into());
    let error = modify.validate().unwrap_err();
    assert!(error.to_string().contains("params.value"));
    assert!(!error.to_string().contains("hidden"));
    assert!(!format!("{modify:?}").contains("hidden"));
    modify.params[0].name = "hidden-parameter-name".into();
    assert!(!format!("{modify:?}").contains("hidden-parameter-name"));
}

#[test]
fn metadata_uses_semantic_aliases_without_new_wire_commands() {
    assert_eq!(
        GetReportConfigsRequest::default().command(),
        Some(GmpCommand::new("get_report_configs"))
    );
    assert_eq!(
        GetReportConfigRequest::new(id("rc-1")).command(),
        Some(GmpCommand::with_semantic_name(
            "get_report_configs",
            "get_report_config"
        ))
    );
    assert_eq!(
        CloneReportConfigRequest::new(id("rc-1")).command(),
        Some(GmpCommand::with_semantic_name(
            "create_report_config",
            "clone_report_config"
        ))
    );
    assert_eq!(
        CreateReportConfigRequest::new("cfg", id("rf-1")).command(),
        Some(GmpCommand::new("create_report_config"))
    );
    assert_eq!(
        ModifyReportConfigRequest::new(id("rc-1")).command(),
        Some(GmpCommand::new("modify_report_config"))
    );
    assert_eq!(
        DeleteReportConfigRequest::new(id("rc-1")).command(),
        Some(GmpCommand::new("delete_report_config"))
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_created_invalid_ids_are_revalidated() {
    use serde::Deserialize as _;
    let invalid = EntityId::deserialize(serde::de::value::SeqDeserializer::<
        _,
        serde::de::value::Error,
    >::new(["bad/id"].into_iter()))
    .expect("derive bypasses constructor");
    let request = GetReportConfigRequest::new(invalid);
    assert!(request.validate().is_err());
    assert!(request.encode(GmpVersion(22, 6)).is_err());
}
