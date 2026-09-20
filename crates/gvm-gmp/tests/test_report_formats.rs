// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::report_formats::*;
use gvm_gmp::responses::{
    CreateReportFormatResponse, DeleteReportFormatResponse, GetReportFormatsResponse,
    ModifyReportFormatResponse, VerifyReportFormatResponse,
};
use gvm_gmp::{EntityId, GmpCommand, GmpRequest, GmpRequestCodec, GmpVersion};

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid entity identifier")
}

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).expect("valid request"))
        .expect("valid UTF-8")
}

fn import_xml(body: &str) -> String {
    format!(
        r#"<get_report_formats_response status="200" status_text="OK"><report_format id="11111111-1111-1111-1111-111111111111"><name>Imported</name>{body}</report_format></get_report_formats_response>"#
    )
}

#[test]
fn seven_exact_wire_contracts_and_response_associations_are_independent() {
    fn associated<R, T>(_: &R)
    where
        R: GmpRequest<Response = T>,
        T: gvm_gmp::GmpResponse,
    {
    }

    let list = GetReportFormatsRequest::new();
    assert_eq!(xml(&list), "<get_report_formats/>");
    associated::<_, GetReportFormatsResponse>(&list);

    let detail = GetReportFormatRequest::new(id("rf-1"));
    assert_eq!(
        xml(&detail),
        "<get_report_formats details=\"1\" report_format_id=\"rf-1\"/>"
    );
    associated::<_, GetReportFormatsResponse>(&detail);

    let import = ImportReportFormatRequest::new(import_xml(
        r#"<extension>txt</extension><content_type>text/plain</content_type><param><name>Label</name><type>string</type><value>red</value><default>blue</default></param><file name="data.txt">aGVsbG8=</file>"#,
    ));
    assert_eq!(
        xml(&import),
        r#"<create_report_format><get_report_formats_response status="200" status_text="OK"><report_format id="11111111-1111-1111-1111-111111111111"><name>Imported</name><extension>txt</extension><content_type>text/plain</content_type><param><name>Label</name><type>string</type><value>red</value><default>blue</default></param><file name="data.txt">aGVsbG8=</file></report_format></get_report_formats_response></create_report_format>"#
    );
    associated::<_, CreateReportFormatResponse>(&import);

    let clone = CloneReportFormatRequest::new(id("rf-1"));
    assert_eq!(
        xml(&clone),
        "<create_report_format><copy>rf-1</copy></create_report_format>"
    );
    associated::<_, CreateReportFormatResponse>(&clone);

    let modify = ModifyReportFormatRequest::new(id("rf-1"));
    assert_eq!(
        xml(&modify),
        "<modify_report_format report_format_id=\"rf-1\"/>"
    );
    associated::<_, ModifyReportFormatResponse>(&modify);

    let delete = DeleteReportFormatRequest::new(id("rf-1"));
    assert_eq!(
        xml(&delete),
        "<delete_report_format report_format_id=\"rf-1\"/>"
    );
    associated::<_, DeleteReportFormatResponse>(&delete);

    let verify = VerifyReportFormatRequest::new(id("rf-1"));
    assert_eq!(
        xml(&verify),
        "<verify_report_format report_format_id=\"rf-1\"/>"
    );
    associated::<_, VerifyReportFormatResponse>(&verify);
}

#[test]
fn query_controls_cover_absent_false_true_sentinels_and_detail_override() {
    let request = GetReportFormatsRequest {
        report_format_id: Some(id("rf-1")),
        filter_string: Some("name=Format first=2 rows=1 sort=name".into()),
        filter_id: Some(id("filter-1")),
        trash: Some(false),
        details: Some(false),
        alerts: Some(true),
        params: Some(true),
        report_configs: Some(true),
        ignore_pagination: Some(true),
    };
    assert_eq!(
        xml(&request),
        "<get_report_formats alerts=\"1\" details=\"0\" filt_id=\"filter-1\" filter=\"name=Format first=2 rows=1 sort=name\" ignore_pagination=\"1\" params=\"1\" report_configs=\"1\" report_format_id=\"rf-1\" trash=\"0\"/>"
    );

    for filter_id in ["0", "-2"] {
        let request = GetReportFormatsRequest {
            filter_string: Some(String::new()),
            filter_id: Some(id(filter_id)),
            ..Default::default()
        };
        assert_eq!(
            xml(&request),
            format!("<get_report_formats filt_id=\"{filter_id}\" filter=\"\"/>")
        );
    }

    for value in [false, true] {
        let request = GetReportFormatsRequest {
            trash: Some(value),
            details: Some(value),
            alerts: Some(value),
            params: Some(false),
            report_configs: Some(value),
            ignore_pagination: Some(value),
            ..Default::default()
        };
        let bit = if value { "1" } else { "0" };
        assert_eq!(
            xml(&request),
            format!("<get_report_formats alerts=\"{bit}\" details=\"{bit}\" ignore_pagination=\"{bit}\" params=\"0\" report_configs=\"{bit}\" trash=\"{bit}\"/>")
        );
    }

    let mut detail = GetReportFormatRequest::new(id("rf-1"));
    detail.details = Some(false);
    assert_eq!(
        xml(&detail),
        "<get_report_formats details=\"0\" report_format_id=\"rf-1\"/>"
    );
}

#[test]
fn clone_modify_delete_and_parameter_distinctions_are_exact() {
    let mut clone = CloneReportFormatRequest::new(id("rf-1"));
    clone.name = Some("A & B".into());
    assert_eq!(
        xml(&clone),
        "<create_report_format><copy>rf-1</copy><name>A &amp; B</name></create_report_format>"
    );
    clone.name = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_report_format><copy>rf-1</copy><name></name></create_report_format>"
    );

    let mut modify = ModifyReportFormatRequest::new(id("rf-1"));
    modify.name = Some("Renamed".into());
    modify.summary = Some(String::new());
    modify.active = Some(false);
    modify.param = Some(ReportFormatParamUpdate {
        name: "Label".into(),
        value: Some("red".into()),
    });
    assert_eq!(
        xml(&modify),
        "<modify_report_format report_format_id=\"rf-1\"><name>Renamed</name><summary></summary><active>0</active><param><name>Label</name><value>cmVk</value></param></modify_report_format>"
    );

    modify.name = None;
    modify.summary = None;
    modify.active = Some(true);
    modify.param = Some(ReportFormatParamUpdate {
        name: " Label \t".into(),
        value: Some("✓aGVsbG8=".into()),
    });
    assert_eq!(
        xml(&modify),
        "<modify_report_format report_format_id=\"rf-1\"><active>1</active><param><name> Label \t</name><value>4pyTYUdWc2JHOD0=</value></param></modify_report_format>"
    );

    modify.active = None;
    modify.param = Some(ReportFormatParamUpdate {
        name: "Label".into(),
        value: None,
    });
    assert_eq!(
        xml(&modify),
        "<modify_report_format report_format_id=\"rf-1\"><param><name>Label</name></param></modify_report_format>"
    );
    modify.param.as_mut().unwrap().value = Some(String::new());
    assert_eq!(
        xml(&modify),
        "<modify_report_format report_format_id=\"rf-1\"><param><name>Label</name><value></value></param></modify_report_format>"
    );
    modify.param.as_mut().unwrap().name.clear();
    assert_eq!(
        xml(&modify),
        "<modify_report_format report_format_id=\"rf-1\"><param><name></name><value></value></param></modify_report_format>"
    );
    modify.param = None;
    modify.name = Some(String::new());
    assert_eq!(
        xml(&modify),
        "<modify_report_format report_format_id=\"rf-1\"><name></name></modify_report_format>"
    );

    let mut delete = DeleteReportFormatRequest::new(id("rf-1"));
    delete.ultimate = Some(false);
    assert_eq!(
        xml(&delete),
        "<delete_report_format report_format_id=\"rf-1\" ultimate=\"0\"/>"
    );
    delete.ultimate = Some(true);
    assert_eq!(
        xml(&delete),
        "<delete_report_format report_format_id=\"rf-1\" ultimate=\"1\"/>"
    );
}

#[test]
fn import_preserves_original_bytes_and_accepts_rich_opaque_content() {
    let source = concat!(
        "\n<!--before--><get_report_formats_response status=\"200\">\n",
        "<report_format id=\"11111111-1111-1111-1111-111111111111\">",
        "<name><![CDATA[Imported & preserved]]></name><unknown><empty/></unknown>",
        "<param><name>Label</name><type> string </type><value> plain </value><default>blue</default><options><option>red</option></options></param>",
        "<file name=\"script.sh\">IyEvYmluL3No</file></report_format>",
        "</get_report_formats_response><!--after-->\n"
    );
    let request = ImportReportFormatRequest::new(source);
    assert_eq!(
        request.encode(GmpVersion(22, 4)).unwrap(),
        format!("<create_report_format>{source}</create_report_format>").as_bytes()
    );

    let mut changed = request.clone();
    changed.report_format_xml = import_xml("<summary>final</summary>");
    assert!(xml(&changed).contains("<summary>final</summary>"));
    assert!(!format!("{changed:?}").contains("final"));
}

#[test]
fn import_rejects_invalid_framing_shape_identity_and_entities_without_leakage() {
    let multiple = r#"<get_report_formats_response><report_format id="11111111-1111-1111-1111-111111111111"><name>one</name></report_format><report_format id="22222222-2222-2222-2222-222222222222"><name>two</name></report_format></get_report_formats_response>"#.to_string();
    let cases = [
        "",
        "<report_format id=\"11111111-1111-1111-1111-111111111111\"><name>x</name></report_format>",
        "<create_report_format><get_report_formats_response/></create_report_format>",
        "<get_report_formats_response/>",
        "<get_report_formats_response><report_format><name>x</name></report_format></get_report_formats_response>",
        "<get_report_formats_response><report_format id=\"x\"><name></name></report_format></get_report_formats_response>",
        "<get_report_formats_response><report_format id=\"x\"/></get_report_formats_response>",
        "<get_report_formats_response><wrapper><report_format id=\"x\"><name>x</name></report_format></wrapper></get_report_formats_response>",
        "prefix<get_report_formats_response><report_format id=\"x\"><name>x</name></report_format></get_report_formats_response>",
        "<get_report_formats_response><report_format id=\"x\"><name>x</name></report_format></get_report_formats_response>suffix",
        "<get_report_formats_response><report_format id=\"x\"><name>x</name></report_format></get_report_formats_response><delete_task/>",
        "<?xml version=\"1.0\"?><get_report_formats_response><report_format id=\"x\"><name>x</name></report_format></get_report_formats_response>",
        "<!DOCTYPE x [<!ENTITY ext SYSTEM \"file:///etc/passwd\">]><get_report_formats_response><report_format id=\"x\"><name>&ext;</name></report_format></get_report_formats_response>",
        "<g:get_report_formats_response xmlns:g=\"urn:gmp\"><report_format id=\"x\"><name>x</name></report_format></g:get_report_formats_response>",
        "<get_report_formats_response xmlns=\"urn:gmp\"><report_format id=\"x\"><name>x</name></report_format></get_report_formats_response>",
        "<get_report_formats_response><report_format id=\"x\"><name>&unknown;</name></report_format></get_report_formats_response>",
        multiple.as_str(),
    ];
    for source in cases {
        let request = ImportReportFormatRequest::new(source);
        let error = request.validate().expect_err(source);
        let displayed = error.to_string();
        assert!(displayed.contains("report_format_xml"));
        if !source.is_empty() {
            assert!(!displayed.contains(source));
        }
        assert!(request.encode(GmpVersion(22, 4)).is_err());
    }
}

#[test]
fn final_value_validation_rejects_invalid_combinations_and_redacts_values() {
    let mut list = GetReportFormatsRequest {
        trash: Some(true),
        params: Some(true),
        ..Default::default()
    };
    assert!(list.validate().is_err());
    assert!(list.encode(GmpVersion(22, 4)).is_err());
    list.params = Some(false);
    assert!(list.validate().is_ok());

    let mut modify = ModifyReportFormatRequest::new(id("rf-1"));
    modify.summary = Some("hidden\u{0}summary".into());
    let error = modify.validate().unwrap_err();
    assert!(error.to_string().contains("summary"));
    assert!(!error.to_string().contains("hidden"));
    modify.summary = None;
    modify.param = Some(ReportFormatParamUpdate {
        name: "hidden-name".into(),
        value: Some("hidden\0value".into()),
    });
    let error = modify.validate().unwrap_err();
    assert!(error.to_string().contains("param.value"));
    assert!(!error.to_string().contains("hidden"));
    let debug = format!("{modify:?}");
    assert!(!debug.contains("hidden-name"));
    assert!(!debug.contains("hidden\0value"));
}

#[test]
fn metadata_has_three_semantic_aliases_and_five_wire_commands() {
    assert_eq!(
        GetReportFormatsRequest::default().command(),
        Some(GmpCommand::new("get_report_formats"))
    );
    assert_eq!(
        GetReportFormatRequest::new(id("rf-1")).command(),
        Some(GmpCommand::with_semantic_name(
            "get_report_formats",
            "get_report_format"
        ))
    );
    assert_eq!(
        ImportReportFormatRequest::new(import_xml("")).command(),
        Some(GmpCommand::with_semantic_name(
            "create_report_format",
            "import_report_format"
        ))
    );
    assert_eq!(
        CloneReportFormatRequest::new(id("rf-1")).command(),
        Some(GmpCommand::with_semantic_name(
            "create_report_format",
            "clone_report_format"
        ))
    );
    assert_eq!(
        ModifyReportFormatRequest::new(id("rf-1")).command(),
        Some(GmpCommand::new("modify_report_format"))
    );
    assert_eq!(
        DeleteReportFormatRequest::new(id("rf-1")).command(),
        Some(GmpCommand::new("delete_report_format"))
    );
    assert_eq!(
        VerifyReportFormatRequest::new(id("rf-1")).command(),
        Some(GmpCommand::new("verify_report_format"))
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
    let request = GetReportFormatRequest::new(invalid);
    assert!(request.validate().is_err());
    assert!(request.encode(GmpVersion(22, 4)).is_err());
}
