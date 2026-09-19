// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::tls_certificates::*;
use gvm_gmp::responses::{
    CreateTlsCertificateResponse, DeleteTlsCertificateResponse, GetTlsCertificatesResponse,
    ModifyTlsCertificateResponse,
};
use gvm_gmp::{EntityId, GmpCommand, GmpRequest, GmpRequestCodec, GmpVersion};

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid entity identifier")
}

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).expect("valid request"))
        .expect("valid UTF-8")
}

#[test]
fn six_exact_wire_contracts_and_response_associations_are_independent() {
    fn associated<R, T>(_: &R)
    where
        R: GmpRequest<Response = T>,
        T: gvm_gmp::GmpResponse,
    {
    }

    let list = GetTlsCertificatesRequest::new();
    assert_eq!(xml(&list), "<get_tls_certificates/>");
    associated::<_, GetTlsCertificatesResponse>(&list);

    let detail = GetTlsCertificateRequest::new(id("tls-1"));
    assert_eq!(
        xml(&detail),
        "<get_tls_certificates details=\"1\" tls_certificate_id=\"tls-1\"/>"
    );
    associated::<_, GetTlsCertificatesResponse>(&detail);

    let create = CreateTlsCertificateRequest::new(b"cert".to_vec());
    assert_eq!(
        xml(&create),
        "<create_tls_certificate><certificate>Y2VydA==</certificate></create_tls_certificate>"
    );
    associated::<_, CreateTlsCertificateResponse>(&create);

    let clone = CloneTlsCertificateRequest::new(id("tls-1"));
    assert_eq!(
        xml(&clone),
        "<create_tls_certificate><copy>tls-1</copy></create_tls_certificate>"
    );
    associated::<_, CreateTlsCertificateResponse>(&clone);

    let modify = ModifyTlsCertificateRequest::new(id("tls-1"));
    assert_eq!(
        xml(&modify),
        "<modify_tls_certificate tls_certificate_id=\"tls-1\"/>"
    );
    associated::<_, ModifyTlsCertificateResponse>(&modify);

    let delete = DeleteTlsCertificateRequest::new(id("tls-1"));
    assert_eq!(
        xml(&delete),
        "<delete_tls_certificate tls_certificate_id=\"tls-1\"/>"
    );
    associated::<_, DeleteTlsCertificateResponse>(&delete);
}

#[test]
fn query_controls_preserve_selectors_filters_sentinels_and_boolean_states() {
    let request = GetTlsCertificatesRequest {
        tls_certificate_id: Some(id("tls-1")),
        filter_string: Some("name=Example first=2 rows=1 sort=name".into()),
        filter_id: Some(id("filter-1")),
        details: Some(false),
        include_certificate_data: Some(true),
    };
    assert_eq!(
        xml(&request),
        "<get_tls_certificates details=\"0\" filt_id=\"filter-1\" filter=\"name=Example first=2 rows=1 sort=name\" include_certificate_data=\"1\" tls_certificate_id=\"tls-1\"/>"
    );

    for filter_id in ["0", "-2"] {
        let request = GetTlsCertificatesRequest {
            filter_string: Some(String::new()),
            filter_id: Some(id(filter_id)),
            ..Default::default()
        };
        assert_eq!(
            xml(&request),
            format!("<get_tls_certificates filt_id=\"{filter_id}\" filter=\"\"/>")
        );
    }

    for value in [false, true] {
        let request = GetTlsCertificatesRequest {
            details: Some(value),
            include_certificate_data: Some(value),
            ..Default::default()
        };
        let bit = if value { "1" } else { "0" };
        assert_eq!(
            xml(&request),
            format!("<get_tls_certificates details=\"{bit}\" include_certificate_data=\"{bit}\"/>")
        );
    }

    let mut detail = GetTlsCertificateRequest::new(id("tls-1"));
    detail.details = Some(false);
    detail.filter_string = Some(String::new());
    detail.include_certificate_data = Some(true);
    assert_eq!(
        xml(&detail),
        "<get_tls_certificates details=\"0\" filter=\"\" include_certificate_data=\"1\" tls_certificate_id=\"tls-1\"/>"
    );
}

#[test]
fn create_clone_and_modify_preserve_absent_empty_value_and_order() {
    let mut create = CreateTlsCertificateRequest::new(b"cert".to_vec());
    create.name = Some("A & B".into());
    create.comment = Some(String::new());
    create.trust = Some(false);
    assert_eq!(
        xml(&create),
        "<create_tls_certificate><name>A &amp; B</name><comment></comment><certificate>Y2VydA==</certificate><trust>0</trust></create_tls_certificate>"
    );
    create.name = Some(String::new());
    create.comment = None;
    create.trust = Some(true);
    assert_eq!(
        xml(&create),
        "<create_tls_certificate><name></name><certificate>Y2VydA==</certificate><trust>1</trust></create_tls_certificate>"
    );

    let mut clone = CloneTlsCertificateRequest::new(id("tls-1"));
    clone.name = Some("Imported copy".into());
    clone.comment = Some("Override".into());
    assert_eq!(
        xml(&clone),
        "<create_tls_certificate><copy>tls-1</copy><name>Imported copy</name><comment>Override</comment></create_tls_certificate>"
    );
    clone.name = Some(String::new());
    clone.comment = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_tls_certificate><copy>tls-1</copy><name></name><comment></comment></create_tls_certificate>"
    );

    let mut modify = ModifyTlsCertificateRequest::new(id("tls-1"));
    modify.name = Some(String::new());
    modify.comment = Some(String::new());
    modify.trust = Some(false);
    assert_eq!(
        xml(&modify),
        "<modify_tls_certificate tls_certificate_id=\"tls-1\"><name></name><comment></comment><trust>0</trust></modify_tls_certificate>"
    );
    modify.name = Some(" \t✓ ".into());
    modify.comment = None;
    modify.trust = Some(true);
    assert_eq!(
        xml(&modify),
        "<modify_tls_certificate tls_certificate_id=\"tls-1\"><name> \t✓ </name><trust>1</trust></modify_tls_certificate>"
    );
}

#[test]
fn certificate_bytes_are_standard_base64_encoded_exactly_once() {
    let pem_lf = b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
    let pem_crlf = b"-----BEGIN CERTIFICATE-----\r\nYWJj\r\n-----END CERTIFICATE-----\r\n";
    let der = [0x30, 0x82, 0x00, 0xff, 0x00, 0x80];
    let already_base64_looking = b"Y2VydA==";

    for (bytes, expected) in [
        (
            pem_lf.as_slice(),
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCllXSmoKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
        ),
        (
            pem_crlf.as_slice(),
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpZV0pqDQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tDQo=",
        ),
        (der.as_slice(), "MIIA/wCA"),
        (already_base64_looking.as_slice(), "WTJWeWRBPT0="),
    ] {
        let rendered = xml(&CreateTlsCertificateRequest::new(bytes));
        assert_eq!(
            rendered,
            format!("<create_tls_certificate><certificate>{expected}</certificate></create_tls_certificate>")
        );
    }
}

#[test]
fn final_mutation_changes_bytes_or_fails_direct_encode() {
    let mut create = CreateTlsCertificateRequest::new(b"initial".to_vec());
    create.certificate = vec![0x00, 0xff, 0x10];
    assert!(xml(&create).contains("AP8Q"));
    create.certificate.clear();
    assert!(create.validate().is_err());
    assert!(create.encode(GmpVersion(22, 4)).is_err());

    let mut query = GetTlsCertificatesRequest::new();
    query.filter_string = Some("valid ✓".into());
    assert!(xml(&query).contains("valid ✓"));
    query.filter_string = Some("hidden\0filter".into());
    let error = query.validate().unwrap_err();
    assert!(error.to_string().contains("filter_string"));
    assert!(!error.to_string().contains("hidden"));
    assert!(query.encode(GmpVersion(22, 4)).is_err());

    let mut modify = ModifyTlsCertificateRequest::new(id("tls-1"));
    modify.comment = Some("hidden\u{1}comment".into());
    let error = modify.validate().unwrap_err();
    assert!(error.to_string().contains("comment"));
    assert!(!error.to_string().contains("hidden"));
    assert!(modify.encode(GmpVersion(22, 4)).is_err());
}

#[test]
fn create_debug_redacts_raw_numeric_and_base64_certificate_forms() {
    let request = CreateTlsCertificateRequest::new(b"secret-certificate\0\xff".to_vec());
    let debug = format!("{request:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("secret-certificate"));
    assert!(!debug.contains("[115, 101, 99, 114, 101, 116"));
    assert!(!debug.contains("c2VjcmV0LWNlcnRpZmljYXRlAP8="));
}

#[test]
fn metadata_has_two_semantic_aliases_and_four_wire_commands() {
    assert_eq!(
        GetTlsCertificatesRequest::new().command(),
        Some(GmpCommand::new("get_tls_certificates"))
    );
    assert_eq!(
        GetTlsCertificateRequest::new(id("tls-1")).command(),
        Some(GmpCommand::with_semantic_name(
            "get_tls_certificates",
            "get_tls_certificate"
        ))
    );
    assert_eq!(
        CreateTlsCertificateRequest::new(b"cert".to_vec()).command(),
        Some(GmpCommand::new("create_tls_certificate"))
    );
    assert_eq!(
        CloneTlsCertificateRequest::new(id("tls-1")).command(),
        Some(GmpCommand::with_semantic_name(
            "create_tls_certificate",
            "clone_tls_certificate"
        ))
    );
    assert_eq!(
        ModifyTlsCertificateRequest::new(id("tls-1")).command(),
        Some(GmpCommand::new("modify_tls_certificate"))
    );
    assert_eq!(
        DeleteTlsCertificateRequest::new(id("tls-1")).command(),
        Some(GmpCommand::new("delete_tls_certificate"))
    );
}

#[test]
fn unsupported_lifecycle_fields_are_absent_from_all_wire_shapes() {
    let requests = [
        xml(&GetTlsCertificatesRequest::new()),
        xml(&GetTlsCertificateRequest::new(id("tls-1"))),
        xml(&CreateTlsCertificateRequest::new(b"cert".to_vec())),
        xml(&CloneTlsCertificateRequest::new(id("tls-1"))),
        xml(&ModifyTlsCertificateRequest::new(id("tls-1"))),
        xml(&DeleteTlsCertificateRequest::new(id("tls-1"))),
    ];
    for request in requests {
        for unsupported in [
            "<private",
            "ultimate=",
            "trash=",
            "ignore_pagination=",
            "first=",
            "rows=",
        ] {
            assert!(!request.contains(unsupported), "{request}");
        }
    }
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
    let request = GetTlsCertificateRequest::new(invalid);
    assert!(request.validate().is_err());
    assert!(request.encode(GmpVersion(22, 4)).is_err());
}
