// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! TLS certificate response models.

use std::fmt;

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsCertificate {
    pub meta: EntityMeta,
    pub certificate: Option<String>,
    pub issuer_dn: Option<String>,
    pub activation_time: Option<String>,
    pub expiration_time: Option<String>,
    pub md5_fingerprint: Option<String>,
    pub sha256_fingerprint: Option<String>,
    pub subject_dn: Option<String>,
    pub valid: bool,
}

impl fmt::Debug for TlsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCertificate")
            .field("meta", &self.meta)
            .field(
                "certificate",
                &self.certificate.as_ref().map(|_| "<redacted>"),
            )
            .field("issuer_dn", &self.issuer_dn)
            .field("activation_time", &self.activation_time)
            .field("expiration_time", &self.expiration_time)
            .field("md5_fingerprint", &self.md5_fingerprint)
            .field("sha256_fingerprint", &self.sha256_fingerprint)
            .field("subject_dn", &self.subject_dn)
            .field("valid", &self.valid)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTlsCertificatesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<TlsCertificate>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateTlsCertificateResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl TlsCertificate {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            certificate: node.optional_child_text("certificate"),
            issuer_dn: node.optional_child_text("issuer_dn"),
            activation_time: node.optional_child_text("activation_time"),
            expiration_time: node.optional_child_text("expiration_time"),
            md5_fingerprint: node.optional_child_text("md5_fingerprint"),
            sha256_fingerprint: node.optional_child_text("sha256_fingerprint"),
            subject_dn: node.optional_child_text("subject_dn"),
            valid: node
                .optional_child_text("valid")
                .map(|value| parse_bool(&value, "valid"))
                .transpose()?
                .unwrap_or(false),
        })
    }
}

impl GetTlsCertificatesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("tls_certificate")
            .map(TlsCertificate::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "tls_certificate_count")?,
        })
    }
}

impl CreateTlsCertificateResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let id = parse_entity_id(
            root.attr("id")
                .ok_or_else(|| ParseError::MissingElement("id".to_string()))?,
            "id",
        )?;
        Ok(Self {
            status,
            status_text,
            id,
        })
    }
}

impl GmpResponse for GetTlsCertificatesResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GmpResponse for CreateTlsCertificateResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyTlsCertificateResponse = ActionResponse;
pub type DeleteTlsCertificateResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_tls_certificates() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK">
                <tls_certificate id="tc-1">
                    <owner><name>admin</name></owner>
                    <name>Cert One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <certificate>MIIB...</certificate>
                    <issuer_dn>CN=Example CA</issuer_dn>
                    <activation_time>2026-01-01T00:00:00Z</activation_time>
                    <expiration_time>2027-01-01T00:00:00Z</expiration_time>
                    <md5_fingerprint>aa:bb:cc:dd</md5_fingerprint>
                    <sha256_fingerprint>ee:ff:00:11</sha256_fingerprint>
                    <subject_dn>CN=example.com</subject_dn>
                    <valid>1</valid>
                </tls_certificate>
                <tls_certificate id="tc-2">
                    <name>Cert Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <valid>0</valid>
                </tls_certificate>
                <tls_certificates start="2" max="1"/>
                <tls_certificate_count>7<filtered>2</filtered><page>1</page></tls_certificate_count>
            </get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("tls_certs parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(7));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].issuer_dn.as_deref(), Some("CN=Example CA"));
        assert_eq!(
            parsed.items[0].subject_dn.as_deref(),
            Some("CN=example.com")
        );
        assert_eq!(
            parsed.items[0].md5_fingerprint.as_deref(),
            Some("aa:bb:cc:dd")
        );
        assert!(parsed.items[0].valid);
        assert!(!parsed.items[1].valid);
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_tls_certificates() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificates start="1" max="100"/><tls_certificate_count>0<filtered>0</filtered><page>0</page></tls_certificate_count></get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("tls_certs parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_tls_certificate_response() {
        let response = Response::from(
            r#"<create_tls_certificate_response status="201" status_text="OK, resource created" id="tc-1"/>"#,
        );

        let parsed = CreateTlsCertificateResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "tc-1");
    }

    #[test]
    fn rejects_server_error() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="400" status_text="Bad request"/>"#,
        );

        let error =
            GetTlsCertificatesResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_tls_certificate_fields() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK">
                <tls_certificate id="tc-1">
                    <name>Only Required</name>
                </tls_certificate>
            </get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("tls_certs parse");
        let cert = &parsed.items[0];

        assert_eq!(cert.meta.comment, None);
        assert_eq!(cert.certificate, None);
        assert_eq!(cert.issuer_dn, None);
        assert_eq!(cert.subject_dn, None);
        assert!(!cert.valid);
    }

    #[test]
    fn empty_and_absent_certificate_data_both_map_to_none() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK">
                <tls_certificate id="tc-1"><name>Absent</name></tls_certificate>
                <tls_certificate id="tc-2"><name>Empty</name><certificate format="PEM"></certificate></tls_certificate>
                <tls_certificate id="tc-3"><name></name><certificate format="DER">AAEC/w==</certificate></tls_certificate>
                <tls_certificates start="1" max="3"/>
                <tls_certificate_count>9<filtered>3</filtered><page>3</page></tls_certificate_count>
            </get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("response parses");
        assert_eq!(parsed.items[0].certificate, None);
        assert_eq!(parsed.items[1].certificate, None);
        assert_eq!(parsed.items[2].meta.name, "");
        assert_eq!(parsed.items[2].certificate.as_deref(), Some("AAEC/w=="));
        assert_eq!(parsed.counts.total, Some(9));
        assert_eq!(parsed.counts.filtered, Some(3));
        assert_eq!(parsed.counts.page, Some(3));
    }

    #[test]
    fn ignores_unmodeled_expansions_and_redacts_certificate_debug() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK">
                <tls_certificate id="tc-1">
                    <owner><name>alice</name></owner><name>Rich</name>
                    <certificate format="PEM">c2VjcmV0LWNlcnRpZmljYXRl</certificate>
                    <trust>1</trust><time_status>valid</time_status><serial>01</serial>
                    <last_seen>2026-09-19T00:00:00Z</last_seen>
                    <permissions><permission><name>Everything</name></permission></permissions>
                    <tags><tag id="tag-1"><name>tag</name></tag></tags>
                    <sources><source id="source-1"><origin><origin_type>Import</origin_type></origin></source></sources>
                </tls_certificate>
                <tls_certificates start="1" max="1"/>
                <tls_certificate_count>1<filtered>1</filtered><page>1</page></tls_certificate_count>
            </get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("response parses");
        assert_eq!(
            parsed.items[0]
                .meta
                .owner
                .as_ref()
                .map(|owner| owner.name.as_str()),
            Some("alice")
        );
        let item_debug = format!("{:?}", parsed.items[0]);
        let outer_debug = format!("{parsed:?}");
        for debug in [item_debug, outer_debug] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("c2VjcmV0LWNlcnRpZmljYXRl"));
        }
    }

    #[test]
    fn rejects_missing_required_identity_and_malformed_values() {
        for xml in [
            r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate><name>Missing ID</name></tls_certificate></get_tls_certificates_response>"#,
            r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate id="tc-1"/></get_tls_certificates_response>"#,
            r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate id="tc-1"><name>x</name><valid>maybe</valid></tls_certificate></get_tls_certificates_response>"#,
            r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate_count>many</tls_certificate_count></get_tls_certificates_response>"#,
            r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate_count>1<filtered>many</filtered></tls_certificate_count></get_tls_certificates_response>"#,
        ] {
            assert!(GetTlsCertificatesResponse::from_response(&Response::from(xml)).is_err());
        }
    }
}
