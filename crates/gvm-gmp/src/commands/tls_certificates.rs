// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical TLS-certificate lifecycle requests.

use std::fmt;

use base64::Engine as _;
use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{
    CreateTlsCertificateResponse, DeleteTlsCertificateResponse, GetTlsCertificatesResponse,
    ModifyTlsCertificateResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing TLS certificates, optionally selecting one by ID.
#[derive(Debug, Clone, Default)]
pub struct GetTlsCertificatesRequest {
    /// Optional TLS-certificate identifier selector.
    pub tls_certificate_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Request detailed output, including observation sources.
    pub details: Option<bool>,
    /// Request certificate data independently of source details.
    pub include_certificate_data: Option<bool>,
}

impl GetTlsCertificatesRequest {
    /// Create an unfiltered TLS-certificate list request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tls_certificate_id: None,
            filter_string: None,
            filter_id: None,
            details: None,
            include_certificate_data: None,
        }
    }
}

impl GmpRequestCodec for GetTlsCertificatesRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            self.tls_certificate_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_tls_certificates"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_tls_certificates_command(
            self.tls_certificate_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.details,
            self.include_certificate_data,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetTlsCertificatesRequest {
    type Response = GetTlsCertificatesResponse;
}

/// Request for retrieving one TLS certificate through the shared list root.
#[derive(Debug, Clone)]
pub struct GetTlsCertificateRequest {
    /// Required TLS-certificate identifier selector.
    pub tls_certificate_id: EntityId,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Request detailed output, including observation sources.
    pub details: Option<bool>,
    /// Request certificate data independently of source details.
    pub include_certificate_data: Option<bool>,
}

impl GetTlsCertificateRequest {
    /// Create an ID-selected request with details enabled by default.
    #[must_use]
    pub fn new(tls_certificate_id: EntityId) -> Self {
        Self {
            tls_certificate_id,
            filter_string: None,
            filter_id: None,
            details: Some(true),
            include_certificate_data: None,
        }
    }
}

impl GmpRequestCodec for GetTlsCertificateRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            Some(&self.tls_certificate_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_tls_certificates",
            "get_tls_certificate",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_tls_certificates_command(
            Some(&self.tls_certificate_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.details,
            self.include_certificate_data,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetTlsCertificateRequest {
    type Response = GetTlsCertificatesResponse;
}

/// Request for creating a TLS certificate from original PEM or DER bytes.
#[derive(Clone)]
pub struct CreateTlsCertificateRequest {
    /// Original certificate-file bytes. The codec applies standard base64 once.
    pub certificate: Vec<u8>,
    /// Optional name. gvmd defaults an omitted or empty name to the SHA-256 fingerprint.
    pub name: Option<String>,
    /// Optional comment. An explicit empty value is emitted as a paired element.
    pub comment: Option<String>,
    /// Optional stored trust flag, independent of certificate time validity.
    pub trust: Option<bool>,
}

impl CreateTlsCertificateRequest {
    /// Own original certificate-file bytes for encoding during execution.
    #[must_use]
    pub fn new(certificate: impl Into<Vec<u8>>) -> Self {
        Self {
            certificate: certificate.into(),
            name: None,
            comment: None,
            trust: None,
        }
    }
}

impl fmt::Debug for CreateTlsCertificateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateTlsCertificateRequest")
            .field("certificate", &"<redacted>")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("trust", &self.trust)
            .finish()
    }
}

impl GmpRequestCodec for CreateTlsCertificateRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if self.certificate.is_empty() {
            return Err(GmpRequestError::invalid_field(
                "certificate",
                "must not be empty",
            ));
        }
        validate_optional_xml_text(self.name.as_deref(), "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_tls_certificate"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("create_tls_certificate");
        if let Some(name) = &self.name {
            command.add_element_with_text("name", name);
        }
        if let Some(comment) = &self.comment {
            command.add_element_with_text("comment", comment);
        }
        command.add_element_with_text(
            "certificate",
            &base64::engine::general_purpose::STANDARD.encode(&self.certificate),
        );
        if let Some(trust) = self.trust {
            command.add_element_with_text("trust", if trust { "1" } else { "0" });
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for CreateTlsCertificateRequest {
    type Response = CreateTlsCertificateResponse;
}

/// Request for cloning a TLS certificate through `create_tls_certificate`.
#[derive(Debug, Clone)]
pub struct CloneTlsCertificateRequest {
    /// Existing TLS certificate to copy.
    pub tls_certificate_id: EntityId,
    /// Optional name override. Omission or an empty value copies the source name.
    pub name: Option<String>,
    /// Optional comment override. Omission or an empty value copies the source comment.
    pub comment: Option<String>,
}

impl CloneTlsCertificateRequest {
    /// Create a TLS-certificate clone request without overrides.
    #[must_use]
    pub fn new(tls_certificate_id: EntityId) -> Self {
        Self {
            tls_certificate_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneTlsCertificateRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.tls_certificate_id, "tls_certificate_id")?;
        validate_optional_xml_text(self.name.as_deref(), "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_tls_certificate",
            "clone_tls_certificate",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("create_tls_certificate");
        command.add_element_with_text("copy", self.tls_certificate_id.as_str());
        if let Some(name) = &self.name {
            command.add_element_with_text("name", name);
        }
        if let Some(comment) = &self.comment {
            command.add_element_with_text("comment", comment);
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for CloneTlsCertificateRequest {
    type Response = CreateTlsCertificateResponse;
}

/// Request for modifying TLS-certificate metadata or trust.
#[derive(Debug, Clone)]
pub struct ModifyTlsCertificateRequest {
    /// TLS certificate to modify.
    pub tls_certificate_id: EntityId,
    /// Optional exact replacement name. An empty value clears the name.
    pub name: Option<String>,
    /// Optional exact replacement comment. An empty value clears the comment.
    pub comment: Option<String>,
    /// Optional stored trust replacement.
    pub trust: Option<bool>,
}

impl ModifyTlsCertificateRequest {
    /// Create a selector-only TLS-certificate modification request.
    #[must_use]
    pub fn new(tls_certificate_id: EntityId) -> Self {
        Self {
            tls_certificate_id,
            name: None,
            comment: None,
            trust: None,
        }
    }
}

impl GmpRequestCodec for ModifyTlsCertificateRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.tls_certificate_id, "tls_certificate_id")?;
        validate_optional_xml_text(self.name.as_deref(), "name")?;
        validate_optional_xml_text(self.comment.as_deref(), "comment")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_tls_certificate"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("modify_tls_certificate");
        command.set_attribute("tls_certificate_id", self.tls_certificate_id.as_str());
        if let Some(name) = &self.name {
            command.add_element_with_text("name", name);
        }
        if let Some(comment) = &self.comment {
            command.add_element_with_text("comment", comment);
        }
        if let Some(trust) = self.trust {
            command.add_element_with_text("trust", if trust { "1" } else { "0" });
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for ModifyTlsCertificateRequest {
    type Response = ModifyTlsCertificateResponse;
}

/// Request for permanently deleting a TLS certificate.
#[derive(Debug, Clone)]
pub struct DeleteTlsCertificateRequest {
    /// TLS certificate to delete permanently.
    pub tls_certificate_id: EntityId,
}

impl DeleteTlsCertificateRequest {
    /// Create a TLS-certificate deletion request.
    #[must_use]
    pub fn new(tls_certificate_id: EntityId) -> Self {
        Self { tls_certificate_id }
    }
}

impl GmpRequestCodec for DeleteTlsCertificateRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.tls_certificate_id, "tls_certificate_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_tls_certificate"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("delete_tls_certificate");
        command.set_attribute("tls_certificate_id", self.tls_certificate_id.as_str());
        Ok(command.to_bytes())
    }
}

impl GmpRequest for DeleteTlsCertificateRequest {
    type Response = DeleteTlsCertificateResponse;
}

fn get_tls_certificates_command(
    tls_certificate_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    details: Option<bool>,
    include_certificate_data: Option<bool>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_tls_certificates");
    if let Some(tls_certificate_id) = tls_certificate_id {
        command.set_attribute("tls_certificate_id", tls_certificate_id.as_str());
    }
    add_filter_attrs(&mut command, filter_string, filter_id);
    set_optional_bool_attr(&mut command, "details", details);
    set_optional_bool_attr(
        &mut command,
        "include_certificate_data",
        include_certificate_data,
    );
    command
}

fn validate_query(
    tls_certificate_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> Result<(), GmpRequestError> {
    validate_optional_id(tls_certificate_id, "tls_certificate_id")?;
    validate_optional_id(filter_id, "filter_id")?;
    validate_optional_xml_text(filter_string, "filter_string")
}

fn validate_optional_xml_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    value.map_or(Ok(()), |value| validate_xml_text(value, field))
}

fn validate_xml_text(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.chars().all(is_xml_1_0_character) {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ))
    }
}

fn validate_optional_id(id: Option<&EntityId>, field: &'static str) -> Result<(), GmpRequestError> {
    id.map_or(Ok(()), |id| validate_id(id, field))
}

fn validate_id(id: &EntityId, field: &'static str) -> Result<(), GmpRequestError> {
    if EntityId::new(id.as_str()).is_ok() {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must be a valid entity identifier",
        ))
    }
}

const fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(character as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}
