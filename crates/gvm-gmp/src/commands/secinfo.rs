// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical security-information discovery requests.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{
    GetCertBundAdvisoriesResponse, GetCpesResponse, GetCvesResponse, GetDfnCertAdvisoriesResponse,
    GetInfoResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Historical security-information wire spellings.
///
/// This enum is not accepted by canonical `get_info` requests: some of its
/// values have no pinned gvmd dispatch. Use [`GenericInfoType`] for supported
/// canonical requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoType {
    /// CERT-Bund advisories.
    CertBundAdvisory,
    /// CPE entries.
    Cpe,
    /// CVE entries.
    Cve,
    /// DFN-CERT advisories.
    DfnCertAdvisory,
    /// Historical operating-system spelling; unsupported by pinned `get_info`.
    OperatingSystem,
    /// Historical vulnerability spelling; unsupported by pinned `get_info`.
    Vulnerability,
}

impl InfoType {
    /// Return the historical GMP wire spelling without implying handler support.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::CertBundAdvisory => "CERT_BUND_ADV",
            Self::Cpe => "CPE",
            Self::Cve => "CVE",
            Self::DfnCertAdvisory => "DFN_CERT_ADV",
            Self::OperatingSystem => "os",
            Self::Vulnerability => "vuln",
        }
    }
}

/// Security-information kinds with pinned gvmd `get_info` dispatch.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericInfoType {
    /// CERT-Bund advisories.
    CertBundAdvisory,
    /// CPE entries.
    Cpe,
    /// CVE entries.
    Cve,
    /// DFN-CERT advisories.
    DfnCertAdvisory,
    /// NVT feed information.
    Nvt,
}

impl GenericInfoType {
    /// Return the canonical GMP type spelling.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::CertBundAdvisory => "CERT_BUND_ADV",
            Self::Cpe => "CPE",
            Self::Cve => "CVE",
            Self::DfnCertAdvisory => "DFN_CERT_ADV",
            Self::Nvt => "NVT",
        }
    }
}

/// Generic supported `get_info` list request.
#[derive(Debug, Clone)]
pub struct GetInfoListRequest {
    /// Required supported information type.
    pub info_type: GenericInfoType,
    /// Optional exact name selector, distinct from `info_id`.
    pub name: Option<String>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. Sentinels `0` and `-2` are valid.
    pub filter_id: Option<EntityId>,
    /// Request source/raw-data expansions.
    pub details: Option<bool>,
}

impl GetInfoListRequest {
    /// Create an unfiltered list request for a supported information type.
    #[must_use]
    pub const fn new(info_type: GenericInfoType) -> Self {
        Self {
            info_type,
            name: None,
            filter_string: None,
            filter_id: None,
            details: None,
        }
    }
}

impl GmpRequestCodec for GetInfoListRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_info_query(
            None,
            self.name.as_deref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_info", "get_info_list"))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(info_command(
            self.info_type,
            None,
            self.name.as_deref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.details,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetInfoListRequest {
    type Response = GetInfoResponse;
}

/// Generic supported `get_info` detail request.
#[derive(Debug, Clone)]
pub struct GetInfoRequest {
    /// Required opaque information identifier.
    pub info_id: String,
    /// Required supported information type.
    pub info_type: GenericInfoType,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. Sentinels `0` and `-2` are valid.
    pub filter_id: Option<EntityId>,
    /// Request source/raw-data expansions. Defaults to `Some(true)`.
    pub details: Option<bool>,
}

impl GetInfoRequest {
    /// Create a detailed request for one supported information item.
    #[must_use]
    pub fn new(info_id: impl Into<String>, info_type: GenericInfoType) -> Self {
        Self {
            info_id: info_id.into(),
            info_type,
            filter_string: None,
            filter_id: None,
            details: Some(true),
        }
    }
}

impl GmpRequestCodec for GetInfoRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_info_query(
            Some(&self.info_id),
            None,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_info"))
    }
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(info_command(
            self.info_type,
            Some(&self.info_id),
            None,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.details,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetInfoRequest {
    type Response = GetInfoResponse;
}

/// Request for listing CPE entries.
#[derive(Debug, Clone, Default)]
pub struct GetCpesRequest {
    /// Optional exact name selector.
    pub name: Option<String>,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion.
    pub details: Option<bool>,
}

/// Request for retrieving one CPE entry.
#[derive(Debug, Clone)]
pub struct GetCpeRequest {
    /// Required opaque CPE identifier.
    pub info_id: String,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion. Defaults to `Some(true)`.
    pub details: Option<bool>,
}

/// Request for listing CVE entries.
#[derive(Debug, Clone, Default)]
pub struct GetCvesRequest {
    /// Optional exact name selector.
    pub name: Option<String>,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion.
    pub details: Option<bool>,
}

/// Request for retrieving one CVE entry.
#[derive(Debug, Clone)]
pub struct GetCveRequest {
    /// Required opaque CVE identifier.
    pub info_id: String,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion. Defaults to `Some(true)`.
    pub details: Option<bool>,
}

/// Request for listing CERT-Bund advisories.
#[derive(Debug, Clone, Default)]
pub struct GetCertBundAdvisoriesRequest {
    /// Optional exact name selector.
    pub name: Option<String>,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion.
    pub details: Option<bool>,
}

/// Request for retrieving one CERT-Bund advisory.
#[derive(Debug, Clone)]
pub struct GetCertBundAdvisoryRequest {
    /// Required opaque advisory identifier.
    pub info_id: String,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion. Defaults to `Some(true)`.
    pub details: Option<bool>,
}

/// Request for listing DFN-CERT advisories.
#[derive(Debug, Clone, Default)]
pub struct GetDfnCertAdvisoriesRequest {
    /// Optional exact name selector.
    pub name: Option<String>,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion.
    pub details: Option<bool>,
}

/// Request for retrieving one DFN-CERT advisory.
#[derive(Debug, Clone)]
pub struct GetDfnCertAdvisoryRequest {
    /// Required opaque advisory identifier.
    pub info_id: String,
    /// Optional inline GMP filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Request detailed expansion. Defaults to `Some(true)`.
    pub details: Option<bool>,
}

macro_rules! impl_list_request {
    ($request:ty, $kind:expr, $response:ty, $semantic:literal) => {
        impl GmpRequestCodec for $request {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_info_query(
                    None,
                    self.name.as_deref(),
                    self.filter_string.as_deref(),
                    self.filter_id.as_ref(),
                )
            }
            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::with_semantic_name("get_info", $semantic))
            }
            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                Ok(info_command(
                    $kind,
                    None,
                    self.name.as_deref(),
                    self.filter_string.as_deref(),
                    self.filter_id.as_ref(),
                    self.details,
                )
                .to_bytes())
            }
        }
        impl GmpRequest for $request {
            type Response = $response;
        }
    };
}

macro_rules! impl_detail_request {
    ($request:ty, $kind:expr, $response:ty, $semantic:literal) => {
        impl GmpRequestCodec for $request {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_info_query(
                    Some(&self.info_id),
                    None,
                    self.filter_string.as_deref(),
                    self.filter_id.as_ref(),
                )
            }
            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::with_semantic_name("get_info", $semantic))
            }
            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                Ok(info_command(
                    $kind,
                    Some(&self.info_id),
                    None,
                    self.filter_string.as_deref(),
                    self.filter_id.as_ref(),
                    self.details,
                )
                .to_bytes())
            }
        }
        impl GmpRequest for $request {
            type Response = $response;
        }
    };
}

macro_rules! detail_constructor {
    ($request:ty) => {
        impl $request {
            /// Create a detailed single-entry request.
            #[must_use]
            pub fn new(info_id: impl Into<String>) -> Self {
                Self {
                    info_id: info_id.into(),
                    filter_string: None,
                    filter_id: None,
                    details: Some(true),
                }
            }
        }
    };
}

detail_constructor!(GetCpeRequest);
detail_constructor!(GetCveRequest);
detail_constructor!(GetCertBundAdvisoryRequest);
detail_constructor!(GetDfnCertAdvisoryRequest);

impl_list_request!(
    GetCpesRequest,
    GenericInfoType::Cpe,
    GetCpesResponse,
    "get_cpes"
);
impl_detail_request!(
    GetCpeRequest,
    GenericInfoType::Cpe,
    GetCpesResponse,
    "get_cpe"
);
impl_list_request!(
    GetCvesRequest,
    GenericInfoType::Cve,
    GetCvesResponse,
    "get_cves"
);
impl_detail_request!(
    GetCveRequest,
    GenericInfoType::Cve,
    GetCvesResponse,
    "get_cve"
);
impl_list_request!(
    GetCertBundAdvisoriesRequest,
    GenericInfoType::CertBundAdvisory,
    GetCertBundAdvisoriesResponse,
    "get_cert_bund_advisories"
);
impl_detail_request!(
    GetCertBundAdvisoryRequest,
    GenericInfoType::CertBundAdvisory,
    GetCertBundAdvisoriesResponse,
    "get_cert_bund_advisory"
);
impl_list_request!(
    GetDfnCertAdvisoriesRequest,
    GenericInfoType::DfnCertAdvisory,
    GetDfnCertAdvisoriesResponse,
    "get_dfn_cert_advisories"
);
impl_detail_request!(
    GetDfnCertAdvisoryRequest,
    GenericInfoType::DfnCertAdvisory,
    GetDfnCertAdvisoriesResponse,
    "get_dfn_cert_advisory"
);

#[allow(clippy::too_many_arguments)]
fn info_command(
    info_type: GenericInfoType,
    info_id: Option<&str>,
    name: Option<&str>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    details: Option<bool>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_info");
    command.set_attribute("type", info_type.as_gmp_str());
    if let Some(value) = info_id {
        command.set_attribute("info_id", value);
    }
    if let Some(value) = name {
        command.set_attribute("name", value);
    }
    add_filter_attrs(&mut command, filter_string, filter_id);
    set_optional_bool_attr(&mut command, "details", details);
    command
}

fn validate_info_query(
    info_id: Option<&str>,
    name: Option<&str>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> Result<(), GmpRequestError> {
    validate_optional_nonempty(info_id, "info_id")?;
    validate_optional_nonempty(name, "name")?;
    validate_optional_xml(filter_string, "filter_string")?;
    if filter_id.is_some_and(|value| EntityId::new(value.as_str()).is_err()) {
        return Err(GmpRequestError::invalid_field(
            "filter_id",
            "must be a valid entity identifier",
        ));
    }
    Ok(())
}

fn validate_optional_nonempty(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            return Err(GmpRequestError::invalid_field(field, "must not be empty"));
        }
        validate_xml(value, field)?;
    }
    Ok(())
}

fn validate_optional_xml(value: Option<&str>, field: &'static str) -> Result<(), GmpRequestError> {
    if let Some(value) = value {
        validate_xml(value, field)?;
    }
    Ok(())
}

fn validate_xml(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if !value.chars().all(is_xml_1_0_character) {
        return Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ));
    }
    Ok(())
}

const fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(character as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }
    fn xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(request.encode(GmpVersion(22, 4)).expect("valid request")).expect("XML")
    }

    #[test]
    fn supported_types_are_exact() {
        assert_eq!(
            GenericInfoType::CertBundAdvisory.as_gmp_str(),
            "CERT_BUND_ADV"
        );
        assert_eq!(GenericInfoType::Cpe.as_gmp_str(), "CPE");
        assert_eq!(GenericInfoType::Cve.as_gmp_str(), "CVE");
        assert_eq!(
            GenericInfoType::DfnCertAdvisory.as_gmp_str(),
            "DFN_CERT_ADV"
        );
        assert_eq!(GenericInfoType::Nvt.as_gmp_str(), "NVT");
    }

    #[test]
    fn generic_requests_encode_exact_independent_xml() {
        assert_eq!(
            xml(&GetInfoListRequest::new(GenericInfoType::Nvt)),
            "<get_info type=\"NVT\"/>"
        );
        let mut list = GetInfoListRequest::new(GenericInfoType::Nvt);
        list.name = Some("Example & test".into());
        list.filter_string = Some("severity>7 rows=10".into());
        list.filter_id = Some(id("0"));
        list.details = Some(false);
        assert_eq!(xml(&list), "<get_info details=\"0\" filt_id=\"0\" filter=\"severity&gt;7 rows=10\" name=\"Example &amp; test\" type=\"NVT\"/>");
        assert_eq!(
            xml(&GetInfoRequest::new("CVE-2026-0001", GenericInfoType::Cve)),
            "<get_info details=\"1\" info_id=\"CVE-2026-0001\" type=\"CVE\"/>"
        );
    }

    #[test]
    fn specialized_requests_have_fixed_types_and_complete_fields() {
        assert_eq!(xml(&GetCpesRequest::default()), "<get_info type=\"CPE\"/>");
        assert_eq!(
            xml(&GetCpeRequest::new("cpe:/a:example:app")),
            "<get_info details=\"1\" info_id=\"cpe:/a:example:app\" type=\"CPE\"/>"
        );
        assert_eq!(xml(&GetCvesRequest::default()), "<get_info type=\"CVE\"/>");
        assert_eq!(
            xml(&GetCveRequest::new("CVE-2026-0001")),
            "<get_info details=\"1\" info_id=\"CVE-2026-0001\" type=\"CVE\"/>"
        );
        assert_eq!(
            xml(&GetCertBundAdvisoriesRequest::default()),
            "<get_info type=\"CERT_BUND_ADV\"/>"
        );
        assert_eq!(
            xml(&GetCertBundAdvisoryRequest::new("CB-K26/001")),
            "<get_info details=\"1\" info_id=\"CB-K26/001\" type=\"CERT_BUND_ADV\"/>"
        );
        assert_eq!(
            xml(&GetDfnCertAdvisoriesRequest::default()),
            "<get_info type=\"DFN_CERT_ADV\"/>"
        );
        assert_eq!(
            xml(&GetDfnCertAdvisoryRequest::new("DFN-2026-001")),
            "<get_info details=\"1\" info_id=\"DFN-2026-001\" type=\"DFN_CERT_ADV\"/>"
        );
    }

    #[test]
    fn metadata_precedes_shared_wire_root() {
        assert_eq!(
            GetInfoListRequest::new(GenericInfoType::Nvt).command(),
            Some(GmpCommand::with_semantic_name("get_info", "get_info_list"))
        );
        assert_eq!(
            GetCvesRequest::default().command(),
            Some(GmpCommand::with_semantic_name("get_info", "get_cves"))
        );
        assert_eq!(
            GetCveRequest::new("CVE-1").command(),
            Some(GmpCommand::with_semantic_name("get_info", "get_cve"))
        );
    }

    #[test]
    fn mutated_final_selectors_validate_and_empty_filters_remain_valid() {
        let mut request = GetCveRequest::new("CVE-2026-0001");
        request.info_id = "  ".into();
        assert!(request.encode(GmpVersion(22, 4)).is_err());
        let request = GetCvesRequest {
            filter_string: Some(String::new()),
            filter_id: Some(id("-2")),
            ..Default::default()
        };
        assert_eq!(
            xml(&request),
            "<get_info filt_id=\"-2\" filter=\"\" type=\"CVE\"/>"
        );
        let request = GetInfoListRequest {
            name: Some("secret\u{0}".into()),
            ..GetInfoListRequest::new(GenericInfoType::Cve)
        };
        let error = request.validate().expect_err("invalid XML");
        assert!(!error.to_string().contains("secret"));
    }
}
