// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Security-information and observed-vulnerability response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, status_from_response, CountInfo, ParseError, XmlNode,
};
use crate::{GmpResponse, GmpVersion};

const SUPPORTED_INFO_ELEMENTS: &[(&str, &str)] = &[
    ("cert_bund_adv", "CERT_BUND_ADV"),
    ("cpe", "CPE"),
    ("cve", "CVE"),
    ("dfn_cert_adv", "DFN_CERT_ADV"),
    ("nvt", "NVT"),
];

/// A bounded resource projection from gvmd's enclosing `<info>` wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GenericInfo {
    /// Canonical GMP type spelling identified by the direct payload child.
    pub info_type: String,
    /// Identifier from the enclosing `<info id="...">` wrapper.
    pub id: String,
    /// Name from the enclosing wrapper.
    pub name: String,
}

/// Typed response for generic supported `get_info` requests.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetInfoResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<GenericInfo>,
    pub counts: CountInfo,
}

macro_rules! info_item {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            pub id: String,
            pub name: String,
        }
    };
}

info_item!(Cve);
info_item!(Cpe);
info_item!(CertBundAdvisory);
info_item!(DfnCertAdvisory);

macro_rules! info_response {
    ($name:ident, $item:ty) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            pub status: u16,
            pub status_text: String,
            pub items: Vec<$item>,
            pub counts: CountInfo,
        }
    };
}

info_response!(GetCvesResponse, Cve);
info_response!(GetCpesResponse, Cpe);
info_response!(GetCertBundAdvisoriesResponse, CertBundAdvisory);
info_response!(GetDfnCertAdvisoriesResponse, DfnCertAdvisory);

fn canonical_info_items(root: &XmlNode) -> Result<Option<Vec<GenericInfo>>, ParseError> {
    let wrappers: Vec<_> = root.children_named("info").collect();
    if wrappers.is_empty() {
        return Ok(None);
    }
    let mut items = Vec::new();
    for wrapper in wrappers {
        let recognized: Vec<_> = SUPPORTED_INFO_ELEMENTS
            .iter()
            .filter(|(element, _)| wrapper.child(element).is_some())
            .collect();
        if recognized.len() > 1 {
            return Err(ParseError::InvalidValue {
                field: "info.payload".into(),
                value: "multiple supported payloads".into(),
            });
        }
        let Some((_, info_type)) = recognized.first() else {
            continue;
        };
        let id = wrapper
            .attr("id")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ParseError::MissingElement("info.id".into()))?;
        let name = wrapper.required_child_text("name")?;
        if name.is_empty() {
            return Err(ParseError::MissingElement("info.name".into()));
        }
        items.push(GenericInfo {
            info_type: (*info_type).to_string(),
            id: id.to_string(),
            name,
        });
    }
    Ok(Some(items))
}

fn legacy_info_items(root: &XmlNode) -> Result<Vec<GenericInfo>, ParseError> {
    root.children
        .iter()
        .filter_map(|node| {
            SUPPORTED_INFO_ELEMENTS
                .iter()
                .find(|(element, _)| *element == node.name)
                .map(|(_, info_type)| {
                    let id = node
                        .attr("id")
                        .or_else(|| node.attr("oid"))
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| ParseError::MissingElement(format!("{}.id", node.name)))?;
                    let name = node.required_child_text("name")?;
                    Ok(GenericInfo {
                        info_type: (*info_type).to_string(),
                        id: id.to_string(),
                        name,
                    })
                })
        })
        .collect()
}

fn parsed_info(
    response: &Response,
) -> Result<(u16, String, Vec<GenericInfo>, CountInfo, bool), ParseError> {
    let (status, status_text) = status_from_response(response)?;
    let root = parse_document(response.data())?;
    if let Some(items) = canonical_info_items(&root)? {
        let counts = count_info(&root, "info_count")?;
        Ok((status, status_text, items, counts, true))
    } else {
        let items = legacy_info_items(&root)?;
        let mut counts = CountInfo::default();
        for (element, _) in SUPPORTED_INFO_ELEMENTS {
            let candidate = count_info(&root, &format!("{element}_count"))?;
            if candidate != CountInfo::default() {
                counts = candidate;
                break;
            }
        }
        Ok((status, status_text, items, counts, false))
    }
}

impl GetInfoResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text, items, counts, _) = parsed_info(response)?;
        Ok(Self {
            status,
            status_text,
            items,
            counts,
        })
    }
}

impl GmpResponse for GetInfoResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

macro_rules! impl_specialized_info_response {
    ($response:ty, $item:ident, $kind:literal) => {
        impl $response {
            pub fn from_response(response: &Response) -> Result<Self, ParseError> {
                let (status, status_text, generic, counts, _) = parsed_info(response)?;
                let items = generic
                    .into_iter()
                    .filter(|item| item.info_type == $kind)
                    .map(|item| $item {
                        id: item.id,
                        name: item.name,
                    })
                    .collect();
                Ok(Self {
                    status,
                    status_text,
                    items,
                    counts,
                })
            }
        }
        impl GmpResponse for $response {
            fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
                Self::from_response(response)
            }
        }
    };
}

impl_specialized_info_response!(GetCvesResponse, Cve, "CVE");
impl_specialized_info_response!(GetCpesResponse, Cpe, "CPE");
impl_specialized_info_response!(
    GetCertBundAdvisoriesResponse,
    CertBundAdvisory,
    "CERT_BUND_ADV"
);
impl_specialized_info_response!(
    GetDfnCertAdvisoriesResponse,
    DfnCertAdvisory,
    "DFN_CERT_ADV"
);

/// Historical/raw operating-system response item. No canonical `get_info` request is associated.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatingSystem {
    pub id: String,
    pub name: String,
}

/// Compact observed-vulnerability projection returned by `get_vulns`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Vulnerability {
    pub id: String,
    pub name: String,
}

/// Historical/raw operating-system response model without a canonical request association.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetOperatingSystemsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<OperatingSystem>,
    pub counts: CountInfo,
}

/// Typed response for observed `get_vulns` summaries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetVulnerabilitiesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Vulnerability>,
    pub counts: CountInfo,
}

fn direct_item(node: &XmlNode, element: &str) -> Result<(String, String), ParseError> {
    let id = node
        .attr("id")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ParseError::MissingElement(format!("{element}.id")))?;
    Ok((id.to_string(), node.required_child_text("name")?))
}

impl GetOperatingSystemsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("os")
            .map(|node| direct_item(node, "os").map(|(id, name)| OperatingSystem { id, name }))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "os_count")?,
        })
    }
}

impl GmpResponse for GetOperatingSystemsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GetVulnerabilitiesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("vuln")
            .map(|node| direct_item(node, "vuln").map(|(id, name)| Vulnerability { id, name }))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "vuln_count")?,
        })
    }
}

impl GmpResponse for GetVulnerabilitiesResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_authoritative_info_wrappers_and_generic_counts() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK"><info id="CVE-2026-0001"><name>CVE-2026-0001</name><cve><severity>7.5</severity><references><cve id="nested"/></references></cve></info><info_count><filtered>1</filtered><page>1</page></info_count></get_info_response>"#,
        );
        let parsed = GetCvesResponse::from_response(&response).expect("canonical CVE response");
        assert_eq!(
            parsed.items,
            [Cve {
                id: "CVE-2026-0001".into(),
                name: "CVE-2026-0001".into()
            }]
        );
        assert_eq!(parsed.counts.filtered, Some(1));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.counts.total, None);
    }

    #[test]
    fn outer_identity_wins_over_nested_nvt_oid() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK"><info id="outer-id"><name>Outer NVT</name><nvt oid="nested-oid"><name>Nested</name><refs><cve id="nested-cve"/></refs></nvt></info><info_count>1</info_count></get_info_response>"#,
        );
        let parsed = GetInfoResponse::from_response(&response).expect("canonical info response");
        assert_eq!(parsed.items[0].id, "outer-id");
        assert_eq!(parsed.items[0].name, "Outer NVT");
        assert_eq!(parsed.items[0].info_type, "NVT");
    }

    #[test]
    fn canonical_wrappers_precede_legacy_fallback_without_double_counting() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK"><info id="canonical"><name>Canonical</name><cve/></info><cve id="legacy"><name>Legacy</name></cve><info_count>1</info_count><cve_count>2</cve_count></get_info_response>"#,
        );
        let parsed = GetCvesResponse::from_response(&response).expect("canonical CVE response");
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].id, "canonical");
        assert_eq!(parsed.counts.total, Some(1));
    }

    #[test]
    fn labeled_legacy_direct_children_remain_parseable() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK"><cpe id="cpe:/a:x"><name>Legacy</name></cpe><cpe_count>1</cpe_count></get_info_response>"#,
        );
        let parsed = GetCpesResponse::from_response(&response).expect("legacy CPE response");
        assert_eq!(parsed.items[0].name, "Legacy");
        assert_eq!(parsed.counts.total, Some(1));
    }

    #[test]
    fn malformed_recognized_wrappers_fail() {
        for xml in [
            r#"<get_info_response status="200" status_text="OK"><info><name>x</name><cve/></info></get_info_response>"#,
            r#"<get_info_response status="200" status_text="OK"><info id="x"><cve/></info></get_info_response>"#,
            r#"<get_info_response status="200" status_text="OK"><info id="x"><name>x</name><cve/><cpe/></info></get_info_response>"#,
        ] {
            assert!(GetInfoResponse::from_response(&Response::from(xml)).is_err());
        }
    }

    #[test]
    fn richer_observed_vulnerability_fields_are_tolerated() {
        let response = Response::from(
            r#"<get_vulns_response status="200" status_text="OK"><vuln id="1.3.6.1"><name>Example</name><severity>7.5</severity><qod>80</qod><results><count>2</count></results><hosts><count>1</count></hosts></vuln><vuln_count><filtered>1</filtered><page>1</page></vuln_count></get_vulns_response>"#,
        );
        let parsed = GetVulnerabilitiesResponse::from_response(&response)
            .expect("canonical vulnerability response");
        assert_eq!(parsed.items[0].id, "1.3.6.1");
        assert_eq!(parsed.counts.filtered, Some(1));
    }
}
