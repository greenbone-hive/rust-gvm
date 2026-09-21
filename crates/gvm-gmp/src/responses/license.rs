// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! License discovery response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError, XmlNode};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetLicenseResponse {
    pub status: u16,
    pub status_text: String,
    pub license: Option<License>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct License {
    pub status: Option<String>,
    pub content: Option<LicenseContent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LicenseContent {
    pub meta: Option<LicenseMeta>,
    pub appliance: Option<LicenseAppliance>,
    pub keys: Vec<LicenseNamedValue>,
    pub signatures: Vec<LicenseNamedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LicenseMeta {
    pub id: Option<String>,
    pub version: Option<String>,
    pub comment: Option<String>,
    pub type_: Option<String>,
    pub customer_name: Option<String>,
    pub created: Option<String>,
    pub begins: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LicenseAppliance {
    pub model: Option<String>,
    pub model_type: Option<String>,
    pub sensor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LicenseNamedValue {
    pub name: Option<String>,
    pub value: String,
}

impl GetLicenseResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
            license: root.child("license").map(License::from_node),
        })
    }
}

impl License {
    fn from_node(node: &XmlNode) -> Self {
        Self {
            status: node.optional_child_text("status"),
            content: node.child("content").map(LicenseContent::from_node),
        }
    }
}

impl LicenseContent {
    fn from_node(node: &XmlNode) -> Self {
        Self {
            meta: node.child("meta").map(LicenseMeta::from_node),
            appliance: node.child("appliance").map(LicenseAppliance::from_node),
            keys: named_values(node.child("keys"), "key"),
            signatures: named_values(node.child("signatures"), "signature"),
        }
    }
}

impl LicenseMeta {
    fn from_node(node: &XmlNode) -> Self {
        Self {
            id: node.optional_child_text("id"),
            version: node.optional_child_text("version"),
            comment: node.optional_child_text("comment"),
            type_: node.optional_child_text("type"),
            customer_name: node.optional_child_text("customer_name"),
            created: node.optional_child_text("created"),
            begins: node.optional_child_text("begins"),
            expires: node.optional_child_text("expires"),
        }
    }
}

impl LicenseAppliance {
    fn from_node(node: &XmlNode) -> Self {
        Self {
            model: node.optional_child_text("model"),
            model_type: node.optional_child_text("model_type"),
            sensor: node.optional_child_text("sensor"),
        }
    }
}

fn named_values(parent: Option<&XmlNode>, element: &str) -> Vec<LicenseNamedValue> {
    parent
        .into_iter()
        .flat_map(|node| node.children_named(element))
        .map(|node| LicenseNamedValue {
            name: node.attr("name").map(ToString::to_string),
            value: node.text.clone(),
        })
        .collect()
}

impl GmpResponse for GetLicenseResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_and_status_only_licenses() {
        let response = Response::from(
            r#"<get_license_response status="200" status_text="OK"><license><status>active</status><content><meta><id>4711</id><version>1.0.0</version></meta><appliance><model>trial</model><sensor>0</sensor></appliance><keys><key name="feed">feed-key</key></keys><signatures><signature name="license">signature</signature></signatures></content></license></get_license_response>"#,
        );
        let parsed = GetLicenseResponse::from_response(&response).expect("license parses");
        let license = parsed.license.expect("license");
        assert_eq!(license.status.as_deref(), Some("active"));
        let content = license.content.expect("content");
        assert_eq!(content.meta.expect("meta").id.as_deref(), Some("4711"));
        assert_eq!(content.keys[0].name.as_deref(), Some("feed"));

        let status_only = Response::from(
            r#"<get_license_response status="200" status_text="OK"><license><status>none</status></license></get_license_response>"#,
        );
        let parsed = GetLicenseResponse::from_response(&status_only).expect("license parses");
        assert!(parsed.license.expect("license").content.is_none());
    }
}
