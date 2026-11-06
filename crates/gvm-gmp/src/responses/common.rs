// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared response-model types and XML helpers.

use std::collections::HashMap;
use std::str;

use gvm_protocol::{ProtocolError, Response};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use crate::{EntityId, GmpResponse, GmpVersion};

const DEFAULT_MAX_XML_DEPTH: usize = 256;

/// Semantic classification of a non-success GMP server response.
///
/// GMP uses status `400` both for ordinary invalid input and for some
/// authentication and authorization failures. Those exceptional outcomes are
/// recognized only when the normalized status text exactly matches text
/// emitted by gvmd. Statuses `401` and `403` are classified directly. All
/// other unrecognized statuses conservatively use [`Self::Unknown`].
///
/// This type deliberately models GMP outcomes rather than HTTP status types.
/// The original numeric status and message remain available on the error that
/// produced this classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum GmpServerErrorKind {
    /// The server rejected ordinary invalid request input.
    InvalidInput,
    /// Authentication failed or is required.
    AuthenticationFailure,
    /// The authenticated caller lacks permission for the operation.
    PermissionDenied,
    /// The outcome has no evidence-backed semantic classification.
    Unknown,
}

impl GmpServerErrorKind {
    /// Classify a raw GMP status and status-text pair.
    ///
    /// Status text is trimmed and compared without ASCII case differences, but
    /// is never matched by substring. An unrecognized status `400` retains
    /// GMP's ordinary invalid-input meaning; an unrecognized status outside
    /// the explicit cases conservatively returns [`Self::Unknown`].
    #[must_use]
    pub fn classify(status: u16, message: &str) -> Self {
        match status {
            401 => Self::AuthenticationFailure,
            403 => Self::PermissionDenied,
            400 if message.trim().eq_ignore_ascii_case("Authentication failed") => {
                Self::AuthenticationFailure
            }
            400 if message.trim().eq_ignore_ascii_case("Permission denied") => {
                Self::PermissionDenied
            }
            400 => Self::InvalidInput,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid XML: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("missing required element: {0}")]
    MissingElement(String),
    #[error("invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },
    #[error("server error {status}: {message}")]
    ServerError { status: u16, message: String },
    #[error("invalid UTF-8: {0}")]
    Utf8(#[from] str::Utf8Error),
    #[error("XML nesting exceeds configured limit of {max_depth}")]
    NestingLimitExceeded { max_depth: usize },
    #[error("protocol error while parsing response: {0}")]
    Protocol(#[from] ProtocolError),
}

impl ParseError {
    /// Return the semantic kind of a GMP server error.
    ///
    /// Structural parsing failures return `None`. The original server status
    /// and message remain intact in [`Self::ServerError`].
    #[must_use]
    pub fn server_error_kind(&self) -> Option<GmpServerErrorKind> {
        match self {
            Self::ServerError { status, message } => {
                Some(GmpServerErrorKind::classify(*status, message))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Owner {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NamedEntity {
    pub id: EntityId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NvtReference {
    pub oid: String,
    pub name: Option<String>,
    pub type_: Option<String>,
}

/// EPSS metadata for the highest-severity and highest-EPSS CVEs of an NVT.
///
/// gvmd reports percentiles in its backend-native percentage unit. Callers
/// should not normalize the raw values in this protocol projection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Epss {
    /// EPSS data for the NVT's CVE with the highest severity.
    pub max_severity: EpssSelection,
    /// EPSS data for the NVT's CVE with the highest EPSS score.
    pub max_epss: EpssSelection,
}

/// One CVE selection from an NVT's EPSS metadata.
///
/// Numeric text is retained exactly as decoded so serialization and
/// diagnostics do not lose gvmd's precision or formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpssSelection {
    /// Raw EPSS score text emitted by gvmd.
    pub score: String,
    /// Raw backend-native EPSS percentile text emitted by gvmd.
    pub percentile: String,
    /// The CVE selected for this maximum.
    pub cve: EpssCve,
}

impl EpssSelection {
    /// Returns the EPSS score as a finite number, or `None` for invalid text.
    #[must_use]
    pub fn score_value(&self) -> Option<f64> {
        parse_score(&self.score)
    }

    /// Returns the percentile as a finite backend-native percentage value.
    #[must_use]
    pub fn percentile_value(&self) -> Option<f64> {
        parse_score(&self.percentile)
    }
}

/// CVE identity and optional severity attached to one EPSS selection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpssCve {
    /// CVE identifier from the `<cve id="...">` attribute.
    pub id: String,
    /// Raw CVE severity text, omitted by gvmd when severity is unavailable.
    pub severity: Option<String>,
}

impl EpssCve {
    /// Returns the CVE severity as a finite number when present and valid.
    #[must_use]
    pub fn severity_score(&self) -> Option<f64> {
        self.severity.as_deref().and_then(parse_score)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CountInfo {
    pub total: Option<u32>,
    pub filtered: Option<u32>,
    pub page: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionResponse {
    pub status: u16,
    pub status_text: String,
}

impl ActionResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let _ = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
        })
    }
}

impl GmpResponse for ActionResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EntityMeta {
    pub id: EntityId,
    pub name: String,
    pub comment: Option<String>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
    pub owner: Option<Owner>,
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XmlNode {
    pub(crate) name: String,
    pub(crate) attributes: HashMap<String, String>,
    pub(crate) text: String,
    raw_text: Option<Box<str>>,
    pub(crate) children: Vec<XmlNode>,
}

impl XmlNode {
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    pub(crate) fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|child| child.name == name)
    }

    pub(crate) fn children_named<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a XmlNode> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    pub(crate) fn child_text(&self, name: &str) -> Option<String> {
        self.child(name).map(|child| child.text.clone())
    }

    pub(crate) fn child_raw_text(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|child| child.raw_text.as_deref().unwrap_or(&child.text))
    }

    pub(crate) fn required_child_text(&self, name: &str) -> Result<String, ParseError> {
        self.child_text(name)
            .ok_or_else(|| ParseError::MissingElement(name.to_string()))
    }

    pub(crate) fn optional_child_text(&self, name: &str) -> Option<String> {
        self.child_text(name)
            .and_then(|text| (!text.is_empty()).then_some(text))
    }
}

pub(crate) fn status_from_response(response: &Response) -> Result<(u16, String), ParseError> {
    let status = response
        .status_code()
        .ok_or_else(|| ParseError::MissingElement("status".to_string()))?;
    let status_text = response
        .status_text()
        .ok_or_else(|| ParseError::MissingElement("status_text".to_string()))?;
    if !(200..300).contains(&status) {
        return Err(ParseError::ServerError {
            status,
            message: status_text,
        });
    }
    Ok((status, status_text))
}

pub(crate) fn parse_document(data: &[u8]) -> Result<XmlNode, ParseError> {
    parse_document_with_non_leaf_raw_text(data, &[])
}

pub(crate) fn parse_document_with_epss_raw_text(data: &[u8]) -> Result<XmlNode, ParseError> {
    parse_document_with_non_leaf_raw_text(data, &["score", "percentile", "severity"])
}

fn parse_document_with_non_leaf_raw_text(
    data: &[u8],
    non_leaf_raw_text_fields: &[&str],
) -> Result<XmlNode, ParseError> {
    let text = str::from_utf8(data)?;
    let mut reader = Reader::from_str(text);
    // Trimming each event loses significant whitespace when quick-xml splits
    // text around a character reference (for example `left &amp; right`).
    reader.config_mut().trim_text(false);
    let mut stack: Vec<XmlNode> = Vec::new();

    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                enforce_xml_depth(stack.len())?;
                stack.push(XmlNode {
                    name: event.name().as_ref().to_string(),
                    attributes: collect_attributes(&event)?,
                    text: String::new(),
                    raw_text: None,
                    children: Vec::new(),
                });
            }
            Event::Empty(event) => {
                enforce_xml_depth(stack.len())?;
                let node = XmlNode {
                    name: event.name().as_ref().to_string(),
                    attributes: collect_attributes(&event)?,
                    text: String::new(),
                    raw_text: None,
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    return Ok(node);
                }
            }
            Event::Text(event) => {
                if let Some(node) = stack.last_mut() {
                    let text = quick_xml::escape::unescape(event.as_ref())
                        .map_err(quick_xml::Error::from)?
                        .into_owned();
                    node.text.push_str(&text);
                }
            }
            Event::CData(event) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(event.as_ref());
                }
            }
            Event::GeneralRef(event) => {
                let node = stack.last_mut().ok_or_else(|| {
                    ParseError::MissingElement("root for entity reference".to_string())
                })?;
                if let Some(character) = event.resolve_char_ref()? {
                    node.text.push(character);
                } else {
                    let entity = event.as_ref();
                    let Some(value) = quick_xml::escape::resolve_xml_entity(entity) else {
                        return Err(ParseError::InvalidValue {
                            field: "entity reference".to_string(),
                            value: entity.to_string(),
                        });
                    };
                    node.text.push_str(value);
                }
            }
            Event::End(_) => {
                let Some(mut node) = stack.pop() else {
                    return Err(ParseError::MissingElement("root".to_string()));
                };
                let raw_text = std::mem::take(&mut node.text);
                let trimmed_text = raw_text.trim();
                let retain_raw_text = node.children.is_empty()
                    || non_leaf_raw_text_fields.contains(&node.name.as_str());
                if retain_raw_text && trimmed_text.len() != raw_text.len() {
                    node.text = trimmed_text.to_string();
                    node.raw_text = Some(raw_text.into_boxed_str());
                } else {
                    node.text = trimmed_text.to_string();
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    return Ok(node);
                }
            }
            Event::Eof => return Err(ParseError::MissingElement("root".to_string())),
            Event::Decl(_) | Event::PI(_) | Event::DocType(_) | Event::Comment(_) => {}
        }
    }
}

fn enforce_xml_depth(current_depth: usize) -> Result<(), ParseError> {
    if current_depth.saturating_add(1) > DEFAULT_MAX_XML_DEPTH {
        return Err(ParseError::NestingLimitExceeded {
            max_depth: DEFAULT_MAX_XML_DEPTH,
        });
    }
    Ok(())
}

fn collect_attributes(
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<HashMap<String, String>, ParseError> {
    let mut attributes = HashMap::new();
    for attribute in event.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        attributes.insert(
            attribute.key.as_ref().to_string(),
            attribute
                .normalized_value(XmlVersion::Implicit1_0)?
                .into_owned(),
        );
    }
    Ok(attributes)
}

pub(crate) fn parse_entity_id(value: &str, field: &str) -> Result<EntityId, ParseError> {
    EntityId::new(value).map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_nvt_reference(
    node: &XmlNode,
    field_prefix: &str,
) -> Result<Option<NvtReference>, ParseError> {
    node.child("nvt")
        .map(|nvt| {
            Ok(NvtReference {
                oid: nvt
                    .attr("oid")
                    .ok_or_else(|| ParseError::MissingElement(format!("{field_prefix}.oid")))?
                    .to_string(),
                name: nvt.optional_child_text("name"),
                type_: nvt.optional_child_text("type"),
            })
        })
        .transpose()
}

pub(crate) fn parse_epss(node: &XmlNode) -> Result<Option<Epss>, ParseError> {
    node.child("epss")
        .map(|epss| {
            Ok(Epss {
                max_severity: parse_epss_selection(epss, "max_severity")?,
                max_epss: parse_epss_selection(epss, "max_epss")?,
            })
        })
        .transpose()
}

fn parse_epss_selection(node: &XmlNode, name: &str) -> Result<EpssSelection, ParseError> {
    let selection = node
        .child(name)
        .ok_or_else(|| ParseError::MissingElement(format!("epss.{name}")))?;
    let score = selection
        .child_raw_text("score")
        .ok_or_else(|| ParseError::MissingElement(format!("epss.{name}.score")))?
        .to_string();
    let percentile = selection
        .child_raw_text("percentile")
        .ok_or_else(|| ParseError::MissingElement(format!("epss.{name}.percentile")))?
        .to_string();
    let cve = selection
        .child("cve")
        .ok_or_else(|| ParseError::MissingElement(format!("epss.{name}.cve")))?;
    let id = cve
        .attr("id")
        .ok_or_else(|| ParseError::MissingElement(format!("epss.{name}.cve.id")))?
        .to_string();

    Ok(EpssSelection {
        score,
        percentile,
        cve: EpssCve {
            id,
            severity: cve.child_raw_text("severity").map(ToString::to_string),
        },
    })
}

pub(crate) fn parse_bool(value: &str, field: &str) -> Result<bool, ParseError> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(ParseError::InvalidValue {
            field: field.to_string(),
            value: value.to_string(),
        }),
    }
}

pub(crate) fn parse_csv_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn parse_u16(value: &str, field: &str) -> Result<u16, ParseError> {
    value.parse::<u16>().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_u32(value: &str, field: &str) -> Result<u32, ParseError> {
    value.parse::<u32>().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_i32(value: &str, field: &str) -> Result<i32, ParseError> {
    value.parse::<i32>().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_score(value: &str) -> Option<f64> {
    value.parse::<f64>().ok().filter(|score| score.is_finite())
}

pub(crate) fn optional_u16(
    node: &XmlNode,
    name: &str,
    field: &str,
) -> Result<Option<u16>, ParseError> {
    node.optional_child_text(name)
        .map(|value| parse_u16(&value, field))
        .transpose()
}

pub(crate) fn optional_u32(
    node: &XmlNode,
    name: &str,
    field: &str,
) -> Result<Option<u32>, ParseError> {
    node.optional_child_text(name)
        .map(|value| parse_u32(&value, field))
        .transpose()
}

pub(crate) fn count_info(node: &XmlNode, count_name: &str) -> Result<CountInfo, ParseError> {
    let Some(count_node) = node.child(count_name) else {
        return Ok(CountInfo::default());
    };
    Ok(CountInfo {
        total: (!count_node.text.is_empty())
            .then(|| parse_u32(&count_node.text, count_name))
            .transpose()?,
        filtered: count_node
            .optional_child_text("filtered")
            .map(|value| parse_u32(&value, &format!("{count_name}.filtered")))
            .transpose()?,
        page: count_node
            .optional_child_text("page")
            .map(|value| parse_u32(&value, &format!("{count_name}.page")))
            .transpose()?,
    })
}

pub(crate) fn parse_owner(node: &XmlNode) -> Result<Option<Owner>, ParseError> {
    node.child("owner")
        .map(|owner| {
            Ok(Owner {
                name: owner.required_child_text("name")?,
            })
        })
        .transpose()
}

pub(crate) fn parse_named_entity(
    node: &XmlNode,
    field: &str,
) -> Result<Option<NamedEntity>, ParseError> {
    node.child(field)
        .map(|child| {
            let Some(raw_id) = child.attr("id") else {
                return Err(ParseError::MissingElement(format!("{field}.id")));
            };
            if raw_id.is_empty() {
                return Ok(None);
            }
            let id = parse_entity_id(raw_id, &format!("{field}.id"))?;
            let name = child.required_child_text("name")?;
            Ok(Some(NamedEntity { id, name }))
        })
        .transpose()
        .map(Option::flatten)
}

pub(crate) fn parse_entity_ref(
    node: &XmlNode,
    field: &str,
) -> Result<Option<NamedEntity>, ParseError> {
    node.child(field)
        .map(|child| {
            let Some(raw_id) = child.attr("id") else {
                return Err(ParseError::MissingElement(format!("{field}.id")));
            };
            if raw_id.is_empty() {
                return Ok(None);
            }
            let id = parse_entity_id(raw_id, &format!("{field}.id"))?;
            let name = child.optional_child_text("name").unwrap_or_default();
            Ok(Some(NamedEntity { id, name }))
        })
        .transpose()
        .map(Option::flatten)
}

fn parse_entity_meta_with_name(
    node: &XmlNode,
    name_required: bool,
) -> Result<EntityMeta, ParseError> {
    let id = parse_entity_id(
        node.attr("id")
            .ok_or_else(|| ParseError::MissingElement(format!("{}.id", node.name)))?,
        &format!("{}.id", node.name),
    )?;
    let name = if name_required {
        node.required_child_text("name")?
    } else {
        node.optional_child_text("name").unwrap_or_default()
    };

    Ok(EntityMeta {
        id,
        name,
        comment: node.optional_child_text("comment"),
        creation_time: node.optional_child_text("creation_time"),
        modification_time: node.optional_child_text("modification_time"),
        owner: parse_owner(node)?,
        in_use: node
            .optional_child_text("in_use")
            .map(|value| parse_bool(&value, "in_use"))
            .transpose()?
            .unwrap_or(false),
        writable: node
            .optional_child_text("writable")
            .map(|value| parse_bool(&value, "writable"))
            .transpose()?
            .unwrap_or(false),
    })
}

pub(crate) fn parse_entity_meta(node: &XmlNode) -> Result<EntityMeta, ParseError> {
    parse_entity_meta_with_name(node, true)
}

pub(crate) fn parse_entity_meta_optional_name(node: &XmlNode) -> Result<EntityMeta, ParseError> {
    parse_entity_meta_with_name(node, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_evidence_backed_server_outcomes() {
        assert_eq!(
            GmpServerErrorKind::classify(400, "invalid scanner port"),
            GmpServerErrorKind::InvalidInput
        );
        assert_eq!(
            GmpServerErrorKind::classify(400, " Authentication FAILED "),
            GmpServerErrorKind::AuthenticationFailure
        );
        assert_eq!(
            GmpServerErrorKind::classify(400, " permission DENIED "),
            GmpServerErrorKind::PermissionDenied
        );
        assert_eq!(
            GmpServerErrorKind::classify(401, "backend-specific text"),
            GmpServerErrorKind::AuthenticationFailure
        );
        assert_eq!(
            GmpServerErrorKind::classify(403, "backend-specific text"),
            GmpServerErrorKind::PermissionDenied
        );
    }

    #[test]
    fn classification_avoids_substrings_and_falls_back_conservatively() {
        assert_eq!(
            GmpServerErrorKind::classify(400, "request failed: Permission denied"),
            GmpServerErrorKind::InvalidInput
        );
        assert_eq!(
            GmpServerErrorKind::classify(500, "Permission denied"),
            GmpServerErrorKind::Unknown
        );
        assert_eq!(
            GmpServerErrorKind::classify(599, "unknown backend outcome"),
            GmpServerErrorKind::Unknown
        );

        let structural = ParseError::MissingElement("status".to_string());
        assert_eq!(structural.server_error_kind(), None);
    }

    fn entity_node(id: Option<&str>, name: &str) -> XmlNode {
        let mut attributes = HashMap::new();
        if let Some(id) = id {
            attributes.insert("id".to_string(), id.to_string());
        }
        XmlNode {
            name: "schedule".to_string(),
            attributes,
            text: String::new(),
            raw_text: None,
            children: vec![XmlNode {
                name: "name".to_string(),
                attributes: HashMap::new(),
                text: name.to_string(),
                raw_text: None,
                children: Vec::new(),
            }],
        }
    }

    #[test]
    fn parse_named_entity_treats_empty_id_as_absent() {
        let root = XmlNode {
            name: "task".to_string(),
            attributes: HashMap::new(),
            text: String::new(),
            raw_text: None,
            children: vec![entity_node(Some(""), "")],
        };

        let parsed = parse_named_entity(&root, "schedule").expect("empty id parses");

        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_named_entity_rejects_invalid_non_empty_id() {
        let root = XmlNode {
            name: "task".to_string(),
            attributes: HashMap::new(),
            text: String::new(),
            raw_text: None,
            children: vec![entity_node(Some("not valid"), "Weekly")],
        };

        let error = parse_named_entity(&root, "schedule").expect_err("invalid id should fail");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, value }
                if field == "schedule.id" && value == "not valid"
        ));
    }

    #[test]
    fn parse_score_rejects_non_finite_values() {
        assert_eq!(parse_score("7.5"), Some(7.5));
        assert_eq!(parse_score("NaN"), None);
        assert_eq!(parse_score("inf"), None);
        assert_eq!(parse_score("-inf"), None);
    }

    #[test]
    fn parse_epss_preserves_raw_values_and_rejects_invalid_numeric_accessors() {
        let root = parse_document(
            br#"<nvt><epss><max_severity><score>0.12345</score><percentile>98.76500</percentile><cve id="CVE-2026-0001"><severity>9.8</severity><future>ignored</future></cve></max_severity><max_epss><score>NaN</score><percentile>inf</percentile><cve id="CVE-2026-0002"><severity>-inf</severity></cve></max_epss><future>ignored</future></epss></nvt>"#,
        )
        .expect("source-shaped EPSS XML parses");

        let epss = parse_epss(&root)
            .expect("EPSS projection parses")
            .expect("EPSS is present");

        assert_eq!(epss.max_severity.score, "0.12345");
        assert_eq!(epss.max_severity.percentile, "98.76500");
        assert_eq!(epss.max_severity.cve.id, "CVE-2026-0001");
        assert_eq!(epss.max_severity.cve.severity.as_deref(), Some("9.8"));
        assert_eq!(epss.max_severity.score_value(), Some(0.12345));
        assert_eq!(epss.max_severity.percentile_value(), Some(98.765));
        assert_eq!(epss.max_severity.cve.severity_score(), Some(9.8));

        assert_eq!(epss.max_epss.score, "NaN");
        assert_eq!(epss.max_epss.percentile, "inf");
        assert_eq!(epss.max_epss.cve.severity.as_deref(), Some("-inf"));
        assert_eq!(epss.max_epss.score_value(), None);
        assert_eq!(epss.max_epss.percentile_value(), None);
        assert_eq!(epss.max_epss.cve.severity_score(), None);
    }

    #[test]
    fn parse_epss_distinguishes_absence_and_optional_cve_severity() {
        let absent = parse_document(br#"<nvt><name>Older gvmd</name></nvt>"#)
            .expect("NVT without EPSS parses");
        assert_eq!(parse_epss(&absent).expect("absence is valid"), None);

        let root = parse_document(
            br#"<nvt><epss><max_severity><score>0.10000</score><percentile>10.00000</percentile><cve id="CVE-2026-0001"/></max_severity><max_epss><score>0.20000</score><percentile>20.00000</percentile><cve id="CVE-2026-0002"/></max_epss></epss></nvt>"#,
        )
        .expect("EPSS without severity parses");
        let epss = parse_epss(&root)
            .expect("EPSS projection parses")
            .expect("EPSS is present");
        assert_eq!(epss.max_severity.cve.severity, None);
        assert_eq!(epss.max_epss.cve.severity, None);
    }

    #[test]
    fn parse_epss_preserves_padded_and_empty_numeric_text() {
        let root = parse_document(
            br#"<nvt><epss><max_severity><score> 0.10000 </score><percentile>&#x20;10.00000&#x20;</percentile><cve id="CVE-2026-0001"><severity> 9.8 </severity></cve></max_severity><max_epss><score></score><percentile/><cve id="CVE-2026-0002"><severity/></cve></max_epss></epss></nvt>"#,
        )
        .expect("padded and empty EPSS XML parses");
        let epss = parse_epss(&root)
            .expect("EPSS projection parses")
            .expect("EPSS is present");

        assert_eq!(epss.max_severity.score, " 0.10000 ");
        assert_eq!(epss.max_severity.percentile, " 10.00000 ");
        assert_eq!(epss.max_severity.cve.severity.as_deref(), Some(" 9.8 "));
        assert_eq!(epss.max_severity.score_value(), None);
        assert_eq!(epss.max_severity.percentile_value(), None);
        assert_eq!(epss.max_severity.cve.severity_score(), None);

        assert_eq!(epss.max_epss.score, "");
        assert_eq!(epss.max_epss.percentile, "");
        assert_eq!(epss.max_epss.cve.severity.as_deref(), Some(""));
        assert_eq!(epss.max_epss.score_value(), None);
        assert_eq!(epss.max_epss.percentile_value(), None);
        assert_eq!(epss.max_epss.cve.severity_score(), None);
    }

    #[test]
    fn parse_epss_preserves_padded_numeric_text_with_additive_children() {
        let root = parse_document_with_epss_raw_text(
            br#"<nvt><epss><max_severity><score> 0.10000 <future/></score><percentile>&#x20;10.00000&#x20;<future/></percentile><cve id="CVE-2026-0001"><severity> 9.8 <future/></severity></cve></max_severity><max_epss><score>0.20000</score><percentile>20.00000</percentile><cve id="CVE-2026-0002"/></max_epss></epss></nvt>"#,
        )
        .expect("EPSS XML with additive children parses");
        let epss = parse_epss(&root)
            .expect("EPSS projection parses")
            .expect("EPSS is present");

        assert_eq!(epss.max_severity.score, " 0.10000 ");
        assert_eq!(epss.max_severity.percentile, " 10.00000 ");
        assert_eq!(epss.max_severity.cve.severity.as_deref(), Some(" 9.8 "));
        assert_eq!(epss.max_severity.score_value(), None);
        assert_eq!(epss.max_severity.percentile_value(), None);
        assert_eq!(epss.max_severity.cve.severity_score(), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn epss_serde_round_trip_preserves_both_selections() {
        let epss = Epss {
            max_severity: EpssSelection {
                score: "0.12345".to_string(),
                percentile: "98.76500".to_string(),
                cve: EpssCve {
                    id: "CVE-2026-0001".to_string(),
                    severity: Some("9.8".to_string()),
                },
            },
            max_epss: EpssSelection {
                score: "0.54321".to_string(),
                percentile: "99.50000".to_string(),
                cve: EpssCve {
                    id: "CVE-2026-0002".to_string(),
                    severity: Some("7.5".to_string()),
                },
            },
        };

        let xml = quick_xml::se::to_string(&epss).expect("EPSS serializes");
        let decoded = quick_xml::de::from_str::<Epss>(&xml).expect("EPSS deserializes");

        assert_eq!(decoded, epss);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn epss_serde_encodes_missing_severity() {
        let cve = EpssCve {
            id: "CVE-2026-0001".to_string(),
            severity: None,
        };

        let xml = quick_xml::se::to_string(&cve).expect("EPSS CVE serializes");

        assert!(xml.contains("<severity/>"));
    }

    #[test]
    fn parse_document_preserves_predefined_and_character_references() {
        let root = parse_document(
            br#"<?xml version="1.0"?><!-- metadata --><?test instruction?><!DOCTYPE root><root attr="A &amp; B"><value>A &amp; B &lt; &#x21;&#33;</value></root>"#,
        )
        .expect("valid references should parse");

        assert_eq!(root.attr("attr"), Some("A & B"));
        assert_eq!(root.child_text("value").as_deref(), Some("A & B < !!"));
    }

    #[test]
    fn parse_document_retains_original_padded_leaf_text() {
        let root = parse_document(
            br#"<root><plain> up </plain><reference>&#x20;up&#x20;</reference><cdata><![CDATA[ up ]]></cdata><nested> up <future/></nested><clean>up</clean><empty/></root>"#,
        )
        .expect("padded text should parse");

        assert_eq!(root.child_text("plain").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("plain"), Some(" up "));
        assert_eq!(root.child_text("reference").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("reference"), Some(" up "));
        assert_eq!(root.child_text("cdata").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("cdata"), Some(" up "));
        assert_eq!(root.child_text("nested").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("nested"), Some("up"));
        assert_eq!(
            root.child("nested")
                .and_then(|node| node.raw_text.as_deref()),
            None
        );
        assert_eq!(root.child_raw_text("clean"), Some("up"));
        assert_eq!(root.child_raw_text("empty"), Some(""));
    }

    #[test]
    fn parse_document_can_retain_raw_text_for_selected_non_leaf_fields() {
        let root = parse_document_with_non_leaf_raw_text(
            br#"<root><selected> up <future/></selected><ordinary> down <future/></ordinary></root>"#,
            &["selected"],
        )
        .expect("selected non-leaf raw text should parse");

        assert_eq!(root.child_text("selected").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("selected"), Some(" up "));
        assert_eq!(root.child_text("ordinary").as_deref(), Some("down"));
        assert_eq!(root.child_raw_text("ordinary"), Some("down"));
    }

    #[test]
    fn parse_document_rejects_unknown_entity_references() {
        let error =
            parse_document(b"<root>&unknown;</root>").expect_err("unknown entity should fail");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, value }
                if field == "entity reference" && value == "unknown"
        ));

        assert!(matches!(
            parse_document(b"&amp;<root/>"),
            Err(ParseError::MissingElement(element))
                if element == "root for entity reference"
        ));
    }
}
