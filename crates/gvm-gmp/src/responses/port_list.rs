// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Port-list response models.

use std::str::FromStr;

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_id, parse_entity_meta, parse_u16,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion, PortRangeType};

/// One canonical structured range returned in a detailed port-list response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortRange {
    /// UUID of the stored port range.
    pub id: crate::EntityId,
    /// First port in the inclusive range.
    pub start: u16,
    /// Last port in the inclusive range.
    pub end: u16,
    /// Transport protocol for the range.
    pub range_type: PortRangeType,
    /// Comment stored on the range, including an explicitly empty comment.
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortList {
    pub meta: EntityMeta,
    pub port_count: Option<u32>,
    pub tcp_count: Option<u32>,
    pub udp_count: Option<u32>,
    /// Canonical structured ranges from the detailed `<port_ranges>` response.
    #[cfg_attr(feature = "serde", serde(default))]
    pub port_ranges: Vec<PortRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetPortListsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<PortList>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreatePortListResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl PortList {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let port_count_node = node.child("port_count");
        let port_ranges = node
            .child("port_ranges")
            .into_iter()
            .flat_map(|ranges| ranges.children_named("port_range"))
            .map(PortRange::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            meta: parse_entity_meta(node)?,
            port_count: port_count_node
                .map(parse_total_port_count)
                .transpose()?
                .flatten(),
            tcp_count: port_count_node
                .map(|count| optional_u32(count, "tcp", "port_count.tcp"))
                .transpose()?
                .flatten(),
            udp_count: port_count_node
                .map(|count| optional_u32(count, "udp", "port_count.udp"))
                .transpose()?
                .flatten(),
            port_ranges,
        })
    }
}

impl PortRange {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let id = parse_entity_id(
            node.attr("id")
                .ok_or_else(|| ParseError::MissingElement("port_range.id".to_string()))?,
            "port_range.id",
        )?;
        let start = parse_port(node, "start")?;
        let end = parse_port(node, "end")?;
        if start > end {
            return Err(ParseError::InvalidValue {
                field: "port_range".to_string(),
                value: format!("{start}-{end}"),
            });
        }
        let raw_type = node
            .child_text("type")
            .ok_or_else(|| ParseError::MissingElement("port_range.type".to_string()))?;
        let range_type =
            PortRangeType::from_str(&raw_type).map_err(|_| ParseError::InvalidValue {
                field: "port_range.type".to_string(),
                value: raw_type,
            })?;
        let comment = node
            .child_text("comment")
            .ok_or_else(|| ParseError::MissingElement("port_range.comment".to_string()))?;
        Ok(Self {
            id,
            start,
            end,
            range_type,
            comment,
        })
    }
}

fn parse_port(node: &crate::responses::common::XmlNode, element: &str) -> Result<u16, ParseError> {
    let field = format!("port_range.{element}");
    let value = node
        .child_text(element)
        .ok_or_else(|| ParseError::MissingElement(field.clone()))?;
    let port = parse_u16(&value, &field)?;
    if port == 0 {
        return Err(ParseError::InvalidValue { field, value });
    }
    Ok(port)
}

fn parse_total_port_count(
    node: &crate::responses::common::XmlNode,
) -> Result<Option<u32>, ParseError> {
    if let Some(total) = optional_u32(node, "all", "port_count.all")? {
        return Ok(Some(total));
    }

    if node.text.is_empty() {
        Ok(None)
    } else {
        node.text
            .parse::<u32>()
            .map(Some)
            .map_err(|_| ParseError::InvalidValue {
                field: "port_count".to_string(),
                value: node.text.clone(),
            })
    }
}

impl GetPortListsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("port_list")
            .map(PortList::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "port_list_count")?,
        })
    }
}

impl GmpResponse for GetPortListsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl CreatePortListResponse {
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

impl GmpResponse for CreatePortListResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyPortListResponse = ActionResponse;
pub type DeletePortListResponse = ActionResponse;
pub type CreatePortRangeResponse = ActionResponse;
pub type DeletePortRangeResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    const ONE_RANGE_RESPONSE: &str = include_str!("../../tests/data/get_port_lists_one_range.xml");
    const MULTIPLE_RANGES_RESPONSE: &str =
        include_str!("../../tests/data/get_port_lists_multiple_ranges.xml");
    const EMPTY_RANGES_RESPONSE: &str =
        include_str!("../../tests/data/get_port_lists_empty_ranges.xml");

    #[test]
    fn parses_current_gvmd_structured_port_range() {
        let parsed = GetPortListsResponse::from_response(&Response::from(ONE_RANGE_RESPONSE))
            .expect("current gvmd port list parses");
        let port_list = &parsed.items[0];

        assert_eq!(port_list.port_ranges.len(), 1);
        assert_eq!(
            port_list.port_ranges[0].id.as_str(),
            "9dbd6178-4d9d-4a58-86c1-680c3f6ecb50"
        );
        assert_eq!(port_list.port_ranges[0].start, 1);
        assert_eq!(port_list.port_ranges[0].end, 100);
        assert_eq!(port_list.port_ranges[0].range_type, PortRangeType::Tcp);
        assert_eq!(port_list.port_ranges[0].comment, "");
    }

    #[test]
    fn parses_multiple_current_gvmd_structured_port_ranges() {
        let parsed = GetPortListsResponse::from_response(&Response::from(MULTIPLE_RANGES_RESPONSE))
            .expect("current gvmd port ranges parse");
        let ranges = &parsed.items[0].port_ranges;

        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].range_type, PortRangeType::Tcp);
        assert_eq!((ranges[0].start, ranges[0].end), (22, 22));
        assert_eq!(ranges[0].comment, "SSH");
        assert_eq!(ranges[1].range_type, PortRangeType::Udp);
        assert_eq!((ranges[1].start, ranges[1].end), (53, 53));
        assert_eq!(ranges[1].comment, "DNS");
    }

    #[test]
    fn parses_empty_current_gvmd_structured_port_range_list() {
        let parsed = GetPortListsResponse::from_response(&Response::from(EMPTY_RANGES_RESPONSE))
            .expect("empty current gvmd port ranges parse");

        assert!(parsed.items[0].port_ranges.is_empty());
    }

    #[test]
    fn parses_multiple_port_lists() {
        let response = Response::from(
            r#"<get_port_lists_response status="200" status_text="OK">
                <port_list id="pl-1">
                    <owner><name>admin</name></owner>
                    <name>All TCP</name>
                    <comment>default</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <port_count>
                        <all>65535</all>
                        <tcp>65535</tcp>
                        <udp>0</udp>
                    </port_count>
                </port_list>
                <port_list id="pl-2">
                    <name>UDP</name>
                </port_list>
                <port_list_count>2<filtered>2</filtered><page>1</page></port_list_count>
            </get_port_lists_response>"#,
        );

        let parsed = GetPortListsResponse::from_response(&response).expect("port lists parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].port_count, Some(65535));
        assert_eq!(parsed.items[0].tcp_count, Some(65535));
        assert_eq!(parsed.items[0].udp_count, Some(0));
        assert!(parsed.items[0].port_ranges.is_empty());
    }

    #[test]
    fn parses_flat_total_port_count_without_protocol_breakdown() {
        let response = Response::from(
            r#"<get_port_lists_response status="200" status_text="OK">
                <port_list id="pl-1">
                    <name>Legacy Port Count</name>
                    <port_count>3</port_count>
                </port_list>
            </get_port_lists_response>"#,
        );

        let parsed = GetPortListsResponse::from_response(&response).expect("port lists parse");
        let port_list = &parsed.items[0];

        assert_eq!(port_list.port_count, Some(3));
        assert_eq!(port_list.tcp_count, None);
        assert_eq!(port_list.udp_count, None);
    }

    #[test]
    fn parses_empty_port_lists() {
        let response = Response::from(
            r#"<get_port_lists_response status="200" status_text="OK"><port_list_count>0<filtered>0</filtered></port_list_count></get_port_lists_response>"#,
        );

        let parsed = GetPortListsResponse::from_response(&response).expect("port lists parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_port_list_response() {
        let response = Response::from(
            r#"<create_port_list_response status="201" status_text="OK, resource created" id="pl-1"/>"#,
        );

        let parsed = CreatePortListResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "pl-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_port_lists_response status="500" status_text="Failed"/>"#);

        let error = GetPortListsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 500,
                message
            } if message == "Failed"
        ));
    }

    #[test]
    fn parses_missing_optional_port_list_fields() {
        let response = Response::from(
            r#"<get_port_lists_response status="200" status_text="OK">
                <port_list id="pl-1">
                    <name>Only Required</name>
                </port_list>
            </get_port_lists_response>"#,
        );

        let parsed = GetPortListsResponse::from_response(&response).expect("port lists parse");
        let port_list = &parsed.items[0];

        assert_eq!(port_list.meta.comment, None);
        assert_eq!(port_list.port_count, None);
        assert_eq!(port_list.tcp_count, None);
        assert_eq!(port_list.udp_count, None);
        assert!(port_list.port_ranges.is_empty());
    }

    #[test]
    fn rejects_missing_and_malformed_structured_range_fields() {
        let cases = [
            (
                r#"<port_range><start>1</start><end>2</end><type>TCP</type><comment/></port_range>"#,
                "port_range.id",
            ),
            (
                r#"<port_range id="range-1"><end>2</end><type>TCP</type><comment/></port_range>"#,
                "port_range.start",
            ),
            (
                r#"<port_range id="range-1"><start>1</start><type>TCP</type><comment/></port_range>"#,
                "port_range.end",
            ),
            (
                r#"<port_range id="range-1"><start>1</start><end>2</end><comment/></port_range>"#,
                "port_range.type",
            ),
            (
                r#"<port_range id="range-1"><start>1</start><end>2</end><type>TCP</type></port_range>"#,
                "port_range.comment",
            ),
            (
                r#"<port_range id="range-1"><start>zero</start><end>2</end><type>TCP</type><comment/></port_range>"#,
                "port_range.start",
            ),
            (
                r#"<port_range id="range-1"><start>0</start><end>2</end><type>TCP</type><comment/></port_range>"#,
                "port_range.start",
            ),
            (
                r#"<port_range id="range-1"><start>2</start><end>1</end><type>TCP</type><comment/></port_range>"#,
                "port_range",
            ),
            (
                r#"<port_range id="range-1"><start>1</start><end>2</end><type>SCTP</type><comment/></port_range>"#,
                "port_range.type",
            ),
        ];

        for (range, expected_field) in cases {
            let xml = format!(
                r#"<get_port_lists_response status="200" status_text="OK"><port_list id="list-1"><name>Malformed</name><port_ranges>{range}</port_ranges></port_list></get_port_lists_response>"#
            );
            let response = Response::from(xml.as_str());
            let error = GetPortListsResponse::from_response(&response)
                .expect_err("malformed structured range must fail");
            match error {
                ParseError::MissingElement(field) => assert_eq!(field, expected_field),
                ParseError::InvalidValue { field, .. } => assert_eq!(field, expected_field),
                other => panic!("unexpected parse error: {other}"),
            }
        }
    }
}
