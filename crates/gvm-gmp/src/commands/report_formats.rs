// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical report-format lifecycle requests.

use std::fmt;

use base64::Engine as _;
use gvm_protocol::{Request as _, XmlCommand};
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{
    CreateReportFormatResponse, DeleteReportFormatResponse, GetReportFormatsResponse,
    ModifyReportFormatResponse, VerifyReportFormatResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// One report-format parameter update.
#[derive(Clone, PartialEq, Eq)]
pub struct ReportFormatParamUpdate {
    /// Exact parameter name. Whitespace and an empty name are preserved.
    pub name: String,
    /// Decoded UTF-8 value. `None` and an empty string both clear the value.
    pub value: Option<String>,
}

impl fmt::Debug for ReportFormatParamUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReportFormatParamUpdate")
            .field("name", &"<redacted>")
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Request for listing report formats, optionally selecting one by ID.
#[derive(Debug, Clone, Default)]
pub struct GetReportFormatsRequest {
    /// Optional report-format identifier selector.
    pub report_format_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select trashed rather than active report formats.
    pub trash: Option<bool>,
    /// Request parameter, file, and signature details.
    pub details: Option<bool>,
    /// Request associated alerts and invisible-reference counts.
    pub alerts: Option<bool>,
    /// Request parameter definitions without full details.
    pub params: Option<bool>,
    /// Request associated report configurations and invisible-reference counts.
    pub report_configs: Option<bool>,
    /// Ignore pagination terms from the selected filter.
    pub ignore_pagination: Option<bool>,
}

impl GetReportFormatsRequest {
    /// Create an unfiltered report-format list request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            report_format_id: None,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: None,
            alerts: None,
            params: None,
            report_configs: None,
            ignore_pagination: None,
        }
    }
}

impl GmpRequestCodec for GetReportFormatsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            self.report_format_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.params,
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_report_formats"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_report_formats_command(
            self.report_format_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.alerts,
            self.params,
            self.report_configs,
            self.ignore_pagination,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetReportFormatsRequest {
    type Response = GetReportFormatsResponse;
}

/// Request for retrieving one report format through the shared list root.
#[derive(Debug, Clone)]
pub struct GetReportFormatRequest {
    /// Required report-format identifier selector.
    pub report_format_id: EntityId,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select a trashed rather than active report format.
    pub trash: Option<bool>,
    /// Request parameter, file, and signature details.
    pub details: Option<bool>,
    /// Request associated alerts and invisible-reference counts.
    pub alerts: Option<bool>,
    /// Request parameter definitions without full details.
    pub params: Option<bool>,
    /// Request associated report configurations and invisible-reference counts.
    pub report_configs: Option<bool>,
    /// Ignore pagination terms from the selected filter.
    pub ignore_pagination: Option<bool>,
}

impl GetReportFormatRequest {
    /// Create an ID-selected detail request with details enabled by default.
    #[must_use]
    pub fn new(report_format_id: EntityId) -> Self {
        Self {
            report_format_id,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: Some(true),
            alerts: None,
            params: None,
            report_configs: None,
            ignore_pagination: None,
        }
    }
}

impl GmpRequestCodec for GetReportFormatRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            Some(&self.report_format_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.params,
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_report_formats",
            "get_report_format",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_report_formats_command(
            Some(&self.report_format_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.alerts,
            self.params,
            self.report_configs,
            self.ignore_pagination,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetReportFormatRequest {
    type Response = GetReportFormatsResponse;
}

/// Request for importing one opaque exported report-format envelope.
#[derive(Clone)]
pub struct ImportReportFormatRequest {
    /// Original exported `get_report_formats_response` XML.
    pub report_format_xml: String,
}

impl ImportReportFormatRequest {
    /// Own an exported response envelope for validation during typed execution.
    #[must_use]
    pub fn new(report_format_xml: impl Into<String>) -> Self {
        Self {
            report_format_xml: report_format_xml.into(),
        }
    }
}

impl fmt::Debug for ImportReportFormatRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportReportFormatRequest")
            .field("report_format_xml", &"<redacted>")
            .finish()
    }
}

impl GmpRequestCodec for ImportReportFormatRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_import_envelope(&self.report_format_xml)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_report_format",
            "import_report_format",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(
            "<create_report_format></create_report_format>".len() + self.report_format_xml.len(),
        );
        bytes.extend_from_slice(b"<create_report_format>");
        bytes.extend_from_slice(self.report_format_xml.as_bytes());
        bytes.extend_from_slice(b"</create_report_format>");
        Ok(bytes)
    }
}

impl GmpRequest for ImportReportFormatRequest {
    type Response = CreateReportFormatResponse;
}

/// Request for cloning a report format through `create_report_format`.
#[derive(Debug, Clone)]
pub struct CloneReportFormatRequest {
    /// Existing report format to copy.
    pub report_format_id: EntityId,
    /// Optional exact name override. An empty value requests automatic naming.
    pub name: Option<String>,
}

impl CloneReportFormatRequest {
    /// Create a report-format clone request without a name override.
    #[must_use]
    pub fn new(report_format_id: EntityId) -> Self {
        Self {
            report_format_id,
            name: None,
        }
    }
}

impl GmpRequestCodec for CloneReportFormatRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.report_format_id, "report_format_id")?;
        validate_optional_xml_text(self.name.as_deref(), "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_report_format",
            "clone_report_format",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("create_report_format");
        command.add_element_with_text("copy", self.report_format_id.as_str());
        if let Some(name) = &self.name {
            command.add_element_with_text("name", name);
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for CloneReportFormatRequest {
    type Response = CreateReportFormatResponse;
}

/// Request for modifying report-format metadata or one parameter value.
#[derive(Debug, Clone)]
pub struct ModifyReportFormatRequest {
    /// Report format to modify.
    pub report_format_id: EntityId,
    /// Optional exact replacement name. An empty string is emitted explicitly.
    pub name: Option<String>,
    /// Optional exact replacement summary. An empty string clears the summary.
    pub summary: Option<String>,
    /// Optional active-state replacement.
    pub active: Option<bool>,
    /// Optional single parameter update.
    pub param: Option<ReportFormatParamUpdate>,
}

impl ModifyReportFormatRequest {
    /// Create a selector-only report-format modification request.
    #[must_use]
    pub fn new(report_format_id: EntityId) -> Self {
        Self {
            report_format_id,
            name: None,
            summary: None,
            active: None,
            param: None,
        }
    }
}

impl GmpRequestCodec for ModifyReportFormatRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.report_format_id, "report_format_id")?;
        validate_optional_xml_text(self.name.as_deref(), "name")?;
        validate_optional_xml_text(self.summary.as_deref(), "summary")?;
        if let Some(param) = &self.param {
            validate_xml_text(&param.name, "param.name")?;
            if param
                .value
                .as_deref()
                .is_some_and(|value| value.contains('\0'))
            {
                return Err(GmpRequestError::invalid_field(
                    "param.value",
                    "must not contain NUL",
                ));
            }
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_report_format"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("modify_report_format");
        command.set_attribute("report_format_id", self.report_format_id.as_str());
        if let Some(name) = &self.name {
            command.add_element_with_text("name", name);
        }
        if let Some(summary) = &self.summary {
            command.add_element_with_text("summary", summary);
        }
        if let Some(active) = self.active {
            command.add_element_with_text("active", if active { "1" } else { "0" });
        }
        if let Some(param) = &self.param {
            let element = command.add_element("param");
            element.add_child_with_text("name", &param.name);
            if let Some(value) = &param.value {
                let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
                element.add_child_with_text("value", &encoded);
            }
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for ModifyReportFormatRequest {
    type Response = ModifyReportFormatResponse;
}

/// Request for deleting a report format.
#[derive(Debug, Clone)]
pub struct DeleteReportFormatRequest {
    /// Report format to delete.
    pub report_format_id: EntityId,
    /// Whether to remove it permanently instead of moving it to trash.
    pub ultimate: Option<bool>,
}

impl DeleteReportFormatRequest {
    /// Create a non-ultimate report-format deletion request.
    #[must_use]
    pub fn new(report_format_id: EntityId) -> Self {
        Self {
            report_format_id,
            ultimate: None,
        }
    }
}

impl GmpRequestCodec for DeleteReportFormatRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.report_format_id, "report_format_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_report_format"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("delete_report_format");
        command.set_attribute("report_format_id", self.report_format_id.as_str());
        set_optional_bool_attr(&mut command, "ultimate", self.ultimate);
        Ok(command.to_bytes())
    }
}

impl GmpRequest for DeleteReportFormatRequest {
    type Response = DeleteReportFormatResponse;
}

/// Request for verifying a report format's signature trust.
#[derive(Debug, Clone)]
pub struct VerifyReportFormatRequest {
    /// Report format to verify.
    pub report_format_id: EntityId,
}

impl VerifyReportFormatRequest {
    /// Create a report-format verification request.
    #[must_use]
    pub fn new(report_format_id: EntityId) -> Self {
        Self { report_format_id }
    }
}

impl GmpRequestCodec for VerifyReportFormatRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_id(&self.report_format_id, "report_format_id")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("verify_report_format"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("verify_report_format");
        command.set_attribute("report_format_id", self.report_format_id.as_str());
        Ok(command.to_bytes())
    }
}

impl GmpRequest for VerifyReportFormatRequest {
    type Response = VerifyReportFormatResponse;
}

#[allow(clippy::too_many_arguments)]
fn get_report_formats_command(
    report_format_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    trash: Option<bool>,
    details: Option<bool>,
    alerts: Option<bool>,
    params: Option<bool>,
    report_configs: Option<bool>,
    ignore_pagination: Option<bool>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_report_formats");
    if let Some(report_format_id) = report_format_id {
        command.set_attribute("report_format_id", report_format_id.as_str());
    }
    add_filter_attrs(&mut command, filter_string, filter_id);
    set_optional_bool_attr(&mut command, "trash", trash);
    set_optional_bool_attr(&mut command, "details", details);
    set_optional_bool_attr(&mut command, "alerts", alerts);
    set_optional_bool_attr(&mut command, "params", params);
    set_optional_bool_attr(&mut command, "report_configs", report_configs);
    set_optional_bool_attr(&mut command, "ignore_pagination", ignore_pagination);
    command
}

fn validate_query(
    report_format_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    trash: Option<bool>,
    params: Option<bool>,
) -> Result<(), GmpRequestError> {
    validate_optional_id(report_format_id, "report_format_id")?;
    validate_optional_id(filter_id, "filter_id")?;
    validate_optional_xml_text(filter_string, "filter_string")?;
    if trash == Some(true) && params == Some(true) {
        return Err(GmpRequestError::invalid_field(
            "trash/params",
            "params=true is not supported with trash=true",
        ));
    }
    Ok(())
}

fn validate_import_envelope(xml: &str) -> Result<(), GmpRequestError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut state = ImportEnvelopeState::default();

    loop {
        let event = reader
            .read_event()
            .map_err(|_| import_error("must be well-formed XML"))?;
        match event {
            Event::Start(element) => state.start(&element)?,
            Event::Empty(element) => state.empty(&element)?,
            Event::End(_) => state.end()?,
            Event::Text(text) => {
                if state.stack.is_empty() {
                    if !text.as_ref().chars().all(char::is_whitespace) {
                        return Err(import_error("must not contain text outside the root"));
                    }
                } else if import_name_path(&state.stack) {
                    state
                        .format_name
                        .push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Event::CData(text) => {
                if state.stack.is_empty() {
                    return Err(import_error("must not contain content outside the root"));
                }
                if import_name_path(&state.stack) {
                    state.format_name.push_str(text.as_ref());
                }
            }
            Event::GeneralRef(reference) => {
                if state.stack.is_empty() {
                    return Err(import_error("must not contain references outside the root"));
                }
                let resolved = resolve_reference(&reference)
                    .ok_or_else(|| import_error("contains an unsupported entity reference"))?;
                if import_name_path(&state.stack) {
                    state.format_name.push_str(&resolved);
                }
            }
            Event::Decl(_) | Event::DocType(_) => {
                return Err(import_error(
                    "must not contain an XML declaration or doctype",
                ));
            }
            Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }

    state.finish()
}

#[derive(Default)]
struct ImportEnvelopeState {
    stack: Vec<String>,
    saw_root: bool,
    completed_root: bool,
    format_count: usize,
    format_has_id: bool,
    format_name: String,
    saw_format_name: bool,
}

impl ImportEnvelopeState {
    fn start(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        if self.stack.is_empty() {
            self.begin_root(element)?;
        }
        let name = element.name().as_ref().to_string();
        self.stack.push(name.clone());
        if self.stack.len() == 2 && name == "report_format" {
            self.record_format(element)?;
        }
        if self.stack.len() == 3 && self.stack[1] == "report_format" && name == "name" {
            self.saw_format_name = true;
        }
        validate_attributes(element)
    }

    fn empty(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        if self.stack.is_empty() {
            self.begin_root(element)?;
            self.completed_root = true;
        } else {
            let name = element.name().as_ref().to_string();
            if self.stack.len() == 1 && name == "report_format" {
                self.record_format(element)?;
            }
            if self.stack.len() == 2 && self.stack[1] == "report_format" && name == "name" {
                self.saw_format_name = true;
            }
        }
        validate_attributes(element)
    }

    fn begin_root(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        if self.saw_root || self.completed_root {
            return Err(import_error("must contain exactly one root element"));
        }
        validate_import_root(element)?;
        self.saw_root = true;
        Ok(())
    }

    fn record_format(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        self.format_count += 1;
        if self.format_count > 1 {
            return Err(import_error(
                "must contain exactly one direct report_format",
            ));
        }
        self.format_has_id = required_nonempty_attribute(element, "id")?;
        Ok(())
    }

    fn end(&mut self) -> Result<(), GmpRequestError> {
        if self.stack.pop().is_none() {
            return Err(import_error("contains an unmatched closing tag"));
        }
        if self.stack.is_empty() {
            self.completed_root = true;
        }
        Ok(())
    }

    fn finish(self) -> Result<(), GmpRequestError> {
        if !self.saw_root || !self.completed_root || !self.stack.is_empty() {
            return Err(import_error("must contain one complete response envelope"));
        }
        if self.format_count != 1 {
            return Err(import_error(
                "must contain exactly one direct report_format",
            ));
        }
        if !self.format_has_id {
            return Err(import_error(
                "report_format must have a nonempty id attribute",
            ));
        }
        if !self.saw_format_name || self.format_name.is_empty() {
            return Err(import_error(
                "report_format must have a nonempty direct name",
            ));
        }
        Ok(())
    }
}

fn validate_import_root(
    element: &quick_xml::events::BytesStart<'_>,
) -> Result<(), GmpRequestError> {
    if element.name().as_ref() != "get_report_formats_response" {
        return Err(import_error(
            "root must be an unqualified get_report_formats_response",
        ));
    }
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| import_error("contains an invalid attribute"))?;
        let key = attribute.key.as_ref();
        if key == "xmlns" || key.starts_with("xmlns:") {
            return Err(import_error(
                "root must be an unqualified get_report_formats_response",
            ));
        }
    }
    Ok(())
}

fn validate_attributes(element: &quick_xml::events::BytesStart<'_>) -> Result<(), GmpRequestError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| import_error("contains an invalid attribute"))?;
        attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| import_error("contains an invalid attribute value"))?;
    }
    Ok(())
}

fn required_nonempty_attribute(
    element: &quick_xml::events::BytesStart<'_>,
    expected: &str,
) -> Result<bool, GmpRequestError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| import_error("contains an invalid attribute"))?;
        if attribute.key.as_ref() == expected {
            return attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map(|value| !value.is_empty())
                .map_err(|_| import_error("contains an invalid attribute value"));
        }
    }
    Ok(false)
}

fn import_name_path(stack: &[String]) -> bool {
    stack.len() == 3
        && stack[0] == "get_report_formats_response"
        && stack[1] == "report_format"
        && stack[2] == "name"
}

fn resolve_reference(reference: &BytesRef<'_>) -> Option<String> {
    if let Some(character) = reference.resolve_char_ref().ok()? {
        return is_xml_1_0_character(character).then(|| character.to_string());
    }
    quick_xml::escape::resolve_xml_entity(reference.as_ref()).map(ToString::to_string)
}

fn import_error(message: &'static str) -> GmpRequestError {
    GmpRequestError::invalid_field("report_format_xml", message)
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
