// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded incremental metadata for native `get_reports_response` pages.

use gvm_protocol::{
    resolve_xml_reference, Response, StreamingXmlElement, StreamingXmlEvent, StreamingXmlReader,
};

use crate::responses::audit_report::{ReportFilter, ReportFilterKeyword, ReportPage};
use crate::responses::common::{parse_entity_id, CountInfo, ParseError};
use crate::{EntityId, GmpResponse, GmpStreamDecoder, GmpStreamingResponse, GmpVersion};

const ROOT: &str = "get_reports_response";
const BUFFERED_EVENT_CHUNK_BYTES: usize = 8 * 1024;
const MAX_METADATA_BYTES: usize = 256 * 1024;
const MAX_FILTER_KEYWORDS: usize = 256;

/// Total, unfiltered, and filtered result counts observed in a native report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeReportResultCount {
    /// Direct text value of `<result_count>`, when gvmd supplies it.
    pub total: Option<u64>,
    /// Value of `<result_count><full>`, when supplied.
    pub full: Option<u64>,
    /// Value of `<result_count><filtered>`, when supplied.
    pub filtered: Option<u64>,
}

/// Small completion metadata for one complete native GMP report page.
///
/// The potentially large report and result bodies are deliberately absent.
/// The generic framer validates them without allocating unselected body text
/// for [`crate::GmpStreamDecoder`], while `GmpClient::execute_stream` yields
/// their original bytes.
///
/// Buffered decoding likewise returns metadata only: although it validates the
/// complete buffered response, it deliberately discards the native XML body.
/// Use streaming execution when the response bytes must be retained.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeReportPageResponse {
    /// Successful GMP response status.
    pub status: u16,
    /// Successful GMP response status text.
    pub status_text: String,
    /// ID on the outer report resource envelope, when present.
    pub report_id: Option<EntityId>,
    /// ID on the nested native report body, when present.
    pub content_report_id: Option<EntityId>,
    /// Task ID from the nested report body, falling back to the outer envelope.
    pub task_id: Option<EntityId>,
    /// Run status captured in the nested native report body.
    pub scan_run_status: Option<String>,
    /// Resolved result-filter metadata from the nested report body.
    pub filter: Option<ReportFilter>,
    /// Actual `<results start="..." max="...">` window returned by gvmd.
    pub page: ReportPage,
    /// Number of direct `<result>` elements actually returned in `results`.
    ///
    /// This, rather than the requested `rows` or returned `page.max`, is the
    /// amount by which a caller can advance `first` after a non-empty page.
    pub returned_results: u64,
    /// Result totals from the nested native report body.
    pub result_count: Option<NativeReportResultCount>,
    /// Outer report collection counts, useful for single-report consistency checks.
    pub report_count: CountInfo,
}

impl GmpResponse for NativeReportPageResponse {
    fn decode(response: &Response, version: GmpVersion) -> Result<Self, ParseError> {
        let mut decoder = Self::stream_decoder(version);
        let mut reader = StreamingXmlReader::new();
        let mut offset = 0;
        while offset < response.data().len() && !reader.is_complete() {
            let end = (offset + BUFFERED_EVENT_CHUNK_BYTES).min(response.data().len());
            let (consumed, events) = reader
                .feed_frame_events_with_text(&response.data()[offset..end], |path| {
                    decoder.wants_text(path)
                })
                .map_err(ParseError::from)?;
            for event in &events {
                decoder.feed(event)?;
            }
            offset += consumed;
        }
        if !reader.is_complete() {
            return Err(ParseError::MissingElement(
                "complete get_reports_response root".to_string(),
            ));
        }
        if response.data()[offset..]
            .iter()
            .any(|byte| !byte.is_ascii_whitespace())
        {
            return Err(ParseError::InvalidValue {
                field: "native report page XML".to_string(),
                value: "data follows the root element".to_string(),
            });
        }
        decoder.finish()
    }
}

impl GmpStreamingResponse for NativeReportPageResponse {
    type Decoder = NativeReportPageDecoder;

    fn stream_decoder(_version: GmpVersion) -> Self::Decoder {
        NativeReportPageDecoder::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureKind {
    ScanRunStatus,
    FilterTerm,
    KeywordColumn,
    KeywordRelation,
    KeywordValue,
    ResultTotal,
    ResultFull,
    ResultFiltered,
    ReportCountTotal,
    ReportCountFiltered,
    ReportCountPage,
}

struct Capture {
    kind: CaptureKind,
    depth: usize,
    text: String,
}

#[derive(Default)]
struct FilterBuilder {
    id: Option<EntityId>,
    term: Option<String>,
    keywords: Vec<ReportFilterKeyword>,
}

#[derive(Default)]
struct KeywordBuilder {
    column: Option<String>,
    relation: Option<String>,
    value: Option<String>,
}

/// Incremental native report-page metadata decoder.
///
/// The decoder consumes only validated events from the generic streaming XML
/// framer. Retention is capped at 256 filter keywords and 256 KiB of small
/// metadata text. Result bodies are skipped by depth, so their element names
/// and text are not retained by this decoder.
pub struct NativeReportPageDecoder {
    elements: Vec<String>,
    captures: Vec<Capture>,
    metadata_bytes: usize,
    root_complete: bool,
    skipped_result_depth: Option<usize>,
    status: Option<u16>,
    status_text: Option<String>,
    report_id: Option<EntityId>,
    content_report_id: Option<EntityId>,
    outer_task_id: Option<EntityId>,
    inner_task_id: Option<EntityId>,
    scan_run_status: Option<String>,
    filter_builder: Option<FilterBuilder>,
    current_keyword: Option<KeywordBuilder>,
    filter: Option<ReportFilter>,
    page: ReportPage,
    returned_results: u64,
    result_count: Option<NativeReportResultCount>,
    report_count: CountInfo,
}

impl std::fmt::Debug for NativeReportPageDecoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeReportPageDecoder")
            .field("depth", &self.elements.len())
            .field("metadata_bytes", &self.metadata_bytes)
            .field("root_complete", &self.root_complete)
            .finish()
    }
}

impl NativeReportPageDecoder {
    /// Create an empty native report-page decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            captures: Vec::new(),
            metadata_bytes: 0,
            root_complete: false,
            skipped_result_depth: None,
            status: None,
            status_text: None,
            report_id: None,
            content_report_id: None,
            outer_task_id: None,
            inner_task_id: None,
            scan_run_status: None,
            filter_builder: None,
            current_keyword: None,
            filter: None,
            page: ReportPage::default(),
            returned_results: 0,
            result_count: None,
            report_count: CountInfo::default(),
        }
    }

    fn start_element(
        &mut self,
        element: &StreamingXmlElement,
        depth: usize,
        empty: bool,
    ) -> Result<(), ParseError> {
        let name = &element.name;

        if self.skipped_result_depth.is_some() {
            return Ok(());
        }
        if self.path_is(&[ROOT, "report", "report", "results"]) && name == "result" {
            self.returned_results = self
                .returned_results
                .checked_add(1)
                .ok_or_else(|| bounded_decoder_error("returned result count"))?;
            if !empty {
                self.skipped_result_depth = Some(depth);
            }
            return Ok(());
        }

        if self.elements.is_empty() {
            if name != ROOT {
                return Err(ParseError::InvalidValue {
                    field: "root".to_string(),
                    value: name.clone(),
                });
            }
            self.status = Some(parse_required_u16_attr(element, "status", "status")?);
            if let Some(status_text) = element.attribute("status_text") {
                self.retain_metadata_bytes(status_text.len())?;
                self.status_text = Some(status_text.to_string());
            }
        } else if self.path_is(&[ROOT]) && name == "report" && self.report_id.is_none() {
            self.report_id = self.parse_optional_id_attr(element, "id", "report.id")?;
        } else if self.path_is(&[ROOT, "report"]) && name == "report" {
            self.content_report_id =
                self.parse_optional_id_attr(element, "id", "report.report.id")?;
        } else if self.path_is(&[ROOT, "report"]) && name == "task" {
            self.outer_task_id = self.parse_optional_id_attr(element, "id", "report.task.id")?;
        } else if self.path_is(&[ROOT, "report", "report"]) && name == "task" {
            self.inner_task_id =
                self.parse_optional_id_attr(element, "id", "report.report.task.id")?;
        } else if self.path_is(&[ROOT, "report", "report"]) && name == "filters" {
            self.filter_builder = Some(FilterBuilder {
                id: self.parse_optional_id_attr(element, "id", "report.report.filters.id")?,
                ..FilterBuilder::default()
            });
        } else if self.path_is(&[ROOT, "report", "report"]) && name == "results" {
            self.page = ReportPage {
                start: parse_optional_u32_attr(element, "start", "report.report.results.start")?,
                max: parse_optional_i32_attr(element, "max", "report.report.results.max")?,
            };
        } else if self.path_is(&[ROOT, "report", "report"]) && name == "result_count" {
            self.result_count = Some(NativeReportResultCount::default());
        }

        self.elements.push(name.clone());
        self.begin_capture_for_current_path();

        if self.path_is(&[ROOT, "report", "report", "filters", "keywords", "keyword"]) {
            if self
                .filter_builder
                .as_ref()
                .is_some_and(|filter| filter.keywords.len() >= MAX_FILTER_KEYWORDS)
            {
                return Err(bounded_decoder_error("filter keyword metadata"));
            }
            self.current_keyword = Some(KeywordBuilder::default());
        }

        if empty {
            self.end_element(name, depth)?;
        }
        Ok(())
    }

    fn begin_capture_for_current_path(&mut self) {
        if let Some(kind) = capture_kind(&self.elements) {
            self.captures.push(Capture {
                kind,
                depth: self.elements.len(),
                text: String::new(),
            });
        }
    }

    fn process_text(&mut self, depth: usize, text: &str) -> Result<(), ParseError> {
        if let Some(capture) = self
            .captures
            .iter_mut()
            .find(|capture| capture.depth == depth)
        {
            self.metadata_bytes = self.metadata_bytes.saturating_add(text.len());
            if self.metadata_bytes > MAX_METADATA_BYTES {
                return Err(bounded_decoder_error("completion metadata"));
            }
            capture.text.push_str(text);
        }
        Ok(())
    }

    fn process_reference(&mut self, depth: usize, reference: &str) -> Result<(), ParseError> {
        let resolved = resolve_xml_reference(reference)?;
        self.process_text(depth, &resolved)
    }

    fn retain_metadata_bytes(&mut self, additional: usize) -> Result<(), ParseError> {
        self.metadata_bytes = self.metadata_bytes.saturating_add(additional);
        if self.metadata_bytes > MAX_METADATA_BYTES {
            return Err(bounded_decoder_error("completion metadata"));
        }
        Ok(())
    }

    fn parse_optional_id_attr(
        &mut self,
        element: &StreamingXmlElement,
        name: &str,
        field: &str,
    ) -> Result<Option<EntityId>, ParseError> {
        let Some(value) = element
            .attribute(name)
            .filter(|value| !value.is_empty() && *value != "0")
        else {
            return Ok(None);
        };
        self.retain_metadata_bytes(value.len())?;
        parse_entity_id(value, field).map(Some)
    }

    fn end_element(&mut self, _name: &str, depth: usize) -> Result<(), ParseError> {
        if let Some(result_depth) = self.skipped_result_depth {
            if depth == result_depth {
                self.skipped_result_depth = None;
            }
            return Ok(());
        }

        let depth = self.elements.len();
        if let Some(capture) = self.captures.pop_if(|capture| capture.depth == depth) {
            self.finish_capture(capture)?;
        }

        if self.path_is(&[ROOT, "report", "report", "filters", "keywords", "keyword"]) {
            self.finish_keyword()?;
        } else if self.path_is(&[ROOT, "report", "report", "filters"]) {
            self.finish_filter();
        } else if self.path_is(&[ROOT]) {
            self.root_complete = true;
        }

        self.elements.pop();
        Ok(())
    }

    fn finish_capture(&mut self, capture: Capture) -> Result<(), ParseError> {
        let value = capture.text.trim().to_string();
        match capture.kind {
            CaptureKind::ScanRunStatus => {
                self.scan_run_status = (!value.is_empty()).then_some(value);
            }
            CaptureKind::FilterTerm => {
                if let Some(filter) = self.filter_builder.as_mut() {
                    filter.term = Some(value);
                }
            }
            CaptureKind::KeywordColumn => {
                if let Some(keyword) = self.current_keyword.as_mut() {
                    keyword.column = Some(value);
                }
            }
            CaptureKind::KeywordRelation => {
                if let Some(keyword) = self.current_keyword.as_mut() {
                    keyword.relation = Some(value);
                }
            }
            CaptureKind::KeywordValue => {
                if let Some(keyword) = self.current_keyword.as_mut() {
                    keyword.value = Some(value);
                }
            }
            CaptureKind::ResultTotal => {
                if let Some(count) = self.result_count.as_mut() {
                    count.total = parse_optional_u64_text(&value, "report.report.result_count")?;
                }
            }
            CaptureKind::ResultFull => {
                if let Some(count) = self.result_count.as_mut() {
                    count.full = Some(parse_u64_text(&value, "report.report.result_count.full")?);
                }
            }
            CaptureKind::ResultFiltered => {
                if let Some(count) = self.result_count.as_mut() {
                    count.filtered = Some(parse_u64_text(
                        &value,
                        "report.report.result_count.filtered",
                    )?);
                }
            }
            CaptureKind::ReportCountTotal => {
                self.report_count.total = parse_optional_u32_text(&value, "report_count")?;
            }
            CaptureKind::ReportCountFiltered => {
                self.report_count.filtered = Some(parse_u32_text(&value, "report_count.filtered")?);
            }
            CaptureKind::ReportCountPage => {
                self.report_count.page = Some(parse_u32_text(&value, "report_count.page")?);
            }
        }
        Ok(())
    }

    fn finish_keyword(&mut self) -> Result<(), ParseError> {
        let keyword = self
            .current_keyword
            .take()
            .ok_or_else(|| ParseError::MissingElement("filters.keyword".to_string()))?;
        let keyword = ReportFilterKeyword {
            column: keyword
                .column
                .ok_or_else(|| ParseError::MissingElement("filters.keyword.column".to_string()))?,
            relation: keyword.relation.ok_or_else(|| {
                ParseError::MissingElement("filters.keyword.relation".to_string())
            })?,
            value: keyword
                .value
                .ok_or_else(|| ParseError::MissingElement("filters.keyword.value".to_string()))?,
        };
        if let Some(filter) = self.filter_builder.as_mut() {
            filter.keywords.push(keyword);
        }
        Ok(())
    }

    fn finish_filter(&mut self) {
        if let Some(filter) = self.filter_builder.take() {
            self.filter = Some(ReportFilter {
                id: filter.id,
                term: filter.term.unwrap_or_default(),
                keywords: filter.keywords,
            });
        }
    }

    fn path_is(&self, expected: &[&str]) -> bool {
        self.elements
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    }
}

impl Default for NativeReportPageDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GmpStreamDecoder for NativeReportPageDecoder {
    type Completion = NativeReportPageResponse;

    fn wants_text(&self, element_path: &[String]) -> bool {
        capture_kind(element_path).is_some()
    }

    fn feed(&mut self, event: &StreamingXmlEvent) -> Result<(), ParseError> {
        match event {
            StreamingXmlEvent::Start { element, depth } => {
                self.start_element(element, *depth, false)
            }
            StreamingXmlEvent::Empty { element, depth } => {
                self.start_element(element, *depth, true)
            }
            StreamingXmlEvent::End { name, depth } => self.end_element(name, *depth),
            StreamingXmlEvent::Text { text, depth } | StreamingXmlEvent::CData { text, depth } => {
                self.process_text(*depth, text)
            }
            StreamingXmlEvent::Reference { reference, depth } => {
                self.process_reference(*depth, reference)
            }
            _ => Ok(()),
        }
    }

    fn finish(self) -> Result<Self::Completion, ParseError> {
        if !self.elements.is_empty() || !self.root_complete {
            return Err(ParseError::MissingElement(
                "complete get_reports_response root".to_string(),
            ));
        }
        let status = self
            .status
            .ok_or_else(|| ParseError::MissingElement("status".to_string()))?;
        let status_text = self.status_text.unwrap_or_else(|| {
            if (200..300).contains(&status) {
                String::new()
            } else {
                "Unknown error".to_string()
            }
        });
        if !(200..300).contains(&status) {
            return Err(ParseError::ServerError {
                status,
                message: status_text,
            });
        }

        Ok(NativeReportPageResponse {
            status,
            status_text,
            report_id: self.report_id,
            content_report_id: self.content_report_id,
            task_id: self.inner_task_id.or(self.outer_task_id),
            scan_run_status: self.scan_run_status,
            filter: self.filter,
            page: self.page,
            returned_results: self.returned_results,
            result_count: self.result_count,
            report_count: self.report_count,
        })
    }
}

fn capture_kind(element_path: &[String]) -> Option<CaptureKind> {
    const PATHS: &[(&[&str], CaptureKind)] = &[
        (
            &[ROOT, "report", "report", "scan_run_status"],
            CaptureKind::ScanRunStatus,
        ),
        (
            &[ROOT, "report", "report", "filters", "term"],
            CaptureKind::FilterTerm,
        ),
        (
            &[
                ROOT, "report", "report", "filters", "keywords", "keyword", "column",
            ],
            CaptureKind::KeywordColumn,
        ),
        (
            &[
                ROOT, "report", "report", "filters", "keywords", "keyword", "relation",
            ],
            CaptureKind::KeywordRelation,
        ),
        (
            &[
                ROOT, "report", "report", "filters", "keywords", "keyword", "value",
            ],
            CaptureKind::KeywordValue,
        ),
        (
            &[ROOT, "report", "report", "result_count"],
            CaptureKind::ResultTotal,
        ),
        (
            &[ROOT, "report", "report", "result_count", "full"],
            CaptureKind::ResultFull,
        ),
        (
            &[ROOT, "report", "report", "result_count", "filtered"],
            CaptureKind::ResultFiltered,
        ),
        (&[ROOT, "report_count"], CaptureKind::ReportCountTotal),
        (
            &[ROOT, "report_count", "filtered"],
            CaptureKind::ReportCountFiltered,
        ),
        (
            &[ROOT, "report_count", "page"],
            CaptureKind::ReportCountPage,
        ),
    ];

    PATHS
        .iter()
        .find_map(|(path, kind)| path_is(element_path, path).then_some(*kind))
}

fn path_is(actual: &[String], expected: &[&str]) -> bool {
    actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn required_attr<'a>(element: &'a StreamingXmlElement, name: &str) -> Result<&'a str, ParseError> {
    element
        .attribute(name)
        .ok_or_else(|| ParseError::MissingElement(name.to_string()))
}

fn parse_required_u16_attr(
    element: &StreamingXmlElement,
    name: &str,
    field: &str,
) -> Result<u16, ParseError> {
    let value = required_attr(element, name)?;
    value.parse().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

fn parse_optional_i32_attr(
    element: &StreamingXmlElement,
    name: &str,
    field: &str,
) -> Result<Option<i32>, ParseError> {
    element
        .attribute(name)
        .map(|value| {
            value.parse().map_err(|_| ParseError::InvalidValue {
                field: field.to_string(),
                value: value.to_string(),
            })
        })
        .transpose()
}

fn parse_optional_u32_attr(
    element: &StreamingXmlElement,
    name: &str,
    field: &str,
) -> Result<Option<u32>, ParseError> {
    element
        .attribute(name)
        .map(|value| parse_u32_text(value, field))
        .transpose()
}

fn parse_u64_text(value: &str, field: &str) -> Result<u64, ParseError> {
    value.parse().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

fn parse_optional_u64_text(value: &str, field: &str) -> Result<Option<u64>, ParseError> {
    (!value.is_empty())
        .then(|| parse_u64_text(value, field))
        .transpose()
}

fn parse_u32_text(value: &str, field: &str) -> Result<u32, ParseError> {
    value.parse().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

fn parse_optional_u32_text(value: &str, field: &str) -> Result<Option<u32>, ParseError> {
    (!value.is_empty())
        .then(|| parse_u32_text(value, field))
        .transpose()
}

fn bounded_decoder_error(field: &str) -> ParseError {
    ParseError::InvalidValue {
        field: field.to_string(),
        value: "exceeds native report-page decoder retention limit".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT_ID: &str = "11111111-1111-1111-1111-111111111111";
    const TASK_ID: &str = "22222222-2222-2222-2222-222222222222";

    fn page(first: u32, rows: u32, total: u64, filtered: u64) -> Vec<u8> {
        let result = (filtered > 0)
            .then_some(r#"<result id="result-1"><description>body</description></result>"#);
        format!(
            r#"<get_reports_response status="200" status_text="OK">
<report id="{REPORT_ID}"><task id="{TASK_ID}"/><report id="{REPORT_ID}">
<filters id=""><term>sev<![CDATA[erity]]>&#x3e;5 &amp; active=1 first={first} rows={rows}</term><keywords>
<keyword><column>sev<![CDATA[erity]]></column><relation>&gt;</relation><value>&#53;</value></keyword>
<keyword><column>first</column><relation>=</relation><value>{first}</value></keyword>
<keyword><column>rows</column><relation>=</relation><value>{rows}</value></keyword>
</keywords></filters><scan_run_status>D<![CDATA[on]]>e</scan_run_status><task id="{TASK_ID}"/>
<results start="{first}" max="{rows}">{result}</results>
<result_count>{total}<full>{total}</full><filtered>{filtered}</filtered></result_count>
</report></report><filters id=""><term>first=1 rows=1000</term><keywords/></filters>
<reports start="1" max="1000"/><report_count>&#49;<filtered>&#x31;</filtered><page><![CDATA[1]]></page></report_count>
</get_reports_response>"#,
            result = result.unwrap_or_default(),
        )
        .into_bytes()
    }

    fn feed_chunks(
        decoder: &mut NativeReportPageDecoder,
        xml: &[u8],
        size: usize,
    ) -> Result<bool, ParseError> {
        let mut reader = StreamingXmlReader::new();
        let mut offset = 0;
        while offset < xml.len() && !reader.is_complete() {
            let end = (offset + size).min(xml.len());
            let (consumed, events) = reader
                .feed_frame_events_with_text(&xml[offset..end], |path| decoder.wants_text(path))
                .map_err(ParseError::from)?;
            for event in &events {
                decoder.feed(event)?;
            }
            offset += consumed;
        }
        Ok(reader.is_complete() && offset == xml.len())
    }

    fn decode_chunks(xml: &[u8], size: usize) -> NativeReportPageResponse {
        let mut decoder = NativeReportPageDecoder::new();
        assert!(feed_chunks(&mut decoder, xml, size).expect("chunks should decode"));
        decoder.finish().expect("page should finish")
    }

    fn assert_page_metadata(metadata: &NativeReportPageResponse) {
        assert_eq!(metadata.status, 200);
        assert_eq!(metadata.status_text, "OK");
        assert_eq!(
            metadata.report_id.as_ref().map(EntityId::as_str),
            Some(REPORT_ID)
        );
        assert_eq!(
            metadata.content_report_id.as_ref().map(EntityId::as_str),
            Some(REPORT_ID)
        );
        assert_eq!(
            metadata.task_id.as_ref().map(EntityId::as_str),
            Some(TASK_ID)
        );
        assert_eq!(metadata.scan_run_status.as_deref(), Some("Done"));
        assert_eq!(metadata.page.start, Some(11));
        assert_eq!(metadata.page.max, Some(25));
        assert_eq!(metadata.returned_results, 1);
        let filter = metadata.filter.as_ref().expect("filter metadata");
        assert_eq!(filter.term, "severity>5 & active=1 first=11 rows=25");
        assert_eq!(filter.keywords.len(), 3);
        assert_eq!(filter.keywords[0].column, "severity");
        assert_eq!(filter.keywords[0].relation, ">");
        assert_eq!(filter.keywords[0].value, "5");
        assert_eq!(filter.keywords[1].column, "first");
        assert_eq!(filter.keywords[1].value, "11");
        assert_eq!(filter.keywords[2].column, "rows");
        assert_eq!(filter.keywords[2].value, "25");
        assert_eq!(
            metadata.result_count,
            Some(NativeReportResultCount {
                total: Some(80),
                full: Some(80),
                filtered: Some(37),
            })
        );
        assert_eq!(metadata.report_count.total, Some(1));
        assert_eq!(metadata.report_count.filtered, Some(1));
        assert_eq!(metadata.report_count.page, Some(1));
    }

    #[test]
    fn decoder_accumulates_fragmented_text_cdata_and_references() {
        let xml = page(11, 25, 80, 37);

        for size in 1..=64 {
            assert_page_metadata(&decode_chunks(&xml, size));
        }
    }

    #[test]
    fn buffered_response_association_uses_the_event_decoder() {
        let mut xml = page(11, 25, 80, 37);
        xml.extend_from_slice(b"\n\t");
        let response = Response::new(xml);
        let metadata = NativeReportPageResponse::decode(&response, GmpVersion(22, 8))
            .expect("buffered native report page");

        assert_page_metadata(&metadata);

        let mut xml = page(11, 25, 80, 37);
        xml.extend_from_slice(b"<extra/>");
        let response = Response::new(xml);
        assert!(matches!(
            NativeReportPageResponse::decode(&response, GmpVersion(22, 8)),
            Err(ParseError::InvalidValue { field, .. })
                if field == "native report page XML"
        ));

        let response = Response::new(
            br#"<get_reports_response status="200" status_text="OK"><report></wrong>"#.to_vec(),
        );
        assert!(matches!(
            NativeReportPageResponse::decode(&response, GmpVersion(22, 8)),
            Err(ParseError::Protocol(gvm_protocol::ProtocolError::XmlParse(
                _
            )))
        ));
    }

    #[test]
    fn decoder_handles_zero_result_and_later_pages() {
        let zero = decode_chunks(&page(1, 10, 0, 0), 7);
        assert_eq!(zero.page.start, Some(1));
        assert_eq!(zero.page.max, Some(10));
        assert_eq!(zero.returned_results, 0);
        assert_eq!(
            zero.result_count,
            Some(NativeReportResultCount {
                total: Some(0),
                full: Some(0),
                filtered: Some(0),
            })
        );

        let later = decode_chunks(&page(26, 25, 80, 37), 13);
        assert_eq!(later.page.start, Some(26));
        assert_eq!(later.page.max, Some(25));
        assert_eq!(later.returned_results, 1);
        assert_eq!(
            later.filter.as_ref().expect("filter").keywords[1].value,
            "26"
        );
    }

    #[test]
    fn decoder_normalizes_server_errors_and_validates_root() {
        let mut decoder = NativeReportPageDecoder::new();
        assert!(feed_chunks(
            &mut decoder,
            br#"<get_reports_response status="503" status_text="Unavailable"/>"#,
            3,
        )
        .expect("valid error envelope"));
        assert!(matches!(
            decoder.finish(),
            Err(ParseError::ServerError { status: 503, message }) if message == "Unavailable"
        ));

        let mut wrong_root = NativeReportPageDecoder::new();
        assert!(matches!(
            feed_chunks(
                &mut wrong_root,
                br#"<get_results_response status="200" status_text="OK"/>"#,
                5,
            ),
            Err(ParseError::InvalidValue { field, .. }) if field == "root"
        ));
    }

    #[test]
    fn decoder_rejects_truncated_or_invalid_metadata() {
        let mut truncated = NativeReportPageDecoder::new();
        assert!(!feed_chunks(
            &mut truncated,
            br#"<get_reports_response status="200" status_text="OK"><report>"#,
            7,
        )
        .expect("prefix is incrementally valid"));
        assert!(matches!(
            truncated.finish(),
            Err(ParseError::MissingElement(_))
        ));

        let xml = page(11, 25, 80, 37);
        let xml = String::from_utf8(xml)
            .expect("fixture UTF-8")
            .replace("<filtered>37</filtered>", "<filtered>many</filtered>");
        let mut invalid = NativeReportPageDecoder::new();
        assert!(matches!(
            feed_chunks(&mut invalid, xml.as_bytes(), 11),
            Err(ParseError::InvalidValue { field, .. })
                if field == "report.report.result_count.filtered"
        ));
    }

    #[test]
    fn decoder_discards_a_large_results_body() {
        let body = "x".repeat(8 * 1024 * 1024);
        let xml = format!(
            r#"<get_reports_response status="200" status_text="OK"><report id="{REPORT_ID}"><report id="{REPORT_ID}"><scan_run_status>Done</scan_run_status><results start="1" max="1"><result id="one"><description>{body}</description></result></results><result_count>1<full>1</full><filtered>1</filtered></result_count></report></report><report_count>1<filtered>1</filtered></report_count></get_reports_response>"#
        );
        let mut decoder = NativeReportPageDecoder::new();
        assert!(feed_chunks(&mut decoder, xml.as_bytes(), 4093).expect("large page chunks"));
        assert!(decoder.metadata_bytes < 1024);
        assert!(!decoder.wants_text(&[
            ROOT.to_string(),
            "report".to_string(),
            "report".to_string(),
            "results".to_string(),
            "result".to_string(),
            "description".to_string(),
        ]));
        let metadata = decoder.finish().expect("large page completion");

        assert_eq!(metadata.page.start, Some(1));
        assert_eq!(metadata.returned_results, 1);
        assert_eq!(
            metadata.result_count.and_then(|count| count.filtered),
            Some(1)
        );
    }

    #[test]
    fn decoder_counts_start_and_empty_results_at_the_exact_path() {
        let xml = br#"<get_reports_response status="200" status_text="OK"><report><report><results start="1" max="10"><result id="empty"/><result id="full"><result id="nested"/></result><wrapper><result id="wrong-path"/></wrapper></results></report></report><result id="outer"/></get_reports_response>"#;

        for size in 1..=32 {
            let metadata = decode_chunks(xml, size);
            assert_eq!(metadata.returned_results, 2);
        }
    }
}
