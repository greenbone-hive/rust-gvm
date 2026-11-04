// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Streaming XML reader for detecting GMP response boundaries.
//!
//! Reads XML data incrementally, validates document structure, and preserves
//! exact root-element boundaries across transport chunks.

use quick_xml::errors::{Error as XmlError, IllFormedError, SyntaxError};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesDecl, BytesEnd, BytesRef, BytesStart, BytesText, Event};
use quick_xml::{Reader, XmlVersion};

use crate::error::ProtocolError;

const DEFAULT_MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_DEPTH: usize = 256;
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// One validated XML element exposed to incremental response decoders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingXmlElement {
    /// Element name exactly as received.
    pub name: String,
    /// Normalized attributes in wire order.
    pub attributes: Vec<(String, String)>,
}

impl StreamingXmlElement {
    /// Return a named attribute value.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
    }
}

/// A validated, bounded incremental XML event.
///
/// Selected character content is reported as ordered [`Self::Text`],
/// [`Self::CData`], and [`Self::Reference`] fragments. A reference preserves
/// its spelling without the surrounding `&` and `;`; it is not expanded into
/// replacement text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamingXmlEvent {
    /// Opening element at the reported one-based depth.
    Start {
        /// Parsed element name and attributes.
        element: StreamingXmlElement,
        /// One-based element depth; the response root is depth one.
        depth: usize,
    },
    /// Self-closing element at the reported one-based depth.
    Empty {
        /// Parsed element name and attributes.
        element: StreamingXmlElement,
        /// One-based element depth; the response root is depth one.
        depth: usize,
    },
    /// Closing element at the reported one-based depth.
    End {
        /// Closing element name.
        name: String,
        /// One-based element depth before the element is closed.
        depth: usize,
    },
    /// Character data inside the reported element depth.
    Text {
        /// One validated XML character-data fragment as received, before
        /// entity expansion.
        text: String,
        /// Current element depth.
        depth: usize,
    },
    /// CDATA content inside the reported element depth.
    CData {
        /// One validated CDATA content fragment.
        text: String,
        /// Current element depth.
        depth: usize,
    },
    /// A general entity or character reference inside the reported depth.
    Reference {
        /// Reference text without `&` and `;` delimiters.
        reference: String,
        /// Current element depth.
        depth: usize,
    },
}

#[derive(Debug)]
enum PendingToken {
    Tag {
        scan_offset: usize,
        quote: Option<u8>,
    },
    Sequence {
        scan_offset: usize,
        terminator: TokenTerminator,
        matched: usize,
    },
}

#[derive(Debug, Clone, Copy)]
enum TokenTerminator {
    ProcessingInstruction,
    Comment,
    CData,
    Reference,
}

impl PendingToken {
    fn from_error(error: &XmlError, scan_offset: usize) -> Option<Self> {
        match error {
            XmlError::Syntax(
                SyntaxError::UnclosedTag
                | SyntaxError::UnclosedSingleQuotedAttributeValue
                | SyntaxError::UnclosedDoubleQuotedAttributeValue,
            ) => Some(Self::Tag {
                scan_offset,
                quote: None,
            }),
            XmlError::Syntax(SyntaxError::UnclosedPI | SyntaxError::UnclosedXmlDecl) => {
                Some(Self::Sequence {
                    scan_offset,
                    terminator: TokenTerminator::ProcessingInstruction,
                    matched: 0,
                })
            }
            XmlError::Syntax(SyntaxError::UnclosedComment) => Some(Self::Sequence {
                scan_offset,
                terminator: TokenTerminator::Comment,
                matched: 0,
            }),
            XmlError::Syntax(SyntaxError::UnclosedCData) => Some(Self::Sequence {
                scan_offset,
                terminator: TokenTerminator::CData,
                matched: 0,
            }),
            XmlError::IllFormed(IllFormedError::UnclosedReference) => Some(Self::Sequence {
                scan_offset,
                terminator: TokenTerminator::Reference,
                matched: 0,
            }),
            _ => None,
        }
    }

    fn scan_until_ready(&mut self, buffer: &[u8]) -> bool {
        match self {
            Self::Tag { scan_offset, quote } => {
                for byte in &buffer[*scan_offset..] {
                    *scan_offset += 1;
                    match (*quote, *byte) {
                        (None, b'\'' | b'"') => *quote = Some(*byte),
                        (Some(active), current) if active == current => *quote = None,
                        (None, b'>') => return true,
                        _ => {}
                    }
                }
                false
            }
            Self::Sequence {
                scan_offset,
                terminator,
                matched,
            } => {
                let needle = terminator.bytes();
                for byte in &buffer[*scan_offset..] {
                    *scan_offset += 1;
                    while *matched > 0 && needle[*matched] != *byte {
                        *matched = terminator.fallback(*matched);
                    }
                    if needle[*matched] == *byte {
                        *matched += 1;
                        if *matched == needle.len() {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }
}

impl TokenTerminator {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::ProcessingInstruction => b"?>",
            Self::Comment => b"-->",
            Self::CData => b"]]>",
            Self::Reference => b";",
        }
    }

    fn fallback(self, matched: usize) -> usize {
        match (self, matched) {
            (Self::Comment | Self::CData, 2) => 1,
            _ => 0,
        }
    }
}

struct FrameProgress<'state, 'sink> {
    max_depth: usize,
    complete: &'state mut bool,
    seen_start: &'state mut bool,
    declaration_allowed: &'state mut bool,
    resume_offset: &'state mut usize,
    frame_end: &'state mut Option<usize>,
    element_names: &'state mut Vec<String>,
    trailing_text_brackets: &'state mut u8,
    pending_token: &'state mut Option<PendingToken>,
    discarded_len: usize,
    events: Option<EventSink<'sink>>,
}

struct EventSink<'a> {
    events: &'a mut Vec<StreamingXmlEvent>,
    wants_text: &'a mut dyn FnMut(&[String]) -> bool,
}

impl EventSink<'_> {
    fn reborrow(&mut self) -> EventSink<'_> {
        EventSink {
            events: self.events,
            wants_text: self.wants_text,
        }
    }
}

impl FrameProgress<'_, '_> {
    fn accept_start(&mut self, element: &BytesStart<'_>) -> Result<(), ProtocolError> {
        *self.trailing_text_brackets = 0;
        open_element(element, self.seen_start, self.element_names, self.max_depth)?;
        let depth = self.element_names.len();
        self.push_event(|| {
            Ok(StreamingXmlEvent::Start {
                element: streaming_element(element)?,
                depth,
            })
        })?;
        Ok(())
    }

    fn accept_end(
        &mut self,
        element: &BytesEnd<'_>,
        buffer: &[u8],
        parsed_len: usize,
    ) -> Result<bool, ProtocolError> {
        *self.trailing_text_brackets = 0;
        let depth = self.element_names.len();
        let Some(end) = closing_frame_end(
            element,
            self.element_names,
            buffer,
            *self.resume_offset,
            parsed_len,
        )?
        else {
            self.push_event(|| {
                Ok(StreamingXmlEvent::End {
                    name: element.name().as_ref().to_string(),
                    depth,
                })
            })?;
            return Ok(false);
        };
        self.push_event(|| {
            Ok(StreamingXmlEvent::End {
                name: element.name().as_ref().to_string(),
                depth,
            })
        })?;
        *self.complete = true;
        *self.frame_end = Some(end);
        Ok(true)
    }

    fn accept_empty(
        &mut self,
        element: &BytesStart<'_>,
        buffer: &[u8],
        parsed_len: usize,
    ) -> Result<bool, ProtocolError> {
        *self.trailing_text_brackets = 0;
        let depth = self.element_names.len().saturating_add(1);
        let Some(end) = empty_frame_end(
            element,
            *self.seen_start,
            self.element_names.len(),
            self.max_depth,
            buffer,
            *self.resume_offset,
            parsed_len,
        )?
        else {
            self.push_event(|| {
                Ok(StreamingXmlEvent::Empty {
                    element: streaming_element(element)?,
                    depth,
                })
            })?;
            return Ok(false);
        };
        self.push_event(|| {
            Ok(StreamingXmlEvent::Empty {
                element: streaming_element(element)?,
                depth,
            })
        })?;
        *self.seen_start = true;
        *self.complete = true;
        *self.frame_end = Some(end);
        Ok(true)
    }

    fn accept_text(&mut self, text: &BytesText<'_>) -> Result<(), ProtocolError> {
        validate_text(
            text,
            *self.seen_start,
            self.declaration_allowed,
            self.trailing_text_brackets,
        )?;
        if self.wants_text() {
            let depth = self.element_names.len();
            self.push_event(|| {
                Ok(StreamingXmlEvent::Text {
                    text: text.as_ref().to_string(),
                    depth,
                })
            })?;
        }
        Ok(())
    }

    fn accept_declaration(&mut self, declaration: &BytesDecl<'_>) -> Result<(), ProtocolError> {
        *self.trailing_text_brackets = 0;
        accept_declaration(declaration, *self.seen_start, self.declaration_allowed)
    }

    fn accept_comment(&mut self, comment: &str) -> Result<(), ProtocolError> {
        *self.trailing_text_brackets = 0;
        validate_misc(comment, *self.seen_start, self.declaration_allowed)
    }

    fn accept_processing_instruction(&mut self, instruction: &str) -> Result<(), ProtocolError> {
        *self.trailing_text_brackets = 0;
        validate_processing_instruction(instruction, *self.seen_start, self.declaration_allowed)
    }

    fn accept_reference(&mut self, reference: &BytesRef<'_>) -> Result<(), ProtocolError> {
        *self.trailing_text_brackets = 0;
        if !*self.seen_start {
            return Err(xml_parse_error("entity reference before root element"));
        }
        validate_reference(reference)?;
        if self.wants_text() {
            let depth = self.element_names.len();
            self.push_event(|| {
                Ok(StreamingXmlEvent::Reference {
                    reference: reference.as_ref().to_string(),
                    depth,
                })
            })?;
        }
        Ok(())
    }

    fn accept_cdata(&mut self, data: &str) -> Result<(), ProtocolError> {
        *self.trailing_text_brackets = 0;
        validate_cdata(data, *self.seen_start)?;
        if self.wants_text() {
            let depth = self.element_names.len();
            self.push_event(|| {
                Ok(StreamingXmlEvent::CData {
                    text: data.to_string(),
                    depth,
                })
            })?;
        }
        Ok(())
    }

    fn wants_text(&mut self) -> bool {
        self.events
            .as_mut()
            .is_some_and(|sink| (sink.wants_text)(self.element_names))
    }

    fn push_event(
        &mut self,
        create: impl FnOnce() -> Result<StreamingXmlEvent, ProtocolError>,
    ) -> Result<(), ProtocolError> {
        if let Some(sink) = &mut self.events {
            sink.events.push(create()?);
        }
        Ok(())
    }

    fn suspend_eof(&mut self, parsed_len: usize) {
        *self.resume_offset += parsed_len;
    }

    fn suspend_incomplete_token(
        &mut self,
        error: &XmlError,
        parsed_len: usize,
        buffer: &[u8],
    ) -> Result<(), ProtocolError> {
        let token_start = self.resume_offset.saturating_add(parsed_len);
        if is_partial_markup_opener(&buffer[token_start..]) {
            *self.resume_offset = token_start;
            return Ok(());
        }
        if matches!(error, XmlError::Syntax(SyntaxError::UnclosedDoctype)) {
            return Err(xml_parse_error("DOCTYPE declarations are not supported"));
        }
        if !is_incomplete_xml_error(error) {
            return Err(xml_parse_error(error));
        }

        *self.resume_offset += parsed_len;
        if let Some(mut token) = PendingToken::from_error(error, *self.resume_offset) {
            let ready = token.scan_until_ready(buffer);
            if ready {
                return Err(xml_parse_error(error));
            }
            *self.pending_token = Some(token);
        }
        Ok(())
    }
}

/// Streaming XML reader that detects when a complete XML root element has been received.
///
/// Feed data incrementally via [`XmlReader::feed`] and check [`XmlReader::is_complete`] to know when
/// a full GMP response has been received.
pub struct XmlReader {
    buffer: Vec<u8>,
    max_buffer_bytes: Option<usize>,
    max_depth: usize,
    complete: bool,
    seen_start: bool,
    declaration_allowed: bool,
    resume_offset: usize,
    frame_end: Option<usize>,
    element_names: Vec<String>,
    trailing_text_brackets: u8,
    pending_token: Option<PendingToken>,
    discarded_len: usize,
}

impl std::fmt::Debug for XmlReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XmlReader")
            .field("buffer_len", &self.buffer.len())
            .field("discarded_len", &self.discarded_len)
            .field("max_buffer_bytes", &self.max_buffer_bytes)
            .field("max_depth", &self.max_depth)
            .field("complete", &self.complete)
            .field("frame_end", &self.frame_end)
            .field("depth", &self.element_names.len())
            .field("pending_token", &self.pending_token.is_some())
            .finish()
    }
}

impl XmlReader {
    /// Create a new `XmlReader`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_buffer_limit(Some(DEFAULT_MAX_BUFFER_BYTES))
    }

    /// Create a new `XmlReader` with a custom maximum buffer size.
    #[must_use]
    pub fn with_max_buffer(max: usize) -> Self {
        Self::with_buffer_limit(Some(max))
    }

    /// Create a new `XmlReader` with an optional maximum buffer size.
    #[must_use]
    pub fn with_buffer_limit(max_buffer_bytes: Option<usize>) -> Self {
        Self::with_limits(max_buffer_bytes, DEFAULT_MAX_DEPTH)
    }

    /// Create a new `XmlReader` with custom buffer and nesting limits.
    #[must_use]
    pub fn with_limits(max_buffer_bytes: Option<usize>, max_depth: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer_bytes,
            max_depth,
            complete: false,
            seen_start: false,
            declaration_allowed: true,
            resume_offset: 0,
            frame_end: None,
            element_names: Vec::new(),
            trailing_text_brackets: 0,
            pending_token: None,
            discarded_len: 0,
        }
    }

    /// Feed data into the reader.
    ///
    /// # Errors
    /// Returns an error if the data contains fatally malformed XML.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        if let Some(max) = self.max_buffer_bytes {
            if self
                .discarded_len
                .saturating_add(self.buffer.len())
                .saturating_add(data.len())
                > max
            {
                return Err(ProtocolError::BufferOverflow { max });
            }
        }

        self.buffer.extend_from_slice(data);
        self.check_complete()
    }

    /// Feed only the bytes belonging to the current XML frame.
    ///
    /// The returned count is the number of bytes consumed from `data`. Once
    /// [`XmlReader::is_complete`] is true, any unconsumed suffix belongs to the
    /// next frame. This method applies the configured size limit to each frame
    /// independently and never copies an unbounded trailing frame into the
    /// current reader.
    ///
    /// # Errors
    /// Returns an error if the current frame is malformed, too deeply nested,
    /// or exceeds the configured buffer limit. Reset the reader before reuse
    /// after an error.
    pub fn feed_frame(&mut self, data: &[u8]) -> Result<usize, ProtocolError> {
        self.feed_frame_internal(data, None)
    }

    fn feed_frame_with_events(
        &mut self,
        data: &[u8],
        events: &mut Vec<StreamingXmlEvent>,
        wants_text: &mut dyn FnMut(&[String]) -> bool,
    ) -> Result<usize, ProtocolError> {
        self.feed_frame_internal(data, Some(EventSink { events, wants_text }))
    }

    fn feed_frame_internal(
        &mut self,
        data: &[u8],
        mut events: Option<EventSink<'_>>,
    ) -> Result<usize, ProtocolError> {
        if self.complete {
            return Ok(0);
        }

        // `take_frame` can leave an already-buffered tail from `feed`. Parse
        // that tail before consuming any new bytes so mixed API use cannot
        // discard a complete buffered frame.
        self.check_complete_with(events.as_mut().map(EventSink::reborrow))?;
        if self.complete {
            return Ok(0);
        }

        let previous_len = self.buffer.len();
        let accepted = match self.max_buffer_bytes {
            Some(max) => data
                .len()
                .min(max.saturating_sub(self.discarded_len.saturating_add(previous_len))),
            None => data.len(),
        };

        self.buffer.extend_from_slice(&data[..accepted]);
        self.check_complete_with(events)?;

        if let Some(frame_end) = self.frame_end {
            let consumed = frame_end.saturating_sub(previous_len);
            self.buffer.truncate(frame_end);
            return Ok(consumed);
        }

        if accepted < data.len()
            || self
                .max_buffer_bytes
                .is_some_and(|max| self.discarded_len.saturating_add(self.buffer.len()) >= max)
        {
            return Err(ProtocolError::BufferOverflow {
                max: self.max_buffer_bytes.unwrap_or_default(),
            });
        }

        Ok(accepted)
    }

    /// Check if a complete XML root element has been received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Return the length of the first complete XML frame.
    #[must_use]
    pub fn frame_len(&self) -> Option<usize> {
        self.frame_end
            .map(|frame_end| self.discarded_len.saturating_add(frame_end))
    }

    /// Return the first complete XML frame, if available.
    #[must_use]
    pub fn frame(&self) -> Option<&[u8]> {
        self.frame_end.map(|end| &self.buffer[..end])
    }

    /// Return bytes accumulated after the first complete XML frame.
    #[must_use]
    pub fn tail(&self) -> Option<&[u8]> {
        self.frame_end.map(|end| &self.buffer[end..])
    }

    /// Remove and return the first complete XML frame.
    ///
    /// Any trailing bytes remain buffered and are parsed on the next call.
    ///
    /// # Errors
    /// Returns an error if buffered trailing data is malformed when this method
    /// is called again to extract the next frame.
    pub fn take_frame(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        self.check_complete()?;
        let Some(frame_end) = self.frame_end else {
            return Ok(None);
        };

        let tail = self.buffer.split_off(frame_end);
        let frame = std::mem::replace(&mut self.buffer, tail);
        self.reset_state();
        Ok(Some(frame))
    }

    /// Return the accumulated data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume the reader and return the accumulated data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.buffer
    }

    /// Reset the reader for reuse.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.reset_state();
    }

    fn reset_state(&mut self) {
        self.complete = false;
        self.seen_start = false;
        self.declaration_allowed = true;
        self.resume_offset = 0;
        self.frame_end = None;
        self.element_names.clear();
        self.trailing_text_brackets = 0;
        self.pending_token = None;
        self.discarded_len = 0;
    }

    fn frame_progress<'state, 'sink>(
        &'state mut self,
        events: Option<EventSink<'sink>>,
    ) -> (&'state [u8], FrameProgress<'state, 'sink>) {
        let Self {
            buffer,
            max_depth,
            complete,
            seen_start,
            declaration_allowed,
            resume_offset,
            frame_end,
            element_names,
            trailing_text_brackets,
            pending_token,
            discarded_len,
            ..
        } = self;
        (
            buffer,
            FrameProgress {
                max_depth: *max_depth,
                complete,
                seen_start,
                declaration_allowed,
                resume_offset,
                frame_end,
                element_names,
                trailing_text_brackets,
                pending_token,
                discarded_len: *discarded_len,
                events,
            },
        )
    }

    fn check_complete(&mut self) -> Result<(), ProtocolError> {
        self.check_complete_with(None)
    }

    fn check_complete_with(&mut self, events: Option<EventSink<'_>>) -> Result<(), ProtocolError> {
        if self.complete {
            return Ok(());
        }

        if let Some(token) = &mut self.pending_token {
            if !token.scan_until_ready(&self.buffer) {
                return Ok(());
            }
            self.pending_token = None;
        }

        let (buffer, mut progress) = self.frame_progress(events);
        let unparsed = &buffer[*progress.resume_offset..];
        let bom_len = usize::from(
            progress.discarded_len == 0
                && *progress.resume_offset == 0
                && unparsed.starts_with(UTF8_BOM),
        ) * UTF8_BOM.len();
        let parseable_len = match std::str::from_utf8(unparsed) {
            Ok(_) => unparsed.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(error) => return Err(xml_parse_error(error)),
        };
        let mut reader = configured_reader(&unparsed[..parseable_len]);
        let (mut event_buf, mut parsed_len) = (Vec::new(), 0_usize);

        loop {
            match reader.read_event_into(&mut event_buf) {
                Ok(Event::Start(element)) => {
                    parsed_len = bom_len + reader.buffer_position() as usize;
                    progress.accept_start(&element)?;
                }
                Ok(Event::End(element)) => {
                    parsed_len = bom_len + reader.buffer_position() as usize;
                    if progress.accept_end(&element, buffer, parsed_len)? {
                        return Ok(());
                    }
                }
                Ok(Event::Empty(element)) => {
                    parsed_len = bom_len + reader.buffer_position() as usize;
                    if progress.accept_empty(&element, buffer, parsed_len)? {
                        return Ok(());
                    }
                }
                Ok(Event::Text(text)) => {
                    progress.accept_text(&text)?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::CData(data)) => {
                    progress.accept_cdata(data.as_ref())?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::DocType(_)) => {
                    return Err(xml_parse_error("DOCTYPE declarations are not supported"));
                }
                Ok(Event::Decl(declaration)) => {
                    progress.accept_declaration(&declaration)?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::Comment(comment)) => {
                    progress.accept_comment(comment.as_ref())?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::PI(instruction)) => {
                    progress.accept_processing_instruction(instruction.as_ref())?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::GeneralRef(reference)) => {
                    progress.accept_reference(&reference)?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::Eof) => {
                    progress.suspend_eof(parsed_len);
                    return Ok(());
                }
                Err(error) => {
                    return progress.suspend_incomplete_token(&error, parsed_len, buffer);
                }
            }

            event_buf.clear();
        }
    }

    fn discard_parsed_prefix(&mut self) {
        if self.complete || self.resume_offset == 0 {
            return;
        }

        let discarded = self.resume_offset;
        self.buffer.drain(..discarded);
        self.discarded_len = self.discarded_len.saturating_add(discarded);
        self.resume_offset = 0;
        if let Some(token) = &mut self.pending_token {
            match token {
                PendingToken::Tag { scan_offset, .. }
                | PendingToken::Sequence { scan_offset, .. } => {
                    *scan_offset = scan_offset.saturating_sub(discarded);
                }
            }
        }
    }
}

fn configured_reader(input: &[u8]) -> Reader<&[u8]> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = false;
    reader.config_mut().allow_unmatched_ends = true;
    reader.config_mut().check_comments = true;
    reader
}

fn validate_misc(
    data: &str,
    seen_start: bool,
    declaration_allowed: &mut bool,
) -> Result<(), ProtocolError> {
    validate_xml_chars(data)?;
    if !seen_start {
        *declaration_allowed = false;
    }
    Ok(())
}

fn validate_processing_instruction(
    data: &str,
    seen_start: bool,
    declaration_allowed: &mut bool,
) -> Result<(), ProtocolError> {
    validate_misc(data, seen_start, declaration_allowed)?;
    let target_end = data.find([' ', '\t', '\r', '\n']).unwrap_or(data.len());
    let target = &data[..target_end];
    validate_name(target)?;
    if target.eq_ignore_ascii_case("xml") {
        return Err(xml_parse_error(
            "processing instruction target 'xml' is reserved",
        ));
    }
    Ok(())
}

fn accept_declaration(
    declaration: &BytesDecl<'_>,
    seen_start: bool,
    declaration_allowed: &mut bool,
) -> Result<(), ProtocolError> {
    if seen_start || !*declaration_allowed {
        return Err(xml_parse_error(
            "XML declaration must be the first document event",
        ));
    }
    validate_declaration(declaration)?;
    *declaration_allowed = false;
    Ok(())
}

fn validate_cdata(data: &str, seen_start: bool) -> Result<(), ProtocolError> {
    if !seen_start {
        return Err(xml_parse_error("CDATA before root element"));
    }
    validate_xml_chars(data)
}

fn open_element(
    element: &BytesStart<'_>,
    seen_start: &mut bool,
    element_names: &mut Vec<String>,
    max_depth: usize,
) -> Result<(), ProtocolError> {
    validate_start(element)?;
    *seen_start = true;
    element_names.push(element.name().as_ref().to_string());
    if element_names.len() > max_depth {
        return Err(xml_parse_error(format!(
            "XML nesting exceeds configured limit of {max_depth}"
        )));
    }
    Ok(())
}

fn close_element(
    element: &BytesEnd<'_>,
    element_names: &mut Vec<String>,
) -> Result<bool, ProtocolError> {
    let Some(expected) = element_names.pop() else {
        return Err(xml_parse_error("unmatched closing tag"));
    };
    if expected != element.name().as_ref() {
        return Err(xml_parse_error("mismatched closing tag"));
    }
    Ok(element_names.is_empty())
}

fn closing_frame_end(
    element: &BytesEnd<'_>,
    element_names: &mut Vec<String>,
    buffer: &[u8],
    resume_offset: usize,
    parsed_len: usize,
) -> Result<Option<usize>, ProtocolError> {
    close_element(element, element_names)?
        .then(|| validated_frame_end(buffer, resume_offset, parsed_len))
        .transpose()
}

fn validate_empty_element(
    element: &BytesStart<'_>,
    current_depth: usize,
    max_depth: usize,
) -> Result<(), ProtocolError> {
    validate_start(element)?;
    if current_depth.saturating_add(1) > max_depth {
        return Err(xml_parse_error(format!(
            "XML nesting exceeds configured limit of {max_depth}"
        )));
    }
    Ok(())
}

fn empty_frame_end(
    element: &BytesStart<'_>,
    seen_start: bool,
    current_depth: usize,
    max_depth: usize,
    buffer: &[u8],
    resume_offset: usize,
    parsed_len: usize,
) -> Result<Option<usize>, ProtocolError> {
    validate_empty_element(element, current_depth, max_depth)?;
    (!seen_start)
        .then(|| validated_frame_end(buffer, resume_offset, parsed_len))
        .transpose()
}

fn validate_text(
    text: &BytesText<'_>,
    seen_start: bool,
    declaration_allowed: &mut bool,
    trailing_brackets: &mut u8,
) -> Result<(), ProtocolError> {
    let decoded = text.as_ref();

    validate_xml_chars(decoded)?;
    validate_character_data(decoded.as_bytes(), trailing_brackets)?;
    if !seen_start {
        if !decoded.chars().all(is_xml_whitespace) {
            return Err(xml_parse_error("non-whitespace text before root element"));
        }
        *declaration_allowed = false;
    }
    Ok(())
}

fn validate_start(element: &BytesStart<'_>) -> Result<(), ProtocolError> {
    validate_name(element.name().as_ref())?;
    validate_xml_chars(element.as_ref())?;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(xml_parse_error)?;
        validate_name(attribute.key.as_ref())?;
        if attribute.value.contains('<') {
            return Err(xml_parse_error(
                "attribute values cannot contain a literal '<'",
            ));
        }
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(xml_parse_error)?;
        validate_xml_chars(&value)?;
    }
    Ok(())
}

fn streaming_element(element: &BytesStart<'_>) -> Result<StreamingXmlElement, ProtocolError> {
    let attributes = element
        .attributes()
        .map(|attribute| {
            let attribute = attribute.map_err(xml_parse_error)?;
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(xml_parse_error)?;
            Ok((attribute.key.as_ref().to_string(), value.into_owned()))
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    Ok(StreamingXmlElement {
        name: element.name().as_ref().to_string(),
        attributes,
    })
}

fn validate_declaration(declaration: &BytesDecl<'_>) -> Result<(), ProtocolError> {
    validate_xml_chars(declaration.as_ref())?;
    let content = declaration.as_ref();
    let start = BytesStart::from_content(content, b"xml".len());
    let mut fields = 0_usize;
    let mut saw_encoding = false;

    for attribute in start.attributes() {
        let attribute = attribute.map_err(xml_parse_error)?;
        if attribute.value.contains('<') {
            return Err(xml_parse_error(
                "XML declaration values cannot contain a literal '<'",
            ));
        }

        match (fields, attribute.key.as_ref()) {
            (0, "version") if attribute.value.as_ref() == "1.0" => {}
            (0, "version") => {
                return Err(xml_parse_error("only XML version 1.0 is supported"));
            }
            (0, _) => {
                return Err(xml_parse_error(
                    "version must be the first XML declaration attribute",
                ));
            }
            (1, "encoding") if attribute.value.eq_ignore_ascii_case("utf-8") => {
                saw_encoding = true;
            }
            (1, "encoding") => {
                return Err(xml_parse_error("only UTF-8 XML declarations are supported"));
            }
            (1, "standalone") if matches!(attribute.value.as_ref(), "yes" | "no") => {}
            (2, "standalone")
                if saw_encoding && matches!(attribute.value.as_ref(), "yes" | "no") => {}
            (_, "standalone") => {
                return Err(xml_parse_error(
                    "standalone must follow version and optional encoding and be 'yes' or 'no'",
                ));
            }
            (_, "encoding") => {
                return Err(xml_parse_error(
                    "encoding must follow version and precede standalone",
                ));
            }
            (_, "version") => {
                return Err(xml_parse_error("version may appear only once"));
            }
            _ => return Err(xml_parse_error("unknown XML declaration attribute")),
        }
        fields += 1;
    }

    if fields == 0 {
        return Err(xml_parse_error("XML declaration version is required"));
    }
    Ok(())
}

fn validate_character_data(data: &[u8], trailing_brackets: &mut u8) -> Result<(), ProtocolError> {
    for byte in data {
        match *byte {
            b']' => *trailing_brackets = trailing_brackets.saturating_add(1).min(2),
            b'>' if *trailing_brackets == 2 => {
                return Err(xml_parse_error("character data cannot contain ']]>'"));
            }
            _ => *trailing_brackets = 0,
        }
    }
    Ok(())
}

fn validate_reference(reference: &BytesRef<'_>) -> Result<(), ProtocolError> {
    if let Some(character) = reference.resolve_char_ref().map_err(xml_parse_error)? {
        return validate_xml_chars(&character.to_string());
    }
    if resolve_xml_entity(reference.as_ref()).is_none() {
        return Err(xml_parse_error("unknown entity reference"));
    }
    Ok(())
}

fn validate_frame(frame: &[u8]) -> Result<(), ProtocolError> {
    validate_xml_bytes(frame)
}

fn validated_frame_end(
    buffer: &[u8],
    resume_offset: usize,
    parsed_len: usize,
) -> Result<usize, ProtocolError> {
    let frame_end = resume_offset + parsed_len;
    validate_frame(&buffer[..frame_end])?;
    Ok(frame_end)
}

fn validate_xml_bytes(data: &[u8]) -> Result<(), ProtocolError> {
    let decoded = std::str::from_utf8(data).map_err(xml_parse_error)?;
    validate_xml_chars(decoded)
}

fn validate_xml_chars(data: &str) -> Result<(), ProtocolError> {
    if data.chars().all(is_xml_char) {
        Ok(())
    } else {
        Err(xml_parse_error("character is not legal in XML 1.0"))
    }
}

fn validate_name(name: &str) -> Result<(), ProtocolError> {
    let mut characters = name.chars();
    if !characters.next().is_some_and(is_xml_name_start) || !characters.all(is_xml_name_character) {
        return Err(xml_parse_error("invalid XML name"));
    }
    Ok(())
}

fn is_xml_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn is_xml_char(character: char) -> bool {
    matches!(
        character,
        '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

fn is_xml_name_start(character: char) -> bool {
    matches!(
        character,
        ':' | 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}'
    )
}

fn is_xml_name_character(character: char) -> bool {
    is_xml_name_start(character)
        || matches!(
            character,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}'
        )
}

fn xml_parse_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::XmlParse(format!("Malformed XML: {error}"))
}

impl Default for XmlReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Incremental, bounded-memory XML frame validator for streamed GMP responses.
///
/// Unlike [`XmlReader`], this type discards fully parsed prefixes while a frame
/// is incomplete. It therefore preserves only the bytes needed to finish the
/// current XML token. The caller remains responsible for forwarding the exact
/// `data[..consumed]` bytes returned by [`Self::feed_frame`].
///
/// Total frame size and retained parsing-window limits are independent. This
/// lets callers stream very large documents while still bounding an unfinished
/// attribute, CDATA section, comment, or other single XML token.
pub struct StreamingXmlReader {
    reader: XmlReader,
    max_frame_bytes: Option<u64>,
    max_retained_bytes: usize,
    frame_bytes: u64,
}

impl std::fmt::Debug for StreamingXmlReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamingXmlReader")
            .field("buffered_len", &self.reader.buffer.len())
            .field("frame_len", &self.frame_len())
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("max_retained_bytes", &self.max_retained_bytes)
            .field("complete", &self.reader.is_complete())
            .finish()
    }
}

impl StreamingXmlReader {
    /// Create a streaming reader with the default frame-size and nesting limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(None, DEFAULT_MAX_BUFFER_BYTES, DEFAULT_MAX_DEPTH)
    }

    /// Create a streaming reader with independent total and retained limits.
    #[must_use]
    pub fn with_limits(
        max_frame_bytes: Option<u64>,
        max_retained_bytes: usize,
        max_depth: usize,
    ) -> Self {
        Self {
            reader: XmlReader::with_limits(None, max_depth),
            max_frame_bytes,
            max_retained_bytes,
            frame_bytes: 0,
        }
    }

    /// Validate bytes belonging to the current XML frame.
    ///
    /// The returned count is the exact prefix of `data` belonging to this
    /// frame. Once [`Self::is_complete`] is true, the unconsumed suffix belongs
    /// to a later frame and must not be yielded as part of the current response.
    ///
    /// # Errors
    /// Returns an error for malformed XML, excessive nesting, or an exceeded
    /// total-frame or retained-token limit.
    pub fn feed_frame(&mut self, data: &[u8]) -> Result<usize, ProtocolError> {
        let accepted = self.accepted_len(data);
        let consumed = self.reader.feed_frame(&data[..accepted])?;
        self.finish_feed(data.len(), accepted, consumed)?;
        Ok(consumed)
    }

    /// Validate bytes and return the ordered parsed events completed by them.
    ///
    /// Event storage is bounded by the input chunk and retained-token limits;
    /// already parsed response prefixes are not accumulated. This is the
    /// reusable decoder interface for streamed typed responses.
    ///
    /// # Errors
    /// Returns an error for malformed XML, excessive nesting, or an exceeded
    /// total-frame or retained-token limit.
    pub fn feed_frame_events(
        &mut self,
        data: &[u8],
    ) -> Result<(usize, Vec<StreamingXmlEvent>), ProtocolError> {
        self.feed_frame_events_with_text(data, |_| true)
    }

    /// Validate bytes and return parsed events, selecting character content by
    /// its current element path.
    ///
    /// Start, empty, and end events are always returned. Character content is
    /// fragmented across `Text`, `CData`, and `Reference` events, whose payloads
    /// are constructed only when `wants_text` returns true for the path
    /// containing that content. References are still validated on unselected
    /// paths. A `Reference` contains the spelling without `&` and `;` and is not
    /// expanded text. The predicate is evaluated during XML parsing, so it must
    /// base its answer on `element_path` rather than state updated later while
    /// consuming the returned event batch.
    ///
    /// # Errors
    /// Returns an error for malformed XML, excessive nesting, or an exceeded
    /// total-frame or retained-token limit.
    pub fn feed_frame_events_with_text(
        &mut self,
        data: &[u8],
        mut wants_text: impl FnMut(&[String]) -> bool,
    ) -> Result<(usize, Vec<StreamingXmlEvent>), ProtocolError> {
        let accepted = self.accepted_len(data);
        let mut events = Vec::new();
        let consumed =
            self.reader
                .feed_frame_with_events(&data[..accepted], &mut events, &mut wants_text)?;
        self.finish_feed(data.len(), accepted, consumed)?;
        Ok((consumed, events))
    }

    fn accepted_len(&self, data: &[u8]) -> usize {
        match self.max_frame_bytes {
            Some(max) => {
                let remaining = max.saturating_sub(self.frame_bytes);
                data.len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX))
            }
            None => data.len(),
        }
    }

    fn finish_feed(
        &mut self,
        input_len: usize,
        accepted: usize,
        consumed: usize,
    ) -> Result<(), ProtocolError> {
        self.frame_bytes += consumed as u64;
        if !self.reader.is_complete() {
            self.reader.discard_parsed_prefix();
            if self.reader.buffer.len() > self.max_retained_bytes {
                return Err(ProtocolError::StreamRetainedLimit {
                    max: self.max_retained_bytes,
                });
            }
            if accepted < input_len {
                return Err(ProtocolError::StreamSizeLimit {
                    max: self.max_frame_bytes.unwrap_or_default(),
                });
            }
            if self
                .max_frame_bytes
                .is_some_and(|max| self.frame_bytes >= max)
            {
                return Err(ProtocolError::StreamSizeLimit {
                    max: self.max_frame_bytes.unwrap_or_default(),
                });
            }
        }
        Ok(())
    }

    /// Return whether exactly one complete XML frame has been validated.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.reader.is_complete()
    }

    /// Return the total validated frame length after completion.
    #[must_use]
    pub fn frame_len(&self) -> Option<u64> {
        self.reader.is_complete().then_some(self.frame_bytes)
    }

    #[cfg(test)]
    fn buffered_len(&self) -> usize {
        self.reader.buffer.len()
    }

    /// Reset the validator for a new response frame.
    pub fn reset(&mut self) {
        self.reader.reset();
        self.frame_bytes = 0;
    }
}

impl Default for StreamingXmlReader {
    fn default() -> Self {
        Self::new()
    }
}

fn is_incomplete_xml_error(error: &XmlError) -> bool {
    matches!(
        error,
        XmlError::Syntax(
            SyntaxError::UnclosedPI
                | SyntaxError::UnclosedXmlDecl
                | SyntaxError::UnclosedComment
                | SyntaxError::UnclosedDoctype
                | SyntaxError::UnclosedCData
                | SyntaxError::UnclosedTag
                | SyntaxError::UnclosedSingleQuotedAttributeValue
                | SyntaxError::UnclosedDoubleQuotedAttributeValue
        ) | XmlError::IllFormed(
            IllFormedError::MissingEndTag(_) | IllFormedError::UnclosedReference
        )
    )
}

fn is_partial_markup_opener(input: &[u8]) -> bool {
    input.len() >= 2
        && [
            b"<!--".as_slice(),
            b"<![CDATA[".as_slice(),
            b"<!DOCTYPE".as_slice(),
        ]
        .iter()
        .any(|opener| input.len() < opener.len() && opener.starts_with(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_rejected_single_and_byte_chunks(xml: &[u8]) {
        let mut single = XmlReader::new();
        assert!(matches!(single.feed(xml), Err(ProtocolError::XmlParse(_))));

        let mut chunked = XmlReader::new();
        let mut error = None;
        for byte in xml {
            if let Err(found) = chunked.feed(&[*byte]) {
                error = Some(found);
                break;
            }
        }
        assert!(matches!(error, Some(ProtocolError::XmlParse(_))));
    }

    // XMLR-001
    #[test]
    fn test_self_closing_element() {
        let mut reader = XmlReader::new();
        reader
            .feed(br#"<get_version_response status="200"/>"#)
            .expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-002
    #[test]
    fn test_element_with_children() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"<get_tasks_response><task><name>t1</name></task></get_tasks_response>")
            .expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-003
    #[test]
    fn test_nested_same_name() {
        let mut reader = XmlReader::new();
        reader.feed(b"<a><a>inner</a></a>").expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-004
    #[test]
    fn test_chunked_delivery() {
        let mut reader = XmlReader::new();

        reader.feed(b"<get_tasks_re").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"sponse status=\"200\"").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"><task><name>").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"t1</name></task>").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"</get_tasks_response>").expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-009
    #[test]
    fn test_empty_root_element() {
        let mut reader = XmlReader::new();
        reader.feed(b"<response></response>").expect("feed ok");
        assert!(reader.is_complete());
    }

    #[test]
    fn test_reset() {
        let mut reader = XmlReader::new();
        reader.feed(b"<a/>").expect("feed ok");
        assert!(reader.is_complete());

        reader.reset();
        assert!(!reader.is_complete());
        assert!(reader.data().is_empty());
    }

    #[test]
    fn test_resume_offset_tracks_completed_events() {
        let mut reader = XmlReader::new();

        reader.feed(b"<root><child>").expect("feed ok");

        assert_eq!(reader.resume_offset, b"<root><child>".len());
        assert_eq!(reader.element_names.len(), 2);
        assert!(reader.seen_start);
        assert!(!reader.is_complete());

        reader.feed(b"value</child></root>").expect("feed ok");
        assert!(reader.is_complete());
    }

    #[test]
    fn test_buffer_overflow() {
        let mut reader = XmlReader::with_max_buffer(8);
        let error = reader.feed(b"<response/>").expect_err("buffer overflow");

        assert!(matches!(error, ProtocolError::BufferOverflow { max: 8 }));
    }

    #[test]
    fn test_malformed_xml_returns_parse_error_after_start() {
        let mut reader = XmlReader::new();
        let error = reader.feed(b"<root><!x></root>").expect_err("parse error");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_unmatched_end_tag_before_start_is_rejected() {
        let mut reader = XmlReader::new();

        let error = reader.feed(b"</garbage>").expect_err("parse error");
        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_non_whitespace_text_before_root_is_rejected() {
        let mut reader = XmlReader::new();

        let error = reader
            .feed(b"garbage<real_response/>")
            .expect_err("parse error");
        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_mismatched_closing_tag_is_rejected_across_chunks() {
        let mut reader = XmlReader::new();

        reader.feed(b"<root><child>").expect("incomplete XML");
        let error = reader.feed(b"</root></child>").expect_err("parse error");
        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_exact_frame_and_tail_are_preserved() {
        let mut reader = XmlReader::new();

        reader.feed(b"<one/><two/>").expect("feed ok");

        assert_eq!(reader.frame_len(), Some(b"<one/>".len()));
        assert_eq!(reader.frame(), Some(b"<one/>".as_slice()));
        assert_eq!(reader.tail(), Some(b"<two/>".as_slice()));
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<one/>".to_vec())
        );
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<two/>".to_vec())
        );
        assert_eq!(reader.take_frame().expect("valid XML"), None);
    }

    #[test]
    fn test_exact_boundary_after_resumed_parse() {
        let mut reader = XmlReader::new();

        reader.feed(b"<root><child>").expect("incomplete XML");
        reader
            .feed(b"value</child></root><next/>")
            .expect("feed ok");

        assert_eq!(
            reader.frame(),
            Some(b"<root><child>value</child></root>".as_slice())
        );
        assert_eq!(reader.tail(), Some(b"<next/>".as_slice()));
    }

    #[test]
    fn test_valid_prefix_is_part_of_frame() {
        let mut reader = XmlReader::new();
        let xml = b"<?xml version=\"1.0\"?> \n<!-- comment --><root/>";

        reader.feed(xml).expect("feed ok");

        assert_eq!(reader.frame(), Some(xml.as_slice()));
        assert_eq!(reader.tail(), Some(b"".as_slice()));
    }

    #[test]
    fn test_declaration_after_whitespace_is_rejected() {
        let mut reader = XmlReader::new();
        let error = reader
            .feed(b" \n<?xml version=\"1.0\"?><root/>")
            .expect_err("misplaced declaration");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_utf8_bom_is_preserved_in_exact_frame() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"\xEF\xBB\xBF<one/><two/>")
            .expect("BOM-prefixed XML");

        assert_eq!(reader.frame(), Some(b"\xEF\xBB\xBF<one/>".as_slice()));
        assert_eq!(reader.tail(), Some(b"<two/>".as_slice()));
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"\xEF\xBB\xBF<one/>".to_vec())
        );
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<two/>".to_vec())
        );
    }

    #[test]
    fn test_split_utf8_bom_is_chunk_safe() {
        let mut reader = XmlReader::new();
        for byte in b"\xEF\xBB\xBF<root/>" {
            reader.feed(&[*byte]).expect("BOM fragment");
        }

        assert_eq!(reader.frame(), Some(b"\xEF\xBB\xBF<root/>".as_slice()));
    }

    #[test]
    fn test_doctype_is_rejected() {
        let mut reader = XmlReader::new();
        let error = reader
            .feed(b"<!DOCTYPE root><root/>")
            .expect_err("doctype must be rejected");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_invalid_declaration_is_rejected() {
        let mut reader = XmlReader::new();
        let error = reader
            .feed(b"<?xml?><root/>")
            .expect_err("declaration version is required");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_declaration_grammar_is_strict_across_chunks() {
        for xml in [
            br#"<?xml version="1.0" bogus="x"?><root/>"#.as_slice(),
            br#"<?xml version="1.0" standalone="yes" encoding="UTF-8"?><root/>"#.as_slice(),
            br#"<?xml version="1.0" version="1.1"?><root/>"#.as_slice(),
            br#"<?xml version="1.1"?><root/>"#.as_slice(),
        ] {
            assert_rejected_single_and_byte_chunks(xml);
        }

        for xml in [
            br#"<?xml version="1.0"?><root/>"#.as_slice(),
            br#"<?xml version="1.0" encoding="UTF-8"?><root/>"#.as_slice(),
            br#"<?xml version="1.0" standalone="no"?><root/>"#.as_slice(),
            br#"<?xml version="1.0" encoding="utf-8" standalone="yes"?><root/>"#.as_slice(),
        ] {
            let mut reader = XmlReader::new();
            reader.feed(xml).expect("valid XML 1.0 declaration");
            assert!(reader.is_complete());
        }
    }

    #[test]
    fn test_forbidden_character_data_and_attribute_literals_are_rejected() {
        for xml in [
            b"<root>]]></root>".as_slice(),
            br#"<root a="x<y"/>"#.as_slice(),
        ] {
            assert_rejected_single_and_byte_chunks(xml);
        }
    }

    #[test]
    fn test_invalid_processing_instruction_targets_are_rejected() {
        for xml in [
            b"<?XML data?><root/>".as_slice(),
            b"<?1bad?><root/>".as_slice(),
            b"<?bad!name?><root/>".as_slice(),
        ] {
            let mut reader = XmlReader::new();
            let error = reader.feed(xml).expect_err("invalid PI target");
            assert!(matches!(error, ProtocolError::XmlParse(_)));
        }

        let mut valid = XmlReader::new();
        valid
            .feed(b"<?gmp instruction?><root/>")
            .expect("valid PI target");
        assert!(valid.is_complete());
    }

    #[test]
    fn test_invalid_names_and_references_are_rejected() {
        for xml in [
            b"<1bad/>".as_slice(),
            b"<bad!name/>".as_slice(),
            b"<root>&bogus;</root>".as_slice(),
            b"<root>&#0;</root>".as_slice(),
            b"<root value=\"&bogus;\"/>".as_slice(),
        ] {
            let mut reader = XmlReader::new();
            let error = reader.feed(xml).expect_err("malformed XML");
            assert!(matches!(error, ProtocolError::XmlParse(_)));
        }

        let mut valid = XmlReader::new();
        valid
            .feed(b"<root value=\"&amp;\">&lt;&#65;</root>")
            .expect("predefined and legal numeric references");
        assert!(valid.is_complete());
    }

    #[test]
    fn test_xml_illegal_characters_are_rejected() {
        for xml in [
            b"\x0B<root/>".as_slice(),
            "\u{A0}<root/>".as_bytes(),
            b"<root>\x0B</root>".as_slice(),
            b"<root><![CDATA[\x0B]]></root>".as_slice(),
        ] {
            let mut reader = XmlReader::new();
            let error = reader.feed(xml).expect_err("illegal XML character");
            assert!(matches!(error, ProtocolError::XmlParse(_)));
        }
    }

    #[test]
    fn test_incomplete_utf8_cannot_mask_invalid_prefix() {
        let data = [0, 0, 2, 2, 0, 0, 52, 0, 127, 223];
        let mut single = XmlReader::new();
        assert!(matches!(
            single.feed(&data),
            Err(ProtocolError::XmlParse(_))
        ));

        let mut chunked = XmlReader::new();
        let mut error = None;
        for byte in data {
            if let Err(found) = chunked.feed(&[byte]) {
                error = Some(found);
                break;
            }
        }
        assert!(matches!(error, Some(ProtocolError::XmlParse(_))));
    }

    #[test]
    fn test_debug_output_redacts_buffer_contents() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"<secret>do-not-log</secret>")
            .expect("valid XML");

        let debug = format!("{reader:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("do-not-log"));
        assert!(debug.contains("buffer_len"));
    }

    #[test]
    fn test_depth_limit_is_enforced() {
        let mut reader = XmlReader::with_limits(None, 2);
        let error = reader
            .feed(b"<one><two><three/></two></one>")
            .expect_err("depth must be bounded");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_feed_frame_consumes_only_first_frame() {
        let mut reader = XmlReader::with_max_buffer(6);
        let input = b"<one/><second-response/>";

        let consumed = reader.feed_frame(input).expect("first frame within limit");

        assert_eq!(consumed, b"<one/>".len());
        assert_eq!(reader.data(), b"<one/>");
        assert_eq!(&input[consumed..], b"<second-response/>");
    }

    #[test]
    fn test_feed_frame_does_not_discard_a_buffered_tail() {
        let mut reader = XmlReader::new();
        reader.feed(b"<one/><two/><three/>").expect("feed ok");
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<one/>".to_vec())
        );

        assert_eq!(reader.feed_frame(b"<four/>").expect("buffered frame"), 0);
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<two/>".to_vec())
        );
        assert_eq!(reader.feed_frame(b"<four/>").expect("buffered frame"), 0);
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<three/>".to_vec())
        );

        assert_eq!(reader.feed_frame(b"<four/>").expect("new frame"), 7);
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<four/>".to_vec())
        );
    }

    #[test]
    fn test_feed_frame_accepts_exact_limit_and_rejects_incomplete_limit() {
        let mut exact = XmlReader::with_max_buffer(6);
        assert_eq!(exact.feed_frame(b"<one/>").expect("exact limit"), 6);
        assert!(exact.is_complete());

        let mut incomplete = XmlReader::with_max_buffer(6);
        let error = incomplete
            .feed_frame(b"<root>")
            .expect_err("incomplete frame at limit");
        assert!(matches!(error, ProtocolError::BufferOverflow { max: 6 }));
    }

    #[test]
    fn test_incomplete_attribute_scanner_advances_only_over_new_bytes() {
        let mut reader = XmlReader::new();
        reader.feed(br#"<root value=""#).expect("incomplete tag");

        for _ in 0..1_024 {
            reader.feed(&[b'a'; 64]).expect("incomplete attribute");
            let scan_offset = match reader.pending_token.as_ref() {
                Some(PendingToken::Tag { scan_offset, .. }) => *scan_offset,
                token => panic!("expected pending tag, got {token:?}"),
            };
            assert_eq!(scan_offset, reader.buffer.len());
        }

        reader.feed(br#""/>"#).expect("completed tag");
        assert!(reader.is_complete());
        assert!(reader.pending_token.is_none());
    }

    fn pending_token_label(token: &PendingToken) -> &'static str {
        match token {
            PendingToken::Tag { .. } => "tag",
            PendingToken::Sequence { terminator, .. } => match terminator {
                TokenTerminator::ProcessingInstruction => "processing-instruction",
                TokenTerminator::Comment => "comment",
                TokenTerminator::CData => "cdata",
                TokenTerminator::Reference => "reference",
            },
        }
    }

    fn assert_all_split_boundaries(label: &str, document: &[u8]) {
        const NEXT_FRAMES: &[u8] = b"<next/><last/>";

        let mut input = document.to_vec();
        input.extend_from_slice(NEXT_FRAMES);

        let mut single_feed = XmlReader::new();
        single_feed.feed(&input).expect("single-buffer feed");
        let expected_frame = single_feed.frame().expect("single-buffer frame").to_vec();
        let expected_tail = single_feed.tail().expect("single-buffer tail").to_vec();
        assert_eq!(expected_frame, document, "{label}: single feed frame");
        assert_eq!(expected_tail, NEXT_FRAMES, "{label}: single feed tail");

        let mut single_frame = XmlReader::new();
        let expected_consumed = single_frame
            .feed_frame(&input)
            .expect("single-buffer feed_frame");
        assert_eq!(expected_consumed, document.len(), "{label}: consumed");
        assert_eq!(
            single_frame.frame(),
            Some(document),
            "{label}: feed_frame frame"
        );
        assert_eq!(
            &input[expected_consumed..],
            NEXT_FRAMES,
            "{label}: feed_frame external tail"
        );

        for split in 0..=input.len() {
            let mut feed = XmlReader::new();
            feed.feed(&input[..split])
                .unwrap_or_else(|error| panic!("{label}: feed prefix {split}: {error}"));
            feed.feed(&input[split..])
                .unwrap_or_else(|error| panic!("{label}: feed suffix {split}: {error}"));
            assert_eq!(
                feed.frame(),
                Some(expected_frame.as_slice()),
                "{label}: feed frame at split {split}"
            );
            assert_eq!(
                feed.tail(),
                Some(expected_tail.as_slice()),
                "{label}: feed tail at split {split}"
            );

            let mut framed = XmlReader::new();
            let first_consumed = framed
                .feed_frame(&input[..split])
                .unwrap_or_else(|error| panic!("{label}: feed_frame prefix {split}: {error}"));
            let total_consumed = if framed.is_complete() {
                first_consumed
            } else {
                assert_eq!(
                    first_consumed, split,
                    "{label}: incomplete prefix consumption at split {split}"
                );
                split
                    + framed.feed_frame(&input[split..]).unwrap_or_else(|error| {
                        panic!("{label}: feed_frame suffix {split}: {error}")
                    })
            };
            assert_eq!(
                total_consumed, expected_consumed,
                "{label}: total consumption at split {split}"
            );
            assert_eq!(
                framed.frame(),
                Some(expected_frame.as_slice()),
                "{label}: feed_frame frame at split {split}"
            );
            assert_eq!(
                &input[total_consumed..],
                expected_tail,
                "{label}: feed_frame external tail at split {split}"
            );
        }
    }

    #[test]
    fn test_partial_xml_tokens_match_single_buffer_at_every_byte_boundary() {
        for (label, document) in [
            (
                "declaration",
                br#"<?xml version="1.0" encoding="UTF-8"?><root/>"#.as_slice(),
            ),
            (
                "processing-instruction",
                b"<?gmp inspect?><root/>".as_slice(),
            ),
            ("comment", b"<!-- safe-comment --><root/>".as_slice()),
            (
                "cdata-fallback-overlap",
                b"<root><![CDATA[content]]]]></root>".as_slice(),
            ),
            (
                "entity-references",
                br#"<root attr="&quot;">&amp;&lt;</root>"#.as_slice(),
            ),
            (
                "numeric-references",
                b"<root>&#65;&#x1F642;</root>".as_slice(),
            ),
        ] {
            assert_all_split_boundaries(label, document);
        }
    }

    #[test]
    fn test_valid_split_inventory_reaches_every_pending_token_variant() {
        let documents = [
            br#"<?xml version="1.0"?><root/>"#.as_slice(),
            b"<?gmp inspect?><root/>".as_slice(),
            b"<!-- safe-comment --><root/>".as_slice(),
            b"<root><![CDATA[data]]></root>".as_slice(),
            b"<root>&amp;&#65;&#x41;</root>".as_slice(),
        ];
        let mut reached = std::collections::BTreeSet::new();

        for document in documents {
            for split in 0..document.len() {
                let mut reader = XmlReader::new();
                reader
                    .feed(&document[..split])
                    .unwrap_or_else(|error| panic!("valid prefix at {split}: {error}"));
                if let Some(token) = reader.pending_token.as_ref() {
                    reached.insert(pending_token_label(token));
                }
            }
        }

        assert_eq!(
            reached,
            std::collections::BTreeSet::from([
                "tag",
                "processing-instruction",
                "comment",
                "cdata",
                "reference",
            ])
        );
    }

    #[test]
    fn test_pending_sequence_scans_are_monotonic_and_cover_fallback_overlaps() {
        for (terminator, bytes, overlap_match) in [
            (TokenTerminator::ProcessingInstruction, b"??>".as_slice(), 1),
            (TokenTerminator::Comment, b"--->".as_slice(), 2),
            (TokenTerminator::CData, b"]]]>".as_slice(), 2),
            (TokenTerminator::Reference, b"x;".as_slice(), 0),
        ] {
            let mut token = PendingToken::Sequence {
                scan_offset: 0,
                terminator,
                matched: 0,
            };
            let mut buffer = Vec::new();
            let mut previous_scan = 0;

            for (index, byte) in bytes.iter().copied().enumerate() {
                buffer.push(byte);
                let ready = token.scan_until_ready(&buffer);
                let PendingToken::Sequence {
                    scan_offset,
                    matched,
                    ..
                } = token
                else {
                    unreachable!("constructed a sequence token");
                };
                assert_eq!(scan_offset, buffer.len());
                assert_eq!(scan_offset - previous_scan, 1);
                previous_scan = scan_offset;
                if index + 1 == bytes.len() {
                    assert!(ready, "{terminator:?} did not find its terminator");
                } else {
                    assert!(!ready, "{terminator:?} completed too early at {index}");
                    if index + 1 == bytes.len() - 1 {
                        assert_eq!(
                            matched, overlap_match,
                            "{terminator:?} fallback overlap state"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_bytewise_partial_token_recovery_cursor_is_monotonic() {
        for document in [
            br#"<?xml version="1.0"?><root/>"#.as_slice(),
            b"<?gmp inspect?><root/>".as_slice(),
            b"<!-- safe-comment --><root/>".as_slice(),
            b"<root><![CDATA[content]]]]></root>".as_slice(),
            b"<root>&amp;&#65;&#x41;</root>".as_slice(),
        ] {
            let mut reader = XmlReader::new();
            let mut previous_cursor = 0;

            for byte in document {
                reader.feed(&[*byte]).expect("valid bytewise document");
                let cursor = reader.frame_end.unwrap_or_else(|| {
                    reader.pending_token.as_ref().map_or(
                        reader.resume_offset,
                        |token| match token {
                            PendingToken::Tag { scan_offset, .. }
                            | PendingToken::Sequence { scan_offset, .. } => *scan_offset,
                        },
                    )
                });
                assert!(
                    cursor >= previous_cursor,
                    "resume/scan cursor regressed from {previous_cursor} to {cursor}"
                );
                assert!(cursor <= reader.buffer.len());
                assert!(
                    reader.buffer.len().saturating_sub(cursor) <= b"<![CDATA[".len(),
                    "recovery cursor lag exceeded the longest bounded markup opener"
                );
                previous_cursor = cursor;
            }

            assert!(reader.is_complete());
            assert!(previous_cursor <= document.len());
        }
    }

    #[test]
    fn test_unterminated_partial_tokens_fail_at_the_frame_size_limit() {
        for input in [
            br#"<?xml version="1.0""#.as_slice(),
            b"<?gmp inspect".as_slice(),
            b"<root><!-- comment".as_slice(),
            b"<root><![CDATA[data".as_slice(),
            b"<root>&amp".as_slice(),
            b"<root>&#65".as_slice(),
            b"<root>&#x41".as_slice(),
        ] {
            let mut feed = XmlReader::with_max_buffer(input.len());
            feed.feed(input)
                .expect("unterminated prefix at exact limit");
            assert!(!feed.is_complete());
            assert!(matches!(
                feed.feed(b"x"),
                Err(ProtocolError::BufferOverflow { max }) if max == input.len()
            ));

            let mut framed = XmlReader::with_max_buffer(input.len());
            assert!(matches!(
                framed.feed_frame(input),
                Err(ProtocolError::BufferOverflow { max }) if max == input.len()
            ));
        }
    }

    #[test]
    fn test_malformed_partial_token_families_remain_rejected_at_size_limit() {
        for input in [
            br#"<?xml version="1.1"?>"#.as_slice(),
            b"<?1bad?>".as_slice(),
            b"<!-- bad--comment -->".as_slice(),
            b"<![CDATA[data]]>".as_slice(),
            b"<root>&bogus;</root>".as_slice(),
            b"<root>&#0;</root>".as_slice(),
            b"<root>&#x0;</root>".as_slice(),
        ] {
            let mut feed = XmlReader::with_max_buffer(input.len());
            assert!(matches!(feed.feed(input), Err(ProtocolError::XmlParse(_))));

            let mut framed = XmlReader::with_max_buffer(input.len());
            assert!(matches!(
                framed.feed_frame(input),
                Err(ProtocolError::XmlParse(_))
            ));
        }
    }

    #[test]
    fn test_partial_markup_opener_suspension_does_not_accept_near_misses() {
        for input in [
            b"<!x><root/>".as_slice(),
            b"<![CDX[data]]><root/>".as_slice(),
            b"<!DOCX root><root/>".as_slice(),
        ] {
            assert_rejected_single_and_byte_chunks(input);
        }
    }

    #[test]
    fn test_incomplete_multibyte_text_across_chunks() {
        let mut reader = XmlReader::new();
        let xml = "<root>Grüße</root>".as_bytes();
        let split = xml.iter().position(|byte| *byte == 0xC3).expect("umlaut") + 1;

        reader.feed(&xml[..split]).expect("incomplete UTF-8");
        assert!(!reader.is_complete());
        reader.feed(&xml[split..]).expect("complete UTF-8");

        assert!(reader.is_complete());
    }

    #[test]
    fn streaming_reader_preserves_exact_frame_across_adversarial_chunks() {
        let response = b"<?xml version=\"1.0\"?><root><!--x--><same><same/>text&amp;<![CDATA[data]]></same></root>";
        let mut wire = response.to_vec();
        wire.extend_from_slice(b"<next/>");

        for chunk_size in 1..=response.len() + 3 {
            let mut reader =
                StreamingXmlReader::with_limits(Some(response.len() as u64), 1024, 256);
            let mut yielded = Vec::new();
            let mut offset = 0;
            while !reader.is_complete() {
                let end = (offset + chunk_size).min(wire.len());
                let consumed = reader
                    .feed_frame(&wire[offset..end])
                    .unwrap_or_else(|error| panic!("chunk size {chunk_size}: {error}"));
                yielded.extend_from_slice(&wire[offset..offset + consumed]);
                offset += consumed;
            }

            assert_eq!(yielded, response, "chunk size {chunk_size}");
            assert_eq!(reader.frame_len(), Some(response.len() as u64));
            assert_eq!(&wire[offset..], b"<next/>", "chunk size {chunk_size}");
        }
    }

    #[test]
    fn streaming_reader_discards_large_parsed_body_prefixes() {
        let body = "x".repeat(1024 * 1024);
        let response = format!("<root><data>{body}</data></root>");
        let mut reader = StreamingXmlReader::with_limits(Some(response.len() as u64), 1024, 256);
        let mut max_buffered = 0;

        for chunk in response.as_bytes().chunks(31) {
            assert_eq!(reader.feed_frame(chunk).expect("valid XML"), chunk.len());
            max_buffered = max_buffered.max(reader.buffered_len());
        }

        assert!(reader.is_complete());
        assert_eq!(reader.frame_len(), Some(response.len() as u64));
        assert!(
            max_buffered < 128,
            "retained {max_buffered} bytes while streaming a 1 MiB body"
        );
    }

    #[test]
    fn streaming_reader_constructs_character_content_only_for_selected_paths() {
        let response = b"<root><ignored>large &amp; body</ignored><metadata>small&amp;<![CDATA[value]]>&#65;</metadata></root>";
        let mut reader = StreamingXmlReader::new();
        let (_, events) = reader
            .feed_frame_events_with_text(
                response,
                |path| matches!(path, [root, metadata] if root == "root" && metadata == "metadata"),
            )
            .expect("valid XML");
        let content = events
            .iter()
            .filter_map(|event| match event {
                StreamingXmlEvent::Text { text, .. } | StreamingXmlEvent::CData { text, .. } => {
                    Some(text.clone())
                }
                StreamingXmlEvent::Reference { reference, .. } => Some(format!("&{reference};")),
                _ => None,
            })
            .collect::<String>();

        assert_eq!(content, "small&amp;value&#65;");
        assert_eq!(
            events
                .iter()
                .filter_map(|event| match event {
                    StreamingXmlEvent::Reference { reference, .. } => Some(reference.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ["amp", "#65"]
        );
        assert!(events.iter().all(|event| {
            !matches!(event, StreamingXmlEvent::Text { text, .. } if text.contains("large"))
        }));

        let mut default_reader = StreamingXmlReader::new();
        let (_, events) = default_reader
            .feed_frame_events_with_text(response, |_| false)
            .expect("valid XML");
        assert!(events.iter().all(|event| !matches!(
            event,
            StreamingXmlEvent::Text { .. }
                | StreamingXmlEvent::CData { .. }
                | StreamingXmlEvent::Reference { .. }
        )));
    }

    #[test]
    fn streaming_reader_validates_references_on_unselected_paths() {
        let mut reader = StreamingXmlReader::new();
        let error = reader
            .feed_frame_events_with_text(b"<root><ignored>&bogus;</ignored></root>", |_| false)
            .expect_err("unknown reference must remain invalid when text is unselected");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn streaming_text_events_are_fragments_across_feed_boundaries() {
        let chunks: [&[u8]; 4] = [
            b"<root><value>o",
            b"n",
            b"e<![CDATA[two]]>thr",
            b"ee</value></root>",
        ];
        let mut reader = StreamingXmlReader::new();
        let mut fragments = Vec::new();

        for chunk in chunks {
            let (_, events) = reader
                .feed_frame_events_with_text(
                    chunk,
                    |path| matches!(path, [root, value] if root == "root" && value == "value"),
                )
                .expect("valid XML fragment");
            fragments.extend(events.into_iter().filter_map(|event| match event {
                StreamingXmlEvent::Text { text, .. } | StreamingXmlEvent::CData { text, .. } => {
                    Some(text)
                }
                _ => None,
            }));
        }

        assert!(reader.is_complete());
        assert_eq!(fragments.concat(), "onetwothree");
        assert!(fragments.len() >= 5, "observed fragments: {fragments:?}");
    }

    #[test]
    fn streaming_reader_enforces_total_limit_after_discarding_prefixes() {
        let response = format!("<root>{}</root>", "x".repeat(4096));
        let mut reader =
            StreamingXmlReader::with_limits(Some((response.len() - 1) as u64), 1024, 256);
        let mut error = None;

        for chunk in response.as_bytes().chunks(23) {
            if let Err(found) = reader.feed_frame(chunk) {
                error = Some(found);
                break;
            }
        }

        assert!(matches!(
            error,
            Some(ProtocolError::StreamSizeLimit { max }) if max == (response.len() - 1) as u64
        ));
    }

    #[test]
    fn streaming_reader_rejects_malformed_suffix_after_discarding_body() {
        let mut reader = StreamingXmlReader::new();
        reader
            .feed_frame(b"<root><data>valid text</data>")
            .expect("valid prefix");
        let error = reader
            .feed_frame(b"</wrong>")
            .expect_err("mismatched close must fail");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }
}
