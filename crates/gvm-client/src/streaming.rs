// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Capability-gated streamed GMP response lifecycle.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use gvm_connection::{ConnectionError, GvmStreamingConnection};
use gvm_gmp::responses::ParseError;
use gvm_gmp::GmpStreamDecoder;
use gvm_protocol::{ProtocolError, StreamingXmlElement, StreamingXmlEvent, StreamingXmlReader};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{GvmError, WireTrace, WireTraceDirection, WireTraceEvent};

const STREAMED_TRACE_MARKER: &[u8] = b"[streamed GMP response omitted]";
const DEFAULT_MAX_RETAINED_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_DEPTH: usize = 256;

/// Per-operation policy for one streamed GMP response.
///
/// These limits are independent of the connection's buffered-response memory
/// ceiling. The default permits an unbounded total stream, retains at most
/// 4 MiB for one unfinished XML token, uses the connection timeout as a
/// per-read idle timeout, and has no total deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamOptions {
    /// Optional maximum total response-frame size.
    pub max_bytes: Option<u64>,
    /// Maximum bytes retained for the pre-root prefix or an incomplete token.
    pub max_retained_bytes: usize,
    /// Optional per-read idle timeout override.
    pub idle_timeout: Option<Duration>,
    /// Optional deadline for the complete stream, including caller pauses.
    pub total_timeout: Option<Duration>,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            max_bytes: None,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            idle_timeout: None,
            total_timeout: None,
        }
    }
}

/// Successful completion of one streamed GMP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmpStreamCompletion<M> {
    /// Exact number of response bytes observed and yielded for this XML frame.
    pub bytes_received: u64,
    /// Small response-specific metadata produced by the incremental decoder.
    pub metadata: M,
}

/// Failure while copying a streamed GMP response into an [`AsyncWrite`] sink.
#[derive(Debug, thiserror::Error)]
pub enum GmpStreamCopyError {
    /// Request, transport, framing, or response-specific decoding failed.
    #[error(transparent)]
    Stream(#[from] GvmError),
    /// Writing an exact response chunk to the caller's sink failed.
    #[error("stream sink write failed: {0}")]
    Sink(#[source] io::Error),
}

enum StreamState<D>
where
    D: GmpStreamDecoder,
{
    Streaming(D),
    Complete(GmpStreamCompletion<D::Completion>),
    Failed,
}

/// Exclusive, backpressured stream of exact bytes for one GMP XML response.
///
/// The stream borrows the active connection mutably, so no other request can
/// use it until this value is consumed or dropped. [`Self::next_chunk`] does
/// not read ahead in a background task; caller demand therefore supplies
/// backpressure. Before the first yield it may perform multiple bounded reads
/// to obtain and validate the complete root start tag. This ensures a non-2xx
/// GMP response is rejected before any error body reaches the caller's sink.
///
/// Cancelling a `next_chunk` future while retaining the stream is safe because
/// built-in transport reads are cancel-safe and framing state changes only
/// after a read completes. Dropping the incomplete stream remains fail-closed.
#[must_use = "dropping an incomplete GMP response stream invalidates the connection"]
pub struct GmpResponseStream<'a, C, D>
where
    C: GvmStreamingConnection,
    D: GmpStreamDecoder,
{
    connection: &'a mut C,
    state: StreamState<D>,
    framer: StreamingXmlReader,
    idle_timeout: Duration,
    total_deadline: Option<tokio::time::Instant>,
    bytes_received: u64,
    held_prefix: Vec<u8>,
    max_retained_bytes: usize,
    root_validated: bool,
    wire_trace: Option<Arc<dyn WireTrace>>,
}

impl<C, D> std::fmt::Debug for GmpResponseStream<'_, C, D>
where
    C: GvmStreamingConnection,
    D: GmpStreamDecoder,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self.state {
            StreamState::Streaming(_) => "streaming",
            StreamState::Complete(_) => "complete",
            StreamState::Failed => "failed",
        };
        formatter
            .debug_struct("GmpResponseStream")
            .field("bytes_received", &self.bytes_received)
            .field("state", &state)
            .field("root_validated", &self.root_validated)
            .field("wire_trace_enabled", &self.wire_trace.is_some())
            .finish()
    }
}

impl<'a, C, D> GmpResponseStream<'a, C, D>
where
    C: GvmStreamingConnection,
    D: GmpStreamDecoder,
{
    pub(crate) fn new(
        connection: &'a mut C,
        decoder: D,
        wire_trace: Option<Arc<dyn WireTrace>>,
        options: StreamOptions,
    ) -> Self {
        let idle_timeout = options
            .idle_timeout
            .unwrap_or_else(|| connection.response_timeout());
        let now = tokio::time::Instant::now();
        let total_deadline = options.total_timeout.map(|timeout| {
            now.checked_add(timeout)
                .unwrap_or_else(|| now + Duration::from_secs(u32::MAX.into()))
        });
        Self {
            connection,
            state: StreamState::Streaming(decoder),
            framer: StreamingXmlReader::with_limits(
                options.max_bytes,
                options.max_retained_bytes,
                DEFAULT_MAX_DEPTH,
            ),
            idle_timeout,
            total_deadline,
            bytes_received: 0,
            held_prefix: Vec::new(),
            max_retained_bytes: options.max_retained_bytes,
            root_validated: false,
            wire_trace,
        }
    }

    /// Read and validate the next exact response-byte chunk.
    ///
    /// `Ok(None)` means the full XML response and response-specific completion
    /// metadata are valid. Call [`Self::finish`] to retrieve them. Returned
    /// chunks are bounded by the transport read configuration except that the
    /// first chunk may combine several reads needed to validate the root tag;
    /// that prefix is bounded by `StreamOptions::max_retained_bytes`.
    ///
    /// # Errors
    /// Returns a transport, framing, root-status, or incremental decoding error
    /// and invalidates the connection.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, GvmError> {
        match self.state {
            StreamState::Complete(_) => return Ok(None),
            StreamState::Failed => {
                return Err(ConnectionError::NotConnected.into());
            }
            StreamState::Streaming(_) => {}
        }

        loop {
            let bytes = self.read_transport_chunk().await?;
            if let Some(output) = self.accept_chunk(&bytes)? {
                return Ok(Some(output));
            }
        }
    }

    /// Drain and validate the response, returning explicit completion details.
    ///
    /// # Errors
    /// Returns a transport, framing, status, or response-decoding error. The
    /// connection is invalidated on every error.
    pub async fn finish(mut self) -> Result<GmpStreamCompletion<D::Completion>, GvmError> {
        while self.next_chunk().await?.is_some() {}
        self.take_completion()
    }

    /// Copy exact response bytes into an async sink and return completion details.
    ///
    /// A non-success root status is rejected before the first sink write. This
    /// adapter does not flush or shut down the sink; durable callers should use
    /// a temporary file, then flush, sync, and atomically rename after success.
    ///
    /// # Errors
    /// Returns [`GmpStreamCopyError::Stream`] for response lifecycle failures or
    /// [`GmpStreamCopyError::Sink`] when `write_all` fails.
    pub async fn copy_to<W>(
        mut self,
        sink: &mut W,
    ) -> Result<GmpStreamCompletion<D::Completion>, GmpStreamCopyError>
    where
        W: AsyncWrite + Unpin,
    {
        while let Some(chunk) = self.next_chunk().await? {
            if let Err(error) = sink.write_all(&chunk).await {
                self.invalidate();
                return Err(GmpStreamCopyError::Sink(error));
            }
        }
        self.take_completion().map_err(GmpStreamCopyError::Stream)
    }

    async fn read_transport_chunk(&mut self) -> Result<Vec<u8>, GvmError> {
        let started = tokio::time::Instant::now();
        if self
            .total_deadline
            .is_some_and(|deadline| deadline <= started)
        {
            self.invalidate();
            return Err(ConnectionError::Timeout(Duration::ZERO).into());
        }
        let idle_deadline = started
            .checked_add(self.idle_timeout)
            .unwrap_or_else(|| started + Duration::from_secs(u32::MAX.into()));
        let deadline = self
            .total_deadline
            .map_or(idle_deadline, |total| total.min(idle_deadline));
        let waited = deadline.saturating_duration_since(started);
        match tokio::time::timeout_at(deadline, self.connection.read_stream_chunk()).await {
            Ok(Ok(bytes)) if !bytes.is_empty() => Ok(bytes),
            Ok(Ok(_)) => {
                debug_assert!(false, "streaming transport returned an empty chunk");
                self.invalidate();
                Err(ConnectionError::ReadFailed(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "streaming transport returned an empty response chunk",
                ))
                .into())
            }
            Ok(Err(error)) => {
                self.state = StreamState::Failed;
                Err(error.into())
            }
            Err(_) => {
                self.invalidate();
                Err(ConnectionError::Timeout(waited).into())
            }
        }
    }

    fn accept_chunk(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, GvmError> {
        let (consumed, events) = self.framer.feed_frame_events(bytes).map_err(|error| {
            self.invalidate();
            GvmError::Protocol(error)
        })?;
        let (frame, tail) = bytes.split_at(consumed);
        self.hold_pre_root_prefix(frame)?;
        self.feed_events(&events)?;
        self.bytes_received += consumed as u64;

        if self.framer.is_complete() {
            self.complete(tail)?;
        } else {
            debug_assert!(tail.is_empty());
        }

        Ok(self.root_validated.then(|| {
            if self.held_prefix.is_empty() {
                frame.to_vec()
            } else {
                std::mem::take(&mut self.held_prefix)
            }
        }))
    }

    fn hold_pre_root_prefix(&mut self, frame: &[u8]) -> Result<(), GvmError> {
        if self.root_validated {
            return Ok(());
        }
        self.held_prefix.extend_from_slice(frame);
        if self.held_prefix.len() <= self.max_retained_bytes {
            return Ok(());
        }
        let error = ProtocolError::StreamRetainedLimit {
            max: self.max_retained_bytes,
        };
        self.invalidate();
        Err(GvmError::Protocol(error))
    }

    fn feed_events(&mut self, events: &[StreamingXmlEvent]) -> Result<(), GvmError> {
        for event in events {
            if !self.root_validated {
                if let Some(root) = root_element(event) {
                    validate_root_status(root).inspect_err(|_| self.invalidate())?;
                    self.root_validated = true;
                }
            }
            let StreamState::Streaming(decoder) = &mut self.state else {
                return Err(ConnectionError::NotConnected.into());
            };
            decoder.feed(event).map_err(|error| {
                self.invalidate();
                GvmError::from(error)
            })?;
        }
        Ok(())
    }

    fn complete(&mut self, tail: &[u8]) -> Result<(), GvmError> {
        self.connection.retain_stream_tail(tail.to_vec());
        let state = std::mem::replace(&mut self.state, StreamState::Failed);
        let StreamState::Streaming(decoder) = state else {
            return Err(ConnectionError::NotConnected.into());
        };
        let metadata = decoder.finish().map_err(|error| {
            self.invalidate();
            GvmError::from(error)
        })?;
        self.state = StreamState::Complete(GmpStreamCompletion {
            bytes_received: self.bytes_received,
            metadata,
        });
        if let Some(wire_trace) = &self.wire_trace {
            wire_trace.trace(WireTraceEvent {
                direction: WireTraceDirection::Response,
                bytes: STREAMED_TRACE_MARKER.to_vec(),
            });
        }
        Ok(())
    }

    fn take_completion(&mut self) -> Result<GmpStreamCompletion<D::Completion>, GvmError> {
        let state = std::mem::replace(&mut self.state, StreamState::Failed);
        match state {
            StreamState::Complete(completion) => Ok(completion),
            StreamState::Streaming(decoder) => {
                self.state = StreamState::Streaming(decoder);
                Err(ConnectionError::NotConnected.into())
            }
            StreamState::Failed => Err(ConnectionError::NotConnected.into()),
        }
    }

    fn invalidate(&mut self) {
        self.connection.invalidate_stream();
        self.state = StreamState::Failed;
        self.held_prefix.clear();
    }
}

impl<C, D> Drop for GmpResponseStream<'_, C, D>
where
    C: GvmStreamingConnection,
    D: GmpStreamDecoder,
{
    fn drop(&mut self) {
        if matches!(self.state, StreamState::Streaming(_)) {
            self.connection.invalidate_stream();
        }
    }
}

fn root_element(event: &StreamingXmlEvent) -> Option<&StreamingXmlElement> {
    match event {
        StreamingXmlEvent::Start { element, depth: 1 }
        | StreamingXmlEvent::Empty { element, depth: 1 } => Some(element),
        _ => None,
    }
}

fn validate_root_status(root: &StreamingXmlElement) -> Result<(), GvmError> {
    let value = root
        .attribute("status")
        .ok_or_else(|| ParseError::MissingElement("status".to_string()))?;
    let status = value.parse::<u16>().map_err(|_| ParseError::InvalidValue {
        field: "status".to_string(),
        value: value.to_string(),
    })?;
    if (200..300).contains(&status) {
        return Ok(());
    }
    Err(GvmError::Server {
        status,
        message: root
            .attribute("status_text")
            .unwrap_or("Unknown error")
            .to_string(),
    })
}
