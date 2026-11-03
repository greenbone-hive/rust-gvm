// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Capability-gated streamed GMP response lifecycle.

use std::io;
use std::sync::Arc;

use gvm_connection::GvmStreamingConnection;
use gvm_gmp::GmpStreamDecoder;
use gvm_protocol::StreamingXmlReader;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{GvmError, WireTrace, WireTraceDirection, WireTraceEvent};

const STREAMED_TRACE_MARKER: &[u8] = b"[streamed GMP response omitted]";

/// Successful completion of one streamed GMP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmpStreamCompletion<M> {
    /// Exact number of response bytes observed and yielded for this XML frame.
    pub bytes_received: usize,
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

/// Exclusive, backpressured stream of exact bytes for one GMP XML response.
///
/// The stream borrows the active connection mutably, so no other request can
/// use it until this value is consumed or dropped. [`Self::next_chunk`] performs
/// at most one bounded transport read and does not read ahead in a background
/// task; caller demand therefore supplies backpressure.
///
/// Call [`Self::finish`] for explicit success and typed completion metadata.
/// `finish` also acts as the explicit drain-and-validate path if the caller no
/// longer needs the remaining bytes. Dropping before a complete valid response,
/// cancelling while dropping the stream, or encountering transport, framing,
/// or decoder failure invalidates the connection. A fully validated response
/// preserves any already-read bytes for the next frame and leaves the connection
/// reusable.
///
/// Opt-in wire tracing never receives raw streamed response bytes. On success it
/// receives a fixed omission marker so large or secret response bodies are not
/// buffered or logged.
#[must_use = "dropping an incomplete GMP response stream invalidates the connection"]
pub struct GmpResponseStream<'a, C, D>
where
    C: GvmStreamingConnection,
    D: GmpStreamDecoder,
{
    connection: &'a mut C,
    decoder: Option<D>,
    framer: StreamingXmlReader,
    deadline: tokio::time::Instant,
    bytes_received: usize,
    completion: Option<GmpStreamCompletion<D::Completion>>,
    validated: bool,
    failed: bool,
    wire_trace: Option<Arc<dyn WireTrace>>,
}

impl<C, D> std::fmt::Debug for GmpResponseStream<'_, C, D>
where
    C: GvmStreamingConnection,
    D: GmpStreamDecoder,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GmpResponseStream")
            .field("bytes_received", &self.bytes_received)
            .field("complete", &self.validated)
            .field("failed", &self.failed)
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
    ) -> Self {
        let framer = StreamingXmlReader::with_buffer_limit(connection.max_response_bytes());
        let deadline = tokio::time::Instant::now() + connection.response_timeout();
        Self {
            connection,
            decoder: Some(decoder),
            framer,
            deadline,
            bytes_received: 0,
            completion: None,
            validated: false,
            failed: false,
            wire_trace,
        }
    }

    /// Read and validate the next exact response-byte chunk.
    ///
    /// `Ok(None)` means the full XML response and response-specific completion
    /// metadata are valid. Call [`Self::finish`] to retrieve the byte count and
    /// metadata. The returned chunk size is bounded by the transport's read
    /// configuration, and another transport read does not occur until this
    /// method is awaited again.
    ///
    /// # Errors
    /// Returns a transport, framing, or incremental response-decoding error and
    /// invalidates the connection.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, GvmError> {
        if self.completion.is_some() {
            return Ok(None);
        }
        if self.failed {
            return Err(GvmError::InvalidState(
                "streamed response has already failed".to_string(),
            ));
        }

        let mut bytes = match self.connection.read_stream_chunk(self.deadline).await {
            Ok(bytes) if !bytes.is_empty() => bytes,
            Ok(_) => {
                self.invalidate();
                return Err(GvmError::InvalidState(
                    "streaming transport returned an empty response chunk".to_string(),
                ));
            }
            Err(error) => {
                self.failed = true;
                return Err(error.into());
            }
        };

        let consumed = match self.framer.feed_frame(&bytes) {
            Ok(consumed) => consumed,
            Err(error) => {
                self.invalidate();
                return Err(GvmError::Protocol(error));
            }
        };
        let tail = bytes.split_off(consumed);
        if let Some(decoder) = self.decoder.as_mut() {
            if let Err(error) = decoder.feed(&bytes) {
                self.invalidate();
                return Err(error.into());
            }
        }
        self.bytes_received = match self.bytes_received.checked_add(bytes.len()) {
            Some(total) => total,
            None => {
                self.invalidate();
                return Err(GvmError::InvalidState(
                    "streamed response byte count overflowed usize".to_string(),
                ));
            }
        };

        if self.framer.is_complete() {
            self.connection.retain_stream_tail(tail);
            let decoder = self.decoder.take().ok_or_else(|| {
                GvmError::InvalidState("streaming decoder is unavailable".to_string())
            })?;
            match decoder.finish() {
                Ok(metadata) => {
                    self.validated = true;
                    self.completion = Some(GmpStreamCompletion {
                        bytes_received: self.bytes_received,
                        metadata,
                    });
                    if let Some(wire_trace) = &self.wire_trace {
                        wire_trace.trace(WireTraceEvent {
                            direction: WireTraceDirection::Response,
                            bytes: STREAMED_TRACE_MARKER.to_vec(),
                        });
                    }
                }
                Err(error) => {
                    self.invalidate();
                    return Err(error.into());
                }
            }
        } else {
            debug_assert!(tail.is_empty());
        }

        Ok(Some(bytes))
    }

    /// Drain and validate the response, returning explicit completion details.
    ///
    /// When called after manually consuming all chunks this returns immediately.
    /// When called early it intentionally reads and validates the remainder
    /// without yielding it, providing the only connection-preserving early-stop
    /// path.
    ///
    /// # Errors
    /// Returns a transport, framing, or response-specific decoding error. The
    /// connection is invalidated on every error.
    pub async fn finish(mut self) -> Result<GmpStreamCompletion<D::Completion>, GvmError> {
        while self.next_chunk().await?.is_some() {}
        self.completion.take().ok_or_else(|| {
            GvmError::InvalidState("stream completed without completion metadata".to_string())
        })
    }

    /// Copy exact response bytes into an async sink and return completion details.
    ///
    /// This adapter does not flush or shut down the sink. A sink write error is
    /// reported separately and invalidates the connection, even when the final
    /// XML bytes had already arrived, so callers get deterministic retry rules.
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
        self.completion.take().ok_or_else(|| {
            GmpStreamCopyError::Stream(GvmError::InvalidState(
                "stream completed without completion metadata".to_string(),
            ))
        })
    }

    fn invalidate(&mut self) {
        self.connection.invalidate_stream();
        self.failed = true;
        self.validated = false;
        self.completion = None;
        self.decoder = None;
    }
}

impl<C, D> Drop for GmpResponseStream<'_, C, D>
where
    C: GvmStreamingConnection,
    D: GmpStreamDecoder,
{
    fn drop(&mut self) {
        if !self.validated || self.failed {
            self.connection.invalidate_stream();
        }
    }
}
