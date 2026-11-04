// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::unwrap_used, missing_docs)]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use gvm_client::{
    GmpClient, GmpStreamCopyError, GvmError, StreamOptions, StreamingXmlEvent, WireTraceEvent,
};
use gvm_connection::{ConnectionError, GvmConnection, GvmStreamingConnection};
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::responses::ParseError;
use gvm_gmp::{
    GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpResponse, GmpStreamDecoder,
    GmpStreamingResponse, GmpVersion,
};
use gvm_protocol::Response;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const VERSION_RESPONSE: &[u8] = br#"<get_version_response status="200" status_text="OK"><version>22.8</version></get_version_response>"#;

#[derive(Debug)]
struct TestStreamingRequest;

impl GmpRequestCodec for TestStreamingRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("test_stream"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(b"<test_stream/>".to_vec())
    }
}

impl GmpRequest for TestStreamingRequest {
    type Response = TestStreamingResponse;
}

#[derive(Debug)]
struct TestStreamingResponse;

impl GmpResponse for TestStreamingResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        status(response.data())?;
        Ok(Self)
    }
}

impl GmpStreamingResponse for TestStreamingResponse {
    type Decoder = TestDecoder;

    fn stream_decoder(_version: GmpVersion) -> Self::Decoder {
        TestDecoder::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestMetadata {
    status: u16,
    events: usize,
}

#[derive(Debug, Default)]
struct TestDecoder {
    status: Option<u16>,
    events: usize,
}

impl GmpStreamDecoder for TestDecoder {
    type Completion = TestMetadata;

    fn feed(&mut self, event: &StreamingXmlEvent) -> Result<(), ParseError> {
        self.events += 1;
        if matches!(event, StreamingXmlEvent::Text { text, .. } if text.contains("decoder-error")) {
            return Err(ParseError::InvalidValue {
                field: "stream".to_string(),
                value: "decoder-error".to_string(),
            });
        }
        if let StreamingXmlEvent::Start { element, depth: 1 }
        | StreamingXmlEvent::Empty { element, depth: 1 } = event
        {
            self.status = element
                .attribute("status")
                .and_then(|value| value.parse().ok());
        }
        Ok(())
    }

    fn finish(self) -> Result<Self::Completion, ParseError> {
        let status = self
            .status
            .ok_or_else(|| ParseError::MissingElement("status".to_string()))?;
        Ok(TestMetadata {
            status,
            events: self.events,
        })
    }
}

fn status(bytes: &[u8]) -> Result<u16, ParseError> {
    let text = std::str::from_utf8(bytes)?;
    let value = text
        .split("status=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or_else(|| ParseError::MissingElement("status".to_string()))?;
    value.parse().map_err(|_| ParseError::InvalidValue {
        field: "status".to_string(),
        value: value.to_string(),
    })
}

enum StreamStep {
    Bytes(Vec<u8>),
    Delay(Duration, Vec<u8>),
    Error,
    Pending,
}

struct TestConnection {
    connected: bool,
    buffered: VecDeque<Vec<u8>>,
    stream: VecDeque<StreamStep>,
    pending_tail: Option<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    invalidations: Arc<AtomicUsize>,
    sent: Arc<AtomicUsize>,
}

impl TestConnection {
    fn new(stream: impl IntoIterator<Item = StreamStep>) -> Self {
        Self {
            connected: false,
            buffered: VecDeque::from([VERSION_RESPONSE.to_vec()]),
            stream: stream.into_iter().collect(),
            pending_tail: None,
            reads: Arc::new(AtomicUsize::new(0)),
            invalidations: Arc::new(AtomicUsize::new(0)),
            sent: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl GvmConnection for TestConnection {
    async fn connect(&mut self) -> gvm_connection::Result<()> {
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> gvm_connection::Result<()> {
        self.connected = false;
        Ok(())
    }

    async fn send(&mut self, _data: &[u8]) -> gvm_connection::Result<()> {
        if !self.connected {
            return Err(ConnectionError::NotConnected);
        }
        self.sent.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn read(&mut self) -> gvm_connection::Result<Vec<u8>> {
        if !self.connected {
            return Err(ConnectionError::NotConnected);
        }
        if let Some(tail) = self.pending_tail.take() {
            return Ok(tail);
        }
        self.buffered.pop_front().ok_or_else(|| {
            ConnectionError::ReadFailed(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffered response exhausted",
            ))
        })
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[async_trait]
impl GvmStreamingConnection for TestConnection {
    fn response_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    async fn read_stream_chunk(&mut self) -> gvm_connection::Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match self.stream.pop_front() {
            Some(StreamStep::Bytes(bytes)) => Ok(bytes),
            Some(StreamStep::Delay(delay, bytes)) => {
                tokio::time::sleep(delay).await;
                Ok(bytes)
            }
            Some(StreamStep::Error) => {
                self.invalidate_stream();
                Err(ConnectionError::ReadFailed(io::Error::other(
                    "injected transport error",
                )))
            }
            Some(StreamStep::Pending) => std::future::pending().await,
            None => {
                self.invalidate_stream();
                Err(ConnectionError::ReadFailed(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated streamed response",
                )))
            }
        }
    }

    fn retain_stream_tail(&mut self, mut tail: Vec<u8>) {
        if let Some(existing) = self.pending_tail.take() {
            tail.extend_from_slice(&existing);
        }
        if !tail.is_empty() {
            self.pending_tail = Some(tail);
        }
    }

    fn invalidate_stream(&mut self) {
        self.connected = false;
        self.invalidations.fetch_add(1, Ordering::SeqCst);
    }
}

async fn client(
    steps: impl IntoIterator<Item = StreamStep>,
) -> (
    GmpClient<TestConnection>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let connection = TestConnection::new(steps);
    let reads = Arc::clone(&connection.reads);
    let invalidations = Arc::clone(&connection.invalidations);
    let client = GmpClient::connect(connection)
        .await
        .expect("connect client");
    (client, reads, invalidations)
}

fn chunks(bytes: &[u8], sizes: &[usize]) -> Vec<StreamStep> {
    let mut result = Vec::new();
    let mut offset = 0;
    for size in sizes.iter().copied().cycle() {
        if offset == bytes.len() {
            break;
        }
        let end = (offset + size).min(bytes.len());
        result.push(StreamStep::Bytes(bytes[offset..end].to_vec()));
        offset = end;
    }
    result
}

#[tokio::test]
async fn opt_in_response_streams_exact_bytes_with_backpressure_and_completion() {
    let response = r#"<test_stream_response status="200" status_text="OK"><body>Grüße &amp; data</body></test_stream_response>"#.as_bytes();
    let (mut client, reads, _invalidations) = client(chunks(response, &[1, 2, 7, 3, 11])).await;
    let mut stream = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream");

    assert_eq!(reads.load(Ordering::SeqCst), 0, "must not read ahead");
    let mut observed = Vec::new();
    let mut yielded_chunks = 0;
    while let Some(chunk) = stream.next_chunk().await.expect("next chunk") {
        yielded_chunks += 1;
        observed.extend_from_slice(&chunk);
        assert!(reads.load(Ordering::SeqCst) >= yielded_chunks);
    }
    let completion = stream.finish().await.expect("finish stream");

    assert_eq!(observed, response);
    assert_eq!(completion.bytes_received, response.len() as u64);
    assert_eq!(completion.metadata.status, 200);
    assert!(completion.metadata.events >= yielded_chunks);
}

#[tokio::test]
async fn completed_stream_preserves_tail_for_follow_up_request() {
    let response = br#"<test_stream_response status="200" status_text="OK"><body>x</body></test_stream_response>"#;
    let mut coalesced = response.to_vec();
    coalesced.extend_from_slice(VERSION_RESPONSE);
    let (mut client, _reads, invalidations) = client([StreamStep::Bytes(coalesced)]).await;

    let completion = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect("drain and finish");
    assert_eq!(completion.bytes_received, response.len() as u64);
    let version = client
        .execute(GetVersionRequest::new())
        .await
        .expect("follow-up request");

    assert_eq!(version.version, "22.8");
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn early_drop_invalidates_connection() {
    let response =
        br#"<test_stream_response status="200"><body>later</body></test_stream_response>"#;
    let (mut client, _reads, invalidations) = client(chunks(response, &[9])).await;
    let mut stream = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream");
    assert!(stream.next_chunk().await.expect("first chunk").is_some());
    drop(stream);

    assert_eq!(invalidations.load(Ordering::SeqCst), 1);
    assert!(matches!(
        client.execute(GetVersionRequest::new()).await,
        Err(GvmError::Connection(ConnectionError::NotConnected))
    ));
}

#[tokio::test]
async fn cancellation_followed_by_drop_invalidates_connection() {
    let (mut client, _reads, invalidations) = client([StreamStep::Pending]).await;
    let mut stream = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream");

    tokio::select! {
        result = stream.next_chunk() => panic!("pending read completed: {result:?}"),
        () = tokio::task::yield_now() => {}
    }
    drop(stream);

    assert_eq!(invalidations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn malformed_and_truncated_xml_invalidate_connection() {
    for steps in [
        vec![StreamStep::Bytes(
            br#"<test_stream_response status="200"><x></wrong>"#.to_vec(),
        )],
        vec![StreamStep::Bytes(
            br#"<test_stream_response status="200"><x>"#.to_vec(),
        )],
    ] {
        let (mut client, _reads, invalidations) = client(steps).await;
        let error = client
            .execute_stream(TestStreamingRequest)
            .await
            .expect("start stream")
            .finish()
            .await
            .expect_err("stream must fail");

        assert!(matches!(
            error,
            GvmError::Protocol(_) | GvmError::Connection(_)
        ));
        assert!(invalidations.load(Ordering::SeqCst) >= 1);
    }
}

#[tokio::test]
async fn transport_and_incremental_decoder_errors_invalidate_connection() {
    for steps in [
        vec![StreamStep::Error],
        vec![StreamStep::Bytes(
            br#"<test_stream_response status="200">decoder-error</test_stream_response>"#.to_vec(),
        )],
    ] {
        let (mut client, _reads, invalidations) = client(steps).await;
        let error = client
            .execute_stream(TestStreamingRequest)
            .await
            .expect("start stream")
            .finish()
            .await
            .expect_err("stream must fail");

        assert!(matches!(
            error,
            GvmError::Connection(_) | GvmError::Parse(_)
        ));
        assert!(invalidations.load(Ordering::SeqCst) >= 1);
    }
}

struct FailingSink;

impl AsyncWrite for FailingSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("injected sink error")))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct RecordingSink(Vec<u8>);

impl AsyncWrite for RecordingSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn copy_adapter_writes_exact_bytes_and_returns_completion() {
    let response =
        br#"<test_stream_response status="200"><body>copy</body></test_stream_response>"#;
    let (mut client, _reads, invalidations) = client(chunks(response, &[2, 1, 5])).await;
    let stream = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream");
    let mut sink = RecordingSink::default();
    let completion = stream.copy_to(&mut sink).await.expect("copy stream");

    assert_eq!(sink.0, response);
    assert_eq!(completion.bytes_received, response.len() as u64);
    assert_eq!(completion.metadata.status, 200);
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn copy_adapter_supports_durable_file_acquisition() {
    let response =
        br#"<test_stream_response status="200"><body>durable</body></test_stream_response>"#;
    let (mut client, _reads, invalidations) = client(chunks(response, &[3, 8, 2])).await;
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("response.xml");
    let mut file = tokio::fs::File::create(&path)
        .await
        .expect("create response file");

    let completion = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream")
        .copy_to(&mut file)
        .await
        .expect("copy stream to file");
    file.flush().await.expect("flush response file");
    file.sync_all().await.expect("sync response file");
    drop(file);

    assert_eq!(
        tokio::fs::read(path).await.expect("read response file"),
        response
    );
    assert_eq!(completion.bytes_received, response.len() as u64);
    assert_eq!(completion.metadata.status, 200);
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn sink_error_is_explicit_and_invalidates_connection() {
    let response = br#"<test_stream_response status="200"><body>x</body></test_stream_response>"#;
    let (mut client, _reads, invalidations) = client([StreamStep::Bytes(response.to_vec())]).await;
    let stream = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream");
    let error = stream
        .copy_to(&mut FailingSink)
        .await
        .expect_err("sink must fail");

    assert!(matches!(error, GmpStreamCopyError::Sink(_)));
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn non_success_completion_is_a_server_error_and_invalidates_connection() {
    let response = br#"<test_stream_response status="503" status_text="Unavailable"/>"#;
    let (mut client, _reads, invalidations) = client([StreamStep::Bytes(response.to_vec())]).await;
    let error = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect_err("server status must fail");

    assert!(matches!(error, GvmError::Server { status: 503, .. }));
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn non_success_status_is_rejected_before_the_first_sink_write() {
    let response = br#"<test_stream_response status="503" status_text="Unavailable"><large>error body</large></test_stream_response>"#;
    let (mut client, _reads, invalidations) = client(chunks(response, &[1, 2, 3])).await;
    let mut sink = RecordingSink::default();
    let error = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream")
        .copy_to(&mut sink)
        .await
        .expect_err("server status must fail before writing");

    assert!(matches!(
        error,
        GmpStreamCopyError::Stream(GvmError::Server { status: 503, .. })
    ));
    assert!(sink.0.is_empty());
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn per_call_total_size_limit_is_independent_and_uses_u64_counts() {
    let response =
        br#"<test_stream_response status="200"><body>large</body></test_stream_response>"#;
    let (mut client, _reads, invalidations) = client(chunks(response, &[7])).await;
    let options = StreamOptions {
        max_bytes: Some((response.len() - 1) as u64),
        ..StreamOptions::default()
    };
    let error = client
        .execute_stream_with(TestStreamingRequest, options)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect_err("size limit must fail");

    assert!(matches!(
        error,
        GvmError::Protocol(gvm_protocol::ProtocolError::StreamSizeLimit { max })
            if max == (response.len() - 1) as u64
    ));
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn retained_token_limit_is_independent_of_total_stream_size() {
    let response = format!(
        "<test_stream_response status=\"200\" value=\"{}\"/>",
        "x".repeat(128)
    );
    let (mut client, _reads, invalidations) = client(chunks(response.as_bytes(), &[8])).await;
    let options = StreamOptions {
        max_retained_bytes: 32,
        ..StreamOptions::default()
    };
    let error = client
        .execute_stream_with(TestStreamingRequest, options)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect_err("retained token limit must fail");

    assert!(matches!(
        error,
        GvmError::Protocol(gvm_protocol::ProtocolError::StreamRetainedLimit { max: 32 })
    ));
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn retained_limit_also_bounds_the_withheld_pre_root_prefix() {
    let response = "<!--12345678--><!--abcdefgh--><test_stream_response status=\"200\"/>";
    let (mut client, _reads, invalidations) = client(chunks(response.as_bytes(), &[8])).await;
    let options = StreamOptions {
        max_retained_bytes: 20,
        ..StreamOptions::default()
    };
    let error = client
        .execute_stream_with(TestStreamingRequest, options)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect_err("withheld prefix limit must fail");

    assert!(matches!(
        error,
        GvmError::Protocol(gvm_protocol::ProtocolError::StreamRetainedLimit { max: 20 })
    ));
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn idle_timeout_resets_after_caller_backpressure() {
    let first = br#"<test_stream_response status="200"><body>"#.to_vec();
    let second = br#"data</body></test_stream_response>"#.to_vec();
    let (mut client, _reads, invalidations) = client([
        StreamStep::Delay(Duration::from_millis(5), first),
        StreamStep::Delay(Duration::from_millis(5), second),
    ])
    .await;
    let options = StreamOptions {
        idle_timeout: Some(Duration::from_millis(20)),
        ..StreamOptions::default()
    };
    let mut stream = client
        .execute_stream_with(TestStreamingRequest, options)
        .await
        .expect("start stream");

    assert!(stream.next_chunk().await.expect("first chunk").is_some());
    tokio::time::sleep(Duration::from_millis(30)).await;
    let completion = stream
        .finish()
        .await
        .expect("caller pause is not idle time");

    let _: u64 = completion.bytes_received;
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn optional_total_timeout_still_bounds_the_complete_operation() {
    let first = br#"<test_stream_response status="200"><body>"#.to_vec();
    let second = br#"data</body></test_stream_response>"#.to_vec();
    let (mut client, _reads, invalidations) =
        client([StreamStep::Bytes(first), StreamStep::Bytes(second)]).await;
    let options = StreamOptions {
        idle_timeout: Some(Duration::from_secs(1)),
        total_timeout: Some(Duration::from_millis(10)),
        ..StreamOptions::default()
    };
    let mut stream = client
        .execute_stream_with(TestStreamingRequest, options)
        .await
        .expect("start stream");

    assert!(stream.next_chunk().await.expect("first chunk").is_some());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let error = stream
        .finish()
        .await
        .expect_err("total timeout must expire");

    assert!(matches!(error, GvmError::Timeout(_)));
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn wire_trace_uses_omission_marker_instead_of_streamed_response_bytes() {
    let response =
        br#"<test_stream_response status="200"><secret>do-not-log</secret></test_stream_response>"#;
    let connection = TestConnection::new([StreamStep::Bytes(response.to_vec())]);
    let events = Arc::new(Mutex::new(Vec::<WireTraceEvent>::new()));
    let observed = Arc::clone(&events);
    let mut client = GmpClient::connect_with_wire_trace(connection, move |event| {
        observed.lock().expect("trace lock").push(event);
    })
    .await
    .expect("connect client");

    client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect("finish stream");

    let events = events.lock().expect("trace lock");
    assert!(events
        .iter()
        .any(|event| { event.bytes == b"[streamed GMP response omitted]" }));
    assert!(events
        .iter()
        .all(|event| !String::from_utf8_lossy(&event.bytes).contains("do-not-log")));
}
