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
use gvm_gmp::commands::reports::{GetNativeReportPageRequest, NativeReportPageOptions};
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::responses::ParseError;
use gvm_gmp::{
    EntityId, GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpResponse,
    GmpStreamDecoder, GmpStreamingResponse, GmpVersion,
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
    content_events: usize,
}

#[derive(Debug, Default)]
struct TestDecoder {
    status: Option<u16>,
    events: usize,
    content_events: usize,
}

impl GmpStreamDecoder for TestDecoder {
    type Completion = TestMetadata;

    fn feed(&mut self, event: &StreamingXmlEvent) -> Result<(), ParseError> {
        self.events += 1;
        if matches!(
            event,
            StreamingXmlEvent::Text { .. }
                | StreamingXmlEvent::CData { .. }
                | StreamingXmlEvent::Reference { .. }
        ) {
            self.content_events += 1;
        }
        if matches!(
            event,
            StreamingXmlEvent::Start { element, .. }
                | StreamingXmlEvent::Empty { element, .. }
                if element.name == "decoder-error"
        ) {
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
            content_events: self.content_events,
        })
    }
}

#[derive(Debug)]
struct TextStreamingRequest;

impl GmpRequestCodec for TextStreamingRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("test_stream"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(b"<test_stream/>".to_vec())
    }
}

impl GmpRequest for TextStreamingRequest {
    type Response = TextStreamingResponse;
}

#[derive(Debug)]
struct TextStreamingResponse;

impl GmpResponse for TextStreamingResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        status(response.data())?;
        Ok(Self)
    }
}

impl GmpStreamingResponse for TextStreamingResponse {
    type Decoder = TextDecoder;

    fn stream_decoder(_version: GmpVersion) -> Self::Decoder {
        TextDecoder::default()
    }
}

#[derive(Debug, Default)]
struct TextDecoder {
    status: Option<u16>,
    metadata: String,
    fragments: usize,
    cdata_fragments: usize,
    reference_fragments: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct TextMetadata {
    status: u16,
    metadata: String,
    fragments: usize,
    cdata_fragments: usize,
    reference_fragments: usize,
}

impl GmpStreamDecoder for TextDecoder {
    type Completion = TextMetadata;

    fn wants_text(&self, element_path: &[String]) -> bool {
        matches!(element_path, [root, metadata] if root == "test_stream_response" && metadata == "metadata")
    }

    fn feed(&mut self, event: &StreamingXmlEvent) -> Result<(), ParseError> {
        match event {
            StreamingXmlEvent::Start { element, depth: 1 }
            | StreamingXmlEvent::Empty { element, depth: 1 } => {
                self.status = element
                    .attribute("status")
                    .and_then(|value| value.parse().ok());
            }
            StreamingXmlEvent::Text { text, .. } => {
                self.metadata.push_str(text);
                self.fragments += 1;
            }
            StreamingXmlEvent::CData { text, .. } => {
                self.metadata.push_str(text);
                self.fragments += 1;
                self.cdata_fragments += 1;
            }
            StreamingXmlEvent::Reference { reference, .. } => {
                self.metadata.push('&');
                self.metadata.push_str(reference);
                self.metadata.push(';');
                self.fragments += 1;
                self.reference_fragments += 1;
            }
            _ => {}
        }
        Ok(())
    }

    fn finish(self) -> Result<Self::Completion, ParseError> {
        Ok(TextMetadata {
            status: self
                .status
                .ok_or_else(|| ParseError::MissingElement("status".to_string()))?,
            metadata: self.metadata,
            fragments: self.fragments,
            cdata_fragments: self.cdata_fragments,
            reference_fragments: self.reference_fragments,
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
    sent_bytes: Arc<Mutex<Vec<Vec<u8>>>>,
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
            sent_bytes: Arc::new(Mutex::new(Vec::new())),
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

    async fn send(&mut self, data: &[u8]) -> gvm_connection::Result<()> {
        if !self.connected {
            return Err(ConnectionError::NotConnected);
        }
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.sent_bytes
            .lock()
            .expect("sent bytes lock")
            .push(data.to_vec());
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
            Some(StreamStep::Error) => Err(ConnectionError::ReadFailed(io::Error::other(
                "injected transport error",
            ))),
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
    let response = r#"<test_stream_response status="200" status_text="OK"><body>Grüße &amp; data<![CDATA[raw]]></body></test_stream_response>"#.as_bytes();
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
    assert!(completion.metadata.events > 0);
    assert_eq!(completion.metadata.content_events, 0);
}

#[tokio::test]
async fn character_content_is_path_selected_and_accumulated_across_all_fragment_kinds() {
    let response = br#"<test_stream_response status="200"><ignored>not &amp; copied</ignored><metadata>a &amp; b<![CDATA[ + c]]> tail</metadata></test_stream_response>"#;

    for sizes in [&[1][..], &[2, 7, 3, 11][..], &[response.len()][..]] {
        let (mut client, _reads, invalidations) = client(chunks(response, sizes)).await;
        let completion = client
            .execute_stream(TextStreamingRequest)
            .await
            .expect("start text stream")
            .finish()
            .await
            .expect("finish text stream");

        assert_eq!(completion.metadata.status, 200);
        assert_eq!(completion.metadata.metadata, "a &amp; b + c tail");
        assert_eq!(completion.metadata.cdata_fragments, 1);
        assert_eq!(completion.metadata.reference_fragments, 1);
        assert!(
            completion.metadata.fragments >= 5,
            "transport boundaries and mixed content must remain observable fragments"
        );
        assert_eq!(invalidations.load(Ordering::SeqCst), 0);
    }
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
async fn transport_read_error_is_explicitly_invalidated_by_the_stream() {
    let (mut client, _reads, invalidations) = client([StreamStep::Error]).await;
    let error = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect_err("stream must fail");

    assert!(matches!(error, GvmError::Connection(_)));
    assert_eq!(invalidations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn incremental_decoder_errors_invalidate_connection() {
    let response = br#"<test_stream_response status="200"><decoder-error/></test_stream_response>"#;
    let (mut client, _reads, invalidations) = client([StreamStep::Bytes(response.to_vec())]).await;
    let error = client
        .execute_stream(TestStreamingRequest)
        .await
        .expect("start stream")
        .finish()
        .await
        .expect_err("stream must fail");

    assert!(matches!(error, GvmError::Parse(_)));
    assert!(invalidations.load(Ordering::SeqCst) >= 1);
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
async fn root_and_large_body_in_first_read_do_not_count_as_retained_prefix() {
    let body = "x".repeat(4 * 1024);
    let response = format!(
        "<?xml version=\"1.0\"?>\n<!--preserved--><test_stream_response status=\"200\"><body>{body}</body></test_stream_response>"
    );
    let (mut client, _reads, invalidations) = client(chunks(response.as_bytes(), &[1024])).await;
    let options = StreamOptions {
        max_retained_bytes: 256,
        ..StreamOptions::default()
    };
    let mut stream = client
        .execute_stream_with(TestStreamingRequest, options)
        .await
        .expect("start stream");
    let mut observed = Vec::new();

    while let Some(chunk) = stream.next_chunk().await.expect("next chunk") {
        observed.extend_from_slice(&chunk);
    }
    let completion = stream.finish().await.expect("finish stream");

    assert_eq!(observed, response.as_bytes());
    assert_eq!(completion.bytes_received, response.len() as u64);
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
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

    assert!(matches!(
        error,
        GvmError::Timeout(duration) if duration == Duration::from_millis(10)
    ));
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

const NATIVE_REPORT_ID: &str = "11111111-1111-1111-1111-111111111111";
const NATIVE_TASK_ID: &str = "22222222-2222-2222-2222-222222222222";

fn native_request(first: i32, rows: i32) -> GetNativeReportPageRequest {
    GetNativeReportPageRequest::new(
        EntityId::new(NATIVE_REPORT_ID).expect("report id"),
        "severity>5",
        first,
        rows,
        NativeReportPageOptions {
            lean: true,
            ..NativeReportPageOptions::default()
        },
    )
    .expect("native page request")
}

fn native_response(
    first: i32,
    requested_rows: i32,
    returned_max: i32,
    total: u64,
    returned_results: usize,
    padding: usize,
) -> Vec<u8> {
    let padding = "x".repeat(padding);
    let result = (0..returned_results)
        .map(|index| {
            if index == 0 {
                format!(
                    r#"<result id="result-{index}"><description>{padding}</description></result>"#
                )
            } else if index % 2 == 0 {
                format!(r#"<result id="result-{index}"/>"#)
            } else {
                format!(r#"<result id="result-{index}"><description/></result>"#)
            }
        })
        .collect::<String>();
    format!(
        r#"<get_reports_response status="200" status_text="OK"><report id="{NATIVE_REPORT_ID}"><task id="{NATIVE_TASK_ID}"/><report id="{NATIVE_REPORT_ID}"><filters id=""><term>severity&gt;5 first={first} rows={requested_rows}</term><keywords><keyword><column>first</column><relation>=</relation><value>{first}</value></keyword><keyword><column>rows</column><relation>=</relation><value>{requested_rows}</value></keyword></keywords></filters><scan_run_status>Done</scan_run_status><task id="{NATIVE_TASK_ID}"/><results start="{first}" max="{returned_max}">{result}</results><result_count>{total}<full>{total}</full><filtered>{total}</filtered></result_count></report></report><report_count>1<filtered>1</filtered><page>1</page></report_count></get_reports_response>"#
    )
    .into_bytes()
}

#[tokio::test]
async fn native_report_page_copy_preserves_complete_envelope_and_metadata() {
    let response = native_response(11, 25, 25, 80, 3, 257);
    let (mut client, _reads, invalidations) = client(chunks(&response, &[1, 17, 2, 31, 5])).await;
    let mut sink = RecordingSink::default();

    let completion = client
        .execute_stream(native_request(11, 25))
        .await
        .expect("start native page stream")
        .copy_to(&mut sink)
        .await
        .expect("copy native page");

    assert_eq!(sink.0, response);
    assert_eq!(completion.bytes_received, response.len() as u64);
    assert_eq!(completion.metadata.status, 200);
    assert_eq!(
        completion.metadata.report_id.as_ref().map(EntityId::as_str),
        Some(NATIVE_REPORT_ID)
    );
    assert_eq!(
        completion.metadata.task_id.as_ref().map(EntityId::as_str),
        Some(NATIVE_TASK_ID)
    );
    assert_eq!(completion.metadata.scan_run_status.as_deref(), Some("Done"));
    assert_eq!(completion.metadata.page.start, Some(11));
    assert_eq!(completion.metadata.page.max, Some(25));
    assert_eq!(completion.metadata.returned_results, 3);
    assert_eq!(
        completion
            .metadata
            .result_count
            .and_then(|count| count.filtered),
        Some(80)
    );
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_report_pages_complete_for_zero_results_and_multiple_windows() {
    let zero = native_response(1, 20, 20, 0, 0, 0);
    let later = native_response(21, 20, 20, 35, 15, 0);
    let mut steps = chunks(&zero, &[3, 7, 19]);
    steps.extend(chunks(&later, &[23, 2, 11]));
    let (mut client, _reads, invalidations) = client(steps).await;

    let first = client
        .execute_stream(native_request(1, 20))
        .await
        .expect("zero page stream")
        .finish()
        .await
        .expect("zero page completion");
    assert_eq!(first.metadata.page.start, Some(1));
    assert_eq!(first.metadata.returned_results, 0);
    assert_eq!(
        first.metadata.result_count.and_then(|count| count.filtered),
        Some(0)
    );

    let second = client
        .execute_stream(native_request(21, 20))
        .await
        .expect("later page stream")
        .finish()
        .await
        .expect("later page completion");
    assert_eq!(second.metadata.page.start, Some(21));
    assert_eq!(second.metadata.page.max, Some(20));
    assert_eq!(second.metadata.returned_results, 15);
    assert_eq!(
        second
            .metadata
            .filter
            .as_ref()
            .expect("filter metadata")
            .keywords[0]
            .value,
        "21"
    );
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_report_page_promotes_server_status_and_rejects_bad_frames() {
    let cases = [
        (
            br#"<get_reports_response status="503" status_text="Unavailable"/>"#.to_vec(),
            "server",
        ),
        (
            br#"<get_reports_response status="200" status_text="OK"><report></wrong>"#.to_vec(),
            "malformed",
        ),
        (
            br#"<get_reports_response status="200" status_text="OK"><report>"#.to_vec(),
            "truncated",
        ),
    ];

    for (response, kind) in cases {
        let (mut client, _reads, invalidations) = client([StreamStep::Bytes(response)]).await;
        let error = client
            .execute_stream(native_request(1, 10))
            .await
            .expect("start native page stream")
            .finish()
            .await
            .expect_err("native page must fail");

        match kind {
            "server" => assert!(matches!(error, GvmError::Server { status: 503, .. })),
            "malformed" => assert!(matches!(error, GvmError::Protocol(_))),
            "truncated" => assert!(matches!(error, GvmError::Connection(_))),
            _ => unreachable!(),
        }
        assert!(invalidations.load(Ordering::SeqCst) >= 1);
    }
}

#[tokio::test]
async fn capped_native_page_advances_by_actual_returned_results() {
    let capped = native_response(1, 500, 2, 5, 2, 0);
    let next = native_response(3, 500, 2, 5, 2, 0);
    let mut steps = chunks(&capped, &[37, 11, 5]);
    steps.extend(chunks(&next, &[7, 29, 3]));
    let (mut client, _reads, invalidations) = client(steps).await;
    let sent = Arc::clone(&client.connection().sent_bytes);

    let first = client
        .execute_stream(native_request(1, 500))
        .await
        .expect("capped page")
        .finish()
        .await
        .expect("capped page completion");
    assert_eq!(first.metadata.page.max, Some(2));
    assert_eq!(first.metadata.returned_results, 2);

    let next_first = i32::try_from(first.metadata.page.start.unwrap()).expect("small start")
        + i32::try_from(first.metadata.returned_results).expect("small result count");
    assert_eq!(next_first, 3);

    let second = client
        .execute_stream(native_request(next_first, 500))
        .await
        .expect("next page")
        .finish()
        .await
        .expect("next page completion");
    assert_eq!(second.metadata.page.start, Some(3));
    assert_eq!(second.metadata.returned_results, 2);

    let requests = sent
        .lock()
        .expect("sent bytes lock")
        .iter()
        .filter_map(|bytes| {
            let text = std::str::from_utf8(bytes).ok()?;
            text.starts_with("<get_reports").then(|| text.to_string())
        })
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("first=1 rows=500"));
    assert!(requests[1].contains("first=3 rows=500"));
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn large_completed_native_page_leaves_connection_reusable() {
    let large = native_response(1, 1, 1, 1, 1, 2 * 1024 * 1024);
    let following = native_response(2, 1, 1, 1, 0, 0);
    let mut steps = chunks(&large, &[4093, 8191, 257]);
    steps.extend(chunks(&following, &[13, 31]));
    let (mut client, _reads, invalidations) = client(steps).await;

    let first = client
        .execute_stream(native_request(1, 1))
        .await
        .expect("large native page")
        .finish()
        .await
        .expect("large page completion");
    assert_eq!(first.bytes_received, large.len() as u64);
    assert_eq!(first.metadata.returned_results, 1);

    let second = client
        .execute_stream(native_request(2, 1))
        .await
        .expect("following native page")
        .finish()
        .await
        .expect("following page completion");
    assert_eq!(second.metadata.returned_results, 0);
    assert_eq!(invalidations.load(Ordering::SeqCst), 0);
}
