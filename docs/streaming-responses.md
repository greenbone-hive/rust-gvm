# Streaming Large GMP Responses

`GmpClient::execute_stream` and `execute_stream_with` are the generic foundation for GMP responses that
can be too large to buffer comfortably. It is intentionally capability-gated:
a request is accepted only when its associated response implements
`GmpStreamingResponse`. Ordinary `GmpResponse` implementations continue to use
the existing buffered `execute`, `send`, and `call` paths.

No response type on the current public command surface opts in yet. In
particular, this foundation does not add a native report-page request, response,
size policy, or pagination strategy. A future crate-owned response can opt in
without adding a report-specific client method.

## Lifecycle

`execute_stream` performs the same request validation, semantic capability
check, version-aware encoding, redacted request tracing, and transport send as
`execute`. It then returns a `GmpResponseStream` that mutably borrows the active
connection.

- `next_chunk().await` returns exact received bytes belonging to the current
  response. Before its first yield it may combine multiple bounded reads until
  the root start tag is complete and its GMP status has been accepted. Later
  calls perform one bounded transport read. Bytes are never rebuilt or
  reserialized.
- No background reader or unbounded channel is created. The caller's next
  `next_chunk` call is the backpressure signal.
- The incremental XML framer validates exactly one XML 1.0 root, the configured
  nesting limit, a per-call optional total-byte limit, and an independent
  retained-token limit. It discards parsed prefixes and retains only incomplete
  token state.
- `finish().await` returns `GmpStreamCompletion { bytes_received, metadata }`.
  Calling it early deliberately drains and validates the remainder without
  yielding those remaining bytes.
- `copy_to(&mut sink).await` is the convenience `AsyncWrite` adapter. It writes
  each exact chunk with `write_all` and returns the same completion value. It
  does not flush or shut down the caller-owned sink. For durable acquisition,
  pass a temporary `tokio::fs::File`, then explicitly call `flush` and
  `sync_all` after successful completion before atomically publishing the file.

The response-specific incremental decoder receives ordered, already validated
`StreamingXmlEvent` values from the same generic framer. It therefore does not
need a second XML parser. The generic stream checks the root `status` before
yielding the first byte and normalizes non-2xx statuses to the same server error
semantics as buffered decoding. Event creation is lazy: buffered response
validation does not build event payloads, and a streaming decoder receives no
`Text` or `CData` strings unless its `wants_text(element_path)` implementation
selects that path. The text-interest decision is made while each transport
chunk is parsed, so it must depend on the supplied path rather than state that
`feed` updates after the event batch has been returned.

`Text` and `CData` events are content fragments, not complete logical XML text
nodes. Feed and transport boundaries can split character data into several
events, and CDATA can appear between ordinary text fragments. A decoder that
selects text must accumulate all selected fragments until the matching `End`
event instead of treating one event as the element's complete value.

## Connection reuse and failures

The stream exclusively controls the connection for its lifetime, enforced by
Rust's mutable borrow rules. After the XML frame and response-specific metadata
both validate, bytes already read after the frame boundary are retained for the
next response and the connection is reusable.

The connection is invalidated in each of these cases:

- transport error, timeout, or EOF before completion;
- malformed, truncated, oversized, or excessively nested XML;
- a non-success or malformed GMP root status;
- response-specific incremental decoding failure;
- dropping the stream before full validation;
- cancelling an in-progress operation and then dropping the stream;
- an `AsyncWrite` sink error in `copy_to`.

After invalidation, reconnect before sending another request. If a caller stops
using response bytes early but wants to preserve the connection, it must call
`finish` and allow the explicit drain-and-validate path to succeed. Simply
dropping the stream never starts hidden background draining.

## Memory and limits

Transport chunks are bounded consistently by each built-in transport's
`read_buffer_size`. `StreamOptions::max_retained_bytes` defaults to 4 MiB and
bounds the held prefix only while the root start tag has not yet been validated,
as well as an unfinished attribute, CDATA section, comment, or other single
token. The bounded transport read that completes and validates the root is
emitted in full, even when a large body shares that read. Consequently the
first emitted chunk may exceed `max_retained_bytes` by up to one bounded
transport read; declarations, comments, and other exact pre-root bytes remain
preserved in that chunk.
`StreamOptions::max_bytes` is an optional `u64` total-frame limit. Neither
setting changes the connection's `max_response_bytes`, which remains the
buffered path's in-memory response ceiling.

Unix, verified TLS, and SSH use the same timeout model. The connection timeout
is the default idle timeout for each stream read, so time spent in the caller's
sink or between `next_chunk` calls is not charged to the server. A caller can
override `idle_timeout` and set an optional `total_timeout` per operation.
Completion byte counts are `u64`.

## Tracing and secrets

Requests use the existing structural redaction before reaching a wire trace.
Raw streamed response chunks are never sent to the trace sink because doing so
would require buffering or risk logging large secret-bearing bodies. After
successful validation, the trace receives a fixed
`[streamed GMP response omitted]` marker instead.

## Implementing an opt-in response

A response opts in by implementing `GmpStreamingResponse` and selecting a
`GmpStreamDecoder`. The decoder's `feed` method observes ordered validated XML
events, while `wants_text` opts selected element paths into fragment delivery;
`finish` returns small typed metadata only after the generic XML framer has
validated the complete frame. This association is static through
`GmpRequest::Response`, so non-opt-in response types fail to compile with
`execute_stream` and no command-name matching is involved.
