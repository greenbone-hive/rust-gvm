# Streaming Large GMP Responses

`GmpClient::execute_stream` is the generic foundation for GMP responses that
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

- `next_chunk().await` reads at most one transport chunk and returns the exact
  received bytes belonging to the current response. Bytes are never rebuilt or
  reserialized.
- No background reader or unbounded channel is created. The caller's next
  `next_chunk` call is the backpressure signal.
- The incremental XML framer validates exactly one XML 1.0 root, the configured
  nesting limit, and the transport's configured total response-byte limit. It
  discards parsed prefixes and retains only incomplete token state.
- `finish().await` returns `GmpStreamCompletion { bytes_received, metadata }`.
  Calling it early deliberately drains and validates the remainder without
  yielding those remaining bytes.
- `copy_to(&mut sink).await` is the convenience `AsyncWrite` adapter. It writes
  each exact chunk with `write_all` and returns the same completion value. It
  does not flush or shut down the caller-owned sink. For durable acquisition,
  pass a `tokio::fs::File`, then explicitly call `flush` and `sync_all` after
  successful completion before publishing the file.

The response-specific incremental decoder receives the same exact chunks and
keeps only the small state needed to produce completion metadata. It is also
responsible for normalizing non-2xx response status to the same server error
semantics as buffered decoding.

## Connection reuse and failures

The stream exclusively controls the connection for its lifetime, enforced by
Rust's mutable borrow rules. After the XML frame and response-specific metadata
both validate, bytes already read after the frame boundary are retained for the
next response and the connection is reusable.

The connection is invalidated in each of these cases:

- transport error, timeout, or EOF before completion;
- malformed, truncated, oversized, or excessively nested XML;
- response-specific incremental decoding failure, including a non-success GMP
  status;
- dropping the stream before full validation;
- cancelling an in-progress operation and then dropping the stream;
- an `AsyncWrite` sink error in `copy_to`.

After invalidation, reconnect before sending another request. If a caller stops
using response bytes early but wants to preserve the connection, it must call
`finish` and allow the explicit drain-and-validate path to succeed. Simply
dropping the stream never starts hidden background draining.

## Memory and limits

Transport chunks are bounded by each built-in transport's `read_buffer_size`.
The streaming XML reader normally retains only a partial XML token plus nesting
state. An adversarial single unfinished token can grow until the configured
`max_response_bytes`, so deployments should keep a finite limit appropriate to
their protocol policy. Set or raise that existing transport limit explicitly
when legitimate responses exceed its default; this foundation introduces no
report-specific threshold.

Unix, verified TLS, and SSH use the same streaming transport contract and keep
one total response deadline: receiving periodic chunks does not reset it.

## Tracing and secrets

Requests use the existing structural redaction before reaching a wire trace.
Raw streamed response chunks are never sent to the trace sink because doing so
would require buffering or risk logging large secret-bearing bodies. After
successful validation, the trace receives a fixed
`[streamed GMP response omitted]` marker instead.

## Implementing an opt-in response

A response opts in by implementing `GmpStreamingResponse` and selecting a
`GmpStreamDecoder`. The decoder's `feed` method observes ordered exact chunks;
`finish` returns small typed metadata only after the generic XML framer has
validated the complete frame. This association is static through
`GmpRequest::Response`, so non-opt-in response types fail to compile with
`execute_stream` and no command-name matching is involved.
