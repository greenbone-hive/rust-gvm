# Streaming Large GMP Responses

`GmpClient::execute_stream` and `execute_stream_with` are the generic foundation for GMP responses that
can be too large to buffer comfortably. It is intentionally capability-gated:
a request is accepted only when its associated response implements
`GmpStreamingResponse`. Ordinary `GmpResponse` implementations continue to use
the existing buffered `execute`, `send`, and `call` paths.

`NativeReportPageResponse` is the first production opt-in. Its distinct
`GetNativeReportPageRequest` retrieves one complete, explicitly windowed native
XML `get_reports_response` through the generic operation; there is no
report-specific client streaming method.

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
`Text`, `CData`, or `Reference` strings unless its
`wants_text(element_path)` implementation selects that path. References on all
paths are still validated. The character-content decision is made while each
transport chunk is parsed, so it must depend on the supplied path rather than
state that `feed` updates after the event batch has been returned.

Selected character content is fragmented across `Text`, `CData`, and
`Reference` events, not delivered as complete logical XML text nodes. Feed and
transport boundaries can split ordinary text into several events, while CDATA
and references can appear between those fragments. `Reference` contains the
reference spelling without its `&` and `;` delimiters; it is not silently
expanded text. A decoder that selects character content must handle and
accumulate all three variants until the matching `End` event. For example, a
decoder preserving the lexical XML content reconstructs `Reference("amp")` as
`&amp;` rather than appending only `amp` or pretending the event contains `&`.

## Native report pages

`GetNativeReportPageRequest::new` requires a report ID, a caller-authored
result filter, a 1-based `first`, positive `rows`, and four named output choices:
lean output, note details, override details, and result tags. It rejects
`first` or `rows` embedded in the result filter, including grouped, spaced, and
case-varied forms. Empty filter text is an explicit unfiltered selection.

The request always sends `details=1` and `ignore_pagination=0`. It has no saved
filter input, default page size, or response-byte limit. Validation, semantic
capability identity, and version-aware XML encoding delegate to the canonical
`GetReportRequest`, including the GMP 22.6+ `usage_type=scan` behavior.

```rust,ignore
use gvm_gmp::commands::reports::{
    GetNativeReportPageRequest, NativeReportPageOptions,
};

let request = GetNativeReportPageRequest::new(
    report_id,
    "severity>5 sort-reverse=severity",
    1,
    500,
    NativeReportPageOptions {
        lean: true,
        ..NativeReportPageOptions::default()
    },
)?;
let completion = client
    .execute_stream(request)
    .await?
    .copy_to(&mut native_xml)
    .await?;
```

The completion metadata contains available outer and nested report IDs, task
ID, scan status, resolved nested result-filter term and keywords, the actual
`results` start/max window, the number of direct result elements actually
returned, total/full/filtered result counts, and the small outer report-count
block. The decoder consumes the generic framer's validated events, caps
accumulated metadata text at 256 KiB, and retains at most 256 filter keywords.
It skips result subtrees by depth, so neither result-body names nor text are
retained for metadata decoding. The generic framer independently bounds XML
nesting, names, and incomplete tokens, validates the complete document, and
supplies the exact response bytes and observed byte count.

Buffered `execute` uses this same event decoder and validates the complete XML,
but `NativeReportPageResponse` contains metadata only. The buffered response's
native XML bytes are deliberately discarded. Call `execute_stream` when those
bytes are the desired output.

### Page continuation and limits

gvmd's **Max Rows Per Page** setting is an upper bound regardless of the
requested `rows`, so a request for 500 rows can return fewer. The response's
`page.max` reports gvmd's window value; it is not the number of `<result>`
elements present. Continue only from a successfully completed page:

1. If `returned_results` is zero, stop. Advancing by zero would loop, even if
   other count metadata changed concurrently.
2. Otherwise compute the next `first` with checked signed arithmetic as
   `page.start + returned_results`. Do not add the requested `rows`.
3. When `result_count.filtered` is present, the traversal is complete once the
   computed next `first` is greater than that count. Without it, request the
   computed next page and stop on a zero-result page.

A missing `page.start`, a value that cannot fit the signed GMP integer range,
or inconsistent counts means there is no safe automatic continuation. Smaller
positive `rows` generally produce smaller pages. `StreamOptions::max_bytes` can
place a total-byte cap on any individual streamed response.

Pagination is not a snapshot. A running or otherwise mutable report can gain,
lose, or change results between requests, shifting later windows. gvmd filter
sorting also does not provide a documented stable total order for tied values;
an explicit sort therefore cannot guarantee gap-free traversal when sort keys
tie. For correctness-sensitive multi-page reads, use a completed report that is
not being mutated. The API remains intentionally page-specific: mandatory
positive `rows` and `ignore_pagination=0` make that scope explicit.

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
events, while `wants_text` opts selected element paths into `Text`, `CData`, and
`Reference` fragment delivery. An opted-in decoder must handle and accumulate
all three character-content variants. `finish` returns small typed metadata
only after the generic XML framer has validated the complete frame. This
association is static through `GmpRequest::Response`, so non-opt-in response
types fail to compile with `execute_stream` and no command-name matching is
involved.
