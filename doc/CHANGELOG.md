# Changelog

## Phase 8 — User API & Documentation

- Added `HTTP2Config` struct for grouped HTTP/2 settings
- Added zero-argument `ListenAndServeTLS()` using pre-configured `TLSConfig`
- Implemented HTTP/1.1 → HTTP/2 unified handler bridge
- Added `blazehttp.WrapHandler()` — adapt `net/http.Handler` for BlazeHTTP
- Added `blazehttp.WrapBlazeHandler()` — adapt BlazeHTTP handler for `net/http`
- Added response accessors: `NumHeaders()`, `HeaderAt()`
- Added request setters: `SetMethod()`, `SetPath()`, `SetScheme()`, `SetAuthority()`, `AddHeader()`
- Created examples: hello, echo, fileserver, benchmark
- Complete documentation: README.md, ARCHITECTURE.md, CHANGELOG.md

## Phase 7 — Conformance & Robustness

- h2spec 146/146 tests passing (100%)
- CVE-2023-44487 (Rapid Reset) mitigation with GOAWAY ENHANCE_YOUR_CALM
- PING, SETTINGS, and RST_STREAM flood protection
- Fuzz testing: 1.36 billion executions across 3 parsers
- Fixed HPACK integer overflow in `decodeString` (found by fuzzer)
- Robustness test suite (8 tests)
- doc/CONFORMANCE.md

## Phase 6 — Optimization & Benchmarking

- HTTP/1.1 benchmarks: +10.6% RPS vs fasthttp, -17.1% p50 latency
- HTTP/2 benchmarks: +96.3% RPS vs net/http, -49.7% mean latency
- HPACK decode/encode: 0 allocs/op confirmed
- TCP_NODELAY + TCP_QUICKACK on all connections
- SetContentType pre-allocation (eliminated per-call []byte allocation)
- CPU profiling: no unexpected hotspots
- Memory profiling: all allocations accounted for and optimized
- doc/BENCHMARKS.md

## Phase 5 — HTTP/2 Server

- Complete HTTP/2 server implementation (RFC 9113)
- Connection preface, SETTINGS exchange, GOAWAY
- Stream multiplexing with configurable max concurrent streams
- HPACK-encoded response headers
- Worker pool for request processing
- h2c (HTTP/2 over cleartext) support
- Integration with HTTP/1.1 via ALPN negotiation

## Phase 4 — Flow Control & Stream Management

- Connection-level and stream-level flow control (RFC 9113 §5.2)
- WINDOW_UPDATE frame handling
- Send window blocking with timeout
- SETTINGS_INITIAL_WINDOW_SIZE delta adjustment for open streams
- Stream state machine (idle, open, half-closed, closed)
- Stream concurrency enforcement (SETTINGS_MAX_CONCURRENT_STREAMS)

## Phase 3 — HTTP/2 Frame Reader/Writer

- Frame reader with zero-alloc reusable buffer
- Frame writer supporting all 10 frame types
- CONTINUATION frame assembly
- Padding validation
- Frame size limits enforcement

## Phase 2 — HPACK Encoder/Decoder

- Complete HPACK implementation (RFC 7541)
- Static table with 61 entries and hash-based O(1) lookup
- Dynamic table with ring buffer (O(1) add/evict)
- Huffman encoder/decoder
- Integer encoding/decoding with overflow protection
- Encoder/decoder pooling via sync.Pool

## Phase 1 — HTTP/1.1 Server

- HTTP/1.1 request parser (zero-alloc header parsing)
- HTTP/1.1 response builder with pooled buffers
- Keep-alive and pipelining support
- Chunked transfer encoding
- Content-Length body handling

## Phase 0 — Foundation

- Project structure and Go module setup
- Byte slice pool (`bytespool`) with size classes
- Shared utilities (`util`) with zero-alloc conversions
- Build-tag-controlled debug logging
