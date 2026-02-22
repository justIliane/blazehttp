# Changelog

## Phase 9.5 — Anti-Detection Validation

- Updated Akamai hash to 4-section format (settings|window|priorities|pseudoHeaders)
- JA3/JA4 verified via local TLS server capture (Chrome ≠ Go default)
- JA4 stability verified across 5 connections (immune to extension randomization)
- HTTP/2 SETTINGS verified for Chrome and Firefox (IDs, values, order)
- Pseudo-header order verified: Chrome (m,a,s,p), Firefox (m,p,a,s)
- 100 multiplexed requests in < 200ms on local server
- Client benchmarks: 15,500+ req/s multiplexed, ~135µs single request
- Optional E2E test against tls.peet.ws
- Complete client documentation: `doc/CLIENT.md`

## Phase 9.4 — Client API & Features

- High-level `Client` with `Do()`, `Get()`, `Post()`, `Head()`, `DoBatch()`, `Close()`
- Browser constructors: `NewChromeClient()`, `NewFirefoxClient()`, `NewSafariClient()`, `NewRandomClient()`
- Thread-safe `CookieJar` with domain/path matching, expiry, secure flag
- Redirect following: 301/302/303 → GET, 307/308 → preserve method+body
- Retry with exponential backoff + jitter
- HTTP CONNECT + SOCKS5 proxy support (fingerprint preserved through tunnel)
- `Request` builder with `SetHeader`, `SetBody`, `SetCookie`, header ordering
- `Response` with `Header()`, `Cookies()`, `Release()`

## Phase 9.3 — Connection Pool

- Auto-scaling connection pool with transparent HTTP/2 multiplexing
- Max 6 connections per host, 2 idle per host (configurable)
- Health checks via periodic PING
- GOAWAY-aware connection eviction with automatic retry
- Wait timeout for backpressure when all connections saturated
- Dial timeout configuration

## Phase 9.2 — Client HTTP/2 Connection

- `ClientConn` with full HTTP/2 handshake (preface, SETTINGS exchange)
- Read loop + write loop with separate goroutines
- Concurrent `roundTrip` with stream multiplexing
- GOAWAY handling with graceful shutdown
- Flow control (connection + stream level) with WINDOW_UPDATE
- Server PING response

## Phase 9.1 — HTTP/2 Fingerprinting

- `H2Profile` type capturing SETTINGS, WINDOW_UPDATE, pseudo-header order, PRIORITY frames
- Chrome 120+ and Firefox 121+ H2 profiles with exact browser values
- Akamai HTTP/2 fingerprint hash computation
- Default headers and header ordering per browser
- `Clone()` for safe concurrent use

## Phase 9.0 — TLS Fingerprinting

- Integrated uTLS for browser-grade TLS ClientHello
- JA3 and JA4 computation from raw ClientHello bytes
- ClientHello parsing (cipher suites, extensions, supported groups, signature algorithms)
- 8 browser profiles: Chrome120, ChromeLatest, Firefox121, FirefoxLatest, Safari17, SafariIOS, Randomized, GoDefault
- `TLSDialer` with configurable fingerprint, timeout, skip verify
- `DialOverConn` for TLS over proxy tunnels

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
