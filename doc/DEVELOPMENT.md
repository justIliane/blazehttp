# BlazeHTTP Development History

BlazeHTTP was built using a structured, phase-by-phase approach over 15 development phases.

## Process

1. **Detailed specification** — A comprehensive design document defined the architecture, performance targets, quality requirements, and phase-by-phase development plan
2. **Phase-by-phase execution** — Each phase had explicit validation criteria that had to pass before moving to the next
3. **Test-driven development** — Every component was tested immediately after implementation, with `go test -race` required at every step
4. **Continuous benchmarking** — Performance was measured and compared against fasthttp/net/http at each optimization phase

## Phase Timeline

### Phase 0 — Foundation & Infrastructure
- Initialized Go module and project structure
- Implemented `pkg/bytespool` — size-class byte slice pool (64B to 64KB)
- Implemented `internal/util` — zero-alloc conversions (unsafe string↔[]byte, AppendUint, EqualFold)
- Build-tag-controlled debug logging (`internal/debug`)
- **Tests**: 32 tests, 100% coverage on core packages

### Phase 1 — HTTP/1.1 Zero-Alloc Parser
- `pkg/header/parser.go` — parses request line and headers directly on the network buffer
- `server/http1/` — handler, request, response with full pooling
- Keep-alive, pipelining, chunked transfer encoding
- **Result**: 0 allocs/op, 5.3x faster than fasthttp's parser on simple GET requests
- **Tests**: 31 handler tests + 27 parser tests + fuzz testing

### Phase 2 — HPACK Encoder/Decoder (RFC 7541)
- Static table with 61 entries and hash-based O(1) lookup
- Dynamic table with ring buffer (O(1) add/evict)
- Huffman encoder/decoder
- Integer encoding with overflow protection
- Encoder/decoder pooling via `sync.Pool`
- **Result**: 0 allocs/op on both encode and decode paths
- **Tests**: 42 tests, 192/192 official HPACK test vectors, fuzz testing

### Phase 3 — HTTP/2 Frame Reader/Writer
- Zero-alloc frame reader with reusable buffer
- Buffered frame writer supporting all 10 HTTP/2 frame types
- CONTINUATION frame assembly
- Padding validation and frame size enforcement
- **Tests**: 67 tests, 15 benchmarks, fuzz testing

### Phase 4 — Flow Control & Stream Management (RFC 9113 §5.2)
- Atomic, lock-free flow control windows (verified to inline)
- Connection-level and stream-level send/receive windows
- WINDOW_UPDATE handling with overflow detection
- Stream state machine (idle → open → half-closed → closed)
- Stream concurrency enforcement (SETTINGS_MAX_CONCURRENT_STREAMS)
- **Tests**: 43 tests including concurrent stress tests

### Phase 5 — Complete HTTP/2 Server
- Full HTTP/2 connection handling: preface, SETTINGS exchange, GOAWAY
- Stream multiplexing with configurable max concurrent streams
- Worker pool for request processing
- h2c (HTTP/2 over cleartext) support
- ALPN negotiation between HTTP/1.1 and HTTP/2
- **Tests**: 56 HTTP/2 tests covering all frame types and error conditions

### Phase 6 — Optimization & Benchmarking
- HTTP/1.1 benchmarks: **+10.6% RPS** vs fasthttp, **-17% p50 latency**
- HTTP/2 benchmarks: **+96.3% RPS** vs net/http, **-50% mean latency**
- Applied TCP_NODELAY + TCP_QUICKACK on all connections
- SetContentType pre-allocation (eliminated per-call []byte allocation)
- Verified all critical functions inline (8 functions checked)
- CPU profiling: no unexpected hotspots (HPACK Huffman = 16.8% as expected)
- Memory profiling: all allocations accounted for and optimized

### Phase 7 — Conformance & Robustness
- **h2spec**: 146/146 tests passing (100% RFC 9113 compliance)
- **CVE-2023-44487** (Rapid Reset): mitigated with GOAWAY ENHANCE_YOUR_CALM
- PING, SETTINGS, RST_STREAM flood protection (>1000 control frames/10s)
- **Fuzzing**: 1.36 billion total executions across 3 parsers, 0 crashes
- **Bug found by fuzzer**: HPACK integer overflow in `decodeString` — fixed with regression test
- 8 robustness tests covering all attack vectors

### Phase 8 — User API & Documentation
- `blazehttp.WrapHandler()` — adapt `net/http.Handler` for BlazeHTTP
- `blazehttp.WrapBlazeHandler()` — adapt BlazeHTTP handler for `net/http`
- 4 examples: hello, echo, fileserver, benchmark
- Complete documentation: ARCHITECTURE.md, BENCHMARKS.md, CONFORMANCE.md, CHANGELOG.md

### Phase 9.0 — TLS Fingerprinting
- Integrated [uTLS](https://github.com/refraction-networking/utls) for browser-grade TLS
- JA3 and JA4 computation from raw ClientHello bytes
- ClientHello parsing (cipher suites, extensions, supported groups, signature algorithms)
- 8 browser profiles: Chrome120, ChromeLatest, Firefox121, FirefoxLatest, Safari17, SafariIOS, Randomized, GoDefault
- **Tests**: 24 fingerprint tests verifying JA3/JA4 for each profile

### Phase 9.1 — HTTP/2 Fingerprinting
- H2Profile type capturing SETTINGS, WINDOW_UPDATE, pseudo-header order, PRIORITY frames
- Chrome and Firefox H2 profiles with exact browser values
- Akamai HTTP/2 fingerprint hash computation (4-section format)
- Default headers and header ordering per browser
- **Tests**: 40+ profile tests including frame capture via local TLS server

### Phase 9.2 — Client HTTP/2 Connection
- `ClientConn` with handshake, read loop, write loop, round-trip
- Full SETTINGS exchange with server
- GOAWAY handling with graceful shutdown
- Flow control (connection + stream level)
- Server PING response
- **Tests**: 34 connection tests with raw TLS server

### Phase 9.3 — Connection Pool
- Auto-scaling connection pool with multiplexing
- Max 6 connections per host, 2 idle per host (configurable)
- Health checks via periodic PING
- GOAWAY-aware connection eviction with transparent retry
- Wait timeout for backpressure
- **Tests**: 11 pool tests + 2 benchmarks (single-conn + parallel)

### Phase 9.4 — Client API & Features
- High-level `Client` with `Do()`, `Get()`, `Post()`, `Head()`, `DoBatch()`, `Close()`
- Browser constructors: `NewChromeClient()`, `NewFirefoxClient()`, `NewSafariClient()`, `NewRandomClient()`
- Thread-safe `CookieJar` with domain/path matching, expiry, secure flag
- Redirect following: 301/302/303 → GET, 307/308 → preserve method+body
- Retry with exponential backoff + jitter
- HTTP CONNECT + SOCKS5 proxy support (fingerprint preserved through tunnel)
- **Tests**: 44 client tests, 76 total passing, 84% coverage

### Phase 9.5 — Anti-Detection Validation
- Updated Akamai hash to 4-section format (added pseudo-headers)
- JA3/JA4 verified via local TLS server capture (Chrome ≠ Go default)
- H2 SETTINGS verified for Chrome and Firefox (IDs, values, order)
- Pseudo-header order verified (Chrome: m,a,s,p / Firefox: m,p,a,s)
- 100 multiplexed requests in < 200ms on local server
- Benchmarks: 15,500+ req/s multiplexed, ~135µs single request
- `doc/CLIENT.md` — complete client documentation

## Metrics Summary

| Metric | Value |
|--------|-------|
| Total development time | ~7 hours |
| Total phases | 15 (Phase 0 through 9.5) |
| Total test functions | 444 |
| Total benchmark functions | 72 |
| Fuzz test executions | 1.36 billion |
| Bugs found by fuzzer | 1 (HPACK integer overflow) |
| Data races found | 0 |
| h2spec conformance | 146/146 (100%) |
| HPACK test vectors | 192/192 (100%) |
| HTTP/1.1 vs fasthttp | +10.6% RPS, -17% p50 latency |
| HTTP/2 vs net/http | +96.3% RPS, -50% mean latency |
| CVE mitigations | CVE-2023-44487 + 3 flood attack types |
| External dependencies | 1 (uTLS for TLS fingerprinting) |

## Key Technical Decisions

1. **From-scratch HPACK**: No dependency on `golang.org/x/net/http2/hpack`. Custom implementation with hash-based static table, ring buffer dynamic table, and zero-alloc encode/decode.

2. **From-scratch frame reader/writer**: No dependency on `golang.org/x/net/http2`. Custom implementation with reusable buffer, pooling, and all 10 frame types.

3. **uTLS for TLS fingerprinting**: `crypto/tls` doesn't allow controlling the ClientHello. uTLS is the standard for TLS fingerprinting in Go, used by Tor and V2Ray.

4. **Worker pool instead of goroutine-per-request**: HTTP/2 uses a fixed worker pool for request processing, avoiding the overhead of goroutine creation per stream.

5. **Atomic flow control**: Flow control windows use atomic operations instead of mutexes, verified to inline for zero overhead.

6. **Object pooling everywhere**: RequestCtx, Request, Response, Encoder, Decoder, FrameReader, FrameWriter — all pooled via `sync.Pool`.

## Bugs Found & Fixed

### HPACK Integer Overflow (Found by Fuzzer)
- **Location**: `pkg/hpack/decoder.go`, `decodeString()` function
- **Issue**: Casting `uint64 > math.MaxInt64` to `int` for slice bounds caused panic
- **Root cause**: Missing overflow check before int conversion
- **Fix**: Added bounds check: `if length > uint64(maxStringLength) { return error }`
- **Found by**: `FuzzHPACKDecode` after ~200M executions
- **Regression test**: `FuzzHPACKDecode/551d461dacc17944`

### HPACK Encoder Pool Corruption (Found by Tests)
- **Location**: `pkg/hpack/encoder.go`, `ReleaseEncoder()` function
- **Issue**: `Reset()` only cleared the buffer, not the dynamic table. Reused encoders from the pool carried stale dynamic table entries from previous connections.
- **Symptom**: `COMPRESSION_ERROR` when pooled encoders were reused across connections
- **Fix**: Changed to `ResetConnection()` which clears both buffer and dynamic table

### Client Init Overwrite (Found by Tests)
- **Location**: `client/client.go`, `init()` function
- **Issue**: Lazy initialization was overwriting pre-configured pool and dialer set by test helpers
- **Fix**: Added `if c.pool != nil { return }` guard at the start of `init()`
