# BlazeHTTP Architecture

## Package Structure

```
github.com/blazehttp/blazehttp
├── blazehttp.go              net/http adapters (WrapHandler, WrapBlazeHandler)
├── server/
│   ├── server.go             Server struct, listener, connection dispatch
│   ├── tls.go                TLS configuration, self-signed cert generation
│   ├── sockopt_linux.go      TCP_NODELAY + TCP_QUICKACK (Linux)
│   ├── sockopt_other.go      TCP_NODELAY (non-Linux)
│   ├── http1/
│   │   ├── handler.go        HTTP/1.1 read loop, RequestCtx, ServeConn
│   │   ├── request.go        HTTP/1.1 request parser (wraps pkg/header)
│   │   └── response.go       HTTP/1.1 response builder
│   └── http2/
│       ├── handler.go        RequestHandler, RequestCtx, WorkerPool
│       ├── conn.go           HTTP/2 connection: read loop, write loop, stream dispatch
│       ├── request.go        HTTP/2 request (from HPACK decoded fields)
│       ├── response.go       HTTP/2 response (HPACK encoded)
│       └── settings.go       ConnSettings (SETTINGS frame handling)
├── pkg/
│   ├── hpack/
│   │   ├── decoder.go        HPACK decoder (RFC 7541) with pooling
│   │   ├── encoder.go        HPACK encoder with static table lookup
│   │   ├── huffman.go        Huffman encoder/decoder
│   │   ├── static_table.go   61-entry static table with hash-based lookup
│   │   └── dynamic_table.go  Ring buffer dynamic table
│   ├── frame/
│   │   ├── reader.go         Frame reader (zero-alloc, reusable buffer)
│   │   ├── writer.go         Frame writer (buffered, supports all frame types)
│   │   └── types.go          Frame types, error codes, settings IDs
│   ├── stream/
│   │   ├── stream.go         Stream state machine (RFC 9113 §5.1)
│   │   ├── manager.go        Stream lifecycle manager
│   │   └── priority.go       Priority handling
│   ├── flowcontrol/
│   │   └── window.go         Flow control window (atomic, inlineable)
│   ├── header/
│   │   └── parser.go         HTTP/1.1 header parser (zero-alloc)
│   └── bytespool/
│       └── pool.go           Size-class byte slice pool
└── internal/
    ├── util/                 Shared utilities
    │   ├── bytes.go          AppendUint, EqualFold
    │   └── unsafe.go         BytesToString, StringToBytes
    └── debug/                Build-tag-controlled debug logging
```

## Request Lifecycle

### HTTP/2 Request

```
Client → TLS Handshake (ALPN: h2) → Connection Preface
  → SETTINGS exchange
  → readLoop:
      Frame Reader → Parse Frame
        HEADERS → HPACK Decode → Request.FromHeaders() → validate
        DATA → append to Request body → flow control accounting
        End of stream → WorkerPool.Submit(RequestCtx)
  → Worker goroutine:
      Handler(ctx) → ctx.Response populated
      → enqueueResponse → writeCh
  → writeLoop:
      HPACK Encode response headers → HEADERS frame
      Response body → DATA frame(s) with flow control
```

### HTTP/1.1 Request

```
Client → Connection (plain or TLS with ALPN: http/1.1)
  → ServeConn read loop:
      Read data → header.Parse() → Request
      Handler(ctx) → ctx.Response populated
      Response.Build() → write to connection
      Keep-alive → loop
```

### Unified Handler Bridge (HTTP/1.1 → HTTP/2 handler)

When `HTTP1Handler` is nil, the server automatically bridges HTTP/1.1 requests:

```
HTTP/1.1 Request → wrapHTTP1Handler
  → Acquire http2.RequestCtx from pool
  → Copy method, path, headers, body
  → Call unified Handler
  → Copy response back to HTTP/1.1 response
  → Release http2.RequestCtx
```

## Key Design Decisions

### Zero-Allocation Strategy

- All request/response objects are pooled via `sync.Pool`
- HPACK encoder/decoder maintain reusable scratch buffers
- Frame reader reuses a single buffer across reads
- Byte slices come from a size-class pool (`bytespool`)
- Static table entries use `unsafe.Slice` for zero-copy access

### HPACK Implementation

- **Static table**: 61 entries with hash-based O(1) lookup using a name hash + value comparison
- **Dynamic table**: Ring buffer with O(1) add/evict, avoiding slice shifting
- **Encoder**: Prefers indexed representation, falls back to literal with incremental indexing
- **Decoder**: `strBuf` accumulates all string copies per Decode call, preventing aliasing with the ring buffer

### Flow Control

- `flowcontrol.Window` is an atomic int64 for lock-free operation
- All methods (`Available`, `Consume`, `Update`) are verified to inline
- Connection-level and per-stream windows are tracked independently
- DATA frames wait (with timeout) when the send window is exhausted

### Worker Pool

- Fixed-size goroutine pool processes HTTP/2 requests
- Decouples request handling from the connection's read/write loops
- Buffered channel (`n*4` capacity) prevents blocking the read loop
- Default size: `NumCPU * 256`

### Security

- Control frame counter (PING + SETTINGS + RST_STREAM) with a sliding window
- Exceeding 1000 control frames in 10 seconds triggers GOAWAY ENHANCE_YOUR_CALM
- Rapid Reset detection (CVE-2023-44487) via RST_STREAM counting
- All parsers fuzz-tested with `go test -fuzz` (1.36 billion executions total)
