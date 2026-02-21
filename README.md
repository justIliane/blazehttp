# BlazeHTTP

A high-performance HTTP/1.1 and HTTP/2 server for Go, built from scratch with zero-dependency protocol implementations.

## Features

- **HTTP/1.1 + HTTP/2** — Full dual-protocol support with automatic ALPN negotiation
- **Zero-alloc hot path** — Pre-allocated, pooled objects; 0 B/op on encode/decode paths
- **RFC 9113 compliant** — h2spec 146/146 tests passing (100%)
- **HPACK (RFC 7541)** — Complete encoder/decoder with static table, Huffman coding, and dynamic table
- **Flow control** — Connection-level and stream-level send/receive windows
- **Security hardened** — CVE-2023-44487 (rapid reset) mitigated, flood protection, fuzz-tested parsers
- **net/http compatible** — Adapters for `http.Handler` interoperability
- **Single unified handler** — One handler function serves both HTTP/1.1 and HTTP/2 requests

## Performance

### HTTP/1.1 vs fasthttp

| Metric | BlazeHTTP | fasthttp | Delta |
|--------|-----------|----------|-------|
| **RPS** | **329,836** | 298,122 | **+10.6%** |
| Latency p50 | 179 us | 216 us | -17.1% |

### HTTP/2 vs net/http

| Metric | BlazeHTTP | net/http | Delta |
|--------|-----------|----------|-------|
| **RPS** | **465,710** | 237,164 | **+96.3%** |
| Latency mean | 20.29 ms | 40.35 ms | -49.7% |

See [doc/BENCHMARKS.md](doc/BENCHMARKS.md) for full results.

## Quick Start

```go
package main

import (
    "crypto/tls"
    "log"

    "github.com/blazehttp/blazehttp/server"
    "github.com/blazehttp/blazehttp/server/http2"
)

func handler(ctx *http2.RequestCtx) {
    ctx.SetStatusCode(200)
    ctx.SetContentType("text/plain")
    ctx.SetBodyString("Hello, World!")
}

func main() {
    cert, _ := server.GenerateSelfSignedCert()

    s := &server.Server{
        Addr:    ":8443",
        Handler: handler,
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{cert},
        },
    }

    log.Fatal(s.ListenAndServeTLS())
}
```

## Installation

```bash
go get github.com/blazehttp/blazehttp
```

Requires Go 1.24+.

## API Overview

### Server

```go
s := &server.Server{
    Addr:    ":8443",
    Handler: handler,            // Unified handler for HTTP/1.1 and HTTP/2

    // Timeouts
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,

    // HTTP/2 settings
    HTTP2: &server.HTTP2Config{
        MaxConcurrentStreams: 250,
        MaxFrameSize:        16384,
        InitialWindowSize:   1 << 20,
        MaxHeaderListSize:   8192,
    },

    // TLS
    TLSConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},
    },
}
```

### Handler

The handler receives a `*http2.RequestCtx` for both HTTP/1.1 and HTTP/2:

```go
func handler(ctx *http2.RequestCtx) {
    // Request
    method := ctx.Request.Method()     // []byte
    path   := ctx.Request.Path()       // []byte
    body   := ctx.Request.Body()       // []byte
    host   := ctx.Request.Authority()  // []byte
    hdr    := ctx.Request.Header([]byte("content-type"))

    // Response
    ctx.SetStatusCode(200)
    ctx.SetContentType("application/json")
    ctx.SetBody(jsonBytes)
}
```

### net/http Adapters

Use existing `http.Handler` implementations with BlazeHTTP:

```go
import "github.com/blazehttp/blazehttp"

// Use a net/http handler with BlazeHTTP
s := &server.Server{
    Handler: blazehttp.WrapHandler(myHTTPHandler),
}

// Use a BlazeHTTP handler with net/http
http.ListenAndServe(":8080", blazehttp.WrapBlazeHandler(myBlazeHandler))
```

### Listening Methods

| Method | Description |
|--------|-------------|
| `ListenAndServe()` | Plain HTTP (h2c supported) |
| `ListenAndServeTLS()` | TLS using pre-configured `TLSConfig` |
| `ListenAndServeTLSFiles(cert, key)` | TLS using certificate files |
| `ListenAndServeTLSCert(cert)` | TLS using a `tls.Certificate` |
| `Serve(listener)` | Use a custom `net.Listener` |

## Examples

| Example | Description |
|---------|-------------|
| [hello](examples/hello/) | Minimal TLS server |
| [echo](examples/echo/) | POST body echo server |
| [fileserver](examples/fileserver/) | Static file server |
| [benchmark](examples/benchmark/) | Optimized benchmark server |

## Architecture

BlazeHTTP is organized into focused packages:

```
server/             Main server, TLS, connection dispatch
server/http1/       HTTP/1.1 request/response handling
server/http2/       HTTP/2 connection, stream, request/response
pkg/hpack/          HPACK encoder/decoder (RFC 7541)
pkg/frame/          HTTP/2 frame reader/writer (RFC 9113)
pkg/stream/         Stream state machine and manager
pkg/flowcontrol/    Flow control window tracking
pkg/header/         HTTP/1.1 header parser
pkg/bytespool/      Size-class byte slice pool
internal/util/      Shared utilities (no-alloc conversions)
```

See [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) for details.

## Security

- **CVE-2023-44487** (HTTP/2 Rapid Reset) — Detected and mitigated with GOAWAY ENHANCE_YOUR_CALM
- **Flood protection** — PING, SETTINGS, and RST_STREAM floods trigger connection termination
- **Fuzz tested** — All parsers fuzzed for 20+ minutes each (~1.36 billion executions)
- **RFC conformant** — h2spec 146/146, strict frame and header validation

See [doc/CONFORMANCE.md](doc/CONFORMANCE.md) for the full conformance report.

## Documentation

- [ARCHITECTURE.md](doc/ARCHITECTURE.md) — System architecture
- [BENCHMARKS.md](doc/BENCHMARKS.md) — Performance benchmarks
- [CONFORMANCE.md](doc/CONFORMANCE.md) — RFC conformance and security
- [CHANGELOG.md](doc/CHANGELOG.md) — Release history

## License

MIT
