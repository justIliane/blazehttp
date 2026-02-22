<p align="center">
  <img src="https://onvi3bhqlbq6rqxv.public.blob.vercel-storage.com/blazehttplogoe.png" alt="BlazeHTTP" width="400">
</p>

<h3 align="center">⚡ High-performance HTTP/1.1 + HTTP/2 server & client for Go</h3>
<h4 align="center">Faster than fasthttp, 2x faster than net/http, with browser-grade TLS/HTTP2 fingerprinting</h4>

<p align="center">
  <a href="https://pkg.go.dev/github.com/blazehttp/blazehttp"><img src="https://img.shields.io/badge/go-1.24+-00ADD8?logo=go" alt="Go 1.24+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <a href="https://goreportcard.com/report/github.com/blazehttp/blazehttp"><img src="https://goreportcard.com/badge/github.com/blazehttp/blazehttp" alt="Go Report Card"></a>
  <img src="https://img.shields.io/badge/tests-444%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/h2spec-146%2F146-brightgreen" alt="h2spec">
  <img src="https://img.shields.io/badge/fuzzing-1.36B%20execs-brightgreen" alt="Fuzzing">
</p>

---

## 🤔 Why BlazeHTTP?

**fasthttp is stuck on HTTP/1.1.** It's been the go-to high-performance HTTP library for Go, but it doesn't support HTTP/2. In 2026, modern WAFs (Cloudflare, Akamai, DataDome) flag HTTP/1.1-only clients as suspicious — you need native HTTP/2 to blend in.

**net/http supports HTTP/2, but it's slow and leaks your identity.** Go's standard `crypto/tls` produces a distinctive JA3/JA4 fingerprint that WAFs instantly recognize as "not a browser." You can't control the ClientHello, SETTINGS frame order, or pseudo-header order — all signals that anti-bot systems use.

**BlazeHTTP solves both problems.** It's a from-scratch HTTP/1.1 + HTTP/2 implementation built for two things: **raw speed** and **anti-detection**. The server side is 10% faster than fasthttp for HTTP/1.1 and 2x faster than net/http for HTTP/2. The client side produces browser-identical TLS and HTTP/2 fingerprints — Chrome, Firefox, or Safari — making your requests indistinguishable from real browser traffic.

Zero external dependencies for the core protocol stack. Every component — HPACK codec, frame reader/writer, flow control, stream manager — is built from scratch with zero-allocation hot paths and object pooling.

## 📊 Performance

### HTTP/1.1: BlazeHTTP vs fasthttp

`wrk -t4 -c128 -d10s --latency`

| Workload | BlazeHTTP | fasthttp | Delta |
|----------|-----------|----------|-------|
| **Plaintext** | **329,836 req/s** | 298,122 req/s | **+10.6%** |
| **JSON** | **328,986 req/s** | 293,992 req/s | **+11.9%** |
| **POST 1KB** | **313,474 req/s** | 275,830 req/s | **+13.6%** |

| Latency (Plaintext) | BlazeHTTP | fasthttp | Delta |
|----------|-----------|----------|-------|
| p50 | **179 µs** | 216 µs | **17% faster** |
| p75 | **331 µs** | 363 µs | **9% faster** |
| p99 | 6.41 ms | 6.26 ms | ~equal |

### HTTP/2: BlazeHTTP vs net/http

`h2load -n1000000`

| Streams | BlazeHTTP | net/http | Delta |
|---------|-----------|----------|-------|
| **100 concurrent** | **465,710 req/s** | 237,164 req/s | **+96.3%** |
| **500 concurrent** | **434,813 req/s** | 277,145 req/s | **+56.9%** |
| **1000 concurrent** | **452,528 req/s** | 193,469 req/s | **+133.9%** |

| Latency (100 streams) | BlazeHTTP | net/http | Delta |
|---------|-----------|----------|-------|
| mean | **20.29 ms** | 40.35 ms | **2x faster** |
| time to first byte | **136.58 ms** | 168.35 ms | **19% faster** |

### Header Parsing: BlazeHTTP vs fasthttp

| Request Type | BlazeHTTP | fasthttp | Speedup |
|------|-----------|----------|---------|
| Simple GET (1 header) | **252 ns, 0 allocs** | 1,336 ns, 1 alloc | **5.3x** |
| Typical (8 headers) | **2,377 ns, 0 allocs** | 6,198 ns, 1 alloc | **2.6x** |
| Many headers (20) | **4,776 ns, 0 allocs** | 10,077 ns, 1 alloc | **2.1x** |

### Client Benchmarks

| Benchmark | Result |
|-----------|--------|
| Single request (local) | ~135 µs/op |
| 100 multiplexed requests | **15,500+ req/s** per connection |
| HPACK encode/decode | **0 allocs/op** |

## ⚔️ BlazeHTTP vs fasthttp — Feature Comparison

| Feature | BlazeHTTP | fasthttp | net/http |
|---------|:---------:|:--------:|:--------:|
| HTTP/1.1 | ✅ | ✅ | ✅ |
| HTTP/2 | ✅ | ❌ | ✅ |
| h2c (cleartext HTTP/2) | ✅ | ❌ | ✅ |
| Zero-alloc parsing | ✅ (0 allocs) | ⚠️ (1 alloc) | ❌ |
| TLS fingerprinting (JA3/JA4) | ✅ | ❌ | ❌ |
| HTTP/2 fingerprinting | ✅ | ❌ | ❌ |
| Browser emulation | ✅ Chrome/Firefox/Safari | ❌ | ❌ |
| Connection multiplexing | ✅ | ❌ | ✅ |
| Cookie jar | ✅ | ❌ | ✅ |
| Proxy CONNECT + SOCKS5 | ✅ | ❌ | ⚠️ (CONNECT only) |
| h2spec conformance | ✅ 146/146 | N/A | partial |
| Akamai H2 fingerprint hash | ✅ | ❌ | ❌ |
| Anti-bot bypass | ✅ | ❌ | ❌ |
| Batch/multiplexed requests | ✅ DoBatch | ❌ | ❌ |

## 🚀 Quick Start — Server

```go
package main

import (
    "github.com/blazehttp/blazehttp/server"
    "github.com/blazehttp/blazehttp/server/http2"
)

func main() {
    s := server.New()

    // HTTP/2 handler (also serves HTTP/1.1 automatically)
    s.HandleHTTP2(func(ctx *http2.RequestCtx) {
        ctx.SetStatusCode(200)
        ctx.SetContentType("text/plain")
        ctx.SetBodyString("Hello from BlazeHTTP! ⚡")
    })

    // Auto-generates TLS cert, serves HTTP/1.1 + HTTP/2
    s.ListenAndServeTLS(":443")
}
```

## 🕷️ Quick Start — Client

```go
package main

import (
    "fmt"
    "github.com/blazehttp/blazehttp/client"
)

func main() {
    // Chrome fingerprint — TLS + HTTP/2 identical to real Chrome
    c := client.NewChromeClient()
    defer c.Close()

    resp, err := c.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    fmt.Println(resp.StatusCode, string(resp.Body))
}
```

### Multiplexed Batch Requests

```go
// Send 100 requests on a single HTTP/2 connection
reqs := make([]*client.Request, 100)
for i := range reqs {
    reqs[i] = client.NewRequest("GET", fmt.Sprintf("https://api.example.com/item/%d", i))
}

resps, err := c.DoBatch(reqs)
// All 100 responses returned, multiplexed on 1 connection
```

### Proxy Support

```go
c := client.NewChromeClient()

// HTTP CONNECT proxy
c.SetProxy("http://proxy.example.com:8080")

// SOCKS5 proxy
c.SetSOCKS5Proxy("socks5-proxy.example.com:1080", "user", "pass")

// TLS fingerprint is preserved through the proxy tunnel
resp, _ := c.Get("https://target.com")
```

## 🛡️ Client Anti-Detection Features

### TLS Fingerprinting (JA3/JA4)

BlazeHTTP uses [uTLS](https://github.com/refraction-networking/utls) to produce browser-identical TLS ClientHello messages. Each profile matches the exact cipher suites, extensions, supported groups, and ALPN of the target browser. JA4 is immune to Chrome's extension order randomization (Chrome 106+).

| Profile | TLS Fingerprint | Matches |
|---------|-----------------|---------|
| `NewChromeClient()` | Chrome 120 (uTLS) | Chrome 120+ on Windows |
| `NewFirefoxClient()` | Firefox 121 (uTLS) | Firefox 121+ on Windows |
| `NewSafariClient()` | Safari 17 (uTLS) | Safari 17+ on macOS |
| `NewRandomClient()` | Randomized (uTLS) | Different each connection |

### HTTP/2 Fingerprinting

The HTTP/2 connection preface is the second signal WAFs use. BlazeHTTP reproduces:

- **SETTINGS frame** — exact parameter IDs, values, and order
- **WINDOW_UPDATE** — browser-specific connection window size
- **Pseudo-header order** — Chrome: `:method,:authority,:scheme,:path` / Firefox: `:method,:path,:authority,:scheme`
- **PRIORITY frames** — Chrome's 5-frame priority tree on startup
- **Akamai HTTP/2 hash** — 4-section fingerprint hash matches known browser values

```
Chrome: 1:65536;3:1000;4:6291456;6:262144|15663105|3:0:200:0,...|m,a,s,p
Firefox: 1:65536;4:131072;5:16384|12517377||m,p,a,s
```

## 📦 Installation

```bash
go get github.com/blazehttp/blazehttp
```

Requires Go 1.24+.

## 🏗️ Architecture

```
github.com/blazehttp/blazehttp
├── server/                    HTTP/1.1 + HTTP/2 server
│   ├── http1/                 HTTP/1.1 handler, request parser, response builder
│   └── http2/                 HTTP/2 connection, stream dispatch, worker pool
├── client/                    HTTP/2 client with anti-detection
│   ├── tls/                   TLS fingerprinting (uTLS, JA3/JA4, browser profiles)
│   └── h2fingerprint/         HTTP/2 fingerprinting (SETTINGS, Akamai hash, profiles)
├── pkg/
│   ├── hpack/                 HPACK encoder/decoder (RFC 7541), zero-alloc
│   ├── frame/                 HTTP/2 frame reader/writer, zero-alloc
│   ├── flowcontrol/           Atomic flow control windows
│   ├── stream/                Stream state machine & manager
│   ├── header/                HTTP/1.1 header parser, zero-alloc
│   └── bytespool/             Size-class byte slice pool
├── blazehttp.go               net/http adapter (WrapHandler/WrapBlazeHandler)
└── examples/                  hello, echo, fileserver, benchmark
```

## 📋 RFC Conformance

| Spec | Coverage | Status |
|------|----------|--------|
| RFC 9113 (HTTP/2) | h2spec 146/146 | ✅ **100%** |
| RFC 7541 (HPACK) | 192/192 test vectors | ✅ **100%** |
| RFC 9110 (HTTP Semantics) | Methods, status codes, headers | ✅ |
| RFC 9112 (HTTP/1.1) | Request parsing, keep-alive, chunked | ✅ |
| TLS ALPN | h2/http/1.1 negotiation | ✅ |

See [doc/CONFORMANCE.md](doc/CONFORMANCE.md) for detailed section-by-section compliance.

## 🔒 Security

| Threat | Mitigation | Status |
|--------|------------|--------|
| **CVE-2023-44487** (Rapid Reset) | GOAWAY ENHANCE_YOUR_CALM after 1000 RST_STREAM/10s | ✅ |
| PING flood | GOAWAY after 1000 control frames/10s | ✅ |
| SETTINGS flood | GOAWAY after 1000 control frames/10s | ✅ |
| Slow loris | Read timeouts on HTTP/1.1 | ✅ |
| HPACK bomb | Dynamic table size limits enforced | ✅ |
| Integer overflow | Overflow protection in HPACK decoder (found by fuzzer) | ✅ |
| Flow control exhaustion | Send window blocking with 10s timeout | ✅ |

**Fuzzing**: 1.36 billion executions across 3 parsers (HTTP/1.1, HPACK, frames) — **0 crashes** in production code. 1 bug found and fixed (HPACK integer overflow in `decodeString`).

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## 🙏 Credits & Acknowledgments

- **[valyala/fasthttp](https://github.com/valyala/fasthttp)** — Inspiration for the zero-alloc architecture and performance philosophy. BlazeHTTP draws from fasthttp's patterns of object pooling and direct buffer parsing.
- **Go standard library** (`net/http`, `crypto/tls`) — Reference implementation for HTTP/2 and TLS
- **[refraction-networking/utls](https://github.com/refraction-networking/utls)** — TLS fingerprinting (the only external dependency for core functionality). Used by Tor, V2Ray, and most anti-censorship tools.
- **RFC 9113** (HTTP/2), **RFC 7541** (HPACK), **RFC 9110** (HTTP Semantics) — The specifications that guided the implementation
- **[h2spec](https://github.com/summerwind/h2spec)** — HTTP/2 conformance test suite (146/146 passing)
- **[hpack-test-case](https://github.com/http2jp/hpack-test-case)** — Official HPACK test vectors (192/192 passing)
- **Akamai HTTP/2 fingerprinting research** — HTTP/2 browser fingerprint profiling
- **[tls.peet.ws](https://tls.peet.ws)** — TLS fingerprint verification service for JA3/JA4

## 📈 Development History

BlazeHTTP was built in 15 phases:

| Phase | Description | Key Metrics |
|-------|-------------|-------------|
| **0** | Foundation & infrastructure | bytespool, util, project setup |
| **1** | HTTP/1.1 zero-alloc parser | 0 allocs/op, 5.3x faster than fasthttp parsing |
| **2** | HPACK encoder/decoder (RFC 7541) | 0 allocs/op, 192/192 test vectors |
| **3** | HTTP/2 frame reader/writer | All 10 frame types, CONTINUATION assembly |
| **4** | Flow control & stream management | Atomic windows, state machine, concurrency |
| **5** | Complete HTTP/2 server | Multiplexing, GOAWAY, h2c, worker pool |
| **6** | Optimization & benchmarking | +10.6% vs fasthttp, +96.3% vs net/http |
| **7** | Conformance & robustness | h2spec 146/146, CVE-2023-44487, 1.36B fuzz |
| **8** | User API & documentation | net/http adapters, examples, docs |
| **9.0** | TLS fingerprinting | uTLS, JA3/JA4, Chrome/Firefox/Safari profiles |
| **9.1** | HTTP/2 fingerprinting | SETTINGS, WINDOW_UPDATE, Akamai hash, priorities |
| **9.2** | Client HTTP/2 connection | Dial, handshake, round-trip, read/write loops |
| **9.3** | Connection pool | Multiplexing, auto-scaling, health checks, GOAWAY |
| **9.4** | Client API & features | Cookie jar, redirects, retry, proxy, DoBatch |
| **9.5** | Anti-detection validation | JA3/JA4 verified, H2 verified, benchmarks, docs |

**Total: 444 tests, 72 benchmarks, 1.36 billion fuzzing executions, 0 data races.**

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Write tests for your changes
4. Ensure all tests pass: `go test -race ./...`
5. Run vet: `go vet ./...`
6. Submit a pull request

## 📄 License

[MIT](LICENSE) — Use it however you want.
