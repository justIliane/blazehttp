# BlazeHTTP Client

Anti-detection HTTP/2 client with browser TLS and HTTP/2 fingerprinting.

## Quick Start

```go
import "github.com/justIliane/blazehttp/client"

c := client.NewChromeClient()
defer c.Close()

resp, err := c.Get("https://example.com")
if err != nil {
    log.Fatal(err)
}
fmt.Println(resp.StatusCode, string(resp.Body))
```

## Browser Profiles

| Constructor | TLS Profile | H2 Profile | User-Agent |
|---|---|---|---|
| `NewChromeClient()` | Chrome 120 (uTLS) | Chrome H2 | Chrome 120 |
| `NewFirefoxClient()` | Firefox 121 (uTLS) | Firefox H2 | Firefox 121 |
| `NewSafariClient()` | Safari 17 (uTLS) | Chrome H2* | Safari 17 |
| `NewRandomClient()` | Randomized (uTLS) | Chrome H2 | Chrome 120 |

Each profile emulates both the TLS ClientHello and the HTTP/2 connection fingerprint of the specified browser.

> \* Safari uses Chrome's H2 profile as a fallback — Safari's HTTP/2 fingerprint is very close to Chrome's in practice (same SETTINGS order and values). A dedicated Safari H2 profile may be added in a future release.

## TLS Fingerprinting

BlazeHTTP uses [uTLS](https://github.com/refraction-networking/utls) to produce browser-identical TLS ClientHello messages. Each profile matches:

- **Cipher suites** and their order
- **TLS extensions** and their order
- **Supported groups** (elliptic curves)
- **ALPN protocols** (h2, http/1.1)
- **Signature algorithms**

### JA3 / JA4

JA3 and JA4 fingerprints can be computed from captured ClientHello bytes:

```go
import blazetls "github.com/justIliane/blazehttp/client/tls"

// From raw ClientHello bytes:
ja3Str, ja3Hash, err := blazetls.ComputeJA3FromRaw(raw)
ja4, err := blazetls.ComputeJA4FromRaw(raw)

// From parsed fields:
ch, _ := blazetls.ParseClientHello(raw)
ja3 := blazetls.ComputeJA3(ch)
ja4 := blazetls.ComputeJA4(ch)
```

JA4 is immune to Chrome's TLS extension order randomization (Chrome 106+).

## HTTP/2 Fingerprinting

Each browser sends a unique HTTP/2 connection preface. BlazeHTTP reproduces:

### SETTINGS Frame

| Parameter | Chrome 120 | Firefox 121 |
|---|---|---|
| HEADER_TABLE_SIZE (1) | 65536 | 65536 |
| MAX_CONCURRENT_STREAMS (3) | 1000 | - |
| INITIAL_WINDOW_SIZE (4) | 6291456 | 131072 |
| MAX_FRAME_SIZE (5) | - | 16384 |
| MAX_HEADER_LIST_SIZE (6) | 262144 | - |

Settings are sent in the exact order shown (order matters for fingerprinting).

### WINDOW_UPDATE

| Browser | Connection Window Update |
|---|---|
| Chrome 120 | 15663105 |
| Firefox 121 | 12517377 |

### Pseudo-Header Order

| Browser | Order |
|---|---|
| Chrome | `:method`, `:authority`, `:scheme`, `:path` |
| Firefox | `:method`, `:path`, `:authority`, `:scheme` |

### PRIORITY Frames

Chrome sends 5 PRIORITY frames on connection startup to build its dependency tree. Firefox uses priority in HEADERS frames instead (no separate PRIORITY frames).

### Akamai HTTP/2 Hash

The Akamai hash summarizes the HTTP/2 fingerprint in a compact format:

```
settings|window_update|priority_tree|pseudo_headers
```

```go
import "github.com/justIliane/blazehttp/client/h2fingerprint"

hash := h2fingerprint.ComputeAkamaiHash(&h2fingerprint.ChromeH2)
// "1:65536;3:1000;4:6291456;6:262144|15663105|3:0:200:0,5:0:100:0,7:0:0:0,9:7:0:0,11:3:0:0|m,a,s,p"

hash = h2fingerprint.ComputeAkamaiHash(&h2fingerprint.FirefoxH2)
// "1:65536;4:131072;5:16384|12517377||m,p,a,s"
```

## Request Builder

```go
req := client.NewRequest("POST", "https://api.example.com/data").
    SetHeader("content-type", "application/json").
    SetHeader("x-custom", "value").
    SetBody([]byte(`{"key":"value"}`)).
    SetCookie("session", "abc123")

resp, err := c.Do(req)
```

### Header Order

Headers are emitted in the profile's configured order, matching the browser's behavior:

```go
req := client.NewRequest("GET", "https://example.com").
    SetHeaderOrder([]string{"accept", "accept-language", "user-agent"})
```

## Response

```go
resp, err := c.Get("https://example.com")

resp.StatusCode    // 200
resp.Body          // []byte
resp.Headers       // []Header{{Name, Value}}
resp.Header("content-type")  // case-insensitive lookup
resp.Cookies()     // []*http.Cookie (parsed Set-Cookie headers)
resp.Release()     // nil out fields for GC
```

## Cookie Jar

```go
c := client.NewChromeClient()
c.CookieJar = client.NewCookieJar()

// Cookies are automatically stored from responses and sent with requests.
// Supports: domain matching, path prefix, expiry (Expires + MaxAge),
// Secure flag, and cookie replacement (same name+domain+path).
```

## Redirects

Redirects are followed automatically (configurable):

```go
c := client.NewChromeClient()
c.FollowRedirects = true  // default
c.MaxRedirects = 10       // default

// 301/302/303: method changes to GET, body dropped
// 307/308: method and body preserved
```

## Retry

```go
c := client.NewChromeClient()
c.RetryConfig = client.DefaultRetryConfig()

// DefaultRetryConfig:
//   MaxRetries:    3
//   InitialDelay:  500ms
//   MaxDelay:      30s
//   Multiplier:    2.0
//   Jitter:        0.1
//   RetryOn:       []int{429, 500, 502, 503, 504}
//   RetryOnError:  true
```

Retry uses exponential backoff with jitter: `delay = min(initialDelay * multiplier^attempt, maxDelay) * (1 + jitter*random)`.

## Connection Pool

The connection pool manages HTTP/2 connections with transparent multiplexing:

- **Auto-scaling**: opens new connections when existing ones are saturated
- **Max 6 connections per host** (configurable via `WithMaxConnsPerHost`)
- **Max 2 idle connections per host** (configurable via `WithMaxIdlePerHost`)
- **Health checks**: periodic PING to detect dead connections
- **GOAWAY handling**: graceful connection teardown with automatic retry
- **Wait timeout**: configurable backpressure when all connections are saturated

## Batch Requests

Send multiple requests concurrently on multiplexed connections:

```go
reqs := []*client.Request{
    client.NewRequest("GET", "https://api.example.com/users/1"),
    client.NewRequest("GET", "https://api.example.com/users/2"),
    client.NewRequest("GET", "https://api.example.com/users/3"),
}

resps, err := c.DoBatch(reqs)
// resps[i] corresponds to reqs[i]
```

## Proxy Support

### HTTP CONNECT Proxy

```go
c := client.NewChromeClient()
c.SetProxy("http://proxy.example.com:8080")
// or with auth:
c.SetProxyWithAuth("http://proxy.example.com:8080", "user", "pass")
```

### SOCKS5 Proxy

```go
c.SetSOCKS5Proxy("socks5-proxy.example.com:1080", "user", "pass")
```

The TLS handshake (with browser fingerprint) occurs **after** the proxy tunnel is established, preserving the fingerprint through the proxy.

## Performance

Benchmark results (Intel Xeon E5-2698 v4, local server):

| Benchmark | Result |
|---|---|
| Single request | ~135 µs/op |
| 100 multiplexed requests | > 15,000 req/s |
| Hot path allocations | ~14 allocs/op |

## Fingerprint Verification

### Local Verification

Run the validation test suite:

```bash
go test -v -race ./client/ -run TestFingerprint -count=1
```

This verifies:
- Chrome/Firefox H2 SETTINGS (IDs, values, order)
- Pseudo-header order (Chrome: m,a,s,p; Firefox: m,p,a,s)
- Akamai hash computation (4-section format)
- JA3 differs from Go default
- JA4 stability across connections
- 100-stream multiplexing performance

### External Verification

```bash
go test -v ./client/ -run TestFingerprint_TLSPeetWS
```

This sends a request to `tls.peet.ws/api/all` and logs the captured JA3, JA4, and HTTP/2 fingerprint.

## Package Structure

```
client/
├── client.go          Client API (Do, Get, Post, Head, DoBatch, Close)
├── conn.go            HTTP/2 client connection (Dial, roundTrip, handshake)
├── connpool.go        Connection pool with multiplexing
├── request.go         Request builder (NewRequest, SetHeader, SetBody)
├── response.go        Response (Header, Cookies, Release)
├── cookie.go          Thread-safe CookieJar
├── redirect.go        Redirect following (301-308)
├── retry.go           Retry with exponential backoff + jitter
├── proxy.go           HTTP CONNECT + SOCKS5 proxy
├── tls/
│   ├── config.go      TLS dialer (uTLS integration)
│   ├── profiles.go    Browser TLS profiles
│   ├── fingerprint.go TLS fingerprint types
│   ├── ja3.go         JA3 computation + ClientHello parsing
│   └── ja4.go         JA4 computation
└── h2fingerprint/
    ├── profile.go     H2Profile type
    ├── profiles.go    Chrome/Firefox H2 profiles
    └── akamai_hash.go Akamai HTTP/2 fingerprint hash
```
