package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blazehttp/blazehttp/client/h2fingerprint"
	blazetls "github.com/blazehttp/blazehttp/client/tls"
	"github.com/blazehttp/blazehttp/pkg/frame"
	"github.com/blazehttp/blazehttp/pkg/hpack"
	"github.com/blazehttp/blazehttp/server/http2"
)

// testClient creates a Client pointing at a local test server (insecure TLS).
func testClient(t *testing.T, addr string) *Client {
	t.Helper()
	c := NewChromeClient()
	c.dialer = blazetls.NewTLSDialer(blazetls.GoDefault).
		SetInsecureSkipVerify(true).
		SetTimeout(10 * time.Second)
	c.h2Profile = h2fingerprint.ChromeH2.Clone()
	c.pool = NewConnPool(c.dialer, c.h2Profile, WithHealthCheckInterval(0))
	return c
}

// --- Client basic tests ---

func TestClient_ChromeGet(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("chrome-ok")
	})
	defer cleanup()

	c := testClient(t, addr)
	defer c.Close()

	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "chrome-ok" {
		t.Errorf("body: got %q, want %q", resp.Body, "chrome-ok")
	}
}

func TestClient_FirefoxGet(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("firefox-ok")
	})
	defer cleanup()

	c := NewFirefoxClient()
	c.dialer = blazetls.NewTLSDialer(blazetls.GoDefault).
		SetInsecureSkipVerify(true).
		SetTimeout(10 * time.Second)
	c.pool = NewConnPool(c.dialer, c.h2Profile, WithHealthCheckInterval(0))
	defer c.Close()

	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "firefox-ok" {
		t.Errorf("body: got %q, want %q", resp.Body, "firefox-ok")
	}
}

func TestClient_Post(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		body := ctx.Request.Body()
		ct := string(ctx.Request.Header([]byte("content-type")))
		ctx.SetStatusCode(200)
		ctx.SetBodyString(ct + ":" + string(body))
	})
	defer cleanup()

	c := testClient(t, addr)
	defer c.Close()

	resp, err := c.Post("https://"+addr+"/echo", "application/json", []byte(`{"key":"value"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	want := `application/json:{"key":"value"}`
	if string(resp.Body) != want {
		t.Errorf("body: got %q, want %q", resp.Body, want)
	}
}

func TestClient_DoBatch(t *testing.T) {
	var count atomic.Int64

	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		n := count.Add(1)
		ctx.SetStatusCode(200)
		ctx.SetBodyString(fmt.Sprintf("%d", n))
	})
	defer cleanup()

	c := testClient(t, addr)
	defer c.Close()

	const N = 20
	reqs := make([]*Request, N)
	for i := 0; i < N; i++ {
		reqs[i] = NewRequest("GET", fmt.Sprintf("https://%s/%d", addr, i))
	}

	responses, err := c.DoBatch(reqs)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != N {
		t.Fatalf("responses: got %d, want %d", len(responses), N)
	}

	for i, resp := range responses {
		if resp.StatusCode != 200 {
			t.Errorf("request %d: status %d", i, resp.StatusCode)
		}
	}

	if count.Load() != N {
		t.Errorf("handler called %d times, want %d", count.Load(), N)
	}
}

func TestClient_CookieJar(t *testing.T) {
	var gotCookie atomic.Value
	var reqCount atomic.Int64

	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		n := reqCount.Add(1)
		if n == 1 {
			// First request: set a cookie.
			ctx.SetStatusCode(200)
			ctx.Response.SetHeader([]byte("set-cookie"), []byte("session=abc123; Path=/"))
		} else {
			// Second request: check the cookie is sent.
			c := string(ctx.Request.Header([]byte("cookie")))
			gotCookie.Store(c)
			ctx.SetStatusCode(200)
		}
	})
	defer cleanup()

	c := testClient(t, addr)
	c.CookieJar = NewCookieJar()
	defer c.Close()

	// First request sets cookie.
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	// Second request should send cookie.
	resp, err = c.Get("https://" + addr + "/page")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	v, ok := gotCookie.Load().(string)
	if !ok || !strings.Contains(v, "session=abc123") {
		t.Errorf("cookie not propagated: got %q", v)
	}
}

func TestClient_Redirect301(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fr := frame.AcquireFrameReader(conn)
				fw := frame.AcquireFrameWriter(conn)
				defer frame.ReleaseFrameReader(fr)
				defer frame.ReleaseFrameWriter(fw)

				enc := hpack.AcquireEncoder()
				defer hpack.ReleaseEncoder(enc)

				if err := rawServerHandshake(conn, fr, fw); err != nil {
					return
				}

				dec := hpack.AcquireDecoder()
				defer hpack.ReleaseDecoder(dec)

				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if f.Type == frame.FrameHeaders {
						fields, _ := dec.Decode(f.HeaderBlock)
						var path string
						for _, hf := range fields {
							if string(hf.Name) == ":path" {
								path = string(hf.Value)
							}
						}

						if path == "/old" {
							hdr := enc.Encode([]hpack.HeaderField{
								{Name: []byte(":status"), Value: []byte("301")},
								{Name: []byte("location"), Value: []byte("https://" + addr + "/new")},
							})
							fw.WriteHeaders(f.StreamID, true, hdr, nil)
						} else {
							hdr := enc.Encode([]hpack.HeaderField{
								{Name: []byte(":status"), Value: []byte("200")},
							})
							fw.WriteHeaders(f.StreamID, false, hdr, nil)
							fw.WriteData(f.StreamID, true, []byte("final"))
						}
						fw.Flush()
					}
				}
			}(conn)
		}
	}()

	c := testClient(t, addr)
	defer c.Close()

	resp, err := c.Get("https://" + addr + "/old")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "final" {
		t.Errorf("body: got %q, want %q", resp.Body, "final")
	}
}

func TestClient_Redirect307(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	var gotMethod atomic.Value

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fr := frame.AcquireFrameReader(conn)
				fw := frame.AcquireFrameWriter(conn)
				defer frame.ReleaseFrameReader(fr)
				defer frame.ReleaseFrameWriter(fw)

				enc := hpack.AcquireEncoder()
				defer hpack.ReleaseEncoder(enc)

				if err := rawServerHandshake(conn, fr, fw); err != nil {
					return
				}

				dec := hpack.AcquireDecoder()
				defer hpack.ReleaseDecoder(dec)

				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if f.Type == frame.FrameHeaders {
						fields, _ := dec.Decode(f.HeaderBlock)
						var path, method string
						for _, hf := range fields {
							switch string(hf.Name) {
							case ":path":
								path = string(hf.Value)
							case ":method":
								method = string(hf.Value)
							}
						}

						if path == "/api" {
							hdr := enc.Encode([]hpack.HeaderField{
								{Name: []byte(":status"), Value: []byte("307")},
								{Name: []byte("location"), Value: []byte("https://" + addr + "/api/v2")},
							})
							fw.WriteHeaders(f.StreamID, true, hdr, nil)
						} else {
							gotMethod.Store(method)
							hdr := enc.Encode([]hpack.HeaderField{
								{Name: []byte(":status"), Value: []byte("200")},
							})
							fw.WriteHeaders(f.StreamID, true, hdr, nil)
						}
						fw.Flush()
					}
				}
			}(conn)
		}
	}()

	c := testClient(t, addr)
	defer c.Close()

	resp, err := c.Post("https://"+addr+"/api", "application/json", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}

	if m, _ := gotMethod.Load().(string); m != "POST" {
		t.Errorf("method after 307: got %q, want POST", m)
	}
}

func TestClient_RedirectMax(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fr := frame.AcquireFrameReader(conn)
				fw := frame.AcquireFrameWriter(conn)
				defer frame.ReleaseFrameReader(fr)
				defer frame.ReleaseFrameWriter(fw)

				enc := hpack.AcquireEncoder()
				defer hpack.ReleaseEncoder(enc)

				if err := rawServerHandshake(conn, fr, fw); err != nil {
					return
				}

				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if f.Type == frame.FrameHeaders {
						// Always redirect.
						hdr := enc.Encode([]hpack.HeaderField{
							{Name: []byte(":status"), Value: []byte("302")},
							{Name: []byte("location"), Value: []byte("https://" + addr + "/loop")},
						})
						fw.WriteHeaders(f.StreamID, true, hdr, nil)
						fw.Flush()
					}
				}
			}(conn)
		}
	}()

	c := testClient(t, addr)
	c.MaxRedirects = 3
	defer c.Close()

	_, err = c.Get("https://" + addr + "/loop")
	if err == nil {
		t.Fatal("expected error for too many redirects")
	}
	if !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_Retry503(t *testing.T) {
	var count atomic.Int64

	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		n := count.Add(1)
		if n <= 2 {
			ctx.SetStatusCode(503)
			return
		}
		ctx.SetStatusCode(200)
		ctx.SetBodyString("recovered")
	})
	defer cleanup()

	c := testClient(t, addr)
	c.RetryConfig = &RetryConfig{
		MaxRetries:   5,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		Jitter:       0.0,
		RetryOn:      []int{503},
		RetryOnError: false,
	}
	defer c.Close()

	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "recovered" {
		t.Errorf("body: got %q, want %q", resp.Body, "recovered")
	}
	if count.Load() != 3 {
		t.Errorf("handler called %d times, want 3", count.Load())
	}
}

func TestClient_Close(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	c := testClient(t, addr)

	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	c.Close()

	_, err = c.Get("https://" + addr + "/")
	if err == nil {
		t.Error("expected error after Close")
	}
}

func TestClient_UserAgent(t *testing.T) {
	var gotUA atomic.Value

	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ua := string(ctx.Request.Header([]byte("user-agent")))
		gotUA.Store(ua)
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	c := testClient(t, addr)
	c.UserAgent = "BlazeHTTP-Test/1.0"
	defer c.Close()

	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	if ua, _ := gotUA.Load().(string); ua != "BlazeHTTP-Test/1.0" {
		t.Errorf("user-agent: got %q, want %q", ua, "BlazeHTTP-Test/1.0")
	}
}

func TestClient_Concurrent(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	c := testClient(t, addr)
	defer c.Close()

	const N = 50
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get("https://" + addr + "/")
			if err != nil {
				errs <- err
				return
			}
			if resp.StatusCode != 200 {
				errs <- fmt.Errorf("status: %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// --- CookieJar unit tests ---

func TestCookieJar_DomainMatch(t *testing.T) {
	jar := NewCookieJar()

	u, _ := url.Parse("https://example.com/")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "a", Value: "1", Domain: "example.com", Path: "/"},
	})

	// Exact match.
	cookies := jar.Cookies(u)
	if len(cookies) != 1 || cookies[0].Value != "1" {
		t.Errorf("exact match: got %v", cookies)
	}

	// Subdomain match.
	sub, _ := url.Parse("https://sub.example.com/")
	cookies = jar.Cookies(sub)
	if len(cookies) != 1 || cookies[0].Value != "1" {
		t.Errorf("subdomain match: got %v", cookies)
	}

	// No match.
	other, _ := url.Parse("https://other.com/")
	cookies = jar.Cookies(other)
	if len(cookies) != 0 {
		t.Errorf("no match: got %v", cookies)
	}
}

func TestCookieJar_PathMatch(t *testing.T) {
	jar := NewCookieJar()

	u, _ := url.Parse("https://example.com/api")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "token", Value: "xyz", Path: "/api"},
	})

	// Exact path.
	cookies := jar.Cookies(u)
	if len(cookies) != 1 {
		t.Errorf("exact path: got %d cookies", len(cookies))
	}

	// Sub-path.
	sub, _ := url.Parse("https://example.com/api/v1")
	cookies = jar.Cookies(sub)
	if len(cookies) != 1 {
		t.Errorf("sub-path: got %d cookies", len(cookies))
	}

	// Non-matching path.
	other, _ := url.Parse("https://example.com/web")
	cookies = jar.Cookies(other)
	if len(cookies) != 0 {
		t.Errorf("non-matching path: got %d cookies", len(cookies))
	}
}

func TestCookieJar_Expiry(t *testing.T) {
	jar := NewCookieJar()

	u, _ := url.Parse("https://example.com/")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "expired", Value: "old", Path: "/", Expires: time.Now().Add(-time.Hour)},
		{Name: "valid", Value: "new", Path: "/", Expires: time.Now().Add(time.Hour)},
	})

	cookies := jar.Cookies(u)
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "valid" {
		t.Errorf("expected valid cookie, got %q", cookies[0].Name)
	}
}

func TestCookieJar_Secure(t *testing.T) {
	jar := NewCookieJar()

	u, _ := url.Parse("https://example.com/")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "sec", Value: "1", Path: "/", Secure: true},
	})

	// HTTPS: should get cookie.
	cookies := jar.Cookies(u)
	if len(cookies) != 1 {
		t.Errorf("https: got %d cookies", len(cookies))
	}

	// HTTP: should not get cookie.
	httpURL, _ := url.Parse("http://example.com/")
	cookies = jar.Cookies(httpURL)
	if len(cookies) != 0 {
		t.Errorf("http: got %d cookies (secure cookie should not be sent)", len(cookies))
	}
}

// --- Retry unit tests ---

func TestRetry_Backoff(t *testing.T) {
	rc := DefaultRetryConfig()
	rc.Jitter = 0 // deterministic

	d0 := rc.delay(0)
	d1 := rc.delay(1)
	d2 := rc.delay(2)

	if d0 != 500*time.Millisecond {
		t.Errorf("delay(0): got %v, want 500ms", d0)
	}
	if d1 != 1*time.Second {
		t.Errorf("delay(1): got %v, want 1s", d1)
	}
	if d2 != 2*time.Second {
		t.Errorf("delay(2): got %v, want 2s", d2)
	}

	// Test max delay cap.
	rc.MaxDelay = 1 * time.Second
	d3 := rc.delay(10) // would be 500ms * 2^10 = 512s without cap
	if d3 != 1*time.Second {
		t.Errorf("delay(10) with cap: got %v, want 1s", d3)
	}
}

func TestRetry_ShouldRetry(t *testing.T) {
	rc := DefaultRetryConfig()

	// Retry on 503.
	if !rc.shouldRetry(&Response{StatusCode: 503}, nil) {
		t.Error("should retry 503")
	}
	// Don't retry on 404.
	if rc.shouldRetry(&Response{StatusCode: 404}, nil) {
		t.Error("should not retry 404")
	}
	// Retry on error.
	if !rc.shouldRetry(nil, fmt.Errorf("network error")) {
		t.Error("should retry on error")
	}
}

// --- Proxy unit tests ---

func TestProxy_CONNECT(t *testing.T) {
	// Create a minimal CONNECT proxy.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	var gotConnect atomic.Bool

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				req := string(buf[:n])
				if strings.HasPrefix(req, "CONNECT ") {
					gotConnect.Store(true)
					// Send 200 OK.
					conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
					// Now we should forward data, but for this test we just validate
					// the CONNECT was issued.
					// Read any further data and discard.
					time.Sleep(100 * time.Millisecond)
				}
			}(conn)
		}
	}()

	pd, err := newProxyDialer("http://"+proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// This will connect through proxy, but TLS handshake will fail (no real server).
	// We just verify the CONNECT request was sent.
	conn, err := pd.dialCONNECT("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	if !gotConnect.Load() {
		t.Error("proxy did not receive CONNECT request")
	}
}

// --- Request builder tests ---

func TestRequest_Builder(t *testing.T) {
	req := NewRequest("POST", "https://example.com/api/v1").
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer token").
		SetBody([]byte(`{"key":"value"}`)).
		SetCookie("session", "abc123")

	h2req, addr, err := req.toH2Request()
	if err != nil {
		t.Fatal(err)
	}

	if addr != "example.com:443" {
		t.Errorf("addr: got %q, want %q", addr, "example.com:443")
	}
	if h2req.Method != "POST" {
		t.Errorf("method: got %q, want POST", h2req.Method)
	}
	if h2req.Scheme != "https" {
		t.Errorf("scheme: got %q, want https", h2req.Scheme)
	}
	if h2req.Authority != "example.com" {
		t.Errorf("authority: got %q, want example.com", h2req.Authority)
	}
	if h2req.Path != "/api/v1" {
		t.Errorf("path: got %q, want /api/v1", h2req.Path)
	}
	if string(h2req.Body) != `{"key":"value"}` {
		t.Errorf("body: got %q", h2req.Body)
	}

	// Check cookie header is set.
	hasCookie := false
	for _, h := range h2req.Headers {
		if h.Name == "cookie" && strings.Contains(h.Value, "session=abc123") {
			hasCookie = true
		}
	}
	if !hasCookie {
		t.Error("cookie header not set")
	}
}

func TestRequest_URLWithPort(t *testing.T) {
	req := NewRequest("GET", "https://example.com:8443/path")
	_, addr, err := req.toH2Request()
	if err != nil {
		t.Fatal(err)
	}
	if addr != "example.com:8443" {
		t.Errorf("addr: got %q, want example.com:8443", addr)
	}
}

// --- Response tests ---

func TestResponse_Header(t *testing.T) {
	resp := &Response{
		Headers: []Header{
			{Name: "content-type", Value: "text/plain"},
			{Name: "X-Custom", Value: "value"},
		},
	}

	if resp.Header("Content-Type") != "text/plain" {
		t.Errorf("Content-Type: got %q", resp.Header("Content-Type"))
	}
	if resp.Header("x-custom") != "value" {
		t.Errorf("x-custom: got %q", resp.Header("x-custom"))
	}
	if resp.Header("missing") != "" {
		t.Errorf("missing: got %q", resp.Header("missing"))
	}
}

func TestResponse_Release(t *testing.T) {
	resp := &Response{
		Body:    []byte("data"),
		Headers: []Header{{Name: "a", Value: "b"}},
	}
	resp.Release()
	if resp.Body != nil || resp.Headers != nil {
		t.Error("Release did not nil out fields")
	}
}

// --- Redirect unit tests ---

func TestShouldRedirect(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		if !shouldRedirect(code) {
			t.Errorf("shouldRedirect(%d) = false", code)
		}
	}
	for _, code := range []int{200, 404, 500} {
		if shouldRedirect(code) {
			t.Errorf("shouldRedirect(%d) = true", code)
		}
	}
}

func TestFollowRedirect_303_MethodChange(t *testing.T) {
	original := &Request{
		method: "POST",
		rawURL: "https://example.com/submit",
		body:   []byte("data"),
	}
	resp := &Response{
		StatusCode: 303,
		Headers:    []Header{{Name: "location", Value: "/result"}},
	}

	newReq, err := followRedirect(original, resp, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if newReq.method != "GET" {
		t.Errorf("method: got %q, want GET", newReq.method)
	}
	if newReq.body != nil {
		t.Error("body should be nil after 303")
	}
}

func TestFollowRedirect_308_PreservesBody(t *testing.T) {
	original := &Request{
		method:  "POST",
		rawURL:  "https://example.com/submit",
		body:    []byte("body-data"),
		headers: []Header{{Name: "content-type", Value: "application/json"}},
	}
	resp := &Response{
		StatusCode: 308,
		Headers:    []Header{{Name: "location", Value: "https://example.com/new"}},
	}

	newReq, err := followRedirect(original, resp, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if newReq.method != "POST" {
		t.Errorf("method: got %q, want POST", newReq.method)
	}
	if string(newReq.body) != "body-data" {
		t.Errorf("body should be preserved after 308, got %q", newReq.body)
	}
}

func TestFollowRedirect_TooMany(t *testing.T) {
	original := &Request{method: "GET", rawURL: "https://example.com/"}
	resp := &Response{
		StatusCode: 302,
		Headers:    []Header{{Name: "location", Value: "/new"}},
	}
	_, err := followRedirect(original, resp, 3, 3)
	if err != ErrTooManyRedirects {
		t.Errorf("expected ErrTooManyRedirects, got %v", err)
	}
}

func TestFollowRedirect_NoLocation(t *testing.T) {
	original := &Request{method: "GET", rawURL: "https://example.com/"}
	resp := &Response{StatusCode: 302, Headers: nil}
	_, err := followRedirect(original, resp, 10, 0)
	if err == nil {
		t.Error("expected error for redirect with no Location header")
	}
}

// --- Additional Client tests ---

func TestClient_Head(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	c := testClient(t, addr)
	defer c.Close()

	resp, err := c.Head("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestClient_SafariConstructor(t *testing.T) {
	c := NewSafariClient()
	if c.UserAgent == "" {
		t.Error("Safari client has no UserAgent")
	}
	if c.h2Profile == nil {
		t.Error("Safari client has no H2Profile")
	}
}

func TestClient_RandomConstructor(t *testing.T) {
	c := NewRandomClient()
	if c.UserAgent == "" {
		t.Error("Random client has no UserAgent")
	}
}

func TestClient_SetProxy(t *testing.T) {
	c := NewChromeClient()
	if err := c.SetProxy("http://proxy.example.com:8080"); err != nil {
		t.Fatal(err)
	}
	if c.pd == nil {
		t.Error("proxy dialer not set")
	}
}

func TestClient_SetProxyWithAuth(t *testing.T) {
	c := NewChromeClient()
	if err := c.SetProxyWithAuth("http://proxy.example.com:8080", "user", "pass"); err != nil {
		t.Fatal(err)
	}
	if c.pd.user != "user" || c.pd.pass != "pass" {
		t.Error("proxy auth not set")
	}
}

func TestClient_SetSOCKS5Proxy(t *testing.T) {
	c := NewChromeClient()
	if err := c.SetSOCKS5Proxy("proxy.example.com:1080", "user", "pass"); err != nil {
		t.Fatal(err)
	}
	if c.pd == nil {
		t.Error("SOCKS5 proxy not set")
	}
	if c.pd.proxyURL.Scheme != "socks5" {
		t.Errorf("scheme: got %q, want socks5", c.pd.proxyURL.Scheme)
	}
}

func TestCookieJar_Replace(t *testing.T) {
	jar := NewCookieJar()

	u, _ := url.Parse("https://example.com/")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "a", Value: "1", Path: "/"},
	})
	jar.SetCookies(u, []*http.Cookie{
		{Name: "a", Value: "2", Path: "/"},
	})

	cookies := jar.Cookies(u)
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Value != "2" {
		t.Errorf("cookie not replaced: got %q, want %q", cookies[0].Value, "2")
	}
}

func TestCookieJar_MaxAge(t *testing.T) {
	jar := NewCookieJar()

	u, _ := url.Parse("https://example.com/")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "a", Value: "1", Path: "/", MaxAge: -1}, // delete
	})

	cookies := jar.Cookies(u)
	if len(cookies) != 0 {
		t.Errorf("expected 0 cookies (MaxAge=-1), got %d", len(cookies))
	}
}

func TestResponse_Cookies(t *testing.T) {
	resp := &Response{
		Headers: []Header{
			{Name: "set-cookie", Value: "a=1; Path=/"},
			{Name: "set-cookie", Value: "b=2; Path=/; HttpOnly"},
		},
	}
	cookies := resp.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies[0].Name != "a" || cookies[0].Value != "1" {
		t.Errorf("cookie 0: %v", cookies[0])
	}
	if cookies[1].Name != "b" || cookies[1].Value != "2" {
		t.Errorf("cookie 1: %v", cookies[1])
	}
}

func TestRequest_SetHeaders(t *testing.T) {
	req := NewRequest("GET", "https://example.com/").
		SetHeaders(map[string]string{
			"Accept":       "text/html",
			"Content-Type": "text/plain",
		})

	if len(req.headers) != 2 {
		t.Errorf("expected 2 headers, got %d", len(req.headers))
	}
}

func TestRequest_SetHeaderOrder(t *testing.T) {
	req := NewRequest("GET", "https://example.com/").
		SetHeader("b", "2").
		SetHeader("a", "1").
		SetHeader("c", "3").
		SetHeaderOrder([]string{"a", "c", "b"})

	if len(req.headers) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(req.headers))
	}
	if req.headers[0].Name != "a" || req.headers[1].Name != "c" || req.headers[2].Name != "b" {
		t.Errorf("order: got %v %v %v", req.headers[0].Name, req.headers[1].Name, req.headers[2].Name)
	}
}

func TestProxy_InvalidScheme(t *testing.T) {
	pd, err := newProxyDialer("ftp://proxy.example.com", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pd.dial("example.com:443")
	if err == nil {
		t.Error("expected error for unsupported proxy scheme")
	}
}

func TestProxy_CONNECTWithAuth(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	var gotAuth atomic.Value

	go func() {
		conn, err := proxyLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		req := string(buf[:n])
		for _, line := range strings.Split(req, "\r\n") {
			if strings.HasPrefix(line, "Proxy-Authorization:") {
				gotAuth.Store(line)
			}
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		time.Sleep(100 * time.Millisecond)
	}()

	pd, err := newProxyDialer("http://"+proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pd.user = "user"
	pd.pass = "pass"

	conn, err := pd.dialCONNECT("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	if auth, _ := gotAuth.Load().(string); !strings.Contains(auth, "Basic") {
		t.Errorf("expected Basic auth header, got %q", auth)
	}
}

func TestDefaultCookiePath(t *testing.T) {
	tests := []struct {
		path, want string
	}{
		{"/foo/bar", "/foo"},
		{"/", "/"},
		{"", "/"},
		{"/a", "/"},
		{"/a/b/c", "/a/b"},
	}
	for _, tt := range tests {
		got := defaultCookiePath(tt.path)
		if got != tt.want {
			t.Errorf("defaultCookiePath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestWithDialTimeout(t *testing.T) {
	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	p := NewConnPool(dialer, profile,
		WithDialTimeout(5*time.Second),
		WithWaitTimeout(10*time.Second),
		WithHealthCheckInterval(0),
	)
	defer p.Close()

	if p.dialTimeout != 5*time.Second {
		t.Errorf("dialTimeout: got %v, want 5s", p.dialTimeout)
	}
	if p.waitTimeout != 10*time.Second {
		t.Errorf("waitTimeout: got %v, want 10s", p.waitTimeout)
	}
}

func TestFromH2Response(t *testing.T) {
	h2 := &h2Response{
		StatusCode: 200,
		Headers:    []Header{{Name: "x-test", Value: "1"}},
		Body:       []byte("body"),
	}
	resp := fromH2Response(h2, "https://example.com/")
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if resp.URL != "https://example.com/" {
		t.Errorf("URL: %q", resp.URL)
	}
	if string(resp.Body) != "body" {
		t.Errorf("body: %q", resp.Body)
	}
}
