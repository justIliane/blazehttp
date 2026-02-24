package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/justIliane/blazehttp/client/h2fingerprint"
	blazetls "github.com/justIliane/blazehttp/client/tls"
	"github.com/justIliane/blazehttp/pkg/frame"
	"github.com/justIliane/blazehttp/pkg/hpack"
	"github.com/justIliane/blazehttp/server/http2"
)

// --- Helpers ---

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}

// testH2Server starts a TLS+HTTP/2 server with the given handler and returns
// the address and a cleanup function.
func testH2Server(t *testing.T, handler http2.RequestHandler) (string, func()) {
	t.Helper()

	cert := testCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	wp := http2.NewWorkerPool(4, handler)

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				http2.ServeConn(c, &http2.ConnConfig{
					Handler:    handler,
					WorkerPool: wp,
					Settings:   http2.DefaultServerSettings(),
				})
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		ln.Close()
		wg.Wait()
		wp.Stop()
	}

	return ln.Addr().String(), cleanup
}

// dialLocal creates a ClientConn to a local test server.
func dialLocal(t *testing.T, addr string) *ClientConn {
	t.Helper()
	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(addr, dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

// rawServerHandshake performs the server side of the HTTP/2 handshake on a raw
// connection. It reads the client preface and settings, sends server settings,
// drains intermediate frames (WINDOW_UPDATE, PRIORITY) until it receives the
// client SETTINGS ACK, then sends its own SETTINGS ACK.
func rawServerHandshake(conn net.Conn, fr *frame.FrameReader, fw *frame.FrameWriter, settings ...frame.Setting) error {
	// Read client preface magic.
	preface := make([]byte, 24)
	if _, err := conn.Read(preface); err != nil {
		return err
	}

	// Read client SETTINGS.
	if _, err := fr.ReadFrame(); err != nil {
		return err
	}

	// Send server SETTINGS.
	if len(settings) == 0 {
		settings = []frame.Setting{{ID: frame.SettingsMaxConcurrentStreams, Value: 100}}
	}
	fw.WriteSettings(settings...)
	fw.Flush()

	// Drain until we get client SETTINGS ACK.
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		if f.Type == frame.FrameSettings && f.Flags.Has(frame.FlagACK) {
			break
		}
	}

	// Send SETTINGS ACK.
	fw.WriteSettingsACK()
	return fw.Flush()
}

// --- Tests ---

func TestDial_LocalServer(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	if cc.GoingAway() {
		t.Error("should not be going away")
	}
}

func TestRoundTrip_GET(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBodyString("hello world")
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "hello world" {
		t.Errorf("body: got %q, want %q", resp.Body, "hello world")
	}

	// Check content-type header
	found := false
	for _, h := range resp.Headers {
		if h.Name == "content-type" && h.Value == "text/plain" {
			found = true
		}
	}
	if !found {
		t.Error("missing content-type header")
	}
}

func TestRoundTrip_POST(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		method := string(ctx.Request.Method())
		body := ctx.Request.Body()
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		// Echo back method + body
		ctx.SetBodyString(method + ":" + string(body))
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method:    "POST",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/echo",
		Body:      []byte("test body"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "POST:test body" {
		t.Errorf("body: got %q, want %q", resp.Body, "POST:test body")
	}
}

func TestRoundTrip_Concurrent(t *testing.T) {
	var counter atomic.Int32

	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		n := counter.Add(1)
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
		_ = n
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := cc.roundTrip(&h2Request{
				Method:    "GET",
				Scheme:    "https",
				Authority: "localhost",
				Path:      "/",
			})
			if err != nil {
				errs <- err
				return
			}
			if resp.StatusCode != 200 {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent request error: %v", err)
	}

	if int(counter.Load()) != N {
		t.Errorf("handler called %d times, want %d", counter.Load(), N)
	}
}

func TestRoundTrip_LargeBody(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		body := ctx.Request.Body()
		ctx.SetStatusCode(200)
		ctx.SetBodyString(string(body))
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	// 256KB body to test flow control.
	largeBody := bytes.Repeat([]byte("A"), 256*1024)

	resp, err := cc.roundTrip(&h2Request{
		Method:    "POST",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/large",
		Body:      largeBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if len(resp.Body) != len(largeBody) {
		t.Errorf("body length: got %d, want %d", len(resp.Body), len(largeBody))
	}
	if !bytes.Equal(resp.Body, largeBody) {
		t.Error("body content mismatch")
	}
}

func TestPingPong(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	// Send PING — the server should respond with PONG.
	cc.Ping()

	// Verify connection is still alive by making a request.
	time.Sleep(50 * time.Millisecond)

	resp, err := cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

func TestGOAWAY(t *testing.T) {
	// Use a raw TLS server to send GOAWAY manually.
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		if err := rawServerHandshake(conn, fr, fw); err != nil {
			return
		}

		// Wait a bit, then send GOAWAY.
		time.Sleep(100 * time.Millisecond)
		fw.WriteGoAway(0, frame.ErrCodeNoError, nil)
		fw.Flush()

		// Keep connection alive briefly for client to read GOAWAY.
		time.Sleep(200 * time.Millisecond)
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(ln.Addr().String(), dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	// Wait for GOAWAY to be processed.
	time.Sleep(200 * time.Millisecond)

	if !cc.GoingAway() {
		t.Error("expected GoingAway after GOAWAY")
	}
}

func TestRSTStream(t *testing.T) {
	// Raw server that resets the first stream.
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		if err := rawServerHandshake(conn, fr, fw); err != nil {
			return
		}

		// Read the HEADERS frame from client (stream 1).
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}

		// Reset that stream.
		fw.WriteRSTStream(f.StreamID, frame.ErrCodeCancel)
		fw.Flush()

		time.Sleep(200 * time.Millisecond)
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(ln.Addr().String(), dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	_, err = cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err == nil {
		t.Fatal("expected error from RST_STREAM")
	}
}

func TestSettingsExchange(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	// After handshake, peer settings should reflect server's SETTINGS.
	ps := cc.PeerSettings()
	// Server sends DefaultServerSettings: MaxConcurrentStreams=250, InitialWindowSize=1MB.
	if ps.MaxConcurrentStreams != 250 {
		t.Errorf("MaxConcurrentStreams: got %d, want 250", ps.MaxConcurrentStreams)
	}
	if ps.InitialWindowSize != 1<<20 {
		t.Errorf("InitialWindowSize: got %d, want %d", ps.InitialWindowSize, 1<<20)
	}
}

func TestClose(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		// Slow handler.
		time.Sleep(500 * time.Millisecond)
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)

	// Start a request in background.
	errCh := make(chan error, 1)
	go func() {
		_, err := cc.roundTrip(&h2Request{
			Method:    "GET",
			Scheme:    "https",
			Authority: "localhost",
			Path:      "/slow",
		})
		errCh <- err
	}()

	// Let request start, then close.
	time.Sleep(50 * time.Millisecond)
	cc.Close()

	err := <-errCh
	if err == nil {
		t.Error("expected error after close")
	}
}

func TestMultipleSequentialRequests(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		path := string(ctx.Request.Path())
		ctx.SetStatusCode(200)
		ctx.SetBodyString(path)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	for i := 0; i < 5; i++ {
		resp, err := cc.roundTrip(&h2Request{
			Method:    "GET",
			Scheme:    "https",
			Authority: "localhost",
			Path:      "/test",
		})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("request %d: status %d", i, resp.StatusCode)
		}
		if string(resp.Body) != "/test" {
			t.Errorf("request %d: body %q", i, resp.Body)
		}
	}
}

func TestRoundTrip_HeadersPassedThrough(t *testing.T) {
	var receivedUA string

	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		receivedUA = string(ctx.Request.Header([]byte("user-agent")))
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
		Headers: []Header{
			{Name: "user-agent", Value: "BlazeHTTP/1.0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if receivedUA != "BlazeHTTP/1.0" {
		t.Errorf("user-agent: got %q, want %q", receivedUA, "BlazeHTTP/1.0")
	}
}

func TestActiveStreams(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	// No active streams initially.
	if cc.ActiveStreams() != 0 {
		t.Errorf("active streams: got %d, want 0", cc.ActiveStreams())
	}

	resp, err := cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}

	// After response, stream should be closed.
	// Give readLoop a moment.
	time.Sleep(50 * time.Millisecond)
	if cc.ActiveStreams() != 0 {
		t.Errorf("active streams after response: got %d, want 0", cc.ActiveStreams())
	}
}

func TestDialNotH2(t *testing.T) {
	cert := testCert(t)
	// Server that doesn't offer h2.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	_, err = Dial(ln.Addr().String(), dialer, profile)
	if err == nil {
		t.Fatal("expected error when server does not support h2")
	}
	// Accept either ErrNotH2 (ALPN negotiated a non-h2 proto) or a TLS/connection
	// error (server may reject when no ALPN protocol matches).
}

// --- Settings ---

func TestDefaultPeerSettings(t *testing.T) {
	ps := defaultPeerSettings()
	if ps.HeaderTableSize != 4096 {
		t.Errorf("HeaderTableSize: %d", ps.HeaderTableSize)
	}
	if ps.MaxConcurrentStreams != 100 {
		t.Errorf("MaxConcurrentStreams: %d", ps.MaxConcurrentStreams)
	}
	if ps.InitialWindowSize != 65535 {
		t.Errorf("InitialWindowSize: %d", ps.InitialWindowSize)
	}
	if ps.MaxFrameSize != 16384 {
		t.Errorf("MaxFrameSize: %d", ps.MaxFrameSize)
	}
}

func TestPeerSettings_Apply(t *testing.T) {
	ps := defaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: frame.SettingsMaxConcurrentStreams, Value: 500}
	settings[1] = frame.Setting{ID: frame.SettingsInitialWindowSize, Value: 1 << 20}

	old, err := ps.apply(settings, 2)
	if err != nil {
		t.Fatal(err)
	}
	if old != 65535 {
		t.Errorf("old window size: %d", old)
	}
	if ps.MaxConcurrentStreams != 500 {
		t.Errorf("MaxConcurrentStreams: %d", ps.MaxConcurrentStreams)
	}
	if ps.InitialWindowSize != 1<<20 {
		t.Errorf("InitialWindowSize: %d", ps.InitialWindowSize)
	}
}

func TestPeerSettings_Apply_InvalidEnablePush(t *testing.T) {
	ps := defaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: frame.SettingsEnablePush, Value: 2}

	_, err := ps.apply(settings, 1)
	if err == nil {
		t.Error("expected error for ENABLE_PUSH=2")
	}
}

func TestPeerSettings_Apply_InvalidWindowSize(t *testing.T) {
	ps := defaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: frame.SettingsInitialWindowSize, Value: 1 << 31}

	_, err := ps.apply(settings, 1)
	if err == nil {
		t.Error("expected error for oversized window")
	}
}

func TestPeerSettings_Apply_InvalidMaxFrameSize(t *testing.T) {
	ps := defaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: frame.SettingsMaxFrameSize, Value: 100} // too small

	_, err := ps.apply(settings, 1)
	if err == nil {
		t.Error("expected error for too-small MAX_FRAME_SIZE")
	}
}

// --- isSensitiveHeader ---

func TestIsSensitiveHeader(t *testing.T) {
	if !isSensitiveHeader("authorization") {
		t.Error("authorization should be sensitive")
	}
	if !isSensitiveHeader("cookie") {
		t.Error("cookie should be sensitive")
	}
	if isSensitiveHeader("accept") {
		t.Error("accept should not be sensitive")
	}
}

// --- RoundTrip after GoAway ---

func TestRoundTrip_AfterGoAway(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	// Simulate GoAway.
	cc.goingAway.Store(true)

	_, err := cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err != ErrGoAway {
		t.Errorf("expected ErrGoAway, got %v", err)
	}
}

// --- Empty body response ---

func TestRoundTrip_EmptyBody(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(204) // No content.
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method:    "DELETE",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/resource",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Errorf("status: got %d, want 204", resp.StatusCode)
	}
	if len(resp.Body) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(resp.Body))
	}
}

// --- Server-initiated PING (server sends PING, client must respond with PONG) ---

func TestServerPing(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var gotPingACK atomic.Bool

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		if err := rawServerHandshake(conn, fr, fw); err != nil {
			return
		}

		// Send PING to client.
		var pingData [8]byte
		copy(pingData[:], []byte("testping"))
		fw.WritePing(false, pingData)
		fw.Flush()

		// Read frames until we get PING ACK or HEADERS.
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if f.Type == frame.FramePing && f.Flags.Has(frame.FlagACK) {
				if f.PingData == pingData {
					gotPingACK.Store(true)
				}
			}
			if f.Type == frame.FrameHeaders {
				// Send back 200 OK.
				enc := hpack.AcquireEncoder()
				defer hpack.ReleaseEncoder(enc)
				hdr := enc.Encode([]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}})
				fw.WriteHeaders(f.StreamID, true, hdr, nil)
				fw.Flush()
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(ln.Addr().String(), dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	// Small delay for PING/PONG exchange.
	time.Sleep(50 * time.Millisecond)

	resp, err := cc.roundTrip(&h2Request{
		Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if !gotPingACK.Load() {
		t.Error("server did not receive PING ACK from client")
	}
}

// --- Server sends SETTINGS mid-connection (handleSettings non-ACK) ---

func TestServerSettingsMidConnection(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		if err := rawServerHandshake(conn, fr, fw); err != nil {
			return
		}

		// Send new SETTINGS mid-connection (to trigger handleSettings non-ACK).
		fw.WriteSettings(
			frame.Setting{ID: frame.SettingsMaxConcurrentStreams, Value: 50},
			frame.Setting{ID: frame.SettingsMaxFrameSize, Value: 32768},
		)
		fw.Flush()

		enc := hpack.AcquireEncoder()
		defer hpack.ReleaseEncoder(enc)

		// Handle remaining frames.
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if f.Type == frame.FrameHeaders {
				hdr := enc.Encode([]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}})
				fw.WriteHeaders(f.StreamID, true, hdr, nil)
				fw.Flush()
			}
		}
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(ln.Addr().String(), dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	// Wait for new settings to be applied.
	time.Sleep(100 * time.Millisecond)

	ps := cc.PeerSettings()
	if ps.MaxConcurrentStreams != 50 {
		t.Errorf("MaxConcurrentStreams: got %d, want 50", ps.MaxConcurrentStreams)
	}
	if ps.MaxFrameSize != 32768 {
		t.Errorf("MaxFrameSize: got %d, want 32768", ps.MaxFrameSize)
	}

	// Connection should still work.
	resp, err := cc.roundTrip(&h2Request{
		Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// --- Flow control: server with tiny initial window to force waitForSendWindow ---

func TestFlowControlPressure(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		preface := make([]byte, 24)
		conn.Read(preface)

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		// Read client SETTINGS.
		fr.ReadFrame()

		// Send server SETTINGS with small initial window (1024 bytes).
		fw.WriteSettings(
			frame.Setting{ID: frame.SettingsMaxConcurrentStreams, Value: 100},
			frame.Setting{ID: frame.SettingsInitialWindowSize, Value: 1024},
		)
		fw.Flush()

		// Drain remaining handshake frames (WINDOW_UPDATE, PRIORITY, SETTINGS ACK).
		gotSettingsACK := false
		for !gotSettingsACK {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if f.Type == frame.FrameSettings && f.Flags.Has(frame.FlagACK) {
				gotSettingsACK = true
			}
		}

		// Send SETTINGS ACK.
		fw.WriteSettingsACK()
		fw.Flush()

		enc := hpack.AcquireEncoder()
		defer hpack.ReleaseEncoder(enc)

		// Read frames and handle them.
		var requestStreamID uint32
		var receivedData []byte
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f.Type {
			case frame.FrameHeaders:
				requestStreamID = f.StreamID
			case frame.FrameData:
				receivedData = append(receivedData, f.Data...)
				// After receiving data, send WINDOW_UPDATE to allow more data.
				fw.WriteWindowUpdate(f.StreamID, uint32(len(f.Data)))
				fw.WriteWindowUpdate(0, uint32(len(f.Data)))
				fw.Flush()
				if f.HasEndStream() {
					// Send response with the received body echoed back.
					hdr := enc.Encode([]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}})
					fw.WriteHeaders(requestStreamID, false, hdr, nil)
					fw.WriteData(requestStreamID, true, receivedData)
					fw.Flush()
					// Keep connection alive for client to read the response.
					time.Sleep(200 * time.Millisecond)
					return
				}
			case frame.FrameWindowUpdate:
			case frame.FramePriority:
				// Ignore priority frames.
			case frame.FrameSettings:
				if !f.Flags.Has(frame.FlagACK) {
					fw.WriteSettingsACK()
					fw.Flush()
				}
			}
		}
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(ln.Addr().String(), dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	// Send a POST with 4KB body (larger than 1024 initial window).
	body := make([]byte, 4096)
	for i := range body {
		body[i] = byte(i % 256)
	}

	resp, err := cc.roundTrip(&h2Request{
		Method: "POST", Scheme: "https", Authority: "localhost", Path: "/",
		Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if !bytes.Equal(resp.Body, body) {
		t.Errorf("body mismatch: got %d bytes, want %d", len(resp.Body), len(body))
	}
}

// --- Server sends WINDOW_UPDATE on a stream ---

func TestStreamWindowUpdate(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		if err := rawServerHandshake(conn, fr, fw); err != nil {
			return
		}

		enc := hpack.AcquireEncoder()
		defer hpack.ReleaseEncoder(enc)

		// Handle requests.
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if f.Type == frame.FrameHeaders {
				streamID := f.StreamID
				// Send WINDOW_UPDATE on the stream before responding.
				fw.WriteWindowUpdate(streamID, 65536)
				fw.Flush()

				// Send response.
				hdr := enc.Encode([]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}})
				fw.WriteHeaders(streamID, true, hdr, nil)
				fw.Flush()
				return
			}
		}
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(ln.Addr().String(), dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// --- Large response body (triggers maybeUpdateWindow) ---

func TestLargeResponseBody(t *testing.T) {
	// Use Firefox profile with 131072 (128KB) initial window.
	// Send response larger than half the window to trigger auto WINDOW_UPDATE.
	bodySize := 96 * 1024 // 96KB > 128KB/2
	expected := make([]byte, bodySize)
	for i := range expected {
		expected[i] = byte(i % 251) // prime to avoid pattern
	}

	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBody(expected)
	})
	defer cleanup()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.FirefoxH2.Clone()
	cc, err := Dial(addr, dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if !bytes.Equal(resp.Body, expected) {
		t.Errorf("body mismatch: got %d bytes, want %d", len(resp.Body), bodySize)
	}
}

// --- PeerSettings returns a copy ---

func TestPeerSettingsCopy(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	ps := cc.PeerSettings()
	// Modifying the copy should not affect the connection.
	ps.MaxConcurrentStreams = 9999
	ps2 := cc.PeerSettings()
	if ps2.MaxConcurrentStreams == 9999 {
		t.Error("PeerSettings returned reference, not copy")
	}
}

// --- GOAWAY with active stream above lastStreamID ---

func TestGOAWAY_ActiveStreams(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		if err := rawServerHandshake(conn, fr, fw); err != nil {
			return
		}

		// Read a HEADERS frame (stream 1).
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if f.Type == frame.FrameHeaders {
				// Send GOAWAY with lastStreamID=0 (rejecting stream 1).
				fw.WriteGoAway(0, frame.ErrCodeNoError, nil)
				fw.Flush()
				time.Sleep(200 * time.Millisecond)
				return
			}
		}
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	cc, err := Dial(ln.Addr().String(), dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	_, err = cc.roundTrip(&h2Request{
		Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
	})
	if err == nil {
		t.Fatal("expected error when stream is above lastStreamID in GOAWAY")
	}
}

// --- Handshake with profile that has no ConnectionWindowUpdate ---

func TestDial_NoConnectionWindowUpdate(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	// Use a profile with ConnectionWindowUpdate=0 (Firefox-like).
	profile := h2fingerprint.FirefoxH2.Clone()
	profile.ConnectionWindowUpdate = 0

	cc, err := Dial(addr, dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

// --- Handshake where server sends non-SETTINGS first ---

func TestDial_BadServerPreface(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read client preface.
		preface := make([]byte, 24)
		conn.Read(preface)

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		// Read client SETTINGS.
		fr.ReadFrame()

		// Send PING instead of SETTINGS (invalid server preface).
		var ping [8]byte
		fw.WritePing(false, ping)
		fw.Flush()

		time.Sleep(100 * time.Millisecond)
	}()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	_, err = Dial(ln.Addr().String(), dialer, profile)
	if err == nil {
		t.Fatal("expected error when server sends non-SETTINGS first")
	}
}

// --- Connection-level window update for large response ---

func TestMaybeUpdateWindow_ConnectionLevel(t *testing.T) {
	// Use a profile with small initial window to ensure connection-level
	// WINDOW_UPDATE gets triggered.
	bodySize := 48 * 1024
	expected := make([]byte, bodySize)
	for i := range expected {
		expected[i] = byte(i % 251)
	}

	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBody(expected)
	})
	defer cleanup()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	// Profile with small initial window and NO connection window update.
	profile := h2fingerprint.FirefoxH2.Clone()
	profile.ConnectionWindowUpdate = 0

	cc, err := Dial(addr, dialer, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if len(resp.Body) != bodySize {
		t.Errorf("body size: got %d, want %d", len(resp.Body), bodySize)
	}
}

// --- Concurrent requests hitting close ---

func TestConcurrentClose(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		time.Sleep(200 * time.Millisecond)
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)

	// Start multiple concurrent requests.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cc.roundTrip(&h2Request{
				Method: "GET", Scheme: "https", Authority: "localhost", Path: "/",
			})
		}()
	}

	// Close while requests are in flight.
	time.Sleep(50 * time.Millisecond)
	cc.Close()
	wg.Wait()
}

// --- writeRequest with HEADERS-only (different path in encodeHeaders) ---

func TestRoundTrip_CustomHeaders(t *testing.T) {
	addr, cleanup := testH2Server(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	cc := dialLocal(t, addr)
	defer cc.Close()

	resp, err := cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/api/v1/test",
		Headers: []Header{
			{Name: "accept", Value: "application/json"},
			{Name: "x-custom-header", Value: "custom-value"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}
