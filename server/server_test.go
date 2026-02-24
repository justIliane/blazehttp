package server_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/justIliane/blazehttp/server"
	"github.com/justIliane/blazehttp/server/http2"

	xhttp2 "golang.org/x/net/http2"
)

func startServer(t *testing.T, handler http2.RequestHandler) (*server.Server, string, *http.Client) {
	t.Helper()

	cert, err := server.GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv := &server.Server{
		Addr:                addr,
		Handler:             handler,
		MaxConcurrentStreams: 250,
		WorkerPoolSize:      64,
		IdleTimeout:         5 * time.Second,
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        5 * time.Second,
	}

	go func() {
		srv.ListenAndServeTLSCert(cert)
	}()

	// Wait for server to be ready.
	for i := 0; i < 100; i++ {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 50 * time.Millisecond},
			"tcp", addr,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
		)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	client := &http.Client{
		Transport: &xhttp2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	return srv, addr, client
}

func TestServer_TLS_ALPN(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("alpn-ok")
	}

	srv, addr, _ := startServer(t, handler)
	defer srv.Close()

	// Connect and verify ALPN negotiation.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("protocol = %q, want h2", state.NegotiatedProtocol)
	}
}

func TestServer_CurlHTTP2(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not found in PATH")
	}

	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBodyString("Hello from BlazeHTTP!")
	}

	srv, addr, _ := startServer(t, handler)
	defer srv.Close()

	cmd := exec.Command(curlPath, "-k", "--http2", "-s",
		fmt.Sprintf("https://%s/", addr))

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl: %v\noutput: %s", err, out)
	}

	if !strings.Contains(string(out), "Hello from BlazeHTTP!") {
		t.Fatalf("curl output = %q, want to contain 'Hello from BlazeHTTP!'", string(out))
	}
}

func TestServer_CurlHTTP2_Verbose(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not found in PATH")
	}

	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBodyString("verbose-check")
	}

	srv, addr, _ := startServer(t, handler)
	defer srv.Close()

	cmd := exec.Command(curlPath, "-k", "--http2", "-v",
		fmt.Sprintf("https://%s/", addr))

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl: %v\noutput: %s", err, out)
	}

	output := string(out)
	// curl -v outputs "using HTTP/2" to stderr when HTTP/2 is negotiated.
	if !strings.Contains(output, "HTTP/2") {
		t.Fatalf("curl -v output does not contain HTTP/2:\n%s", output)
	}
}

func TestServer_MultipleRequests(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	srv, addr, client := startServer(t, handler)
	defer srv.Close()

	for i := 0; i < 20; i++ {
		resp, err := client.Get(fmt.Sprintf("https://%s/req/%d", addr, i))
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "ok" {
			t.Fatalf("req %d: body = %q, want ok", i, body)
		}
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	srv, addr, client := startServer(t, handler)

	// Verify server works.
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Close server.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// New connections should fail.
	_, err = client.Get("https://" + addr + "/")
	if err == nil {
		t.Fatal("expected error after shutdown")
	}
}

func TestServer_NoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	srv, addr, client := startServer(t, handler)

	for i := 0; i < 10; i++ {
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
	}

	client.Transport.(*xhttp2.Transport).CloseIdleConnections()
	srv.Close()

	time.Sleep(500 * time.Millisecond)

	after := runtime.NumGoroutine()
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d, after=%d", before, after)
	}
}
