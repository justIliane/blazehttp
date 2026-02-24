package http2_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/justIliane/blazehttp/server"
	"github.com/justIliane/blazehttp/server/http2"

	xhttp2 "golang.org/x/net/http2"
)

// startTestServer starts a BlazeHTTP server on a random port with TLS.
// Returns the server, address, and a TLS-configured HTTP client.
func startTestServer(t *testing.T, handler http2.RequestHandler) (*server.Server, string, *http.Client) {
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

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeTLSCert(cert)
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

	// Create HTTP/2 client.
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

func TestHTTP2EndToEnd(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBodyString("Hello, HTTP/2!")
	}

	srv, addr, client := startTestServer(t, handler)
	defer srv.Close()

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %s, want HTTP/2.0", resp.Proto)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != "Hello, HTTP/2!" {
		t.Fatalf("body = %q, want %q", string(body), "Hello, HTTP/2!")
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "text/plain" {
		t.Fatalf("content-type = %q, want text/plain", ct)
	}
}

func TestHTTP2_MultipleStreams(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		path := string(ctx.Request.Path())
		ctx.SetStatusCode(200)
		ctx.SetBodyString("path=" + path)
	}

	srv, addr, client := startTestServer(t, handler)
	defer srv.Close()

	const numRequests = 50
	var wg sync.WaitGroup
	wg.Add(numRequests)
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(i int) {
			defer wg.Done()
			url := fmt.Sprintf("https://%s/path/%d", addr, i)
			resp, err := client.Get(url)
			if err != nil {
				errors <- fmt.Errorf("GET %s: %v", url, err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			expected := fmt.Sprintf("path=/path/%d", i)
			if string(body) != expected {
				errors <- fmt.Errorf("body = %q, want %q", string(body), expected)
			}
		}(i)
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestHTTP2_LargeBody(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		// Echo back the request body.
		ctx.SetStatusCode(200)
		ctx.SetBody(ctx.Request.Body())
	}

	srv, addr, client := startTestServer(t, handler)
	defer srv.Close()

	// Send 1MB body.
	bodySize := 1024 * 1024
	largeBody := strings.Repeat("X", bodySize)

	resp, err := client.Post("https://"+addr+"/upload", "application/octet-stream", strings.NewReader(largeBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(respBody) != bodySize {
		t.Fatalf("response body size = %d, want %d", len(respBody), bodySize)
	}
}

func TestHTTP2_RequestHeaders(t *testing.T) {
	var gotMethod, gotPath, gotAuthority string
	var gotCustomHeader string

	handler := func(ctx *http2.RequestCtx) {
		gotMethod = string(ctx.Request.Method())
		gotPath = string(ctx.Request.Path())
		gotAuthority = string(ctx.Request.Authority())
		gotCustomHeader = string(ctx.Request.Header([]byte("x-custom")))
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	srv, addr, client := startTestServer(t, handler)
	defer srv.Close()

	req, _ := http.NewRequest("POST", "https://"+addr+"/api/test", nil)
	req.Header.Set("X-Custom", "hello-world")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotMethod != "POST" {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/test" {
		t.Fatalf("path = %q, want /api/test", gotPath)
	}
	if gotAuthority == "" {
		t.Fatal("authority should not be empty")
	}
	if gotCustomHeader != "hello-world" {
		t.Fatalf("x-custom = %q, want hello-world", gotCustomHeader)
	}
}

func TestHTTP2_StatusCodes(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		path := string(ctx.Request.Path())
		switch path {
		case "/not-found":
			ctx.SetStatusCode(404)
			ctx.SetBodyString("not found")
		case "/error":
			ctx.SetStatusCode(500)
			ctx.SetBodyString("internal error")
		default:
			ctx.SetStatusCode(200)
			ctx.SetBodyString("ok")
		}
	}

	srv, addr, client := startTestServer(t, handler)
	defer srv.Close()

	tests := []struct {
		path string
		code int
	}{
		{"/", 200},
		{"/not-found", 404},
		{"/error", 500},
	}
	for _, tt := range tests {
		resp, err := client.Get("https://" + addr + tt.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tt.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tt.code {
			t.Errorf("GET %s: status = %d, want %d", tt.path, resp.StatusCode, tt.code)
		}
	}
}

func TestHTTP2_EmptyBody(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(204) // No Content
	}

	srv, addr, client := startTestServer(t, handler)
	defer srv.Close()

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

func TestHTTP2_GracefulShutdown(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	srv, addr, client := startTestServer(t, handler)

	// Verify server works.
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	// Graceful shutdown.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Give time for shutdown to propagate.
	time.Sleep(100 * time.Millisecond)

	// New connections should fail.
	_, err = client.Get("https://" + addr + "/")
	if err == nil {
		t.Fatal("expected error after shutdown")
	}
}

func TestHTTP2_NoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	srv, addr, client := startTestServer(t, handler)

	// Send some requests.
	for i := 0; i < 10; i++ {
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
	}

	// Close the client transport to release connections.
	client.Transport.(*xhttp2.Transport).CloseIdleConnections()

	// Shutdown server.
	srv.Close()

	// Wait for goroutines to settle.
	time.Sleep(500 * time.Millisecond)

	after := runtime.NumGoroutine()
	// Allow some slack (up to 5 goroutines) for runtime internals.
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d, after=%d", before, after)
	}
}
