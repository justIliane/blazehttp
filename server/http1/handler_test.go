package http1

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeConn_SimpleRequest(t *testing.T) {
	handler := func(ctx *RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBodyString("Hello, World!")
	}

	reqData := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- ServeConn(server, &ConnConfig{
			Handler:      handler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  5 * time.Second,
		})
		server.Close()
	}()

	_, err := client.Write([]byte(reqData))
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	resp, err := io.ReadAll(client)
	client.Close()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	// Wait for serve to finish.
	<-done

	respStr := string(resp)
	if !strings.Contains(respStr, "200 OK") {
		t.Errorf("response does not contain 200 OK: %s", respStr)
	}
	if !strings.Contains(respStr, "Hello, World!") {
		t.Errorf("response does not contain body: %s", respStr)
	}
	if !strings.Contains(respStr, "Content-Length: 13") {
		t.Errorf("response does not contain Content-Length: %s", respStr)
	}
	if !strings.Contains(respStr, "Connection: close") {
		t.Errorf("response does not contain Connection: close: %s", respStr)
	}
}

func TestServeConn_BadRequest(t *testing.T) {
	handler := func(ctx *RequestCtx) {
		ctx.SetStatusCode(200)
	}

	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- ServeConn(server, &ConnConfig{
			Handler:      handler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  5 * time.Second,
		})
		server.Close()
	}()

	// Send garbage.
	_, _ = client.Write([]byte("GARBAGE\r\n\r\n\r\n"))

	resp, _ := io.ReadAll(client)
	client.Close()

	<-done

	if !strings.Contains(string(resp), "400 Bad Request") {
		t.Errorf("expected 400 response, got: %s", resp)
	}
}

func TestRequest_ParseSimple(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n, err := req.Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(buf) {
		t.Errorf("consumed = %d, want %d", n, len(buf))
	}
	assertBytes(t, "Method", req.Method(), "GET")
	assertBytes(t, "Path", req.Path(), "/path")
	assertBytes(t, "Version", req.Version(), "HTTP/1.1")
	assertBytes(t, "Host header", req.Header([]byte("Host")), "example.com")
	if req.Body() != nil {
		t.Errorf("Body should be nil, got %q", req.Body())
	}
}

func TestRequest_ParseWithBody(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
	n, err := req.Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(buf) {
		t.Errorf("consumed = %d, want %d", n, len(buf))
	}
	assertBytes(t, "Body", req.Body(), "hello")
	if req.ContentLength() != 5 {
		t.Errorf("ContentLength = %d, want 5", req.ContentLength())
	}
}

func TestRequest_ParseChunked(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	_, err := req.Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !req.IsChunked() {
		t.Error("should be chunked")
	}
	assertBytes(t, "Body", req.Body(), "hello world")
}

func TestRequest_ParseIncompleteBody(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhello")
	_, err := req.Parse(buf)
	if err == nil {
		t.Error("expected ErrNeedMore for incomplete body")
	}
}

func TestRequest_HeaderByIndex(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n")
	_, err := req.Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	k, v := req.HeaderByIndex(0)
	assertBytes(t, "key0", k, "Host")
	assertBytes(t, "val0", v, "x")

	k, v = req.HeaderByIndex(1)
	assertBytes(t, "key1", k, "Accept")
	assertBytes(t, "val1", v, "*/*")

	k, v = req.HeaderByIndex(2)
	if k != nil || v != nil {
		t.Error("out of bounds should return nil")
	}

	k, v = req.HeaderByIndex(-1)
	if k != nil || v != nil {
		t.Error("negative index should return nil")
	}
}

func TestRequest_PoolReuse(t *testing.T) {
	// Acquire, parse, release, acquire again — should not retain old data.
	req := AcquireRequest()
	buf := []byte("GET /first HTTP/1.1\r\nHost: a\r\n\r\n")
	_, _ = req.Parse(buf)
	ReleaseRequest(req)

	req2 := AcquireRequest()
	buf2 := []byte("POST /second HTTP/1.1\r\nHost: b\r\nContent-Length: 3\r\n\r\nfoo")
	_, err := req2.Parse(buf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBytes(t, "Method", req2.Method(), "POST")
	assertBytes(t, "Path", req2.Path(), "/second")
	assertBytes(t, "Body", req2.Body(), "foo")
	ReleaseRequest(req2)
}

func TestResponse_Build(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetStatusCode(200)
	resp.SetHeader([]byte("Content-Type"), []byte("text/plain"))
	resp.SetBody([]byte("OK"))

	data := resp.Build(true)
	s := string(data)

	if !strings.Contains(s, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("missing status line: %s", s)
	}
	if !strings.Contains(s, "Content-Type: text/plain\r\n") {
		t.Errorf("missing Content-Type: %s", s)
	}
	if !strings.Contains(s, "Content-Length: 2\r\n") {
		t.Errorf("missing Content-Length: %s", s)
	}
	if !strings.Contains(s, "Connection: keep-alive\r\n") {
		t.Errorf("missing Connection: keep-alive: %s", s)
	}
	if !bytes.HasSuffix(data, []byte("\r\n\r\nOK")) {
		t.Errorf("body not at end: %s", s)
	}
}

func TestResponse_BuildChunked(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetStatusCode(200)
	resp.SetBody([]byte("Hello, World!"))

	data := resp.BuildChunked(false)
	s := string(data)

	if !strings.Contains(s, "Transfer-Encoding: chunked\r\n") {
		t.Errorf("missing TE header: %s", s)
	}
	if !strings.Contains(s, "Connection: close\r\n") {
		t.Errorf("missing Connection: close: %s", s)
	}
	// Should contain chunk: "d\r\nHello, World!\r\n0\r\n\r\n"
	if !strings.Contains(s, "d\r\nHello, World!\r\n0\r\n\r\n") {
		t.Errorf("malformed chunked body: %s", s)
	}
}

func TestResponse_StatusCodes(t *testing.T) {
	codes := []int{200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 500, 502, 503}
	for _, code := range codes {
		resp := AcquireResponse()
		resp.SetStatusCode(code)
		data := resp.Build(false)
		s := string(data)
		if !strings.Contains(s, "HTTP/1.1 ") {
			t.Errorf("code %d: missing HTTP/1.1: %s", code, s)
		}
		ReleaseResponse(resp)
	}
}

func TestResponse_SetHeaderReplace(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetHeader([]byte("Content-Type"), []byte("text/html"))
	resp.SetHeader([]byte("Content-Type"), []byte("text/plain"))
	data := resp.Build(false)
	s := string(data)
	if strings.Count(s, "Content-Type") != 1 {
		t.Errorf("Content-Type should appear once, got: %s", s)
	}
	if !strings.Contains(s, "text/plain") {
		t.Errorf("Content-Type should be text/plain: %s", s)
	}
}

func TestResponse_PoolReuse(t *testing.T) {
	resp := AcquireResponse()
	resp.SetStatusCode(404)
	resp.SetBody([]byte("not found"))
	_ = resp.Build(false)
	ReleaseResponse(resp)

	resp2 := AcquireResponse()
	defer ReleaseResponse(resp2)
	if resp2.StatusCode() != 200 {
		t.Errorf("reused response should have default status 200, got %d", resp2.StatusCode())
	}
	if resp2.Body() != nil {
		t.Errorf("reused response should have nil body")
	}
}

func TestRequestCtx_RemoteLocalAddr(t *testing.T) {
	handler := func(ctx *RequestCtx) {
		if ctx.RemoteAddr() == nil {
			t.Error("RemoteAddr should not be nil")
		}
		if ctx.LocalAddr() == nil {
			t.Error("LocalAddr should not be nil")
		}
		ctx.SetStatusCode(200)
		ctx.SetBody([]byte("ok"))
	}

	reqData := "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- ServeConn(server, &ConnConfig{
			Handler:     handler,
			IdleTimeout: 5 * time.Second,
		})
		server.Close()
	}()

	_, _ = client.Write([]byte(reqData))
	_, _ = io.ReadAll(client)
	client.Close()
	<-done
}

func TestRequest_NumHeaders(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\nX-Foo: bar\r\n\r\n")
	_, err := req.Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.NumHeaders() != 3 {
		t.Errorf("NumHeaders = %d, want 3", req.NumHeaders())
	}
}

func TestRequest_ParseChunked_Incomplete(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	// Chunked body cut short.
	buf := []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
	_, err := req.Parse(buf)
	if err == nil {
		t.Error("expected error for incomplete chunked body")
	}
}

func TestRequest_ParseChunked_InvalidHex(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\ndata\r\n0\r\n\r\n")
	_, err := req.Parse(buf)
	if err == nil {
		t.Error("expected error for invalid hex in chunked body")
	}
}

func TestRequest_ParseChunked_MalformedCRLF(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)

	buf := []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello!!")
	_, err := req.Parse(buf)
	if err == nil {
		t.Error("expected error for malformed chunked CRLF")
	}
}

func TestParseHex(t *testing.T) {
	tests := []struct {
		input string
		want  int64
		ok    bool
	}{
		{"0", 0, true},
		{"5", 5, true},
		{"a", 10, true},
		{"f", 15, true},
		{"A", 10, true},
		{"F", 15, true},
		{"ff", 255, true},
		{"1a", 26, true},
		{"10", 16, true},
		{"", 0, false},
		{"gg", 0, false},
		{"xyz", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseHex([]byte(tt.input))
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("parseHex(%q) = %d, %v; want %d, %v", tt.input, got, ok, tt.want, tt.ok)
		}
	}
}

func TestResponse_BuildChunked_KeepAlive(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetStatusCode(200)
	resp.SetBody([]byte("data"))
	data := resp.BuildChunked(true)
	s := string(data)

	if !strings.Contains(s, "Connection: keep-alive") {
		t.Errorf("missing keep-alive in chunked response: %s", s)
	}
}

func TestResponse_BuildChunked_EmptyBody(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetStatusCode(204)
	data := resp.BuildChunked(false)
	s := string(data)

	// Should end with final chunk "0\r\n\r\n"
	if !strings.HasSuffix(s, "0\r\n\r\n") {
		t.Errorf("missing final chunk: %s", s)
	}
}

func TestResponse_UncommonStatusCode(t *testing.T) {
	// Test a status code that goes through the default appendStatusCode path.
	codes := []int{100, 101, 202, 408, 413, 429, 504, 999}
	for _, code := range codes {
		resp := AcquireResponse()
		resp.SetStatusCode(code)
		data := resp.Build(false)
		s := string(data)
		if !strings.Contains(s, "HTTP/1.1 ") {
			t.Errorf("code %d: missing HTTP/1.1: %s", code, s)
		}
		ReleaseResponse(resp)
	}
}

func TestResponse_BuildTwice(t *testing.T) {
	// Calling Build twice should free the old buffer.
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetStatusCode(200)
	resp.SetBody([]byte("first"))
	_ = resp.Build(true)

	resp.SetBody([]byte("second"))
	data := resp.Build(true)
	if !strings.Contains(string(data), "second") {
		t.Errorf("second Build should contain new body: %s", data)
	}
}

func TestRequest_ChunkedBodyReleased(t *testing.T) {
	// Parse a chunked request, then release — chunkedBody should be cleaned up.
	req := AcquireRequest()
	buf := []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	_, err := req.Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBytes(t, "Body", req.Body(), "abc")
	// Release should put the chunked buffer back to pool.
	ReleaseRequest(req)
}

func TestStatusText(t *testing.T) {
	// Exercise all statusText branches.
	codes := []struct {
		code int
		text string
	}{
		{100, "Continue"},
		{101, "Switching Protocols"},
		{200, "OK"},
		{201, "Created"},
		{202, "Accepted"},
		{204, "No Content"},
		{301, "Moved Permanently"},
		{302, "Found"},
		{304, "Not Modified"},
		{400, "Bad Request"},
		{401, "Unauthorized"},
		{403, "Forbidden"},
		{404, "Not Found"},
		{405, "Method Not Allowed"},
		{408, "Request Timeout"},
		{413, "Content Too Large"},
		{429, "Too Many Requests"},
		{500, "Internal Server Error"},
		{502, "Bad Gateway"},
		{503, "Service Unavailable"},
		{504, "Gateway Timeout"},
		{999, "Unknown"},
	}
	for _, tt := range codes {
		got := statusText(tt.code)
		if got != tt.text {
			t.Errorf("statusText(%d) = %q, want %q", tt.code, got, tt.text)
		}
	}
}

func TestResponse_BuildChunked_WithHeaders(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetStatusCode(200)
	resp.SetHeader([]byte("X-Custom"), []byte("val"))
	resp.SetBody([]byte("chunk data here"))
	data := resp.BuildChunked(true)
	s := string(data)

	if !strings.Contains(s, "X-Custom: val\r\n") {
		t.Errorf("missing custom header: %s", s)
	}
	if !strings.Contains(s, "Transfer-Encoding: chunked") {
		t.Errorf("missing TE: %s", s)
	}
	if !strings.Contains(s, "Connection: keep-alive") {
		t.Errorf("missing keep-alive: %s", s)
	}
}

func TestResponse_BuildChunked_ThenBuild(t *testing.T) {
	// Call BuildChunked then Build — should free old buffer.
	resp := AcquireResponse()
	defer ReleaseResponse(resp)

	resp.SetStatusCode(200)
	resp.SetBody([]byte("test"))
	_ = resp.BuildChunked(false)
	data := resp.Build(false)
	if !strings.Contains(string(data), "Content-Length: 4") {
		t.Errorf("Build after BuildChunked should work: %s", data)
	}
}

func TestParseChunkedBody_NoTerminalCRLF(t *testing.T) {
	// Zero-size chunk missing trailing CRLF.
	buf := []byte("0\r\n")
	_, _, err := parseChunkedBody(buf)
	if err == nil {
		t.Error("expected error for missing trailing CRLF")
	}
}

func TestParseChunkedBody_ChunkSizeMissingCRLF(t *testing.T) {
	buf := []byte("5")
	_, _, err := parseChunkedBody(buf)
	if err == nil {
		t.Error("expected error for incomplete chunk size")
	}
}

func TestParseChunkedBody_BadCRLFAfterSize(t *testing.T) {
	buf := []byte("5\rXhello\r\n0\r\n\r\n")
	_, _, err := parseChunkedBody(buf)
	if err == nil {
		t.Error("expected error for bad CRLF after chunk size")
	}
}

func TestAppendHex(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{15, "f"},
		{16, "10"},
		{255, "ff"},
		{4096, "1000"},
	}
	for _, tt := range tests {
		got := string(appendHex(nil, tt.n))
		if got != tt.want {
			t.Errorf("appendHex(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// --- Benchmarks ---

func BenchmarkRequest_Parse(b *testing.B) {
	buf := []byte("GET /path/to/resource HTTP/1.1\r\n" +
		"Host: www.example.com\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; Test/1.0)\r\n" +
		"Accept: text/html,application/xhtml+xml\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Connection: keep-alive\r\n" +
		"Cookie: session=abc123; theme=light\r\n" +
		"\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := AcquireRequest()
		_, _ = req.Parse(buf)
		ReleaseRequest(req)
	}
}

func BenchmarkResponse_Build(b *testing.B) {
	body := []byte("Hello, World!")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := AcquireResponse()
		resp.SetStatusCode(200)
		resp.SetHeader([]byte("Content-Type"), []byte("text/plain"))
		resp.SetBody(body)
		_ = resp.Build(true)
		ReleaseResponse(resp)
	}
}

func assertBytes(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if string(got) != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}
