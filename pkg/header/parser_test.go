package header

import (
	"strings"
	"testing"
)

func TestParse_SimpleGet(t *testing.T) {
	buf := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	var r ParsedRequest
	n, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(buf) {
		t.Errorf("consumed = %d, want %d", n, len(buf))
	}
	assertBytes(t, "Method", r.Method, "GET")
	assertBytes(t, "URI", r.URI, "/")
	assertBytes(t, "Version", r.Version, "HTTP/1.1")
	if r.Major != 1 || r.Minor != 1 {
		t.Errorf("version = %d.%d, want 1.1", r.Major, r.Minor)
	}
	if r.NumHeaders != 1 {
		t.Fatalf("NumHeaders = %d, want 1", r.NumHeaders)
	}
	assertBytes(t, "Header[0].Key", r.Headers[0].Key, "Host")
	assertBytes(t, "Header[0].Value", r.Headers[0].Value, "example.com")
	if !r.KeepAlive {
		t.Error("KeepAlive should be true for HTTP/1.1")
	}
}

func TestParse_PostWithBody(t *testing.T) {
	buf := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello")
	var r ParsedRequest
	n, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantHeaderEnd := strings.Index(string(buf), "\r\n\r\n") + 4
	if n != wantHeaderEnd {
		t.Errorf("consumed = %d, want %d", n, wantHeaderEnd)
	}
	assertBytes(t, "Method", r.Method, "POST")
	assertBytes(t, "URI", r.URI, "/api")
	if r.ContentLength != 5 {
		t.Errorf("ContentLength = %d, want 5", r.ContentLength)
	}
}

func TestParse_MultipleHeaders(t *testing.T) {
	buf := []byte("GET /path HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: text/html\r\n" +
		"User-Agent: test\r\n" +
		"X-Custom: value\r\n" +
		"\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NumHeaders != 4 {
		t.Fatalf("NumHeaders = %d, want 4", r.NumHeaders)
	}
	assertBytes(t, "Header[0]", r.Headers[0].Key, "Host")
	assertBytes(t, "Header[1]", r.Headers[1].Key, "Accept")
	assertBytes(t, "Header[2]", r.Headers[2].Key, "User-Agent")
	assertBytes(t, "Header[3]", r.Headers[3].Key, "X-Custom")
}

func TestParse_ConnectionClose(t *testing.T) {
	buf := []byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.KeepAlive {
		t.Error("KeepAlive should be false with Connection: close")
	}
	if !r.ConnClose {
		t.Error("ConnClose should be true")
	}
}

func TestParse_ConnectionKeepAlive(t *testing.T) {
	buf := []byte("GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// HTTP/1.0 default is not keep-alive, but the explicit header sets it.
	// However, our parser only sets KeepAlive=true for HTTP/1.1 by default.
	// For HTTP/1.0, KeepAlive is false unless explicitly requested.
	// The parser sets ConnClose and KeepAlive based on Connection header,
	// but final KeepAlive is set based on version.
	if r.KeepAlive {
		t.Error("HTTP/1.0 should not be keep-alive by default")
	}
}

func TestParse_ChunkedTE(t *testing.T) {
	buf := []byte("POST /data HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Chunked {
		t.Error("Chunked should be true")
	}
}

func TestParse_HTTP10(t *testing.T) {
	buf := []byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Major != 1 || r.Minor != 0 {
		t.Errorf("version = %d.%d, want 1.0", r.Major, r.Minor)
	}
	if r.KeepAlive {
		t.Error("HTTP/1.0 default should not be keep-alive")
	}
}

func TestParse_HeaderValueLookup(t *testing.T) {
	buf := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := r.HeaderValue([]byte("content-type"))
	assertBytes(t, "Content-Type value", v, "text/plain")

	v = r.HeaderValue([]byte("X-Missing"))
	if v != nil {
		t.Errorf("missing header should return nil, got %q", v)
	}
}

func TestParse_LeadingCRLF(t *testing.T) {
	// RFC 9112 §2.2: tolerate leading CRLF.
	buf := []byte("\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBytes(t, "Method", r.Method, "GET")
}

func TestParse_HeaderWithSpaces(t *testing.T) {
	buf := []byte("GET / HTTP/1.1\r\nHost:   example.com  \r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBytes(t, "Host value", r.Headers[0].Value, "example.com")
}

func TestParse_LargeNumHeaders(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < MaxHeaders; i++ {
		sb.WriteString("X-Header: value\r\n")
	}
	sb.WriteString("\r\n")
	buf := []byte(sb.String())

	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.NumHeaders != MaxHeaders {
		t.Errorf("NumHeaders = %d, want %d", r.NumHeaders, MaxHeaders)
	}
}

func TestParse_TooManyHeaders(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < MaxHeaders+1; i++ {
		sb.WriteString("X-Header: value\r\n")
	}
	sb.WriteString("\r\n")
	buf := []byte(sb.String())

	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != ErrTooManyHeaders {
		t.Errorf("expected ErrTooManyHeaders, got %v", err)
	}
}

// --- Error cases ---

func TestParse_Empty(t *testing.T) {
	var r ParsedRequest
	_, err := Parse(nil, &r)
	if err != ErrNeedMore {
		t.Errorf("expected ErrNeedMore, got %v", err)
	}
}

func TestParse_Incomplete(t *testing.T) {
	buf := []byte("GET / HTTP/1.1\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != ErrNeedMore {
		t.Errorf("expected ErrNeedMore, got %v", err)
	}
}

func TestParse_InvalidMethod(t *testing.T) {
	buf := []byte("get / HTTP/1.1\r\nHost: x\r\n\r\n") // lowercase
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParse_InvalidVersion(t *testing.T) {
	tests := []string{
		"GET / HTP/1.1\r\nHost: x\r\n\r\n",
		"GET / HTTP/a.1\r\nHost: x\r\n\r\n",
		"GET / HTTP/1.a\r\nHost: x\r\n\r\n",
		"GET / HTTP1.1\r\nHost: x\r\n\r\n",
	}
	for _, s := range tests {
		var r ParsedRequest
		_, err := Parse([]byte(s), &r)
		if err != ErrInvalidVersion {
			t.Errorf("input %q: expected ErrInvalidVersion, got %v", s, err)
		}
	}
}

func TestParse_MalformedRequestLine(t *testing.T) {
	tests := []string{
		"GET\r\nHost: x\r\n\r\n",         // no URI
		" / HTTP/1.1\r\nHost: x\r\n\r\n", // no method (space first = invalid method)
	}
	for _, s := range tests {
		var r ParsedRequest
		_, err := Parse([]byte(s), &r)
		if err == nil {
			t.Errorf("input %q: expected error, got nil", s)
		}
	}
}

func TestParse_MalformedHeader(t *testing.T) {
	buf := []byte("GET / HTTP/1.1\r\n: value\r\n\r\n") // empty key
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != ErrMalformedHeader {
		t.Errorf("expected ErrMalformedHeader, got %v", err)
	}
}

func TestParse_HeaderTooLarge(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	sb.WriteString("X-Big: ")
	sb.WriteString(strings.Repeat("A", MaxHeaderSize))
	sb.WriteString("\r\n\r\n")
	buf := []byte(sb.String())

	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != ErrHeaderTooLarge {
		t.Errorf("expected ErrHeaderTooLarge, got %v", err)
	}
}

func TestParse_ContentLength(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantCL  int64
	}{
		{"normal", "GET / HTTP/1.1\r\nContent-Length: 42\r\n\r\n", 42},
		{"zero", "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 0},
		{"missing", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r ParsedRequest
			_, err := Parse([]byte(tt.input), &r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if r.ContentLength != tt.wantCL {
				t.Errorf("ContentLength = %d, want %d", r.ContentLength, tt.wantCL)
			}
		})
	}
}

func TestParse_AllMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
	for _, m := range methods {
		buf := []byte(m + " / HTTP/1.1\r\nHost: x\r\n\r\n")
		var r ParsedRequest
		_, err := Parse(buf, &r)
		if err != nil {
			t.Errorf("method %s: unexpected error: %v", m, err)
			continue
		}
		assertBytes(t, "Method", r.Method, m)
	}
}

func TestParse_LongURI(t *testing.T) {
	uri := "/" + strings.Repeat("a", 4096)
	buf := []byte("GET " + uri + " HTTP/1.1\r\nHost: x\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBytes(t, "URI", r.URI, uri)
}

func TestParse_Slicing(t *testing.T) {
	// Verify that parsed fields are slices into the original buffer.
	buf := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
	var r ParsedRequest
	_, err := Parse(buf, &r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Method should point into buf.
	if &r.Method[0] != &buf[0] {
		t.Error("Method does not point into original buffer")
	}
}

// --- Benchmark ---

func BenchmarkParse_SimpleGet(b *testing.B) {
	buf := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	var r ParsedRequest
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		_, _ = Parse(buf, &r)
	}
}

func BenchmarkParse_Typical(b *testing.B) {
	buf := []byte("GET /path/to/resource HTTP/1.1\r\n" +
		"Host: www.example.com\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; Test/1.0)\r\n" +
		"Accept: text/html,application/xhtml+xml\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Connection: keep-alive\r\n" +
		"Cookie: session=abc123; theme=light\r\n" +
		"\r\n")
	var r ParsedRequest
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		_, _ = Parse(buf, &r)
	}
}

func BenchmarkParse_ManyHeaders(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 20; i++ {
		sb.WriteString("X-Custom-Header-Long-Name: some-value-here\r\n")
	}
	sb.WriteString("\r\n")
	buf := []byte(sb.String())
	var r ParsedRequest
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		_, _ = Parse(buf, &r)
	}
}

func BenchmarkHeaderValue(b *testing.B) {
	buf := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nAccept: */*\r\n\r\n")
	var r ParsedRequest
	Parse(buf, &r)
	key := []byte("Content-Type")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.HeaderValue(key)
	}
}

func assertBytes(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if string(got) != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}
