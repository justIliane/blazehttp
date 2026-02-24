package http2

import (
	"testing"

	"github.com/justIliane/blazehttp/pkg/frame"
	"github.com/justIliane/blazehttp/pkg/hpack"
)

// === Request tests ===

func TestRequest_FromHeaders_Valid(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/test")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("example.com")},
		{Name: []byte("accept"), Value: []byte("text/html")},
		{Name: []byte("content-length"), Value: []byte("42")},
	}
	if err := r.FromHeaders(fields); err != nil {
		t.Fatalf("FromHeaders: %v", err)
	}
	if string(r.Method()) != "GET" {
		t.Fatalf("method = %q", r.Method())
	}
	if string(r.Path()) != "/test" {
		t.Fatalf("path = %q", r.Path())
	}
	if string(r.Scheme()) != "https" {
		t.Fatalf("scheme = %q", r.Scheme())
	}
	if string(r.Authority()) != "example.com" {
		t.Fatalf("authority = %q", r.Authority())
	}
	if r.ContentLength() != 42 {
		t.Fatalf("content-length = %d", r.ContentLength())
	}
	if r.NumHeaders() != 2 { // accept + content-length
		t.Fatalf("numHeaders = %d", r.NumHeaders())
	}
	n, v := r.HeaderAt(0)
	if string(n) != "accept" || string(v) != "text/html" {
		t.Fatalf("header[0] = %q:%q", n, v)
	}
	n, v = r.HeaderAt(-1)
	if n != nil || v != nil {
		t.Fatal("HeaderAt(-1) should return nil")
	}
	n, v = r.HeaderAt(999)
	if n != nil || v != nil {
		t.Fatal("HeaderAt(999) should return nil")
	}
	if r.StreamID() != 0 {
		t.Fatalf("streamID = %d", r.StreamID())
	}
}

func TestRequest_FromHeaders_MissingMethod(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":scheme"), Value: []byte("https")},
	}
	err := r.FromHeaders(fields)
	if err == nil {
		t.Fatal("expected error for missing :method")
	}
}

func TestRequest_FromHeaders_DuplicatePseudo(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":method"), Value: []byte("POST")},
	}
	err := r.FromHeaders(fields)
	if err == nil {
		t.Fatal("expected error for duplicate :method")
	}
}

func TestRequest_FromHeaders_PseudoAfterRegular(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte("accept"), Value: []byte("*/*")},
		{Name: []byte(":path"), Value: []byte("/")},
	}
	err := r.FromHeaders(fields)
	if err == nil {
		t.Fatal("expected error for pseudo after regular")
	}
}

func TestRequest_FromHeaders_UnknownPseudo(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":unknown"), Value: []byte("x")},
	}
	err := r.FromHeaders(fields)
	if err == nil {
		t.Fatal("expected error for unknown pseudo-header")
	}
}

func TestRequest_FromHeaders_ConnectionHeader(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte("connection"), Value: []byte("keep-alive")},
	}
	err := r.FromHeaders(fields)
	if err == nil {
		t.Fatal("expected error for connection header")
	}
}

func TestRequest_FromHeaders_ConnectionHeaders(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"upgrade", "websocket"},
		{"keep-alive", "timeout=5"},
		{"proxy-connection", "keep-alive"},
		{"transfer-encoding", "chunked"},
	}
	for _, tt := range tests {
		r := &Request{}
		r.Reset()
		fields := []hpack.DecodedField{
			{Name: []byte(":method"), Value: []byte("GET")},
			{Name: []byte(":path"), Value: []byte("/")},
			{Name: []byte(tt.name), Value: []byte(tt.value)},
		}
		if err := r.FromHeaders(fields); err == nil {
			t.Errorf("expected error for %s header", tt.name)
		}
	}
}

func TestRequest_FromHeaders_CONNECT(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("CONNECT")},
		{Name: []byte(":authority"), Value: []byte("example.com:443")},
	}
	if err := r.FromHeaders(fields); err != nil {
		t.Fatalf("CONNECT without :path should be valid: %v", err)
	}
}

func TestRequest_AppendBody(t *testing.T) {
	r := &Request{}
	r.Reset()
	r.AppendBody(nil) // empty, no-op
	if r.Body() != nil {
		t.Fatal("body should be nil after empty append")
	}
	r.AppendBody([]byte("hello"))
	r.AppendBody([]byte(" world"))
	if string(r.Body()) != "hello world" {
		t.Fatalf("body = %q", r.Body())
	}
}

func TestRequest_SetTrailers(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte("grpc-status"), Value: []byte("0")},
		{Name: []byte("grpc-message"), Value: []byte("OK")},
	}
	r.setTrailers(fields)
	if r.numTrailers != 2 {
		t.Fatalf("numTrailers = %d", r.numTrailers)
	}
}

func TestRequest_Header_NotFound(t *testing.T) {
	r := &Request{}
	r.Reset()
	fields := []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte("accept"), Value: []byte("*/*")},
	}
	r.FromHeaders(fields)
	if v := r.Header([]byte("x-nonexistent")); v != nil {
		t.Fatalf("expected nil for nonexistent header, got %q", v)
	}
}

func TestRequest_StreamError_String(t *testing.T) {
	e := &StreamError{StreamID: 1, Code: frame.ErrCodeProtocolError}
	s := e.Error()
	if s == "" {
		t.Fatal("empty error string")
	}
}

// === Response tests ===

func TestResponse_SetHeader_Replace(t *testing.T) {
	r := &Response{}
	r.Reset()
	r.SetHeader([]byte("content-type"), []byte("text/plain"))
	r.SetHeader([]byte("content-type"), []byte("text/html"))
	if r.numHeaders != 1 {
		t.Fatalf("numHeaders = %d, want 1", r.numHeaders)
	}
}

func TestResponse_StatusCode(t *testing.T) {
	r := &Response{}
	r.Reset()
	if r.StatusCode() != 200 {
		t.Fatalf("default status = %d", r.StatusCode())
	}
	r.SetStatusCode(404)
	if r.StatusCode() != 404 {
		t.Fatalf("status = %d", r.StatusCode())
	}
}

func TestResponse_EncodeHeaders(t *testing.T) {
	r := &Response{}
	r.Reset()
	r.SetStatusCode(200)
	r.SetContentType([]byte("text/plain"))
	r.SetBodyString("test")

	enc := hpack.AcquireEncoder()
	defer hpack.ReleaseEncoder(enc)

	hb := r.EncodeHeaders(enc)
	if len(hb) == 0 {
		t.Fatal("empty header block")
	}
}

func TestResponse_StatusCodeBytes_OutOfRange(t *testing.T) {
	b := statusCodeBytes(999)
	if string(b) != "500" {
		t.Fatalf("out-of-range status bytes = %q", b)
	}
	b = statusCodeBytes(50)
	if string(b) != "500" {
		t.Fatalf("below-range status bytes = %q", b)
	}
}

// === Settings tests ===

func TestSettings_Apply_EnablePushInvalid(t *testing.T) {
	s := DefaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: frame.SettingsEnablePush, Value: 2}
	_, err := s.Apply(settings, 1)
	if err == nil {
		t.Fatal("expected error for EnablePush=2")
	}
}

func TestSettings_Apply_WindowSizeTooLarge(t *testing.T) {
	s := DefaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: frame.SettingsInitialWindowSize, Value: 1 << 31}
	_, err := s.Apply(settings, 1)
	if err == nil {
		t.Fatal("expected error for window size too large")
	}
}

func TestSettings_Apply_MaxFrameSizeInvalid(t *testing.T) {
	s := DefaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: frame.SettingsMaxFrameSize, Value: 100}
	_, err := s.Apply(settings, 1)
	if err == nil {
		t.Fatal("expected error for max frame size too small")
	}
}

func TestSettings_Apply_UnknownIgnored(t *testing.T) {
	s := DefaultPeerSettings()
	var settings [frame.MaxSettingsPerFrame]frame.Setting
	settings[0] = frame.Setting{ID: 0xFF, Value: 42} // unknown ID
	_, err := s.Apply(settings, 1)
	if err != nil {
		t.Fatalf("unknown setting should be ignored: %v", err)
	}
}

// === RequestCtx tests ===

func TestRequestCtx_Pool(t *testing.T) {
	ctx := acquireCtx()
	if ctx == nil {
		t.Fatal("nil ctx")
	}
	ctx.SetStatusCode(200)
	ctx.SetContentType("text/plain")
	ctx.SetBody([]byte("test"))
	ctx.SetBodyString("test2")

	if ctx.RemoteAddr() != nil {
		t.Fatal("remote addr should be nil")
	}
	if ctx.LocalAddr() != nil {
		t.Fatal("local addr should be nil")
	}

	releaseCtx(ctx)
}

// === Pool tests (acquireRequest/releaseRequest, acquireResponse/releaseResponse) ===

func TestRequestPool(t *testing.T) {
	r := acquireRequest()
	if r == nil {
		t.Fatal("nil request")
	}
	if r.contentLength != -1 {
		t.Fatalf("contentLength = %d, want -1", r.contentLength)
	}
	releaseRequest(r)
}

func TestResponsePool(t *testing.T) {
	r := acquireResponse()
	if r == nil {
		t.Fatal("nil response")
	}
	if r.statusCode != 200 {
		t.Fatalf("statusCode = %d, want 200", r.statusCode)
	}
	releaseResponse(r)
}

func TestResponse_HasHeader(t *testing.T) {
	r := &Response{}
	r.Reset()
	r.SetHeader([]byte("content-type"), []byte("text/plain"))
	r.SetHeader([]byte("content-length"), []byte("10"))
	// hasHeader should find it
	if !r.hasHeader([]byte("content-type")) {
		t.Fatal("should have content-type")
	}
	if r.hasHeader([]byte("x-nonexistent")) {
		t.Fatal("should not have x-nonexistent")
	}
}

// === WorkerPool tests ===

func TestWorkerPool_SubmitAndStop(t *testing.T) {
	done := make(chan struct{})
	handler := func(ctx *RequestCtx) {
		close(done)
	}
	wp := NewWorkerPool(2, handler)

	ctx := acquireCtx()
	if !wp.Submit(ctx) {
		t.Fatal("submit failed")
	}
	<-done
	wp.Stop()
}
