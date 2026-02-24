package bench

import (
	"testing"

	"github.com/justIliane/blazehttp/pkg/hpack"
	"github.com/justIliane/blazehttp/server/http1"
	"github.com/justIliane/blazehttp/server/http2"
)

// Pre-built HTTP/1.1 request bytes for benchmarks.
var rawHTTP1Get = []byte("GET /plaintext HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n")
var rawHTTP1JSON = []byte("GET /json HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nAccept: application/json\r\n\r\n")

// Pre-allocated response payloads.
var (
	plaintextBody = []byte("Hello, World!")
	jsonBody      = []byte(`{"message":"Hello, World!"}`)
	contentPlain  = []byte("text/plain")
	contentJSON   = []byte("application/json")
)

// ========== HTTP/1.1 Benchmarks ==========

// BenchmarkHTTP1_Plaintext measures the full HTTP/1.1 hot path:
// parse request → call handler → build response.
func BenchmarkHTTP1_Plaintext(b *testing.B) {
	b.ReportAllocs()

	handler := func(ctx *http1.RequestCtx) {
		ctx.Response.SetStatusCode(200)
		ctx.Response.SetContentType(contentPlain)
		ctx.Response.SetBody(plaintextBody)
	}

	req := http1.AcquireRequest()
	resp := http1.AcquireResponse()
	defer http1.ReleaseRequest(req)
	defer http1.ReleaseResponse(resp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Reset()
		resp.Reset()

		req.Parse(rawHTTP1Get)

		ctx := &http1.RequestCtx{}
		ctx.Request = *req
		ctx.Response = *resp
		handler(ctx)
		ctx.Response.Build(true)

		*req = ctx.Request
		*resp = ctx.Response
	}
}

// BenchmarkHTTP1_JSON measures the JSON response path.
func BenchmarkHTTP1_JSON(b *testing.B) {
	b.ReportAllocs()

	handler := func(ctx *http1.RequestCtx) {
		ctx.Response.SetStatusCode(200)
		ctx.Response.SetContentType(contentJSON)
		ctx.Response.SetBody(jsonBody)
	}

	req := http1.AcquireRequest()
	resp := http1.AcquireResponse()
	defer http1.ReleaseRequest(req)
	defer http1.ReleaseResponse(resp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Reset()
		resp.Reset()

		req.Parse(rawHTTP1JSON)

		ctx := &http1.RequestCtx{}
		ctx.Request = *req
		ctx.Response = *resp
		handler(ctx)
		ctx.Response.Build(true)

		*req = ctx.Request
		*resp = ctx.Response
	}
}

// ========== HTTP/2 Benchmarks ==========

// Pre-encoded HPACK header block for a GET /plaintext request.
var h2GetPlaintextHeaders []hpack.DecodedField

func init() {
	h2GetPlaintextHeaders = []hpack.DecodedField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/plaintext")},
		{Name: []byte(":scheme"), Value: []byte("https")},
		{Name: []byte(":authority"), Value: []byte("localhost")},
		{Name: []byte("accept"), Value: []byte("*/*")},
	}
}

// BenchmarkHTTP2_HeadersDecode measures HPACK decoding of a typical request.
func BenchmarkHTTP2_HeadersDecode(b *testing.B) {
	b.ReportAllocs()

	// Encode once to get the header block.
	enc := hpack.AcquireEncoder()
	for _, f := range h2GetPlaintextHeaders {
		enc.EncodeSingle(f.Name, f.Value, false)
	}
	headerBlock := make([]byte, len(enc.Bytes()))
	copy(headerBlock, enc.Bytes())
	hpack.ReleaseEncoder(enc)

	dec := hpack.AcquireDecoder()
	defer hpack.ReleaseDecoder(dec)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec.Decode(headerBlock)
	}
}

// BenchmarkHTTP2_ResponseEncode measures HPACK encoding of a typical response.
func BenchmarkHTTP2_ResponseEncode(b *testing.B) {
	b.ReportAllocs()

	resp := &http2.Response{}
	resp.Reset()
	resp.SetStatusCode(200)
	resp.SetContentType(contentPlain)
	resp.SetBody(plaintextBody)

	enc := hpack.AcquireEncoder()
	defer hpack.ReleaseEncoder(enc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.EncodeHeaders(enc)
	}
}

// BenchmarkHTTP2_FullCycle measures the complete HTTP/2 request processing:
// decode HPACK headers → build Request → call handler → encode response.
func BenchmarkHTTP2_FullCycle(b *testing.B) {
	b.ReportAllocs()

	// Pre-encode the header block.
	enc := hpack.AcquireEncoder()
	for _, f := range h2GetPlaintextHeaders {
		enc.EncodeSingle(f.Name, f.Value, false)
	}
	headerBlock := make([]byte, len(enc.Bytes()))
	copy(headerBlock, enc.Bytes())
	hpack.ReleaseEncoder(enc)

	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.Response.SetContentType(contentPlain)
		ctx.Response.SetBody(plaintextBody)
	}

	dec := hpack.AcquireDecoder()
	respEnc := hpack.AcquireEncoder()
	defer hpack.ReleaseDecoder(dec)
	defer hpack.ReleaseEncoder(respEnc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 1. Decode HPACK headers.
		fields, _ := dec.Decode(headerBlock)

		// 2. Build request from headers.
		ctx := &http2.RequestCtx{}
		ctx.Request.Reset()
		ctx.Response.Reset()
		ctx.Request.FromHeaders(fields)

		// 3. Call handler.
		handler(ctx)

		// 4. Encode response headers.
		ctx.Response.EncodeHeaders(respEnc)
	}
}

// ========== Comparative: BlazeHTTP vs fasthttp (in-process parse+respond) ==========

// BenchmarkFastHTTP_Plaintext measures fasthttp's request/response cycle.
func BenchmarkFastHTTP_Plaintext(b *testing.B) {
	b.ReportAllocs()

	// We can't easily benchmark fasthttp's full cycle in-process without
	// running a full server, since its request parsing is tightly coupled
	// to the connection handler. Instead, we compare at the parser level,
	// which is done in pkg/header/parser_bench_test.go.
	b.Skip("fasthttp comparison uses wrk (external benchmark)")
}
