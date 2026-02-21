package header

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

// Benchmark data: typical browser GET request.
var benchBuf = []byte("GET /path/to/resource?q=search&page=1 HTTP/1.1\r\n" +
	"Host: www.example.com\r\n" +
	"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
	"Accept-Language: en-US,en;q=0.9,fr;q=0.8\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n" +
	"Connection: keep-alive\r\n" +
	"Cookie: session=abc123def456; theme=dark; lang=en\r\n" +
	"Cache-Control: max-age=0\r\n" +
	"\r\n")

// BenchmarkBlazeHTTP1Parse benchmarks BlazeHTTP's parser on a typical request.
func BenchmarkBlazeHTTP1Parse(b *testing.B) {
	var r ParsedRequest
	b.ReportAllocs()
	b.SetBytes(int64(len(benchBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		_, _ = Parse(benchBuf, &r)
	}
}

// BenchmarkFasthttpParse benchmarks fasthttp's parser on the same request.
func BenchmarkFasthttpParse(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(benchBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req fasthttp.Request
		br := bufio.NewReader(bytes.NewReader(benchBuf))
		req.Header.DisableNormalizing()
		_ = req.Header.Read(br)
	}
}

// BenchmarkFasthttpParse_Reuse benchmarks fasthttp with object reuse (more realistic).
func BenchmarkFasthttpParse_Reuse(b *testing.B) {
	var req fasthttp.Request
	br := bufio.NewReaderSize(bytes.NewReader(benchBuf), len(benchBuf)+64)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Header.DisableNormalizing()
		br.Reset(bytes.NewReader(benchBuf))
		_ = req.Header.Read(br)
		req.Reset()
	}
}

// Benchmark with simple GET (minimal headers).
var simpleBuf = []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

func BenchmarkBlazeHTTP1Parse_Simple(b *testing.B) {
	var r ParsedRequest
	b.ReportAllocs()
	b.SetBytes(int64(len(simpleBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		_, _ = Parse(simpleBuf, &r)
	}
}

func BenchmarkFasthttpParse_Simple(b *testing.B) {
	var req fasthttp.Request
	br := bufio.NewReaderSize(bytes.NewReader(simpleBuf), len(simpleBuf)+64)
	b.ReportAllocs()
	b.SetBytes(int64(len(simpleBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Header.DisableNormalizing()
		br.Reset(bytes.NewReader(simpleBuf))
		_ = req.Header.Read(br)
		req.Reset()
	}
}

// Benchmark with many headers (20 custom headers).
var manyHeadersBuf = func() []byte {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	sb.WriteString("Host: example.com\r\n")
	for i := 0; i < 20; i++ {
		sb.WriteString("X-Custom-Header-Name: some-header-value-here\r\n")
	}
	sb.WriteString("\r\n")
	return []byte(sb.String())
}()

func BenchmarkBlazeHTTP1Parse_ManyHeaders(b *testing.B) {
	var r ParsedRequest
	b.ReportAllocs()
	b.SetBytes(int64(len(manyHeadersBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		_, _ = Parse(manyHeadersBuf, &r)
	}
}

func BenchmarkFasthttpParse_ManyHeaders(b *testing.B) {
	var req fasthttp.Request
	br := bufio.NewReaderSize(bytes.NewReader(manyHeadersBuf), len(manyHeadersBuf)+64)
	b.ReportAllocs()
	b.SetBytes(int64(len(manyHeadersBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Header.DisableNormalizing()
		br.Reset(bytes.NewReader(manyHeadersBuf))
		_ = req.Header.Read(br)
		req.Reset()
	}
}
