package hpack

import "testing"

// Typical 10-header HTTP/2 request.
var benchHeaders = []HeaderField{
	{Name: []byte(":method"), Value: []byte("GET")},
	{Name: []byte(":scheme"), Value: []byte("https")},
	{Name: []byte(":path"), Value: []byte("/index.html")},
	{Name: []byte(":authority"), Value: []byte("www.example.com")},
	{Name: []byte("accept"), Value: []byte("text/html,application/xhtml+xml")},
	{Name: []byte("accept-encoding"), Value: []byte("gzip, deflate, br")},
	{Name: []byte("accept-language"), Value: []byte("en-US,en;q=0.9")},
	{Name: []byte("user-agent"), Value: []byte("Mozilla/5.0")},
	{Name: []byte("cookie"), Value: []byte("session=abc123")},
	{Name: []byte("cache-control"), Value: []byte("no-cache")},
}

func BenchmarkHPACKEncode(b *testing.B) {
	enc := newEncoder(4096)
	// Warm up the dynamic table.
	enc.Encode(benchHeaders)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.Reset()
		enc.Encode(benchHeaders)
	}
}

func BenchmarkHPACKDecode(b *testing.B) {
	enc := newEncoder(4096)
	// First encode: cold — produces literals + indexed references.
	coldEncoded := enc.Encode(benchHeaders)
	// Second encode: warm — produces all indexed references (typical warm path).
	enc.Reset()
	warmEncoded := enc.Encode(benchHeaders)
	data := make([]byte, len(warmEncoded))
	copy(data, warmEncoded)

	dec := newDecoder(4096)
	// Populate decoder's dynamic table with cold data (has literal-with-indexing).
	dec.Decode(coldEncoded)
	dec.Reset()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec.Reset()
		dec.Decode(data)
	}
}

func BenchmarkHPACKEncode_FirstBlock(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc := newEncoder(4096)
		enc.Encode(benchHeaders)
	}
}

func BenchmarkHPACKDecode_FirstBlock(b *testing.B) {
	enc := newEncoder(4096)
	encoded := enc.Encode(benchHeaders)
	data := make([]byte, len(encoded))
	copy(data, encoded)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec := newDecoder(4096)
		dec.Decode(data)
	}
}

func BenchmarkHuffmanEncode(b *testing.B) {
	src := []byte("www.example.com")
	dst := make([]byte, 0, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = huffmanEncode(dst[:0], src)
	}
}

func BenchmarkHuffmanDecode(b *testing.B) {
	src := []byte("www.example.com")
	encoded := huffmanEncode(nil, src)
	dst := make([]byte, 0, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = huffmanDecode(dst[:0], encoded)
	}
}

func BenchmarkHuffmanEncodeLong(b *testing.B) {
	src := []byte("Mon, 21 Oct 2013 20:13:21 GMT; foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")
	dst := make([]byte, 0, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = huffmanEncode(dst[:0], src)
	}
}

func BenchmarkHuffmanDecodeLong(b *testing.B) {
	src := []byte("Mon, 21 Oct 2013 20:13:21 GMT; foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")
	encoded := huffmanEncode(nil, src)
	dst := make([]byte, 0, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = huffmanDecode(dst[:0], encoded)
	}
}
