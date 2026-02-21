package header

import (
	"strings"
	"testing"
)

func FuzzParseRequest(f *testing.F) {
	// Valid seeds.
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"))
	f.Add([]byte("PUT /data HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"))
	f.Add([]byte("DELETE /item HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	f.Add([]byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"))
	f.Add([]byte("OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add([]byte("GET /path?query=1&foo=bar HTTP/1.1\r\nHost: x\r\n\r\n"))

	// Multiple headers.
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\nUser-Agent: test\r\nCookie: a=b\r\n\r\n"))

	// Malformed seeds.
	f.Add([]byte("INVALID"))
	f.Add([]byte("\x00\x00\x00"))
	f.Add([]byte(""))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte("GET"))
	f.Add([]byte("GET /"))
	f.Add([]byte("GET / HTTP"))
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte("\xff\xff\xff\xff"))

	// Many headers.
	f.Add([]byte("GET / HTTP/1.1\r\n" + strings.Repeat("X-Header: value\r\n", 100) + "\r\n"))

	// Large URI.
	f.Add([]byte("GET /" + strings.Repeat("a", 1000) + " HTTP/1.1\r\nHost: x\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var r ParsedRequest
		// Must never panic.
		_, _ = Parse(data, &r)
	})
}
