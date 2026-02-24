// Package http1 implements the HTTP/1.1 server handler for BlazeHTTP.
package http1

import (
	"sync"

	"github.com/justIliane/blazehttp/pkg/bytespool"
	"github.com/justIliane/blazehttp/pkg/header"
)

// Request represents an HTTP/1.1 request. It is pooled via sync.Pool
// to avoid allocations. All returned slices point into the internal
// read buffer and are valid only until the Request is released.
type Request struct {
	parsed header.ParsedRequest

	// rawBuf is the reference to the network buffer the request was parsed from.
	// All slices in parsed point into this buffer.
	rawBuf []byte

	// body is a slice into rawBuf (for Content-Length bodies)
	// or a decoded buffer (for chunked bodies, owned and pooled separately).
	body        []byte
	chunkedBody []byte // non-nil if body was decoded from chunked TE

	// total bytes consumed from the buffer (headers + body)
	totalBytes int
}

var requestPool = sync.Pool{
	New: func() any {
		return &Request{}
	},
}

// AcquireRequest gets a Request from the pool.
func AcquireRequest() *Request {
	return requestPool.Get().(*Request)
}

// ReleaseRequest returns a Request to the pool.
func ReleaseRequest(r *Request) {
	r.Reset()
	requestPool.Put(r)
}

// Reset clears the request for reuse.
func (r *Request) Reset() {
	r.parsed.Reset()
	r.rawBuf = nil
	r.body = nil
	if r.chunkedBody != nil {
		bytespool.Put(r.chunkedBody)
		r.chunkedBody = nil
	}
	r.totalBytes = 0
}

// Parse parses an HTTP request from buf. Returns the total bytes consumed
// (headers + body) or an error.
func (r *Request) Parse(buf []byte) (int, error) {
	r.Reset()
	r.rawBuf = buf

	n, err := header.Parse(buf, &r.parsed)
	if err != nil {
		return 0, err
	}
	r.totalBytes = n

	// Read body based on Content-Length or chunked TE.
	if r.parsed.Chunked {
		bodyStart := n
		body, consumed, err := parseChunkedBody(buf[bodyStart:])
		if err != nil {
			return 0, err
		}
		r.body = body
		r.chunkedBody = body // track pooled buffer for release in Reset
		r.totalBytes += consumed
	} else if r.parsed.ContentLength > 0 {
		bodyStart := n
		bodyEnd := bodyStart + int(r.parsed.ContentLength)
		if bodyEnd > len(buf) {
			return 0, header.ErrNeedMore
		}
		r.body = buf[bodyStart:bodyEnd]
		r.totalBytes = bodyEnd
	}

	return r.totalBytes, nil
}

// Method returns the HTTP method (e.g., GET, POST).
func (r *Request) Method() []byte {
	return r.parsed.Method
}

// Path returns the request URI path.
func (r *Request) Path() []byte {
	return r.parsed.URI
}

// Version returns the HTTP version string (e.g., "HTTP/1.1").
func (r *Request) Version() []byte {
	return r.parsed.Version
}

// Header returns the value of the first header matching key (case-insensitive).
func (r *Request) Header(key []byte) []byte {
	return r.parsed.HeaderValue(key)
}

// Body returns the request body, if any.
func (r *Request) Body() []byte {
	return r.body
}

// ContentLength returns the parsed Content-Length, or -1 if not present.
func (r *Request) ContentLength() int64 {
	return r.parsed.ContentLength
}

// IsChunked reports whether the request uses chunked transfer encoding.
func (r *Request) IsChunked() bool {
	return r.parsed.Chunked
}

// IsKeepAlive reports whether the connection should be kept alive.
func (r *Request) IsKeepAlive() bool {
	return r.parsed.KeepAlive
}

// NumHeaders returns the number of parsed headers.
func (r *Request) NumHeaders() int {
	return r.parsed.NumHeaders
}

// HeaderByIndex returns the key and value of the header at the given index.
func (r *Request) HeaderByIndex(i int) (key, value []byte) {
	if i < 0 || i >= r.parsed.NumHeaders {
		return nil, nil
	}
	h := &r.parsed.Headers[i]
	return h.Key, h.Value
}

// parseChunkedBody parses a chunked transfer-encoded body.
// Returns the decoded body, total bytes consumed from buf, and any error.
func parseChunkedBody(buf []byte) (body []byte, consumed int, err error) {
	// Accumulate chunks into a result slice.
	// We build the body in-place or into a pooled buffer.
	var result []byte
	pos := 0

	for {
		// Parse chunk size (hex).
		sizeStart := pos
		for pos < len(buf) && buf[pos] != '\r' {
			pos++
		}
		if pos+1 >= len(buf) {
			return nil, 0, header.ErrNeedMore
		}
		if buf[pos+1] != '\n' {
			return nil, 0, header.ErrMalformedRequest
		}

		// Parse hex size.
		chunkSize, ok := parseHex(buf[sizeStart:pos])
		if !ok {
			return nil, 0, header.ErrMalformedRequest
		}

		pos += 2 // skip \r\n

		if chunkSize == 0 {
			// Final chunk. Expect \r\n after 0-size chunk.
			if pos+1 >= len(buf) {
				return nil, 0, header.ErrNeedMore
			}
			if buf[pos] == '\r' && buf[pos+1] == '\n' {
				pos += 2
			}
			return result, pos, nil
		}

		// Read chunk data.
		if pos+int(chunkSize)+2 > len(buf) {
			return nil, 0, header.ErrNeedMore
		}

		// Lazy-init result buffer.
		if result == nil {
			result = bytespool.Get(int(chunkSize))[:0]
		}
		result = append(result, buf[pos:pos+int(chunkSize)]...)
		pos += int(chunkSize)

		// Expect \r\n after chunk data.
		if buf[pos] != '\r' || buf[pos+1] != '\n' {
			return nil, 0, header.ErrMalformedRequest
		}
		pos += 2
	}
}

// parseHex parses a hexadecimal number from b without allocation.
func parseHex(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, false
		}
		n = n<<4 | int64(v)
		if n < 0 {
			return 0, false // overflow
		}
	}
	return n, true
}
