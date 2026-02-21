package http1

import (
	"sync"

	"github.com/blazehttp/blazehttp/internal/util"
	"github.com/blazehttp/blazehttp/pkg/bytespool"
)

const defaultBufSize = 4096

// Response represents an HTTP/1.1 response. It is pooled via sync.Pool.
// The response writes directly into a pooled buffer for zero-alloc operation.
type Response struct {
	statusCode int
	headers    [maxRespHeaders]respHeader
	numHeaders int
	body       []byte

	// buf is the assembled response buffer, owned by bytespool.
	buf []byte
}

const maxRespHeaders = 32

type respHeader struct {
	key   []byte
	value []byte
}

var responsePool = sync.Pool{
	New: func() any {
		return &Response{}
	},
}

// AcquireResponse gets a Response from the pool.
func AcquireResponse() *Response {
	r := responsePool.Get().(*Response)
	r.statusCode = 200
	return r
}

// ReleaseResponse returns a Response to the pool.
func ReleaseResponse(r *Response) {
	r.Reset()
	responsePool.Put(r)
}

// Reset clears the response for reuse.
func (r *Response) Reset() {
	r.statusCode = 200
	r.numHeaders = 0
	r.body = nil
	if r.buf != nil {
		bytespool.Put(r.buf)
		r.buf = nil
	}
}

// SetStatusCode sets the HTTP status code.
func (r *Response) SetStatusCode(code int) {
	r.statusCode = code
}

// StatusCode returns the current status code.
func (r *Response) StatusCode() int {
	return r.statusCode
}

// SetHeader adds or replaces a response header.
func (r *Response) SetHeader(key, value []byte) {
	// Check if header already exists.
	for i := 0; i < r.numHeaders; i++ {
		if util.EqualFold(r.headers[i].key, key) {
			r.headers[i].value = value
			return
		}
	}
	if r.numHeaders < maxRespHeaders {
		r.headers[r.numHeaders] = respHeader{key: key, value: value}
		r.numHeaders++
	}
}

// SetContentType is a convenience method for setting Content-Type.
func (r *Response) SetContentType(ct []byte) {
	r.SetHeader([]byte("Content-Type"), ct)
}

// SetBody sets the response body.
func (r *Response) SetBody(body []byte) {
	r.body = body
}

// SetBodyString sets the response body from a string.
func (r *Response) SetBodyString(s string) {
	r.body = util.StringToBytes(s)
}

// Body returns the response body.
func (r *Response) Body() []byte {
	return r.body
}

// Build assembles the full HTTP response into a pooled buffer and returns it.
// The returned buffer is valid until the Response is released.
func (r *Response) Build(keepAlive bool) []byte {
	// Estimate size.
	size := 64 // status line + some overhead
	for i := 0; i < r.numHeaders; i++ {
		size += len(r.headers[i].key) + len(r.headers[i].value) + 4 // ": " + "\r\n"
	}
	size += 32 // Content-Length header
	size += len(r.body)

	if r.buf != nil {
		bytespool.Put(r.buf)
	}
	r.buf = bytespool.Get(size)[:0]

	// Status line.
	r.buf = append(r.buf, "HTTP/1.1 "...)
	r.buf = appendStatusCode(r.buf, r.statusCode)
	r.buf = append(r.buf, '\r', '\n')

	// Headers.
	for i := 0; i < r.numHeaders; i++ {
		r.buf = append(r.buf, r.headers[i].key...)
		r.buf = append(r.buf, ':', ' ')
		r.buf = append(r.buf, r.headers[i].value...)
		r.buf = append(r.buf, '\r', '\n')
	}

	// Content-Length.
	r.buf = append(r.buf, "Content-Length: "...)
	r.buf = util.AppendUint(r.buf, uint64(len(r.body)))
	r.buf = append(r.buf, '\r', '\n')

	// Connection header.
	if keepAlive {
		r.buf = append(r.buf, "Connection: keep-alive\r\n"...)
	} else {
		r.buf = append(r.buf, "Connection: close\r\n"...)
	}

	// End of headers.
	r.buf = append(r.buf, '\r', '\n')

	// Body.
	r.buf = append(r.buf, r.body...)

	return r.buf
}

// BuildChunked assembles a chunked HTTP response. It writes the headers
// with Transfer-Encoding: chunked and then each body as a chunk.
// For Phase 1, this provides single-chunk encoding.
func (r *Response) BuildChunked(keepAlive bool) []byte {
	size := 128
	for i := 0; i < r.numHeaders; i++ {
		size += len(r.headers[i].key) + len(r.headers[i].value) + 4
	}
	size += len(r.body) + 32

	if r.buf != nil {
		bytespool.Put(r.buf)
	}
	r.buf = bytespool.Get(size)[:0]

	// Status line.
	r.buf = append(r.buf, "HTTP/1.1 "...)
	r.buf = appendStatusCode(r.buf, r.statusCode)
	r.buf = append(r.buf, '\r', '\n')

	// Headers.
	for i := 0; i < r.numHeaders; i++ {
		r.buf = append(r.buf, r.headers[i].key...)
		r.buf = append(r.buf, ':', ' ')
		r.buf = append(r.buf, r.headers[i].value...)
		r.buf = append(r.buf, '\r', '\n')
	}

	// Transfer-Encoding and Connection.
	r.buf = append(r.buf, "Transfer-Encoding: chunked\r\n"...)
	if keepAlive {
		r.buf = append(r.buf, "Connection: keep-alive\r\n"...)
	} else {
		r.buf = append(r.buf, "Connection: close\r\n"...)
	}
	r.buf = append(r.buf, '\r', '\n')

	// Single chunk.
	if len(r.body) > 0 {
		r.buf = appendHex(r.buf, len(r.body))
		r.buf = append(r.buf, '\r', '\n')
		r.buf = append(r.buf, r.body...)
		r.buf = append(r.buf, '\r', '\n')
	}

	// Final chunk.
	r.buf = append(r.buf, '0', '\r', '\n', '\r', '\n')

	return r.buf
}

// appendStatusCode appends "XXX Reason" to dst.
func appendStatusCode(dst []byte, code int) []byte {
	// Fast path for common codes.
	switch code {
	case 200:
		return append(dst, "200 OK"...)
	case 201:
		return append(dst, "201 Created"...)
	case 204:
		return append(dst, "204 No Content"...)
	case 301:
		return append(dst, "301 Moved Permanently"...)
	case 302:
		return append(dst, "302 Found"...)
	case 304:
		return append(dst, "304 Not Modified"...)
	case 400:
		return append(dst, "400 Bad Request"...)
	case 401:
		return append(dst, "401 Unauthorized"...)
	case 403:
		return append(dst, "403 Forbidden"...)
	case 404:
		return append(dst, "404 Not Found"...)
	case 405:
		return append(dst, "405 Method Not Allowed"...)
	case 500:
		return append(dst, "500 Internal Server Error"...)
	case 502:
		return append(dst, "502 Bad Gateway"...)
	case 503:
		return append(dst, "503 Service Unavailable"...)
	default:
		dst = util.AppendUint(dst, uint64(code))
		dst = append(dst, ' ')
		dst = append(dst, statusText(code)...)
		return dst
	}
}

// statusText returns the reason phrase for an HTTP status code.
func statusText(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 413:
		return "Content Too Large"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return "Unknown"
	}
}

// appendHex appends the hex representation of n to dst.
func appendHex(dst []byte, n int) []byte {
	if n == 0 {
		return append(dst, '0')
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = "0123456789abcdef"[n&0xf]
		n >>= 4
	}
	return append(dst, buf[i:]...)
}
