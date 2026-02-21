package http2

import (
	"sync"

	"github.com/blazehttp/blazehttp/internal/util"
	"github.com/blazehttp/blazehttp/pkg/hpack"
)

const maxRespHeaders = 32

// Response represents an HTTP/2 response.
type Response struct {
	statusCode int
	headers    [maxRespHeaders]headerKV
	numHeaders int
	body       []byte
}

var responsePool = sync.Pool{
	New: func() any { return &Response{} },
}

func acquireResponse() *Response {
	r := responsePool.Get().(*Response)
	r.statusCode = 200
	r.numHeaders = 0
	r.body = nil
	return r
}

func releaseResponse(r *Response) {
	r.Reset()
	responsePool.Put(r)
}

// Reset clears the response for reuse.
func (r *Response) Reset() {
	r.statusCode = 200
	r.numHeaders = 0
	r.body = nil
}

// SetStatusCode sets the HTTP response status code.
func (r *Response) SetStatusCode(code int) { r.statusCode = code }

// StatusCode returns the current status code.
func (r *Response) StatusCode() int { return r.statusCode }

// SetHeader adds or replaces a response header.
func (r *Response) SetHeader(key, value []byte) {
	for i := 0; i < r.numHeaders; i++ {
		if util.EqualFold(r.headers[i].name, key) {
			r.headers[i].value = value
			return
		}
	}
	if r.numHeaders < maxRespHeaders {
		r.headers[r.numHeaders] = headerKV{name: key, value: value}
		r.numHeaders++
	}
}

var contentTypeKey = []byte("content-type")

// SetContentType is a convenience method for setting content-type.
func (r *Response) SetContentType(ct []byte) {
	r.SetHeader(contentTypeKey, ct)
}

// SetBody sets the response body.
func (r *Response) SetBody(body []byte) { r.body = body }

// SetBodyString sets the response body from a string.
func (r *Response) SetBodyString(s string) {
	r.body = util.StringToBytes(s)
}

// Body returns the response body.
func (r *Response) Body() []byte { return r.body }

// Pre-computed status code byte slices for zero-alloc encoding.
var statusBytesTable [600][]byte

func init() {
	for i := 100; i < 600; i++ {
		var buf [3]byte
		buf[0] = byte('0' + i/100)
		buf[1] = byte('0' + (i/10)%10)
		buf[2] = byte('0' + i%10)
		statusBytesTable[i] = append([]byte(nil), buf[:]...)
	}
}

func statusCodeBytes(code int) []byte {
	if code >= 100 && code < 600 {
		return statusBytesTable[code]
	}
	return []byte("500")
}

// EncodeHeaders encodes the response headers using the provided HPACK encoder.
// Returns the encoded header block. Valid until the encoder is reset.
func (r *Response) EncodeHeaders(enc *hpack.Encoder) []byte {
	enc.Reset()

	// :status pseudo-header.
	enc.EncodeSingle([]byte(":status"), statusCodeBytes(r.statusCode), false)

	// Regular headers.
	for i := 0; i < r.numHeaders; i++ {
		h := &r.headers[i]
		enc.EncodeSingle(h.name, h.value, false)
	}

	// Content-length if body is set and not already present.
	if r.body != nil && !r.hasHeader([]byte("content-length")) {
		var clBuf [20]byte
		cl := util.AppendUint(clBuf[:0], uint64(len(r.body)))
		enc.EncodeSingle([]byte("content-length"), cl, false)
	}

	return enc.Bytes()
}

// NumHeaders returns the number of response headers.
func (r *Response) NumHeaders() int { return r.numHeaders }

// HeaderAt returns the name and value of the header at index i.
func (r *Response) HeaderAt(i int) ([]byte, []byte) {
	if i < 0 || i >= r.numHeaders {
		return nil, nil
	}
	return r.headers[i].name, r.headers[i].value
}

func (r *Response) hasHeader(name []byte) bool {
	for i := 0; i < r.numHeaders; i++ {
		if util.EqualFold(r.headers[i].name, name) {
			return true
		}
	}
	return false
}
