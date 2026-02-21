package http2

import (
	"sync"

	"github.com/blazehttp/blazehttp/internal/util"
	"github.com/blazehttp/blazehttp/pkg/bytespool"
	"github.com/blazehttp/blazehttp/pkg/frame"
	"github.com/blazehttp/blazehttp/pkg/hpack"
)

const maxRequestHeaders = 128

// Request represents an HTTP/2 request reconstructed from HPACK-decoded headers.
type Request struct {
	method    []byte
	scheme    []byte
	path      []byte
	authority []byte

	headers    [maxRequestHeaders]headerKV
	numHeaders int

	contentLength int64

	body    []byte
	bodyBuf []byte // owned buffer from bytespool

	// dataBuf accumulates copies of all header name/value data.
	// This prevents aliasing with the HPACK decoder's internal buffer
	// which is reused across Decode calls.
	dataBuf []byte

	streamID uint32

	trailers    [32]headerKV
	numTrailers int
}

type headerKV struct {
	name  []byte
	value []byte
}

var requestPool = sync.Pool{
	New: func() any { return &Request{} },
}

func acquireRequest() *Request {
	r := requestPool.Get().(*Request)
	r.Reset()
	return r
}

func releaseRequest(r *Request) {
	r.Reset()
	requestPool.Put(r)
}

// Reset clears the request for reuse.
func (r *Request) Reset() {
	r.method = nil
	r.scheme = nil
	r.path = nil
	r.authority = nil
	r.numHeaders = 0
	r.contentLength = -1
	r.body = nil
	if r.bodyBuf != nil {
		bytespool.Put(r.bodyBuf)
		r.bodyBuf = nil
	}
	r.dataBuf = r.dataBuf[:0]
	r.streamID = 0
	r.numTrailers = 0
}

// copyBytes appends b to the internal dataBuf and returns the copy.
func (r *Request) copyBytes(b []byte) []byte {
	off := len(r.dataBuf)
	r.dataBuf = append(r.dataBuf, b...)
	return r.dataBuf[off : off+len(b)]
}

// FromHeaders reconstructs the request from HPACK decoded fields.
// Validates pseudo-headers per RFC 9113 §8.3.
// All field data is copied into the request's owned buffer.
func (r *Request) FromHeaders(fields []hpack.DecodedField) error {
	pseudoDone := false

	// Pre-size dataBuf if empty.
	if r.dataBuf == nil {
		r.dataBuf = make([]byte, 0, 512)
	}

	for i := range fields {
		f := &fields[i]
		name := f.Name
		value := f.Value

		if len(name) > 0 && name[0] == ':' {
			// Pseudo-header.
			if pseudoDone {
				return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
			}
			switch string(name) {
			case ":method":
				if r.method != nil {
					return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
				}
				r.method = r.copyBytes(value)
			case ":scheme":
				if r.scheme != nil {
					return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
				}
				r.scheme = r.copyBytes(value)
			case ":path":
				if r.path != nil {
					return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
				}
				// Empty :path is not allowed per RFC 9113 §8.3.1.
				if len(value) == 0 {
					return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
				}
				r.path = r.copyBytes(value)
			case ":authority":
				if r.authority != nil {
					return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
				}
				r.authority = r.copyBytes(value)
			default:
				return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
			}
		} else {
			pseudoDone = true

			// Reject uppercase header field names per RFC 9113 §8.2.1.
			if hasUppercase(name) {
				return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
			}

			// Reject connection-specific headers per RFC 9113 §8.2.2.
			if isConnectionHeader(name) {
				return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
			}

			// TE header: only "trailers" is allowed per RFC 9113 §8.2.2.
			if len(name) == 2 && string(name) == "te" {
				if string(value) != "trailers" {
					return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
				}
			}

			// Parse content-length.
			if len(name) == 14 && string(name) == "content-length" {
				if cl, err := util.ParseUint(value); err == nil {
					r.contentLength = int64(cl)
				}
			}

			if r.numHeaders < maxRequestHeaders {
				r.headers[r.numHeaders] = headerKV{
					name:  r.copyBytes(name),
					value: r.copyBytes(value),
				}
				r.numHeaders++
			}
		}
	}

	// Validate required pseudo-headers.
	if r.method == nil {
		return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
	}
	// For non-CONNECT methods, :scheme and :path are required per RFC 9113 §8.3.1.
	if string(r.method) != "CONNECT" {
		if r.path == nil {
			return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
		}
		if r.scheme == nil {
			return &StreamError{StreamID: r.streamID, Code: frame.ErrCodeProtocolError}
		}
	}

	return nil
}

// hasUppercase reports whether name contains any uppercase ASCII letter.
// HTTP/2 header field names MUST be lowercase per RFC 9113 §8.2.1.
func hasUppercase(name []byte) bool {
	for _, c := range name {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// isConnectionHeader returns true if the header is connection-specific
// and must be rejected in HTTP/2 per RFC 9113 §8.2.2.
func isConnectionHeader(name []byte) bool {
	switch len(name) {
	case 7:
		return string(name) == "upgrade"
	case 10:
		s := string(name)
		return s == "connection" || s == "keep-alive"
	case 16:
		return string(name) == "proxy-connection"
	case 17:
		return string(name) == "transfer-encoding"
	}
	return false
}

// setTrailers sets trailing headers on the request.
func (r *Request) setTrailers(fields []hpack.DecodedField) {
	for i := range fields {
		if r.numTrailers >= len(r.trailers) {
			break
		}
		r.trailers[r.numTrailers] = headerKV{
			name:  r.copyBytes(fields[i].Name),
			value: r.copyBytes(fields[i].Value),
		}
		r.numTrailers++
	}
}

// AppendBody appends DATA frame payload to the request body.
func (r *Request) AppendBody(data []byte) {
	if len(data) == 0 {
		return
	}
	if r.bodyBuf == nil {
		r.bodyBuf = bytespool.Get(len(data))[:0]
	}
	r.bodyBuf = append(r.bodyBuf, data...)
	r.body = r.bodyBuf
}

// Accessors.

func (r *Request) Method() []byte      { return r.method }
func (r *Request) Scheme() []byte      { return r.scheme }
func (r *Request) Path() []byte        { return r.path }
func (r *Request) Authority() []byte   { return r.authority }
func (r *Request) Body() []byte        { return r.body }
func (r *Request) ContentLength() int64 { return r.contentLength }
func (r *Request) StreamID() uint32    { return r.streamID }

// SetMethod sets the request method.
func (r *Request) SetMethod(m []byte) { r.method = r.copyBytes(m) }

// SetPath sets the request path.
func (r *Request) SetPath(p []byte) { r.path = r.copyBytes(p) }

// SetScheme sets the request scheme.
func (r *Request) SetScheme(s []byte) { r.scheme = r.copyBytes(s) }

// SetAuthority sets the request authority (host).
func (r *Request) SetAuthority(a []byte) { r.authority = r.copyBytes(a) }

// SetBody sets the request body.
func (r *Request) SetBody(b []byte) { r.body = b }

// AddHeader adds a regular header to the request.
func (r *Request) AddHeader(name, value []byte) {
	if r.numHeaders < maxRequestHeaders {
		r.headers[r.numHeaders] = headerKV{
			name:  r.copyBytes(name),
			value: r.copyBytes(value),
		}
		r.numHeaders++
	}
}

// Header returns the first value for the given header name, or nil.
func (r *Request) Header(name []byte) []byte {
	for i := 0; i < r.numHeaders; i++ {
		if util.EqualFold(r.headers[i].name, name) {
			return r.headers[i].value
		}
	}
	return nil
}

// NumHeaders returns the number of regular headers.
func (r *Request) NumHeaders() int { return r.numHeaders }

// HeaderAt returns the name and value at index i.
func (r *Request) HeaderAt(i int) ([]byte, []byte) {
	if i < 0 || i >= r.numHeaders {
		return nil, nil
	}
	return r.headers[i].name, r.headers[i].value
}

// StreamError represents an HTTP/2 stream-level error.
type StreamError struct {
	StreamID uint32
	Code     frame.ErrorCode
}

func (e *StreamError) Error() string {
	return "http2: stream error: " + e.Code.String()
}
