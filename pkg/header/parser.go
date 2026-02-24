// Package header provides a zero-allocation HTTP/1.1 request parser.
//
// The parser works directly on the network buffer and returns slices pointing
// into the original buffer. No copies are made during parsing. All method
// return values are valid only as long as the underlying buffer is not modified.
package header

import (
	"errors"

	"github.com/justIliane/blazehttp/internal/util"
)

// Parsing errors.
var (
	ErrNeedMore         = errors.New("header: need more data")
	ErrMalformedRequest = errors.New("header: malformed request line")
	ErrMalformedHeader  = errors.New("header: malformed header")
	ErrTooManyHeaders   = errors.New("header: too many headers")
	ErrInvalidMethod    = errors.New("header: invalid method")
	ErrInvalidURI       = errors.New("header: invalid URI")
	ErrInvalidVersion   = errors.New("header: invalid HTTP version")
	ErrHeaderTooLarge   = errors.New("header: header section too large")
	ErrInvalidContentLength = errors.New("header: invalid Content-Length")
)

// MaxHeaders is the maximum number of headers a request can contain.
const MaxHeaders = 128

// MaxHeaderSize is the maximum size of the header section in bytes (64KB).
const MaxHeaderSize = 65536

// Header represents a single HTTP header as slices into the original buffer.
type Header struct {
	Key   []byte
	Value []byte
}

// ParsedRequest holds the parsed components of an HTTP request.
// All fields are slices into the original buffer — no copies are made.
type ParsedRequest struct {
	// Request line
	Method  []byte
	URI     []byte
	Version []byte

	// Parsed version numbers
	Major byte
	Minor byte

	// Headers — fixed array to avoid allocation
	Headers    [MaxHeaders]Header
	NumHeaders int

	// Precomputed values from headers
	ContentLength int64
	Chunked       bool
	KeepAlive     bool
	ConnClose     bool

	// Total bytes consumed from the buffer (header section including final \r\n)
	HeaderBytes int
}

// Reset clears all fields for reuse.
func (r *ParsedRequest) Reset() {
	r.Method = nil
	r.URI = nil
	r.Version = nil
	r.Major = 0
	r.Minor = 0
	r.NumHeaders = 0
	r.ContentLength = -1
	r.Chunked = false
	r.KeepAlive = false
	r.ConnClose = false
	r.HeaderBytes = 0
}

// HeaderValue returns the value of the first header matching key (case-insensitive).
// Returns nil if not found.
func (r *ParsedRequest) HeaderValue(key []byte) []byte {
	for i := 0; i < r.NumHeaders; i++ {
		if util.EqualFold(r.Headers[i].Key, key) {
			return r.Headers[i].Value
		}
	}
	return nil
}

// Pre-allocated well-known header names for fast comparison.
var (
	headerContentLength    = []byte("Content-Length")
	headerTransferEncoding = []byte("Transfer-Encoding")
	headerConnection       = []byte("Connection")
	valueChunked           = []byte("chunked")
	valueClose             = []byte("close")
	valueKeepAlive         = []byte("keep-alive")
)

// Parse parses an HTTP/1.1 request from buf.
// Returns the number of bytes consumed (the full header section including body delimiter)
// or an error. On ErrNeedMore, the caller should read more data and retry.
//
// The parsed data in r contains slices pointing directly into buf.
// buf must not be modified while r is in use.
func Parse(buf []byte, r *ParsedRequest) (int, error) {
	r.Reset()
	r.ContentLength = -1

	if len(buf) == 0 {
		return 0, ErrNeedMore
	}

	// Limit total header size.
	searchBuf := buf
	if len(searchBuf) > MaxHeaderSize {
		searchBuf = searchBuf[:MaxHeaderSize]
	}

	// Find the end of the header section (\r\n\r\n).
	headerEnd := findHeaderEnd(searchBuf)
	if headerEnd < 0 {
		if len(buf) >= MaxHeaderSize {
			return 0, ErrHeaderTooLarge
		}
		return 0, ErrNeedMore
	}

	// Parse the request line.
	pos, err := parseRequestLine(buf, r)
	if err != nil {
		return 0, err
	}

	// Parse headers.
	pos, err = parseHeaders(buf, pos, headerEnd, r)
	if err != nil {
		return 0, err
	}

	r.HeaderBytes = headerEnd

	// Determine keep-alive default based on HTTP version.
	if r.Major == 1 && r.Minor == 1 {
		r.KeepAlive = !r.ConnClose
	} else {
		r.KeepAlive = false
	}

	return headerEnd, nil
}

// findHeaderEnd returns the position just after \r\n\r\n, or -1 if not found.
func findHeaderEnd(buf []byte) int {
	n := len(buf)
	for i := 0; i+3 < n; i++ {
		if buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n' {
			return i + 4
		}
	}
	return -1
}

// parseRequestLine parses "METHOD URI HTTP/x.y\r\n" and returns the position after \r\n.
func parseRequestLine(buf []byte, r *ParsedRequest) (int, error) {
	// Skip leading \r\n (tolerate as per RFC 9112 §2.2).
	pos := 0
	for pos < len(buf) && (buf[pos] == '\r' || buf[pos] == '\n') {
		pos++
	}

	// Find method (first space).
	start := pos
	for pos < len(buf) && buf[pos] != ' ' {
		if buf[pos] < 'A' || buf[pos] > 'Z' {
			return 0, ErrInvalidMethod
		}
		pos++
	}
	if pos >= len(buf) || pos == start {
		return 0, ErrMalformedRequest
	}
	r.Method = buf[start:pos]

	// Skip space.
	pos++
	if pos >= len(buf) {
		return 0, ErrMalformedRequest
	}

	// Find URI (next space).
	start = pos
	for pos < len(buf) && buf[pos] != ' ' {
		pos++
	}
	if pos >= len(buf) || pos == start {
		return 0, ErrMalformedRequest
	}
	r.URI = buf[start:pos]

	// Skip space.
	pos++
	if pos >= len(buf) {
		return 0, ErrMalformedRequest
	}

	// Parse HTTP version "HTTP/x.y".
	start = pos
	for pos < len(buf) && buf[pos] != '\r' {
		pos++
	}
	if pos+1 >= len(buf) || buf[pos+1] != '\n' {
		return 0, ErrMalformedRequest
	}
	r.Version = buf[start:pos]

	// Validate version format "HTTP/X.Y".
	ver := r.Version
	if len(ver) != 8 || ver[0] != 'H' || ver[1] != 'T' || ver[2] != 'T' || ver[3] != 'P' || ver[4] != '/' || ver[6] != '.' {
		return 0, ErrInvalidVersion
	}
	if ver[5] < '0' || ver[5] > '9' || ver[7] < '0' || ver[7] > '9' {
		return 0, ErrInvalidVersion
	}
	r.Major = ver[5] - '0'
	r.Minor = ver[7] - '0'

	// Skip \r\n.
	pos += 2

	return pos, nil
}

// parseHeaders parses "Key: Value\r\n" pairs until headerEnd.
func parseHeaders(buf []byte, pos int, headerEnd int, r *ParsedRequest) (int, error) {
	limit := headerEnd - 2 // Exclude final \r\n.
	for pos < limit {
		if r.NumHeaders >= MaxHeaders {
			return 0, ErrTooManyHeaders
		}

		// Find header name (colon).
		start := pos
		for pos < limit && buf[pos] != ':' {
			pos++
		}
		if pos >= limit {
			return 0, ErrMalformedHeader
		}
		keyEnd := pos

		// Trim trailing whitespace from key (shouldn't exist per RFC, but be lenient).
		for keyEnd > start && buf[keyEnd-1] == ' ' {
			keyEnd--
		}

		if keyEnd == start {
			return 0, ErrMalformedHeader
		}

		key := buf[start:keyEnd]

		// Skip colon and optional whitespace.
		pos++ // skip ':'
		for pos < limit && buf[pos] == ' ' {
			pos++
		}

		// Find value (until \r\n).
		start = pos
		for pos < limit && buf[pos] != '\r' {
			pos++
		}

		// Validate \r\n.
		if pos+1 >= headerEnd || buf[pos+1] != '\n' {
			return 0, ErrMalformedHeader
		}

		valueEnd := pos
		// Trim trailing whitespace from value.
		for valueEnd > start && buf[valueEnd-1] == ' ' {
			valueEnd--
		}

		value := buf[start:valueEnd]

		// Store header.
		r.Headers[r.NumHeaders] = Header{Key: key, Value: value}
		r.NumHeaders++

		// Interpret well-known headers.
		interpretHeader(key, value, r)

		// Skip \r\n.
		pos += 2
	}

	return pos, nil
}

// interpretHeader checks if the header is a well-known one and sets computed fields.
func interpretHeader(key, value []byte, r *ParsedRequest) {
	if len(key) == 0 {
		return
	}

	// Fast switch on first byte to avoid full comparison.
	switch key[0] | 0x20 { // lowercase first byte
	case 'c':
		if util.EqualFold(key, headerContentLength) {
			n, err := util.ParseUint(value)
			if err == nil {
				r.ContentLength = int64(n)
			}
		} else if util.EqualFold(key, headerConnection) {
			if util.EqualFold(value, valueClose) {
				r.ConnClose = true
			} else if util.EqualFold(value, valueKeepAlive) {
				r.KeepAlive = true
			}
		}
	case 't':
		if util.EqualFold(key, headerTransferEncoding) {
			if util.EqualFold(value, valueChunked) {
				r.Chunked = true
			}
		}
	}
}
