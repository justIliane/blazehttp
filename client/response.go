package client

import (
	"net/http"
	"strings"
)

// Response is a high-level HTTP response.
type Response struct {
	StatusCode int
	Headers    []Header
	Body       []byte
	URL        string
}

// Header returns the first value for the given header name (case-insensitive).
// Returns empty string if not found.
func (r *Response) Header(key string) string {
	key = strings.ToLower(key)
	for _, h := range r.Headers {
		if strings.ToLower(h.Name) == key {
			return h.Value
		}
	}
	return ""
}

// Cookies parses Set-Cookie headers from the response using net/http.
func (r *Response) Cookies() []*http.Cookie {
	// Build a minimal http.Response to leverage net/http's cookie parsing.
	hdr := make(http.Header)
	for _, h := range r.Headers {
		hdr.Add(h.Name, h.Value)
	}
	resp := &http.Response{Header: hdr}
	return resp.Cookies()
}

// Release nils out the body to allow GC.
func (r *Response) Release() {
	r.Body = nil
	r.Headers = nil
}

// fromH2Response converts a low-level h2Response to a high-level Response.
// Returns nil if h2 is nil (connection closed before response arrived).
func fromH2Response(h2 *h2Response, reqURL string) *Response {
	if h2 == nil {
		return nil
	}
	return &Response{
		StatusCode: h2.StatusCode,
		Headers:    h2.Headers,
		Body:       h2.Body,
		URL:        reqURL,
	}
}
