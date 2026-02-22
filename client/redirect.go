package client

import (
	"errors"
	"net/url"
)

// ErrTooManyRedirects is returned when the redirect limit is exceeded.
var ErrTooManyRedirects = errors.New("client: too many redirects")

// shouldRedirect returns true if the status code is a redirect.
func shouldRedirect(statusCode int) bool {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// followRedirect creates a new Request for following a redirect.
// 301/302/303: method becomes GET, body dropped.
// 307/308: method + body preserved.
func followRedirect(original *Request, resp *Response, maxRedirects int, count int) (*Request, error) {
	if count >= maxRedirects {
		return nil, ErrTooManyRedirects
	}

	location := resp.Header("location")
	if location == "" {
		return nil, errors.New("client: redirect with no Location header")
	}

	// Resolve relative URL against original.
	base, err := url.Parse(original.rawURL)
	if err != nil {
		return nil, err
	}
	ref, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	resolved := base.ResolveReference(ref)

	method := original.method
	var body []byte

	switch resp.StatusCode {
	case 301, 302, 303:
		// Method becomes GET, body dropped.
		method = "GET"
		body = nil
	case 307, 308:
		// Preserve method + body.
		method = original.method
		body = original.body
	}

	newReq := &Request{
		method: method,
		rawURL: resolved.String(),
	}

	// Copy headers from original.
	if len(original.headers) > 0 {
		newReq.headers = make([]Header, len(original.headers))
		copy(newReq.headers, original.headers)
	}

	// For 307/308 with body, keep content-type.
	// For 301/302/303, remove content-type and content-length.
	if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 {
		filtered := newReq.headers[:0]
		for _, h := range newReq.headers {
			if h.Name != "content-type" && h.Name != "content-length" {
				filtered = append(filtered, h)
			}
		}
		newReq.headers = filtered
	}

	if body != nil {
		newReq.body = body
	}

	return newReq, nil
}
