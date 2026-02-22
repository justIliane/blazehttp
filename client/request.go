package client

import (
	"fmt"
	"net/url"
	"strings"
)

// Request is a high-level HTTP request builder.
type Request struct {
	method  string
	rawURL  string
	url     *url.URL
	headers []Header // ordered
	body    []byte
	cookies []cookie // name-value pairs
}

type cookie struct {
	name  string
	value string
}

// NewRequest creates a new Request with the given method and URL.
func NewRequest(method, rawURL string) *Request {
	return &Request{
		method: method,
		rawURL: rawURL,
	}
}

// SetHeader sets a header (upsert by lowercased key).
func (r *Request) SetHeader(key, value string) *Request {
	key = strings.ToLower(key)
	for i, h := range r.headers {
		if strings.ToLower(h.Name) == key {
			r.headers[i].Value = value
			return r
		}
	}
	r.headers = append(r.headers, Header{Name: key, Value: value})
	return r
}

// SetHeaders sets multiple headers at once (upsert each).
func (r *Request) SetHeaders(headers map[string]string) *Request {
	for k, v := range headers {
		r.SetHeader(k, v)
	}
	return r
}

// SetHeaderOrder reorders the headers slice to match the given order.
// Headers not in the order list are appended after.
func (r *Request) SetHeaderOrder(order []string) *Request {
	ordered := make([]Header, 0, len(r.headers))
	used := make(map[string]bool, len(order))
	for _, name := range order {
		name = strings.ToLower(name)
		for _, h := range r.headers {
			if strings.ToLower(h.Name) == name && !used[name] {
				ordered = append(ordered, h)
				used[name] = true
				break
			}
		}
	}
	for _, h := range r.headers {
		if !used[strings.ToLower(h.Name)] {
			ordered = append(ordered, h)
		}
	}
	r.headers = ordered
	return r
}

// SetBody sets the request body.
func (r *Request) SetBody(body []byte) *Request {
	r.body = body
	return r
}

// SetCookie adds a cookie to the request.
func (r *Request) SetCookie(name, value string) *Request {
	r.cookies = append(r.cookies, cookie{name: name, value: value})
	return r
}

// toH2Request converts the high-level Request to a low-level h2Request
// and returns the addr (host:port) for the connection pool.
func (r *Request) toH2Request() (*h2Request, string, error) {
	u, err := url.Parse(r.rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("client: invalid URL: %w", err)
	}
	r.url = u

	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := host + ":" + port

	authority := u.Host
	if u.Port() == "" {
		authority = host
	}

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	// Build headers, merging cookies.
	headers := make([]Header, len(r.headers))
	copy(headers, r.headers)

	if len(r.cookies) > 0 {
		var sb strings.Builder
		for i, c := range r.cookies {
			if i > 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(c.name)
			sb.WriteByte('=')
			sb.WriteString(c.value)
		}
		// Check if there is already a cookie header and append.
		found := false
		for i, h := range headers {
			if h.Name == "cookie" {
				headers[i].Value = h.Value + "; " + sb.String()
				found = true
				break
			}
		}
		if !found {
			headers = append(headers, Header{Name: "cookie", Value: sb.String()})
		}
	}

	return &h2Request{
		Method:    r.method,
		Authority: authority,
		Scheme:    scheme,
		Path:      path,
		Headers:   headers,
		Body:      r.body,
	}, addr, nil
}
