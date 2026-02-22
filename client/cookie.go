package client

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CookieJar is a thread-safe cookie jar with domain and path matching.
type CookieJar struct {
	mu      sync.RWMutex
	entries map[string][]jarEntry // key = domain
}

type jarEntry struct {
	name     string
	value    string
	domain   string
	path     string
	expires  time.Time
	secure   bool
	httpOnly bool
}

// NewCookieJar creates a new empty CookieJar.
func NewCookieJar() *CookieJar {
	return &CookieJar{
		entries: make(map[string][]jarEntry),
	}
}

// SetCookies stores cookies for the given URL.
func (j *CookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()

	for _, c := range cookies {
		domain := c.Domain
		if domain == "" {
			domain = u.Hostname()
		}
		domain = strings.TrimPrefix(strings.ToLower(domain), ".")

		path := c.Path
		if path == "" {
			path = defaultCookiePath(u.Path)
		}

		var expires time.Time
		if c.MaxAge > 0 {
			expires = time.Now().Add(time.Duration(c.MaxAge) * time.Second)
		} else if c.MaxAge < 0 {
			expires = time.Unix(0, 0) // delete
		} else if !c.Expires.IsZero() {
			expires = c.Expires
		}

		entry := jarEntry{
			name:     c.Name,
			value:    c.Value,
			domain:   domain,
			path:     path,
			expires:  expires,
			secure:   c.Secure,
			httpOnly: c.HttpOnly,
		}

		// Replace existing cookie with same name+domain+path.
		entries := j.entries[domain]
		replaced := false
		for i, e := range entries {
			if e.name == entry.name && e.path == entry.path {
				entries[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			j.entries[domain] = append(entries, entry)
		}
	}
}

// Cookies returns the cookies that should be sent with a request to the given URL.
func (j *CookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	host := strings.ToLower(u.Hostname())
	path := u.Path
	if path == "" {
		path = "/"
	}
	isSecure := u.Scheme == "https"
	now := time.Now()

	var cookies []*http.Cookie

	for domain, entries := range j.entries {
		if !domainMatch(host, domain) {
			continue
		}
		for _, e := range entries {
			// Check expiry.
			if !e.expires.IsZero() && now.After(e.expires) {
				continue
			}
			// Check path prefix.
			if !pathMatch(path, e.path) {
				continue
			}
			// Check secure flag.
			if e.secure && !isSecure {
				continue
			}
			cookies = append(cookies, &http.Cookie{
				Name:  e.name,
				Value: e.value,
			})
		}
	}

	return cookies
}

// domainMatch returns true if host matches the cookie domain.
// Exact match or subdomain match (.example.com matches foo.example.com).
func domainMatch(host, domain string) bool {
	if host == domain {
		return true
	}
	// Subdomain match: host must end with "."+domain.
	return strings.HasSuffix(host, "."+domain)
}

// pathMatch returns true if the request path matches the cookie path.
func pathMatch(requestPath, cookiePath string) bool {
	if requestPath == cookiePath {
		return true
	}
	if strings.HasPrefix(requestPath, cookiePath) {
		if strings.HasSuffix(cookiePath, "/") {
			return true
		}
		if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true
		}
	}
	return false
}

// defaultCookiePath returns the default cookie path from the request URI.
func defaultCookiePath(p string) string {
	if p == "" || p[0] != '/' {
		return "/"
	}
	i := strings.LastIndex(p, "/")
	if i == 0 {
		return "/"
	}
	return p[:i]
}
