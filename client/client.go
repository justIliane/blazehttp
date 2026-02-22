package client

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/blazehttp/blazehttp/client/h2fingerprint"
	blazetls "github.com/blazehttp/blazehttp/client/tls"
)

// Client is the high-level HTTP/2 client with browser fingerprinting,
// cookie jar, redirect following, retry with backoff, and proxy support.
type Client struct {
	UserAgent       string
	FollowRedirects bool
	MaxRedirects    int
	CookieJar       *CookieJar
	RetryConfig     *RetryConfig
	RequestTimeout  time.Duration

	tlsFingerprint blazetls.TLSFingerprint
	h2Profile      *h2fingerprint.H2Profile
	pool           *ConnPool
	dialer         *blazetls.TLSDialer
	pd             *proxyDialer

	initOnce sync.Once
	initErr  error
}

// NewChromeClient creates a client mimicking Chrome's TLS and HTTP/2 fingerprint.
func NewChromeClient() *Client {
	return &Client{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		FollowRedirects: true,
		MaxRedirects:    10,
		RequestTimeout:  30 * time.Second,
		tlsFingerprint:  blazetls.ChromeLatest,
		h2Profile:       h2fingerprint.ChromeH2.Clone(),
	}
}

// NewFirefoxClient creates a client mimicking Firefox's TLS and HTTP/2 fingerprint.
func NewFirefoxClient() *Client {
	return &Client{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		FollowRedirects: true,
		MaxRedirects:    10,
		RequestTimeout:  30 * time.Second,
		tlsFingerprint:  blazetls.FirefoxLatest,
		h2Profile:       h2fingerprint.FirefoxH2.Clone(),
	}
}

// NewSafariClient creates a client mimicking Safari's TLS fingerprint
// (uses Chrome H2 profile since Safari doesn't have a distinct one).
func NewSafariClient() *Client {
	return &Client{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		FollowRedirects: true,
		MaxRedirects:    10,
		RequestTimeout:  30 * time.Second,
		tlsFingerprint:  blazetls.Safari17,
		h2Profile:       h2fingerprint.ChromeH2.Clone(),
	}
}

// NewRandomClient creates a client with a randomized TLS fingerprint.
func NewRandomClient() *Client {
	return &Client{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		FollowRedirects: true,
		MaxRedirects:    10,
		RequestTimeout:  30 * time.Second,
		tlsFingerprint:  blazetls.Randomized,
		h2Profile:       h2fingerprint.ChromeH2.Clone(),
	}
}

// init lazily initializes the TLS dialer and connection pool.
func (c *Client) init() error {
	c.initOnce.Do(func() {
		if c.pool != nil {
			return // already initialized (e.g. by tests)
		}

		if c.dialer == nil {
			c.dialer = blazetls.NewTLSDialer(c.tlsFingerprint).
				SetInsecureSkipVerify(false).
				SetTimeout(c.RequestTimeout)
		}

		var poolOpts []PoolOption
		if c.pd != nil {
			poolOpts = append(poolOpts, withDialFunc(func(addr string, dialer *blazetls.TLSDialer, profile *h2fingerprint.H2Profile) (*ClientConn, error) {
				return c.dialViaProxy(addr, profile)
			}))
		}

		c.pool = NewConnPool(c.dialer, c.h2Profile, poolOpts...)
	})
	return c.initErr
}

// Do sends a Request and returns a Response.
// It handles cookie injection, redirect following, and retry.
func (c *Client) Do(req *Request) (*Response, error) {
	if err := c.init(); err != nil {
		return nil, err
	}

	// Inject user-agent if not set.
	if c.UserAgent != "" {
		hasUA := false
		for _, h := range req.headers {
			if h.Name == "user-agent" {
				hasUA = true
				break
			}
		}
		if !hasUA {
			req.SetHeader("user-agent", c.UserAgent)
		}
	}

	// Retry loop.
	var lastResp *Response
	var lastErr error
	maxRetries := 0
	if c.RetryConfig != nil {
		maxRetries = c.RetryConfig.MaxRetries
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 && c.RetryConfig != nil {
			time.Sleep(c.RetryConfig.delay(attempt - 1))
		}

		resp, err := c.doOnce(req)
		if err == nil && (c.RetryConfig == nil || !c.RetryConfig.shouldRetry(resp, nil)) {
			return resp, nil
		}
		if err != nil && (c.RetryConfig == nil || !c.RetryConfig.shouldRetry(nil, err)) {
			return nil, err
		}
		lastResp = resp
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return lastResp, nil
}

// doOnce performs a single request with redirect following.
func (c *Client) doOnce(req *Request) (*Response, error) {
	redirectCount := 0

	for {
		// Inject cookies from jar.
		if c.CookieJar != nil {
			u, err := url.Parse(req.rawURL)
			if err == nil {
				cookies := c.CookieJar.Cookies(u)
				for _, ck := range cookies {
					req.SetCookie(ck.Name, ck.Value)
				}
			}
		}

		h2req, addr, err := req.toH2Request()
		if err != nil {
			return nil, err
		}

		h2resp, err := c.pool.roundTrip(addr, h2req)
		if err != nil {
			return nil, err
		}

		resp := fromH2Response(h2resp, req.rawURL)

		// Store cookies from response.
		if c.CookieJar != nil {
			u, err := url.Parse(req.rawURL)
			if err == nil {
				cookies := resp.Cookies()
				if len(cookies) > 0 {
					c.CookieJar.SetCookies(u, cookies)
				}
			}
		}

		// Follow redirects.
		if c.FollowRedirects && shouldRedirect(resp.StatusCode) {
			newReq, err := followRedirect(req, resp, c.MaxRedirects, redirectCount)
			if err != nil {
				return nil, err
			}
			req = newReq
			redirectCount++
			continue
		}

		return resp, nil
	}
}

// Get sends a GET request to the given URL.
func (c *Client) Get(rawURL string) (*Response, error) {
	return c.Do(NewRequest("GET", rawURL))
}

// Post sends a POST request with the given content type and body.
func (c *Client) Post(rawURL, contentType string, body []byte) (*Response, error) {
	req := NewRequest("POST", rawURL).
		SetHeader("content-type", contentType).
		SetBody(body)
	return c.Do(req)
}

// Head sends a HEAD request to the given URL.
func (c *Client) Head(rawURL string) (*Response, error) {
	return c.Do(NewRequest("HEAD", rawURL))
}

// DoBatch sends multiple requests concurrently and returns responses in order.
// Returns on the first error encountered.
func (c *Client) DoBatch(reqs []*Request) ([]*Response, error) {
	if err := c.init(); err != nil {
		return nil, err
	}

	type result struct {
		index int
		resp  *Response
		err   error
	}

	results := make(chan result, len(reqs))
	for i, req := range reqs {
		go func(idx int, r *Request) {
			resp, err := c.Do(r)
			results <- result{index: idx, resp: resp, err: err}
		}(i, req)
	}

	responses := make([]*Response, len(reqs))
	for range reqs {
		r := <-results
		if r.err != nil {
			return nil, fmt.Errorf("client: batch request %d: %w", r.index, r.err)
		}
		responses[r.index] = r.resp
	}

	return responses, nil
}

// SetProxy configures an HTTP CONNECT proxy.
func (c *Client) SetProxy(proxyURL string) error {
	pd, err := newProxyDialer(proxyURL, c.RequestTimeout)
	if err != nil {
		return err
	}
	c.pd = pd
	return nil
}

// SetProxyWithAuth configures an HTTP CONNECT proxy with credentials.
func (c *Client) SetProxyWithAuth(proxyURL, user, pass string) error {
	pd, err := newProxyDialer(proxyURL, c.RequestTimeout)
	if err != nil {
		return err
	}
	pd.user = user
	pd.pass = pass
	c.pd = pd
	return nil
}

// SetSOCKS5Proxy configures a SOCKS5 proxy.
func (c *Client) SetSOCKS5Proxy(addr, user, pass string) error {
	u := "socks5://" + addr
	pd, err := newProxyDialer(u, c.RequestTimeout)
	if err != nil {
		return err
	}
	pd.user = user
	pd.pass = pass
	c.pd = pd
	return nil
}

// SetInsecureSkipVerify disables TLS certificate verification. Testing only.
func (c *Client) SetInsecureSkipVerify(v bool) *Client {
	// Reset so init() re-creates the dialer.
	c.initOnce = sync.Once{}
	c.dialer = blazetls.NewTLSDialer(c.tlsFingerprint).
		SetInsecureSkipVerify(v).
		SetTimeout(c.RequestTimeout)
	return c
}

// Close shuts down the client and its connection pool.
func (c *Client) Close() error {
	if c.pool != nil {
		return c.pool.Close()
	}
	return nil
}

// dialViaProxy establishes an HTTP/2 connection through the proxy.
func (c *Client) dialViaProxy(addr string, profile *h2fingerprint.H2Profile) (*ClientConn, error) {
	// Establish tunnel.
	tunnelConn, err := c.pd.dial(addr)
	if err != nil {
		return nil, err
	}

	// Perform TLS handshake over tunnel.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port in addr, use addr as host.
		host = addr
	}
	tlsConn, err := c.dialer.DialOverConn(tunnelConn, host)
	if err != nil {
		tunnelConn.Close()
		return nil, err
	}

	// Verify h2 negotiation.
	if blazetls.NegotiatedProtocol(tlsConn) != "h2" {
		tlsConn.Close()
		return nil, ErrNotH2
	}

	return newClientConn(tlsConn, profile)
}

// withDialFunc sets a custom dial function for the pool (used for proxy).
func withDialFunc(fn func(addr string, dialer *blazetls.TLSDialer, profile *h2fingerprint.H2Profile) (*ClientConn, error)) PoolOption {
	return func(p *ConnPool) {
		p.dialFunc = fn
	}
}

// Ensure Response implements the standard cookie parsing.
var _ interface{ Cookies() []*http.Cookie } = (*Response)(nil)
