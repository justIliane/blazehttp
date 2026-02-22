package client

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// proxyDialer dials through an HTTP CONNECT or SOCKS5 proxy.
type proxyDialer struct {
	proxyURL *url.URL
	user     string
	pass     string
	timeout  time.Duration
}

// newProxyDialer creates a proxy dialer from a URL string.
// Supported schemes: http, https, socks5.
func newProxyDialer(proxyURL string, timeout time.Duration) (*proxyDialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("client: invalid proxy URL: %w", err)
	}
	pd := &proxyDialer{
		proxyURL: u,
		timeout:  timeout,
	}
	if u.User != nil {
		pd.user = u.User.Username()
		pd.pass, _ = u.User.Password()
	}
	return pd, nil
}

// dial establishes a connection through the proxy to targetAddr (host:port).
func (pd *proxyDialer) dial(targetAddr string) (net.Conn, error) {
	switch pd.proxyURL.Scheme {
	case "http", "https":
		return pd.dialCONNECT(targetAddr)
	case "socks5":
		return pd.dialSOCKS5(targetAddr)
	default:
		return nil, fmt.Errorf("client: unsupported proxy scheme %q", pd.proxyURL.Scheme)
	}
}

// dialCONNECT establishes an HTTP CONNECT tunnel.
func (pd *proxyDialer) dialCONNECT(targetAddr string) (net.Conn, error) {
	proxyAddr := pd.proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = proxyAddr + ":443"
	}

	dialer := &net.Dialer{Timeout: pd.timeout}
	conn, err := dialer.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("client: proxy dial: %w", err)
	}

	// Send CONNECT request.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if pd.user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(pd.user + ":" + pd.pass))
		connectReq += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("client: proxy CONNECT write: %w", err)
	}

	// Read response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("client: proxy CONNECT read: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("client: proxy CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

// dialSOCKS5 establishes a SOCKS5 connection.
func (pd *proxyDialer) dialSOCKS5(targetAddr string) (net.Conn, error) {
	proxyAddr := pd.proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = proxyAddr + ":1080"
	}

	var auth *proxy.Auth
	if pd.user != "" {
		auth = &proxy.Auth{User: pd.user, Password: pd.pass}
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{Timeout: pd.timeout})
	if err != nil {
		return nil, fmt.Errorf("client: SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("client: SOCKS5 dial: %w", err)
	}

	return conn, nil
}

// ErrProxyConnect is returned when a proxy CONNECT or SOCKS5 connection fails.
var ErrProxyConnect = errors.New("client: proxy connection failed")
