package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLSDialer establishes TLS connections with configurable fingerprints.
// It dials TCP, wraps the connection with uTLS (or crypto/tls for GoDefault),
// and performs the TLS handshake.
type TLSDialer struct {
	fingerprint  TLSFingerprint
	insecureSkip bool
	alpn         []string
	sessionCache utls.ClientSessionCache
	customCAs    *x509.CertPool
	timeout      time.Duration
}

// NewTLSDialer creates a TLSDialer for the given fingerprint.
// Default ALPN is ["h2", "http/1.1"].
func NewTLSDialer(fp TLSFingerprint) *TLSDialer {
	return &TLSDialer{
		fingerprint: fp,
		alpn:        []string{"h2", "http/1.1"},
	}
}

// SetInsecureSkipVerify disables certificate verification. Use only for testing.
func (d *TLSDialer) SetInsecureSkipVerify(v bool) *TLSDialer {
	d.insecureSkip = v
	return d
}

// SetALPN sets the Application-Layer Protocol Negotiation protocols.
func (d *TLSDialer) SetALPN(protos []string) *TLSDialer {
	d.alpn = protos
	return d
}

// SetTimeout sets the dial + handshake timeout.
func (d *TLSDialer) SetTimeout(t time.Duration) *TLSDialer {
	d.timeout = t
	return d
}

// SetSessionCache sets the TLS session cache for session resumption.
func (d *TLSDialer) SetSessionCache(c utls.ClientSessionCache) *TLSDialer {
	d.sessionCache = c
	return d
}

// SetCustomCAs sets a custom root CA pool for certificate verification.
func (d *TLSDialer) SetCustomCAs(pool *x509.CertPool) *TLSDialer {
	d.customCAs = pool
	return d
}

// Fingerprint returns the configured fingerprint.
func (d *TLSDialer) Fingerprint() TLSFingerprint {
	return d.fingerprint
}

// Dial connects to the address on the named network with the configured TLS fingerprint.
// The addr must include a port (e.g. "example.com:443").
func (d *TLSDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext connects with the given context.
func (d *TLSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Dial TCP.
	var dialer net.Dialer
	if d.timeout > 0 {
		dialer.Timeout = d.timeout
	}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Perform TLS handshake.
	tlsConn, err := d.handshake(ctx, tcpConn, host)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// handshake performs the TLS handshake with the configured fingerprint.
func (d *TLSDialer) handshake(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error) {
	if d.fingerprint.IsGoDefault() {
		return d.handshakeStandard(ctx, conn, serverName)
	}
	return d.handshakeUTLS(ctx, conn, serverName)
}

// handshakeStandard uses the standard Go crypto/tls stack.
func (d *TLSDialer) handshakeStandard(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		NextProtos:         d.alpn,
		InsecureSkipVerify: d.insecureSkip,
		RootCAs:            d.customCAs,
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// handshakeUTLS uses uTLS to produce a browser-matching ClientHello.
func (d *TLSDialer) handshakeUTLS(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName:         serverName,
		NextProtos:         d.alpn,
		InsecureSkipVerify: d.insecureSkip,
		RootCAs:            d.customCAs,
		ClientSessionCache: d.sessionCache,
	}

	var helloID utls.ClientHelloID
	if d.fingerprint.IsCustom() {
		helloID = utls.HelloCustom
	} else if d.fingerprint.UTLSClientHelloID != nil {
		helloID = *d.fingerprint.UTLSClientHelloID
	} else {
		return nil, errors.New("blazehttp/tls: fingerprint has neither UTLSClientHelloID nor CustomSpec")
	}

	uconn := utls.UClient(conn, cfg, helloID)

	// Apply custom spec if provided.
	if d.fingerprint.IsCustom() {
		if err := uconn.ApplyPreset(d.fingerprint.CustomSpec); err != nil {
			return nil, err
		}
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}

// DialOverConn performs a TLS handshake over an already-established connection
// (e.g. a CONNECT proxy tunnel) using the configured fingerprint.
func (d *TLSDialer) DialOverConn(conn net.Conn, serverName string) (net.Conn, error) {
	return d.handshake(context.Background(), conn, serverName)
}

// NegotiatedProtocol returns the ALPN protocol negotiated on the connection.
// Returns empty string if the connection is not a TLS connection or ALPN was not negotiated.
func NegotiatedProtocol(conn net.Conn) string {
	switch c := conn.(type) {
	case *utls.UConn:
		return c.ConnectionState().NegotiatedProtocol
	case *tls.Conn:
		return c.ConnectionState().NegotiatedProtocol
	default:
		return ""
	}
}

// ConnectionState returns the TLS connection state.
// Returns nil if the connection is not a TLS connection.
func ConnectionState(conn net.Conn) *tls.ConnectionState {
	switch c := conn.(type) {
	case *utls.UConn:
		state := c.ConnectionState()
		stdState := tls.ConnectionState{
			Version:                     state.Version,
			HandshakeComplete:           state.HandshakeComplete,
			CipherSuite:                 state.CipherSuite,
			NegotiatedProtocol:          state.NegotiatedProtocol,
			ServerName:                  state.ServerName,
			PeerCertificates:            state.PeerCertificates,
			VerifiedChains:              state.VerifiedChains,
			NegotiatedProtocolIsMutual:  true,
		}
		return &stdState
	case *tls.Conn:
		state := c.ConnectionState()
		return &state
	default:
		return nil
	}
}
