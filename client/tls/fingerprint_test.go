package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// testCert generates a self-signed certificate for testing.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}

// captureServer starts a TLS server that captures the raw ClientHello
// from the first connection. Returns the listener address, a channel
// that receives the raw ClientHello bytes, and a cleanup function.
func captureServer(t *testing.T) (string, <-chan []byte, func()) {
	t.Helper()
	cert := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan []byte, 8)
	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				return
			}
			// Read the raw ClientHello
			buf := make([]byte, 16384)
			n, _ := conn.Read(buf)
			if n > 0 {
				raw := make([]byte, n)
				copy(raw, buf[:n])
				ch <- raw
			}
			// Now do a proper TLS handshake to complete the connection
			// We need to "unread" the data — wrap with a peekConn
			pr := &prefixReader{prefix: buf[:n], conn: conn}
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			}
			srvConn := tls.Server(pr, tlsCfg)
			srvConn.Handshake()
			srvConn.Close()
		}
	}()

	cleanup := func() {
		close(done)
		ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), ch, cleanup
}

// prefixReader replays prefix bytes then reads from conn.
type prefixReader struct {
	prefix []byte
	pos    int
	conn   net.Conn
}

func (r *prefixReader) Read(p []byte) (int, error) {
	if r.pos < len(r.prefix) {
		n := copy(p, r.prefix[r.pos:])
		r.pos += n
		return n, nil
	}
	return r.conn.Read(p)
}

func (r *prefixReader) Write(p []byte) (int, error)       { return r.conn.Write(p) }
func (r *prefixReader) Close() error                       { return r.conn.Close() }
func (r *prefixReader) LocalAddr() net.Addr                { return r.conn.LocalAddr() }
func (r *prefixReader) RemoteAddr() net.Addr               { return r.conn.RemoteAddr() }
func (r *prefixReader) SetDeadline(t time.Time) error      { return r.conn.SetDeadline(t) }
func (r *prefixReader) SetReadDeadline(t time.Time) error  { return r.conn.SetReadDeadline(t) }
func (r *prefixReader) SetWriteDeadline(t time.Time) error { return r.conn.SetWriteDeadline(t) }

// ======================== FINGERPRINT TESTS ========================

func TestTLSFingerprint_ChromeClientHello(t *testing.T) {
	addr, rawCh, cleanup := captureServer(t)
	defer cleanup()

	d := NewTLSDialer(ChromeLatest).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	select {
	case raw := <-rawCh:
		ch, err := ParseClientHello(raw)
		if err != nil {
			t.Fatalf("ParseClientHello: %v", err)
		}
		// Chrome must have cipher suites (non-GREASE)
		nonGREASE := 0
		for _, cs := range ch.CipherSuites {
			if !IsGREASE(cs) {
				nonGREASE++
			}
		}
		if nonGREASE < 5 {
			t.Fatalf("Chrome should have at least 5 non-GREASE cipher suites, got %d", nonGREASE)
		}
		// Chrome must have extensions
		if len(ch.Extensions) < 5 {
			t.Fatalf("Chrome should have at least 5 extensions, got %d", len(ch.Extensions))
		}
		// Chrome must have supported_groups
		if len(ch.SupportedGroups) == 0 {
			t.Fatal("Chrome should have supported_groups")
		}
		// Chrome must have ALPN with h2
		foundH2 := false
		for _, p := range ch.ALPNProtocols {
			if p == "h2" {
				foundH2 = true
			}
		}
		if !foundH2 {
			t.Fatal("Chrome ALPN should include h2")
		}
		t.Logf("Chrome ClientHello: %d ciphers, %d extensions, ALPN=%v", nonGREASE, len(ch.Extensions), ch.ALPNProtocols)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ClientHello")
	}
}

func TestTLSFingerprint_FirefoxClientHello(t *testing.T) {
	addr, rawCh, cleanup := captureServer(t)
	defer cleanup()

	d := NewTLSDialer(FirefoxLatest).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	select {
	case raw := <-rawCh:
		ch, err := ParseClientHello(raw)
		if err != nil {
			t.Fatalf("ParseClientHello: %v", err)
		}
		nonGREASE := 0
		for _, cs := range ch.CipherSuites {
			if !IsGREASE(cs) {
				nonGREASE++
			}
		}
		if nonGREASE < 3 {
			t.Fatalf("Firefox should have at least 3 non-GREASE cipher suites, got %d", nonGREASE)
		}
		if len(ch.Extensions) < 5 {
			t.Fatalf("Firefox should have at least 5 extensions, got %d", len(ch.Extensions))
		}
		t.Logf("Firefox ClientHello: %d ciphers, %d extensions, ALPN=%v", nonGREASE, len(ch.Extensions), ch.ALPNProtocols)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ClientHello")
	}
}

func TestTLSFingerprint_ALPN(t *testing.T) {
	cert := testCert(t)
	profiles := []struct {
		name string
		fp   TLSFingerprint
	}{
		{"ChromeLatest", ChromeLatest},
		{"FirefoxLatest", FirefoxLatest},
		{"Safari17", Safari17},
		{"GoDefault", GoDefault},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			var serverProto string
			var srvWg sync.WaitGroup
			srvWg.Add(1)
			go func() {
				defer srvWg.Done()
				srvConn, err := ln.Accept()
				if err != nil {
					return
				}
				defer srvConn.Close()
				tlsConn := srvConn.(*tls.Conn)
				tlsConn.Handshake()
				serverProto = tlsConn.ConnectionState().NegotiatedProtocol
			}()

			d := NewTLSDialer(p.fp).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
			conn, err := d.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}

			clientProto := NegotiatedProtocol(conn)
			conn.Close()
			srvWg.Wait()

			if clientProto != "h2" {
				t.Errorf("client negotiated %q, want h2", clientProto)
			}
			if serverProto != "h2" {
				t.Errorf("server negotiated %q, want h2", serverProto)
			}
		})
	}
}

func TestTLSFingerprint_SessionResumption(t *testing.T) {
	cert := testCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			tlsConn.Handshake()
			tlsConn.Close()
		}
	}()

	cache := utls.NewLRUClientSessionCache(10)
	d := NewTLSDialer(ChromeLatest).SetInsecureSkipVerify(true).SetSessionCache(cache).SetTimeout(5 * time.Second)

	// First connection — no session ticket
	conn1, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	conn1.Close()

	// Second connection — should attempt session resumption
	conn2, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("second Dial: %v", err)
	}
	conn2.Close()

	// We can't directly check if session was resumed from the client side
	// with uTLS, but the fact that both connections succeed with session
	// cache enabled proves the mechanism doesn't break.
	t.Log("Session cache connections succeeded")
}

func TestTLSFingerprint_CustomSpec(t *testing.T) {
	addr, rawCh, cleanup := captureServer(t)
	defer cleanup()

	// Create a minimal custom spec with known cipher suites
	customFP := TLSFingerprint{
		Name: "Custom-Test",
		CustomSpec: &utls.ClientHelloSpec{
			TLSVersMin: utls.VersionTLS12,
			TLSVersMax: utls.VersionTLS13,
			CipherSuites: []uint16{
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			CompressionMethods: []byte{0x00},
			Extensions: []utls.TLSExtension{
				&utls.SNIExtension{},
				&utls.SupportedVersionsExtension{Versions: []uint16{
					utls.VersionTLS13, utls.VersionTLS12,
				}},
				&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
					utls.X25519, utls.CurveP256,
				}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
				}},
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
					{Group: utls.X25519},
				}},
			},
		},
	}

	d := NewTLSDialer(customFP).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	select {
	case raw := <-rawCh:
		ch, err := ParseClientHello(raw)
		if err != nil {
			t.Fatalf("ParseClientHello: %v", err)
		}
		// Verify the custom cipher suites are present
		if len(ch.CipherSuites) < 4 {
			t.Fatalf("expected at least 4 cipher suites, got %d", len(ch.CipherSuites))
		}
		// Verify supported groups
		if len(ch.SupportedGroups) < 2 {
			t.Fatalf("expected at least 2 supported groups, got %d", len(ch.SupportedGroups))
		}
		t.Logf("Custom spec: %d ciphers, %d extensions, groups=%v", len(ch.CipherSuites), len(ch.Extensions), ch.SupportedGroups)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ClientHello")
	}
}

func TestTLSFingerprint_GoDefault(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := conn.(*tls.Conn)
		tlsConn.Handshake()
		tlsConn.Close()
	}()

	d := NewTLSDialer(GoDefault).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// GoDefault should produce a *tls.Conn, not *utls.UConn
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatalf("expected *tls.Conn, got %T", conn)
	}

	proto := NegotiatedProtocol(conn)
	if proto != "h2" {
		t.Errorf("negotiated %q, want h2", proto)
	}
}

func TestTLSFingerprint_IsGoDefault(t *testing.T) {
	if !GoDefault.IsGoDefault() {
		t.Error("GoDefault.IsGoDefault() should be true")
	}
	if ChromeLatest.IsGoDefault() {
		t.Error("ChromeLatest.IsGoDefault() should be false")
	}
}

func TestTLSFingerprint_ConnectionState(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	d := NewTLSDialer(ChromeLatest).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	state := ConnectionState(conn)
	if state == nil {
		t.Fatal("ConnectionState returned nil")
	}
	if !state.HandshakeComplete {
		t.Error("HandshakeComplete should be true")
	}
	if state.NegotiatedProtocol != "h2" {
		t.Errorf("NegotiatedProtocol = %q, want h2", state.NegotiatedProtocol)
	}
}

// ======================== JA3 TESTS ========================

func TestJA3_Computation(t *testing.T) {
	// Known ClientHello fields for a simple test
	ch := &ClientHelloFields{
		Version:         0x0303, // TLS 1.2
		CipherSuites:    []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		Extensions:      []uint16{0x0000, 0x0017, 0xff01, 0x000a, 0x000b},
		SupportedGroups: []uint16{0x001d, 0x0017, 0x0018},
		ECPointFormats:  []uint8{0x00},
	}

	ja3 := ComputeJA3(ch)
	expected := "771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23-24,0"
	if ja3 != expected {
		t.Errorf("JA3 = %q, want %q", ja3, expected)
	}

	hash := ComputeJA3Hash(ch)
	if len(hash) != 32 {
		t.Errorf("JA3 hash length = %d, want 32", len(hash))
	}
	t.Logf("JA3: %s", ja3)
	t.Logf("JA3 Hash: %s", hash)
}

func TestJA3_GREASEStripping(t *testing.T) {
	ch := &ClientHelloFields{
		Version: 0x0303,
		CipherSuites: []uint16{
			0x0a0a, // GREASE
			0x1301,
			0x4a4a, // GREASE
			0xc02b,
		},
		Extensions: []uint16{
			0x2a2a, // GREASE
			0x0000,
			0x000a,
		},
		SupportedGroups: []uint16{
			0x6a6a, // GREASE
			0x001d,
		},
	}

	ja3 := ComputeJA3(ch)
	// GREASE values should be stripped
	if containsGREASE(ja3) {
		t.Errorf("JA3 contains GREASE values: %s", ja3)
	}

	expected := "771,4865-49195,0-10,29,"
	if ja3 != expected {
		t.Errorf("JA3 = %q, want %q", ja3, expected)
	}
}

func containsGREASE(s string) bool {
	// Check for common GREASE decimal values
	greaseVals := []string{"2570", "6682", "10794", "14906", "19018", "23130", "27242", "31354", "35466", "39578", "43690", "47802", "51914", "56026", "60138", "64250"}
	for _, g := range greaseVals {
		if len(g) > 0 {
			for i := 0; i+len(g) <= len(s); i++ {
				if s[i:i+len(g)] == g {
					// Check it's bounded by delimiters
					before := i == 0 || s[i-1] == '-' || s[i-1] == ','
					after := i+len(g) == len(s) || s[i+len(g)] == '-' || s[i+len(g)] == ','
					if before && after {
						return true
					}
				}
			}
		}
	}
	return false
}

func TestJA3_FromRawCaptured(t *testing.T) {
	addr, rawCh, cleanup := captureServer(t)
	defer cleanup()

	d := NewTLSDialer(ChromeLatest).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	select {
	case raw := <-rawCh:
		ja3Str, ja3Hash, err := ComputeJA3FromRaw(raw)
		if err != nil {
			t.Fatalf("ComputeJA3FromRaw: %v", err)
		}
		if ja3Str == "" {
			t.Error("JA3 string is empty")
		}
		if len(ja3Hash) != 32 {
			t.Errorf("JA3 hash length = %d, want 32", len(ja3Hash))
		}
		t.Logf("Chrome JA3: %s", ja3Str)
		t.Logf("Chrome JA3 hash: %s", ja3Hash)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

// ======================== JA4 TESTS ========================

func TestJA4_Computation(t *testing.T) {
	ch := &ClientHelloFields{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		Extensions:   []uint16{0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b},
		SupportedGroups: []uint16{0x001d, 0x0017},
		ECPointFormats:  []uint8{0x00},
		SignatureAlgos:  []uint16{0x0403, 0x0804},
		ALPNProtocols:   []string{"h2", "http/1.1"},
		SNI:             "example.com",
		SupportedVers:   []uint16{0x0304, 0x0303},
	}

	ja4 := ComputeJA4(ch)
	parts := splitJA4(ja4)
	if len(parts) != 3 {
		t.Fatalf("JA4 should have 3 parts, got %d: %q", len(parts), ja4)
	}

	// Check JA4_a format
	a := parts[0]
	if len(a) != 10 {
		t.Errorf("JA4_a length = %d, want 10: %q", len(a), a)
	}
	// Protocol should be 't' (TCP)
	if a[0] != 't' {
		t.Errorf("JA4_a protocol = %c, want t", a[0])
	}
	// Version should be '13' (TLS 1.3 from supported_versions)
	if a[1:3] != "13" {
		t.Errorf("JA4_a version = %s, want 13", a[1:3])
	}
	// SNI should be 'd' (domain)
	if a[3] != 'd' {
		t.Errorf("JA4_a sni = %c, want d", a[3])
	}
	// ALPN should be 'h2'
	if a[8:10] != "h2" {
		t.Errorf("JA4_a alpn = %s, want h2", a[8:10])
	}

	// Check JA4_b and JA4_c are 12 hex chars
	if len(parts[1]) != 12 {
		t.Errorf("JA4_b length = %d, want 12: %q", len(parts[1]), parts[1])
	}
	if len(parts[2]) != 12 {
		t.Errorf("JA4_c length = %d, want 12: %q", len(parts[2]), parts[2])
	}

	t.Logf("JA4: %s", ja4)
}

func TestJA4_ChromeStable(t *testing.T) {
	// Chrome randomizes extension order, but JA4 sorts extensions
	// so it should be stable across multiple connections.
	addr, rawCh, cleanup := captureServer(t)
	defer cleanup()

	var ja4s []string
	for i := 0; i < 3; i++ {
		d := NewTLSDialer(ChromeLatest).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
		conn, err := d.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		conn.Close()

		select {
		case raw := <-rawCh:
			ja4, err := ComputeJA4FromRaw(raw)
			if err != nil {
				t.Fatalf("ComputeJA4FromRaw %d: %v", i, err)
			}
			ja4s = append(ja4s, ja4)
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	}

	// All JA4 hashes should be identical
	for i := 1; i < len(ja4s); i++ {
		if ja4s[i] != ja4s[0] {
			t.Errorf("JA4[%d] = %q differs from JA4[0] = %q", i, ja4s[i], ja4s[0])
		}
	}
	t.Logf("Chrome JA4 (stable across %d connections): %s", len(ja4s), ja4s[0])
}

func TestJA4_NoSNI(t *testing.T) {
	ch := &ClientHelloFields{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x000a},
		SupportedVers: []uint16{0x0304},
	}

	ja4 := ComputeJA4(ch)
	parts := splitJA4(ja4)
	a := parts[0]
	if a[3] != 'i' {
		t.Errorf("JA4_a sni = %c, want i (no SNI)", a[3])
	}
}

func TestJA4_VersionFallback(t *testing.T) {
	// When no supported_versions extension, use ClientHello version
	ch := &ClientHelloFields{
		Version:      0x0303, // TLS 1.2
		CipherSuites: []uint16{0xc02b},
		Extensions:   []uint16{0x000a},
	}

	ja4 := ComputeJA4(ch)
	parts := splitJA4(ja4)
	if parts[0][1:3] != "12" {
		t.Errorf("JA4_a version = %s, want 12 (TLS 1.2 fallback)", parts[0][1:3])
	}
}

// ======================== PARSE TESTS ========================

func TestParseClientHello_InvalidRecord(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x16, 0x03}},
		{"not handshake", []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}},
		{"not clienthello", []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseClientHello(tt.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	for _, v := range greaseValues {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = false, want true", v)
		}
	}
	nonGREASE := []uint16{0x0000, 0x1301, 0xc02b, 0xff01, 0x0a0b}
	for _, v := range nonGREASE {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = true, want false", v)
		}
	}
}

// ======================== COVERAGE BOOSTER TESTS ========================

func TestTLSDialer_BuilderMethods(t *testing.T) {
	d := NewTLSDialer(ChromeLatest)
	d.SetALPN([]string{"h2"})
	d.SetCustomCAs(nil)
	fp := d.Fingerprint()
	if fp.Name != "Chrome-Latest" {
		t.Errorf("Fingerprint().Name = %q, want Chrome-Latest", fp.Name)
	}
}

func TestTLSVersionStr(t *testing.T) {
	tests := []struct {
		ver  uint16
		want string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0x0200, "00"},
	}
	for _, tt := range tests {
		got := tlsVersionStr(tt.ver)
		if got != tt.want {
			t.Errorf("tlsVersionStr(%#04x) = %q, want %q", tt.ver, got, tt.want)
		}
	}
}

func TestNegotiatedProtocol_PlainConn(t *testing.T) {
	// Non-TLS connection should return empty string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	proto := NegotiatedProtocol(conn)
	if proto != "" {
		t.Errorf("NegotiatedProtocol(plain) = %q, want empty", proto)
	}

	state := ConnectionState(conn)
	if state != nil {
		t.Error("ConnectionState(plain) should be nil")
	}
}

func TestConnectionState_GoDefault(t *testing.T) {
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	d := NewTLSDialer(GoDefault).SetInsecureSkipVerify(true).SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	state := ConnectionState(conn)
	if state == nil {
		t.Fatal("ConnectionState returned nil for GoDefault")
	}
	if !state.HandshakeComplete {
		t.Error("HandshakeComplete should be true")
	}
}

func TestJA4_ALPN_SingleChar(t *testing.T) {
	ch := &ClientHelloFields{
		Version:       0x0303,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x0010},
		ALPNProtocols: []string{"x"},
		SupportedVers: []uint16{0x0304},
	}
	ja4 := ComputeJA4(ch)
	parts := splitJA4(ja4)
	if parts[0][8:10] != "xx" {
		t.Errorf("JA4_a alpn for single char = %s, want xx", parts[0][8:10])
	}
}

func TestJA4_NoALPN(t *testing.T) {
	ch := &ClientHelloFields{
		Version:       0x0303,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x000a},
		SupportedVers: []uint16{0x0304},
	}
	ja4 := ComputeJA4(ch)
	parts := splitJA4(ja4)
	if parts[0][8:10] != "00" {
		t.Errorf("JA4_a alpn for no ALPN = %s, want 00", parts[0][8:10])
	}
}

func TestFingerprint_IsCustom(t *testing.T) {
	fp := TLSFingerprint{CustomSpec: &utls.ClientHelloSpec{}}
	if !fp.IsCustom() {
		t.Error("IsCustom() should be true when CustomSpec is set")
	}
	if GoDefault.IsCustom() {
		t.Error("GoDefault.IsCustom() should be false")
	}
}

// ======================== HELPERS ========================

func splitJA4(ja4 string) []string {
	parts := make([]string, 0, 3)
	idx := 0
	for i := 0; i < len(ja4); i++ {
		if ja4[i] == '_' {
			parts = append(parts, ja4[idx:i])
			idx = i + 1
		}
	}
	parts = append(parts, ja4[idx:])
	return parts
}
