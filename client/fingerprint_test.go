package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/justIliane/blazehttp/client/h2fingerprint"
	blazetls "github.com/justIliane/blazehttp/client/tls"
	"github.com/justIliane/blazehttp/pkg/frame"
	"github.com/justIliane/blazehttp/pkg/hpack"
	"github.com/justIliane/blazehttp/server/http2"
)

// --- H2 SETTINGS capture tests ---

// captureH2Settings starts a TLS server, accepts one connection, reads the
// HTTP/2 connection preface, and returns the captured frames (SETTINGS,
// WINDOW_UPDATE, PRIORITY).
func captureH2Settings(t *testing.T) (string, <-chan []frame.Frame, func()) {
	t.Helper()
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan []frame.Frame, 1)
	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the HTTP/2 connection preface magic.
		magic := make([]byte, 24)
		if _, err := io.ReadFull(conn, magic); err != nil {
			return
		}

		// Read frames using the frame reader.
		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)

		// Send server SETTINGS so the client handshake can complete.
		fw := frame.AcquireFrameWriter(conn)
		fw.WriteSettings(frame.Setting{ID: frame.SettingsMaxConcurrentStreams, Value: 100})
		fw.Flush()
		frame.ReleaseFrameWriter(fw)

		var frames []frame.Frame
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for i := 0; i < 20; i++ {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			fc := frame.Frame{
				Type:            f.Type,
				Flags:           f.Flags,
				StreamID:        f.StreamID,
				Length:          f.Length,
				NumSettings:     f.NumSettings,
				WindowIncrement: f.WindowIncrement,
				StreamDep:       f.StreamDep,
				Weight:          f.Weight,
				Exclusive:       f.Exclusive,
			}
			for j := 0; j < f.NumSettings; j++ {
				fc.Settings[j] = f.Settings[j]
			}
			if f.Type == frame.FrameHeaders {
				// Copy header block for pseudo-header analysis.
				fc.HeaderBlock = make([]byte, len(f.HeaderBlock))
				copy(fc.HeaderBlock, f.HeaderBlock)
			}
			frames = append(frames, fc)
			// Stop after SETTINGS ACK (client handshake done).
			if f.Type == frame.FrameSettings && f.Flags.Has(frame.FlagACK) {
				break
			}
		}
		ch <- frames
	}()

	cleanup := func() {
		close(done)
		ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), ch, cleanup
}

func TestFingerprint_ChromeH2Settings(t *testing.T) {
	addr, framesCh, cleanup := captureH2Settings(t)
	defer cleanup()

	// Connect using Chrome profile.
	d := blazetls.NewTLSDialer(blazetls.ChromeLatest).
		SetInsecureSkipVerify(true).
		SetTimeout(5 * time.Second)
	profile := h2fingerprint.ChromeH2.Clone()

	cc, err := Dial(addr, d, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	select {
	case frames := <-framesCh:
		// First frame must be SETTINGS.
		if len(frames) < 1 || frames[0].Type != frame.FrameSettings {
			t.Fatal("first frame is not SETTINGS")
		}

		// Verify settings count.
		f := frames[0]
		if f.NumSettings != len(h2fingerprint.ChromeH2.Settings) {
			t.Fatalf("settings count: got %d, want %d", f.NumSettings, len(h2fingerprint.ChromeH2.Settings))
		}

		// Verify each setting ID and value in order.
		for i := 0; i < f.NumSettings; i++ {
			if f.Settings[i].ID != h2fingerprint.ChromeH2.Settings[i].ID {
				t.Errorf("setting[%d] ID: got %d, want %d", i, f.Settings[i].ID, h2fingerprint.ChromeH2.Settings[i].ID)
			}
			if f.Settings[i].Value != h2fingerprint.ChromeH2.Settings[i].Value {
				t.Errorf("setting[%d] Value: got %d, want %d", i, f.Settings[i].Value, h2fingerprint.ChromeH2.Settings[i].Value)
			}
		}

		// Second frame must be WINDOW_UPDATE.
		if len(frames) < 2 || frames[1].Type != frame.FrameWindowUpdate {
			t.Fatal("second frame is not WINDOW_UPDATE")
		}
		if frames[1].WindowIncrement != h2fingerprint.ChromeH2.ConnectionWindowUpdate {
			t.Errorf("WINDOW_UPDATE: got %d, want %d", frames[1].WindowIncrement, h2fingerprint.ChromeH2.ConnectionWindowUpdate)
		}

		// Frames 2-6 must be PRIORITY.
		for i, p := range h2fingerprint.ChromeH2.PriorityFrames {
			idx := i + 2
			if idx >= len(frames) {
				t.Fatalf("missing PRIORITY frame %d", i)
			}
			if frames[idx].Type != frame.FramePriority {
				t.Fatalf("frame[%d]: got %v, want PRIORITY", idx, frames[idx].Type)
			}
			if frames[idx].StreamID != p.StreamID {
				t.Errorf("priority[%d] streamID: got %d, want %d", i, frames[idx].StreamID, p.StreamID)
			}
			if frames[idx].Weight != p.Weight {
				t.Errorf("priority[%d] weight: got %d, want %d", i, frames[idx].Weight, p.Weight)
			}
		}

	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for captured frames")
	}
}

func TestFingerprint_FirefoxH2Settings(t *testing.T) {
	addr, framesCh, cleanup := captureH2Settings(t)
	defer cleanup()

	// Connect using Firefox profile.
	d := blazetls.NewTLSDialer(blazetls.FirefoxLatest).
		SetInsecureSkipVerify(true).
		SetTimeout(5 * time.Second)
	profile := h2fingerprint.FirefoxH2.Clone()

	cc, err := Dial(addr, d, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	select {
	case frames := <-framesCh:
		// SETTINGS.
		if len(frames) < 1 || frames[0].Type != frame.FrameSettings {
			t.Fatal("first frame is not SETTINGS")
		}
		f := frames[0]
		if f.NumSettings != len(h2fingerprint.FirefoxH2.Settings) {
			t.Fatalf("settings count: got %d, want %d", f.NumSettings, len(h2fingerprint.FirefoxH2.Settings))
		}
		for i := 0; i < f.NumSettings; i++ {
			if f.Settings[i].ID != h2fingerprint.FirefoxH2.Settings[i].ID {
				t.Errorf("setting[%d] ID: got %d, want %d", i, f.Settings[i].ID, h2fingerprint.FirefoxH2.Settings[i].ID)
			}
			if f.Settings[i].Value != h2fingerprint.FirefoxH2.Settings[i].Value {
				t.Errorf("setting[%d] Value: got %d, want %d", i, f.Settings[i].Value, h2fingerprint.FirefoxH2.Settings[i].Value)
			}
		}

		// WINDOW_UPDATE.
		if len(frames) < 2 || frames[1].Type != frame.FrameWindowUpdate {
			t.Fatal("second frame is not WINDOW_UPDATE")
		}
		if frames[1].WindowIncrement != h2fingerprint.FirefoxH2.ConnectionWindowUpdate {
			t.Errorf("WINDOW_UPDATE: got %d, want %d", frames[1].WindowIncrement, h2fingerprint.FirefoxH2.ConnectionWindowUpdate)
		}

		// No PRIORITY frames for Firefox.
		for i := 2; i < len(frames); i++ {
			if frames[i].Type == frame.FramePriority {
				t.Errorf("unexpected PRIORITY frame at index %d", i)
			}
		}

	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for captured frames")
	}
}

// --- Pseudo-header order tests ---

// captureH2Headers starts a TLS+HTTP/2 server that captures the raw HEADERS
// frame payload from the first request for pseudo-header order analysis.
func captureH2Headers(t *testing.T) (string, <-chan []byte, func()) {
	t.Helper()
	cert := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan []byte, 1)
	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)
		fw := frame.AcquireFrameWriter(conn)
		defer frame.ReleaseFrameWriter(fw)

		// Perform server-side handshake.
		if err := rawServerHandshake(conn, fr, fw); err != nil {
			return
		}

		// Read HEADERS frame from client.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if f.Type == frame.FrameHeaders {
				payload := make([]byte, len(f.HeaderBlock))
				copy(payload, f.HeaderBlock)
				ch <- payload

				// Send a minimal response.
				enc := hpack.AcquireEncoder()
				enc.EncodeSingle([]byte(":status"), []byte("200"), false)
				fw.WriteHeaders(f.StreamID, true, enc.Bytes(), nil)
				fw.Flush()
				hpack.ReleaseEncoder(enc)
				break
			}
		}
	}()

	cleanup := func() {
		close(done)
		ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), ch, cleanup
}

func TestFingerprint_ChromePseudoHeaders(t *testing.T) {
	addr, headersCh, cleanup := captureH2Headers(t)
	defer cleanup()

	// Connect with Chrome profile.
	d := blazetls.NewTLSDialer(blazetls.ChromeLatest).
		SetInsecureSkipVerify(true).
		SetTimeout(5 * time.Second)
	profile := h2fingerprint.ChromeH2.Clone()

	cc, err := Dial(addr, d, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	// Send a request.
	_, err = cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: addr,
		Path:      "/test",
	})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case payload := <-headersCh:
		// Decode the HPACK-encoded headers and extract pseudo-header order.
		pseudoOrder := decodePseudoHeaderOrder(t, payload)
		expected := []string{":method", ":authority", ":scheme", ":path"}
		if len(pseudoOrder) != len(expected) {
			t.Fatalf("pseudo-header count: got %d %v, want %d %v", len(pseudoOrder), pseudoOrder, len(expected), expected)
		}
		for i, ph := range expected {
			if pseudoOrder[i] != ph {
				t.Errorf("pseudo[%d]: got %q, want %q", i, pseudoOrder[i], ph)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for headers")
	}
}

func TestFingerprint_FirefoxPseudoHeaders(t *testing.T) {
	addr, headersCh, cleanup := captureH2Headers(t)
	defer cleanup()

	// Connect with Firefox profile.
	d := blazetls.NewTLSDialer(blazetls.FirefoxLatest).
		SetInsecureSkipVerify(true).
		SetTimeout(5 * time.Second)
	profile := h2fingerprint.FirefoxH2.Clone()

	cc, err := Dial(addr, d, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	_, err = cc.roundTrip(&h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: addr,
		Path:      "/test",
	})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case payload := <-headersCh:
		pseudoOrder := decodePseudoHeaderOrder(t, payload)
		expected := []string{":method", ":path", ":authority", ":scheme"}
		if len(pseudoOrder) != len(expected) {
			t.Fatalf("pseudo-header count: got %d %v, want %d %v", len(pseudoOrder), pseudoOrder, len(expected), expected)
		}
		for i, ph := range expected {
			if pseudoOrder[i] != ph {
				t.Errorf("pseudo[%d]: got %q, want %q", i, pseudoOrder[i], ph)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for headers")
	}
}

// decodePseudoHeaderOrder decodes an HPACK block and returns the pseudo-header
// names in the order they appear.
func decodePseudoHeaderOrder(t *testing.T, payload []byte) []string {
	t.Helper()
	dec := hpack.AcquireDecoder()
	defer hpack.ReleaseDecoder(dec)

	fields, err := dec.Decode(payload)
	if err != nil {
		t.Fatalf("HPACK decode: %v", err)
	}

	var order []string
	for _, f := range fields {
		n := string(f.Name)
		if strings.HasPrefix(n, ":") {
			order = append(order, n)
		}
	}
	return order
}

// --- Akamai hash tests ---

func TestFingerprint_AkamaiHash_Chrome(t *testing.T) {
	hash := h2fingerprint.ComputeAkamaiHash(&h2fingerprint.ChromeH2)
	expected := "1:65536;3:1000;4:6291456;6:262144|15663105|3:0:200:0,5:0:100:0,7:0:0:0,9:7:0:0,11:3:0:0|m,a,s,p"
	if hash != expected {
		t.Errorf("Chrome Akamai hash:\n  got:  %s\n  want: %s", hash, expected)
	}
	t.Logf("Chrome Akamai hash: %s", hash)
}

func TestFingerprint_AkamaiHash_Firefox(t *testing.T) {
	hash := h2fingerprint.ComputeAkamaiHash(&h2fingerprint.FirefoxH2)
	expected := "1:65536;4:131072;5:16384|12517377||m,p,a,s"
	if hash != expected {
		t.Errorf("Firefox Akamai hash:\n  got:  %s\n  want: %s", hash, expected)
	}
	t.Logf("Firefox Akamai hash: %s", hash)
}

// --- JA3/JA4 local capture tests ---

// captureClientHello starts a TLS server that captures the raw ClientHello.
func captureClientHello(t *testing.T) (string, <-chan []byte, func()) {
	t.Helper()
	cert := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan []byte, 8)
	done := make(chan struct{})
	var wg sync.WaitGroup

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
			// Read the raw ClientHello.
			buf := make([]byte, 16384)
			n, _ := conn.Read(buf)
			if n > 0 {
				raw := make([]byte, n)
				copy(raw, buf[:n])
				ch <- raw
			}
			// Complete TLS handshake so the connection can proceed.
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

func TestFingerprint_JA3_NotGoDefault(t *testing.T) {
	addr, rawCh, cleanup := captureClientHello(t)
	defer cleanup()

	// Capture Chrome ClientHello.
	d := blazetls.NewTLSDialer(blazetls.ChromeLatest).
		SetInsecureSkipVerify(true).
		SetTimeout(5 * time.Second)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	var chromeJA3 string
	select {
	case raw := <-rawCh:
		ja3Str, ja3Hash, err := blazetls.ComputeJA3FromRaw(raw)
		if err != nil {
			t.Fatalf("ComputeJA3FromRaw: %v", err)
		}
		chromeJA3 = ja3Str
		t.Logf("Chrome JA3: %s", ja3Str)
		t.Logf("Chrome JA3 hash: %s", ja3Hash)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Chrome ClientHello")
	}

	// Capture Go default ClientHello.
	dGo := blazetls.NewTLSDialer(blazetls.GoDefault).
		SetInsecureSkipVerify(true).
		SetTimeout(5 * time.Second)
	connGo, err := dGo.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	connGo.Close()

	select {
	case raw := <-rawCh:
		goJA3, _, err := blazetls.ComputeJA3FromRaw(raw)
		if err != nil {
			t.Fatalf("ComputeJA3FromRaw (Go): %v", err)
		}
		t.Logf("Go default JA3: %s", goJA3)

		if chromeJA3 == goJA3 {
			t.Error("Chrome JA3 should differ from Go default JA3")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Go ClientHello")
	}
}

func TestFingerprint_JA4_ChromeStable(t *testing.T) {
	addr, rawCh, cleanup := captureClientHello(t)
	defer cleanup()

	const numConns = 5
	var ja4s []string

	for i := 0; i < numConns; i++ {
		d := blazetls.NewTLSDialer(blazetls.ChromeLatest).
			SetInsecureSkipVerify(true).
			SetTimeout(5 * time.Second)
		conn, err := d.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.Close()

		select {
		case raw := <-rawCh:
			ja4, err := blazetls.ComputeJA4FromRaw(raw)
			if err != nil {
				t.Fatalf("ComputeJA4FromRaw %d: %v", i, err)
			}
			ja4s = append(ja4s, ja4)
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for ClientHello %d", i)
		}
	}

	// All JA4 hashes should be identical (JA4 is immune to extension order randomization).
	for i := 1; i < len(ja4s); i++ {
		if ja4s[i] != ja4s[0] {
			t.Errorf("JA4[%d] = %q differs from JA4[0] = %q", i, ja4s[i], ja4s[0])
		}
	}
	t.Logf("Chrome JA4 (stable across %d connections): %s", len(ja4s), ja4s[0])
}

// --- Multiplex test ---

func TestFingerprint_Multiplex100Streams(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	})
	defer cleanup()

	c := testClient(t, addr)
	defer c.Close()

	// Build 100 requests.
	const numReqs = 100
	reqs := make([]*Request, numReqs)
	for i := 0; i < numReqs; i++ {
		reqs[i] = NewRequest("GET", fmt.Sprintf("https://%s/req/%d", addr, i))
	}

	start := time.Now()
	resps, err := c.DoBatch(reqs)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatal(err)
	}
	if len(resps) != numReqs {
		t.Fatalf("responses: got %d, want %d", len(resps), numReqs)
	}

	for i, resp := range resps {
		if resp.StatusCode != 200 {
			t.Errorf("response[%d] status: %d", i, resp.StatusCode)
		}
	}

	// Should complete in < 1 second on a local server.
	if elapsed > time.Second {
		t.Errorf("100 multiplexed requests took %v, want < 1s", elapsed)
	}
	t.Logf("100 multiplexed requests in %v", elapsed)

	// Verify multiplexing (should use a small number of connections, not 100).
	connCount := c.pool.ConnCount(addr)
	t.Logf("connections used: %d", connCount)
	if connCount > 10 {
		t.Errorf("too many connections: got %d, want <= 10 (multiplexing should reuse connections)", connCount)
	}
}

// --- Optional E2E test against tls.peet.ws ---

func TestFingerprint_TLSPeetWS(t *testing.T) {
	if testing.Short() {
		t.Skip("Requires internet — skipped in -short mode")
	}

	c := NewChromeClient()
	defer c.Close()

	resp, err := c.Get("https://tls.peet.ws/api/all")
	if err != nil {
		t.Skipf("Cannot reach tls.peet.ws: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("tls.peet.ws status: %d", resp.StatusCode)
	}

	body := string(resp.Body)
	t.Logf("tls.peet.ws response length: %d bytes", len(body))

	// Verify the response contains expected fingerprint sections.
	if !strings.Contains(body, "ja3") && !strings.Contains(body, "JA3") {
		t.Error("response does not contain JA3 data")
	}
	if !strings.Contains(body, "ja4") && !strings.Contains(body, "JA4") {
		t.Error("response does not contain JA4 data")
	}
	if !strings.Contains(body, "h2") || !strings.Contains(body, "http2") {
		// Some responses may use different key names; just log it.
		t.Logf("response may not contain HTTP/2 fingerprint data")
	}

	t.Logf("tls.peet.ws body (first 500 chars): %s", truncate(body, 500))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
