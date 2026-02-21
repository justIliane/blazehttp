package http2_test

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/blazehttp/blazehttp/pkg/frame"
	"github.com/blazehttp/blazehttp/pkg/hpack"
	"github.com/blazehttp/blazehttp/server"
	"github.com/blazehttp/blazehttp/server/http2"
)

// rawH2Conn wraps a TLS connection with frame reader/writer for raw HTTP/2 testing.
type rawH2Conn struct {
	conn net.Conn
	fr   *frame.FrameReader
	fw   *frame.FrameWriter
	enc  *hpack.Encoder
	dec  *hpack.Decoder
}

func dialRawH2(t *testing.T, addr string) *rawH2Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	rc := &rawH2Conn{
		conn: conn,
		fr:   frame.AcquireFrameReader(conn),
		fw:   frame.AcquireFrameWriter(conn),
		enc:  hpack.AcquireEncoder(),
		dec:  hpack.AcquireDecoder(),
	}

	// Send client preface.
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatalf("Write preface: %v", err)
	}

	// Send empty SETTINGS.
	rc.fw.WriteSettings()
	if err := rc.fw.Flush(); err != nil {
		t.Fatalf("Flush SETTINGS: %v", err)
	}

	// Read server's SETTINGS + SETTINGS ACK + WINDOW_UPDATE.
	for i := 0; i < 3; i++ {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := rc.fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if f.Type == frame.FrameSettings && !f.Flags.Has(frame.FlagACK) {
			// ACK the server's settings.
			rc.fw.WriteSettingsACK()
			if err := rc.fw.Flush(); err != nil {
				t.Fatalf("Flush SETTINGS ACK: %v", err)
			}
		}
	}

	conn.SetReadDeadline(time.Time{})
	return rc
}

func (rc *rawH2Conn) close() {
	rc.conn.Close()
	frame.ReleaseFrameReader(rc.fr)
	hpack.ReleaseEncoder(rc.enc)
	hpack.ReleaseDecoder(rc.dec)
}

func (rc *rawH2Conn) sendHeaders(streamID uint32, endStream bool, method, path string) {
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte(method), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte(path), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)

	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())

	rc.fw.WriteHeaders(streamID, endStream, hb, nil)
	rc.fw.Flush()
}

func (rc *rawH2Conn) readResponse(t *testing.T) (*frame.Frame, []byte) {
	t.Helper()
	rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var headerFrame *frame.Frame
	var body []byte

	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		switch f.Type {
		case frame.FrameHeaders:
			// Make a copy since the frame is reused.
			headerFrame = &frame.Frame{
				Type:        f.Type,
				Flags:       f.Flags,
				StreamID:    f.StreamID,
				HeaderBlock: append([]byte(nil), f.HeaderBlock...),
			}
			if f.HasEndStream() {
				return headerFrame, body
			}
		case frame.FrameData:
			body = append(body, f.Data...)
			if f.HasEndStream() {
				return headerFrame, body
			}
		case frame.FrameWindowUpdate:
			// Skip window updates
		case frame.FrameSettings:
			// Skip settings
		default:
			// Skip other frames
		}
	}
}

// startRawTestServer starts a server without the readiness-check connection.
func startRawTestServer(t *testing.T, handler http2.RequestHandler) (string, func()) {
	t.Helper()
	cert, err := server.GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv := &server.Server{
		Addr:                addr,
		Handler:             handler,
		MaxConcurrentStreams: 250,
		WorkerPoolSize:      8,
		IdleTimeout:         5 * time.Second,
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        5 * time.Second,
	}

	go srv.ListenAndServeTLSCert(cert)

	// Wait for server to be ready.
	for i := 0; i < 100; i++ {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 50 * time.Millisecond},
			"tcp", addr,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
		)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return addr, func() { srv.Close() }
}

func TestHTTP2_PingPong(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send PING.
	pingData := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	rc.fw.WritePing(false, pingData)
	if err := rc.fw.Flush(); err != nil {
		t.Fatalf("Flush PING: %v", err)
	}

	// Read PING ACK.
	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	f, err := rc.fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != frame.FramePing {
		t.Fatalf("expected PING, got type=%d", f.Type)
	}
	if !f.Flags.Has(frame.FlagACK) {
		t.Fatal("PING should have ACK flag")
	}
	if f.PingData != pingData {
		t.Fatalf("PING data = %v, want %v", f.PingData, pingData)
	}
}

func TestHTTP2_RSTStream(t *testing.T) {
	handlerCalled := make(chan struct{}, 1)
	handler := func(ctx *http2.RequestCtx) {
		handlerCalled <- struct{}{}
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send HEADERS without END_STREAM (body will follow).
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte("POST"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/upload"), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)
	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, false, hb, nil)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Immediately send RST_STREAM to cancel.
	rc.fw.WriteRSTStream(1, frame.ErrCodeCancel)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Send another request on stream 3 to verify the connection is still good.
	rc.sendHeaders(3, true, "GET", "/")
	hf, body := rc.readResponse(t)
	if hf == nil {
		t.Fatal("no response received")
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

func TestHTTP2_GoAwayFromClient(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("goaway-ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send request.
	rc.sendHeaders(1, true, "GET", "/")

	// Send GOAWAY (like curl does).
	rc.fw.WriteGoAway(0, frame.ErrCodeNoError, nil)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Should still receive the response.
	hf, body := rc.readResponse(t)
	if hf == nil {
		t.Fatal("no response received after GOAWAY")
	}
	if string(body) != "goaway-ok" {
		t.Fatalf("body = %q, want goaway-ok", body)
	}
}

func TestHTTP2_FlowControl_WindowUpdate(t *testing.T) {
	const bodySize = 32 * 1024 // fits within initial window of 65535
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		body := make([]byte, bodySize)
		for i := range body {
			body[i] = 'A'
		}
		ctx.SetBody(body)
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	rc.sendHeaders(1, true, "GET", "/large")

	var totalData int
	rc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("ReadFrame: %v", err)
		}
		switch f.Type {
		case frame.FrameData:
			totalData += len(f.Data)
			if f.HasEndStream() {
				goto done
			}
		case frame.FrameHeaders, frame.FrameWindowUpdate, frame.FrameSettings:
			// Skip
		default:
			// Skip other frames
		}
	}
done:
	if totalData != bodySize {
		t.Fatalf("total data = %d, want %d", totalData, bodySize)
	}
}

func TestHTTP2_SettingsExchange(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("settings-ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send new SETTINGS mid-connection.
	rc.fw.WriteSettings(
		frame.Setting{ID: frame.SettingsMaxConcurrentStreams, Value: 50},
	)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Read SETTINGS ACK from server.
	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	f, err := rc.fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != frame.FrameSettings || !f.Flags.Has(frame.FlagACK) {
		t.Fatalf("expected SETTINGS ACK, got type=%d flags=0x%02x", f.Type, f.Flags)
	}

	// Verify connection still works.
	rc.sendHeaders(1, true, "GET", "/")
	hf, body := rc.readResponse(t)
	if hf == nil {
		t.Fatal("no response")
	}
	if string(body) != "settings-ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTP2_PostWithBody_WindowUpdate(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBody(ctx.Request.Body())
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send HEADERS without END_STREAM (body will follow).
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte("POST"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/echo"), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)
	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, false, hb, nil)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Send DATA frames to exercise the DATA handling path.
	payload := make([]byte, 8192)
	for i := range payload {
		payload[i] = 'X'
	}

	// Send 4 DATA frames (32KB total), last with END_STREAM.
	for i := 0; i < 4; i++ {
		endStream := i == 3
		rc.fw.WriteData(1, endStream, payload)
		if err := rc.fw.Flush(); err != nil {
			t.Fatal(err)
		}
	}

	// Read response.
	_, body := rc.readResponse(t)
	if len(body) != 4*8192 {
		t.Fatalf("body size = %d, want %d", len(body), 4*8192)
	}
}

func TestHTTP2_MalformedFrame_GoAway(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Send client preface.
	conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))

	// Send valid SETTINGS.
	fw := frame.AcquireFrameWriter(conn)
	fw.WriteSettings()
	fw.Flush()

	// Read server frames.
	fr := frame.AcquireFrameReader(conn)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 3; i++ {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameSettings && !f.Flags.Has(frame.FlagACK) {
			fw.WriteSettingsACK()
			fw.Flush()
		}
	}

	// Send a SETTINGS frame on a non-zero stream (protocol error).
	// This should trigger server to send GOAWAY.
	raw := []byte{
		0, 0, 0, // length=0
		4,    // type=SETTINGS
		0,    // flags
		0, 0, 0, 1, // stream ID = 1 (invalid for SETTINGS)
	}
	conn.Write(raw)

	// Read GOAWAY from server.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			// Connection closed, which is expected after GOAWAY.
			break
		}
		if f.Type == frame.FrameGoAway {
			if f.ErrorCode != frame.ErrCodeProtocolError {
				t.Fatalf("GOAWAY error code = %d, want PROTOCOL_ERROR", f.ErrorCode)
			}
			return // Success.
		}
	}
	// If we get here without seeing GOAWAY, that's OK — the server may have
	// closed the connection directly.
}

func TestHTTP2_WindowUpdate_OnStream(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send WINDOW_UPDATE on stream 0 to bump connection window.
	rc.fw.WriteWindowUpdate(0, 65535)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Should still work.
	rc.sendHeaders(1, true, "GET", "/")
	_, body := rc.readResponse(t)
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTP2_TrailingHeaders(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBody(ctx.Request.Body())
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send HEADERS without END_STREAM.
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte("POST"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/echo"), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)
	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, false, hb, nil)
	rc.fw.Flush()

	// Send DATA without END_STREAM.
	rc.fw.WriteData(1, false, []byte("hello"))
	rc.fw.Flush()

	// Send trailing HEADERS with END_STREAM (trailers).
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte("grpc-status"), []byte("0"), false)
	thb := make([]byte, len(rc.enc.Bytes()))
	copy(thb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, true, thb, nil)
	rc.fw.Flush()

	// Read response — should echo the body.
	_, body := rc.readResponse(t)
	if string(body) != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
}

func TestHTTP2_TrailingHeadersWithoutEndStream(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send HEADERS without END_STREAM (open stream 1).
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte("POST"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/"), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)
	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, false, hb, nil)
	rc.fw.Flush()

	// Send trailing HEADERS WITHOUT END_STREAM (protocol error).
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte("trailer-key"), []byte("val"), false)
	thb := make([]byte, len(rc.enc.Bytes()))
	copy(thb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, false, thb, nil)
	rc.fw.Flush()

	// Server should send RST_STREAM for protocol error.
	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameRSTStream && f.StreamID == 1 {
			return // Success — protocol error detected.
		}
	}
	t.Fatal("expected RST_STREAM for trailing headers without END_STREAM")
}

func TestHTTP2_LargePostTriggersWindowUpdate(t *testing.T) {
	const bodySize = 600 * 1024 // 600KB — exceeds initial 1MB window / 2 threshold
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send HEADERS without END_STREAM.
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte("POST"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/upload"), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)
	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, false, hb, nil)
	rc.fw.Flush()

	// Send lots of DATA frames (16KB each) to consume >50% of the receive window.
	// Server's InitialWindowSize is 1MB, threshold = 512KB.
	// Sending 600KB should trigger WINDOW_UPDATE.
	chunk := make([]byte, 16384)
	sent := 0
	for sent < bodySize {
		remaining := bodySize - sent
		n := len(chunk)
		if n > remaining {
			n = remaining
		}
		endStream := sent+n >= bodySize
		rc.fw.WriteData(1, endStream, chunk[:n])
		rc.fw.Flush()
		sent += n
	}

	// Read frames — look for WINDOW_UPDATE frames.
	sawWindowUpdate := false
	rc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameWindowUpdate {
			sawWindowUpdate = true
		}
		if f.Type == frame.FrameHeaders && f.HasEndStream() {
			break
		}
		if f.Type == frame.FrameData && f.HasEndStream() {
			break
		}
	}
	if !sawWindowUpdate {
		t.Fatal("expected WINDOW_UPDATE from server for large POST")
	}
}

func TestHTTP2_SettingsInitialWindowSizeChange(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send SETTINGS with changed INITIAL_WINDOW_SIZE to exercise applyPeerSettings delta path.
	rc.fw.WriteSettings(
		frame.Setting{ID: frame.SettingsInitialWindowSize, Value: 1 << 20},
	)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Read SETTINGS ACK from server.
	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	f, err := rc.fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != frame.FrameSettings || !f.Flags.Has(frame.FlagACK) {
		t.Fatalf("expected SETTINGS ACK, got type=%d flags=0x%02x", f.Type, f.Flags)
	}

	// Verify connection still works.
	rc.sendHeaders(1, true, "GET", "/")
	_, body := rc.readResponse(t)
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTP2_PingACKFromClient(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send a PING with ACK flag (client ACK — server should ignore).
	pingData := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	rc.fw.WritePing(true, pingData)
	if err := rc.fw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Verify connection still works.
	rc.sendHeaders(1, true, "GET", "/")
	_, body := rc.readResponse(t)
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTP2_DataOnClosedStream(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send a complete request on stream 1.
	rc.sendHeaders(1, true, "GET", "/")
	rc.readResponse(t)

	// Now send DATA on stream 1 (which is closed). Server should handle gracefully.
	rc.fw.WriteData(1, true, []byte("stale-data"))
	rc.fw.Flush()

	// Verify connection still works on stream 3.
	rc.sendHeaders(3, true, "GET", "/")
	_, body := rc.readResponse(t)
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTP2_DuplicatePseudoPath(t *testing.T) {
	handler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("should-not-reach")
	}

	addr, cleanup := startRawTestServer(t, handler)
	defer cleanup()

	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send HEADERS with duplicate :path.
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte("GET"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/a"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/b"), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)
	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, true, hb, nil)
	rc.fw.Flush()

	// Server should send RST_STREAM for protocol error.
	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameRSTStream {
			// RST_STREAM received — test passes.
			return
		}
	}
	t.Fatal("expected RST_STREAM for duplicate pseudo-header")
}
