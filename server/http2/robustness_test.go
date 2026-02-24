package http2_test

import (
	"testing"
	"time"

	"github.com/justIliane/blazehttp/pkg/frame"
	"github.com/justIliane/blazehttp/server/http2"
)

var robustnessHandler = func(ctx *http2.RequestCtx) {
	ctx.SetStatusCode(200)
	ctx.SetBodyString("ok")
}

// TestRobustness_PINGFlood verifies the server closes the connection
// when a client sends too many PING frames (flood protection).
func TestRobustness_PINGFlood(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send 1100 PING frames rapidly (threshold is 1000 per 10s).
	for i := 0; i < 1100; i++ {
		rc.fw.WritePing(false, [8]byte{byte(i), byte(i >> 8)})
	}
	if err := rc.fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Expect GOAWAY with ENHANCE_YOUR_CALM.
	rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	gotGoAway := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameGoAway && f.ErrorCode == frame.ErrCodeEnhanceYourCalm {
			gotGoAway = true
			break
		}
	}
	if !gotGoAway {
		t.Fatal("expected GOAWAY ENHANCE_YOUR_CALM for PING flood")
	}
}

// TestRobustness_RapidReset (CVE-2023-44487) verifies the server detects
// and mitigates the HTTP/2 rapid reset attack.
func TestRobustness_RapidReset(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	// Open streams and immediately reset them.
	for i := 0; i < 1100; i++ {
		streamID := uint32(2*i + 1)
		rc.sendHeaders(streamID, true, "GET", "/")
		rc.fw.WriteRSTStream(streamID, frame.ErrCodeCancel)
	}
	if err := rc.fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Expect GOAWAY with ENHANCE_YOUR_CALM.
	rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	gotGoAway := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameGoAway && f.ErrorCode == frame.ErrCodeEnhanceYourCalm {
			gotGoAway = true
			break
		}
	}
	if !gotGoAway {
		t.Fatal("expected GOAWAY ENHANCE_YOUR_CALM for rapid reset (CVE-2023-44487)")
	}
}

// TestRobustness_SETTINGSFlood verifies SETTINGS flood protection.
func TestRobustness_SETTINGSFlood(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	for i := 0; i < 1100; i++ {
		rc.fw.WriteSettings(frame.Setting{
			ID:    frame.SettingsMaxConcurrentStreams,
			Value: 100,
		})
	}
	if err := rc.fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	gotGoAway := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameGoAway && f.ErrorCode == frame.ErrCodeEnhanceYourCalm {
			gotGoAway = true
			break
		}
	}
	if !gotGoAway {
		t.Fatal("expected GOAWAY ENHANCE_YOUR_CALM for SETTINGS flood")
	}
}

// TestRobustness_WindowUpdateZeroStream verifies that WINDOW_UPDATE
// with 0 increment on a stream causes RST_STREAM, not connection error.
func TestRobustness_WindowUpdateZeroStream(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	// Open a stream.
	rc.sendHeaders(1, false, "POST", "/")

	// Send WINDOW_UPDATE with 0 increment on stream 1.
	rc.fw.WriteWindowUpdate(1, 0)
	if err := rc.fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotRST := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameRSTStream && f.StreamID == 1 && f.ErrorCode == frame.ErrCodeProtocolError {
			gotRST = true
			break
		}
	}
	if !gotRST {
		t.Fatal("expected RST_STREAM PROTOCOL_ERROR for WINDOW_UPDATE with 0 increment on stream")
	}
}

// TestRobustness_WindowUpdateZeroConnection verifies that WINDOW_UPDATE
// with 0 increment on the connection causes GOAWAY.
func TestRobustness_WindowUpdateZeroConnection(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send WINDOW_UPDATE with 0 increment on connection (stream 0).
	rc.fw.WriteWindowUpdate(0, 0)
	if err := rc.fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotGoAway := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameGoAway && f.ErrorCode == frame.ErrCodeProtocolError {
			gotGoAway = true
			break
		}
	}
	if !gotGoAway {
		t.Fatal("expected GOAWAY PROTOCOL_ERROR for WINDOW_UPDATE with 0 increment on connection")
	}
}

// TestRobustness_HeadersOnClosedStream verifies GOAWAY for HEADERS on a closed stream.
func TestRobustness_HeadersOnClosedStream(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send request and wait for response.
	rc.sendHeaders(1, true, "GET", "/")
	rc.readResponse(t)

	// Send HEADERS on the now-closed stream 1.
	time.Sleep(10 * time.Millisecond) // let server close the stream
	rc.sendHeaders(1, true, "GET", "/")

	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotGoAway := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameGoAway && f.ErrorCode == frame.ErrCodeStreamClosed {
			gotGoAway = true
			break
		}
	}
	if !gotGoAway {
		t.Fatal("expected GOAWAY STREAM_CLOSED for HEADERS on closed stream")
	}
}

// TestRobustness_EvenStreamID verifies that even stream IDs from client are rejected.
func TestRobustness_EvenStreamID(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	// Send HEADERS with even stream ID.
	rc.sendHeaders(2, true, "GET", "/")

	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotGoAway := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameGoAway && f.ErrorCode == frame.ErrCodeProtocolError {
			gotGoAway = true
			break
		}
	}
	if !gotGoAway {
		t.Fatal("expected GOAWAY PROTOCOL_ERROR for even stream ID")
	}
}

// TestRobustness_UppercaseHeaders verifies rejection of uppercase header names.
func TestRobustness_UppercaseHeaders(t *testing.T) {
	_, addr, _ := startTestServer(t, robustnessHandler)
	rc := dialRawH2(t, addr)
	defer rc.close()

	// Encode headers with an uppercase header name.
	rc.enc.Reset()
	rc.enc.EncodeSingle([]byte(":method"), []byte("GET"), false)
	rc.enc.EncodeSingle([]byte(":path"), []byte("/"), false)
	rc.enc.EncodeSingle([]byte(":scheme"), []byte("https"), false)
	rc.enc.EncodeSingle([]byte("X-Custom"), []byte("value"), false) // uppercase!

	hb := make([]byte, len(rc.enc.Bytes()))
	copy(hb, rc.enc.Bytes())
	rc.fw.WriteHeaders(1, true, hb, nil)
	rc.fw.Flush()

	rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotRST := false
	for {
		f, err := rc.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == frame.FrameRSTStream && f.StreamID == 1 && f.ErrorCode == frame.ErrCodeProtocolError {
			gotRST = true
			break
		}
	}
	if !gotRST {
		t.Fatal("expected RST_STREAM PROTOCOL_ERROR for uppercase header name")
	}
}
