// Package client provides an HTTP/2 client with TLS and HTTP/2 fingerprinting.
// It reuses the same frame, hpack, flowcontrol, and stream packages as the server.
package client

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blazehttp/blazehttp/client/h2fingerprint"
	blazetls "github.com/blazehttp/blazehttp/client/tls"
	"github.com/blazehttp/blazehttp/pkg/flowcontrol"
	"github.com/blazehttp/blazehttp/pkg/frame"
	"github.com/blazehttp/blazehttp/pkg/hpack"
	"github.com/blazehttp/blazehttp/pkg/stream"
)

// HTTP/2 connection preface sent by the client.
var clientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// Errors returned by ClientConn.
var (
	ErrConnClosed  = errors.New("client: connection closed")
	ErrGoAway      = errors.New("client: server sent GOAWAY")
	ErrStreamReset = errors.New("client: stream reset by server")
	ErrNotH2       = errors.New("client: server did not negotiate h2")
)

// Header is a name-value pair for HTTP headers.
type Header struct {
	Name  string
	Value string
}

// h2Request holds a low-level HTTP/2 request to send.
type h2Request struct {
	Method    string
	Authority string // :authority pseudo-header (host:port)
	Scheme    string // "https" or "http"
	Path      string // request path (e.g. "/")
	Headers   []Header
	Body      []byte
}

// h2Response holds a low-level HTTP/2 response received from the server.
type h2Response struct {
	StatusCode int
	Headers    []Header
	Body       []byte
}

// responseWaiter bridges readLoop → RoundTrip.
type responseWaiter struct {
	resp     *h2Response
	err      error
	done     chan struct{}
	closeOnce sync.Once
}

// signal safely closes the done channel exactly once.
func (w *responseWaiter) signal() {
	w.closeOnce.Do(func() { close(w.done) })
}

// roundTripRequest is sent from RoundTrip → writeLoop.
type roundTripRequest struct {
	req    *h2Request
	waiter *responseWaiter
}

// writeItem represents a control frame to be written by the write loop.
type writeItem struct {
	typ          writeType
	streamID     uint32
	increment    uint32
	errorCode    frame.ErrorCode
	lastStreamID uint32
	pingData     [8]byte
}

type writeType uint8

const (
	writeSettingsACK writeType = iota
	writePingACK  // PING response (ack=true)
	writePingReq  // PING request (ack=false)
	writeGoAway
	writeWindowUpdate
	writeRSTStream
)

// ClientConn is a single HTTP/2 client connection.
type ClientConn struct {
	rawConn net.Conn

	fr  *frame.FrameReader  // read goroutine only
	fw  *frame.FrameWriter  // write goroutine only
	enc *hpack.Encoder      // write goroutine only
	dec *hpack.Decoder      // read goroutine only

	streams *stream.Manager
	sendWin *flowcontrol.Window // connection-level send window
	recvWin *flowcontrol.Window // connection-level receive window

	h2Profile          *h2fingerprint.H2Profile
	clientInitialWin   int32 // our INITIAL_WINDOW_SIZE for stream recv
	settingsMu         sync.RWMutex
	peerSettings       peerSettings

	controlCh     chan writeItem
	requestCh     chan roundTripRequest
	sendWinNotify chan struct{}
	done          chan struct{}

	nextStreamID uint32 // always odd, starts at 1
	mu           sync.Mutex
	pending      map[uint32]*responseWaiter

	goingAway   atomic.Bool
	closeOnce   sync.Once
	cleanupOnce sync.Once

	writeWg sync.WaitGroup
	readWg  sync.WaitGroup
}

// Dial establishes an HTTP/2 connection to addr (host:port) using the given
// TLS dialer and HTTP/2 fingerprint profile.
func Dial(addr string, tlsDialer *blazetls.TLSDialer, profile *h2fingerprint.H2Profile) (*ClientConn, error) {
	conn, err := tlsDialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	if blazetls.NegotiatedProtocol(conn) != "h2" {
		conn.Close()
		return nil, ErrNotH2
	}

	return newClientConn(conn, profile)
}

// newClientConn wraps an already-established net.Conn (which must have
// negotiated h2) into a ClientConn.  This is also used for proxy tunnels
// where the TLS handshake happens over an existing connection.
func newClientConn(conn net.Conn, profile *h2fingerprint.H2Profile) (*ClientConn, error) {
	ps := defaultPeerSettings()

	// Extract our own INITIAL_WINDOW_SIZE for stream receive windows.
	clientInitialWin := int32(flowcontrol.DefaultInitialWindowSize)
	for _, s := range profile.Settings {
		if s.ID == frame.SettingsInitialWindowSize {
			clientInitialWin = int32(s.Value)
			break
		}
	}

	cc := &ClientConn{
		rawConn:          conn,
		fr:               frame.AcquireFrameReader(conn),
		fw:               frame.AcquireFrameWriter(conn),
		enc:              hpack.AcquireEncoder(),
		dec:              hpack.AcquireDecoder(),
		streams:          stream.NewManager(ps.MaxConcurrentStreams, int32(ps.InitialWindowSize)),
		sendWin:          flowcontrol.NewWindow(int32(flowcontrol.DefaultInitialWindowSize)),
		recvWin:          flowcontrol.NewWindow(int32(flowcontrol.DefaultInitialWindowSize)),
		h2Profile:        profile,
		clientInitialWin: clientInitialWin,
		peerSettings:     ps,
		controlCh:     make(chan writeItem, 64),
		requestCh:     make(chan roundTripRequest, 256),
		sendWinNotify: make(chan struct{}, 1),
		done:          make(chan struct{}),
		nextStreamID:  1,
		pending:       make(map[uint32]*responseWaiter, 64),
	}

	if err := cc.handshake(); err != nil {
		cc.cleanup()
		return nil, err
	}

	cc.writeWg.Add(1)
	go func() {
		defer cc.writeWg.Done()
		cc.writeLoop()
	}()
	cc.readWg.Add(1)
	go cc.readLoop()

	return cc, nil
}

// roundTrip sends a request and returns the response.
// It is safe for concurrent use.
func (cc *ClientConn) roundTrip(req *h2Request) (*h2Response, error) {
	if cc.goingAway.Load() {
		return nil, ErrGoAway
	}

	waiter := &responseWaiter{done: make(chan struct{})}
	rtr := roundTripRequest{
		req:    req,
		waiter: waiter,
	}

	// Send to writeLoop — stream ID allocation happens there to ensure ordering.
	select {
	case cc.requestCh <- rtr:
	case <-cc.done:
		return nil, ErrConnClosed
	}

	// Wait for response.
	select {
	case <-waiter.done:
		return waiter.resp, waiter.err
	case <-cc.done:
		// Connection closed. Check if the waiter was already signaled
		// (happens-before on waiter.done guarantees safe err read).
		select {
		case <-waiter.done:
			return waiter.resp, waiter.err
		default:
		}
		return nil, ErrConnClosed
	}
}

// Close gracefully closes the connection.
func (cc *ClientConn) Close() error {
	cc.closeOnce.Do(func() {
		close(cc.done)
	})
	// Close the connection first to unblock readLoop (blocked on ReadFrame).
	err := cc.rawConn.Close()
	// Wait for both goroutines to finish before releasing pooled resources.
	cc.writeWg.Wait()
	cc.readWg.Wait()
	cc.signalAllPending(ErrConnClosed)
	cc.cleanupOnce.Do(cc.cleanup)
	return err
}

// handshake performs the HTTP/2 client connection preface.
func (cc *ClientConn) handshake() error {
	// 1. Send connection preface magic.
	if _, err := cc.rawConn.Write(clientPreface); err != nil {
		return err
	}

	// 2. Send SETTINGS from H2Profile (exact order).
	cc.fw.WriteSettings(cc.h2Profile.Settings...)

	// 3. Send WINDOW_UPDATE on stream 0 if profile requires it.
	if cc.h2Profile.ConnectionWindowUpdate > 0 {
		cc.fw.WriteWindowUpdate(0, cc.h2Profile.ConnectionWindowUpdate)
		// Update our receive window to match.
		cc.recvWin.Update(int32(cc.h2Profile.ConnectionWindowUpdate))
	}

	// 4. Send PRIORITY frames from profile.
	for _, p := range cc.h2Profile.PriorityFrames {
		cc.fw.WritePriority(p.StreamID, frame.PriorityParam{
			StreamDep: p.Dep,
			Weight:    p.Weight,
			Exclusive: p.Exclusive,
		})
	}

	if err := cc.fw.Flush(); err != nil {
		return err
	}

	// 5. Read server's SETTINGS frame.
	f, err := cc.fr.ReadFrame()
	if err != nil {
		return err
	}
	if f.Type != frame.FrameSettings || f.Flags.Has(frame.FlagACK) {
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "expected SETTINGS from server"}
	}

	if err := cc.applyPeerSettings(f); err != nil {
		return err
	}

	// 6. Send SETTINGS ACK.
	cc.fw.WriteSettingsACK()
	return cc.fw.Flush()
}

// readLoop reads frames from the server and dispatches them.
func (cc *ClientConn) readLoop() {
	defer cc.readWg.Done()
	defer func() {
		// If readLoop exits before Close() is called (e.g., server disconnect),
		// signal done so writeLoop and pending RoundTrips know.
		cc.closeOnce.Do(func() { close(cc.done) })
		cc.signalAllPending(ErrConnClosed)
	}()

	for {
		f, err := cc.fr.ReadFrame()
		if err != nil {
			if connErr, ok := err.(*frame.ConnError); ok {
				cc.enqueueControl(writeItem{
					typ:          writeGoAway,
					lastStreamID: cc.streams.LastClientStreamID(),
					errorCode:    connErr.Code,
				})
			}
			return
		}

		var handlerErr error
		switch f.Type {
		case frame.FrameHeaders:
			handlerErr = cc.handleHeaders(f)
		case frame.FrameData:
			handlerErr = cc.handleData(f)
		case frame.FrameSettings:
			handlerErr = cc.handleSettings(f)
		case frame.FramePing:
			handlerErr = cc.handlePing(f)
		case frame.FrameWindowUpdate:
			handlerErr = cc.handleWindowUpdate(f)
		case frame.FrameRSTStream:
			cc.handleRSTStream(f)
		case frame.FrameGoAway:
			cc.handleGoAway(f)
		case frame.FramePushPromise:
			// Client never enables push; ignore.
		default:
			// Unknown frame types: ignore per RFC 9113 §4.1.
		}

		if handlerErr != nil {
			if connErr, ok := handlerErr.(*frame.ConnError); ok {
				cc.enqueueControl(writeItem{
					typ:          writeGoAway,
					lastStreamID: cc.streams.LastClientStreamID(),
					errorCode:    connErr.Code,
				})
				time.Sleep(5 * time.Millisecond)
			}
			return
		}
	}
}

// handleHeaders processes a HEADERS frame (response headers).
func (cc *ClientConn) handleHeaders(f *frame.Frame) error {
	streamID := f.StreamID

	fields, err := cc.dec.Decode(f.HeaderBlock)
	if err != nil {
		return &frame.ConnError{Code: frame.ErrCodeCompressionError, Reason: "HPACK decode error"}
	}

	s := cc.streams.GetStream(streamID)
	if s == nil {
		// Ignore headers for unknown/closed streams.
		return nil
	}

	// Transition: open → half-closed(remote) will happen when END_STREAM is set.
	if err := s.Transition(stream.EventRecvHeaders); err != nil {
		// Already have headers (trailing headers) — ignore transition error.
	}

	// Parse response.
	resp := &h2Response{}
	for _, field := range fields {
		name := string(field.Name)
		value := string(field.Value)
		if name == ":status" {
			resp.StatusCode, _ = strconv.Atoi(value)
		} else if !strings.HasPrefix(name, ":") {
			resp.Headers = append(resp.Headers, Header{Name: name, Value: value})
		}
	}

	cc.mu.Lock()
	waiter := cc.pending[streamID]
	cc.mu.Unlock()

	if waiter == nil {
		return nil
	}

	if f.HasEndStream() {
		s.Transition(stream.EventRecvEndStream)
		waiter.resp = resp
		waiter.signal()
		cc.mu.Lock()
		delete(cc.pending, streamID)
		cc.mu.Unlock()
		cc.streams.CloseStream(streamID)
	} else {
		// Store partial response; body will follow in DATA frames.
		waiter.resp = resp
	}

	return nil
}

// handleData processes a DATA frame (response body).
func (cc *ClientConn) handleData(f *frame.Frame) error {
	streamID := f.StreamID

	s := cc.streams.GetStream(streamID)
	if s == nil {
		// Count against connection flow control even for closed streams.
		dataLen := int32(len(f.Data))
		if dataLen > 0 {
			cc.recvWin.Consume(dataLen)
		}
		return nil
	}

	dataLen := int32(len(f.Data))
	if dataLen > 0 {
		// Connection-level flow control.
		if !cc.recvWin.Consume(dataLen) {
			return &frame.ConnError{Code: frame.ErrCodeFlowControlError, Reason: "connection receive window exhausted"}
		}
		// Stream-level flow control.
		if !s.RecvWin.Consume(dataLen) {
			cc.enqueueControl(writeItem{
				typ:       writeRSTStream,
				streamID:  streamID,
				errorCode: frame.ErrCodeFlowControlError,
			})
			return nil
		}
	}

	cc.mu.Lock()
	waiter := cc.pending[streamID]
	cc.mu.Unlock()

	if waiter != nil && waiter.resp != nil && len(f.Data) > 0 {
		waiter.resp.Body = append(waiter.resp.Body, f.Data...)
	}

	// Auto WINDOW_UPDATE.
	cc.maybeUpdateWindow(streamID, s, dataLen)

	if f.HasEndStream() {
		s.Transition(stream.EventRecvEndStream)
		if waiter != nil {
			waiter.signal()
			cc.mu.Lock()
			delete(cc.pending, streamID)
			cc.mu.Unlock()
		}
		cc.streams.CloseStream(streamID)
	}

	return nil
}

// maybeUpdateWindow sends WINDOW_UPDATE if the receive window drops below threshold.
func (cc *ClientConn) maybeUpdateWindow(streamID uint32, s *stream.Stream, consumed int32) {
	if consumed <= 0 {
		return
	}

	// Use our own initial window size for receive window thresholds.
	initialWin := cc.clientInitialWin
	if initialWin == 0 {
		initialWin = int32(flowcontrol.DefaultInitialWindowSize)
	}
	threshold := initialWin / 2

	// Stream-level.
	if s.RecvWin.Available() < threshold {
		increment := initialWin - s.RecvWin.Available()
		if increment > 0 {
			s.RecvWin.Update(increment)
			cc.enqueueControl(writeItem{
				typ:       writeWindowUpdate,
				streamID:  streamID,
				increment: uint32(increment),
			})
		}
	}

	// Connection-level.
	if cc.recvWin.Available() < threshold {
		increment := initialWin - cc.recvWin.Available()
		if increment > 0 {
			cc.recvWin.Update(increment)
			cc.enqueueControl(writeItem{
				typ:       writeWindowUpdate,
				streamID:  0,
				increment: uint32(increment),
			})
		}
	}
}

// handleSettings processes a SETTINGS frame from the server.
func (cc *ClientConn) handleSettings(f *frame.Frame) error {
	if f.Flags.Has(frame.FlagACK) {
		return nil
	}
	if err := cc.applyPeerSettings(f); err != nil {
		return err
	}
	cc.enqueueControl(writeItem{typ: writeSettingsACK})
	return nil
}

// handlePing processes a PING frame.
func (cc *ClientConn) handlePing(f *frame.Frame) error {
	if f.Flags.Has(frame.FlagACK) {
		// PING ACK — keepalive confirmed.
		return nil
	}
	cc.enqueueControl(writeItem{
		typ:      writePingACK,
		pingData: f.PingData,
	})
	return nil
}

// handleWindowUpdate processes a WINDOW_UPDATE frame.
func (cc *ClientConn) handleWindowUpdate(f *frame.Frame) error {
	increment := int32(f.WindowIncrement)

	if f.StreamID == 0 {
		if increment == 0 {
			return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "WINDOW_UPDATE increment 0"}
		}
		if err := cc.sendWin.Update(increment); err != nil {
			return &frame.ConnError{Code: frame.ErrCodeFlowControlError, Reason: "connection send window overflow"}
		}
		cc.notifySendWin()
		return nil
	}

	if increment == 0 {
		cc.enqueueControl(writeItem{
			typ:       writeRSTStream,
			streamID:  f.StreamID,
			errorCode: frame.ErrCodeProtocolError,
		})
		return nil
	}

	s := cc.streams.GetStream(f.StreamID)
	if s == nil {
		return nil // closed stream, ignore
	}
	if err := s.SendWin.Update(increment); err != nil {
		cc.enqueueControl(writeItem{
			typ:       writeRSTStream,
			streamID:  f.StreamID,
			errorCode: frame.ErrCodeFlowControlError,
		})
		return nil
	}
	cc.notifySendWin()
	return nil
}

// handleRSTStream processes a RST_STREAM frame.
func (cc *ClientConn) handleRSTStream(f *frame.Frame) {
	streamID := f.StreamID

	s := cc.streams.GetStream(streamID)
	if s != nil {
		s.Transition(stream.EventRecvRST)
	}

	cc.mu.Lock()
	waiter := cc.pending[streamID]
	delete(cc.pending, streamID)
	cc.mu.Unlock()

	if waiter != nil {
		waiter.err = fmt.Errorf("%w: %s", ErrStreamReset, f.ErrorCode)
		waiter.signal()
	}
	cc.streams.CloseStream(streamID)
}

// handleGoAway processes a GOAWAY frame.
func (cc *ClientConn) handleGoAway(f *frame.Frame) {
	cc.goingAway.Store(true)
	cc.streams.GoAway()

	// Signal all pending waiters for streams above lastStreamID.
	cc.mu.Lock()
	for id, waiter := range cc.pending {
		if id > f.LastStreamID {
			waiter.err = ErrGoAway
			waiter.signal()
			delete(cc.pending, id)
		}
	}
	cc.mu.Unlock()
}

// applyPeerSettings applies the server's SETTINGS.
func (cc *ClientConn) applyPeerSettings(f *frame.Frame) error {
	cc.settingsMu.Lock()
	oldWindowSize, err := cc.peerSettings.apply(f.Settings, f.NumSettings)
	if err != nil {
		cc.settingsMu.Unlock()
		return err
	}
	headerTableSize := cc.peerSettings.HeaderTableSize
	maxFrameSize := cc.peerSettings.MaxFrameSize
	maxConcurrent := cc.peerSettings.MaxConcurrentStreams
	newWindowSize := cc.peerSettings.InitialWindowSize
	cc.settingsMu.Unlock()

	// Update HPACK encoder table size.
	cc.enc.SetMaxDynamicTableSize(headerTableSize)

	// Update frame writer max frame size.
	cc.fw.SetMaxFrameSize(maxFrameSize)

	// Update stream manager max concurrent.
	cc.streams.SetMaxConcurrent(maxConcurrent)

	// Adjust stream send windows if INITIAL_WINDOW_SIZE changed.
	if newWindowSize != oldWindowSize {
		if err := cc.streams.AdjustInitialWindowSize(int32(newWindowSize)); err != nil {
			return err
		}
		cc.notifySendWin()
	}

	return nil
}

// writeLoop serializes all outgoing frames.
func (cc *ClientConn) writeLoop() {
	for {
		// Priority: control > requests > done.
		select {
		case item := <-cc.controlCh:
			cc.writeControlFrame(item)
		default:
			select {
			case item := <-cc.controlCh:
				cc.writeControlFrame(item)
			case rtr := <-cc.requestCh:
				cc.writeRequest(rtr)
			case <-cc.done:
				cc.drainShutdown()
				cc.fw.Flush()
				return
			}
		}

		// Batch drain.
		cc.drainQueues()

		// Flush.
		if cc.fw.Buffered() > 0 {
			if err := cc.fw.Flush(); err != nil {
				return
			}
		}
	}
}

// writeControlFrame writes a single control frame.
func (cc *ClientConn) writeControlFrame(item writeItem) {
	switch item.typ {
	case writeSettingsACK:
		cc.fw.WriteSettingsACK()
	case writePingACK:
		cc.fw.WritePing(true, item.pingData)
	case writePingReq:
		cc.fw.WritePing(false, item.pingData)
	case writeGoAway:
		cc.fw.WriteGoAway(item.lastStreamID, item.errorCode, nil)
	case writeWindowUpdate:
		cc.fw.WriteWindowUpdate(item.streamID, item.increment)
	case writeRSTStream:
		cc.fw.WriteRSTStream(item.streamID, item.errorCode)
	}
}

// writeRequest encodes and sends a request on the connection.
func (cc *ClientConn) writeRequest(rtr roundTripRequest) {
	req := rtr.req

	// Allocate stream ID in the writeLoop to guarantee monotonic ordering.
	cc.mu.Lock()
	streamID := cc.nextStreamID
	cc.nextStreamID += 2
	cc.pending[streamID] = rtr.waiter
	cc.mu.Unlock()

	// Open stream.
	s, err := cc.streams.OpenStream(streamID)
	if err != nil {
		rtr.waiter.err = err
		rtr.waiter.signal()
		cc.mu.Lock()
		delete(cc.pending, streamID)
		cc.mu.Unlock()
		return
	}

	// The stream manager initializes both SendWin and RecvWin to the server's
	// INITIAL_WINDOW_SIZE. SendWin is correct (controls how much we can send),
	// but RecvWin should use OUR initial window size (controls how much the
	// server can send to us).
	s.RecvWin.Reset(cc.clientInitialWin)

	// Transition idle → open.
	s.Transition(stream.EventSendHeaders)

	// Encode headers in profile order.
	headerBlock := cc.encodeHeaders(req)

	endStream := len(req.Body) == 0
	cc.fw.WriteHeaders(streamID, endStream, headerBlock, nil)

	if endStream {
		s.Transition(stream.EventSendEndStream)
	}

	if len(req.Body) > 0 {
		cc.writeDataFrames(streamID, s, req.Body)
		s.Transition(stream.EventSendEndStream)
	}
}

// encodeHeaders encodes request headers using HPACK in the profile's order.
func (cc *ClientConn) encodeHeaders(req *h2Request) []byte {
	cc.enc.Reset()

	// Build the set of user-supplied header names for dedup.
	userHeaders := make(map[string]string, len(req.Headers))
	for _, h := range req.Headers {
		userHeaders[strings.ToLower(h.Name)] = h.Value
	}

	// 1. Pseudo-headers in profile order.
	for _, ph := range cc.h2Profile.PseudoHeaderOrder {
		var val string
		switch ph {
		case ":method":
			val = req.Method
		case ":authority":
			val = req.Authority
		case ":scheme":
			val = req.Scheme
		case ":path":
			val = req.Path
		}
		if val != "" {
			cc.enc.EncodeSingle([]byte(ph), []byte(val), false)
		}
	}

	// 2. Build ordered regular headers.
	// Start with headers in profile order, then append any remaining.
	emitted := make(map[string]bool, len(cc.h2Profile.HeaderOrder))

	// Add default headers from profile if not overridden.
	allHeaders := make(map[string]string, len(cc.h2Profile.DefaultHeaders)+len(req.Headers))
	for _, dh := range cc.h2Profile.DefaultHeaders {
		allHeaders[dh.Name] = dh.Value
	}
	// User headers override defaults.
	for _, h := range req.Headers {
		allHeaders[strings.ToLower(h.Name)] = h.Value
	}

	// Emit in profile header order.
	for _, name := range cc.h2Profile.HeaderOrder {
		if val, ok := allHeaders[name]; ok {
			cc.enc.EncodeSingle([]byte(name), []byte(val), isSensitiveHeader(name))
			emitted[name] = true
		}
	}

	// Emit any remaining headers not in profile order.
	for _, h := range req.Headers {
		name := strings.ToLower(h.Name)
		if !emitted[name] {
			cc.enc.EncodeSingle([]byte(name), []byte(h.Value), isSensitiveHeader(name))
			emitted[name] = true
		}
	}
	for _, dh := range cc.h2Profile.DefaultHeaders {
		if !emitted[dh.Name] {
			cc.enc.EncodeSingle([]byte(dh.Name), []byte(dh.Value), isSensitiveHeader(dh.Name))
			emitted[dh.Name] = true
		}
	}

	return cc.enc.Bytes()
}

// isSensitiveHeader returns true for headers that should never be indexed.
func isSensitiveHeader(name string) bool {
	switch name {
	case "authorization", "cookie", "proxy-authorization", "set-cookie":
		return true
	}
	return false
}

// writeDataFrames sends DATA frames with flow control.
func (cc *ClientConn) writeDataFrames(streamID uint32, s *stream.Stream, data []byte) {
	cc.settingsMu.RLock()
	maxFrameSize := int(cc.peerSettings.MaxFrameSize)
	cc.settingsMu.RUnlock()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for len(data) > 0 {
		if s.IsClosed() {
			break
		}

		chunk := len(data)
		if chunk > maxFrameSize {
			chunk = maxFrameSize
		}

		// Connection-level send window.
		connAvail := int(cc.sendWin.Available())
		if connAvail <= 0 {
			if cc.fw.Buffered() > 0 {
				cc.fw.Flush()
			}
			if !cc.waitForSendWindow(timeout.C) {
				return
			}
			continue
		}
		if chunk > connAvail {
			chunk = connAvail
		}

		// Stream-level send window.
		streamAvail := int(s.SendWin.Available())
		if streamAvail <= 0 {
			if cc.fw.Buffered() > 0 {
				cc.fw.Flush()
			}
			if !cc.waitForSendWindow(timeout.C) {
				return
			}
			continue
		}
		if chunk > streamAvail {
			chunk = streamAvail
		}

		isLast := chunk == len(data)
		cc.fw.WriteData(streamID, isLast, data[:chunk])

		cc.sendWin.Consume(int32(chunk))
		s.SendWin.Consume(int32(chunk))

		data = data[chunk:]
	}
}

// waitForSendWindow waits for a WINDOW_UPDATE notification while processing control frames.
func (cc *ClientConn) waitForSendWindow(timeoutCh <-chan time.Time) bool {
	for {
		select {
		case <-cc.sendWinNotify:
			return true
		case item := <-cc.controlCh:
			cc.writeControlFrame(item)
			if cc.fw.Buffered() > 0 {
				cc.fw.Flush()
			}
		case <-cc.done:
			return false
		case <-timeoutCh:
			return false
		}
	}
}

// Ping sends a PING frame and does not wait for the response.
func (cc *ClientConn) Ping() {
	var data [8]byte
	data[0] = 0x42 // arbitrary payload
	data[1] = 0x4C
	data[2] = 0x41
	data[3] = 0x5A
	data[4] = 0x45 // "BLAZE"
	select {
	case cc.controlCh <- writeItem{typ: writePingReq, pingData: data}:
	case <-cc.done:
	}
}

// enqueueControl sends a control frame to the writeLoop.
func (cc *ClientConn) enqueueControl(item writeItem) {
	select {
	case cc.controlCh <- item:
	case <-cc.done:
	}
}

// notifySendWin signals the writeLoop that send window space is available.
func (cc *ClientConn) notifySendWin() {
	select {
	case cc.sendWinNotify <- struct{}{}:
	default:
	}
}

// drainQueues processes any additional queued control frames and requests.
func (cc *ClientConn) drainQueues() {
	for {
		select {
		case item := <-cc.controlCh:
			cc.writeControlFrame(item)
		case rtr := <-cc.requestCh:
			cc.writeRequest(rtr)
		default:
			return
		}
	}
}

// drainShutdown drains remaining control frames on shutdown.
func (cc *ClientConn) drainShutdown() {
	for {
		select {
		case item := <-cc.controlCh:
			cc.writeControlFrame(item)
		default:
			return
		}
	}
}

// signalAllPending signals all pending response waiters with an error.
func (cc *ClientConn) signalAllPending(err error) {
	cc.mu.Lock()
	for id, waiter := range cc.pending {
		waiter.err = err
		waiter.signal()
		delete(cc.pending, id)
	}
	cc.mu.Unlock()
}

// cleanup releases pooled resources.
func (cc *ClientConn) cleanup() {
	if cc.fr != nil {
		frame.ReleaseFrameReader(cc.fr)
		cc.fr = nil
	}
	if cc.fw != nil {
		frame.ReleaseFrameWriter(cc.fw)
		cc.fw = nil
	}
	if cc.enc != nil {
		hpack.ReleaseEncoder(cc.enc)
		cc.enc = nil
	}
	if cc.dec != nil {
		hpack.ReleaseDecoder(cc.dec)
		cc.dec = nil
	}
	if cc.streams != nil {
		cc.streams.Reset()
	}
}

// GoingAway reports whether the server has sent GOAWAY.
func (cc *ClientConn) GoingAway() bool {
	return cc.goingAway.Load()
}

// ActiveStreams returns the number of active streams.
func (cc *ClientConn) ActiveStreams() int {
	return cc.streams.ActiveCount()
}

// IsClosed reports whether the connection is closed.
func (cc *ClientConn) IsClosed() bool {
	select {
	case <-cc.done:
		return true
	default:
		return false
	}
}

// PeerSettings returns the server's current settings.
func (cc *ClientConn) PeerSettings() peerSettings {
	cc.settingsMu.RLock()
	ps := cc.peerSettings
	cc.settingsMu.RUnlock()
	return ps
}
