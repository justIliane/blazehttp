package http2

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blazehttp/blazehttp/pkg/bytespool"
	"github.com/blazehttp/blazehttp/pkg/flowcontrol"
	"github.com/blazehttp/blazehttp/pkg/frame"
	"github.com/blazehttp/blazehttp/pkg/hpack"
	"github.com/blazehttp/blazehttp/pkg/stream"
)

// clientPreface is the HTTP/2 connection preface that the client must send.
var clientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// writeItem represents a control frame to be written by the write loop.
type writeItem struct {
	typ writeType

	streamID    uint32
	increment   uint32
	errorCode   frame.ErrorCode
	lastStreamID uint32
	pingData    [8]byte
	debugData   []byte
}

type writeType uint8

const (
	writeSettingsACK  writeType = iota
	writeSettings
	writePing
	writeGoAway
	writeWindowUpdate
	writeRSTStream
)

// ConnConfig holds configuration for an HTTP/2 connection.
type ConnConfig struct {
	Handler    RequestHandler
	WorkerPool *WorkerPool
	Settings   ConnSettings

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	MaxRequestBodySize int
}

// Flood protection thresholds.
const (
	maxControlFramesPerWindow = 1000        // PING + SETTINGS + RST_STREAM
	controlFrameWindow        = 10 * time.Second
)

// serverConn represents a single HTTP/2 server-side connection.
type serverConn struct {
	conn net.Conn

	fr *frame.FrameReader
	fw *frame.FrameWriter

	enc *hpack.Encoder // used only in write goroutine
	dec *hpack.Decoder // used only in read goroutine

	streams *stream.Manager

	sendWin *flowcontrol.Window // connection-level send window
	recvWin *flowcontrol.Window // connection-level receive window

	localSettings ConnSettings
	peerSettings  ConnSettings

	controlCh  chan writeItem    // high-priority control frames
	responseCh chan *RequestCtx  // completed requests → write goroutine

	pendingMu sync.Mutex
	pending   map[uint32]*RequestCtx // streams awaiting DATA frames

	cfg        *ConnConfig
	remoteAddr net.Addr
	localAddr  net.Addr

	goingAway  atomic.Bool
	inFlight   atomic.Int32 // number of requests submitted to worker pool but not yet sent
	done       chan struct{}
	closeOnce  sync.Once

	// Flood protection (CVE-2023-44487, PING/SETTINGS/RST floods).
	controlFrameCount int
	controlFrameReset time.Time

	// Flow control: signaled when WINDOW_UPDATE or SETTINGS changes send window.
	sendWinNotify chan struct{}

	// completedStreams: writeLoop sends closed stream IDs here so the readLoop
	// can call CloseStream, keeping activeCount accurate for concurrency checks.
	completedStreams chan uint32
}

// ServeConn serves HTTP/2 on the given connection.
func ServeConn(conn net.Conn, cfg *ConnConfig) error {
	sc := &serverConn{
		conn:             conn,
		fr:               frame.AcquireFrameReader(conn),
		fw:               frame.AcquireFrameWriter(conn),
		enc:              hpack.AcquireEncoder(),
		dec:              hpack.AcquireDecoder(),
		streams:          stream.NewManager(cfg.Settings.MaxConcurrentStreams, int32(cfg.Settings.InitialWindowSize)),
		sendWin:          flowcontrol.NewWindow(int32(flowcontrol.DefaultInitialWindowSize)),
		recvWin:          flowcontrol.NewWindow(int32(cfg.Settings.InitialWindowSize)),
		localSettings:    cfg.Settings,
		peerSettings:     DefaultPeerSettings(),
		controlCh:        make(chan writeItem, 64),
		responseCh:       make(chan *RequestCtx, 256),
		pending:          make(map[uint32]*RequestCtx, 64),
		cfg:              cfg,
		remoteAddr:       conn.RemoteAddr(),
		localAddr:        conn.LocalAddr(),
		done:             make(chan struct{}),
		sendWinNotify:    make(chan struct{}, 1),
		completedStreams: make(chan uint32, 256),
	}

	defer sc.cleanup()

	// 1. Read client connection preface.
	if err := sc.readClientPreface(); err != nil {
		return err
	}

	// 3. Start write goroutine.
	var writeErr error
	var writeWg sync.WaitGroup
	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		writeErr = sc.writeLoop()
	}()

	// 4. Read loop (blocks until connection closes or error).
	readErr := sc.readLoop()

	// 5. Signal write loop to stop.
	close(sc.done)
	writeWg.Wait()

	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	return writeErr
}

func (sc *serverConn) readClientPreface() error {
	if sc.cfg.ReadTimeout > 0 {
		sc.conn.SetReadDeadline(time.Now().Add(sc.cfg.ReadTimeout))
	}

	var buf [24]byte
	if _, err := io.ReadFull(sc.conn, buf[:]); err != nil {
		return err
	}
	if string(buf[:]) != string(clientPreface) {
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "invalid client preface"}
	}

	// Client must send SETTINGS immediately after preface.
	f, err := sc.fr.ReadFrame()
	if err != nil {
		return err
	}
	if f.Type != frame.FrameSettings || f.Flags.Has(frame.FlagACK) {
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "first frame must be SETTINGS"}
	}

	if err := sc.applyPeerSettings(f); err != nil {
		return err
	}

	// Server connection preface: our SETTINGS frame MUST be the first frame
	// we send per RFC 9113 §3.4.
	settings := sc.localSettings.ToSettings()
	sc.fw.WriteSettings(settings...)

	// Then ACK the client's SETTINGS.
	sc.fw.WriteSettingsACK()

	// Increase connection-level receive window beyond the RFC default (65535).
	// The stream-level window is set via SETTINGS_INITIAL_WINDOW_SIZE,
	// but the connection-level window can only be increased via WINDOW_UPDATE on stream 0.
	connWindowBump := int32(sc.localSettings.InitialWindowSize) - int32(flowcontrol.DefaultInitialWindowSize)
	if connWindowBump > 0 {
		sc.fw.WriteWindowUpdate(0, uint32(connWindowBump))
		sc.recvWin.Update(connWindowBump)
	}

	return sc.fw.Flush()
}

func (sc *serverConn) readLoop() error {
	sc.controlFrameReset = time.Now()

	for {
		// Drain completed streams so activeCount stays accurate for concurrency checks.
		sc.drainCompletedStreams()

		if sc.cfg.IdleTimeout > 0 {
			sc.conn.SetReadDeadline(time.Now().Add(sc.cfg.IdleTimeout))
		}

		f, err := sc.fr.ReadFrame()
		if err != nil {
			if connErr, ok := err.(*frame.ConnError); ok {
				sc.goAway(connErr.Code, []byte(connErr.Reason))
			}
			return err
		}

		var handlerErr error
		switch f.Type {
		case frame.FrameHeaders:
			handlerErr = sc.handleHeaders(f)
		case frame.FrameData:
			handlerErr = sc.handleData(f)
		case frame.FrameSettings:
			handlerErr = sc.handleSettings(f)
		case frame.FramePing:
			handlerErr = sc.handlePing(f)
		case frame.FrameWindowUpdate:
			handlerErr = sc.handleWindowUpdate(f)
		case frame.FrameRSTStream:
			handlerErr = sc.handleRSTStream(f)
		case frame.FrameGoAway:
			sc.handleGoAway(f)
		case frame.FramePriority:
			sc.handlePriority(f)
		case frame.FramePushPromise:
			// Clients MUST NOT send PUSH_PROMISE per RFC 9113 §8.4.
			handlerErr = &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "client sent PUSH_PROMISE"}
		default:
			// Unknown frame types: ignore per RFC 9113 §4.1.
		}

		if handlerErr != nil {
			if connErr, ok := handlerErr.(*frame.ConnError); ok {
				sc.goAway(connErr.Code, []byte(connErr.Reason))
				// Give the write loop time to flush the GOAWAY frame.
				time.Sleep(5 * time.Millisecond)
			}
			return handlerErr
		}
	}
}


func (sc *serverConn) handleHeaders(f *frame.Frame) error {
	streamID := f.StreamID

	// Clients MUST use odd-numbered stream IDs per RFC 9113 §5.1.1.
	if streamID%2 == 0 {
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "client used even stream ID"}
	}

	// Decode HPACK.
	fields, err := sc.dec.Decode(f.HeaderBlock)
	if err != nil {
		return &frame.ConnError{Code: frame.ErrCodeCompressionError, Reason: "HPACK decode error"}
	}

	// Check if this is trailing headers on an existing stream.
	existingStream := sc.streams.GetStream(streamID)
	if existingStream != nil {
		state := existingStream.State()

		// Receiving HEADERS on a closed stream is a connection error per RFC 9113 §5.1.
		if state == stream.StateClosed {
			return &frame.ConnError{Code: frame.ErrCodeStreamClosed, Reason: "HEADERS on closed stream"}
		}

		// If the stream is half-closed(remote), the client already sent END_STREAM
		// and MUST NOT send more frames. Per RFC 9113 §5.1.
		if state == stream.StateHalfClosedRemote {
			sc.resetStream(streamID, frame.ErrCodeStreamClosed)
			return nil
		}
		if !f.HasEndStream() {
			sc.resetStream(streamID, frame.ErrCodeProtocolError)
			return nil
		}
		sc.pendingMu.Lock()
		ctx := sc.pending[streamID]
		delete(sc.pending, streamID)
		sc.pendingMu.Unlock()
		if ctx != nil {
			ctx.Request.setTrailers(fields)
			existingStream.Transition(stream.EventRecvEndStream)
			sc.submitToWorkerPool(ctx)
		}
		return nil
	}

	// Self-dependency check for HEADERS with PRIORITY per RFC 9113 §5.3.1.
	if f.HasPriority() && f.StreamDep == streamID {
		sc.resetStream(streamID, frame.ErrCodeProtocolError)
		return nil
	}

	// New stream.
	s, err := sc.streams.OpenStream(streamID)
	if err != nil {
		if err == stream.ErrMaxConcurrentStreams {
			sc.resetStream(streamID, frame.ErrCodeRefusedStream)
			return nil
		}
		// Stream ID regression means reuse of a closed stream ID.
		if err == stream.ErrStreamIDRegression {
			return &frame.ConnError{Code: frame.ErrCodeStreamClosed, Reason: "HEADERS on closed stream"}
		}
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: err.Error()}
	}

	// Transition idle → open.
	if err := s.Transition(stream.EventRecvHeaders); err != nil {
		sc.resetStream(streamID, frame.ErrCodeProtocolError)
		return nil
	}

	// Build request context.
	ctx := acquireCtx()
	ctx.streamID = streamID
	ctx.conn = sc
	ctx.remoteAddr = sc.remoteAddr
	ctx.localAddr = sc.localAddr
	ctx.Request.streamID = streamID

	if err := ctx.Request.FromHeaders(fields); err != nil {
		releaseCtx(ctx)
		sc.resetStream(streamID, frame.ErrCodeProtocolError)
		return nil
	}

	if f.HasEndStream() {
		// No body. Transition to half-closed(remote).
		s.Transition(stream.EventRecvEndStream)
		sc.submitToWorkerPool(ctx)
	} else {
		// Body will follow in DATA frames.
		sc.pendingMu.Lock()
		sc.pending[streamID] = ctx
		sc.pendingMu.Unlock()
	}

	return nil
}

func (sc *serverConn) handleData(f *frame.Frame) error {
	streamID := f.StreamID

	// DATA on an idle stream is a connection error per RFC 9113 §5.1.
	if sc.streams.IsIdle(streamID) {
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "DATA on idle stream"}
	}

	s := sc.streams.GetStream(streamID)
	if s == nil {
		// Stream was reset or closed. Still count against connection flow control
		// per RFC 9113 §5.1 (closed stream), then send STREAM_CLOSED.
		dataLen := int32(len(f.Data))
		if dataLen > 0 {
			sc.recvWin.Consume(dataLen)
		}
		sc.resetStream(streamID, frame.ErrCodeStreamClosed)
		return nil
	}

	// DATA on half-closed(remote) is a stream error per RFC 9113 §5.1.
	if s.State() == stream.StateHalfClosedRemote {
		sc.resetStream(streamID, frame.ErrCodeStreamClosed)
		return nil
	}

	dataLen := int32(len(f.Data))
	if dataLen > 0 {
		// Connection-level flow control.
		if !sc.recvWin.Consume(dataLen) {
			return &frame.ConnError{Code: frame.ErrCodeFlowControlError, Reason: "connection receive window exhausted"}
		}
		// Stream-level flow control.
		if !s.RecvWin.Consume(dataLen) {
			sc.resetStream(streamID, frame.ErrCodeFlowControlError)
			return nil
		}
	}

	sc.pendingMu.Lock()
	ctx := sc.pending[streamID]
	sc.pendingMu.Unlock()
	if ctx == nil {
		sc.resetStream(streamID, frame.ErrCodeStreamClosed)
		return nil
	}

	if len(f.Data) > 0 {
		ctx.Request.AppendBody(f.Data)
	}

	// Auto WINDOW_UPDATE.
	sc.maybeUpdateWindow(streamID, s, dataLen)

	if f.HasEndStream() {
		// Validate content-length if specified per RFC 9113 §8.1.1.
		if ctx.Request.contentLength >= 0 && int64(len(ctx.Request.body)) != ctx.Request.contentLength {
			sc.resetStream(streamID, frame.ErrCodeProtocolError)
			sc.pendingMu.Lock()
			delete(sc.pending, streamID)
			sc.pendingMu.Unlock()
			releaseCtx(ctx)
			return nil
		}
		s.Transition(stream.EventRecvEndStream)
		sc.pendingMu.Lock()
		delete(sc.pending, streamID)
		sc.pendingMu.Unlock()
		sc.submitToWorkerPool(ctx)
	}

	return nil
}

func (sc *serverConn) maybeUpdateWindow(streamID uint32, s *stream.Stream, consumed int32) {
	if consumed <= 0 {
		return
	}

	// Stream-level.
	threshold := int32(sc.localSettings.InitialWindowSize) / 2
	if s.RecvWin.Available() < threshold {
		increment := int32(sc.localSettings.InitialWindowSize) - s.RecvWin.Available()
		if increment > 0 {
			s.RecvWin.Update(increment)
			sc.enqueueControl(writeItem{
				typ:       writeWindowUpdate,
				streamID:  streamID,
				increment: uint32(increment),
			})
		}
	}

	// Connection-level.
	if sc.recvWin.Available() < threshold {
		increment := int32(sc.localSettings.InitialWindowSize) - sc.recvWin.Available()
		if increment > 0 {
			sc.recvWin.Update(increment)
			sc.enqueueControl(writeItem{
				typ:       writeWindowUpdate,
				streamID:  0,
				increment: uint32(increment),
			})
		}
	}
}

func (sc *serverConn) handleSettings(f *frame.Frame) error {
	if f.Flags.Has(frame.FlagACK) {
		// Our SETTINGS was acknowledged.
		return nil
	}
	if sc.checkControlFlood() {
		return &frame.ConnError{Code: frame.ErrCodeEnhanceYourCalm, Reason: "SETTINGS flood detected"}
	}
	if err := sc.applyPeerSettings(f); err != nil {
		return err
	}
	sc.enqueueControl(writeItem{typ: writeSettingsACK})
	return nil
}

func (sc *serverConn) applyPeerSettings(f *frame.Frame) error {
	oldWindowSize, err := sc.peerSettings.Apply(f.Settings, f.NumSettings)
	if err != nil {
		return err
	}

	// Update HPACK encoder table size.
	sc.enc.SetMaxDynamicTableSize(sc.peerSettings.HeaderTableSize)

	// Update frame writer max frame size.
	sc.fw.SetMaxFrameSize(sc.peerSettings.MaxFrameSize)

	// Adjust all existing stream send windows if INITIAL_WINDOW_SIZE changed.
	if sc.peerSettings.InitialWindowSize != oldWindowSize {
		if err := sc.streams.AdjustInitialWindowSize(int32(sc.peerSettings.InitialWindowSize)); err != nil {
			return err
		}
		sc.notifySendWin()
	}

	return nil
}

func (sc *serverConn) handlePing(f *frame.Frame) error {
	if f.Flags.Has(frame.FlagACK) {
		return nil
	}
	if sc.checkControlFlood() {
		return &frame.ConnError{Code: frame.ErrCodeEnhanceYourCalm, Reason: "PING flood detected"}
	}
	sc.enqueueControl(writeItem{
		typ:      writePing,
		pingData: f.PingData,
	})
	return nil
}

func (sc *serverConn) handleWindowUpdate(f *frame.Frame) error {
	increment := int32(f.WindowIncrement)

	if f.StreamID == 0 {
		// Connection-level WINDOW_UPDATE.
		if increment == 0 {
			return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "WINDOW_UPDATE increment 0 on connection"}
		}
		if err := sc.sendWin.Update(increment); err != nil {
			return &frame.ConnError{Code: frame.ErrCodeFlowControlError, Reason: "connection send window overflow"}
		}
		sc.notifySendWin()
		return nil
	}

	// Stream-level WINDOW_UPDATE on idle stream is a protocol error per RFC 9113 §5.1.
	if sc.streams.IsIdle(f.StreamID) {
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "WINDOW_UPDATE on idle stream"}
	}

	// Stream-level WINDOW_UPDATE with 0 increment is a stream error per RFC 9113 §6.9.
	if increment == 0 {
		sc.resetStream(f.StreamID, frame.ErrCodeProtocolError)
		return nil
	}

	s := sc.streams.GetStream(f.StreamID)
	if s == nil {
		// Closed stream — ignore.
		return nil
	}
	if err := s.SendWin.Update(increment); err != nil {
		sc.resetStream(f.StreamID, frame.ErrCodeFlowControlError)
		return nil
	}
	sc.notifySendWin()
	return nil
}

func (sc *serverConn) handleRSTStream(f *frame.Frame) error {
	// RST_STREAM on an idle stream is a connection error per RFC 9113 §5.1.
	if sc.streams.IsIdle(f.StreamID) {
		return &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "RST_STREAM on idle stream"}
	}

	// CVE-2023-44487: rapid reset attack detection.
	if sc.checkControlFlood() {
		return &frame.ConnError{Code: frame.ErrCodeEnhanceYourCalm, Reason: "rapid reset flood detected"}
	}

	s := sc.streams.GetStream(f.StreamID)
	if s != nil {
		s.Transition(stream.EventRecvRST)
	}
	sc.pendingMu.Lock()
	ctx := sc.pending[f.StreamID]
	delete(sc.pending, f.StreamID)
	sc.pendingMu.Unlock()
	if ctx != nil {
		releaseCtx(ctx)
	}
	sc.streams.CloseStream(f.StreamID)
	return nil
}

// drainCompletedStreams closes streams that the writeLoop has finished
// responding to, so that activeCount stays accurate.
func (sc *serverConn) drainCompletedStreams() {
	for {
		select {
		case id := <-sc.completedStreams:
			sc.streams.CloseStream(id)
		default:
			return
		}
	}
}

// notifySendWin signals the writeLoop that send window space is available.
func (sc *serverConn) notifySendWin() {
	select {
	case sc.sendWinNotify <- struct{}{}:
	default:
	}
}

func (sc *serverConn) handlePriority(f *frame.Frame) {
	// PRIORITY is deprecated in RFC 9113, but we must still validate:
	// self-dependency is a stream error per RFC 9113 §5.3.1.
	if f.StreamDep == f.StreamID {
		sc.resetStream(f.StreamID, frame.ErrCodeProtocolError)
	}
}

// checkControlFlood increments the control frame counter and returns true
// if the flood threshold has been exceeded.
func (sc *serverConn) checkControlFlood() bool {
	now := time.Now()
	if now.Sub(sc.controlFrameReset) > controlFrameWindow {
		sc.controlFrameCount = 0
		sc.controlFrameReset = now
	}
	sc.controlFrameCount++
	return sc.controlFrameCount > maxControlFramesPerWindow
}

func (sc *serverConn) handleGoAway(f *frame.Frame) {
	sc.streams.GoAway()
	sc.goingAway.Store(true)
}

// writeLoop runs in the write goroutine. It serializes all outgoing frames.
func (sc *serverConn) writeLoop() error {
	for {
		// Priority: control > response > done.
		select {
		case item := <-sc.controlCh:
			sc.writeControlFrame(item)
		default:
			select {
			case item := <-sc.controlCh:
				sc.writeControlFrame(item)
			case ctx := <-sc.responseCh:
				sc.sendResponse(ctx)
			case <-sc.done:
				sc.drainShutdown()
				return sc.fw.Flush()
			}
		}

		// Batch: drain any additional queued frames.
		sc.drainQueues()

		// Flush all buffered frames.
		if sc.fw.Buffered() > 0 {
			if sc.cfg.WriteTimeout > 0 {
				sc.conn.SetWriteDeadline(time.Now().Add(sc.cfg.WriteTimeout))
			}
			if err := sc.fw.Flush(); err != nil {
				return err
			}
		}
	}
}

func (sc *serverConn) writeControlFrame(item writeItem) {
	switch item.typ {
	case writeSettingsACK:
		sc.fw.WriteSettingsACK()
	case writeSettings:
		// Not used yet, but available.
	case writePing:
		sc.fw.WritePing(true, item.pingData)
	case writeGoAway:
		sc.fw.WriteGoAway(item.lastStreamID, item.errorCode, item.debugData)
	case writeWindowUpdate:
		sc.fw.WriteWindowUpdate(item.streamID, item.increment)
	case writeRSTStream:
		sc.fw.WriteRSTStream(item.streamID, item.errorCode)
	}
}

func (sc *serverConn) sendResponse(ctx *RequestCtx) {
	streamID := ctx.streamID

	s := sc.streams.GetStream(streamID)
	if s == nil {
		// Stream was reset while handler was running.
		sc.inFlight.Add(-1)
		releaseCtx(ctx)
		return
	}

	// Encode response headers (encoder is only used in this goroutine).
	headerBlock := ctx.Response.EncodeHeaders(sc.enc)

	// Copy headerBlock since encoder buffer is reused.
	hbCopy := bytespool.Get(len(headerBlock))[:len(headerBlock)]
	copy(hbCopy, headerBlock)

	body := ctx.Response.Body()
	endStream := len(body) == 0

	sc.fw.WriteHeaders(streamID, endStream, hbCopy, nil)

	if len(body) > 0 {
		sc.writeDataFrames(streamID, body, true)
	}

	bytespool.Put(hbCopy)

	// Transition: send END_STREAM → closes the stream from our side.
	s.Transition(stream.EventSendEndStream)

	// Notify readLoop to close the stream (keeps activeCount accurate for
	// concurrent stream limit enforcement).
	select {
	case sc.completedStreams <- streamID:
	case <-sc.done:
	}

	sc.inFlight.Add(-1)
	releaseCtx(ctx)
}

func (sc *serverConn) writeDataFrames(streamID uint32, data []byte, endStream bool) {
	maxFrameSize := int(sc.peerSettings.MaxFrameSize)
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	for len(data) > 0 {
		s := sc.streams.GetStream(streamID)
		if s == nil {
			break
		}

		chunk := len(data)
		if chunk > maxFrameSize {
			chunk = maxFrameSize
		}

		// Respect connection-level send window.
		connAvail := int(sc.sendWin.Available())
		if connAvail <= 0 {
			// Flow control blocked — flush pending frames and wait for WINDOW_UPDATE.
			if sc.fw.Buffered() > 0 {
				if err := sc.fw.Flush(); err != nil {
					return
				}
			}
			// Process control frames while waiting (includes WINDOW_UPDATE).
			if !sc.waitForSendWindow(timeout.C) {
				return
			}
			continue
		}
		if chunk > connAvail {
			chunk = connAvail
		}

		// Respect stream-level send window.
		streamAvail := int(s.SendWin.Available())
		if streamAvail <= 0 {
			// Flush and wait for stream-level WINDOW_UPDATE or SETTINGS change.
			if sc.fw.Buffered() > 0 {
				if err := sc.fw.Flush(); err != nil {
					return
				}
			}
			if !sc.waitForSendWindow(timeout.C) {
				return
			}
			continue
		}
		if chunk > streamAvail {
			chunk = streamAvail
		}

		isLast := chunk == len(data) && endStream
		sc.fw.WriteData(streamID, isLast, data[:chunk])

		sc.sendWin.Consume(int32(chunk))
		s.SendWin.Consume(int32(chunk))

		data = data[chunk:]
	}
}

// waitForSendWindow waits for a send window notification while processing
// control frames. Returns false if connection is closing or timed out.
func (sc *serverConn) waitForSendWindow(timeoutCh <-chan time.Time) bool {
	for {
		select {
		case <-sc.sendWinNotify:
			return true
		case item := <-sc.controlCh:
			sc.writeControlFrame(item)
			if sc.fw.Buffered() > 0 {
				if sc.cfg.WriteTimeout > 0 {
					sc.conn.SetWriteDeadline(time.Now().Add(sc.cfg.WriteTimeout))
				}
				sc.fw.Flush()
			}
		case <-sc.done:
			return false
		case <-timeoutCh:
			return false
		}
	}
}

func (sc *serverConn) drainQueues() {
	for {
		select {
		case item := <-sc.controlCh:
			sc.writeControlFrame(item)
		case ctx := <-sc.responseCh:
			sc.sendResponse(ctx)
		default:
			return
		}
	}
}

// drainShutdown drains both control and response channels, waiting
// for any in-flight handler responses that haven't been enqueued yet.
func (sc *serverConn) drainShutdown() {
	// First, drain anything already queued.
	sc.drainQueues()

	// If no in-flight requests, we're done.
	if sc.inFlight.Load() <= 0 {
		return
	}

	// Wait up to 5 seconds for in-flight responses from the worker pool.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	for sc.inFlight.Load() > 0 {
		select {
		case item := <-sc.controlCh:
			sc.writeControlFrame(item)
		case ctx := <-sc.responseCh:
			sc.sendResponse(ctx)
		case <-deadline.C:
			sc.drainQueues()
			return
		}
	}

	// Final drain.
	sc.drainQueues()
}


func (sc *serverConn) enqueueControl(item writeItem) {
	select {
	case sc.controlCh <- item:
	case <-sc.done:
	}
}

func (sc *serverConn) enqueueResponse(ctx *RequestCtx) {
	select {
	case sc.responseCh <- ctx:
	case <-sc.done:
		releaseCtx(ctx)
	}
}

func (sc *serverConn) resetStream(streamID uint32, code frame.ErrorCode) {
	sc.enqueueControl(writeItem{
		typ:       writeRSTStream,
		streamID:  streamID,
		errorCode: code,
	})
	sc.streams.CloseStream(streamID)
}

func (sc *serverConn) submitToWorkerPool(ctx *RequestCtx) {
	sc.inFlight.Add(1)
	if !sc.cfg.WorkerPool.Submit(ctx) {
		sc.inFlight.Add(-1)
		// Worker pool full — refuse the stream.
		sc.resetStream(ctx.streamID, frame.ErrCodeRefusedStream)
		releaseCtx(ctx)
	}
}

func (sc *serverConn) goAway(code frame.ErrorCode, debugData []byte) {
	if sc.goingAway.Swap(true) {
		return
	}
	sc.streams.GoAway()
	lastStreamID := sc.streams.LastClientStreamID()
	sc.enqueueControl(writeItem{
		typ:          writeGoAway,
		lastStreamID: lastStreamID,
		errorCode:    code,
		debugData:    debugData,
	})
}

func (sc *serverConn) cleanup() {
	sc.closeOnce.Do(func() {
		sc.conn.Close()
		frame.ReleaseFrameReader(sc.fr)
		// Note: fw is released in writeLoop defer, but also safe to skip
		// if writeLoop hasn't started. We check Buffered to decide.
		hpack.ReleaseEncoder(sc.enc)
		hpack.ReleaseDecoder(sc.dec)

		// Release all pending contexts.
		sc.pendingMu.Lock()
		for id, ctx := range sc.pending {
			delete(sc.pending, id)
			releaseCtx(ctx)
		}
		sc.pendingMu.Unlock()

		sc.streams.Reset()
	})
}
