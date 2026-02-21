package stream

import (
	"sync"
	"testing"

	"github.com/blazehttp/blazehttp/pkg/frame"
)

func newTestStream(id uint32) *Stream {
	s := &Stream{}
	s.id.Store(id)
	return s
}

// ====================== STATE MACHINE TESTS ======================

func TestTransition_ValidTransitions(t *testing.T) {
	tests := []struct {
		name  string
		from  State
		event Event
		to    State
	}{
		// From idle.
		{"idle+sendHeaders→open", StateIdle, EventSendHeaders, StateOpen},
		{"idle+recvHeaders→open", StateIdle, EventRecvHeaders, StateOpen},
		{"idle+sendPush→reservedLocal", StateIdle, EventSendPush, StateReservedLocal},
		{"idle+recvPush→reservedRemote", StateIdle, EventRecvPush, StateReservedRemote},

		// From open.
		{"open+sendEndStream→halfClosedLocal", StateOpen, EventSendEndStream, StateHalfClosedLocal},
		{"open+recvEndStream→halfClosedRemote", StateOpen, EventRecvEndStream, StateHalfClosedRemote},
		{"open+sendRST→closed", StateOpen, EventSendRST, StateClosed},
		{"open+recvRST→closed", StateOpen, EventRecvRST, StateClosed},

		// From reserved(local).
		{"reservedLocal+sendHeaders→halfClosedRemote", StateReservedLocal, EventSendHeaders, StateHalfClosedRemote},
		{"reservedLocal+sendRST→closed", StateReservedLocal, EventSendRST, StateClosed},
		{"reservedLocal+recvRST→closed", StateReservedLocal, EventRecvRST, StateClosed},

		// From reserved(remote).
		{"reservedRemote+recvHeaders→halfClosedLocal", StateReservedRemote, EventRecvHeaders, StateHalfClosedLocal},
		{"reservedRemote+sendRST→closed", StateReservedRemote, EventSendRST, StateClosed},
		{"reservedRemote+recvRST→closed", StateReservedRemote, EventRecvRST, StateClosed},

		// From half-closed(local).
		{"halfClosedLocal+recvEndStream→closed", StateHalfClosedLocal, EventRecvEndStream, StateClosed},
		{"halfClosedLocal+sendRST→closed", StateHalfClosedLocal, EventSendRST, StateClosed},
		{"halfClosedLocal+recvRST→closed", StateHalfClosedLocal, EventRecvRST, StateClosed},

		// From half-closed(remote).
		{"halfClosedRemote+sendEndStream→closed", StateHalfClosedRemote, EventSendEndStream, StateClosed},
		{"halfClosedRemote+sendRST→closed", StateHalfClosedRemote, EventSendRST, StateClosed},
		{"halfClosedRemote+recvRST→closed", StateHalfClosedRemote, EventRecvRST, StateClosed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStream(1)
			s.state.Store(uint32(tt.from))

			err := s.Transition(tt.event)
			if err != nil {
				t.Fatalf("Transition(%s) from %s error: %v", tt.event, tt.from, err)
			}
			if got := s.State(); got != tt.to {
				t.Fatalf("state = %s, want %s", got, tt.to)
			}
		})
	}
}

func TestTransition_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name  string
		from  State
		event Event
	}{
		// From idle — can't send/recv END_STREAM or RST.
		{"idle+sendEndStream", StateIdle, EventSendEndStream},
		{"idle+recvEndStream", StateIdle, EventRecvEndStream},
		{"idle+sendRST", StateIdle, EventSendRST},
		{"idle+recvRST", StateIdle, EventRecvRST},

		// From open — can't send/recv HEADERS or PUSH_PROMISE.
		{"open+sendHeaders", StateOpen, EventSendHeaders},
		{"open+recvHeaders", StateOpen, EventRecvHeaders},
		{"open+sendPush", StateOpen, EventSendPush},
		{"open+recvPush", StateOpen, EventRecvPush},

		// From reserved(local).
		{"reservedLocal+recvHeaders", StateReservedLocal, EventRecvHeaders},
		{"reservedLocal+sendEndStream", StateReservedLocal, EventSendEndStream},
		{"reservedLocal+recvEndStream", StateReservedLocal, EventRecvEndStream},
		{"reservedLocal+sendPush", StateReservedLocal, EventSendPush},
		{"reservedLocal+recvPush", StateReservedLocal, EventRecvPush},

		// From reserved(remote).
		{"reservedRemote+sendHeaders", StateReservedRemote, EventSendHeaders},
		{"reservedRemote+sendEndStream", StateReservedRemote, EventSendEndStream},
		{"reservedRemote+recvEndStream", StateReservedRemote, EventRecvEndStream},
		{"reservedRemote+sendPush", StateReservedRemote, EventSendPush},
		{"reservedRemote+recvPush", StateReservedRemote, EventRecvPush},

		// From half-closed(local) — can't send anything.
		{"halfClosedLocal+sendHeaders", StateHalfClosedLocal, EventSendHeaders},
		{"halfClosedLocal+recvHeaders", StateHalfClosedLocal, EventRecvHeaders},
		{"halfClosedLocal+sendEndStream", StateHalfClosedLocal, EventSendEndStream},
		{"halfClosedLocal+sendPush", StateHalfClosedLocal, EventSendPush},
		{"halfClosedLocal+recvPush", StateHalfClosedLocal, EventRecvPush},

		// From half-closed(remote) — can't recv anything.
		{"halfClosedRemote+sendHeaders", StateHalfClosedRemote, EventSendHeaders},
		{"halfClosedRemote+recvHeaders", StateHalfClosedRemote, EventRecvHeaders},
		{"halfClosedRemote+recvEndStream", StateHalfClosedRemote, EventRecvEndStream},
		{"halfClosedRemote+sendPush", StateHalfClosedRemote, EventSendPush},
		{"halfClosedRemote+recvPush", StateHalfClosedRemote, EventRecvPush},

		// From closed — all transitions invalid.
		{"closed+sendHeaders", StateClosed, EventSendHeaders},
		{"closed+recvHeaders", StateClosed, EventRecvHeaders},
		{"closed+sendEndStream", StateClosed, EventSendEndStream},
		{"closed+recvEndStream", StateClosed, EventRecvEndStream},
		{"closed+sendRST", StateClosed, EventSendRST},
		{"closed+recvRST", StateClosed, EventRecvRST},
		{"closed+sendPush", StateClosed, EventSendPush},
		{"closed+recvPush", StateClosed, EventRecvPush},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStream(1)
			s.state.Store(uint32(tt.from))

			err := s.Transition(tt.event)
			if err == nil {
				t.Fatalf("Transition(%s) from %s should fail", tt.event, tt.from)
			}
			se, ok := err.(*StreamError)
			if !ok {
				t.Fatalf("error type = %T, want *StreamError", err)
			}
			if se.Code != frame.ErrCodeProtocolError {
				t.Fatalf("error code = %s, want PROTOCOL_ERROR", se.Code)
			}
			if se.StreamID != 1 {
				t.Fatalf("error stream ID = %d, want 1", se.StreamID)
			}
			// State should be unchanged.
			if got := s.State(); got != tt.from {
				t.Fatalf("state = %s, want %s (unchanged)", got, tt.from)
			}
		})
	}
}

func TestStream_FullLifecycle(t *testing.T) {
	s := newTestStream(1)
	s.state.Store(uint32(StateIdle))

	// idle → open (recv HEADERS)
	if err := s.Transition(EventRecvHeaders); err != nil {
		t.Fatalf("recv HEADERS: %v", err)
	}
	if s.State() != StateOpen {
		t.Fatalf("state = %s, want open", s.State())
	}

	// open → half-closed(local) (send END_STREAM)
	if err := s.Transition(EventSendEndStream); err != nil {
		t.Fatalf("send END_STREAM: %v", err)
	}
	if s.State() != StateHalfClosedLocal {
		t.Fatalf("state = %s, want half-closed(local)", s.State())
	}

	// half-closed(local) → closed (recv END_STREAM)
	if err := s.Transition(EventRecvEndStream); err != nil {
		t.Fatalf("recv END_STREAM: %v", err)
	}
	if s.State() != StateClosed {
		t.Fatalf("state = %s, want closed", s.State())
	}
	if !s.IsClosed() {
		t.Fatal("IsClosed() should return true")
	}
}

func TestStream_RSTFromOpen(t *testing.T) {
	for _, event := range []Event{EventSendRST, EventRecvRST} {
		s := newTestStream(1)
		s.state.Store(uint32(StateOpen))
		if err := s.Transition(event); err != nil {
			t.Fatalf("%s from open: %v", event, err)
		}
		if s.State() != StateClosed {
			t.Fatalf("state = %s, want closed after %s", s.State(), event)
		}
	}
}

func TestStream_PushPromisePath(t *testing.T) {
	// Server push: idle → reserved(local) → half-closed(remote)
	s := newTestStream(2)
	s.state.Store(uint32(StateIdle))
	if err := s.Transition(EventSendPush); err != nil {
		t.Fatalf("send PUSH_PROMISE: %v", err)
	}
	if s.State() != StateReservedLocal {
		t.Fatalf("state = %s, want reserved(local)", s.State())
	}
	if err := s.Transition(EventSendHeaders); err != nil {
		t.Fatalf("send HEADERS from reserved(local): %v", err)
	}
	if s.State() != StateHalfClosedRemote {
		t.Fatalf("state = %s, want half-closed(remote)", s.State())
	}
}

func TestStream_RecvPushPromisePath(t *testing.T) {
	// Client receives push: idle → reserved(remote) → half-closed(local)
	s := newTestStream(2)
	s.state.Store(uint32(StateIdle))
	if err := s.Transition(EventRecvPush); err != nil {
		t.Fatalf("recv PUSH_PROMISE: %v", err)
	}
	if s.State() != StateReservedRemote {
		t.Fatalf("state = %s, want reserved(remote)", s.State())
	}
	if err := s.Transition(EventRecvHeaders); err != nil {
		t.Fatalf("recv HEADERS from reserved(remote): %v", err)
	}
	if s.State() != StateHalfClosedLocal {
		t.Fatalf("state = %s, want half-closed(local)", s.State())
	}
}

func TestStream_FlowControl(t *testing.T) {
	s := acquireStream(1, 65535)
	defer releaseStream(s)

	if got := s.SendWin.Available(); got != 65535 {
		t.Fatalf("SendWin.Available() = %d, want 65535", got)
	}
	if got := s.RecvWin.Available(); got != 65535 {
		t.Fatalf("RecvWin.Available() = %d, want 65535", got)
	}

	if !s.SendWin.Consume(1000) {
		t.Fatal("SendWin.Consume(1000) should succeed")
	}
	if got := s.SendWin.Available(); got != 64535 {
		t.Fatalf("SendWin.Available() = %d, want 64535", got)
	}
}

func TestStreamError_String(t *testing.T) {
	e := &StreamError{StreamID: 5, Code: frame.ErrCodeCancel}
	expected := "http2: stream 5 error: CANCEL"
	if got := e.Error(); got != expected {
		t.Fatalf("Error() = %q, want %q", got, expected)
	}
}

func TestState_String(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateIdle, "idle"},
		{StateOpen, "open"},
		{StateReservedLocal, "reserved(local)"},
		{StateReservedRemote, "reserved(remote)"},
		{StateHalfClosedLocal, "half-closed(local)"},
		{StateHalfClosedRemote, "half-closed(remote)"},
		{StateClosed, "closed"},
		{State(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestEvent_String(t *testing.T) {
	tests := []struct {
		e    Event
		want string
	}{
		{EventSendHeaders, "send_HEADERS"},
		{EventRecvRST, "recv_RST_STREAM"},
		{Event(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.e.String(); got != tt.want {
			t.Errorf("Event(%d).String() = %q, want %q", tt.e, got, tt.want)
		}
	}
}

// ====================== MANAGER TESTS ======================

func TestManager_OpenAndGet(t *testing.T) {
	m := NewManager(100, 65535)
	s, err := m.OpenStream(1)
	if err != nil {
		t.Fatalf("OpenStream(1): %v", err)
	}
	if s.ID() != 1 {
		t.Fatalf("ID = %d, want 1", s.ID())
	}
	if s.State() != StateIdle {
		t.Fatalf("state = %s, want idle", s.State())
	}

	got := m.GetStream(1)
	if got != s {
		t.Fatal("GetStream(1) returned different stream")
	}

	if m.ActiveCount() != 1 {
		t.Fatalf("ActiveCount() = %d, want 1", m.ActiveCount())
	}
}

func TestManager_GetNotFound(t *testing.T) {
	m := NewManager(100, 65535)
	if s := m.GetStream(1); s != nil {
		t.Fatal("GetStream(1) should return nil for nonexistent stream")
	}
}

func TestManager_MaxConcurrent(t *testing.T) {
	m := NewManager(2, 65535)
	if _, err := m.OpenStream(1); err != nil {
		t.Fatalf("OpenStream(1): %v", err)
	}
	if _, err := m.OpenStream(3); err != nil {
		t.Fatalf("OpenStream(3): %v", err)
	}
	_, err := m.OpenStream(5)
	if err != ErrMaxConcurrentStreams {
		t.Fatalf("OpenStream(5) error = %v, want ErrMaxConcurrentStreams", err)
	}

	// Close one, should be able to open again.
	m.CloseStream(1)
	if _, err := m.OpenStream(5); err != nil {
		t.Fatalf("OpenStream(5) after close: %v", err)
	}
}

func TestManager_StreamIDValidation(t *testing.T) {
	m := NewManager(100, 65535)

	// Stream ID 0 is invalid.
	_, err := m.OpenStream(0)
	if err != ErrStreamIDParity {
		t.Fatalf("OpenStream(0) error = %v, want ErrStreamIDParity", err)
	}

	// Open stream 3 (odd, client).
	if _, err := m.OpenStream(3); err != nil {
		t.Fatalf("OpenStream(3): %v", err)
	}

	// Stream 1 < 3 → regression.
	_, err = m.OpenStream(1)
	if err != ErrStreamIDRegression {
		t.Fatalf("OpenStream(1) error = %v, want ErrStreamIDRegression", err)
	}

	// Stream 3 == last → regression.
	_, err = m.OpenStream(3)
	if err != ErrStreamIDRegression {
		t.Fatalf("OpenStream(3) again error = %v, want ErrStreamIDRegression", err)
	}

	// Even IDs (server) are independent.
	if _, err := m.OpenStream(2); err != nil {
		t.Fatalf("OpenStream(2): %v", err)
	}
	_, err = m.OpenStream(2)
	if err != ErrStreamIDRegression {
		t.Fatalf("OpenStream(2) again error = %v, want ErrStreamIDRegression", err)
	}
}

func TestManager_CloseStream(t *testing.T) {
	m := NewManager(100, 65535)
	m.OpenStream(1)
	m.OpenStream(3)
	if m.ActiveCount() != 2 {
		t.Fatalf("ActiveCount() = %d, want 2", m.ActiveCount())
	}

	m.CloseStream(1)
	if m.ActiveCount() != 1 {
		t.Fatalf("ActiveCount() = %d, want 1", m.ActiveCount())
	}
	if s := m.GetStream(1); s != nil {
		t.Fatal("GetStream(1) should return nil after close")
	}

	// Double close is safe.
	m.CloseStream(1)
	if m.ActiveCount() != 1 {
		t.Fatalf("ActiveCount() = %d, want 1 after double close", m.ActiveCount())
	}
}

func TestManager_AdjustInitialWindowSize(t *testing.T) {
	m := NewManager(100, 65535)
	s1, _ := m.OpenStream(1)
	s2, _ := m.OpenStream(3)

	// Decrease window by 32767.
	if err := m.AdjustInitialWindowSize(32768); err != nil {
		t.Fatalf("AdjustInitialWindowSize(32768): %v", err)
	}

	if got := s1.SendWin.Size(); got != 32768 {
		t.Fatalf("s1.SendWin.Size() = %d, want 32768", got)
	}
	if got := s2.SendWin.Size(); got != 32768 {
		t.Fatalf("s2.SendWin.Size() = %d, want 32768", got)
	}

	// New streams get the new initial window.
	s3, _ := m.OpenStream(5)
	if got := s3.SendWin.Size(); got != 32768 {
		t.Fatalf("s3.SendWin.Size() = %d, want 32768", got)
	}
}

func TestManager_AdjustInitialWindowSize_Negative(t *testing.T) {
	m := NewManager(100, 65535)
	s, _ := m.OpenStream(1)

	// Consume most of the window.
	s.SendWin.Consume(65535)
	if got := s.SendWin.Size(); got != 0 {
		t.Fatalf("SendWin.Size() = %d, want 0", got)
	}

	// Decrease initial window → delta makes it negative.
	if err := m.AdjustInitialWindowSize(32768); err != nil {
		t.Fatalf("AdjustInitialWindowSize(32768): %v", err)
	}
	// 0 + (32768 - 65535) = -32767
	if got := s.SendWin.Size(); got != -32767 {
		t.Fatalf("SendWin.Size() = %d, want -32767", got)
	}
	if got := s.SendWin.Available(); got != 0 {
		t.Fatalf("SendWin.Available() = %d, want 0 (negative window)", got)
	}
}

func TestManager_GoAway(t *testing.T) {
	m := NewManager(100, 65535)
	m.OpenStream(1)
	m.GoAway()

	_, err := m.OpenStream(3)
	if err != ErrGoAway {
		t.Fatalf("OpenStream after GoAway error = %v, want ErrGoAway", err)
	}

	// Existing streams still accessible.
	if s := m.GetStream(1); s == nil {
		t.Fatal("existing stream should still be accessible after GoAway")
	}
}

func TestManager_ForEach(t *testing.T) {
	m := NewManager(100, 65535)
	m.OpenStream(1)
	m.OpenStream(3)
	m.OpenStream(5)

	var ids []uint32
	m.ForEach(func(s *Stream) {
		ids = append(ids, s.ID())
	})
	if len(ids) != 3 {
		t.Fatalf("ForEach visited %d streams, want 3", len(ids))
	}
}

func TestManager_Reset(t *testing.T) {
	m := NewManager(100, 65535)
	m.OpenStream(1)
	m.OpenStream(3)
	m.GoAway()
	m.Reset()

	if m.ActiveCount() != 0 {
		t.Fatalf("ActiveCount() = %d, want 0", m.ActiveCount())
	}
	if m.LastClientStreamID() != 0 {
		t.Fatalf("LastClientStreamID() = %d, want 0", m.LastClientStreamID())
	}

	// Should be able to open streams again.
	if _, err := m.OpenStream(1); err != nil {
		t.Fatalf("OpenStream(1) after reset: %v", err)
	}
}

func TestManager_SetMaxConcurrent(t *testing.T) {
	m := NewManager(1, 65535)
	m.OpenStream(1)
	_, err := m.OpenStream(3)
	if err != ErrMaxConcurrentStreams {
		t.Fatalf("error = %v, want ErrMaxConcurrentStreams", err)
	}

	m.SetMaxConcurrent(2)
	if _, err := m.OpenStream(3); err != nil {
		t.Fatalf("OpenStream(3) after SetMaxConcurrent(2): %v", err)
	}
}

func TestManager_LastStreamIDs(t *testing.T) {
	m := NewManager(100, 65535)
	m.OpenStream(1)
	m.OpenStream(3)
	m.OpenStream(2)
	m.OpenStream(4)

	if got := m.LastClientStreamID(); got != 3 {
		t.Fatalf("LastClientStreamID() = %d, want 3", got)
	}
	if got := m.LastServerStreamID(); got != 4 {
		t.Fatalf("LastServerStreamID() = %d, want 4", got)
	}
}

// ====================== STRESS TEST ======================

func TestManager_10000ConcurrentStreams(t *testing.T) {
	const numStreams = 10000
	m := NewManager(numStreams, 65535)

	var wg sync.WaitGroup
	wg.Add(numStreams)

	// Phase 1: Open all streams concurrently.
	// Each goroutine gets a unique odd ID.
	errCh := make(chan error, numStreams)
	for i := 0; i < numStreams; i++ {
		id := uint32(2*i + 1) // 1, 3, 5, ..., 19999
		go func(id uint32) {
			defer wg.Done()
			_, err := m.OpenStream(id)
			if err != nil {
				errCh <- err
			}
		}(id)
	}
	wg.Wait()
	close(errCh)

	// OpenStream enforces id > lastClientID, so with concurrent opens
	// some will fail with ErrStreamIDRegression. That's expected behavior —
	// in real usage, stream IDs are opened sequentially by the connection handler.
	// For the stress test, open them sequentially first.

	// Reset and do sequential open + concurrent transition + concurrent close.
	m.Reset()

	// Sequential open (as would happen in the real connection handler).
	streams := make([]*Stream, numStreams)
	for i := 0; i < numStreams; i++ {
		id := uint32(2*i + 1)
		s, err := m.OpenStream(id)
		if err != nil {
			t.Fatalf("OpenStream(%d): %v", id, err)
		}
		// Transition to open.
		if err := s.Transition(EventRecvHeaders); err != nil {
			t.Fatalf("Transition to open for stream %d: %v", id, err)
		}
		streams[i] = s
	}

	if m.ActiveCount() != numStreams {
		t.Fatalf("ActiveCount() = %d, want %d", m.ActiveCount(), numStreams)
	}

	// Phase 2: Concurrent transition + close.
	wg.Add(numStreams)
	for i := 0; i < numStreams; i++ {
		go func(s *Stream) {
			defer wg.Done()
			// Transition: open → half-closed(local) → closed.
			if err := s.Transition(EventSendEndStream); err != nil {
				t.Errorf("stream %d send END_STREAM: %v", s.ID(), err)
				return
			}
			if err := s.Transition(EventRecvEndStream); err != nil {
				t.Errorf("stream %d recv END_STREAM: %v", s.ID(), err)
				return
			}
			m.CloseStream(s.ID())
		}(streams[i])
	}
	wg.Wait()

	// Phase 3: Verify cleanup.
	if m.ActiveCount() != 0 {
		t.Fatalf("ActiveCount() = %d, want 0", m.ActiveCount())
	}
}

// Test concurrent GetStream during mutations.
func TestManager_ConcurrentGetStream(t *testing.T) {
	const numStreams = 1000
	m := NewManager(numStreams, 65535)

	// Open streams.
	for i := 0; i < numStreams; i++ {
		m.OpenStream(uint32(2*i + 1))
	}

	var wg sync.WaitGroup
	// Readers.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numStreams; j++ {
				_ = m.GetStream(uint32(2*j + 1))
			}
		}()
	}
	// Closers.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			m.CloseStream(id)
		}(uint32(2*i + 1))
	}
	wg.Wait()

	if m.ActiveCount() != 0 {
		t.Fatalf("ActiveCount() = %d, want 0", m.ActiveCount())
	}
}

// ====================== POOL TESTS ======================

func TestStream_Pool(t *testing.T) {
	s := acquireStream(1, 65535)
	if s.ID() != 1 {
		t.Fatalf("ID = %d, want 1", s.ID())
	}
	if s.State() != StateIdle {
		t.Fatalf("state = %s, want idle", s.State())
	}
	if got := s.SendWin.Size(); got != 65535 {
		t.Fatalf("SendWin.Size() = %d, want 65535", got)
	}

	// Transition and close.
	s.Transition(EventRecvHeaders)
	s.Transition(EventSendRST)
	releaseStream(s)

	// Reacquire — should be reset.
	s2 := acquireStream(3, 32768)
	if s2.ID() != 3 {
		t.Fatalf("ID = %d, want 3", s2.ID())
	}
	if s2.State() != StateIdle {
		t.Fatalf("state = %s, want idle (after pool reuse)", s2.State())
	}
	if got := s2.SendWin.Size(); got != 32768 {
		t.Fatalf("SendWin.Size() = %d, want 32768", got)
	}
	releaseStream(s2)
}
