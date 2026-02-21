// Package stream implements HTTP/2 stream state management per RFC 9113 §5.
package stream

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/blazehttp/blazehttp/pkg/flowcontrol"
	"github.com/blazehttp/blazehttp/pkg/frame"
)

// Stream states per RFC 9113 §5.1.
type State uint8

const (
	StateIdle             State = 0
	StateOpen             State = 1
	StateReservedLocal    State = 2
	StateReservedRemote   State = 3
	StateHalfClosedLocal  State = 4
	StateHalfClosedRemote State = 5
	StateClosed           State = 6

	stateCount   = 7
	stateInvalid = State(0xFF) // sentinel for invalid transitions
)

var stateNames = [stateCount]string{
	"idle", "open", "reserved(local)", "reserved(remote)",
	"half-closed(local)", "half-closed(remote)", "closed",
}

// String returns the state name.
func (s State) String() string {
	if int(s) < len(stateNames) {
		return stateNames[s]
	}
	return "unknown"
}

// Events that trigger stream state transitions.
type Event uint8

const (
	EventSendHeaders   Event = 0
	EventRecvHeaders   Event = 1
	EventSendEndStream Event = 2
	EventRecvEndStream Event = 3
	EventSendRST       Event = 4
	EventRecvRST       Event = 5
	EventSendPush      Event = 6
	EventRecvPush      Event = 7

	eventCount = 8
)

var eventNames = [eventCount]string{
	"send_HEADERS", "recv_HEADERS", "send_END_STREAM", "recv_END_STREAM",
	"send_RST_STREAM", "recv_RST_STREAM", "send_PUSH_PROMISE", "recv_PUSH_PROMISE",
}

// String returns the event name.
func (e Event) String() string {
	if int(e) < len(eventNames) {
		return eventNames[e]
	}
	return "unknown"
}

// Transition table: transitionTable[currentState][event] = nextState.
// stateInvalid (0xFF) means the transition is not allowed.
var transitionTable = [stateCount][eventCount]State{
	// StateIdle
	{
		EventSendHeaders: StateOpen,           // send HEADERS
		EventRecvHeaders: StateOpen,           // recv HEADERS
		EventSendPush:    StateReservedLocal,  // send PUSH_PROMISE
		EventRecvPush:    StateReservedRemote, // recv PUSH_PROMISE
		// All others invalid from idle.
		EventSendEndStream: stateInvalid,
		EventRecvEndStream: stateInvalid,
		EventSendRST:       stateInvalid,
		EventRecvRST:       stateInvalid,
	},
	// StateOpen
	{
		EventSendEndStream: StateHalfClosedLocal,  // send END_STREAM
		EventRecvEndStream: StateHalfClosedRemote, // recv END_STREAM
		EventSendRST:       StateClosed,           // send RST_STREAM
		EventRecvRST:       StateClosed,           // recv RST_STREAM
		EventSendHeaders:   stateInvalid,          // can't send new HEADERS on open stream
		EventRecvHeaders:   stateInvalid,          // trailing headers handled via END_STREAM, not state change
		EventSendPush:      stateInvalid,
		EventRecvPush:      stateInvalid,
	},
	// StateReservedLocal
	{
		EventSendHeaders: StateHalfClosedRemote, // send HEADERS (push response)
		EventSendRST:     StateClosed,
		EventRecvRST:     StateClosed,
		// All others invalid.
		EventRecvHeaders:   stateInvalid,
		EventSendEndStream: stateInvalid,
		EventRecvEndStream: stateInvalid,
		EventSendPush:      stateInvalid,
		EventRecvPush:      stateInvalid,
	},
	// StateReservedRemote
	{
		EventRecvHeaders: StateHalfClosedLocal, // recv HEADERS (push response)
		EventSendRST:     StateClosed,
		EventRecvRST:     StateClosed,
		// All others invalid.
		EventSendHeaders:   stateInvalid,
		EventSendEndStream: stateInvalid,
		EventRecvEndStream: stateInvalid,
		EventSendPush:      stateInvalid,
		EventRecvPush:      stateInvalid,
	},
	// StateHalfClosedLocal
	{
		EventRecvEndStream: StateClosed, // recv END_STREAM → fully closed
		EventSendRST:       StateClosed,
		EventRecvRST:       StateClosed,
		// Cannot send data/headers after local close.
		EventSendHeaders:   stateInvalid,
		EventRecvHeaders:   stateInvalid,
		EventSendEndStream: stateInvalid,
		EventSendPush:      stateInvalid,
		EventRecvPush:      stateInvalid,
	},
	// StateHalfClosedRemote
	{
		EventSendEndStream: StateClosed, // send END_STREAM → fully closed
		EventSendRST:       StateClosed,
		EventRecvRST:       StateClosed,
		// Cannot receive data/headers after remote close.
		EventSendHeaders:   stateInvalid,
		EventRecvHeaders:   stateInvalid,
		EventRecvEndStream: stateInvalid,
		EventSendPush:      stateInvalid,
		EventRecvPush:      stateInvalid,
	},
	// StateClosed — no valid transitions (terminal state).
	{
		stateInvalid, stateInvalid, stateInvalid, stateInvalid,
		stateInvalid, stateInvalid, stateInvalid, stateInvalid,
	},
}

// StreamError represents an HTTP/2 stream-level error.
type StreamError struct {
	StreamID uint32
	Code     frame.ErrorCode
}

func (e *StreamError) Error() string {
	return fmt.Sprintf("http2: stream %d error: %s", e.StreamID, e.Code)
}

// Stream represents a single HTTP/2 stream with its state machine and flow control.
type Stream struct {
	ID       uint32
	state    atomic.Uint32
	SendWin  flowcontrol.Window
	RecvWin  flowcontrol.Window
	Priority frame.PriorityParam
}

// State returns the current stream state.
func (s *Stream) State() State {
	return State(s.state.Load())
}

// IsClosed reports whether the stream is in the closed state.
func (s *Stream) IsClosed() bool {
	return State(s.state.Load()) == StateClosed
}

// Transition atomically transitions the stream to the next state for the given event.
// Returns a StreamError if the transition is invalid.
func (s *Stream) Transition(event Event) error {
	for {
		cur := s.state.Load()
		curState := State(cur)
		if curState >= stateCount {
			return &StreamError{StreamID: s.ID, Code: frame.ErrCodeProtocolError}
		}
		next := transitionTable[curState][event]
		if next == stateInvalid {
			return &StreamError{
				StreamID: s.ID,
				Code:     frame.ErrCodeProtocolError,
			}
		}
		if s.state.CompareAndSwap(cur, uint32(next)) {
			return nil
		}
	}
}

func (s *Stream) reset(id uint32, initialWindowSize int32) {
	s.ID = id
	s.state.Store(uint32(StateIdle))
	s.SendWin.Reset(initialWindowSize)
	s.RecvWin.Reset(initialWindowSize)
	s.Priority = frame.PriorityParam{}
}

var streamPool = sync.Pool{
	New: func() any {
		return &Stream{}
	},
}

func acquireStream(id uint32, initialWindowSize int32) *Stream {
	s := streamPool.Get().(*Stream)
	s.reset(id, initialWindowSize)
	return s
}

func releaseStream(s *Stream) {
	s.ID = 0
	s.state.Store(uint32(StateClosed))
	streamPool.Put(s)
}
