package stream

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/justIliane/blazehttp/pkg/frame"
)

// Manager errors.
var (
	ErrMaxConcurrentStreams = errors.New("stream: max concurrent streams exceeded")
	ErrStreamIDRegression   = errors.New("stream: stream ID must be greater than previous")
	ErrStreamIDParity       = errors.New("stream: invalid stream ID parity")
	ErrGoAway               = errors.New("stream: connection is closing")
	ErrStreamNotFound       = errors.New("stream: not found")
)

// Manager manages the lifecycle of HTTP/2 streams on a connection.
// It is safe for concurrent use.
type Manager struct {
	mu      sync.RWMutex
	streams map[uint32]*Stream

	maxConcurrent uint32
	activeCount   atomic.Int32

	lastClientID uint32 // highest odd stream ID seen
	lastServerID uint32 // highest even stream ID seen

	initialWindow int32 // SETTINGS_INITIAL_WINDOW_SIZE for new streams

	closed bool // true after GoAway
}

// NewManager creates a Manager with the given settings.
func NewManager(maxConcurrent uint32, initialWindow int32) *Manager {
	return &Manager{
		streams:       make(map[uint32]*Stream, 64),
		maxConcurrent: maxConcurrent,
		initialWindow: initialWindow,
	}
}

// OpenStream creates and registers a new stream.
// For client-initiated streams, id must be odd and greater than lastClientID.
// For server-initiated streams, id must be even and greater than lastServerID.
func (m *Manager) OpenStream(id uint32) (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrGoAway
	}

	// Validate parity and monotonicity.
	if id == 0 {
		return nil, ErrStreamIDParity
	}
	if id%2 == 1 {
		// Client-initiated (odd).
		if id <= m.lastClientID {
			return nil, ErrStreamIDRegression
		}
	} else {
		// Server-initiated (even).
		if id <= m.lastServerID {
			return nil, ErrStreamIDRegression
		}
	}

	// Check concurrency limit.
	if uint32(m.activeCount.Load()) >= m.maxConcurrent {
		return nil, ErrMaxConcurrentStreams
	}

	s := acquireStream(id, m.initialWindow)
	m.streams[id] = s
	m.activeCount.Add(1)

	if id%2 == 1 {
		m.lastClientID = id
	} else {
		m.lastServerID = id
	}

	return s, nil
}

// GetStream returns the stream with the given ID, or nil if not found.
func (m *Manager) GetStream(id uint32) *Stream {
	m.mu.RLock()
	s := m.streams[id]
	m.mu.RUnlock()
	return s
}

// CloseStream removes the stream from the manager and returns it to the pool.
func (m *Manager) CloseStream(id uint32) {
	m.mu.Lock()
	s, ok := m.streams[id]
	if ok {
		delete(m.streams, id)
		m.activeCount.Add(-1)
	}
	m.mu.Unlock()

	if ok {
		releaseStream(s)
	}
}

// SetMaxConcurrent updates the maximum concurrent stream limit.
func (m *Manager) SetMaxConcurrent(n uint32) {
	m.mu.Lock()
	m.maxConcurrent = n
	m.mu.Unlock()
}

// AdjustInitialWindowSize adjusts all existing stream send windows
// when SETTINGS_INITIAL_WINDOW_SIZE changes (RFC 9113 §6.9.2).
// The delta is applied to every open stream's send window and can make them negative.
func (m *Manager) AdjustInitialWindowSize(newSize int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delta := newSize - m.initialWindow
	m.initialWindow = newSize

	for _, s := range m.streams {
		s.SendWin.Add(delta)
		// Check overflow: if the new window exceeds 2^31-1, that's a flow control error.
		if s.SendWin.Size() > int32(flowcontrolMaxWindowSize) {
			return &frame.ConnError{
				Code:   frame.ErrCodeFlowControlError,
				Reason: "SETTINGS_INITIAL_WINDOW_SIZE caused window overflow",
			}
		}
	}
	return nil
}

// flowcontrolMaxWindowSize avoids importing flowcontrol just for the constant.
const flowcontrolMaxWindowSize = (1 << 31) - 1

// ActiveCount returns the number of active (non-closed) streams.
func (m *Manager) ActiveCount() int {
	return int(m.activeCount.Load())
}

// GoAway marks the connection as closing. No new streams will be accepted.
func (m *Manager) GoAway() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
}

// ForEach calls fn for each active stream while holding a read lock.
func (m *Manager) ForEach(fn func(*Stream)) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.streams {
		fn(s)
	}
}

// Reset closes all streams and resets the manager to initial state.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, s := range m.streams {
		delete(m.streams, id)
		releaseStream(s)
	}
	m.activeCount.Store(0)
	m.lastClientID = 0
	m.lastServerID = 0
	m.closed = false
}

// LastClientStreamID returns the highest client-initiated stream ID.
func (m *Manager) LastClientStreamID() uint32 {
	m.mu.RLock()
	id := m.lastClientID
	m.mu.RUnlock()
	return id
}

// LastServerStreamID returns the highest server-initiated stream ID.
func (m *Manager) LastServerStreamID() uint32 {
	m.mu.RLock()
	id := m.lastServerID
	m.mu.RUnlock()
	return id
}

// IsIdle reports whether the given stream ID refers to a stream in the idle state.
// A stream is idle if it has never been opened (ID exceeds the highest seen for its parity).
func (m *Manager) IsIdle(id uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.streams[id]; ok {
		return false // active stream
	}
	if id%2 == 1 {
		return id > m.lastClientID
	}
	return id > m.lastServerID
}
