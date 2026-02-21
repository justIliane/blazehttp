// Package flowcontrol implements HTTP/2 flow control windows per RFC 9113 §5.2.
package flowcontrol

import (
	"sync/atomic"

	"github.com/blazehttp/blazehttp/pkg/frame"
)

// Flow control constants per RFC 9113.
const (
	MaxWindowSize          = (1 << 31) - 1 // 2^31-1, maximum window size
	DefaultInitialWindowSize = 65535        // RFC 9113 §6.5.2 default
	WindowUpdateThreshold  = DefaultInitialWindowSize / 2
)

// Window is a lock-free HTTP/2 flow control window.
// It uses atomic operations for safe concurrent access.
// The window value can go negative after SETTINGS_INITIAL_WINDOW_SIZE changes (RFC 9113 §6.9.2).
type Window struct {
	val atomic.Int64
}

// NewWindow creates a Window with the given initial size.
func NewWindow(initial int32) *Window {
	w := &Window{}
	w.val.Store(int64(initial))
	return w
}

// Size returns the raw window value, which can be negative.
func (w *Window) Size() int32 {
	return int32(w.val.Load())
}

// Available returns the available window for sending.
// Returns 0 if the window is negative or zero.
func (w *Window) Available() int32 {
	v := int32(w.val.Load())
	if v < 0 {
		return 0
	}
	return v
}

// Consume atomically decrements the window by n bytes.
// Returns true if the window had sufficient space, false otherwise.
// n must be positive.
func (w *Window) Consume(n int32) bool {
	if n <= 0 {
		return false
	}
	for {
		cur := w.val.Load()
		if int32(cur) < n {
			return false
		}
		if w.val.CompareAndSwap(cur, cur-int64(n)) {
			return true
		}
	}
}

// Update atomically increases the window by n bytes (from WINDOW_UPDATE).
// Returns an error if the resulting window would exceed MaxWindowSize.
// n must be positive.
func (w *Window) Update(n int32) error {
	if n <= 0 {
		return nil
	}
	for {
		cur := w.val.Load()
		newVal := cur + int64(n)
		if newVal > MaxWindowSize {
			return &frame.ConnError{
				Code:   frame.ErrCodeFlowControlError,
				Reason: "flow control window overflow",
			}
		}
		if w.val.CompareAndSwap(cur, newVal) {
			return nil
		}
	}
}

// Add unconditionally adds delta to the window.
// Used for SETTINGS_INITIAL_WINDOW_SIZE changes (RFC 9113 §6.9.2),
// which can make the window negative.
func (w *Window) Add(delta int32) {
	w.val.Add(int64(delta))
}

// Reset sets the window to the given value.
func (w *Window) Reset(val int32) {
	w.val.Store(int64(val))
}
