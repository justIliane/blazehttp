// Package frame implements HTTP/2 frame reading and writing per RFC 9113.
package frame

import "errors"

// Frame type codes per RFC 9113 §6.
type FrameType uint8

const (
	FrameData         FrameType = 0x0
	FrameHeaders      FrameType = 0x1
	FramePriority     FrameType = 0x2
	FrameRSTStream    FrameType = 0x3
	FrameSettings     FrameType = 0x4
	FramePushPromise  FrameType = 0x5
	FramePing         FrameType = 0x6
	FrameGoAway       FrameType = 0x7
	FrameWindowUpdate FrameType = 0x8
	FrameContinuation FrameType = 0x9
)

var frameTypeNames = [10]string{
	"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
	"PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION",
}

// String returns the frame type name.
func (t FrameType) String() string {
	if int(t) < len(frameTypeNames) {
		return frameTypeNames[t]
	}
	return "UNKNOWN"
}

// Frame flags per RFC 9113 §6.
type Flags uint8

const (
	FlagEndStream  Flags = 0x01
	FlagACK        Flags = 0x01 // Same bit, different context (SETTINGS, PING).
	FlagEndHeaders Flags = 0x04
	FlagPadded     Flags = 0x08
	FlagPriority   Flags = 0x20
)

// Has reports whether f contains the given flag.
func (f Flags) Has(flag Flags) bool { return f&flag != 0 }

// HTTP/2 error codes per RFC 9113 §7.
type ErrorCode uint32

const (
	ErrCodeNoError            ErrorCode = 0x0
	ErrCodeProtocolError      ErrorCode = 0x1
	ErrCodeInternalError      ErrorCode = 0x2
	ErrCodeFlowControlError   ErrorCode = 0x3
	ErrCodeSettingsTimeout    ErrorCode = 0x4
	ErrCodeStreamClosed       ErrorCode = 0x5
	ErrCodeFrameSizeError     ErrorCode = 0x6
	ErrCodeRefusedStream      ErrorCode = 0x7
	ErrCodeCancel             ErrorCode = 0x8
	ErrCodeCompressionError   ErrorCode = 0x9
	ErrCodeConnectError       ErrorCode = 0xa
	ErrCodeEnhanceYourCalm    ErrorCode = 0xb
	ErrCodeInadequateSecurity ErrorCode = 0xc
	ErrCodeHTTP11Required     ErrorCode = 0xd
)

var errCodeNames = [14]string{
	"NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR",
	"SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM",
	"CANCEL", "COMPRESSION_ERROR", "CONNECT_ERROR", "ENHANCE_YOUR_CALM",
	"INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED",
}

// String returns the error code name.
func (c ErrorCode) String() string {
	if int(c) < len(errCodeNames) {
		return errCodeNames[c]
	}
	return "UNKNOWN_ERROR"
}

// ConnError represents an HTTP/2 connection error with an error code.
// The connection layer should send GOAWAY with the given code.
type ConnError struct {
	Code   ErrorCode
	Reason string
}

func (e *ConnError) Error() string {
	return "http2: connection error: " + e.Code.String() + ": " + e.Reason
}

// Sentinel errors for common validation failures.
var (
	ErrFrameTooLarge = errors.New("frame: payload exceeds max frame size")
	ErrTruncated     = errors.New("frame: truncated")
)

// SETTINGS parameter IDs per RFC 9113 §6.5.2.
type SettingsID uint16

const (
	SettingsHeaderTableSize      SettingsID = 0x1
	SettingsEnablePush           SettingsID = 0x2
	SettingsMaxConcurrentStreams  SettingsID = 0x3
	SettingsInitialWindowSize    SettingsID = 0x4
	SettingsMaxFrameSize         SettingsID = 0x5
	SettingsMaxHeaderListSize    SettingsID = 0x6
)

// Setting is a single SETTINGS parameter.
type Setting struct {
	ID    SettingsID
	Value uint32
}

// PriorityParam holds stream priority fields for HEADERS and PRIORITY frames.
type PriorityParam struct {
	Exclusive bool
	StreamDep uint32
	Weight    uint8 // 0-255, actual priority weight is Weight+1
}

// Frame size limits per RFC 9113 §4.2.
const (
	DefaultMaxFrameSize = 16384   // 2^14
	MaxMaxFrameSize     = 1<<24 - 1 // 2^24 - 1
	frameHeaderLen      = 9
)

// MaxSettingsPerFrame is the max number of settings in the fixed array.
// Real-world SETTINGS frames contain at most 6 defined parameters.
const MaxSettingsPerFrame = 32

// Frame is a reusable, zero-allocation frame representation.
// Only fields relevant to the frame Type are valid after a read.
// Data, HeaderBlock, and DebugData slices point into the reader's buffer
// and are valid only until the next ReadFrame call.
type Frame struct {
	// Header fields (always valid).
	Type     FrameType
	Flags    Flags
	StreamID uint32
	Length   uint32 // payload length from the wire

	// DATA
	Data []byte

	// HEADERS / PUSH_PROMISE / CONTINUATION (assembled)
	HeaderBlock []byte

	// Priority fields (HEADERS with FlagPriority, or PRIORITY frame).
	StreamDep uint32
	Weight    uint8
	Exclusive bool

	// PUSH_PROMISE
	PromisedStreamID uint32

	// RST_STREAM / GOAWAY
	ErrorCode ErrorCode

	// SETTINGS
	Settings    [MaxSettingsPerFrame]Setting
	NumSettings int

	// PING
	PingData [8]byte

	// GOAWAY
	LastStreamID uint32
	DebugData    []byte

	// WINDOW_UPDATE
	WindowIncrement uint32
}

// Reset clears all frame fields for reuse.
func (f *Frame) Reset() {
	f.Type = 0
	f.Flags = 0
	f.StreamID = 0
	f.Length = 0
	f.Data = nil
	f.HeaderBlock = nil
	f.StreamDep = 0
	f.Weight = 0
	f.Exclusive = false
	f.PromisedStreamID = 0
	f.ErrorCode = 0
	f.NumSettings = 0
	f.LastStreamID = 0
	f.DebugData = nil
	f.WindowIncrement = 0
}

// Convenience flag checks.

// HasEndStream reports whether the END_STREAM flag is set.
func (f *Frame) HasEndStream() bool { return f.Flags.Has(FlagEndStream) }

// HasEndHeaders reports whether the END_HEADERS flag is set.
func (f *Frame) HasEndHeaders() bool { return f.Flags.Has(FlagEndHeaders) }

// HasPadded reports whether the PADDED flag is set.
func (f *Frame) HasPadded() bool { return f.Flags.Has(FlagPadded) }

// HasPriority reports whether the PRIORITY flag is set.
func (f *Frame) HasPriority() bool { return f.Flags.Has(FlagPriority) }

// HasACK reports whether the ACK flag is set.
func (f *Frame) HasACK() bool { return f.Flags.Has(FlagACK) }
