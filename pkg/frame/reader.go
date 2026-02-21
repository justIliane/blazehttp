package frame

import (
	"io"
	"sync"
)

// FrameReader reads HTTP/2 frames from an io.Reader.
// It automatically assembles CONTINUATION frames into a single header block.
// The returned *Frame is valid until the next ReadFrame call.
type FrameReader struct {
	r   io.Reader
	buf []byte // read buffer
	off int    // consumed offset
	end int    // valid data end

	maxFrameSize uint32

	// CONTINUATION assembly state.
	contBuf      []byte // assembled header block fragments
	contStreamID uint32
	inCont       bool

	// Reusable frame returned by ReadFrame.
	frame Frame
}

var readerPool = sync.Pool{
	New: func() any {
		return newFrameReader()
	},
}

// AcquireFrameReader gets a FrameReader from the pool.
func AcquireFrameReader(r io.Reader) *FrameReader {
	fr := readerPool.Get().(*FrameReader)
	fr.r = r
	fr.off = 0
	fr.end = 0
	fr.inCont = false
	return fr
}

// ReleaseFrameReader returns a FrameReader to the pool.
func ReleaseFrameReader(fr *FrameReader) {
	fr.r = nil
	fr.off = 0
	fr.end = 0
	fr.inCont = false
	fr.contStreamID = 0
	fr.contBuf = fr.contBuf[:0]
	fr.maxFrameSize = DefaultMaxFrameSize
	readerPool.Put(fr)
}

func newFrameReader() *FrameReader {
	bufCap := DefaultMaxFrameSize + frameHeaderLen + 256
	return &FrameReader{
		buf:          make([]byte, bufCap),
		contBuf:      make([]byte, 0, DefaultMaxFrameSize),
		maxFrameSize: DefaultMaxFrameSize,
	}
}

// SetMaxFrameSize sets the maximum allowed frame payload size.
func (fr *FrameReader) SetMaxFrameSize(size uint32) {
	if size < DefaultMaxFrameSize {
		size = DefaultMaxFrameSize
	}
	if size > MaxMaxFrameSize {
		size = MaxMaxFrameSize
	}
	fr.maxFrameSize = size
}

// MaxFrameSize returns the current maximum frame payload size.
func (fr *FrameReader) MaxFrameSize() uint32 {
	return fr.maxFrameSize
}

// fill ensures at least need bytes are available in buf[off:end].
func (fr *FrameReader) fill(need int) error {
	avail := fr.end - fr.off
	if avail >= need {
		return nil
	}

	// Compact: move unread data to front of buffer.
	if fr.off > 0 {
		copy(fr.buf, fr.buf[fr.off:fr.end])
		fr.end -= fr.off
		fr.off = 0
		avail = fr.end
	}

	// Grow if buffer is too small.
	if need > len(fr.buf) {
		newBuf := make([]byte, need+4096)
		copy(newBuf, fr.buf[:fr.end])
		fr.buf = newBuf
	}

	// Read until we have enough.
	for fr.end < need {
		n, err := fr.r.Read(fr.buf[fr.end:])
		fr.end += n
		if fr.end >= need {
			return nil
		}
		if err != nil {
			if err == io.EOF && fr.end > 0 && fr.end < need {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// ReadFrame reads the next frame. The returned *Frame is reused on the next call.
func (fr *FrameReader) ReadFrame() (*Frame, error) {
	f := &fr.frame
	f.Reset()

	// Read the 9-byte header.
	if err := fr.fill(frameHeaderLen); err != nil {
		return nil, err
	}

	b := fr.buf[fr.off:]
	length := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	ftype := FrameType(b[3])
	flags := Flags(b[4])
	streamID := (uint32(b[5])<<24 | uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8])) & 0x7FFFFFFF

	// Validate frame size.
	if length > fr.maxFrameSize {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "frame payload exceeds max frame size"}
	}

	// CONTINUATION state machine.
	if fr.inCont {
		if ftype != FrameContinuation || streamID != fr.contStreamID {
			return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "expected CONTINUATION frame"}
		}
	} else if ftype == FrameContinuation {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "unexpected CONTINUATION frame"}
	}

	// Read the full payload.
	totalLen := frameHeaderLen + int(length)
	if err := fr.fill(totalLen); err != nil {
		return nil, err
	}

	payload := fr.buf[fr.off+frameHeaderLen : fr.off+totalLen]
	fr.off += totalLen

	f.Type = ftype
	f.Flags = flags
	f.StreamID = streamID
	f.Length = length

	switch ftype {
	case FrameData:
		return fr.parseData(f, payload)
	case FrameHeaders:
		return fr.parseHeaders(f, payload)
	case FramePriority:
		return fr.parsePriority(f, payload)
	case FrameRSTStream:
		return fr.parseRSTStream(f, payload)
	case FrameSettings:
		return fr.parseSettings(f, payload)
	case FramePushPromise:
		return fr.parsePushPromise(f, payload)
	case FramePing:
		return fr.parsePing(f, payload)
	case FrameGoAway:
		return fr.parseGoAway(f, payload)
	case FrameWindowUpdate:
		return fr.parseWindowUpdate(f, payload)
	default:
		// Unknown frame types: return as-is per RFC 9113 §4.1.
		f.Data = payload
		return f, nil
	}
}

func (fr *FrameReader) parseData(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID == 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "DATA frame on stream 0"}
	}
	data := payload
	if f.Flags.Has(FlagPadded) {
		if len(payload) < 1 {
			return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "DATA PADDED but no pad length"}
		}
		padLen := int(payload[0])
		if padLen >= len(payload) {
			return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "DATA padding exceeds payload"}
		}
		data = payload[1 : len(payload)-padLen]
	}
	f.Data = data
	return f, nil
}

func (fr *FrameReader) parseHeaders(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID == 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "HEADERS frame on stream 0"}
	}
	pos := 0
	padLen := 0
	if f.Flags.Has(FlagPadded) {
		if len(payload) < 1 {
			return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "HEADERS PADDED but no pad length"}
		}
		padLen = int(payload[0])
		pos = 1
	}
	if f.Flags.Has(FlagPriority) {
		if len(payload)-pos < 5 {
			return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "HEADERS PRIORITY fields truncated"}
		}
		v := uint32(payload[pos])<<24 | uint32(payload[pos+1])<<16 | uint32(payload[pos+2])<<8 | uint32(payload[pos+3])
		f.Exclusive = v>>31 == 1
		f.StreamDep = v & 0x7FFFFFFF
		f.Weight = payload[pos+4]
		pos += 5
	}
	if padLen > len(payload)-pos {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "HEADERS padding exceeds payload"}
	}
	headerBlock := payload[pos : len(payload)-padLen]

	if f.Flags.Has(FlagEndHeaders) {
		f.HeaderBlock = headerBlock
		return f, nil
	}

	// Begin CONTINUATION assembly.
	fr.contBuf = append(fr.contBuf[:0], headerBlock...)
	fr.contStreamID = f.StreamID
	fr.inCont = true
	return fr.readContinuations(f)
}

func (fr *FrameReader) parsePriority(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID == 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "PRIORITY frame on stream 0"}
	}
	if len(payload) != 5 {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "PRIORITY frame must be 5 bytes"}
	}
	v := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	f.Exclusive = v>>31 == 1
	f.StreamDep = v & 0x7FFFFFFF
	f.Weight = payload[4]
	return f, nil
}

func (fr *FrameReader) parseRSTStream(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID == 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "RST_STREAM frame on stream 0"}
	}
	if len(payload) != 4 {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "RST_STREAM frame must be 4 bytes"}
	}
	f.ErrorCode = ErrorCode(uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3]))
	return f, nil
}

func (fr *FrameReader) parseSettings(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID != 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "SETTINGS frame on stream != 0"}
	}
	if f.Flags.Has(FlagACK) {
		if len(payload) != 0 {
			return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "SETTINGS ACK must have empty payload"}
		}
		return f, nil
	}
	if len(payload)%6 != 0 {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "SETTINGS payload not multiple of 6"}
	}
	n := len(payload) / 6
	if n > MaxSettingsPerFrame {
		return nil, &ConnError{Code: ErrCodeEnhanceYourCalm, Reason: "too many settings in frame"}
	}
	f.NumSettings = n
	for i := 0; i < n; i++ {
		off := i * 6
		f.Settings[i] = Setting{
			ID:    SettingsID(uint16(payload[off])<<8 | uint16(payload[off+1])),
			Value: uint32(payload[off+2])<<24 | uint32(payload[off+3])<<16 | uint32(payload[off+4])<<8 | uint32(payload[off+5]),
		}
	}
	return f, nil
}

func (fr *FrameReader) parsePushPromise(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID == 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "PUSH_PROMISE frame on stream 0"}
	}
	pos := 0
	padLen := 0
	if f.Flags.Has(FlagPadded) {
		if len(payload) < 1 {
			return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "PUSH_PROMISE PADDED but no pad length"}
		}
		padLen = int(payload[0])
		pos = 1
	}
	if len(payload)-pos < 4 {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "PUSH_PROMISE too short for promised stream ID"}
	}
	f.PromisedStreamID = (uint32(payload[pos])<<24 | uint32(payload[pos+1])<<16 | uint32(payload[pos+2])<<8 | uint32(payload[pos+3])) & 0x7FFFFFFF
	pos += 4
	if padLen > len(payload)-pos {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "PUSH_PROMISE padding exceeds payload"}
	}
	headerBlock := payload[pos : len(payload)-padLen]

	if f.Flags.Has(FlagEndHeaders) {
		f.HeaderBlock = headerBlock
		return f, nil
	}

	// Begin CONTINUATION assembly.
	fr.contBuf = append(fr.contBuf[:0], headerBlock...)
	fr.contStreamID = f.StreamID
	fr.inCont = true
	return fr.readContinuations(f)
}

func (fr *FrameReader) parsePing(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID != 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "PING frame on stream != 0"}
	}
	if len(payload) != 8 {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "PING frame must be 8 bytes"}
	}
	copy(f.PingData[:], payload)
	return f, nil
}

func (fr *FrameReader) parseGoAway(f *Frame, payload []byte) (*Frame, error) {
	if f.StreamID != 0 {
		return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "GOAWAY frame on stream != 0"}
	}
	if len(payload) < 8 {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "GOAWAY frame too short"}
	}
	f.LastStreamID = (uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])) & 0x7FFFFFFF
	f.ErrorCode = ErrorCode(uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7]))
	if len(payload) > 8 {
		f.DebugData = payload[8:]
	}
	return f, nil
}

func (fr *FrameReader) parseWindowUpdate(f *Frame, payload []byte) (*Frame, error) {
	if len(payload) != 4 {
		return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "WINDOW_UPDATE frame must be 4 bytes"}
	}
	f.WindowIncrement = (uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])) & 0x7FFFFFFF
	// Note: 0-increment validation is handled by the connection layer (conn.go)
	// because stream 0 requires a connection error while stream N requires a stream error.
	return f, nil
}

// readContinuations reads CONTINUATION frames until END_HEADERS.
func (fr *FrameReader) readContinuations(f *Frame) (*Frame, error) {
	for {
		// Read next frame header.
		if err := fr.fill(frameHeaderLen); err != nil {
			return nil, err
		}

		b := fr.buf[fr.off:]
		length := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		ftype := FrameType(b[3])
		flags := Flags(b[4])
		streamID := (uint32(b[5])<<24 | uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8])) & 0x7FFFFFFF

		if ftype != FrameContinuation || streamID != fr.contStreamID {
			return nil, &ConnError{Code: ErrCodeProtocolError, Reason: "expected CONTINUATION frame"}
		}
		if length > fr.maxFrameSize {
			return nil, &ConnError{Code: ErrCodeFrameSizeError, Reason: "CONTINUATION frame too large"}
		}

		totalLen := frameHeaderLen + int(length)
		if err := fr.fill(totalLen); err != nil {
			return nil, err
		}

		payload := fr.buf[fr.off+frameHeaderLen : fr.off+totalLen]
		fr.off += totalLen

		fr.contBuf = append(fr.contBuf, payload...)

		// Safety: prevent unbounded accumulation.
		if len(fr.contBuf) > int(fr.maxFrameSize)*64 {
			fr.inCont = false
			return nil, &ConnError{Code: ErrCodeEnhanceYourCalm, Reason: "assembled header block too large"}
		}

		if flags.Has(FlagEndHeaders) {
			fr.inCont = false
			f.Flags |= FlagEndHeaders
			f.HeaderBlock = fr.contBuf
			return f, nil
		}
	}
}
