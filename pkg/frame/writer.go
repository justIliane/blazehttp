package frame

import (
	"io"
	"sync"
)

// FrameWriter encodes HTTP/2 frames into a batched write buffer.
// Frames are accumulated and flushed together to reduce syscalls.
type FrameWriter struct {
	w            io.Writer
	buf          []byte
	maxFrameSize uint32
}

var writerPool = sync.Pool{
	New: func() any {
		return newFrameWriter()
	},
}

// AcquireFrameWriter gets a FrameWriter from the pool.
func AcquireFrameWriter(w io.Writer) *FrameWriter {
	fw := writerPool.Get().(*FrameWriter)
	fw.w = w
	return fw
}

// ReleaseFrameWriter returns a FrameWriter to the pool.
func ReleaseFrameWriter(fw *FrameWriter) {
	fw.w = nil
	fw.buf = fw.buf[:0]
	fw.maxFrameSize = DefaultMaxFrameSize
	writerPool.Put(fw)
}

func newFrameWriter() *FrameWriter {
	return &FrameWriter{
		buf:          make([]byte, 0, DefaultMaxFrameSize+frameHeaderLen+256),
		maxFrameSize: DefaultMaxFrameSize,
	}
}

// Reset clears the write buffer.
func (fw *FrameWriter) Reset() {
	fw.buf = fw.buf[:0]
}

// SetMaxFrameSize sets the maximum frame payload size for fragmentation.
func (fw *FrameWriter) SetMaxFrameSize(size uint32) {
	if size < DefaultMaxFrameSize {
		size = DefaultMaxFrameSize
	}
	if size > MaxMaxFrameSize {
		size = MaxMaxFrameSize
	}
	fw.maxFrameSize = size
}

// MaxFrameSize returns the current maximum frame payload size.
func (fw *FrameWriter) MaxFrameSize() uint32 {
	return fw.maxFrameSize
}

// Flush writes all buffered frames to the underlying writer.
func (fw *FrameWriter) Flush() error {
	if len(fw.buf) == 0 {
		return nil
	}
	_, err := fw.w.Write(fw.buf)
	fw.buf = fw.buf[:0]
	return err
}

// Buffered returns the number of bytes buffered.
func (fw *FrameWriter) Buffered() int {
	return len(fw.buf)
}

// appendFrameHeader appends a 9-byte frame header to dst.
func appendFrameHeader(dst []byte, length uint32, ftype FrameType, flags Flags, streamID uint32) []byte {
	return append(dst,
		byte(length>>16), byte(length>>8), byte(length),
		byte(ftype),
		byte(flags),
		byte(streamID>>24), byte(streamID>>16), byte(streamID>>8), byte(streamID),
	)
}

// WriteData writes a DATA frame.
func (fw *FrameWriter) WriteData(streamID uint32, endStream bool, data []byte) {
	flags := Flags(0)
	if endStream {
		flags |= FlagEndStream
	}
	fw.buf = appendFrameHeader(fw.buf, uint32(len(data)), FrameData, flags, streamID)
	fw.buf = append(fw.buf, data...)
}

// WriteDataPadded writes a DATA frame with padding.
func (fw *FrameWriter) WriteDataPadded(streamID uint32, endStream bool, data []byte, padLen uint8) {
	length := 1 + uint32(len(data)) + uint32(padLen)
	flags := FlagPadded
	if endStream {
		flags |= FlagEndStream
	}
	fw.buf = appendFrameHeader(fw.buf, length, FrameData, flags, streamID)
	fw.buf = append(fw.buf, padLen)
	fw.buf = append(fw.buf, data...)
	fw.buf = appendZeros(fw.buf, int(padLen))
}

// WriteHeaders writes a HEADERS frame, automatically fragmenting into
// CONTINUATION frames if the header block exceeds maxFrameSize.
func (fw *FrameWriter) WriteHeaders(streamID uint32, endStream bool, headerBlock []byte, priority *PriorityParam) {
	flags := Flags(0)
	if endStream {
		flags |= FlagEndStream
	}

	overhead := 0
	if priority != nil {
		flags |= FlagPriority
		overhead = 5
	}

	maxPayload := int(fw.maxFrameSize)
	available := maxPayload - overhead

	if len(headerBlock) <= available {
		// Single HEADERS frame with END_HEADERS.
		flags |= FlagEndHeaders
		fw.buf = appendFrameHeader(fw.buf, uint32(overhead+len(headerBlock)), FrameHeaders, flags, streamID)
		if priority != nil {
			fw.buf = appendPriority(fw.buf, priority)
		}
		fw.buf = append(fw.buf, headerBlock...)
		return
	}

	// Fragmented: HEADERS without END_HEADERS + CONTINUATION(s).
	fw.buf = appendFrameHeader(fw.buf, uint32(overhead+available), FrameHeaders, flags, streamID)
	if priority != nil {
		fw.buf = appendPriority(fw.buf, priority)
	}
	fw.buf = append(fw.buf, headerBlock[:available]...)
	remaining := headerBlock[available:]

	for len(remaining) > 0 {
		chunk := remaining
		contFlags := FlagEndHeaders
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
			contFlags = 0
		}
		fw.buf = appendFrameHeader(fw.buf, uint32(len(chunk)), FrameContinuation, contFlags, streamID)
		fw.buf = append(fw.buf, chunk...)
		remaining = remaining[len(chunk):]
	}
}

// WriteHeadersPadded writes a HEADERS frame with padding.
// Does not fragment (caller must ensure the padded frame fits within maxFrameSize).
func (fw *FrameWriter) WriteHeadersPadded(streamID uint32, endStream bool, headerBlock []byte, priority *PriorityParam, padLen uint8) {
	flags := FlagPadded | FlagEndHeaders
	if endStream {
		flags |= FlagEndStream
	}

	overhead := 1 // pad length byte
	if priority != nil {
		flags |= FlagPriority
		overhead += 5
	}

	length := uint32(overhead + len(headerBlock) + int(padLen))
	fw.buf = appendFrameHeader(fw.buf, length, FrameHeaders, flags, streamID)
	fw.buf = append(fw.buf, padLen)
	if priority != nil {
		fw.buf = appendPriority(fw.buf, priority)
	}
	fw.buf = append(fw.buf, headerBlock...)
	fw.buf = appendZeros(fw.buf, int(padLen))
}

// WritePriority writes a PRIORITY frame.
func (fw *FrameWriter) WritePriority(streamID uint32, p PriorityParam) {
	fw.buf = appendFrameHeader(fw.buf, 5, FramePriority, 0, streamID)
	fw.buf = appendPriority(fw.buf, &p)
}

// WriteRSTStream writes a RST_STREAM frame.
func (fw *FrameWriter) WriteRSTStream(streamID uint32, code ErrorCode) {
	fw.buf = appendFrameHeader(fw.buf, 4, FrameRSTStream, 0, streamID)
	fw.buf = appendUint32(fw.buf, uint32(code))
}

// WriteSettings writes a SETTINGS frame.
func (fw *FrameWriter) WriteSettings(settings ...Setting) {
	length := uint32(len(settings) * 6)
	fw.buf = appendFrameHeader(fw.buf, length, FrameSettings, 0, 0)
	for i := range settings {
		s := &settings[i]
		fw.buf = append(fw.buf, byte(s.ID>>8), byte(s.ID))
		fw.buf = appendUint32(fw.buf, s.Value)
	}
}

// WriteSettingsACK writes a SETTINGS ACK frame.
func (fw *FrameWriter) WriteSettingsACK() {
	fw.buf = appendFrameHeader(fw.buf, 0, FrameSettings, FlagACK, 0)
}

// WritePushPromise writes a PUSH_PROMISE frame, automatically fragmenting
// into CONTINUATION frames if the header block exceeds maxFrameSize.
func (fw *FrameWriter) WritePushPromise(streamID, promisedStreamID uint32, headerBlock []byte) {
	overhead := 4 // promised stream ID
	maxPayload := int(fw.maxFrameSize)
	available := maxPayload - overhead

	if len(headerBlock) <= available {
		flags := FlagEndHeaders
		fw.buf = appendFrameHeader(fw.buf, uint32(overhead+len(headerBlock)), FramePushPromise, flags, streamID)
		fw.buf = appendUint32(fw.buf, promisedStreamID&0x7FFFFFFF)
		fw.buf = append(fw.buf, headerBlock...)
		return
	}

	// Fragmented.
	fw.buf = appendFrameHeader(fw.buf, uint32(overhead+available), FramePushPromise, 0, streamID)
	fw.buf = appendUint32(fw.buf, promisedStreamID&0x7FFFFFFF)
	fw.buf = append(fw.buf, headerBlock[:available]...)
	remaining := headerBlock[available:]

	for len(remaining) > 0 {
		chunk := remaining
		contFlags := FlagEndHeaders
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
			contFlags = 0
		}
		fw.buf = appendFrameHeader(fw.buf, uint32(len(chunk)), FrameContinuation, contFlags, streamID)
		fw.buf = append(fw.buf, chunk...)
		remaining = remaining[len(chunk):]
	}
}

// WritePing writes a PING frame.
func (fw *FrameWriter) WritePing(ack bool, data [8]byte) {
	flags := Flags(0)
	if ack {
		flags = FlagACK
	}
	fw.buf = appendFrameHeader(fw.buf, 8, FramePing, flags, 0)
	fw.buf = append(fw.buf, data[:]...)
}

// WriteGoAway writes a GOAWAY frame.
func (fw *FrameWriter) WriteGoAway(lastStreamID uint32, code ErrorCode, debugData []byte) {
	length := uint32(8 + len(debugData))
	fw.buf = appendFrameHeader(fw.buf, length, FrameGoAway, 0, 0)
	fw.buf = appendUint32(fw.buf, lastStreamID&0x7FFFFFFF)
	fw.buf = appendUint32(fw.buf, uint32(code))
	fw.buf = append(fw.buf, debugData...)
}

// WriteWindowUpdate writes a WINDOW_UPDATE frame.
func (fw *FrameWriter) WriteWindowUpdate(streamID uint32, increment uint32) {
	fw.buf = appendFrameHeader(fw.buf, 4, FrameWindowUpdate, 0, streamID)
	fw.buf = appendUint32(fw.buf, increment&0x7FFFFFFF)
}

// WriteRaw writes a raw frame with the given header fields and payload.
// Useful for testing or forwarding unknown frame types.
func (fw *FrameWriter) WriteRaw(ftype FrameType, flags Flags, streamID uint32, payload []byte) {
	fw.buf = appendFrameHeader(fw.buf, uint32(len(payload)), ftype, flags, streamID)
	fw.buf = append(fw.buf, payload...)
}

// appendPriority appends the 5-byte priority fields.
func appendPriority(dst []byte, p *PriorityParam) []byte {
	v := p.StreamDep & 0x7FFFFFFF
	if p.Exclusive {
		v |= 0x80000000
	}
	dst = append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v), p.Weight)
	return dst
}

// appendUint32 appends a 32-bit big-endian integer.
func appendUint32(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendZeros appends n zero bytes.
func appendZeros(dst []byte, n int) []byte {
	for i := 0; i < n; i++ {
		dst = append(dst, 0)
	}
	return dst
}
