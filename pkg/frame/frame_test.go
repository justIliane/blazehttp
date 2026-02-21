package frame

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// helper: write frames and read them back.
func writeAndRead(t *testing.T, writeFn func(fw *FrameWriter)) *Frame {
	t.Helper()
	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	writeFn(fw)
	if err := fw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	ReleaseFrameWriter(fw)

	fr := AcquireFrameReader(&buf)
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	// Copy fields we need since they point into the reader's buffer.
	return copyFrame(f)
}

// copyFrame copies a Frame's slice fields so they survive ReleaseFrameReader.
func copyFrame(f *Frame) *Frame {
	out := *f
	if f.Data != nil {
		out.Data = append([]byte(nil), f.Data...)
	}
	if f.HeaderBlock != nil {
		out.HeaderBlock = append([]byte(nil), f.HeaderBlock...)
	}
	if f.DebugData != nil {
		out.DebugData = append([]byte(nil), f.DebugData...)
	}
	return &out
}

// readError reads a frame and expects an error with the given error code.
func readError(t *testing.T, data []byte, wantCode ErrorCode) {
	t.Helper()
	fr := AcquireFrameReader(bytes.NewReader(data))
	defer ReleaseFrameReader(fr)
	_, err := fr.ReadFrame()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("expected ConnError, got %T: %v", err, err)
	}
	if ce.Code != wantCode {
		t.Fatalf("expected error code %v, got %v: %s", wantCode, ce.Code, ce.Reason)
	}
}

// encodeFrame is a helper to build raw frame bytes.
func encodeFrame(ftype FrameType, flags Flags, streamID uint32, payload []byte) []byte {
	length := len(payload)
	hdr := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		byte(ftype),
		byte(flags),
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	return append(hdr, payload...)
}

// ====================== ROUND-TRIP TESTS ======================

func TestRoundTrip_Data(t *testing.T) {
	tests := []struct {
		name      string
		streamID  uint32
		endStream bool
		data      []byte
	}{
		{"simple", 1, false, []byte("hello")},
		{"end_stream", 3, true, []byte("world")},
		{"empty", 1, false, nil},
		{"large", 1, false, bytes.Repeat([]byte("x"), 16384)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := writeAndRead(t, func(fw *FrameWriter) {
				fw.WriteData(tt.streamID, tt.endStream, tt.data)
			})
			if f.Type != FrameData {
				t.Fatalf("Type = %v, want DATA", f.Type)
			}
			if f.StreamID != tt.streamID {
				t.Fatalf("StreamID = %d, want %d", f.StreamID, tt.streamID)
			}
			if f.HasEndStream() != tt.endStream {
				t.Fatalf("EndStream = %v, want %v", f.HasEndStream(), tt.endStream)
			}
			if !bytes.Equal(f.Data, tt.data) {
				t.Fatalf("Data mismatch: got %d bytes, want %d", len(f.Data), len(tt.data))
			}
		})
	}
}

func TestRoundTrip_DataPadded(t *testing.T) {
	data := []byte("hello padded")
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteDataPadded(1, false, data, 10)
	})
	if f.Type != FrameData {
		t.Fatalf("Type = %v, want DATA", f.Type)
	}
	if !bytes.Equal(f.Data, data) {
		t.Fatalf("Data = %q, want %q", f.Data, data)
	}
}

func TestRoundTrip_Headers(t *testing.T) {
	headerBlock := []byte{0x82, 0x86, 0x84, 0x41, 0x8a, 0x08}
	tests := []struct {
		name      string
		streamID  uint32
		endStream bool
		priority  *PriorityParam
	}{
		{"simple", 1, false, nil},
		{"end_stream", 1, true, nil},
		{"with_priority", 1, false, &PriorityParam{Exclusive: true, StreamDep: 0, Weight: 255}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := writeAndRead(t, func(fw *FrameWriter) {
				fw.WriteHeaders(tt.streamID, tt.endStream, headerBlock, tt.priority)
			})
			if f.Type != FrameHeaders {
				t.Fatalf("Type = %v, want HEADERS", f.Type)
			}
			if f.StreamID != tt.streamID {
				t.Fatalf("StreamID = %d, want %d", f.StreamID, tt.streamID)
			}
			if f.HasEndStream() != tt.endStream {
				t.Fatalf("EndStream = %v, want %v", f.HasEndStream(), tt.endStream)
			}
			if !bytes.Equal(f.HeaderBlock, headerBlock) {
				t.Fatalf("HeaderBlock mismatch: got %x, want %x", f.HeaderBlock, headerBlock)
			}
			if tt.priority != nil {
				if f.Exclusive != tt.priority.Exclusive || f.StreamDep != tt.priority.StreamDep || f.Weight != tt.priority.Weight {
					t.Fatalf("Priority = {%v, %d, %d}, want {%v, %d, %d}",
						f.Exclusive, f.StreamDep, f.Weight,
						tt.priority.Exclusive, tt.priority.StreamDep, tt.priority.Weight)
				}
			}
		})
	}
}

func TestRoundTrip_HeadersPadded(t *testing.T) {
	headerBlock := []byte{0x82, 0x86}
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteHeadersPadded(1, false, headerBlock, nil, 5)
	})
	if f.Type != FrameHeaders {
		t.Fatalf("Type = %v, want HEADERS", f.Type)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("HeaderBlock = %x, want %x", f.HeaderBlock, headerBlock)
	}
}

func TestRoundTrip_HeadersPaddedWithPriority(t *testing.T) {
	headerBlock := []byte{0x82, 0x86}
	pri := &PriorityParam{Exclusive: false, StreamDep: 5, Weight: 128}
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteHeadersPadded(1, true, headerBlock, pri, 3)
	})
	if f.Type != FrameHeaders {
		t.Fatalf("Type = %v, want HEADERS", f.Type)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("HeaderBlock = %x, want %x", f.HeaderBlock, headerBlock)
	}
	if !f.HasEndStream() {
		t.Fatal("expected END_STREAM")
	}
	if f.StreamDep != 5 || f.Weight != 128 || f.Exclusive {
		t.Fatalf("Priority = {%v, %d, %d}, want {false, 5, 128}", f.Exclusive, f.StreamDep, f.Weight)
	}
}

func TestRoundTrip_Priority(t *testing.T) {
	p := PriorityParam{Exclusive: true, StreamDep: 7, Weight: 200}
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WritePriority(3, p)
	})
	if f.Type != FramePriority {
		t.Fatalf("Type = %v, want PRIORITY", f.Type)
	}
	if f.StreamID != 3 {
		t.Fatalf("StreamID = %d, want 3", f.StreamID)
	}
	if f.Exclusive != p.Exclusive || f.StreamDep != p.StreamDep || f.Weight != p.Weight {
		t.Fatalf("Priority = {%v, %d, %d}, want {%v, %d, %d}",
			f.Exclusive, f.StreamDep, f.Weight,
			p.Exclusive, p.StreamDep, p.Weight)
	}
}

func TestRoundTrip_RSTStream(t *testing.T) {
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteRSTStream(1, ErrCodeCancel)
	})
	if f.Type != FrameRSTStream {
		t.Fatalf("Type = %v, want RST_STREAM", f.Type)
	}
	if f.StreamID != 1 {
		t.Fatalf("StreamID = %d, want 1", f.StreamID)
	}
	if f.ErrorCode != ErrCodeCancel {
		t.Fatalf("ErrorCode = %v, want CANCEL", f.ErrorCode)
	}
}

func TestRoundTrip_Settings(t *testing.T) {
	settings := []Setting{
		{SettingsHeaderTableSize, 4096},
		{SettingsMaxConcurrentStreams, 100},
		{SettingsInitialWindowSize, 65535},
	}
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteSettings(settings...)
	})
	if f.Type != FrameSettings {
		t.Fatalf("Type = %v, want SETTINGS", f.Type)
	}
	if f.StreamID != 0 {
		t.Fatalf("StreamID = %d, want 0", f.StreamID)
	}
	if f.HasACK() {
		t.Fatal("unexpected ACK")
	}
	if f.NumSettings != len(settings) {
		t.Fatalf("NumSettings = %d, want %d", f.NumSettings, len(settings))
	}
	for i, s := range settings {
		if f.Settings[i] != s {
			t.Fatalf("Settings[%d] = %v, want %v", i, f.Settings[i], s)
		}
	}
}

func TestRoundTrip_SettingsACK(t *testing.T) {
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteSettingsACK()
	})
	if f.Type != FrameSettings {
		t.Fatalf("Type = %v, want SETTINGS", f.Type)
	}
	if !f.HasACK() {
		t.Fatal("expected ACK")
	}
	if f.NumSettings != 0 {
		t.Fatalf("NumSettings = %d, want 0", f.NumSettings)
	}
}

func TestRoundTrip_Ping(t *testing.T) {
	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, ack := range []bool{false, true} {
		name := "request"
		if ack {
			name = "ack"
		}
		t.Run(name, func(t *testing.T) {
			f := writeAndRead(t, func(fw *FrameWriter) {
				fw.WritePing(ack, data)
			})
			if f.Type != FramePing {
				t.Fatalf("Type = %v, want PING", f.Type)
			}
			if f.HasACK() != ack {
				t.Fatalf("ACK = %v, want %v", f.HasACK(), ack)
			}
			if f.PingData != data {
				t.Fatalf("PingData = %v, want %v", f.PingData, data)
			}
		})
	}
}

func TestRoundTrip_GoAway(t *testing.T) {
	tests := []struct {
		name         string
		lastStreamID uint32
		code         ErrorCode
		debugData    []byte
	}{
		{"no_debug", 7, ErrCodeNoError, nil},
		{"with_debug", 100, ErrCodeProtocolError, []byte("something went wrong")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := writeAndRead(t, func(fw *FrameWriter) {
				fw.WriteGoAway(tt.lastStreamID, tt.code, tt.debugData)
			})
			if f.Type != FrameGoAway {
				t.Fatalf("Type = %v, want GOAWAY", f.Type)
			}
			if f.LastStreamID != tt.lastStreamID {
				t.Fatalf("LastStreamID = %d, want %d", f.LastStreamID, tt.lastStreamID)
			}
			if f.ErrorCode != tt.code {
				t.Fatalf("ErrorCode = %v, want %v", f.ErrorCode, tt.code)
			}
			if !bytes.Equal(f.DebugData, tt.debugData) {
				t.Fatalf("DebugData = %q, want %q", f.DebugData, tt.debugData)
			}
		})
	}
}

func TestRoundTrip_WindowUpdate(t *testing.T) {
	tests := []struct {
		name      string
		streamID  uint32
		increment uint32
	}{
		{"connection", 0, 65535},
		{"stream", 1, 1000000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := writeAndRead(t, func(fw *FrameWriter) {
				fw.WriteWindowUpdate(tt.streamID, tt.increment)
			})
			if f.Type != FrameWindowUpdate {
				t.Fatalf("Type = %v, want WINDOW_UPDATE", f.Type)
			}
			if f.StreamID != tt.streamID {
				t.Fatalf("StreamID = %d, want %d", f.StreamID, tt.streamID)
			}
			if f.WindowIncrement != tt.increment {
				t.Fatalf("WindowIncrement = %d, want %d", f.WindowIncrement, tt.increment)
			}
		})
	}
}

func TestRoundTrip_PushPromise(t *testing.T) {
	headerBlock := []byte{0x82, 0x86, 0x84}
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WritePushPromise(1, 2, headerBlock)
	})
	if f.Type != FramePushPromise {
		t.Fatalf("Type = %v, want PUSH_PROMISE", f.Type)
	}
	if f.StreamID != 1 {
		t.Fatalf("StreamID = %d, want 1", f.StreamID)
	}
	if f.PromisedStreamID != 2 {
		t.Fatalf("PromisedStreamID = %d, want 2", f.PromisedStreamID)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("HeaderBlock = %x, want %x", f.HeaderBlock, headerBlock)
	}
}

// ====================== CONTINUATION TESTS ======================

func TestContinuation_SingleCont(t *testing.T) {
	// Build HEADERS without END_HEADERS + CONTINUATION with END_HEADERS.
	headerBlock := bytes.Repeat([]byte{0xAB}, 100)
	split := 40

	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	// Write HEADERS without END_HEADERS manually.
	fw.WriteRaw(FrameHeaders, FlagEndStream, 1, headerBlock[:split])
	fw.WriteRaw(FrameContinuation, FlagEndHeaders, 1, headerBlock[split:])
	fw.Flush()
	ReleaseFrameWriter(fw)

	fr := AcquireFrameReader(&buf)
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("assembled HeaderBlock: got %d bytes, want %d", len(f.HeaderBlock), len(headerBlock))
	}
	if !f.HasEndHeaders() {
		t.Fatal("expected END_HEADERS after assembly")
	}
}

func TestContinuation_MultipleCont(t *testing.T) {
	headerBlock := bytes.Repeat([]byte{0xCD}, 300)

	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	fw.WriteRaw(FrameHeaders, 0, 1, headerBlock[:100])
	fw.WriteRaw(FrameContinuation, 0, 1, headerBlock[100:200])
	fw.WriteRaw(FrameContinuation, FlagEndHeaders, 1, headerBlock[200:])
	fw.Flush()
	ReleaseFrameWriter(fw)

	fr := AcquireFrameReader(&buf)
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("assembled HeaderBlock: got %d bytes, want %d", len(f.HeaderBlock), len(headerBlock))
	}
}

func TestContinuation_WrongStream(t *testing.T) {
	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	fw.WriteRaw(FrameHeaders, 0, 1, []byte{0x82}) // no END_HEADERS
	fw.WriteRaw(FrameContinuation, FlagEndHeaders, 3, []byte{0x86}) // wrong stream
	fw.Flush()
	ReleaseFrameWriter(fw)

	fr := AcquireFrameReader(&buf)
	defer ReleaseFrameReader(fr)
	_, err := fr.ReadFrame()
	var ce *ConnError
	if !errors.As(err, &ce) || ce.Code != ErrCodeProtocolError {
		t.Fatalf("expected PROTOCOL_ERROR, got %v", err)
	}
}

func TestContinuation_Unexpected(t *testing.T) {
	data := encodeFrame(FrameContinuation, FlagEndHeaders, 1, []byte{0x82})
	readError(t, data, ErrCodeProtocolError)
}

func TestContinuation_MissingAfterHeaders(t *testing.T) {
	// HEADERS without END_HEADERS followed by a DATA frame (not CONTINUATION).
	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	fw.WriteRaw(FrameHeaders, 0, 1, []byte{0x82}) // no END_HEADERS
	fw.WriteData(1, false, []byte("data"))
	fw.Flush()
	ReleaseFrameWriter(fw)

	fr := AcquireFrameReader(&buf)
	defer ReleaseFrameReader(fr)
	_, err := fr.ReadFrame()
	var ce *ConnError
	if !errors.As(err, &ce) || ce.Code != ErrCodeProtocolError {
		t.Fatalf("expected PROTOCOL_ERROR, got %v", err)
	}
}

// ====================== HEADERS FRAGMENTATION TESTS ======================

func TestWriteHeaders_Fragmentation(t *testing.T) {
	// Create a header block larger than max frame size.
	maxSize := uint32(100)
	headerBlock := bytes.Repeat([]byte{0xAB}, 250)

	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	fw.SetMaxFrameSize(DefaultMaxFrameSize) // Reset to default since SetMaxFrameSize clamps
	fw.maxFrameSize = maxSize               // Override for test
	fw.WriteHeaders(1, true, headerBlock, nil)
	fw.Flush()
	ReleaseFrameWriter(fw)

	// Read back: should be assembled into one header block.
	fr := AcquireFrameReader(&buf)
	fr.maxFrameSize = maxSize
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("assembled HeaderBlock: got %d bytes, want %d", len(f.HeaderBlock), len(headerBlock))
	}
	if !f.HasEndStream() {
		t.Fatal("expected END_STREAM")
	}
}

func TestWriteHeaders_ExactFit(t *testing.T) {
	// Header block exactly maxFrameSize: should be single HEADERS frame.
	headerBlock := bytes.Repeat([]byte{0xAB}, DefaultMaxFrameSize)
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteHeaders(1, false, headerBlock, nil)
	})
	if f.Type != FrameHeaders {
		t.Fatalf("Type = %v, want HEADERS", f.Type)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("HeaderBlock length = %d, want %d", len(f.HeaderBlock), len(headerBlock))
	}
}

func TestWritePushPromise_Fragmentation(t *testing.T) {
	maxSize := uint32(100)
	headerBlock := bytes.Repeat([]byte{0xEF}, 250)

	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	fw.maxFrameSize = maxSize
	fw.WritePushPromise(1, 2, headerBlock)
	fw.Flush()
	ReleaseFrameWriter(fw)

	fr := AcquireFrameReader(&buf)
	fr.maxFrameSize = maxSize
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.PromisedStreamID != 2 {
		t.Fatalf("PromisedStreamID = %d, want 2", f.PromisedStreamID)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("assembled HeaderBlock: got %d bytes, want %d", len(f.HeaderBlock), len(headerBlock))
	}
}

// ====================== CONFORMANCE TESTS ======================

func TestConformance_DataOnStream0(t *testing.T) {
	data := encodeFrame(FrameData, 0, 0, []byte("hello"))
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_HeadersOnStream0(t *testing.T) {
	data := encodeFrame(FrameHeaders, FlagEndHeaders, 0, []byte{0x82})
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_SettingsOnNonZeroStream(t *testing.T) {
	data := encodeFrame(FrameSettings, 0, 1, make([]byte, 6))
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_PingWrongSize(t *testing.T) {
	data := encodeFrame(FramePing, 0, 0, []byte{1, 2, 3}) // 3 bytes, should be 8
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_PingOnNonZeroStream(t *testing.T) {
	data := encodeFrame(FramePing, 0, 1, make([]byte, 8))
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_WindowUpdateZero(t *testing.T) {
	data := encodeFrame(FrameWindowUpdate, 0, 1, []byte{0, 0, 0, 0})
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_WindowUpdateWrongSize(t *testing.T) {
	data := encodeFrame(FrameWindowUpdate, 0, 1, []byte{0, 0, 1})
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_FrameTooLarge(t *testing.T) {
	// Encode a frame header claiming 16385 bytes payload.
	hdr := []byte{0, 0x40, 0x01, byte(FrameData), 0, 0, 0, 0, 1} // length=16385
	readError(t, hdr, ErrCodeFrameSizeError)
}

func TestConformance_SettingsACKNonEmpty(t *testing.T) {
	data := encodeFrame(FrameSettings, FlagACK, 0, make([]byte, 6))
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_SettingsInvalidLength(t *testing.T) {
	data := encodeFrame(FrameSettings, 0, 0, make([]byte, 7)) // not multiple of 6
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_PriorityWrongSize(t *testing.T) {
	data := encodeFrame(FramePriority, 0, 1, make([]byte, 3)) // should be 5
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_PriorityOnStream0(t *testing.T) {
	data := encodeFrame(FramePriority, 0, 0, make([]byte, 5))
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_RSTStreamWrongSize(t *testing.T) {
	data := encodeFrame(FrameRSTStream, 0, 1, make([]byte, 3)) // should be 4
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_RSTStreamOnStream0(t *testing.T) {
	data := encodeFrame(FrameRSTStream, 0, 0, make([]byte, 4))
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_GoAwayOnNonZeroStream(t *testing.T) {
	data := encodeFrame(FrameGoAway, 0, 1, make([]byte, 8))
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_GoAwayTooShort(t *testing.T) {
	data := encodeFrame(FrameGoAway, 0, 0, make([]byte, 4))
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_PushPromiseOnStream0(t *testing.T) {
	data := encodeFrame(FramePushPromise, FlagEndHeaders, 0, make([]byte, 4))
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_PushPromiseTooShort(t *testing.T) {
	data := encodeFrame(FramePushPromise, FlagEndHeaders, 1, make([]byte, 2))
	readError(t, data, ErrCodeFrameSizeError)
}

func TestConformance_DataPaddingExceedsPayload(t *testing.T) {
	// PADDED DATA with padLen = 10, but only 5 bytes total (padLen byte + 4 data bytes).
	payload := []byte{10, 1, 2, 3, 4} // padLen=10, but only 4 data bytes remain
	data := encodeFrame(FrameData, FlagPadded, 1, payload)
	readError(t, data, ErrCodeProtocolError)
}

func TestConformance_HeadersPaddingExceedsPayload(t *testing.T) {
	payload := []byte{100, 0x82} // padLen=100, only 1 byte of header block
	data := encodeFrame(FrameHeaders, FlagPadded|FlagEndHeaders, 1, payload)
	readError(t, data, ErrCodeProtocolError)
}

// ====================== UNKNOWN FRAME TYPE ======================

func TestUnknownFrameType(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	data := encodeFrame(FrameType(0xFF), 0x03, 1, payload)
	fr := AcquireFrameReader(bytes.NewReader(data))
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("expected no error for unknown frame type, got %v", err)
	}
	if f.Type != FrameType(0xFF) {
		t.Fatalf("Type = %v, want 0xFF", f.Type)
	}
	if !bytes.Equal(f.Data, payload) {
		t.Fatalf("Data = %v, want %v", f.Data, payload)
	}
}

// ====================== POOL TESTS ======================

func TestAcquireReleaseFrameWriter(t *testing.T) {
	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	fw.WriteSettingsACK()
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}
	ReleaseFrameWriter(fw)
	if buf.Len() != 9 {
		t.Fatalf("expected 9 bytes, got %d", buf.Len())
	}
}

func TestAcquireReleaseFrameReader(t *testing.T) {
	data := encodeFrame(FramePing, 0, 0, make([]byte, 8))
	fr := AcquireFrameReader(bytes.NewReader(data))
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FramePing {
		t.Fatalf("Type = %v, want PING", f.Type)
	}
	ReleaseFrameReader(fr)
}

// ====================== MULTIPLE FRAMES ======================

func TestMultipleFramesSequential(t *testing.T) {
	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	fw.WriteSettingsACK()
	fw.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	fw.WriteWindowUpdate(0, 65535)
	fw.WriteData(1, true, []byte("hello"))
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}
	ReleaseFrameWriter(fw)

	fr := AcquireFrameReader(&buf)
	defer ReleaseFrameReader(fr)

	// Frame 1: SETTINGS ACK
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FrameSettings || !f.HasACK() {
		t.Fatalf("expected SETTINGS ACK, got %v", f.Type)
	}

	// Frame 2: PING
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FramePing {
		t.Fatalf("expected PING, got %v", f.Type)
	}

	// Frame 3: WINDOW_UPDATE
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FrameWindowUpdate {
		t.Fatalf("expected WINDOW_UPDATE, got %v", f.Type)
	}

	// Frame 4: DATA
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FrameData {
		t.Fatalf("expected DATA, got %v", f.Type)
	}
	if string(f.Data) != "hello" {
		t.Fatalf("Data = %q, want hello", f.Data)
	}

	// EOF
	_, err = fr.ReadFrame()
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// ====================== EDGE CASES ======================

func TestReadFrame_Empty(t *testing.T) {
	fr := AcquireFrameReader(bytes.NewReader(nil))
	defer ReleaseFrameReader(fr)
	_, err := fr.ReadFrame()
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestReadFrame_Truncated(t *testing.T) {
	// Only 5 bytes, need 9 for header.
	fr := AcquireFrameReader(bytes.NewReader([]byte{0, 0, 0, 0, 0}))
	defer ReleaseFrameReader(fr)
	_, err := fr.ReadFrame()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	// Frame header says 10 bytes payload, but only 5 available.
	hdr := encodeFrame(FrameData, 0, 1, nil)
	hdr[2] = 10 // override length to 10
	data := append(hdr, []byte("hello")...) // only 5 bytes of payload
	fr := AcquireFrameReader(bytes.NewReader(data))
	defer ReleaseFrameReader(fr)
	_, err := fr.ReadFrame()
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

func TestFrameTypeString(t *testing.T) {
	if FrameData.String() != "DATA" {
		t.Fatalf("DATA.String() = %q", FrameData.String())
	}
	if FrameType(0xFF).String() != "UNKNOWN" {
		t.Fatalf("0xFF.String() = %q", FrameType(0xFF).String())
	}
}

func TestErrorCodeString(t *testing.T) {
	if ErrCodeProtocolError.String() != "PROTOCOL_ERROR" {
		t.Fatalf("PROTOCOL_ERROR.String() = %q", ErrCodeProtocolError.String())
	}
	if ErrorCode(0xFF).String() != "UNKNOWN_ERROR" {
		t.Fatalf("0xFF.String() = %q", ErrorCode(0xFF).String())
	}
}

func TestConnErrorString(t *testing.T) {
	ce := &ConnError{Code: ErrCodeProtocolError, Reason: "bad frame"}
	s := ce.Error()
	if s != "http2: connection error: PROTOCOL_ERROR: bad frame" {
		t.Fatalf("ConnError.Error() = %q", s)
	}
}

func TestFlagsHas(t *testing.T) {
	f := FlagEndStream | FlagPadded
	if !f.Has(FlagEndStream) {
		t.Fatal("should have END_STREAM")
	}
	if f.Has(FlagEndHeaders) {
		t.Fatal("should not have END_HEADERS")
	}
}

func TestFrameReset(t *testing.T) {
	f := &Frame{
		Type:            FrameData,
		Flags:           FlagEndStream,
		StreamID:        1,
		Length:           5,
		Data:            []byte("hello"),
		WindowIncrement: 100,
	}
	f.Reset()
	if f.Type != 0 || f.Flags != 0 || f.StreamID != 0 || f.Length != 0 || f.Data != nil || f.WindowIncrement != 0 {
		t.Fatal("Reset did not clear all fields")
	}
}

func TestSetMaxFrameSize(t *testing.T) {
	fr := newFrameReader()
	fr.SetMaxFrameSize(100) // below minimum, should clamp
	if fr.MaxFrameSize() != DefaultMaxFrameSize {
		t.Fatalf("MaxFrameSize = %d, want %d", fr.MaxFrameSize(), DefaultMaxFrameSize)
	}
	fr.SetMaxFrameSize(MaxMaxFrameSize + 1) // above maximum, should clamp
	if fr.MaxFrameSize() != MaxMaxFrameSize {
		t.Fatalf("MaxFrameSize = %d, want %d", fr.MaxFrameSize(), MaxMaxFrameSize)
	}
	fr.SetMaxFrameSize(32768)
	if fr.MaxFrameSize() != 32768 {
		t.Fatalf("MaxFrameSize = %d, want 32768", fr.MaxFrameSize())
	}

	fw := newFrameWriter()
	fw.SetMaxFrameSize(100)
	if fw.MaxFrameSize() != DefaultMaxFrameSize {
		t.Fatalf("MaxFrameSize = %d, want %d", fw.MaxFrameSize(), DefaultMaxFrameSize)
	}
}

func TestWriterBuffered(t *testing.T) {
	fw := newFrameWriter()
	if fw.Buffered() != 0 {
		t.Fatalf("Buffered = %d, want 0", fw.Buffered())
	}
	fw.WriteSettingsACK()
	if fw.Buffered() != 9 {
		t.Fatalf("Buffered = %d, want 9", fw.Buffered())
	}
	fw.Reset()
	if fw.Buffered() != 0 {
		t.Fatalf("Buffered = %d after Reset, want 0", fw.Buffered())
	}
}

func TestWriterFlushEmpty(t *testing.T) {
	var buf bytes.Buffer
	fw := AcquireFrameWriter(&buf)
	defer ReleaseFrameWriter(fw)
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty flush, got %d bytes", buf.Len())
	}
}

func TestWriteRaw(t *testing.T) {
	payload := []byte{1, 2, 3}
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteRaw(FrameType(0xFE), 0x03, 42, payload)
	})
	if f.Type != FrameType(0xFE) {
		t.Fatalf("Type = %v, want 0xFE", f.Type)
	}
	if f.StreamID != 42 {
		t.Fatalf("StreamID = %d, want 42", f.StreamID)
	}
	if !bytes.Equal(f.Data, payload) {
		t.Fatalf("Data = %v, want %v", f.Data, payload)
	}
}

// Test reading a valid HEADERS frame with PADDED but empty after stripping.
func TestHeaders_PaddedEmptyBlock(t *testing.T) {
	// Pad length = 0, so header block is all remaining data.
	payload := []byte{0, 0x82, 0x86} // padLen=0, headerBlock=0x82 0x86
	data := encodeFrame(FrameHeaders, FlagPadded|FlagEndHeaders, 1, payload)
	fr := AcquireFrameReader(bytes.NewReader(data))
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.HeaderBlock, []byte{0x82, 0x86}) {
		t.Fatalf("HeaderBlock = %x, want 8286", f.HeaderBlock)
	}
}

// Test that the reserved bit in stream ID is masked off.
func TestReservedBitMasked(t *testing.T) {
	// Write a frame where the stream ID has the reserved bit set (0x80000001).
	hdr := []byte{0, 0, 0, byte(FrameData), 0, 0x80, 0x00, 0x00, 0x01}
	fr := AcquireFrameReader(bytes.NewReader(hdr))
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.StreamID != 1 {
		t.Fatalf("StreamID = 0x%X, want 0x1", f.StreamID)
	}
}

// Test DATA with PADDED flag and no remaining payload after padding.
func TestData_PaddedNoData(t *testing.T) {
	// padLen=5, plus 5 zero bytes of padding, no data.
	payload := make([]byte, 6) // padLen=5, then 5 zero bytes
	payload[0] = 5
	data := encodeFrame(FrameData, FlagPadded, 1, payload)
	fr := AcquireFrameReader(bytes.NewReader(data))
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Data) != 0 {
		t.Fatalf("expected empty Data, got %d bytes", len(f.Data))
	}
}

// Test PUSH_PROMISE with padding.
func TestPushPromise_Padded(t *testing.T) {
	// Build manually: padLen(1) + promisedStreamID(4) + headerBlock + padding
	headerBlock := []byte{0x82, 0x86}
	padLen := byte(3)
	payload := make([]byte, 0, 1+4+len(headerBlock)+int(padLen))
	payload = append(payload, padLen)
	payload = append(payload, 0, 0, 0, 2) // promised stream ID = 2
	payload = append(payload, headerBlock...)
	payload = append(payload, 0, 0, 0) // 3 bytes padding

	data := encodeFrame(FramePushPromise, FlagPadded|FlagEndHeaders, 1, payload)
	fr := AcquireFrameReader(bytes.NewReader(data))
	defer ReleaseFrameReader(fr)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.PromisedStreamID != 2 {
		t.Fatalf("PromisedStreamID = %d, want 2", f.PromisedStreamID)
	}
	if !bytes.Equal(f.HeaderBlock, headerBlock) {
		t.Fatalf("HeaderBlock = %x, want %x", f.HeaderBlock, headerBlock)
	}
}

// Test settings with many parameters.
func TestSettings_ManyParams(t *testing.T) {
	settings := make([]Setting, 10)
	for i := range settings {
		settings[i] = Setting{ID: SettingsID(i + 1), Value: uint32(i * 1000)}
	}
	f := writeAndRead(t, func(fw *FrameWriter) {
		fw.WriteSettings(settings...)
	})
	if f.NumSettings != 10 {
		t.Fatalf("NumSettings = %d, want 10", f.NumSettings)
	}
	for i := 0; i < 10; i++ {
		if f.Settings[i] != settings[i] {
			t.Fatalf("Settings[%d] = %v, want %v", i, f.Settings[i], settings[i])
		}
	}
}

// Test HEADERS with PRIORITY flag truncated.
func TestHeaders_PriorityTruncated(t *testing.T) {
	// HEADERS with PRIORITY flag but only 3 bytes (need 5 for priority fields).
	payload := []byte{0x82, 0x86, 0x84}
	data := encodeFrame(FrameHeaders, FlagPriority|FlagEndHeaders, 1, payload)
	readError(t, data, ErrCodeFrameSizeError)
}

// Test DATA PADDED with empty payload (no pad length byte).
func TestData_PaddedEmpty(t *testing.T) {
	data := encodeFrame(FrameData, FlagPadded, 1, nil)
	readError(t, data, ErrCodeFrameSizeError)
}

// Test HEADERS PADDED with empty payload.
func TestHeaders_PaddedEmpty(t *testing.T) {
	data := encodeFrame(FrameHeaders, FlagPadded|FlagEndHeaders, 1, nil)
	readError(t, data, ErrCodeFrameSizeError)
}

// Test PushPromise PADDED with empty payload.
func TestPushPromise_PaddedEmpty(t *testing.T) {
	data := encodeFrame(FramePushPromise, FlagPadded|FlagEndHeaders, 1, nil)
	readError(t, data, ErrCodeFrameSizeError)
}

// Test PUSH_PROMISE padding exceeds payload.
func TestPushPromise_PaddingExceeds(t *testing.T) {
	payload := []byte{100, 0, 0, 0, 2, 0x82} // padLen=100, but only 1 byte after promised ID
	data := encodeFrame(FramePushPromise, FlagPadded|FlagEndHeaders, 1, payload)
	readError(t, data, ErrCodeProtocolError)
}
