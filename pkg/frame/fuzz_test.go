package frame

import (
	"bytes"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	// Valid frame seeds.
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WriteData(1, false, []byte("hello"))
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WriteHeaders(1, true, []byte{0x82, 0x86}, nil)
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WritePriority(1, PriorityParam{Exclusive: true, StreamDep: 0, Weight: 255})
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WriteRSTStream(1, ErrCodeCancel)
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WriteSettings(Setting{SettingsMaxFrameSize, 32768})
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WriteSettingsACK()
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WriteGoAway(1, ErrCodeNoError, []byte("debug"))
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WriteWindowUpdate(1, 65535)
	}))
	f.Add(encodeForFuzz(func(fw *FrameWriter) {
		fw.WritePushPromise(1, 2, []byte{0x82})
	}))

	// Malformed seeds.
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0}) // zero-length frame
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(bytes.Repeat([]byte{0}, 100))
	f.Add([]byte{0, 0, 5, byte(FrameData), 0, 0, 0, 0, 1, 1, 2, 3, 4, 5}) // valid DATA

	f.Fuzz(func(t *testing.T, data []byte) {
		fr := AcquireFrameReader(bytes.NewReader(data))
		defer ReleaseFrameReader(fr)
		// Must never panic.
		_, _ = fr.ReadFrame()
	})
}

func encodeForFuzz(writeFn func(fw *FrameWriter)) []byte {
	fw := newFrameWriter()
	writeFn(fw)
	return append([]byte(nil), fw.buf...)
}
