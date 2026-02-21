package frame

import (
	"bytes"
	"testing"
)

// bytesReaderResettable wraps pre-encoded frame bytes for benchmark reads.
type bytesReaderResettable struct {
	data []byte
	off  int
}

func (r *bytesReaderResettable) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, bytes.ErrTooLarge // signal done
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func (r *bytesReaderResettable) Reset() {
	r.off = 0
}

// encodeForBench encodes a frame and returns the raw bytes.
func encodeForBench(writeFn func(fw *FrameWriter)) []byte {
	fw := newFrameWriter()
	writeFn(fw)
	return append([]byte(nil), fw.buf...)
}

// ====================== WRITE BENCHMARKS ======================

func BenchmarkWriteData(b *testing.B) {
	fw := newFrameWriter()
	data := []byte("Hello, World!")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WriteData(1, false, data)
	}
}

func BenchmarkWriteHeaders(b *testing.B) {
	fw := newFrameWriter()
	headerBlock := []byte{0x82, 0x86, 0x84, 0x41, 0x8a, 0x08, 0x9d, 0x5c}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WriteHeaders(1, true, headerBlock, nil)
	}
}

func BenchmarkWriteSettings(b *testing.B) {
	fw := newFrameWriter()
	settings := []Setting{
		{SettingsHeaderTableSize, 4096},
		{SettingsMaxConcurrentStreams, 100},
		{SettingsInitialWindowSize, 65535},
		{SettingsMaxFrameSize, 16384},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WriteSettings(settings...)
	}
}

func BenchmarkWritePing(b *testing.B) {
	fw := newFrameWriter()
	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WritePing(false, data)
	}
}

func BenchmarkWriteWindowUpdate(b *testing.B) {
	fw := newFrameWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WriteWindowUpdate(0, 65535)
	}
}

func BenchmarkWriteRSTStream(b *testing.B) {
	fw := newFrameWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WriteRSTStream(1, ErrCodeCancel)
	}
}

func BenchmarkWriteGoAway(b *testing.B) {
	fw := newFrameWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WriteGoAway(100, ErrCodeNoError, nil)
	}
}

// ====================== READ BENCHMARKS ======================

func BenchmarkReadData(b *testing.B) {
	raw := encodeForBench(func(fw *FrameWriter) {
		fw.WriteData(1, false, []byte("Hello, World!"))
	})
	r := &bytesReaderResettable{data: raw}
	fr := newFrameReader()
	fr.r = r
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		fr.off = 0
		fr.end = 0
		_, _ = fr.ReadFrame()
	}
}

func BenchmarkReadHeaders(b *testing.B) {
	raw := encodeForBench(func(fw *FrameWriter) {
		fw.WriteHeaders(1, true, []byte{0x82, 0x86, 0x84, 0x41, 0x8a, 0x08, 0x9d, 0x5c}, nil)
	})
	r := &bytesReaderResettable{data: raw}
	fr := newFrameReader()
	fr.r = r
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		fr.off = 0
		fr.end = 0
		_, _ = fr.ReadFrame()
	}
}

func BenchmarkReadSettings(b *testing.B) {
	raw := encodeForBench(func(fw *FrameWriter) {
		fw.WriteSettings(
			Setting{SettingsHeaderTableSize, 4096},
			Setting{SettingsMaxConcurrentStreams, 100},
			Setting{SettingsInitialWindowSize, 65535},
			Setting{SettingsMaxFrameSize, 16384},
		)
	})
	r := &bytesReaderResettable{data: raw}
	fr := newFrameReader()
	fr.r = r
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		fr.off = 0
		fr.end = 0
		_, _ = fr.ReadFrame()
	}
}

func BenchmarkReadPing(b *testing.B) {
	raw := encodeForBench(func(fw *FrameWriter) {
		fw.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	})
	r := &bytesReaderResettable{data: raw}
	fr := newFrameReader()
	fr.r = r
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		fr.off = 0
		fr.end = 0
		_, _ = fr.ReadFrame()
	}
}

func BenchmarkReadWindowUpdate(b *testing.B) {
	raw := encodeForBench(func(fw *FrameWriter) {
		fw.WriteWindowUpdate(0, 65535)
	})
	r := &bytesReaderResettable{data: raw}
	fr := newFrameReader()
	fr.r = r
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset()
		fr.off = 0
		fr.end = 0
		_, _ = fr.ReadFrame()
	}
}

// ====================== ROUND-TRIP BENCHMARKS ======================

func BenchmarkRoundTrip_Data(b *testing.B) {
	data := []byte("Hello, World!")
	var buf bytes.Buffer
	fw := newFrameWriter()
	fw.w = &buf

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		fw.buf = fw.buf[:0]
		fw.WriteData(1, false, data)
		fw.Flush()

		fr := newFrameReader()
		fr.r = &buf
		fr.ReadFrame()
	}
}

func BenchmarkRoundTrip_Settings(b *testing.B) {
	settings := []Setting{
		{SettingsHeaderTableSize, 4096},
		{SettingsMaxConcurrentStreams, 100},
		{SettingsInitialWindowSize, 65535},
		{SettingsMaxFrameSize, 16384},
	}
	var buf bytes.Buffer
	fw := newFrameWriter()
	fw.w = &buf

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		fw.buf = fw.buf[:0]
		fw.WriteSettings(settings...)
		fw.Flush()

		fr := newFrameReader()
		fr.r = &buf
		fr.ReadFrame()
	}
}

// ====================== BATCH WRITE BENCHMARK ======================

func BenchmarkWriteBatch(b *testing.B) {
	fw := newFrameWriter()
	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.buf = fw.buf[:0]
		fw.WriteSettingsACK()
		fw.WritePing(true, data)
		fw.WriteWindowUpdate(0, 65535)
		fw.WriteData(1, false, []byte("hello"))
	}
}
