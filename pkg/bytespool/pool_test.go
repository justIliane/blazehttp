package bytespool

import (
	"testing"
)

func TestGet_ReturnsCorrectLength(t *testing.T) {
	tests := []struct {
		name     string
		reqSize  int
		wantLen  int
		wantCap  int
	}{
		{"zero", 0, 0, class0},
		{"small_1", 1, 1, class0},
		{"exact_class0", class0, class0, class0},
		{"just_over_class0", class0 + 1, class0 + 1, class1},
		{"exact_class1", class1, class1, class1},
		{"just_over_class1", class1 + 1, class1 + 1, class2},
		{"exact_class2", class2, class2, class2},
		{"just_over_class2", class2 + 1, class2 + 1, class3},
		{"exact_class3", class3, class3, class3},
		{"just_over_class3", class3 + 1, class3 + 1, class4},
		{"exact_class4", class4, class4, class4},
		{"just_over_class4", class4 + 1, class4 + 1, class5},
		{"exact_class5", class5, class5, class5},
		{"over_max", class5 + 1, class5 + 1, class5 + 1},
		{"very_large", 1 << 20, 1 << 20, 1 << 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := Get(tt.reqSize)
			if len(buf) != tt.wantLen {
				t.Errorf("Get(%d): len = %d, want %d", tt.reqSize, len(buf), tt.wantLen)
			}
			if cap(buf) < tt.wantLen {
				t.Errorf("Get(%d): cap = %d, want >= %d", tt.reqSize, cap(buf), tt.wantLen)
			}
			if tt.wantCap > 0 && cap(buf) != tt.wantCap {
				t.Errorf("Get(%d): cap = %d, want %d", tt.reqSize, cap(buf), tt.wantCap)
			}
		})
	}
}

func TestPut_ReuseBuffer(t *testing.T) {
	// Get a buffer, put it back, get another of the same size.
	// We can't guarantee the same pointer due to sync.Pool behavior,
	// but we verify no panics and correct behavior.
	for _, size := range sizeClasses {
		buf := Get(size)
		if len(buf) != size {
			t.Fatalf("Get(%d): len = %d", size, len(buf))
		}
		Put(buf)

		buf2 := Get(size)
		if len(buf2) != size {
			t.Fatalf("second Get(%d): len = %d", size, len(buf2))
		}
		Put(buf2)
	}
}

func TestPut_DiscardOversized(t *testing.T) {
	// Putting an oversized buffer should not panic.
	buf := make([]byte, maxPooled+1)
	Put(buf) // Should not panic.
}

func TestPut_DiscardZeroCap(t *testing.T) {
	// Putting a nil or empty slice should not panic.
	Put(nil)
	Put([]byte{})
}

func TestPut_DiscardNonClassCap(t *testing.T) {
	// Buffers with non-standard capacity should be discarded.
	buf := make([]byte, 100)
	Put(buf) // cap=100 doesn't match any class, should be discarded.
}

func TestGet_BufferIsUsable(t *testing.T) {
	buf := Get(class2)
	// Write to every byte.
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	// Verify.
	for i := range buf {
		if buf[i] != byte(i%256) {
			t.Fatalf("byte %d: got %d, want %d", i, buf[i], byte(i%256))
		}
	}
	Put(buf)
}

func TestClassIndex(t *testing.T) {
	tests := []struct {
		size int
		want int
	}{
		{0, 0},
		{1, 0},
		{64, 0},
		{65, 1},
		{256, 1},
		{257, 2},
		{1024, 2},
		{1025, 3},
		{4096, 3},
		{4097, 4},
		{16384, 4},
		{16385, 5},
		{65536, 5},
		{65537, -1},
	}
	for _, tt := range tests {
		got := classIndex(tt.size)
		if got != tt.want {
			t.Errorf("classIndex(%d) = %d, want %d", tt.size, got, tt.want)
		}
	}
}

// BenchmarkGet benchmarks Get from pool for various sizes.
func BenchmarkGet64(b *testing.B) {
	benchGet(b, 64)
}

func BenchmarkGet256(b *testing.B) {
	benchGet(b, 256)
}

func BenchmarkGet1024(b *testing.B) {
	benchGet(b, 1024)
}

func BenchmarkGet4096(b *testing.B) {
	benchGet(b, 4096)
}

func BenchmarkGet16384(b *testing.B) {
	benchGet(b, 16384)
}

func BenchmarkGet65536(b *testing.B) {
	benchGet(b, 65536)
}

func benchGet(b *testing.B, size int) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := Get(size)
			Put(buf)
		}
	})
}

// BenchmarkNaiveAlloc benchmarks naive make([]byte, n) for comparison.
func BenchmarkNaiveAlloc64(b *testing.B) {
	benchNaive(b, 64)
}

func BenchmarkNaiveAlloc256(b *testing.B) {
	benchNaive(b, 256)
}

func BenchmarkNaiveAlloc1024(b *testing.B) {
	benchNaive(b, 1024)
}

func BenchmarkNaiveAlloc4096(b *testing.B) {
	benchNaive(b, 4096)
}

func BenchmarkNaiveAlloc16384(b *testing.B) {
	benchNaive(b, 16384)
}

func BenchmarkNaiveAlloc65536(b *testing.B) {
	benchNaive(b, 65536)
}

//go:noinline
func useBuffer(buf []byte) {
	// Prevent compiler optimization.
	if len(buf) > 0 {
		buf[0] = 1
	}
}

func benchNaive(b *testing.B, size int) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, size)
		useBuffer(buf)
	}
}
