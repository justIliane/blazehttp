package flowcontrol

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blazehttp/blazehttp/pkg/frame"
)

func TestWindow_Basic(t *testing.T) {
	w := NewWindow(1000)
	if got := w.Size(); got != 1000 {
		t.Fatalf("Size() = %d, want 1000", got)
	}
	if got := w.Available(); got != 1000 {
		t.Fatalf("Available() = %d, want 1000", got)
	}

	if !w.Consume(100) {
		t.Fatal("Consume(100) should succeed")
	}
	if got := w.Size(); got != 900 {
		t.Fatalf("Size() = %d, want 900", got)
	}

	if err := w.Update(50); err != nil {
		t.Fatalf("Update(50) error: %v", err)
	}
	if got := w.Size(); got != 950 {
		t.Fatalf("Size() = %d, want 950", got)
	}
}

func TestWindow_ConsumeExact(t *testing.T) {
	w := NewWindow(100)
	if !w.Consume(100) {
		t.Fatal("Consume(100) should succeed with window of 100")
	}
	if got := w.Size(); got != 0 {
		t.Fatalf("Size() = %d, want 0", got)
	}
	if got := w.Available(); got != 0 {
		t.Fatalf("Available() = %d, want 0", got)
	}
}

func TestWindow_ConsumeTooMuch(t *testing.T) {
	w := NewWindow(50)
	if w.Consume(51) {
		t.Fatal("Consume(51) should fail with window of 50")
	}
	if got := w.Size(); got != 50 {
		t.Fatalf("Size() = %d, want 50 (unchanged)", got)
	}
}

func TestWindow_ConsumeZeroOrNegative(t *testing.T) {
	w := NewWindow(100)
	if w.Consume(0) {
		t.Fatal("Consume(0) should return false")
	}
	if w.Consume(-1) {
		t.Fatal("Consume(-1) should return false")
	}
	if got := w.Size(); got != 100 {
		t.Fatalf("Size() = %d, want 100 (unchanged)", got)
	}
}

func TestWindow_ConsumeFromEmpty(t *testing.T) {
	w := NewWindow(0)
	if w.Consume(1) {
		t.Fatal("Consume(1) should fail with window of 0")
	}
}

func TestWindow_Overflow(t *testing.T) {
	w := NewWindow(MaxWindowSize)
	err := w.Update(1)
	if err == nil {
		t.Fatal("Update(1) on max window should return error")
	}
	connErr, ok := err.(*frame.ConnError)
	if !ok {
		t.Fatalf("error type = %T, want *ConnError", err)
	}
	if connErr.Code != frame.ErrCodeFlowControlError {
		t.Fatalf("error code = %v, want FLOW_CONTROL_ERROR", connErr.Code)
	}
	// Window should be unchanged.
	if got := w.Size(); got != MaxWindowSize {
		t.Fatalf("Size() = %d, want %d (unchanged)", got, MaxWindowSize)
	}
}

func TestWindow_OverflowPartial(t *testing.T) {
	w := NewWindow(MaxWindowSize - 10)
	if err := w.Update(10); err != nil {
		t.Fatalf("Update(10) should succeed: %v", err)
	}
	if got := w.Size(); got != MaxWindowSize {
		t.Fatalf("Size() = %d, want %d", got, MaxWindowSize)
	}
	err := w.Update(1)
	if err == nil {
		t.Fatal("Update(1) at max should fail")
	}
}

func TestWindow_Negative(t *testing.T) {
	w := NewWindow(100)
	w.Add(-200)
	if got := w.Size(); got != -100 {
		t.Fatalf("Size() = %d, want -100", got)
	}
	if got := w.Available(); got != 0 {
		t.Fatalf("Available() = %d, want 0 (negative window)", got)
	}
	// Consume should fail on negative window.
	if w.Consume(1) {
		t.Fatal("Consume should fail on negative window")
	}
	// Update should bring it back.
	if err := w.Update(150); err != nil {
		t.Fatalf("Update(150) error: %v", err)
	}
	if got := w.Size(); got != 50 {
		t.Fatalf("Size() = %d, want 50", got)
	}
}

func TestWindow_Add(t *testing.T) {
	w := NewWindow(65535)
	// Simulate SETTINGS_INITIAL_WINDOW_SIZE change from 65535 to 32768.
	w.Add(32768 - 65535) // delta = -32767
	if got := w.Size(); got != 32768 {
		t.Fatalf("Size() = %d, want 32768", got)
	}

	// Simulate increase from 32768 to 131072.
	w.Add(131072 - 32768) // delta = +98304
	if got := w.Size(); got != 131072 {
		t.Fatalf("Size() = %d, want 131072", got)
	}
}

func TestWindow_Reset(t *testing.T) {
	w := NewWindow(100)
	w.Consume(50)
	w.Reset(65535)
	if got := w.Size(); got != 65535 {
		t.Fatalf("Size() = %d, want 65535", got)
	}
}

func TestWindow_UpdateZero(t *testing.T) {
	w := NewWindow(100)
	if err := w.Update(0); err != nil {
		t.Fatalf("Update(0) should not error: %v", err)
	}
	if got := w.Size(); got != 100 {
		t.Fatalf("Size() = %d, want 100 (unchanged)", got)
	}
}

func TestWindow_ConcurrentConsume(t *testing.T) {
	const goroutines = 100
	w := NewWindow(int32(goroutines))

	var successCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if w.Consume(1) {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := successCount.Load(); got != goroutines {
		t.Fatalf("successful consumes = %d, want %d", got, goroutines)
	}
	if got := w.Size(); got != 0 {
		t.Fatalf("Size() = %d, want 0", got)
	}

	// One more should fail.
	if w.Consume(1) {
		t.Fatal("Consume should fail on empty window")
	}
}

func TestWindow_ConcurrentUpdate(t *testing.T) {
	const goroutines = 100
	const increment int32 = 10
	w := NewWindow(0)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if err := w.Update(increment); err != nil {
				t.Errorf("Update error: %v", err)
			}
		}()
	}
	wg.Wait()

	expected := int32(goroutines) * increment
	if got := w.Size(); got != expected {
		t.Fatalf("Size() = %d, want %d", got, expected)
	}
}

func TestWindow_ConcurrentConsumeAndUpdate(t *testing.T) {
	w := NewWindow(1000)

	var wg sync.WaitGroup
	// 50 consumers taking 10 each = 500.
	// 50 updaters adding 10 each = 500.
	// Expected final: 1000 - 500 + 500 = 1000.
	const consumers = 50
	const updaters = 50
	wg.Add(consumers + updaters)

	for i := 0; i < consumers; i++ {
		go func() {
			defer wg.Done()
			for !w.Consume(10) {
				// Retry until consume succeeds (updaters replenish).
			}
		}()
	}
	for i := 0; i < updaters; i++ {
		go func() {
			defer wg.Done()
			_ = w.Update(10)
		}()
	}
	wg.Wait()

	if got := w.Size(); got != 1000 {
		t.Fatalf("Size() = %d, want 1000", got)
	}
}

// ====================== BENCHMARKS ======================

func BenchmarkWindow_Consume(b *testing.B) {
	w := NewWindow(MaxWindowSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Consume(1)
	}
}

func BenchmarkWindow_Update(b *testing.B) {
	w := NewWindow(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = w.Update(1)
	}
}

func BenchmarkWindow_Available(b *testing.B) {
	w := NewWindow(65535)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = w.Available()
	}
}

func BenchmarkWindow_ConsumeContended(b *testing.B) {
	w := NewWindow(MaxWindowSize)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w.Consume(1)
		}
	})
}
