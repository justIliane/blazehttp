package stream

import (
	"testing"
)

func BenchmarkStreamCreate(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := acquireStream(1, 65535)
		releaseStream(s)
	}
}

func BenchmarkStreamTransition(b *testing.B) {
	s := acquireStream(1, 65535)
	defer releaseStream(s)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.state.Store(uint32(StateOpen))
		s.Transition(EventSendEndStream)
	}
}

func BenchmarkManagerOpenClose(b *testing.B) {
	m := NewManager(uint32(b.N)+1, 65535)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := uint32(2*i + 1)
		m.OpenStream(id)
		m.CloseStream(id)
	}
}

func BenchmarkManagerGetStream(b *testing.B) {
	m := NewManager(1000, 65535)
	for i := 0; i < 100; i++ {
		m.OpenStream(uint32(2*i + 1))
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		id := uint32(1)
		for pb.Next() {
			_ = m.GetStream(id)
			id += 2
			if id > 199 {
				id = 1
			}
		}
	})
}
