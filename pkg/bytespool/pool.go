// Package bytespool provides a pool of reusable byte slices organized by size classes.
//
// The pool maintains separate sync.Pool instances for different buffer sizes,
// minimizing memory waste by selecting the smallest size class that fits the
// requested size. This avoids repeated allocations in hot paths.
//
// The implementation uses a wrapper-reuse technique: *[]byte pointers are recycled
// between Get and Put via a secondary pool, achieving zero allocations in steady state.
package bytespool

import "sync"

// Size classes for pooled buffers.
const (
	class0 = 64
	class1 = 256
	class2 = 1024
	class3 = 4096
	class4 = 16384
	class5 = 65536

	numClasses = 6
	maxPooled  = class5
)

// sizeClasses is the ordered list of buffer sizes managed by the pool.
var sizeClasses = [numClasses]int{class0, class1, class2, class3, class4, class5}

// pools holds one sync.Pool per size class.
// Each pool stores *[]byte pointers to avoid interface boxing allocations.
var pools [numClasses]sync.Pool

// wrapperPool provides reusable *[]byte pointers so that Put does not
// need to allocate a new wrapper on each call.
var wrapperPool sync.Pool

func init() {
	wrapperPool = sync.Pool{
		New: func() any {
			return new([]byte)
		},
	}
	for i := range pools {
		size := sizeClasses[i]
		pools[i] = sync.Pool{
			New: func() any {
				bp := wrapperPool.Get().(*[]byte)
				*bp = make([]byte, size)
				return bp
			},
		}
	}
}

// classIndex returns the index into sizeClasses for the given size.
// Returns -1 if size exceeds maxPooled.
func classIndex(size int) int {
	// Unrolled check for 6 classes — avoids loop overhead.
	switch {
	case size <= class0:
		return 0
	case size <= class1:
		return 1
	case size <= class2:
		return 2
	case size <= class3:
		return 3
	case size <= class4:
		return 4
	case size <= class5:
		return 5
	default:
		return -1
	}
}

// Get returns a byte slice with length == size from the pool.
// The returned slice may have a capacity larger than size.
// If size exceeds the maximum pooled size (65536), a new slice is allocated directly.
func Get(size int) []byte {
	idx := classIndex(size)
	if idx < 0 {
		return make([]byte, size)
	}
	bp := pools[idx].Get().(*[]byte)
	buf := (*bp)[:size]
	// Return the wrapper pointer for reuse by Put.
	wrapperPool.Put(bp)
	return buf
}

// Put returns a byte slice to the pool for reuse.
// Slices larger than the maximum pooled size or with zero capacity are silently discarded.
// The caller must not use the slice after calling Put.
func Put(buf []byte) {
	c := cap(buf)
	if c == 0 || c > maxPooled {
		return
	}
	idx := classIndex(c)
	if idx < 0 {
		return
	}
	// Only put back buffers whose capacity matches a size class exactly.
	if sizeClasses[idx] != c {
		return
	}
	// Get a reusable wrapper pointer instead of allocating a new one.
	bp := wrapperPool.Get().(*[]byte)
	*bp = buf[:c]
	pools[idx].Put(bp)
}
