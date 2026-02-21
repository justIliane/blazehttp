package hpack

// dynamicTable implements the HPACK dynamic table as a ring buffer.
// RFC 7541 §2.3.2: entries are added to the front and referenced in LIFO order.
type dynamicTable struct {
	// Ring buffer storage.
	entries []dynamicEntry
	head    int // index of newest entry
	mask    int // len(entries) - 1, for fast modulo (capacity is always power of 2)
	count   int // number of entries

	// Size tracking per RFC 7541 §4.1.
	size    uint32 // current size in octets
	maxSize uint32 // maximum size in octets
}

type dynamicEntry struct {
	name  []byte
	value []byte
	size  uint32 // 32 + len(name) + len(value) per RFC 7541 §4.1
}

const dynamicTableInitialCap = 64

// newDynamicTable creates a dynamic table with the given maximum size.
func newDynamicTable(maxSize uint32) *dynamicTable {
	return &dynamicTable{
		entries: make([]dynamicEntry, dynamicTableInitialCap),
		mask:    dynamicTableInitialCap - 1,
		maxSize: maxSize,
	}
}

// Len returns the number of entries in the table.
func (dt *dynamicTable) Len() int {
	return dt.count
}

// Size returns the current size of the table in octets.
func (dt *dynamicTable) Size() uint32 {
	return dt.size
}

// MaxSize returns the maximum allowed size.
func (dt *dynamicTable) MaxSize() uint32 {
	return dt.maxSize
}

// entrySize computes the size of a header field per RFC 7541 §4.1.
func entrySize(name, value []byte) uint32 {
	return uint32(len(name) + len(value) + 32)
}

// Get returns the entry at position i (0-based, 0 = newest).
func (dt *dynamicTable) Get(i int) (name, value []byte) {
	if i < 0 || i >= dt.count {
		return nil, nil
	}
	e := &dt.entries[(dt.head-i+dt.mask+1)&dt.mask]
	return e.name, e.value
}

// ringIndex converts a logical index (0=newest) to a ring buffer index.
func (dt *dynamicTable) ringIndex(i int) int {
	return (dt.head - i + dt.mask + 1) & dt.mask
}

// Add inserts a new entry at the front of the table.
// Evicts old entries if necessary to stay within maxSize.
func (dt *dynamicTable) Add(name, value []byte) {
	eSize := entrySize(name, value)

	// RFC 7541 §4.4: if the entry is larger than maxSize, clear the table.
	if eSize > dt.maxSize {
		dt.clear()
		return
	}

	// Evict until there is room.
	for dt.size+eSize > dt.maxSize {
		dt.evictOldest()
	}

	// Grow ring buffer if full.
	if dt.count > dt.mask {
		dt.grow()
	}

	// Insert at head+1.
	dt.head = (dt.head + 1) & dt.mask
	dt.count++

	e := &dt.entries[dt.head]

	// Copy name and value to avoid aliasing the network buffer.
	e.name = appendCopy(e.name[:0], name)
	e.value = appendCopy(e.value[:0], value)
	e.size = eSize

	dt.size += eSize
}

// appendCopy appends src to dst, reusing dst's capacity if possible.
func appendCopy(dst, src []byte) []byte {
	if cap(dst) >= len(src) {
		dst = dst[:len(src)]
		copy(dst, src)
		return dst
	}
	return append(dst[:0], src...)
}

// Find searches for a name-value pair in the dynamic table.
// Returns (index, true) for exact match, (nameIndex, false) for name-only match, (0, false) for no match.
// Index is 0-based (0=newest).
func (dt *dynamicTable) Find(name, value []byte) (int, bool) {
	nameLen := len(name)
	valueLen := len(value)
	nameIdx := -1
	m := dt.mask
	h := dt.head
	for i := 0; i < dt.count; i++ {
		e := &dt.entries[(h-i+m+1)&m]
		if len(e.name) != nameLen {
			continue
		}
		if !bytesEqual(e.name, name) {
			continue
		}
		// Name matches — check value.
		if len(e.value) == valueLen && bytesEqual(e.value, value) {
			return i, true
		}
		if nameIdx < 0 {
			nameIdx = i
		}
	}
	if nameIdx >= 0 {
		return nameIdx, false
	}
	return 0, false
}

// FindName searches for a name-only match in the dynamic table via linear scan.
// Returns logical index (0=newest) or -1 if not found.
func (dt *dynamicTable) FindName(name []byte) int {
	nameLen := len(name)
	m := dt.mask
	h := dt.head
	for i := 0; i < dt.count; i++ {
		e := &dt.entries[(h-i+m+1)&m]
		if len(e.name) == nameLen && bytesEqual(e.name, name) {
			return i
		}
	}
	return -1
}

// SetMaxSize changes the maximum size of the dynamic table.
// Evicts entries as needed.
func (dt *dynamicTable) SetMaxSize(maxSize uint32) {
	dt.maxSize = maxSize
	for dt.size > dt.maxSize {
		dt.evictOldest()
	}
}

// evictOldest removes the oldest entry from the table.
func (dt *dynamicTable) evictOldest() {
	if dt.count == 0 {
		return
	}
	// Oldest is at logical index count-1.
	idx := (dt.head - dt.count + 1 + dt.mask + 1) & dt.mask
	dt.size -= dt.entries[idx].size
	dt.count--
}

// clear removes all entries.
func (dt *dynamicTable) clear() {
	dt.count = 0
	dt.size = 0
}

// grow doubles the ring buffer capacity.
func (dt *dynamicTable) grow() {
	oldCap := dt.mask + 1
	newCap := oldCap * 2
	newEntries := make([]dynamicEntry, newCap)

	// Copy entries in logical order (newest first).
	for i := 0; i < dt.count; i++ {
		oldIdx := (dt.head - i + oldCap) & dt.mask
		newEntries[dt.count-1-i] = dt.entries[oldIdx]
	}

	dt.entries = newEntries
	dt.mask = newCap - 1
	dt.head = dt.count - 1
}

// Reset clears the dynamic table for reuse.
func (dt *dynamicTable) Reset() {
	dt.clear()
}
