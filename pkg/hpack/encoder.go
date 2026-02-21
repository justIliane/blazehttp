package hpack

import "sync"

// Encoder encodes header fields into HPACK format.
// It maintains a dynamic table for the connection.
type Encoder struct {
	dynTable *dynamicTable
	buf      []byte // reusable encode buffer

	// Whether to use Huffman encoding (conditional: only if it reduces size).
	UseHuffman bool

	// nameCache maps static table name index → physical ring buffer index.
	// Enables O(1) dynamic table lookups for headers whose name is in the
	// static table (covers virtually all standard HTTP headers).
	// Index 0 unused; entries 1-61 correspond to static table names.
	nameCache [staticTableLen + 1]int16

}

// sensitiveHeaders lists header names that should be marked "never indexed".
var sensitiveHeaders = [4]string{
	"authorization",
	"cookie",
	"set-cookie",
	"proxy-authorization",
}

var encoderPool = sync.Pool{
	New: func() any {
		return newEncoder(defaultMaxDynTableSize)
	},
}

// AcquireEncoder gets an Encoder from the pool.
func AcquireEncoder() *Encoder {
	return encoderPool.Get().(*Encoder)
}

// ReleaseEncoder returns an Encoder to the pool.
func ReleaseEncoder(e *Encoder) {
	e.ResetConnection()
	encoderPool.Put(e)
}

func newEncoder(maxTableSize uint32) *Encoder {
	enc := &Encoder{
		dynTable:   newDynamicTable(maxTableSize),
		buf:        make([]byte, 0, 512),
		UseHuffman: true,
	}
	for i := range enc.nameCache {
		enc.nameCache[i] = -1
	}
	return enc
}

// Reset clears the encode buffer but keeps the dynamic table.
func (e *Encoder) Reset() {
	e.buf = e.buf[:0]
}

// ResetConnection fully resets the encoder including the dynamic table.
func (e *Encoder) ResetConnection() {
	e.dynTable.Reset()
	e.buf = e.buf[:0]
	for i := range e.nameCache {
		e.nameCache[i] = -1
	}
}

// SetMaxDynamicTableSize changes the max size and emits a size update.
func (e *Encoder) SetMaxDynamicTableSize(maxSize uint32) {
	e.dynTable.SetMaxSize(maxSize)
}

// Encode encodes a list of header fields into HPACK format.
// Returns the encoded bytes. The returned slice is valid until the next Encode call.
func (e *Encoder) Encode(fields []HeaderField) []byte {
	e.buf = e.buf[:0]

	for i := range fields {
		f := &fields[i]
		e.encodeField(f.Name, f.Value, isSensitiveHeader(f.Name))
	}

	return e.buf
}

// EncodeSingle encodes a single header field and appends to the internal buffer.
func (e *Encoder) EncodeSingle(name, value []byte, sensitive bool) {
	e.encodeField(name, value, sensitive)
}

// Bytes returns the current encoded bytes.
func (e *Encoder) Bytes() []byte {
	return e.buf
}

func (e *Encoder) encodeField(name, value []byte, sensitive bool) {
	if sensitive {
		e.encodeLiteralNeverIndexed(name, value)
		return
	}

	// Static table lookup — also gives us the nameIdx for cache key.
	idx, nameIdx := staticFind(name, value)
	if idx > 0 {
		e.encodeIndexed(idx)
		return
	}

	// O(1) dynamic table lookup using static name index as cache key.
	// No hash computation — just array index + value comparison.
	if nameIdx > 0 {
		phys := e.nameCache[nameIdx]
		if phys >= 0 {
			dt := e.dynTable
			logical := (dt.head - int(phys) + dt.mask + 1) & dt.mask
			if logical < dt.count {
				entry := &dt.entries[phys]
				if len(entry.value) == len(value) && bytesEqual(entry.value, value) {
					e.encodeIndexed(staticTableLen + 1 + logical)
					return
				}
			}
		}
	}

	// Literal with incremental indexing.
	nameRef := nameIdx
	if nameRef == 0 {
		dynNameIdx := e.dynTable.FindName(name)
		if dynNameIdx >= 0 {
			nameRef = staticTableLen + 1 + dynNameIdx
		}
	}

	e.encodeLiteralWithIndexing(nameRef, name, value)
	e.dynTable.Add(name, value)

	// Update name cache after adding to dynamic table.
	if nameIdx > 0 {
		e.nameCache[nameIdx] = int16(e.dynTable.head)
	}
}

// encodeIndexed encodes an indexed header field (§6.1).
func (e *Encoder) encodeIndexed(index int) {
	e.buf = encodeInteger(e.buf, 0x80, 7, uint64(index))
}

// encodeLiteralWithIndexing encodes a literal field with incremental indexing (§6.2.1).
func (e *Encoder) encodeLiteralWithIndexing(nameIndex int, name, value []byte) {
	e.buf = encodeInteger(e.buf, 0x40, 6, uint64(nameIndex))
	if nameIndex == 0 {
		e.buf = e.encodeString(e.buf, name)
	}
	e.buf = e.encodeString(e.buf, value)
}

// encodeLiteralNeverIndexed encodes a literal field never indexed (§6.2.3).
func (e *Encoder) encodeLiteralNeverIndexed(name, value []byte) {
	// Try to use name index from static table.
	_, nameIdx := staticFind(name, nil)
	e.buf = encodeInteger(e.buf, 0x10, 4, uint64(nameIdx))
	if nameIdx == 0 {
		e.buf = e.encodeString(e.buf, name)
	}
	e.buf = e.encodeString(e.buf, value)
}

// encodeString encodes an HPACK string, using Huffman if it reduces size.
func (e *Encoder) encodeString(dst, s []byte) []byte {
	if e.UseHuffman {
		hLen := huffmanEncodedLen(s)
		if hLen < len(s) {
			// Huffman is shorter — use it.
			dst = encodeInteger(dst, 0x80, 7, uint64(hLen))
			dst = huffmanEncode(dst, s)
			return dst
		}
	}
	// Plain string.
	dst = encodeInteger(dst, 0x00, 7, uint64(len(s)))
	dst = append(dst, s...)
	return dst
}

// encodeInteger encodes an HPACK integer with the given prefix.
// RFC 7541 §5.1.
func encodeInteger(dst []byte, prefix byte, prefixBits int, value uint64) []byte {
	mask := uint64((1 << prefixBits) - 1)
	if value < mask {
		dst = append(dst, prefix|byte(value))
		return dst
	}

	dst = append(dst, prefix|byte(mask))
	value -= mask
	for value >= 0x80 {
		dst = append(dst, byte(value&0x7f)|0x80)
		value >>= 7
	}
	dst = append(dst, byte(value))
	return dst
}

// isSensitiveHeader checks if a header name is sensitive and should never be indexed.
func isSensitiveHeader(name []byte) bool {
	switch len(name) {
	case 6: // "cookie"
		return string(name) == sensitiveHeaders[1]
	case 10: // "set-cookie"
		return string(name) == sensitiveHeaders[2]
	case 13: // "authorization"
		return string(name) == sensitiveHeaders[0]
	case 19: // "proxy-authorization"
		return string(name) == sensitiveHeaders[3]
	}
	return false
}

// EncodeDynamicTableSizeUpdate emits a dynamic table size update instruction.
func (e *Encoder) EncodeDynamicTableSizeUpdate(maxSize uint32) {
	e.buf = encodeInteger(e.buf, 0x20, 5, uint64(maxSize))
	e.dynTable.SetMaxSize(maxSize)
}
