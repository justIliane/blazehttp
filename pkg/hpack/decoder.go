package hpack

import (
	"errors"
	"sync"
	"unsafe"
)

// HPACK decoding errors.
var (
	ErrIndexZero       = errors.New("hpack: index 0 is not valid")
	ErrIndexOutOfRange = errors.New("hpack: index out of range")
	ErrIntegerOverflow = errors.New("hpack: integer overflow")
	ErrStringTooLong   = errors.New("hpack: string length exceeds buffer")
	ErrTruncated       = errors.New("hpack: truncated input")
	ErrTableSizeUpdate = errors.New("hpack: invalid dynamic table size update")
)

// DecodedField represents a decoded header field.
type DecodedField struct {
	Name      []byte
	Value     []byte
	Sensitive bool // true if marked "never indexed"
}

// Decoder decodes HPACK-encoded header blocks.
// It maintains the dynamic table state across multiple header blocks
// for the same connection.
type Decoder struct {
	dynTable *dynamicTable

	// fields is a pre-allocated buffer for decoded header fields.
	fields    []DecodedField
	maxFields int

	// scratch buffer for Huffman decoding.
	scratch []byte

	// strBuf accumulates copies of dynamic table strings and Huffman-decoded
	// strings during a single Decode call. This prevents aliasing with ring
	// buffer slots that might be evicted and reused by later headers in the
	// same block, and eliminates per-string allocations.
	strBuf []byte

	// maxAllowedTableSize is the protocol-level maximum for dynamic table size updates,
	// set by SETTINGS_HEADER_TABLE_SIZE. Any dynamic table size update in a header block
	// MUST NOT exceed this value (RFC 7541 §4.2).
	maxAllowedTableSize uint32

	// Whether the next block must start with a dynamic table size update.
	pendingSizeUpdate bool
	pendingMaxSize    uint32
}

const (
	defaultMaxDynTableSize = 4096
	defaultMaxFields       = 128
)

var decoderPool = sync.Pool{
	New: func() any {
		return newDecoder(defaultMaxDynTableSize)
	},
}

// AcquireDecoder gets a Decoder from the pool.
func AcquireDecoder() *Decoder {
	return decoderPool.Get().(*Decoder)
}

// ReleaseDecoder returns a Decoder to the pool.
func ReleaseDecoder(d *Decoder) {
	d.Reset()
	decoderPool.Put(d)
}

func newDecoder(maxTableSize uint32) *Decoder {
	return &Decoder{
		dynTable:            newDynamicTable(maxTableSize),
		fields:              make([]DecodedField, 0, defaultMaxFields),
		maxFields:           defaultMaxFields,
		scratch:             make([]byte, 0, 256),
		strBuf:              make([]byte, 0, 4096),
		maxAllowedTableSize: maxTableSize,
	}
}

// Reset clears the decoder state (but keeps the dynamic table for connection reuse).
func (d *Decoder) Reset() {
	d.fields = d.fields[:0]
}

// ResetConnection fully resets the decoder including the dynamic table.
func (d *Decoder) ResetConnection() {
	d.dynTable.Reset()
	d.fields = d.fields[:0]
	d.pendingSizeUpdate = false
}

// SetMaxDynamicTableSize sets the maximum size for the dynamic table.
func (d *Decoder) SetMaxDynamicTableSize(maxSize uint32) {
	d.maxAllowedTableSize = maxSize
	d.pendingSizeUpdate = true
	d.pendingMaxSize = maxSize
}

// DynamicTableSize returns the current dynamic table size.
func (d *Decoder) DynamicTableSize() uint32 {
	return d.dynTable.Size()
}

// Decode decodes an HPACK-encoded header block and returns the decoded fields.
// The returned slice is valid until the next call to Decode or Reset.
func (d *Decoder) Decode(data []byte) ([]DecodedField, error) {
	d.fields = d.fields[:0]
	d.strBuf = d.strBuf[:0]
	pos := 0
	headersSeen := false // true after any non-table-size-update entry

	for pos < len(data) {
		b := data[pos]

		switch {
		case b&0x80 != 0:
			// §6.1: Indexed Header Field Representation
			idx, n, err := decodeInteger(data[pos:], 7)
			if err != nil {
				return nil, err
			}
			pos += n
			if idx == 0 {
				return nil, ErrIndexZero
			}
			name, value, err := d.lookupIndex(int(idx))
			if err != nil {
				return nil, err
			}
			d.fields = append(d.fields, DecodedField{Name: name, Value: value})
			headersSeen = true

		case b&0xc0 == 0x40:
			// §6.2.1: Literal Header Field with Incremental Indexing
			n, err := d.decodeLiteral(data[pos:], 6, true, false)
			if err != nil {
				return nil, err
			}
			pos += n
			headersSeen = true

		case b&0xf0 == 0x00:
			// §6.2.2: Literal Header Field without Indexing
			n, err := d.decodeLiteral(data[pos:], 4, false, false)
			if err != nil {
				return nil, err
			}
			pos += n
			headersSeen = true

		case b&0xf0 == 0x10:
			// §6.2.3: Literal Header Field Never Indexed
			n, err := d.decodeLiteral(data[pos:], 4, false, true)
			if err != nil {
				return nil, err
			}
			pos += n
			headersSeen = true

		case b&0xe0 == 0x20:
			// §6.3: Dynamic Table Size Update
			// MUST occur at the beginning of the first header block, per RFC 7541 §4.2.
			if headersSeen {
				return nil, ErrTableSizeUpdate
			}
			maxSize, n, err := decodeInteger(data[pos:], 5)
			if err != nil {
				return nil, err
			}
			pos += n
			// The new size MUST NOT exceed SETTINGS_HEADER_TABLE_SIZE (RFC 7541 §4.2).
			if uint32(maxSize) > d.maxAllowedTableSize {
				return nil, ErrTableSizeUpdate
			}
			d.dynTable.SetMaxSize(uint32(maxSize))

		default:
			return nil, ErrTruncated
		}
	}

	return d.fields, nil
}

// decodeLiteral decodes a literal header field representation.
func (d *Decoder) decodeLiteral(data []byte, prefixBits int, addToTable bool, sensitive bool) (int, error) {
	pos := 0

	// Decode name index.
	idx, n, err := decodeInteger(data[pos:], prefixBits)
	if err != nil {
		return 0, err
	}
	pos += n

	var name, value []byte

	if idx > 0 {
		// Name is from the table.
		name, _, err = d.lookupIndex(int(idx))
		if err != nil {
			return 0, err
		}
	} else {
		// New name: decode string.
		name, n, err = d.decodeString(data[pos:])
		if err != nil {
			return 0, err
		}
		pos += n
	}

	// Decode value.
	value, n, err = d.decodeString(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += n

	if addToTable {
		d.dynTable.Add(name, value)
	}

	d.fields = append(d.fields, DecodedField{
		Name:      name,
		Value:     value,
		Sensitive: sensitive,
	})

	return pos, nil
}

// decodeString decodes an HPACK string (with optional Huffman encoding).
func (d *Decoder) decodeString(data []byte) ([]byte, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrTruncated
	}

	huffman := data[0]&0x80 != 0
	length, n, err := decodeInteger(data, 7)
	if err != nil {
		return nil, 0, err
	}

	if length > uint64(len(data)-n) {
		return nil, 0, ErrTruncated
	}

	intLen := int(length)
	raw := data[n : n+intLen]

	if huffman {
		d.scratch = d.scratch[:0]
		d.scratch, err = huffmanDecode(d.scratch, raw)
		if err != nil {
			return nil, 0, err
		}
		// Copy into strBuf to avoid aliasing the scratch buffer (0 allocs steady state).
		off := len(d.strBuf)
		d.strBuf = append(d.strBuf, d.scratch...)
		return d.strBuf[off : off+len(d.scratch)], n + intLen, nil
	}

	return raw, n + intLen, nil
}

// lookupIndex resolves a 1-based HPACK index to a name-value pair.
// Indices 1-61 are in the static table; indices 62+ are in the dynamic table.
func (d *Decoder) lookupIndex(idx int) (name, value []byte, err error) {
	if idx <= staticTableLen {
		e := &staticTable[idx]
		// Zero-alloc conversion: static table strings are immutable constants.
		var n, v []byte
		if len(e.name) > 0 {
			n = unsafe.Slice(unsafe.StringData(e.name), len(e.name))
		}
		if len(e.value) > 0 {
			v = unsafe.Slice(unsafe.StringData(e.value), len(e.value))
		}
		return n, v, nil
	}
	dynIdx := idx - staticTableLen - 1
	n, v := d.dynTable.Get(dynIdx)
	if n == nil {
		return nil, nil, ErrIndexOutOfRange
	}
	// Copy into strBuf to avoid aliasing the ring buffer.
	// A later header in this block may evict and reuse the slot.
	off := len(d.strBuf)
	d.strBuf = append(d.strBuf, n...)
	d.strBuf = append(d.strBuf, v...)
	name = d.strBuf[off : off+len(n)]
	value = d.strBuf[off+len(n) : off+len(n)+len(v)]
	return name, value, nil
}

// decodeInteger decodes an HPACK integer with the given prefix bit width.
// RFC 7541 §5.1.
func decodeInteger(data []byte, prefixBits int) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrTruncated
	}

	mask := uint8((1 << prefixBits) - 1)
	val := uint64(data[0] & mask)

	if val < uint64(mask) {
		return val, 1, nil
	}

	// Multi-byte integer.
	var m uint64
	pos := 1
	for {
		if pos >= len(data) {
			return 0, 0, ErrTruncated
		}
		b := data[pos]
		pos++
		val += uint64(b&0x7f) << m
		if val > (1<<63 - 1) {
			return 0, 0, ErrIntegerOverflow
		}
		m += 7
		if b&0x80 == 0 {
			break
		}
		if m > 63 {
			return 0, 0, ErrIntegerOverflow
		}
	}

	return val, pos, nil
}
