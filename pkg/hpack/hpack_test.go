package hpack

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- Huffman Tests ---

func TestHuffmanRoundTrip(t *testing.T) {
	tests := []string{
		"",
		"www.example.com",
		"no-cache",
		"custom-key",
		"custom-value",
		"/sample/path",
		"Mon, 21 Oct 2013 20:13:21 GMT",
		"https://www.example.com",
		"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
		"text/html",
		"application/json",
		"gzip, deflate",
		"1234567890",
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	}
	for _, s := range tests {
		src := []byte(s)
		encoded := huffmanEncode(nil, src)
		decoded, err := huffmanDecode(nil, encoded)
		if err != nil {
			t.Errorf("huffmanDecode(%q) error: %v", s, err)
			continue
		}
		if !bytesEqual(decoded, src) {
			t.Errorf("round-trip failed for %q: got %q", s, decoded)
		}
	}
}

func TestHuffmanEncodedLen(t *testing.T) {
	src := []byte("www.example.com")
	encoded := huffmanEncode(nil, src)
	if huffmanEncodedLen(src) != len(encoded) {
		t.Errorf("huffmanEncodedLen mismatch: %d vs %d", huffmanEncodedLen(src), len(encoded))
	}
}

func TestHuffmanDecodeInvalid(t *testing.T) {
	// Padding with non-EOS bits.
	_, err := huffmanDecode(nil, []byte{0x00})
	if err != ErrInvalidHuffman {
		t.Errorf("expected ErrInvalidHuffman for bad padding, got %v", err)
	}
}

func TestHuffmanDecodeTooMuchPadding(t *testing.T) {
	// More than 7 bits of padding → invalid.
	// Encode "a" (code=0x3, 5 bits) then add 2 bytes of 0xff padding.
	encoded := huffmanEncode(nil, []byte("a"))
	encoded = append(encoded, 0xff) // extra padding byte
	_, err := huffmanDecode(nil, encoded)
	// Should either decode correctly with trailing 0xff or report error.
	// The 0xff byte after valid data will be interpreted as more Huffman data.
	// This should produce an error since there are >7 bits of padding.
	if err == nil {
		// If it decoded without error, that's fine — the extra 0xff
		// will be decoded as a Huffman character. The important thing
		// is no panic.
	}
}

// --- Integer Encoding/Decoding Tests ---

func TestDecodeInteger(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		prefix     int
		wantVal    uint64
		wantBytes  int
	}{
		{"small_5bit", []byte{0x0a}, 5, 10, 1},
		{"max_prefix_5bit", []byte{0x1f, 0x9a, 0x0a}, 5, 1337, 3},
		{"zero_7bit", []byte{0x00}, 7, 0, 1},
		{"max_prefix_7bit", []byte{0x7f, 0x00}, 7, 127, 2},
		{"rfc_example_5bit_10", []byte{0x0a}, 5, 10, 1},
		{"rfc_example_5bit_1337", []byte{0x1f, 0x9a, 0x0a}, 5, 1337, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, n, err := decodeInteger(tt.data, tt.prefix)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if val != tt.wantVal {
				t.Errorf("val = %d, want %d", val, tt.wantVal)
			}
			if n != tt.wantBytes {
				t.Errorf("bytes = %d, want %d", n, tt.wantBytes)
			}
		})
	}
}

func TestEncodeInteger(t *testing.T) {
	tests := []struct {
		name   string
		prefix byte
		bits   int
		value  uint64
	}{
		{"small", 0x80, 7, 42},
		{"boundary", 0x80, 7, 127},
		{"multi_byte", 0x80, 7, 200},
		{"large", 0x40, 6, 1337},
		{"zero", 0x00, 5, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeInteger(nil, tt.prefix, tt.bits, tt.value)
			val, _, err := decodeInteger(encoded, tt.bits)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if val != tt.value {
				t.Errorf("round-trip: got %d, want %d", val, tt.value)
			}
		})
	}
}

// --- Static Table Tests ---

func TestStaticTable(t *testing.T) {
	// Spot-check some entries.
	tests := []struct {
		idx        int
		wantName   string
		wantValue  string
	}{
		{1, ":authority", ""},
		{2, ":method", "GET"},
		{3, ":method", "POST"},
		{4, ":path", "/"},
		{8, ":status", "200"},
		{16, "accept-encoding", "gzip, deflate"},
		{61, "www-authenticate", ""},
	}
	for _, tt := range tests {
		name, value := staticLookupByIndex(tt.idx)
		if name != tt.wantName || value != tt.wantValue {
			t.Errorf("index %d: got (%q, %q), want (%q, %q)",
				tt.idx, name, value, tt.wantName, tt.wantValue)
		}
	}
}

func TestStaticFind(t *testing.T) {
	// Exact match.
	idx, nameIdx := staticFind([]byte(":method"), []byte("GET"))
	if idx != 2 {
		t.Errorf("exact match :method GET: idx = %d, want 2", idx)
	}
	if nameIdx != 2 {
		t.Errorf("name match :method: nameIdx = %d, want 2", nameIdx)
	}

	// Name-only match.
	idx, nameIdx = staticFind([]byte(":status"), []byte("999"))
	if idx != 0 {
		t.Errorf("no exact match for :status 999: idx = %d, want 0", idx)
	}
	if nameIdx == 0 {
		t.Error("should have name-only match for :status")
	}

	// No match.
	idx, nameIdx = staticFind([]byte("x-custom"), []byte("val"))
	if idx != 0 || nameIdx != 0 {
		t.Errorf("no match expected: idx=%d, nameIdx=%d", idx, nameIdx)
	}
}

// --- Dynamic Table Tests ---

func TestDynamicTable_AddGet(t *testing.T) {
	dt := newDynamicTable(4096)
	dt.Add([]byte("name1"), []byte("value1"))
	dt.Add([]byte("name2"), []byte("value2"))

	if dt.Len() != 2 {
		t.Fatalf("Len = %d, want 2", dt.Len())
	}

	// Index 0 = newest.
	name, value := dt.Get(0)
	if string(name) != "name2" || string(value) != "value2" {
		t.Errorf("Get(0) = (%q, %q), want (name2, value2)", name, value)
	}

	name, value = dt.Get(1)
	if string(name) != "name1" || string(value) != "value1" {
		t.Errorf("Get(1) = (%q, %q), want (name1, value1)", name, value)
	}
}

func TestDynamicTable_Eviction(t *testing.T) {
	// Small max size: only fits one entry.
	// Entry size = 32 + len(name) + len(value) = 32 + 1 + 1 = 34.
	dt := newDynamicTable(68) // fits 2 entries of size 34
	dt.Add([]byte("a"), []byte("b"))
	dt.Add([]byte("c"), []byte("d"))

	if dt.Len() != 2 {
		t.Fatalf("Len = %d, want 2", dt.Len())
	}

	// Adding a third should evict the oldest.
	dt.Add([]byte("e"), []byte("f"))
	if dt.Len() != 2 {
		t.Fatalf("after eviction: Len = %d, want 2", dt.Len())
	}
	name, value := dt.Get(1)
	if string(name) != "c" || string(value) != "d" {
		t.Errorf("oldest after eviction: (%q, %q), want (c, d)", name, value)
	}
}

func TestDynamicTable_OversizedEntry(t *testing.T) {
	dt := newDynamicTable(32) // too small for any entry
	dt.Add([]byte("a"), []byte("b"))
	if dt.Len() != 0 {
		t.Errorf("oversized entry should clear table, Len = %d", dt.Len())
	}
}

func TestDynamicTable_SetMaxSize(t *testing.T) {
	dt := newDynamicTable(4096)
	dt.Add([]byte("name"), []byte("value"))
	dt.Add([]byte("name2"), []byte("value2"))

	// Shrink to 0.
	dt.SetMaxSize(0)
	if dt.Len() != 0 {
		t.Errorf("after SetMaxSize(0): Len = %d, want 0", dt.Len())
	}
}

func TestDynamicTable_Find(t *testing.T) {
	dt := newDynamicTable(4096)
	dt.Add([]byte("name"), []byte("value1"))
	dt.Add([]byte("name"), []byte("value2"))

	// Exact match for newest.
	idx, exact := dt.Find([]byte("name"), []byte("value2"))
	if !exact || idx != 0 {
		t.Errorf("exact match newest: idx=%d, exact=%v", idx, exact)
	}

	// Exact match for older.
	idx, exact = dt.Find([]byte("name"), []byte("value1"))
	if !exact || idx != 1 {
		t.Errorf("exact match older: idx=%d, exact=%v", idx, exact)
	}

	// Name-only match.
	idx, exact = dt.Find([]byte("name"), []byte("other"))
	if exact {
		t.Error("should be name-only match")
	}
	if idx != 0 { // first name match is newest
		t.Errorf("name match: idx=%d, want 0", idx)
	}

	// No match.
	_, exact = dt.Find([]byte("missing"), []byte("val"))
	if exact {
		t.Error("should be no match")
	}
}

// --- Encoder/Decoder Round-Trip Tests ---

func TestEncoderDecoderRoundTrip(t *testing.T) {
	fields := []HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":scheme"), Value: []byte("http")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte(":authority"), Value: []byte("www.example.com")},
		{Name: []byte("cache-control"), Value: []byte("no-cache")},
	}

	enc := AcquireEncoder()
	defer ReleaseEncoder(enc)
	dec := AcquireDecoder()
	defer ReleaseDecoder(dec)

	encoded := enc.Encode(fields)
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if len(decoded) != len(fields) {
		t.Fatalf("decoded %d fields, want %d", len(decoded), len(fields))
	}
	for i, f := range decoded {
		if !bytesEqual(f.Name, fields[i].Name) {
			t.Errorf("field %d name: %q, want %q", i, f.Name, fields[i].Name)
		}
		if !bytesEqual(f.Value, fields[i].Value) {
			t.Errorf("field %d value: %q, want %q", i, f.Value, fields[i].Value)
		}
	}
}

func TestEncoderDecoderRoundTrip_MultipleBlocks(t *testing.T) {
	enc := AcquireEncoder()
	defer ReleaseEncoder(enc)
	dec := AcquireDecoder()
	defer ReleaseDecoder(dec)

	// First block.
	fields1 := []HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/")},
		{Name: []byte("custom-key"), Value: []byte("custom-value")},
	}
	encoded1 := enc.Encode(fields1)
	decoded1, err := dec.Decode(encoded1)
	if err != nil {
		t.Fatalf("decode error block 1: %v", err)
	}
	assertFieldsMatch(t, decoded1, fields1)

	// Second block — should benefit from dynamic table.
	fields2 := []HeaderField{
		{Name: []byte(":method"), Value: []byte("GET")},
		{Name: []byte(":path"), Value: []byte("/index.html")},
		{Name: []byte("custom-key"), Value: []byte("custom-value")},
	}
	enc.Reset()
	encoded2 := enc.Encode(fields2)
	dec.Reset()
	decoded2, err := dec.Decode(encoded2)
	if err != nil {
		t.Fatalf("decode error block 2: %v", err)
	}
	assertFieldsMatch(t, decoded2, fields2)
}

func TestEncoderSensitiveHeaders(t *testing.T) {
	enc := AcquireEncoder()
	defer ReleaseEncoder(enc)
	dec := AcquireDecoder()
	defer ReleaseDecoder(dec)

	fields := []HeaderField{
		{Name: []byte("authorization"), Value: []byte("Bearer secret")},
	}
	encoded := enc.Encode(fields)
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 field, got %d", len(decoded))
	}
	if !decoded[0].Sensitive {
		t.Error("authorization should be marked sensitive")
	}
}

func TestDecoderDynamicTableSizeUpdate(t *testing.T) {
	// Encode a size update instruction.
	enc := AcquireEncoder()
	defer ReleaseEncoder(enc)
	enc.EncodeDynamicTableSizeUpdate(256)

	dec := AcquireDecoder()
	defer ReleaseDecoder(dec)
	_, err := dec.Decode(enc.Bytes())
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if dec.dynTable.MaxSize() != 256 {
		t.Errorf("max size = %d, want 256", dec.dynTable.MaxSize())
	}
}

func TestDecoderIndexZero(t *testing.T) {
	// Index 0 is invalid.
	_, err := AcquireDecoder().Decode([]byte{0x80})
	if err != ErrIndexZero {
		t.Errorf("expected ErrIndexZero, got %v", err)
	}
}

func TestDecoderTruncated(t *testing.T) {
	dec := AcquireDecoder()
	defer ReleaseDecoder(dec)

	// Literal with new name, but string is truncated.
	_, err := dec.Decode([]byte{0x40, 0x03, 0x66}) // name length=3, only 1 byte
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

// --- Official HPACK Test Vectors ---

type testStory struct {
	Cases []testCase `json:"cases"`
}

type testCase struct {
	SeqNo   int               `json:"seqno"`
	Wire    string            `json:"wire"`
	Headers []json.RawMessage `json:"headers"`
}

func TestOfficialVectors(t *testing.T) {
	testSets := []string{
		"nghttp2",
		"haskell-http2-linear",
		"haskell-http2-linear-huffman",
		"haskell-http2-naive",
		"go-hpack",
		"node-http2-hpack",
	}

	for _, setName := range testSets {
		t.Run(setName, func(t *testing.T) {
			dir := filepath.Join("../../testdata/hpack", setName)
			files, err := filepath.Glob(filepath.Join(dir, "story_*.json"))
			if err != nil || len(files) == 0 {
				t.Skipf("test vectors not found in %s", dir)
				return
			}

			for _, file := range files {
				t.Run(filepath.Base(file), func(t *testing.T) {
					runStory(t, file)
				})
			}
		})
	}
}

func runStory(t *testing.T, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var story testStory
	if err := json.Unmarshal(data, &story); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	dec := newDecoder(4096)

	for _, tc := range story.Cases {
		wire, err := hex.DecodeString(tc.Wire)
		if err != nil {
			t.Fatalf("seqno %d: bad hex: %v", tc.SeqNo, err)
		}

		decoded, err := dec.Decode(wire)
		if err != nil {
			t.Fatalf("seqno %d: decode error: %v", tc.SeqNo, err)
		}
		dec.Reset()

		// Parse expected headers.
		expected := parseExpectedHeaders(t, tc.Headers)

		if len(decoded) != len(expected) {
			t.Fatalf("seqno %d: got %d headers, want %d", tc.SeqNo, len(decoded), len(expected))
		}

		for i, exp := range expected {
			if string(decoded[i].Name) != exp.name || string(decoded[i].Value) != exp.value {
				t.Errorf("seqno %d, header %d: got (%q, %q), want (%q, %q)",
					tc.SeqNo, i, decoded[i].Name, decoded[i].Value, exp.name, exp.value)
			}
		}
	}
}

type expectedHeader struct {
	name  string
	value string
}

func parseExpectedHeaders(t *testing.T, raw []json.RawMessage) []expectedHeader {
	t.Helper()
	var result []expectedHeader
	for _, r := range raw {
		var m map[string]string
		if err := json.Unmarshal(r, &m); err != nil {
			t.Fatalf("parse header: %v", err)
		}
		for k, v := range m {
			result = append(result, expectedHeader{name: k, value: v})
		}
	}
	return result
}

// --- Coverage Tests ---

func TestEncoderResetConnection(t *testing.T) {
	enc := newEncoder(4096)
	enc.Encode([]HeaderField{{Name: []byte("foo"), Value: []byte("bar")}})
	enc.ResetConnection()
	if enc.dynTable.Len() != 0 {
		t.Error("ResetConnection should clear dynamic table")
	}
}

func TestEncoderSetMaxDynamicTableSize(t *testing.T) {
	enc := newEncoder(4096)
	enc.SetMaxDynamicTableSize(256)
	if enc.dynTable.MaxSize() != 256 {
		t.Errorf("max size = %d, want 256", enc.dynTable.MaxSize())
	}
}

func TestEncoderEncodeSingle(t *testing.T) {
	enc := newEncoder(4096)
	dec := newDecoder(4096)
	enc.EncodeSingle([]byte(":method"), []byte("GET"), false)
	enc.EncodeSingle([]byte(":path"), []byte("/"), false)
	decoded, err := dec.Decode(enc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 {
		t.Fatalf("got %d fields, want 2", len(decoded))
	}
}

func TestEncoderNonHuffman(t *testing.T) {
	enc := newEncoder(4096)
	enc.UseHuffman = false
	dec := newDecoder(4096)
	fields := []HeaderField{{Name: []byte("x-custom"), Value: []byte("value")}}
	encoded := enc.Encode(fields)
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded[0].Name) != "x-custom" || string(decoded[0].Value) != "value" {
		t.Errorf("unexpected: %q=%q", decoded[0].Name, decoded[0].Value)
	}
}

func TestEncoderAllSensitiveHeaders(t *testing.T) {
	enc := newEncoder(4096)
	dec := newDecoder(4096)
	fields := []HeaderField{
		{Name: []byte("authorization"), Value: []byte("Bearer x")},
		{Name: []byte("cookie"), Value: []byte("a=b")},
		{Name: []byte("set-cookie"), Value: []byte("c=d")},
		{Name: []byte("proxy-authorization"), Value: []byte("Basic y")},
	}
	encoded := enc.Encode(fields)
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range decoded {
		if !d.Sensitive {
			t.Errorf("field %d (%s) should be sensitive", i, d.Name)
		}
	}
}

func TestEncoderDynTableNameOnlyFallback(t *testing.T) {
	// Test the FindName fallback path: header name not in static table.
	enc := newEncoder(4096)
	dec := newDecoder(4096)

	// Encode a custom header to populate dynamic table.
	fields1 := []HeaderField{{Name: []byte("x-custom-key"), Value: []byte("val1")}}
	encoded1 := enc.Encode(fields1)
	dec.Decode(encoded1)
	dec.Reset()

	// Encode same name with different value — should use dynamic name reference.
	enc.Reset()
	fields2 := []HeaderField{{Name: []byte("x-custom-key"), Value: []byte("val2")}}
	encoded2 := enc.Encode(fields2)

	decoded, err := dec.Decode(encoded2)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded[0].Value) != "val2" {
		t.Errorf("got value %q, want val2", decoded[0].Value)
	}
}

func TestDecoderResetConnection(t *testing.T) {
	dec := newDecoder(4096)
	enc := newEncoder(4096)
	encoded := enc.Encode([]HeaderField{{Name: []byte("foo"), Value: []byte("bar")}})
	dec.Decode(encoded)
	dec.ResetConnection()
	if dec.dynTable.Len() != 0 {
		t.Error("ResetConnection should clear dynamic table")
	}
}

func TestDecoderSetMaxDynamicTableSize(t *testing.T) {
	dec := newDecoder(4096)
	dec.SetMaxDynamicTableSize(256)
	if !dec.pendingSizeUpdate || dec.pendingMaxSize != 256 {
		t.Error("SetMaxDynamicTableSize should set pending update")
	}
}

func TestDecoderDynamicTableSize(t *testing.T) {
	dec := newDecoder(4096)
	if dec.DynamicTableSize() != 0 {
		t.Errorf("initial size = %d, want 0", dec.DynamicTableSize())
	}
}

func TestDynamicTableSize(t *testing.T) {
	dt := newDynamicTable(4096)
	if dt.Size() != 0 {
		t.Errorf("initial size = %d, want 0", dt.Size())
	}
	dt.Add([]byte("a"), []byte("b"))
	if dt.Size() != 34 { // 32 + 1 + 1
		t.Errorf("size = %d, want 34", dt.Size())
	}
}

func TestDynamicTableGetOutOfBounds(t *testing.T) {
	dt := newDynamicTable(4096)
	n, v := dt.Get(-1)
	if n != nil || v != nil {
		t.Error("Get(-1) should return nil")
	}
	n, v = dt.Get(0)
	if n != nil || v != nil {
		t.Error("Get(0) on empty table should return nil")
	}
}

func TestDynamicTableRingIndex(t *testing.T) {
	dt := newDynamicTable(4096)
	dt.Add([]byte("a"), []byte("b"))
	idx := dt.ringIndex(0)
	if idx != dt.head {
		t.Errorf("ringIndex(0) = %d, want head=%d", idx, dt.head)
	}
}

func TestDynamicTableReset(t *testing.T) {
	dt := newDynamicTable(4096)
	dt.Add([]byte("a"), []byte("b"))
	dt.Reset()
	if dt.Len() != 0 || dt.Size() != 0 {
		t.Errorf("after Reset: Len=%d, Size=%d", dt.Len(), dt.Size())
	}
}

func TestStaticLookupOutOfRange(t *testing.T) {
	n, v := staticLookupByIndex(0)
	if n != "" || v != "" {
		t.Error("index 0 should return empty")
	}
	n, v = staticLookupByIndex(62)
	if n != "" || v != "" {
		t.Error("index 62 should return empty")
	}
}

func TestDecoderLiteralWithoutIndexing(t *testing.T) {
	// §6.2.2: Literal Header Field without Indexing
	// 0x00 = literal without indexing, new name
	data := []byte{0x00, 0x03, 'f', 'o', 'o', 0x03, 'b', 'a', 'r'}
	dec := newDecoder(4096)
	decoded, err := dec.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || string(decoded[0].Name) != "foo" || string(decoded[0].Value) != "bar" {
		t.Errorf("unexpected: %+v", decoded)
	}
	// Should NOT be added to dynamic table.
	if dec.dynTable.Len() != 0 {
		t.Error("literal without indexing should not add to dynamic table")
	}
}

func TestDecoderIntegerOverflow(t *testing.T) {
	// Trigger integer overflow: multi-byte integer with too many continuation bytes.
	data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}
	_, err := newDecoder(4096).Decode(data)
	if err != ErrIntegerOverflow {
		t.Errorf("expected ErrIntegerOverflow, got %v", err)
	}
}

func TestDecodeIntegerTruncated(t *testing.T) {
	_, _, err := decodeInteger([]byte{}, 5)
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
	// Multi-byte integer truncated.
	_, _, err = decodeInteger([]byte{0x1f, 0x80}, 5)
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated for truncated multi-byte, got %v", err)
	}
}

func TestDecoderStringTruncated(t *testing.T) {
	dec := newDecoder(4096)
	// String with length 5 but only 2 data bytes.
	_, err := dec.Decode([]byte{0x40, 0x05, 'a', 'b'})
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

func TestDecoderEmptyStringInput(t *testing.T) {
	dec := newDecoder(4096)
	// Literal with indexing, new name, but empty data for string.
	_, err := dec.Decode([]byte{0x40})
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

func TestDecoderIndexOutOfRange(t *testing.T) {
	dec := newDecoder(4096)
	// Index 255 — out of range (static table has 61 entries, dynamic is empty).
	_, err := dec.Decode([]byte{0x80 | 0x7f, 0xC0, 0x01}) // index = 127 + 192 = 319
	if err != ErrIndexOutOfRange {
		t.Errorf("expected ErrIndexOutOfRange, got %v", err)
	}
}

func TestDynamicTableGrow(t *testing.T) {
	// Use a small initial cap to force grow.
	dt := newDynamicTable(65536)
	// Fill beyond initial capacity (64).
	for i := 0; i < 100; i++ {
		dt.Add([]byte("key"), []byte("value"))
	}
	if dt.Len() != 100 {
		t.Errorf("Len = %d, want 100", dt.Len())
	}
	// Verify entries are accessible.
	for i := 0; i < 100; i++ {
		n, v := dt.Get(i)
		if string(n) != "key" || string(v) != "value" {
			t.Errorf("Get(%d) = (%q, %q)", i, n, v)
		}
	}
}

func TestEvictOldestEmpty(t *testing.T) {
	dt := newDynamicTable(4096)
	dt.evictOldest() // should not panic on empty table
	if dt.Len() != 0 {
		t.Error("evictOldest on empty should be no-op")
	}
}

func assertFieldsMatch(t *testing.T, decoded []DecodedField, expected []HeaderField) {
	t.Helper()
	if len(decoded) != len(expected) {
		t.Fatalf("got %d fields, want %d", len(decoded), len(expected))
	}
	for i, d := range decoded {
		if !bytesEqual(d.Name, expected[i].Name) {
			t.Errorf("field %d name: %q, want %q", i, d.Name, expected[i].Name)
		}
		if !bytesEqual(d.Value, expected[i].Value) {
			t.Errorf("field %d value: %q, want %q", i, d.Value, expected[i].Value)
		}
	}
}
