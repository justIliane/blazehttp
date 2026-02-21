package hpack

import "errors"

// ErrInvalidHuffman is returned when Huffman-encoded data is malformed.
var ErrInvalidHuffman = errors.New("hpack: invalid huffman encoding")

// huffmanCodeEntry holds the Huffman code and bit length for a single symbol.
type huffmanCodeEntry struct {
	code uint32
	bits uint8
}

// huffmanCodes is the Huffman code table from RFC 7541, Appendix B.
// Index is the symbol value (0-255 for bytes, 256 for EOS).
var huffmanCodes [257]huffmanCodeEntry

func init() {
	copy(huffmanCodes[:], rawHuffmanCodes[:])
	buildDecodeTables()
}

// --- Encoder ---

// huffmanEncode encodes src using HPACK Huffman coding and appends to dst.
func huffmanEncode(dst, src []byte) []byte {
	var bitBuf uint64
	var bitCount uint8

	for _, b := range src {
		entry := &huffmanCodes[b]
		bitBuf = bitBuf<<entry.bits | uint64(entry.code)
		bitCount += entry.bits

		for bitCount >= 8 {
			bitCount -= 8
			dst = append(dst, byte(bitBuf>>bitCount))
		}
		bitBuf &= (1 << bitCount) - 1
	}

	// Pad with EOS prefix (all 1s) per RFC 7541 §5.2.
	if bitCount > 0 {
		dst = append(dst, byte(bitBuf<<(8-bitCount))|byte(0xff>>bitCount))
	}

	return dst
}

// huffmanEncodedLen returns the byte length of src after Huffman encoding.
func huffmanEncodedLen(src []byte) int {
	var bits uint64
	for _, b := range src {
		bits += uint64(huffmanCodes[b].bits)
	}
	return int((bits + 7) / 8)
}

// --- Decoder with left-aligned accumulator and 8-bit primary lookup ---

// Primary decode table: indexed by 8-bit prefix.
// For codes with length ≤ 8 bits, the entry contains the symbol and bit count.
// For prefixes that map to codes > 8 bits, bits == 0 (need secondary lookup).
type primaryEntry struct {
	sym  uint8
	bits uint8 // 0 = need secondary lookup
}

var primaryTable [256]primaryEntry

// Secondary decode: for codes > 8 bits, searched when primary table says bits=0.
type secondaryEntry struct {
	code uint32
	bits uint8
	sym  uint8
}

var secondaryTable []secondaryEntry

func buildDecodeTables() {
	// Fill primary table for codes ≤ 8 bits.
	for sym := 0; sym < 256; sym++ {
		entry := &huffmanCodes[sym]
		if entry.bits <= 8 {
			prefix := entry.code << (8 - entry.bits)
			count := 1 << (8 - entry.bits)
			for j := 0; j < count; j++ {
				primaryTable[prefix+uint32(j)] = primaryEntry{
					sym:  uint8(sym),
					bits: entry.bits,
				}
			}
		}
	}

	// Build secondary table for codes > 8 bits.
	secondaryTable = make([]secondaryEntry, 0, 192)
	for sym := 0; sym < 256; sym++ {
		entry := &huffmanCodes[sym]
		if entry.bits > 8 {
			secondaryTable = append(secondaryTable, secondaryEntry{
				code: entry.code,
				bits: entry.bits,
				sym:  uint8(sym),
			})
		}
	}
}

// huffmanDecode decodes Huffman-encoded data and appends to dst.
// Uses a left-aligned uint64 accumulator for fast bit extraction:
// meaningful bits are always at the MSB end, so the primary table index
// is always acc>>56 (a constant shift) with no masking needed.
func huffmanDecode(dst, src []byte) ([]byte, error) {
	var acc uint64  // left-aligned bit accumulator
	var nBits uint8 // number of valid bits in acc (at MSB end)

	for _, b := range src {
		if nBits > 48 {
			return nil, ErrInvalidHuffman
		}
		acc |= uint64(b) << (56 - nBits)
		nBits += 8

		for nBits >= 5 { // minimum code length
			// Primary table: top 8 bits → O(1) for codes ≤ 8 bits.
			pe := &primaryTable[uint8(acc>>56)]
			if pe.bits > 0 && pe.bits <= nBits {
				dst = append(dst, pe.sym)
				acc <<= pe.bits
				nBits -= pe.bits
				continue
			}

			// Secondary lookup for codes > 8 bits (rare for ASCII).
			found := false
			for i := range secondaryTable {
				se := &secondaryTable[i]
				if nBits < se.bits {
					continue
				}
				if uint32(acc>>(64-uint(se.bits))) == se.code {
					dst = append(dst, se.sym)
					acc <<= se.bits
					nBits -= se.bits
					found = true
					break
				}
			}
			if !found {
				break // need more bits
			}
		}
	}

	// Validate padding per RFC 7541 §5.2:
	// Remaining bits must be all 1s and at most 7 bits.
	if nBits > 7 {
		return nil, ErrInvalidHuffman
	}
	if nBits > 0 {
		mask := uint64((1<<nBits)-1) << (64 - nBits)
		if acc&mask != mask {
			return nil, ErrInvalidHuffman
		}
	}

	return dst, nil
}

// rawHuffmanCodes contains the complete Huffman table from RFC 7541 Appendix B.
var rawHuffmanCodes = [257]huffmanCodeEntry{
	/*   0 */ {0x1ff8, 13},
	/*   1 */ {0x7fffd8, 23},
	/*   2 */ {0xfffffe2, 28},
	/*   3 */ {0xfffffe3, 28},
	/*   4 */ {0xfffffe4, 28},
	/*   5 */ {0xfffffe5, 28},
	/*   6 */ {0xfffffe6, 28},
	/*   7 */ {0xfffffe7, 28},
	/*   8 */ {0xfffffe8, 28},
	/*   9 */ {0xffffea, 24},
	/*  10 */ {0x3ffffffc, 30},
	/*  11 */ {0xfffffe9, 28},
	/*  12 */ {0xfffffea, 28},
	/*  13 */ {0x3ffffffd, 30},
	/*  14 */ {0xfffffeb, 28},
	/*  15 */ {0xfffffec, 28},
	/*  16 */ {0xfffffed, 28},
	/*  17 */ {0xfffffee, 28},
	/*  18 */ {0xfffffef, 28},
	/*  19 */ {0xffffff0, 28},
	/*  20 */ {0xffffff1, 28},
	/*  21 */ {0xffffff2, 28},
	/*  22 */ {0x3ffffffe, 30},
	/*  23 */ {0xffffff3, 28},
	/*  24 */ {0xffffff4, 28},
	/*  25 */ {0xffffff5, 28},
	/*  26 */ {0xffffff6, 28},
	/*  27 */ {0xffffff7, 28},
	/*  28 */ {0xffffff8, 28},
	/*  29 */ {0xffffff9, 28},
	/*  30 */ {0xffffffa, 28},
	/*  31 */ {0xffffffb, 28},
	/*  32 */ {0x14, 6},
	/*  33 */ {0x3f8, 10},
	/*  34 */ {0x3f9, 10},
	/*  35 */ {0xffa, 12},
	/*  36 */ {0x1ff9, 13},
	/*  37 */ {0x15, 6},
	/*  38 */ {0xf8, 8},
	/*  39 */ {0x7fa, 11},
	/*  40 */ {0x3fa, 10},
	/*  41 */ {0x3fb, 10},
	/*  42 */ {0xf9, 8},
	/*  43 */ {0x7fb, 11},
	/*  44 */ {0xfa, 8},
	/*  45 */ {0x16, 6},
	/*  46 */ {0x17, 6},
	/*  47 */ {0x18, 6},
	/*  48 */ {0x0, 5},
	/*  49 */ {0x1, 5},
	/*  50 */ {0x2, 5},
	/*  51 */ {0x19, 6},
	/*  52 */ {0x1a, 6},
	/*  53 */ {0x1b, 6},
	/*  54 */ {0x1c, 6},
	/*  55 */ {0x1d, 6},
	/*  56 */ {0x1e, 6},
	/*  57 */ {0x1f, 6},
	/*  58 */ {0x5c, 7},
	/*  59 */ {0xfb, 8},
	/*  60 */ {0x7ffc, 15},
	/*  61 */ {0x20, 6},
	/*  62 */ {0xffb, 12},
	/*  63 */ {0x3fc, 10},
	/*  64 */ {0x1ffa, 13},
	/*  65 */ {0x21, 6},
	/*  66 */ {0x5d, 7},
	/*  67 */ {0x5e, 7},
	/*  68 */ {0x5f, 7},
	/*  69 */ {0x60, 7},
	/*  70 */ {0x61, 7},
	/*  71 */ {0x62, 7},
	/*  72 */ {0x63, 7},
	/*  73 */ {0x64, 7},
	/*  74 */ {0x65, 7},
	/*  75 */ {0x66, 7},
	/*  76 */ {0x67, 7},
	/*  77 */ {0x68, 7},
	/*  78 */ {0x69, 7},
	/*  79 */ {0x6a, 7},
	/*  80 */ {0x6b, 7},
	/*  81 */ {0x6c, 7},
	/*  82 */ {0x6d, 7},
	/*  83 */ {0x6e, 7},
	/*  84 */ {0x6f, 7},
	/*  85 */ {0x70, 7},
	/*  86 */ {0x71, 7},
	/*  87 */ {0x72, 7},
	/*  88 */ {0xfc, 8},
	/*  89 */ {0x73, 7},
	/*  90 */ {0xfd, 8},
	/*  91 */ {0x1ffb, 13},
	/*  92 */ {0x7fff0, 19},
	/*  93 */ {0x1ffc, 13},
	/*  94 */ {0x3ffc, 14},
	/*  95 */ {0x22, 6},
	/*  96 */ {0x7ffd, 15},
	/*  97 */ {0x3, 5},
	/*  98 */ {0x23, 6},
	/*  99 */ {0x4, 5},
	/* 100 */ {0x24, 6},
	/* 101 */ {0x5, 5},
	/* 102 */ {0x25, 6},
	/* 103 */ {0x26, 6},
	/* 104 */ {0x27, 6},
	/* 105 */ {0x6, 5},
	/* 106 */ {0x74, 7},
	/* 107 */ {0x75, 7},
	/* 108 */ {0x28, 6},
	/* 109 */ {0x29, 6},
	/* 110 */ {0x2a, 6},
	/* 111 */ {0x7, 5},
	/* 112 */ {0x2b, 6},
	/* 113 */ {0x76, 7},
	/* 114 */ {0x2c, 6},
	/* 115 */ {0x8, 5},
	/* 116 */ {0x9, 5},
	/* 117 */ {0x2d, 6},
	/* 118 */ {0x77, 7},
	/* 119 */ {0x78, 7},
	/* 120 */ {0x79, 7},
	/* 121 */ {0x7a, 7},
	/* 122 */ {0x7b, 7},
	/* 123 */ {0x7ffe, 15},
	/* 124 */ {0x7fc, 11},
	/* 125 */ {0x3ffd, 14},
	/* 126 */ {0x1ffd, 13},
	/* 127 */ {0xffffffc, 28},
	/* 128 */ {0xfffe6, 20},
	/* 129 */ {0x3fffd2, 22},
	/* 130 */ {0xfffe7, 20},
	/* 131 */ {0xfffe8, 20},
	/* 132 */ {0x3fffd3, 22},
	/* 133 */ {0x3fffd4, 22},
	/* 134 */ {0x3fffd5, 22},
	/* 135 */ {0x7fffd9, 23},
	/* 136 */ {0x3fffd6, 22},
	/* 137 */ {0x7fffda, 23},
	/* 138 */ {0x7fffdb, 23},
	/* 139 */ {0x7fffdc, 23},
	/* 140 */ {0x7fffdd, 23},
	/* 141 */ {0x7fffde, 23},
	/* 142 */ {0xffffeb, 24},
	/* 143 */ {0x7fffdf, 23},
	/* 144 */ {0xffffec, 24},
	/* 145 */ {0xffffed, 24},
	/* 146 */ {0x3fffd7, 22},
	/* 147 */ {0x7fffe0, 23},
	/* 148 */ {0xffffee, 24},
	/* 149 */ {0x7fffe1, 23},
	/* 150 */ {0x7fffe2, 23},
	/* 151 */ {0x7fffe3, 23},
	/* 152 */ {0x7fffe4, 23},
	/* 153 */ {0x1fffdc, 21},
	/* 154 */ {0x3fffd8, 22},
	/* 155 */ {0x7fffe5, 23},
	/* 156 */ {0x3fffd9, 22},
	/* 157 */ {0x7fffe6, 23},
	/* 158 */ {0x7fffe7, 23},
	/* 159 */ {0xffffef, 24},
	/* 160 */ {0x3fffda, 22},
	/* 161 */ {0x1fffdd, 21},
	/* 162 */ {0xfffe9, 20},
	/* 163 */ {0x3fffdb, 22},
	/* 164 */ {0x3fffdc, 22},
	/* 165 */ {0x7fffe8, 23},
	/* 166 */ {0x7fffe9, 23},
	/* 167 */ {0x1fffde, 21},
	/* 168 */ {0x7fffea, 23},
	/* 169 */ {0x3fffdd, 22},
	/* 170 */ {0x3fffde, 22},
	/* 171 */ {0xfffff0, 24},
	/* 172 */ {0x1fffdf, 21},
	/* 173 */ {0x3fffdf, 22},
	/* 174 */ {0x7fffeb, 23},
	/* 175 */ {0x7fffec, 23},
	/* 176 */ {0x1fffe0, 21},
	/* 177 */ {0x1fffe1, 21},
	/* 178 */ {0x3fffe0, 22},
	/* 179 */ {0x1fffe2, 21},
	/* 180 */ {0x7fffed, 23},
	/* 181 */ {0x3fffe1, 22},
	/* 182 */ {0x7fffee, 23},
	/* 183 */ {0x7fffef, 23},
	/* 184 */ {0xfffea, 20},
	/* 185 */ {0x3fffe2, 22},
	/* 186 */ {0x3fffe3, 22},
	/* 187 */ {0x3fffe4, 22},
	/* 188 */ {0x7ffff0, 23},
	/* 189 */ {0x3fffe5, 22},
	/* 190 */ {0x3fffe6, 22},
	/* 191 */ {0x7ffff1, 23},
	/* 192 */ {0x3ffffe0, 26},
	/* 193 */ {0x3ffffe1, 26},
	/* 194 */ {0xfffeb, 20},
	/* 195 */ {0x7fff1, 19},
	/* 196 */ {0x3fffe7, 22},
	/* 197 */ {0x7ffff2, 23},
	/* 198 */ {0x3fffe8, 22},
	/* 199 */ {0x1ffffec, 25},
	/* 200 */ {0x3ffffe2, 26},
	/* 201 */ {0x3ffffe3, 26},
	/* 202 */ {0x3ffffe4, 26},
	/* 203 */ {0x7ffffde, 27},
	/* 204 */ {0x7ffffdf, 27},
	/* 205 */ {0x3ffffe5, 26},
	/* 206 */ {0xfffff1, 24},
	/* 207 */ {0x1ffffed, 25},
	/* 208 */ {0x7fff2, 19},
	/* 209 */ {0x1fffe3, 21},
	/* 210 */ {0x3ffffe6, 26},
	/* 211 */ {0x7ffffe0, 27},
	/* 212 */ {0x7ffffe1, 27},
	/* 213 */ {0x3ffffe7, 26},
	/* 214 */ {0x7ffffe2, 27},
	/* 215 */ {0xfffff2, 24},
	/* 216 */ {0x1fffe4, 21},
	/* 217 */ {0x1fffe5, 21},
	/* 218 */ {0x3ffffe8, 26},
	/* 219 */ {0x3ffffe9, 26},
	/* 220 */ {0xffffffd, 28},
	/* 221 */ {0x7ffffe3, 27},
	/* 222 */ {0x7ffffe4, 27},
	/* 223 */ {0x7ffffe5, 27},
	/* 224 */ {0xfffec, 20},
	/* 225 */ {0xfffff3, 24},
	/* 226 */ {0xfffed, 20},
	/* 227 */ {0x1fffe6, 21},
	/* 228 */ {0x3fffe9, 22},
	/* 229 */ {0x1fffe7, 21},
	/* 230 */ {0x1fffe8, 21},
	/* 231 */ {0x7ffff3, 23},
	/* 232 */ {0x3fffea, 22},
	/* 233 */ {0x3fffeb, 22},
	/* 234 */ {0x1ffffee, 25},
	/* 235 */ {0x1ffffef, 25},
	/* 236 */ {0xfffff4, 24},
	/* 237 */ {0xfffff5, 24},
	/* 238 */ {0x3ffffea, 26},
	/* 239 */ {0x7ffff4, 23},
	/* 240 */ {0x3ffffeb, 26},
	/* 241 */ {0x7ffffe6, 27},
	/* 242 */ {0x3ffffec, 26},
	/* 243 */ {0x3ffffed, 26},
	/* 244 */ {0x7ffffe7, 27},
	/* 245 */ {0x7ffffe8, 27},
	/* 246 */ {0x7ffffe9, 27},
	/* 247 */ {0x7ffffea, 27},
	/* 248 */ {0x7ffffeb, 27},
	/* 249 */ {0xffffffe, 28},
	/* 250 */ {0x7ffffec, 27},
	/* 251 */ {0x7ffffed, 27},
	/* 252 */ {0x7ffffee, 27},
	/* 253 */ {0x7ffffef, 27},
	/* 254 */ {0x7fffff0, 27},
	/* 255 */ {0x3ffffee, 26},
	/* EOS */ {0x3fffffff, 30},
}
