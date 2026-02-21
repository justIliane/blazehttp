// Package util provides zero-allocation utility functions for byte slice and
// string manipulation used throughout BlazeHTTP.
package util

// EqualFold reports whether a and b are equal under Unicode case-folding
// for ASCII characters. Non-ASCII bytes are compared as-is.
// This is allocation-free and branchless per byte.
func EqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i]|0x20 != b[i]|0x20 {
			return false
		}
		// Ensure non-alpha bytes match exactly.
		ab := a[i] | 0x20
		if ab < 'a' || ab > 'z' {
			if a[i] != b[i] {
				return false
			}
		}
	}
	return true
}

// AppendUint appends the decimal representation of n to dst and returns
// the extended buffer. It performs no allocations.
func AppendUint(dst []byte, n uint64) []byte {
	// Fast path for small numbers.
	if n < 10 {
		return append(dst, byte('0'+n))
	}

	// Maximum uint64 is 20 digits.
	var buf [20]byte
	i := len(buf)
	for n >= 10 {
		i--
		q := n / 10
		buf[i] = byte('0' + n - q*10)
		n = q
	}
	i--
	buf[i] = byte('0' + n)

	return append(dst, buf[i:]...)
}

// ParseUint parses a decimal number from b. It returns the parsed value
// and any error. It performs no allocations.
func ParseUint(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, ErrEmptyInput
	}

	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, ErrInvalidDigit
		}
		n1 := n*10 + uint64(c-'0')
		if n1 < n {
			return 0, ErrOverflow
		}
		n = n1
	}
	return n, nil
}
