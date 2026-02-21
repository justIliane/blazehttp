package util

import "unsafe"

// BytesToString converts a byte slice to a string without copying.
// The caller must ensure that the byte slice is not modified after the call,
// as the returned string shares the same underlying memory.
func BytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// StringToBytes converts a string to a byte slice without copying.
// The returned slice MUST NOT be modified, as it shares memory with the string.
// Modifying the slice results in undefined behavior.
func StringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
