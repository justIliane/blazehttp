package util

import (
	"math"
	"testing"
)

func TestEqualFold(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"empty", nil, nil, true},
		{"empty_vs_nonempty", nil, []byte("a"), false},
		{"same", []byte("hello"), []byte("hello"), true},
		{"upper_lower", []byte("Hello"), []byte("hELLO"), true},
		{"all_upper_vs_lower", []byte("CONTENT-TYPE"), []byte("content-type"), true},
		{"mixed", []byte("Content-Type"), []byte("content-type"), true},
		{"different_length", []byte("abc"), []byte("abcd"), false},
		{"different_content", []byte("abc"), []byte("abd"), false},
		{"numbers", []byte("123"), []byte("123"), true},
		{"numbers_differ", []byte("123"), []byte("124"), false},
		{"special_chars", []byte("a-b_c"), []byte("A-B_C"), true},
		{"special_chars_differ", []byte("a-b"), []byte("a_b"), false},
		{"single_char", []byte("A"), []byte("a"), true},
		{"non_alpha_same", []byte("!@#"), []byte("!@#"), true},
		{"non_alpha_differ", []byte("!@#"), []byte("!@$"), false},
		{"space", []byte(" "), []byte(" "), true},
		{"at_boundary", []byte("@"), []byte("`"), false}, // @ = 0x40, ` = 0x60
		{"bracket_brace", []byte("["), []byte("{"), false}, // [ = 0x5B, { = 0x7B
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EqualFold(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("EqualFold(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAppendUint(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
		want string
	}{
		{"zero", 0, "0"},
		{"one", 1, "1"},
		{"nine", 9, "9"},
		{"ten", 10, "10"},
		{"hundred", 100, "100"},
		{"large", 1234567890, "1234567890"},
		{"max_uint64", math.MaxUint64, "18446744073709551615"},
		{"power_of_2", 1024, "1024"},
		{"all_digits", 1234567890, "1234567890"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := AppendUint(nil, tt.n)
			got := string(buf)
			if got != tt.want {
				t.Errorf("AppendUint(nil, %d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}

	// Test appending to existing buffer.
	t.Run("append_to_existing", func(t *testing.T) {
		buf := []byte("prefix:")
		buf = AppendUint(buf, 42)
		got := string(buf)
		if got != "prefix:42" {
			t.Errorf("AppendUint(prefix, 42) = %q, want %q", got, "prefix:42")
		}
	})
}

func TestParseUint(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    uint64
		wantErr error
	}{
		{"zero", []byte("0"), 0, nil},
		{"one", []byte("1"), 1, nil},
		{"nine", []byte("9"), 9, nil},
		{"ten", []byte("10"), 10, nil},
		{"large", []byte("1234567890"), 1234567890, nil},
		{"max_uint64", []byte("18446744073709551615"), math.MaxUint64, nil},
		{"empty", nil, 0, ErrEmptyInput},
		{"empty_slice", []byte{}, 0, ErrEmptyInput},
		{"letter", []byte("abc"), 0, ErrInvalidDigit},
		{"space", []byte(" 1"), 0, ErrInvalidDigit},
		{"mixed", []byte("12a4"), 0, ErrInvalidDigit},
		{"negative", []byte("-1"), 0, ErrInvalidDigit},
		{"overflow", []byte("18446744073709551616"), 0, ErrOverflow},
		{"leading_zeros", []byte("007"), 7, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUint(tt.input)
			if err != tt.wantErr {
				t.Errorf("ParseUint(%q) error = %v, want %v", tt.input, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("ParseUint(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestByteStringRoundTrip(t *testing.T) {
	tests := []string{
		"",
		"hello",
		"Content-Type",
		"this is a longer string with spaces and stuff 12345",
		"\x00\x01\x02binary data",
	}
	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			b := StringToBytes(s)
			s2 := BytesToString(b)
			if s2 != s {
				t.Errorf("round-trip failed: got %q, want %q", s2, s)
			}
		})
	}
}

func TestBytesToString_Empty(t *testing.T) {
	s := BytesToString(nil)
	if s != "" {
		t.Errorf("BytesToString(nil) = %q, want empty", s)
	}
	s = BytesToString([]byte{})
	if s != "" {
		t.Errorf("BytesToString([]byte{}) = %q, want empty", s)
	}
}

func TestStringToBytes_Empty(t *testing.T) {
	b := StringToBytes("")
	if b != nil {
		t.Errorf("StringToBytes(\"\") = %v, want nil", b)
	}
}

func TestBytesToString_Content(t *testing.T) {
	b := []byte("hello world")
	s := BytesToString(b)
	if s != "hello world" {
		t.Errorf("BytesToString(%q) = %q", b, s)
	}
}

func TestStringToBytes_Content(t *testing.T) {
	s := "hello world"
	b := StringToBytes(s)
	if string(b) != s {
		t.Errorf("StringToBytes(%q) = %q", s, b)
	}
	if len(b) != len(s) {
		t.Errorf("len mismatch: %d != %d", len(b), len(s))
	}
}

// Benchmarks

func BenchmarkEqualFold(b *testing.B) {
	a := []byte("Content-Type")
	c := []byte("content-type")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		EqualFold(a, c)
	}
}

func BenchmarkAppendUint(b *testing.B) {
	buf := make([]byte, 0, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = AppendUint(buf[:0], 1234567890)
	}
}

func BenchmarkParseUint(b *testing.B) {
	data := []byte("1234567890")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseUint(data)
	}
}

func BenchmarkBytesToString(b *testing.B) {
	data := []byte("Content-Type: application/json")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BytesToString(data)
	}
}

func BenchmarkStringToBytes(b *testing.B) {
	s := "Content-Type: application/json"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = StringToBytes(s)
	}
}
