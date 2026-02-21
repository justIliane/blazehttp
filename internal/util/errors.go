package util

import "errors"

// Errors returned by ParseUint.
var (
	ErrEmptyInput   = errors.New("util: empty input")
	ErrInvalidDigit = errors.New("util: invalid digit")
	ErrOverflow     = errors.New("util: integer overflow")
)
