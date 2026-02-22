// Package tls provides TLS fingerprinting for the BlazeHTTP client.
// It wraps github.com/refraction-networking/utls to produce ClientHello
// messages that match real browser fingerprints (Chrome, Firefox, Safari).
package tls

import (
	utls "github.com/refraction-networking/utls"
)

// TLSFingerprint defines a TLS client fingerprint profile.
// Either UTLSClientHelloID or CustomSpec must be set.
// If both are nil, the standard Go crypto/tls stack is used.
type TLSFingerprint struct {
	// Name identifies this fingerprint (e.g. "Chrome-120", "Firefox-121").
	Name string

	// JA3Hash is the expected JA3 hash for verification.
	// Empty for profiles that randomize extension order (Chrome 106+).
	JA3Hash string

	// JA4Hash is the expected JA4 hash for verification.
	// JA4 is stable across extension order randomization.
	JA4Hash string

	// UTLSClientHelloID selects a pre-defined uTLS browser profile.
	UTLSClientHelloID *utls.ClientHelloID

	// CustomSpec provides full manual control over the ClientHello.
	// Takes precedence over UTLSClientHelloID if both are set.
	CustomSpec *utls.ClientHelloSpec
}

// IsGoDefault reports whether this fingerprint uses the standard Go TLS stack.
func (f *TLSFingerprint) IsGoDefault() bool {
	return f.UTLSClientHelloID == nil && f.CustomSpec == nil
}

// IsCustom reports whether this fingerprint uses a custom ClientHello spec.
func (f *TLSFingerprint) IsCustom() bool {
	return f.CustomSpec != nil
}
