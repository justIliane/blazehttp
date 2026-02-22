package tls

import (
	utls "github.com/refraction-networking/utls"
)

// Pre-defined TLS fingerprint profiles matching real browsers.
// Each profile produces a ClientHello identical to the specified browser.
//
// Note: Browser fingerprints change with each major version update.
// The *Latest variants auto-update with uTLS library updates.
// Last verified: February 2026.
var (
	// Chrome120 matches Chrome 120 with Encrypted Client Hello support.
	Chrome120 = TLSFingerprint{
		Name:              "Chrome-120",
		UTLSClientHelloID: &utls.HelloChrome_120,
	}

	// ChromeLatest matches the latest Chrome version supported by uTLS.
	// Currently maps to Chrome 133 (utls v1.8.2).
	ChromeLatest = TLSFingerprint{
		Name:              "Chrome-Latest",
		UTLSClientHelloID: &utls.HelloChrome_Auto,
	}

	// Firefox121 matches Firefox 120+ with GREASE ECH.
	Firefox121 = TLSFingerprint{
		Name:              "Firefox-121",
		UTLSClientHelloID: &utls.HelloFirefox_120,
	}

	// FirefoxLatest matches the latest Firefox version supported by uTLS.
	// Currently maps to Firefox 120 (utls v1.8.2).
	FirefoxLatest = TLSFingerprint{
		Name:              "Firefox-Latest",
		UTLSClientHelloID: &utls.HelloFirefox_Auto,
	}

	// Safari17 matches Safari on macOS. Uses HelloSafari_Auto which
	// maps to Safari 16.0 in utls v1.8.2.
	Safari17 = TLSFingerprint{
		Name:              "Safari-17",
		UTLSClientHelloID: &utls.HelloSafari_Auto,
	}

	// SafariIOS matches Safari on iOS devices.
	SafariIOS = TLSFingerprint{
		Name:              "Safari-iOS",
		UTLSClientHelloID: &utls.HelloIOS_Auto,
	}

	// Randomized produces a different fingerprint on each connection.
	// Useful for avoiding fingerprint-based tracking.
	Randomized = TLSFingerprint{
		Name:              "Randomized",
		UTLSClientHelloID: &utls.HelloRandomized,
	}

	// GoDefault uses the standard Go crypto/tls stack.
	// This produces a recognizable Go TLS fingerprint — use only for
	// debugging or when fingerprint evasion is not needed.
	GoDefault = TLSFingerprint{
		Name: "Go-Default",
	}
)
