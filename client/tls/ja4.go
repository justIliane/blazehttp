package tls

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// ComputeJA4 computes the JA4 fingerprint from parsed ClientHello fields.
// Format: JA4_a_JA4_b_JA4_c
// JA4 is immune to TLS extension order randomization (Chrome 106+).
func ComputeJA4(ch *ClientHelloFields) string {
	a := computeJA4a(ch)
	b := computeJA4b(ch)
	c := computeJA4c(ch)
	return a + "_" + b + "_" + c
}

// computeJA4a computes the protocol metadata section (10 characters).
// Format: {proto}{ver}{sni}{cipherCt}{extCt}{alpn}
func computeJA4a(ch *ClientHelloFields) string {
	// Protocol: t=TCP (always for this implementation)
	proto := "t"

	// TLS version: use highest version from supported_versions extension if available
	ver := "00"
	if len(ch.SupportedVers) > 0 {
		highest := uint16(0)
		for _, v := range ch.SupportedVers {
			if !IsGREASE(v) && v > highest {
				highest = v
			}
		}
		ver = tlsVersionStr(highest)
	} else {
		ver = tlsVersionStr(ch.Version)
	}

	// SNI: d=domain, i=IP or absent
	sni := "i"
	if ch.SNI != "" {
		sni = "d"
	}

	// Cipher count (excluding GREASE), 2-digit hex
	cipherCount := 0
	for _, cs := range ch.CipherSuites {
		if !IsGREASE(cs) {
			cipherCount++
		}
	}

	// Extension count (excluding GREASE), 2-digit hex
	extCount := 0
	for _, ext := range ch.Extensions {
		if !IsGREASE(ext) {
			extCount++
		}
	}

	// ALPN: first + last char of first ALPN value
	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		first := ch.ALPNProtocols[0]
		if len(first) >= 2 {
			alpn = string(first[0]) + string(first[len(first)-1])
		} else if len(first) == 1 {
			alpn = string(first[0]) + string(first[0])
		}
	}

	return fmt.Sprintf("%s%s%s%02x%02x%s", proto, ver, sni, cipherCount, extCount, alpn)
}

// computeJA4b computes the cipher hash section (12 characters).
// SHA256 of sorted cipher suites in 4-char hex, truncated to 12.
func computeJA4b(ch *ClientHelloFields) string {
	var ciphers []string
	for _, cs := range ch.CipherSuites {
		if IsGREASE(cs) {
			continue
		}
		ciphers = append(ciphers, fmt.Sprintf("%04x", cs))
	}
	sort.Strings(ciphers)
	joined := strings.Join(ciphers, ",")
	hash := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("%x", hash)[:12]
}

// computeJA4c computes the extension hash section (12 characters).
// SHA256 of sorted extensions (excluding SNI 0x0000 and ALPN 0x0010),
// appended with signature algorithms in original order.
func computeJA4c(ch *ClientHelloFields) string {
	var exts []string
	for _, ext := range ch.Extensions {
		if IsGREASE(ext) {
			continue
		}
		// Exclude SNI (0x0000) and ALPN (0x0010)
		if ext == 0x0000 || ext == 0x0010 {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", ext))
	}
	sort.Strings(exts)

	input := strings.Join(exts, ",")

	// Append signature algorithms in original order
	if len(ch.SignatureAlgos) > 0 {
		var sigAlgs []string
		for _, sa := range ch.SignatureAlgos {
			sigAlgs = append(sigAlgs, fmt.Sprintf("%04x", sa))
		}
		input += "_" + strings.Join(sigAlgs, ",")
	}

	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)[:12]
}

// tlsVersionStr converts a TLS version to the JA4 2-char representation.
func tlsVersionStr(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3" // SSL 3.0
	default:
		return "00"
	}
}

// ComputeJA4FromRaw parses a raw TLS ClientHello record and computes JA4.
func ComputeJA4FromRaw(raw []byte) (string, error) {
	ch, err := ParseClientHello(raw)
	if err != nil {
		return "", err
	}
	return ComputeJA4(ch), nil
}
