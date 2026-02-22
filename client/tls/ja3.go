package tls

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
)

// ClientHelloFields holds the parsed fields from a TLS ClientHello message,
// used for JA3 and JA4 fingerprint computation.
type ClientHelloFields struct {
	Version         uint16
	CipherSuites    []uint16
	Extensions      []uint16
	SupportedGroups []uint16
	ECPointFormats  []uint8
	SignatureAlgos  []uint16
	ALPNProtocols   []string
	SNI             string
	SupportedVers   []uint16 // from supported_versions extension
}

// ParseClientHello parses a raw TLS record containing a ClientHello message.
// The input should be the complete TLS record (record header + handshake message).
func ParseClientHello(raw []byte) (*ClientHelloFields, error) {
	if len(raw) < 5 {
		return nil, fmt.Errorf("ja3: record too short: %d bytes", len(raw))
	}

	// TLS record header: type(1) + version(2) + length(2)
	if raw[0] != 0x16 { // Handshake
		return nil, fmt.Errorf("ja3: not a handshake record (type %d)", raw[0])
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	body := raw[5:]
	if len(body) < recLen {
		return nil, fmt.Errorf("ja3: record truncated")
	}
	body = body[:recLen]

	// Handshake header: type(1) + length(3)
	if len(body) < 4 || body[0] != 0x01 { // ClientHello
		return nil, fmt.Errorf("ja3: not a ClientHello (type %d)", body[0])
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	body = body[4:]
	if len(body) < hsLen {
		return nil, fmt.Errorf("ja3: handshake truncated")
	}
	body = body[:hsLen]

	return parseClientHelloBody(body)
}

// parseClientHelloBody parses the body of a ClientHello message
// (after the handshake header).
func parseClientHelloBody(data []byte) (*ClientHelloFields, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("ja3: ClientHello too short")
	}

	ch := &ClientHelloFields{}

	// Version (2 bytes)
	ch.Version = binary.BigEndian.Uint16(data[0:2])
	pos := 2

	// Random (32 bytes)
	pos += 32

	// Session ID
	if pos >= len(data) {
		return nil, fmt.Errorf("ja3: truncated at session ID")
	}
	sessIDLen := int(data[pos])
	pos++
	pos += sessIDLen
	if pos > len(data) {
		return nil, fmt.Errorf("ja3: truncated after session ID")
	}

	// Cipher suites
	if pos+2 > len(data) {
		return nil, fmt.Errorf("ja3: truncated at cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+csLen > len(data) {
		return nil, fmt.Errorf("ja3: truncated cipher suites")
	}
	for i := 0; i < csLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(data[pos+i:pos+i+2]))
	}
	pos += csLen

	// Compression methods
	if pos >= len(data) {
		return nil, fmt.Errorf("ja3: truncated at compression")
	}
	compLen := int(data[pos])
	pos++
	pos += compLen
	if pos > len(data) {
		return nil, fmt.Errorf("ja3: truncated after compression")
	}

	// Extensions
	if pos+2 > len(data) {
		return ch, nil // no extensions
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(data) {
		return nil, fmt.Errorf("ja3: truncated extensions")
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > extEnd {
			break
		}
		extData := data[pos : pos+extDataLen]
		ch.Extensions = append(ch.Extensions, extType)

		switch extType {
		case 0x000a: // supported_groups
			ch.SupportedGroups = parseUint16List(extData)
		case 0x000b: // ec_point_formats
			if len(extData) >= 1 {
				pfLen := int(extData[0])
				if 1+pfLen <= len(extData) {
					ch.ECPointFormats = make([]uint8, pfLen)
					copy(ch.ECPointFormats, extData[1:1+pfLen])
				}
			}
		case 0x000d: // signature_algorithms
			ch.SignatureAlgos = parseUint16List(extData)
		case 0x0010: // ALPN
			ch.ALPNProtocols = parseALPN(extData)
		case 0x0000: // SNI
			ch.SNI = parseSNI(extData)
		case 0x002b: // supported_versions
			ch.SupportedVers = parseSupportedVersions(extData)
		}

		pos += extDataLen
	}

	return ch, nil
}

// parseUint16List parses a length-prefixed list of uint16 values.
func parseUint16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if listLen > len(data) {
		listLen = len(data)
	}
	var result []uint16
	for i := 0; i+1 < listLen; i += 2 {
		result = append(result, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return result
}

// parseSNI extracts the server name from an SNI extension.
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// SNI list length (2) + type (1) + name length (2) + name
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// parseALPN extracts ALPN protocols.
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if listLen > len(data) {
		listLen = len(data)
	}
	var protos []string
	for i := 0; i < listLen; {
		if i >= len(data) {
			break
		}
		pLen := int(data[i])
		i++
		if i+pLen > listLen || i+pLen > len(data) {
			break
		}
		protos = append(protos, string(data[i:i+pLen]))
		i += pLen
	}
	return protos
}

// parseSupportedVersions extracts the supported_versions client extension.
func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	data = data[1:]
	if listLen > len(data) {
		listLen = len(data)
	}
	var versions []uint16
	for i := 0; i+1 < listLen; i += 2 {
		versions = append(versions, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return versions
}

// IsGREASE reports whether the value is a GREASE (Generate Random Extensions
// And Sustain Extensibility) placeholder, per RFC 8701.
func IsGREASE(val uint16) bool {
	return (val & 0x0f0f) == 0x0a0a
}

// ComputeJA3 computes the JA3 fingerprint string from parsed ClientHello fields.
// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
func ComputeJA3(ch *ClientHelloFields) string {
	var b strings.Builder

	// SSLVersion
	fmt.Fprintf(&b, "%d,", ch.Version)

	// Cipher suites (minus GREASE)
	first := true
	for _, cs := range ch.CipherSuites {
		if IsGREASE(cs) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%d", cs)
		first = false
	}
	b.WriteByte(',')

	// Extensions (minus GREASE)
	first = true
	for _, ext := range ch.Extensions {
		if IsGREASE(ext) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%d", ext)
		first = false
	}
	b.WriteByte(',')

	// Supported groups (minus GREASE)
	first = true
	for _, g := range ch.SupportedGroups {
		if IsGREASE(g) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%d", g)
		first = false
	}
	b.WriteByte(',')

	// EC point formats
	first = true
	for _, pf := range ch.ECPointFormats {
		if !first {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%d", pf)
		first = false
	}

	return b.String()
}

// ComputeJA3Hash computes the MD5 hash of the JA3 fingerprint string.
func ComputeJA3Hash(ch *ClientHelloFields) string {
	ja3 := ComputeJA3(ch)
	hash := md5.Sum([]byte(ja3))
	return fmt.Sprintf("%x", hash)
}

// ComputeJA3FromRaw parses a raw TLS ClientHello record and computes JA3.
func ComputeJA3FromRaw(raw []byte) (ja3String string, ja3Hash string, err error) {
	ch, err := ParseClientHello(raw)
	if err != nil {
		return "", "", err
	}
	s := ComputeJA3(ch)
	hash := md5.Sum([]byte(s))
	return s, fmt.Sprintf("%x", hash), nil
}
