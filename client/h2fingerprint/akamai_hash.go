package h2fingerprint

import (
	"fmt"
	"strings"
)

// ComputeAkamaiHash computes the Akamai HTTP/2 fingerprint hash for a profile.
//
// Format: S[settings]|WU[window_update]|P[priority_tree]|PH[pseudo_headers]
//
// Where:
//   - settings: semicolon-separated id:value pairs in the original order
//   - window_update: the connection-level WINDOW_UPDATE value (0 if none)
//   - priority_tree: comma-separated streamID:dep:weight:exclusive entries
//   - pseudo_headers: comma-separated abbreviations (m=:method, a=:authority, s=:scheme, p=:path)
//
// Example (Chrome 120):
//
//	1:65536;3:1000;4:6291456;6:262144|15663105|3:0:200:0,5:0:100:0,7:0:0:0,9:7:0:0,11:3:0:0|m,a,s,p
func ComputeAkamaiHash(profile *H2Profile) string {
	var b strings.Builder

	// Settings section: id:value;id:value;...
	for i, s := range profile.Settings {
		if i > 0 {
			b.WriteByte(';')
		}
		fmt.Fprintf(&b, "%d:%d", s.ID, s.Value)
	}

	// Separator + window update
	fmt.Fprintf(&b, "|%d|", profile.ConnectionWindowUpdate)

	// Priority tree: streamID:dep:weight:exclusive,...
	for i, p := range profile.PriorityFrames {
		if i > 0 {
			b.WriteByte(',')
		}
		excl := 0
		if p.Exclusive {
			excl = 1
		}
		fmt.Fprintf(&b, "%d:%d:%d:%d", p.StreamID, p.Dep, p.Weight, excl)
	}

	// Pseudo-header order section.
	b.WriteByte('|')
	for i, ph := range profile.PseudoHeaderOrder {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pseudoHeaderAbbrev(ph))
	}

	return b.String()
}

// pseudoHeaderAbbrev returns the single-char abbreviation for a pseudo-header.
func pseudoHeaderAbbrev(ph string) string {
	switch ph {
	case ":method":
		return "m"
	case ":authority":
		return "a"
	case ":scheme":
		return "s"
	case ":path":
		return "p"
	default:
		return ph
	}
}

// ParseAkamaiHash parses an Akamai HTTP/2 fingerprint hash string back into
// its component parts. Accepts both 3-section (legacy) and 4-section formats.
func ParseAkamaiHash(hash string) (settings string, windowUpdate string, priorities string, pseudoHeaders string, err error) {
	parts := strings.SplitN(hash, "|", 4)
	if len(parts) < 3 {
		return "", "", "", "", fmt.Errorf("h2fingerprint: invalid Akamai hash format: expected 3-4 pipe-separated sections, got %d", len(parts))
	}
	ph := ""
	if len(parts) == 4 {
		ph = parts[3]
	}
	return parts[0], parts[1], parts[2], ph, nil
}
