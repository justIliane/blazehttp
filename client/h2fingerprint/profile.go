// Package h2fingerprint defines HTTP/2 connection fingerprint profiles.
// Each profile controls the SETTINGS, WINDOW_UPDATE, pseudo-header order,
// PRIORITY frames, and default headers sent on a new HTTP/2 connection
// to match a real browser's behaviour.
package h2fingerprint

import (
	"github.com/justIliane/blazehttp/pkg/frame"
)

// H2Profile describes an HTTP/2 connection-level fingerprint.
type H2Profile struct {
	// Name identifies this profile (e.g. "Chrome-120", "Firefox-121").
	Name string

	// Settings are sent in this exact order in the initial SETTINGS frame.
	Settings []frame.Setting

	// ConnectionWindowUpdate is the WINDOW_UPDATE increment sent on stream 0
	// immediately after the SETTINGS frame. Zero means no WINDOW_UPDATE is sent.
	ConnectionWindowUpdate uint32

	// PseudoHeaderOrder defines the order of pseudo-headers in HEADERS frames.
	// Default browser orders:
	//   Chrome:  :method, :authority, :scheme, :path
	//   Firefox: :method, :path, :authority, :scheme
	PseudoHeaderOrder []string

	// PriorityFrames are PRIORITY frames sent on connection startup.
	// Chrome sends 5 priority frames to build its priority tree.
	// Firefox sends none (uses priority in HEADERS instead).
	PriorityFrames []PriorityInit

	// DefaultHeaders are standard headers the browser always includes.
	// These are added to every request unless overridden.
	DefaultHeaders []Header

	// HeaderOrder defines the order of regular headers.
	// Headers present in the request are sorted according to this order.
	// Headers not in this list are appended in their original order.
	HeaderOrder []string
}

// PriorityInit describes a PRIORITY frame sent during connection setup.
type PriorityInit struct {
	StreamID  uint32
	Dep       uint32
	Weight    uint8
	Exclusive bool
}

// Header is a name-value pair for HTTP headers.
type Header struct {
	Name  string
	Value string
}

// Clone returns a deep copy of the profile.
func (p *H2Profile) Clone() *H2Profile {
	c := &H2Profile{
		Name:                   p.Name,
		ConnectionWindowUpdate: p.ConnectionWindowUpdate,
	}

	if len(p.Settings) > 0 {
		c.Settings = make([]frame.Setting, len(p.Settings))
		copy(c.Settings, p.Settings)
	}

	if len(p.PseudoHeaderOrder) > 0 {
		c.PseudoHeaderOrder = make([]string, len(p.PseudoHeaderOrder))
		copy(c.PseudoHeaderOrder, p.PseudoHeaderOrder)
	}

	if len(p.PriorityFrames) > 0 {
		c.PriorityFrames = make([]PriorityInit, len(p.PriorityFrames))
		copy(c.PriorityFrames, p.PriorityFrames)
	}

	if len(p.DefaultHeaders) > 0 {
		c.DefaultHeaders = make([]Header, len(p.DefaultHeaders))
		copy(c.DefaultHeaders, p.DefaultHeaders)
	}

	if len(p.HeaderOrder) > 0 {
		c.HeaderOrder = make([]string, len(p.HeaderOrder))
		copy(c.HeaderOrder, p.HeaderOrder)
	}

	return c
}

// SettingsMap returns the settings as a map for easy lookup.
func (p *H2Profile) SettingsMap() map[frame.SettingsID]uint32 {
	m := make(map[frame.SettingsID]uint32, len(p.Settings))
	for _, s := range p.Settings {
		m[s.ID] = s.Value
	}
	return m
}
