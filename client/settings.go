package client

import "github.com/blazehttp/blazehttp/pkg/frame"

// peerSettings tracks the server's HTTP/2 settings.
type peerSettings struct {
	HeaderTableSize     uint32
	EnablePush          uint32
	MaxConcurrentStreams uint32
	InitialWindowSize   uint32
	MaxFrameSize        uint32
	MaxHeaderListSize   uint32
}

// defaultPeerSettings returns the RFC-default settings assumed for the peer
// before their first SETTINGS frame is received.
func defaultPeerSettings() peerSettings {
	return peerSettings{
		HeaderTableSize:     4096,
		EnablePush:          1,
		MaxConcurrentStreams: 100,
		InitialWindowSize:   65535,
		MaxFrameSize:        16384,
		MaxHeaderListSize:   1<<31 - 1,
	}
}

// apply updates the settings from a received SETTINGS frame.
// Returns the old InitialWindowSize for computing the delta.
func (s *peerSettings) apply(settings [frame.MaxSettingsPerFrame]frame.Setting, n int) (uint32, error) {
	old := s.InitialWindowSize
	for i := 0; i < n; i++ {
		p := &settings[i]
		switch p.ID {
		case frame.SettingsHeaderTableSize:
			s.HeaderTableSize = p.Value
		case frame.SettingsEnablePush:
			if p.Value > 1 {
				return old, &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "ENABLE_PUSH must be 0 or 1"}
			}
			s.EnablePush = p.Value
		case frame.SettingsMaxConcurrentStreams:
			s.MaxConcurrentStreams = p.Value
		case frame.SettingsInitialWindowSize:
			if p.Value > 1<<31-1 {
				return old, &frame.ConnError{Code: frame.ErrCodeFlowControlError, Reason: "INITIAL_WINDOW_SIZE too large"}
			}
			s.InitialWindowSize = p.Value
		case frame.SettingsMaxFrameSize:
			if p.Value < frame.DefaultMaxFrameSize || p.Value > frame.MaxMaxFrameSize {
				return old, &frame.ConnError{Code: frame.ErrCodeProtocolError, Reason: "invalid MAX_FRAME_SIZE"}
			}
			s.MaxFrameSize = p.Value
		case frame.SettingsMaxHeaderListSize:
			s.MaxHeaderListSize = p.Value
		}
	}
	return old, nil
}
