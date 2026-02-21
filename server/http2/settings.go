package http2

import "github.com/blazehttp/blazehttp/pkg/frame"

// ConnSettings holds the HTTP/2 connection settings.
type ConnSettings struct {
	HeaderTableSize     uint32
	EnablePush          uint32
	MaxConcurrentStreams uint32
	InitialWindowSize   uint32
	MaxFrameSize        uint32
	MaxHeaderListSize   uint32
}

// DefaultServerSettings returns the settings the server advertises.
func DefaultServerSettings() ConnSettings {
	return ConnSettings{
		HeaderTableSize:     4096,
		EnablePush:          0,
		MaxConcurrentStreams: 250,
		InitialWindowSize:   1 << 20, // 1MB — larger window for better throughput
		MaxFrameSize:        16384,
		MaxHeaderListSize:   1 << 20,
	}
}

// DefaultPeerSettings returns the RFC-default settings assumed for the peer
// before their first SETTINGS frame is received.
func DefaultPeerSettings() ConnSettings {
	return ConnSettings{
		HeaderTableSize:     4096,
		EnablePush:          1,
		MaxConcurrentStreams: 100, // conservative default
		InitialWindowSize:   65535,
		MaxFrameSize:        16384,
		MaxHeaderListSize:   1<<31 - 1, // unlimited per RFC
	}
}

// Apply updates the settings from a received SETTINGS frame.
// Returns the old InitialWindowSize for computing the delta.
func (s *ConnSettings) Apply(settings [frame.MaxSettingsPerFrame]frame.Setting, n int) (uint32, error) {
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
		// Unknown settings IDs: ignore per RFC 9113 §6.5.2.
		}
	}
	return old, nil
}

// ToSettings serializes the settings for sending in a SETTINGS frame.
func (s *ConnSettings) ToSettings() []frame.Setting {
	return []frame.Setting{
		{ID: frame.SettingsHeaderTableSize, Value: s.HeaderTableSize},
		{ID: frame.SettingsEnablePush, Value: s.EnablePush},
		{ID: frame.SettingsMaxConcurrentStreams, Value: s.MaxConcurrentStreams},
		{ID: frame.SettingsInitialWindowSize, Value: s.InitialWindowSize},
		{ID: frame.SettingsMaxFrameSize, Value: s.MaxFrameSize},
		{ID: frame.SettingsMaxHeaderListSize, Value: s.MaxHeaderListSize},
	}
}
