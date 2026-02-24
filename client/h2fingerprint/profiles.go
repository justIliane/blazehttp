package h2fingerprint

import (
	"github.com/justIliane/blazehttp/pkg/frame"
)

// Pre-defined HTTP/2 fingerprint profiles matching real browsers.
// Each profile captures the exact SETTINGS order/values, WINDOW_UPDATE,
// pseudo-header order, PRIORITY tree, and default headers.
//
// Last verified: February 2026.
var (
	// ChromeH2 matches Chrome 120+ HTTP/2 fingerprint.
	ChromeH2 = H2Profile{
		Name: "Chrome-120",

		// SETTINGS sent in this exact order.
		Settings: []frame.Setting{
			{ID: frame.SettingsHeaderTableSize, Value: 65536},
			{ID: frame.SettingsMaxConcurrentStreams, Value: 1000},
			{ID: frame.SettingsInitialWindowSize, Value: 6291456},
			{ID: frame.SettingsMaxHeaderListSize, Value: 262144},
		},

		// WINDOW_UPDATE on connection (stream 0) after SETTINGS.
		ConnectionWindowUpdate: 15663105,

		// Chrome pseudo-header order.
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},

		// Chrome priority tree (PRIORITY frames on connection startup).
		PriorityFrames: []PriorityInit{
			{StreamID: 3, Dep: 0, Weight: 200, Exclusive: false},
			{StreamID: 5, Dep: 0, Weight: 100, Exclusive: false},
			{StreamID: 7, Dep: 0, Weight: 0, Exclusive: false},
			{StreamID: 9, Dep: 7, Weight: 0, Exclusive: false},
			{StreamID: 11, Dep: 3, Weight: 0, Exclusive: false},
		},

		// Standard headers Chrome always sends.
		DefaultHeaders: []Header{
			{Name: "sec-ch-ua", Value: `"Chromium";v="120", "Not_A_Brand";v="8"`},
			{Name: "sec-ch-ua-mobile", Value: "?0"},
			{Name: "sec-ch-ua-platform", Value: `"Windows"`},
			{Name: "upgrade-insecure-requests", Value: "1"},
			{Name: "accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
			{Name: "sec-fetch-site", Value: "none"},
			{Name: "sec-fetch-mode", Value: "navigate"},
			{Name: "sec-fetch-user", Value: "?1"},
			{Name: "sec-fetch-dest", Value: "document"},
			{Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
			{Name: "accept-language", Value: "en-US,en;q=0.9"},
		},

		// Chrome header order.
		HeaderOrder: []string{
			"host", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "accept",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"accept-encoding", "accept-language", "cookie",
		},
	}

	// FirefoxH2 matches Firefox 121+ HTTP/2 fingerprint.
	FirefoxH2 = H2Profile{
		Name: "Firefox-121",

		Settings: []frame.Setting{
			{ID: frame.SettingsHeaderTableSize, Value: 65536},
			{ID: frame.SettingsInitialWindowSize, Value: 131072},
			{ID: frame.SettingsMaxFrameSize, Value: 16384},
		},

		ConnectionWindowUpdate: 12517377,

		// Firefox pseudo-header order (different from Chrome).
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},

		// Firefox uses priority in HEADERS, not separate PRIORITY frames.
		PriorityFrames: nil,

		// Standard headers Firefox always sends.
		DefaultHeaders: []Header{
			{Name: "accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{Name: "accept-language", Value: "en-US,en;q=0.5"},
			{Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
			{Name: "upgrade-insecure-requests", Value: "1"},
			{Name: "sec-fetch-dest", Value: "document"},
			{Name: "sec-fetch-mode", Value: "navigate"},
			{Name: "sec-fetch-site", Value: "none"},
			{Name: "sec-fetch-user", Value: "?1"},
			{Name: "te", Value: "trailers"},
		},

		// Firefox header order.
		HeaderOrder: []string{
			"host", "user-agent", "accept", "accept-language",
			"accept-encoding", "upgrade-insecure-requests",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
			"sec-fetch-user", "te", "cookie",
		},
	}
)
