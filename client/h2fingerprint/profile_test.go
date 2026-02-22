package h2fingerprint

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blazehttp/blazehttp/pkg/frame"
)

// --- Chrome SETTINGS ---

func TestChromeH2_Settings(t *testing.T) {
	expected := []frame.Setting{
		{ID: frame.SettingsHeaderTableSize, Value: 65536},
		{ID: frame.SettingsMaxConcurrentStreams, Value: 1000},
		{ID: frame.SettingsInitialWindowSize, Value: 6291456},
		{ID: frame.SettingsMaxHeaderListSize, Value: 262144},
	}

	if len(ChromeH2.Settings) != len(expected) {
		t.Fatalf("Chrome settings count: got %d, want %d", len(ChromeH2.Settings), len(expected))
	}

	for i, s := range ChromeH2.Settings {
		if s.ID != expected[i].ID {
			t.Errorf("Chrome setting[%d] ID: got %d, want %d", i, s.ID, expected[i].ID)
		}
		if s.Value != expected[i].Value {
			t.Errorf("Chrome setting[%d] Value: got %d, want %d", i, s.Value, expected[i].Value)
		}
	}
}

func TestChromeH2_SettingsOrder(t *testing.T) {
	// Chrome sends settings in a specific order: 1, 3, 4, 6
	expectedIDs := []frame.SettingsID{
		frame.SettingsHeaderTableSize,     // 1
		frame.SettingsMaxConcurrentStreams, // 3
		frame.SettingsInitialWindowSize,   // 4
		frame.SettingsMaxHeaderListSize,   // 6
	}

	for i, s := range ChromeH2.Settings {
		if s.ID != expectedIDs[i] {
			t.Errorf("Chrome setting order[%d]: got ID %d, want %d", i, s.ID, expectedIDs[i])
		}
	}
}

// --- Firefox SETTINGS ---

func TestFirefoxH2_Settings(t *testing.T) {
	expected := []frame.Setting{
		{ID: frame.SettingsHeaderTableSize, Value: 65536},
		{ID: frame.SettingsInitialWindowSize, Value: 131072},
		{ID: frame.SettingsMaxFrameSize, Value: 16384},
	}

	if len(FirefoxH2.Settings) != len(expected) {
		t.Fatalf("Firefox settings count: got %d, want %d", len(FirefoxH2.Settings), len(expected))
	}

	for i, s := range FirefoxH2.Settings {
		if s.ID != expected[i].ID {
			t.Errorf("Firefox setting[%d] ID: got %d, want %d", i, s.ID, expected[i].ID)
		}
		if s.Value != expected[i].Value {
			t.Errorf("Firefox setting[%d] Value: got %d, want %d", i, s.Value, expected[i].Value)
		}
	}
}

func TestFirefoxH2_SettingsOrder(t *testing.T) {
	// Firefox sends settings in order: 1, 4, 5
	expectedIDs := []frame.SettingsID{
		frame.SettingsHeaderTableSize,   // 1
		frame.SettingsInitialWindowSize, // 4
		frame.SettingsMaxFrameSize,      // 5
	}

	for i, s := range FirefoxH2.Settings {
		if s.ID != expectedIDs[i] {
			t.Errorf("Firefox setting order[%d]: got ID %d, want %d", i, s.ID, expectedIDs[i])
		}
	}
}

// --- WINDOW_UPDATE ---

func TestChromeH2_WindowUpdate(t *testing.T) {
	if ChromeH2.ConnectionWindowUpdate != 15663105 {
		t.Errorf("Chrome WINDOW_UPDATE: got %d, want 15663105", ChromeH2.ConnectionWindowUpdate)
	}
}

func TestFirefoxH2_WindowUpdate(t *testing.T) {
	if FirefoxH2.ConnectionWindowUpdate != 12517377 {
		t.Errorf("Firefox WINDOW_UPDATE: got %d, want 12517377", FirefoxH2.ConnectionWindowUpdate)
	}
}

// --- Pseudo-header order ---

func TestChromeH2_PseudoHeaderOrder(t *testing.T) {
	expected := []string{":method", ":authority", ":scheme", ":path"}
	if len(ChromeH2.PseudoHeaderOrder) != len(expected) {
		t.Fatalf("Chrome pseudo-header count: got %d, want %d",
			len(ChromeH2.PseudoHeaderOrder), len(expected))
	}
	for i, h := range ChromeH2.PseudoHeaderOrder {
		if h != expected[i] {
			t.Errorf("Chrome pseudo-header[%d]: got %q, want %q", i, h, expected[i])
		}
	}
}

func TestFirefoxH2_PseudoHeaderOrder(t *testing.T) {
	expected := []string{":method", ":path", ":authority", ":scheme"}
	if len(FirefoxH2.PseudoHeaderOrder) != len(expected) {
		t.Fatalf("Firefox pseudo-header count: got %d, want %d",
			len(FirefoxH2.PseudoHeaderOrder), len(expected))
	}
	for i, h := range FirefoxH2.PseudoHeaderOrder {
		if h != expected[i] {
			t.Errorf("Firefox pseudo-header[%d]: got %q, want %q", i, h, expected[i])
		}
	}
}

func TestPseudoHeaderOrder_Configurable(t *testing.T) {
	custom := ChromeH2.Clone()
	custom.PseudoHeaderOrder = []string{":method", ":path", ":scheme", ":authority"}

	// Original unchanged
	if ChromeH2.PseudoHeaderOrder[1] != ":authority" {
		t.Error("original Chrome profile was mutated")
	}
	// Custom changed
	if custom.PseudoHeaderOrder[1] != ":path" {
		t.Errorf("custom pseudo-header[1]: got %q, want %q", custom.PseudoHeaderOrder[1], ":path")
	}
}

// --- Priority frames ---

func TestChromeH2_PriorityFrames(t *testing.T) {
	expected := []PriorityInit{
		{StreamID: 3, Dep: 0, Weight: 200, Exclusive: false},
		{StreamID: 5, Dep: 0, Weight: 100, Exclusive: false},
		{StreamID: 7, Dep: 0, Weight: 0, Exclusive: false},
		{StreamID: 9, Dep: 7, Weight: 0, Exclusive: false},
		{StreamID: 11, Dep: 3, Weight: 0, Exclusive: false},
	}

	if len(ChromeH2.PriorityFrames) != len(expected) {
		t.Fatalf("Chrome priority frames: got %d, want %d", len(ChromeH2.PriorityFrames), len(expected))
	}
	for i, p := range ChromeH2.PriorityFrames {
		if p != expected[i] {
			t.Errorf("Chrome priority[%d]: got %+v, want %+v", i, p, expected[i])
		}
	}
}

func TestFirefoxH2_NoPriorityFrames(t *testing.T) {
	if len(FirefoxH2.PriorityFrames) != 0 {
		t.Errorf("Firefox should have no priority frames, got %d", len(FirefoxH2.PriorityFrames))
	}
}

// --- Akamai hash ---

func TestAkamaiHash_Chrome(t *testing.T) {
	expected := "1:65536;3:1000;4:6291456;6:262144|15663105|3:0:200:0,5:0:100:0,7:0:0:0,9:7:0:0,11:3:0:0|m,a,s,p"
	got := ComputeAkamaiHash(&ChromeH2)
	if got != expected {
		t.Errorf("Chrome Akamai hash:\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestAkamaiHash_Firefox(t *testing.T) {
	expected := "1:65536;4:131072;5:16384|12517377||m,p,a,s"
	got := ComputeAkamaiHash(&FirefoxH2)
	if got != expected {
		t.Errorf("Firefox Akamai hash:\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestAkamaiHash_NoPriority(t *testing.T) {
	profile := H2Profile{
		Name: "no-priority",
		Settings: []frame.Setting{
			{ID: frame.SettingsHeaderTableSize, Value: 4096},
		},
		ConnectionWindowUpdate: 65535,
	}
	expected := "1:4096|65535||"
	got := ComputeAkamaiHash(&profile)
	if got != expected {
		t.Errorf("No-priority Akamai hash:\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestAkamaiHash_ExclusivePriority(t *testing.T) {
	profile := H2Profile{
		Name: "exclusive",
		Settings: []frame.Setting{
			{ID: frame.SettingsInitialWindowSize, Value: 65535},
		},
		ConnectionWindowUpdate: 0,
		PriorityFrames: []PriorityInit{
			{StreamID: 1, Dep: 0, Weight: 255, Exclusive: true},
		},
	}
	expected := "4:65535|0|1:0:255:1|"
	got := ComputeAkamaiHash(&profile)
	if got != expected {
		t.Errorf("Exclusive priority Akamai hash:\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestAkamaiHash_EmptyProfile(t *testing.T) {
	profile := H2Profile{Name: "empty"}
	got := ComputeAkamaiHash(&profile)
	if got != "|0||" {
		t.Errorf("Empty profile Akamai hash: got %q, want %q", got, "|0||")
	}
}

// --- ParseAkamaiHash ---

func TestParseAkamaiHash_Valid(t *testing.T) {
	hash := "1:65536;3:1000;4:6291456;6:262144|15663105|3:0:200:0,5:0:100:0|m,a,s,p"
	settings, wu, priorities, ph, err := ParseAkamaiHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if settings != "1:65536;3:1000;4:6291456;6:262144" {
		t.Errorf("settings: %q", settings)
	}
	if wu != "15663105" {
		t.Errorf("window update: %q", wu)
	}
	if priorities != "3:0:200:0,5:0:100:0" {
		t.Errorf("priorities: %q", priorities)
	}
	if ph != "m,a,s,p" {
		t.Errorf("pseudo-headers: %q", ph)
	}
}

func TestParseAkamaiHash_Invalid(t *testing.T) {
	_, _, _, _, err := ParseAkamaiHash("invalid")
	if err == nil {
		t.Error("expected error for invalid hash")
	}
}

func TestParseAkamaiHash_EmptyPriority(t *testing.T) {
	settings, wu, priorities, ph, err := ParseAkamaiHash("1:4096|65535||")
	if err != nil {
		t.Fatal(err)
	}
	if settings != "1:4096" {
		t.Errorf("settings: %q", settings)
	}
	if wu != "65535" {
		t.Errorf("window update: %q", wu)
	}
	if priorities != "" {
		t.Errorf("priorities: expected empty, got %q", priorities)
	}
	if ph != "" {
		t.Errorf("pseudo-headers: expected empty, got %q", ph)
	}
}

// --- Clone ---

func TestClone_DeepCopy(t *testing.T) {
	original := ChromeH2
	cloned := original.Clone()

	// Modify clone
	cloned.Name = "Modified"
	cloned.Settings[0].Value = 99999
	cloned.PseudoHeaderOrder[0] = ":custom"
	cloned.PriorityFrames[0].Weight = 42
	cloned.DefaultHeaders[0].Value = "modified"
	cloned.HeaderOrder[0] = "modified"
	cloned.ConnectionWindowUpdate = 0

	// Original unchanged
	if original.Name != "Chrome-120" {
		t.Error("original name mutated")
	}
	if original.Settings[0].Value != 65536 {
		t.Error("original settings mutated")
	}
	if original.PseudoHeaderOrder[0] != ":method" {
		t.Error("original pseudo-header order mutated")
	}
	if original.PriorityFrames[0].Weight != 200 {
		t.Error("original priority frames mutated")
	}
	if original.DefaultHeaders[0].Value != `"Chromium";v="120", "Not_A_Brand";v="8"` {
		t.Error("original default headers mutated")
	}
	if original.HeaderOrder[0] != "host" {
		t.Error("original header order mutated")
	}
	if original.ConnectionWindowUpdate != 15663105 {
		t.Error("original window update mutated")
	}
}

func TestClone_EmptyFields(t *testing.T) {
	original := H2Profile{Name: "empty"}
	cloned := original.Clone()
	if cloned.Name != "empty" {
		t.Errorf("clone name: %q", cloned.Name)
	}
	if cloned.Settings != nil {
		t.Error("expected nil settings")
	}
	if cloned.PseudoHeaderOrder != nil {
		t.Error("expected nil pseudo-header order")
	}
	if cloned.PriorityFrames != nil {
		t.Error("expected nil priority frames")
	}
	if cloned.DefaultHeaders != nil {
		t.Error("expected nil default headers")
	}
	if cloned.HeaderOrder != nil {
		t.Error("expected nil header order")
	}
}

// --- SettingsMap ---

func TestSettingsMap_Chrome(t *testing.T) {
	m := ChromeH2.SettingsMap()
	if v, ok := m[frame.SettingsHeaderTableSize]; !ok || v != 65536 {
		t.Errorf("header table size: %v %v", v, ok)
	}
	if v, ok := m[frame.SettingsMaxConcurrentStreams]; !ok || v != 1000 {
		t.Errorf("max concurrent streams: %v %v", v, ok)
	}
	if v, ok := m[frame.SettingsInitialWindowSize]; !ok || v != 6291456 {
		t.Errorf("initial window size: %v %v", v, ok)
	}
	if v, ok := m[frame.SettingsMaxHeaderListSize]; !ok || v != 262144 {
		t.Errorf("max header list size: %v %v", v, ok)
	}
}

func TestSettingsMap_Firefox(t *testing.T) {
	m := FirefoxH2.SettingsMap()
	if v, ok := m[frame.SettingsHeaderTableSize]; !ok || v != 65536 {
		t.Errorf("header table size: %v %v", v, ok)
	}
	if v, ok := m[frame.SettingsInitialWindowSize]; !ok || v != 131072 {
		t.Errorf("initial window size: %v %v", v, ok)
	}
	if v, ok := m[frame.SettingsMaxFrameSize]; !ok || v != 16384 {
		t.Errorf("max frame size: %v %v", v, ok)
	}
	if _, ok := m[frame.SettingsMaxConcurrentStreams]; ok {
		t.Error("Firefox should not have SettingsMaxConcurrentStreams")
	}
}

// --- Default headers ---

func TestChromeH2_DefaultHeaders(t *testing.T) {
	expectedNames := []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language",
	}
	if len(ChromeH2.DefaultHeaders) != len(expectedNames) {
		t.Fatalf("Chrome default headers: got %d, want %d", len(ChromeH2.DefaultHeaders), len(expectedNames))
	}
	for i, h := range ChromeH2.DefaultHeaders {
		if h.Name != expectedNames[i] {
			t.Errorf("Chrome header[%d] name: got %q, want %q", i, h.Name, expectedNames[i])
		}
		if h.Value == "" {
			t.Errorf("Chrome header[%d] %q has empty value", i, h.Name)
		}
	}
}

func TestFirefoxH2_DefaultHeaders(t *testing.T) {
	expectedNames := []string{
		"accept", "accept-language", "accept-encoding",
		"upgrade-insecure-requests",
		"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
		"te",
	}
	if len(FirefoxH2.DefaultHeaders) != len(expectedNames) {
		t.Fatalf("Firefox default headers: got %d, want %d", len(FirefoxH2.DefaultHeaders), len(expectedNames))
	}
	for i, h := range FirefoxH2.DefaultHeaders {
		if h.Name != expectedNames[i] {
			t.Errorf("Firefox header[%d] name: got %q, want %q", i, h.Name, expectedNames[i])
		}
		if h.Value == "" {
			t.Errorf("Firefox header[%d] %q has empty value", i, h.Name)
		}
	}
}

// --- Header order ---

func TestChromeH2_HeaderOrder(t *testing.T) {
	expected := []string{
		"host", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language", "cookie",
	}
	if len(ChromeH2.HeaderOrder) != len(expected) {
		t.Fatalf("Chrome header order: got %d, want %d", len(ChromeH2.HeaderOrder), len(expected))
	}
	for i, h := range ChromeH2.HeaderOrder {
		if h != expected[i] {
			t.Errorf("Chrome header order[%d]: got %q, want %q", i, h, expected[i])
		}
	}
}

func TestFirefoxH2_HeaderOrder(t *testing.T) {
	expected := []string{
		"host", "user-agent", "accept", "accept-language",
		"accept-encoding", "upgrade-insecure-requests",
		"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
		"sec-fetch-user", "te", "cookie",
	}
	if len(FirefoxH2.HeaderOrder) != len(expected) {
		t.Fatalf("Firefox header order: got %d, want %d", len(FirefoxH2.HeaderOrder), len(expected))
	}
	for i, h := range FirefoxH2.HeaderOrder {
		if h != expected[i] {
			t.Errorf("Firefox header order[%d]: got %q, want %q", i, h, expected[i])
		}
	}
}

// --- Frame wire encoding tests ---
// Verify SETTINGS and WINDOW_UPDATE are encoded correctly when written to a connection.

func TestChromeH2_SettingsFrameEncoding(t *testing.T) {
	var buf bytes.Buffer
	fw := frame.AcquireFrameWriter(&buf)
	defer frame.ReleaseFrameWriter(fw)

	fw.WriteSettings(ChromeH2.Settings...)
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	data := buf.Bytes()
	fr := frame.AcquireFrameReader(&buf)
	defer frame.ReleaseFrameReader(fr)

	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}

	if f.Type != frame.FrameSettings {
		t.Fatalf("frame type: got %v, want SETTINGS", f.Type)
	}
	if f.StreamID != 0 {
		t.Errorf("stream ID: got %d, want 0", f.StreamID)
	}
	if f.NumSettings != len(ChromeH2.Settings) {
		t.Fatalf("num settings: got %d, want %d", f.NumSettings, len(ChromeH2.Settings))
	}
	for i := 0; i < f.NumSettings; i++ {
		if f.Settings[i].ID != ChromeH2.Settings[i].ID {
			t.Errorf("setting[%d] ID: got %d, want %d", i, f.Settings[i].ID, ChromeH2.Settings[i].ID)
		}
		if f.Settings[i].Value != ChromeH2.Settings[i].Value {
			t.Errorf("setting[%d] Value: got %d, want %d", i, f.Settings[i].Value, ChromeH2.Settings[i].Value)
		}
	}

	// Verify wire length: 9-byte header + 4 settings * 6 bytes = 33
	expectedLen := 9 + len(ChromeH2.Settings)*6
	if len(data) != expectedLen {
		t.Errorf("wire length: got %d, want %d", len(data), expectedLen)
	}
}

func TestFirefoxH2_SettingsFrameEncoding(t *testing.T) {
	var buf bytes.Buffer
	fw := frame.AcquireFrameWriter(&buf)
	defer frame.ReleaseFrameWriter(fw)

	fw.WriteSettings(FirefoxH2.Settings...)
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	fr := frame.AcquireFrameReader(&buf)
	defer frame.ReleaseFrameReader(fr)

	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}

	if f.Type != frame.FrameSettings {
		t.Fatalf("frame type: got %v, want SETTINGS", f.Type)
	}
	if f.NumSettings != len(FirefoxH2.Settings) {
		t.Fatalf("num settings: got %d, want %d", f.NumSettings, len(FirefoxH2.Settings))
	}
	for i := 0; i < f.NumSettings; i++ {
		if f.Settings[i].ID != FirefoxH2.Settings[i].ID {
			t.Errorf("setting[%d] ID: got %d, want %d", i, f.Settings[i].ID, FirefoxH2.Settings[i].ID)
		}
		if f.Settings[i].Value != FirefoxH2.Settings[i].Value {
			t.Errorf("setting[%d] Value: got %d, want %d", i, f.Settings[i].Value, FirefoxH2.Settings[i].Value)
		}
	}
}

func TestChromeH2_WindowUpdateFrameEncoding(t *testing.T) {
	var buf bytes.Buffer
	fw := frame.AcquireFrameWriter(&buf)
	defer frame.ReleaseFrameWriter(fw)

	fw.WriteWindowUpdate(0, ChromeH2.ConnectionWindowUpdate)
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	fr := frame.AcquireFrameReader(&buf)
	defer frame.ReleaseFrameReader(fr)

	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}

	if f.Type != frame.FrameWindowUpdate {
		t.Fatalf("frame type: got %v, want WINDOW_UPDATE", f.Type)
	}
	if f.StreamID != 0 {
		t.Errorf("stream ID: got %d, want 0", f.StreamID)
	}
	if f.WindowIncrement != ChromeH2.ConnectionWindowUpdate {
		t.Errorf("window increment: got %d, want %d", f.WindowIncrement, ChromeH2.ConnectionWindowUpdate)
	}
}

func TestFirefoxH2_WindowUpdateFrameEncoding(t *testing.T) {
	var buf bytes.Buffer
	fw := frame.AcquireFrameWriter(&buf)
	defer frame.ReleaseFrameWriter(fw)

	fw.WriteWindowUpdate(0, FirefoxH2.ConnectionWindowUpdate)
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	fr := frame.AcquireFrameReader(&buf)
	defer frame.ReleaseFrameReader(fr)

	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}

	if f.Type != frame.FrameWindowUpdate {
		t.Fatalf("frame type: got %v, want WINDOW_UPDATE", f.Type)
	}
	if f.WindowIncrement != FirefoxH2.ConnectionWindowUpdate {
		t.Errorf("window increment: got %d, want %d", f.WindowIncrement, FirefoxH2.ConnectionWindowUpdate)
	}
}

func TestChromeH2_PriorityFrameEncoding(t *testing.T) {
	var buf bytes.Buffer
	fw := frame.AcquireFrameWriter(&buf)
	defer frame.ReleaseFrameWriter(fw)

	for _, p := range ChromeH2.PriorityFrames {
		fw.WritePriority(p.StreamID, frame.PriorityParam{
			StreamDep: p.Dep,
			Weight:    p.Weight,
			Exclusive: p.Exclusive,
		})
	}
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	fr := frame.AcquireFrameReader(&buf)
	defer frame.ReleaseFrameReader(fr)

	for i, expected := range ChromeH2.PriorityFrames {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("priority[%d] read: %v", i, err)
		}
		if f.Type != frame.FramePriority {
			t.Fatalf("priority[%d] type: got %v, want PRIORITY", i, f.Type)
		}
		if f.StreamID != expected.StreamID {
			t.Errorf("priority[%d] stream ID: got %d, want %d", i, f.StreamID, expected.StreamID)
		}
		if f.StreamDep != expected.Dep {
			t.Errorf("priority[%d] dep: got %d, want %d", i, f.StreamDep, expected.Dep)
		}
		if f.Weight != expected.Weight {
			t.Errorf("priority[%d] weight: got %d, want %d", i, f.Weight, expected.Weight)
		}
		if f.Exclusive != expected.Exclusive {
			t.Errorf("priority[%d] exclusive: got %v, want %v", i, f.Exclusive, expected.Exclusive)
		}
	}
}

// --- Full connection preface simulation ---

func TestChromeH2_FullPreface(t *testing.T) {
	var buf bytes.Buffer

	// HTTP/2 connection preface magic
	buf.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	fw := frame.AcquireFrameWriter(&buf)
	defer frame.ReleaseFrameWriter(fw)

	fw.WriteSettings(ChromeH2.Settings...)
	fw.WriteWindowUpdate(0, ChromeH2.ConnectionWindowUpdate)
	for _, p := range ChromeH2.PriorityFrames {
		fw.WritePriority(p.StreamID, frame.PriorityParam{
			StreamDep: p.Dep,
			Weight:    p.Weight,
			Exclusive: p.Exclusive,
		})
	}
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	data := buf.Bytes()

	// Verify magic prefix
	magic := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if !bytes.HasPrefix(data, []byte(magic)) {
		t.Fatal("missing HTTP/2 connection preface")
	}

	// Parse frames after magic
	fr := frame.AcquireFrameReader(bytes.NewReader(data[len(magic):]))
	defer frame.ReleaseFrameReader(fr)

	// SETTINGS
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != frame.FrameSettings {
		t.Fatalf("frame 1: got %v, want SETTINGS", f.Type)
	}
	if f.NumSettings != 4 {
		t.Fatalf("SETTINGS count: got %d, want 4", f.NumSettings)
	}

	// WINDOW_UPDATE
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != frame.FrameWindowUpdate {
		t.Fatalf("frame 2: got %v, want WINDOW_UPDATE", f.Type)
	}
	if f.WindowIncrement != 15663105 {
		t.Errorf("WINDOW_UPDATE: got %d, want 15663105", f.WindowIncrement)
	}

	// 5 PRIORITY frames
	for i := 0; i < 5; i++ {
		f, err = fr.ReadFrame()
		if err != nil {
			t.Fatalf("priority frame %d: %v", i, err)
		}
		if f.Type != frame.FramePriority {
			t.Fatalf("frame %d: got %v, want PRIORITY", i+3, f.Type)
		}
	}
}

func TestFirefoxH2_FullPreface(t *testing.T) {
	var buf bytes.Buffer

	buf.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	fw := frame.AcquireFrameWriter(&buf)
	defer frame.ReleaseFrameWriter(fw)

	fw.WriteSettings(FirefoxH2.Settings...)
	fw.WriteWindowUpdate(0, FirefoxH2.ConnectionWindowUpdate)
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	data := buf.Bytes()
	magic := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	fr := frame.AcquireFrameReader(bytes.NewReader(data[len(magic):]))
	defer frame.ReleaseFrameReader(fr)

	// SETTINGS
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != frame.FrameSettings {
		t.Fatalf("frame 1: got %v, want SETTINGS", f.Type)
	}
	if f.NumSettings != 3 {
		t.Fatalf("SETTINGS count: got %d, want 3", f.NumSettings)
	}

	// WINDOW_UPDATE
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != frame.FrameWindowUpdate {
		t.Fatalf("frame 2: got %v, want WINDOW_UPDATE", f.Type)
	}
	if f.WindowIncrement != 12517377 {
		t.Errorf("WINDOW_UPDATE: got %d, want 12517377", f.WindowIncrement)
	}

	// No more frames
	_, err = fr.ReadFrame()
	if err == nil {
		t.Error("expected EOF after WINDOW_UPDATE")
	}
}

// --- Integration: capture frames from TLS connection ---

func TestChromeH2_CaptureFrames(t *testing.T) {
	captured := captureH2Preface(t, &ChromeH2)

	if len(captured) < 2 {
		t.Fatalf("expected at least 2 frames, got %d", len(captured))
	}

	// First frame: SETTINGS
	if captured[0].Type != frame.FrameSettings {
		t.Fatalf("frame 0: got %v, want SETTINGS", captured[0].Type)
	}
	if captured[0].NumSettings != len(ChromeH2.Settings) {
		t.Fatalf("settings count: got %d, want %d", captured[0].NumSettings, len(ChromeH2.Settings))
	}
	for i := 0; i < captured[0].NumSettings; i++ {
		if captured[0].Settings[i] != ChromeH2.Settings[i] {
			t.Errorf("setting[%d]: got %+v, want %+v", i, captured[0].Settings[i], ChromeH2.Settings[i])
		}
	}

	// Second frame: WINDOW_UPDATE
	if captured[1].Type != frame.FrameWindowUpdate {
		t.Fatalf("frame 1: got %v, want WINDOW_UPDATE", captured[1].Type)
	}
	if captured[1].WindowIncrement != ChromeH2.ConnectionWindowUpdate {
		t.Errorf("window update: got %d, want %d", captured[1].WindowIncrement, ChromeH2.ConnectionWindowUpdate)
	}

	// Frames 2-6: PRIORITY
	for i := 0; i < len(ChromeH2.PriorityFrames); i++ {
		idx := i + 2
		if idx >= len(captured) {
			t.Fatalf("missing priority frame %d", i)
		}
		if captured[idx].Type != frame.FramePriority {
			t.Fatalf("frame %d: got %v, want PRIORITY", idx, captured[idx].Type)
		}
		if captured[idx].StreamID != ChromeH2.PriorityFrames[i].StreamID {
			t.Errorf("priority[%d] stream: got %d, want %d", i, captured[idx].StreamID, ChromeH2.PriorityFrames[i].StreamID)
		}
		if captured[idx].Weight != ChromeH2.PriorityFrames[i].Weight {
			t.Errorf("priority[%d] weight: got %d, want %d", i, captured[idx].Weight, ChromeH2.PriorityFrames[i].Weight)
		}
	}
}

func TestFirefoxH2_CaptureFrames(t *testing.T) {
	captured := captureH2Preface(t, &FirefoxH2)

	if len(captured) < 2 {
		t.Fatalf("expected at least 2 frames, got %d", len(captured))
	}

	// SETTINGS
	if captured[0].Type != frame.FrameSettings {
		t.Fatalf("frame 0: got %v, want SETTINGS", captured[0].Type)
	}
	if captured[0].NumSettings != len(FirefoxH2.Settings) {
		t.Fatalf("settings count: got %d, want %d", captured[0].NumSettings, len(FirefoxH2.Settings))
	}

	// WINDOW_UPDATE
	if captured[1].Type != frame.FrameWindowUpdate {
		t.Fatalf("frame 1: got %v, want WINDOW_UPDATE", captured[1].Type)
	}
	if captured[1].WindowIncrement != FirefoxH2.ConnectionWindowUpdate {
		t.Errorf("window update: got %d, want %d", captured[1].WindowIncrement, FirefoxH2.ConnectionWindowUpdate)
	}

	// No PRIORITY frames for Firefox
	for i := 2; i < len(captured); i++ {
		if captured[i].Type == frame.FramePriority {
			t.Errorf("unexpected PRIORITY frame at index %d", i)
		}
	}
}

// --- Profile names ---

func TestProfileNames(t *testing.T) {
	if ChromeH2.Name != "Chrome-120" {
		t.Errorf("Chrome name: %q", ChromeH2.Name)
	}
	if FirefoxH2.Name != "Firefox-121" {
		t.Errorf("Firefox name: %q", FirefoxH2.Name)
	}
}

// --- Akamai hash roundtrip ---

func TestAkamaiHash_Roundtrip(t *testing.T) {
	hash := ComputeAkamaiHash(&ChromeH2)
	settings, wu, priorities, ph, err := ParseAkamaiHash(hash)
	if err != nil {
		t.Fatal(err)
	}

	if settings != "1:65536;3:1000;4:6291456;6:262144" {
		t.Errorf("roundtrip settings: %q", settings)
	}
	if wu != "15663105" {
		t.Errorf("roundtrip window update: %q", wu)
	}
	if priorities != "3:0:200:0,5:0:100:0,7:0:0:0,9:7:0:0,11:3:0:0" {
		t.Errorf("roundtrip priorities: %q", priorities)
	}
	if ph != "m,a,s,p" {
		t.Errorf("roundtrip pseudo-headers: %q", ph)
	}
}

// --- Differential test: Chrome vs Firefox Akamai hash ---

func TestAkamaiHash_ChromeVsFirefox(t *testing.T) {
	chromeHash := ComputeAkamaiHash(&ChromeH2)
	firefoxHash := ComputeAkamaiHash(&FirefoxH2)

	if chromeHash == firefoxHash {
		t.Error("Chrome and Firefox Akamai hashes should differ")
	}

	// Chrome has priorities, Firefox doesn't
	if !strings.Contains(chromeHash, "3:0:200:0") {
		t.Error("Chrome hash should contain priority entries")
	}
	// Firefox hash should contain pseudo-header section
	if !strings.Contains(firefoxHash, "|m,p,a,s") {
		t.Error("Firefox hash should contain pseudo-header section |m,p,a,s")
	}
}

// --- Profile distinct pseudo-header orders ---

func TestPseudoHeaderOrder_ChromeVsFirefox(t *testing.T) {
	if ChromeH2.PseudoHeaderOrder[1] != ":authority" {
		t.Errorf("Chrome pseudo[1]: %s", ChromeH2.PseudoHeaderOrder[1])
	}
	if FirefoxH2.PseudoHeaderOrder[1] != ":path" {
		t.Errorf("Firefox pseudo[1]: %s", FirefoxH2.PseudoHeaderOrder[1])
	}
}

// --- Helpers ---

// testCert generates a self-signed certificate for testing.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}

// captureH2Preface starts a TLS server, connects a simulated client that
// sends the HTTP/2 connection preface with the profile's frames, and
// returns the captured frames.
func captureH2Preface(t *testing.T, profile *H2Profile) []frame.Frame {
	t.Helper()

	cert := testCert(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		frames []frame.Frame
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer conn.Close()

		// Read the client preface magic
		magic := make([]byte, 24)
		if _, err := io.ReadFull(conn, magic); err != nil {
			ch <- result{err: fmt.Errorf("reading magic: %w", err)}
			return
		}
		if string(magic) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			ch <- result{err: fmt.Errorf("bad magic: %q", magic)}
			return
		}

		// Read frames
		fr := frame.AcquireFrameReader(conn)
		defer frame.ReleaseFrameReader(fr)

		var frames []frame.Frame
		for i := 0; i < 10; i++ {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			// Deep copy relevant fields
			fc := frame.Frame{
				Type:            f.Type,
				Flags:           f.Flags,
				StreamID:        f.StreamID,
				Length:          f.Length,
				NumSettings:     f.NumSettings,
				WindowIncrement: f.WindowIncrement,
				StreamDep:       f.StreamDep,
				Weight:          f.Weight,
				Exclusive:       f.Exclusive,
			}
			for j := 0; j < f.NumSettings; j++ {
				fc.Settings[j] = f.Settings[j]
			}
			frames = append(frames, fc)
		}
		ch <- result{frames: frames}
	}()

	// Client connects and sends preface
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("h2 not negotiated")
	}

	// Send preface
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	fw := frame.AcquireFrameWriter(conn)
	fw.WriteSettings(profile.Settings...)
	if profile.ConnectionWindowUpdate > 0 {
		fw.WriteWindowUpdate(0, profile.ConnectionWindowUpdate)
	}
	for _, p := range profile.PriorityFrames {
		fw.WritePriority(p.StreamID, frame.PriorityParam{
			StreamDep: p.Dep,
			Weight:    p.Weight,
			Exclusive: p.Exclusive,
		})
	}
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}
	frame.ReleaseFrameWriter(fw)

	// Close write side to signal we're done
	if tc, ok := conn.NetConn().(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	} else {
		conn.Close()
	}

	res := <-ch
	if res.err != nil {
		t.Fatal(res.err)
	}
	return res.frames
}
