package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
)

func TestStderrProgressReporter_ThrottlesByInterval(t *testing.T) {
	var buf bytes.Buffer
	base := time.Unix(1_000, 0)
	now := base
	r := newStderrProgressReporter(&buf, 20*time.Second, func() time.Time { return now }, "walk progress: %d modules fetched (%s elapsed)\n")

	// First call lands at t≈start: within the interval, so silent.
	r.Advance(1)
	if buf.Len() != 0 {
		t.Fatalf("first Advance emitted output, want silence: %q", buf.String())
	}

	// Still inside the interval: silent.
	now = base.Add(10 * time.Second)
	r.Advance(5)
	if buf.Len() != 0 {
		t.Fatalf("Advance within interval emitted output: %q", buf.String())
	}

	// Interval elapsed: one line.
	now = base.Add(25 * time.Second)
	r.Advance(42)
	got := buf.String()
	if !strings.Contains(got, "42 modules fetched") {
		t.Errorf("line missing module count: %q", got)
	}
	if !strings.Contains(got, "25s elapsed") {
		t.Errorf("line missing elapsed time: %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Errorf("want exactly one line, got %q", got)
	}

	// Next call within a fresh interval: silent again.
	buf.Reset()
	now = base.Add(30 * time.Second)
	r.Advance(50)
	if buf.Len() != 0 {
		t.Fatalf("Advance within new interval emitted output: %q", buf.String())
	}
}

func TestNewWalkProgressReporter_Enablement(t *testing.T) {
	on := configdomain.Config{Preferences: configdomain.Preferences{Progress: true}}
	off := configdomain.Config{Preferences: configdomain.Preferences{Progress: false}}

	tests := []struct {
		name       string
		noProgress bool
		cfg        configdomain.Config
		level      string
		wantNil    bool
	}{
		{"default on", false, on, "warn", false},
		{"error level still on", false, on, "error", false},
		{"no-progress flag", true, on, "warn", true},
		{"preference disabled", false, off, "warn", true},
		{"info streams already", false, on, "info", true},
		{"debug streams already", false, on, "debug", true},
		{"info uppercase", false, on, "INFO", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			got := newWalkProgressReporter(&buf, tt.noProgress, tt.cfg, tt.level)
			if (got == nil) != tt.wantNil {
				t.Errorf("newWalkProgressReporter nil=%v, want nil=%v", got == nil, tt.wantNil)
			}
		})
	}
}

// newExtractProgressReporter shares its enablement rules with
// newWalkProgressReporter (same gating: --no-progress, preferences.progress,
// and info/debug log levels that already stream per-module lines).
func TestNewExtractProgressReporter_Enablement(t *testing.T) {
	on := configdomain.Config{Preferences: configdomain.Preferences{Progress: true}}
	off := configdomain.Config{Preferences: configdomain.Preferences{Progress: false}}

	tests := []struct {
		name       string
		noProgress bool
		cfg        configdomain.Config
		level      string
		wantNil    bool
	}{
		{"default on", false, on, "warn", false},
		{"no-progress flag", true, on, "warn", true},
		{"preference disabled", false, off, "warn", true},
		{"debug streams already", false, on, "debug", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			got := newExtractProgressReporter(&buf, tt.noProgress, tt.cfg, tt.level)
			if (got == nil) != tt.wantNil {
				t.Errorf("newExtractProgressReporter nil=%v, want nil=%v", got == nil, tt.wantNil)
			}
		})
	}
}
