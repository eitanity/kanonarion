package domain

import "testing"

func TestDefaultConfig_LogLevelIsWarn(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Preferences.LogLevel != "warn" {
		t.Errorf("DefaultConfig().Preferences.LogLevel = %q, want %q", cfg.Preferences.LogLevel, "warn")
	}
}
