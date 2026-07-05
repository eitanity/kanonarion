package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestDefaultLogLevel_SuppressesInfo verifies that the built-in default log
// level is warn, so INFO diagnostics do not pollute user-facing output unless
// the caller explicitly opts in via --log-level info or --log-level debug.
func TestDefaultLogLevel_SuppressesInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := buildLogger("warn", &buf)
	logger.Info("should not appear")
	logger.Warn("should appear")

	out := buf.String()
	if strings.Contains(out, "should not appear") {
		t.Errorf("default log level (warn) must suppress INFO messages, but got: %q", out)
	}
	if !strings.Contains(out, "should appear") {
		t.Errorf("default log level (warn) must pass WARN messages, but got: %q", out)
	}
}

// TestDefaultLogLevel_FlagDefault confirms the --log-level flag ships with
// "warn" as its hardcoded default, independent of any stored config.
func TestDefaultLogLevel_FlagDefault(t *testing.T) {
	root := newRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
	f := root.PersistentFlags().Lookup("log-level")
	if f == nil {
		t.Fatal("--log-level flag not registered on root command")
	}
	if f.DefValue != "warn" {
		t.Errorf("--log-level default = %q, want %q", f.DefValue, "warn")
	}
}

// TestBuildLogger_FormatFollowsGlobalJSON ensures the log format must be
// driven by the single global --json flag, not a per-call argument, so every
// subsystem in one invocation emits exactly one format on stderr. Independent
// buildLogger calls must therefore agree on format.
func TestBuildLogger_FormatFollowsGlobalJSON(t *testing.T) {
	orig := jsonOut
	t.Cleanup(func() { jsonOut = orig })

	t.Run("json mode emits JSON from every logger", func(t *testing.T) {
		jsonOut = true
		var a, b bytes.Buffer
		buildLogger("info", &a).Info("alpha")
		buildLogger("info", &b).Info("beta")
		for name, out := range map[string]string{"a": a.String(), "b": b.String()} {
			if !strings.HasPrefix(strings.TrimSpace(out), "{") {
				t.Errorf("logger %s: expected JSON line, got %q", name, out)
			}
		}
	})

	t.Run("text mode emits logfmt from every logger", func(t *testing.T) {
		jsonOut = false
		var a, b bytes.Buffer
		buildLogger("info", &a).Info("alpha")
		buildLogger("info", &b).Info("beta")
		for name, out := range map[string]string{"a": a.String(), "b": b.String()} {
			if strings.HasPrefix(strings.TrimSpace(out), "{") {
				t.Errorf("logger %s: expected logfmt line, got JSON %q", name, out)
			}
			if !strings.Contains(out, "level=INFO") {
				t.Errorf("logger %s: expected logfmt line, got %q", name, out)
			}
		}
	})
}
