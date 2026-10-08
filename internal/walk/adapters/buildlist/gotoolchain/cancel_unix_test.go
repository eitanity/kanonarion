//go:build unix

package gotoolchain_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
)

// probeGo stands in for the go command: the module list and graph answer at once,
// and `go env` runs envBody after touching started.
func probeGo(t *testing.T, envBody string) (bin, started string) {
	t.Helper()
	dir := t.TempDir()
	started = filepath.Join(dir, "started")
	bin = filepath.Join(dir, "go")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"list) printf '%s' '{\"Path\":\"example.com/p\",\"Main\":true}' ;;\n" +
		"mod) printf 'example.com/p example.com/d@v1.0.0\\n' ;;\n" +
		"env) touch " + started + "; " + envBody + " ;;\n" +
		"esac\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatalf("writing the stand-in go: %v", err)
	}
	return bin, started
}

// An environment probe the run's cancellation stopped is neither a failed probe
// nor an environment with no toolchain: the resolve returns the cancellation and
// logs no warning. A probe that genuinely failed still warns and degrades.
func TestResolve_EnvironmentProbeStoppedByTheCancellation(t *testing.T) {
	bin, started := probeGo(t, "sleep 30")
	var logs bytes.Buffer
	r := gotoolchain.New(bin, slog.New(slog.NewTextHandler(&logs, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(started); err == nil {
				break
			}
		}
		cancel()
	}()
	bl, err := r.Resolve(ctx, t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v (build list %+v), want the cancellation", err, bl)
	}
	if strings.Contains(logs.String(), "env_probe_failed") {
		t.Errorf("a stopped probe was logged as a failure:\n%s", logs.String())
	}

	failing, _ := probeGo(t, "exit 1")
	logs.Reset()
	bl, err = gotoolchain.New(failing, slog.New(slog.NewTextHandler(&logs, nil))).Resolve(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("a failed probe must degrade, not fail the resolve: %v", err)
	}
	if bl.GoVersion != "" || !strings.Contains(logs.String(), "level=WARN msg=walk.build_list.env_probe_failed") {
		t.Errorf("a failed probe recorded GoVersion %q and logged:\n%s", bl.GoVersion, logs.String())
	}
}
