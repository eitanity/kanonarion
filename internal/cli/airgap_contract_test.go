package cli

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// declareAirGapInEnvFile writes `GOPROXY=off` into a Go env file and points
// $GOENV at it, leaving the process environment saying nothing. This is what
// `go env -w GOPROXY=off` does, and the reason it is worth a test of its own:
// an operator who declares the air gap the way the go command documents it was
// previously invisible to every reader in this tree.
func declareAirGapInEnvFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	t.Setenv("GOENV", path)
	t.Setenv("GOPROXY", "")
}

func declarePermitted(t *testing.T) {
	t.Helper()
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("GOPROXY", "https://proxy.example.com")
}

// TestOfflineStdlibAnchor_SelectedByEitherCircumstance pins the wiring
// correction: the local-toolchain anchor is chosen when module bytes come from
// the cache OR when the environment forbids the network. Before, only the first
// selected it, so an air-gapped walk without --from-modcache reached go.dev/dl.
func TestOfflineStdlibAnchor_SelectedByEitherCircumstance(t *testing.T) {
	t.Run("network permitted, network bytes", func(t *testing.T) {
		declarePermitted(t)
		if offlineStdlibAnchor(false) {
			t.Error("offline anchor selected with nothing asking for it")
		}
	})
	t.Run("modcache alone", func(t *testing.T) {
		declarePermitted(t)
		if !offlineStdlibAnchor(true) {
			t.Error("--from-modcache must keep selecting the offline anchor")
		}
	})
	t.Run("air gap alone", func(t *testing.T) {
		declareAirGapInEnvFile(t)
		if !offlineStdlibAnchor(false) {
			t.Error("a declared air gap must select the offline anchor without --from-modcache")
		}
	})
}

// TestEnvFileAirGap_ContainerStillConstructs carries the landed precedent's
// property across to the env-file declaration: the refusal withdraws fetching,
// never the store. A read-only command inside an air gap that could no longer
// build its container would be a worse bug than the egress this closes.
func TestEnvFileAirGap_ContainerStillConstructs(t *testing.T) {
	declareAirGapInEnvFile(t)
	rec := installDialRecorder(t, true)

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	ctr, cleanup, err := NewContainer(t.TempDir(), "", "", false, activeConfig, logger)
	if err != nil {
		t.Fatalf("NewContainer with the air gap declared in Go's env file: %v", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("cleanup: %v", cerr)
		}
	}()
	if ctr.QueryCallGraph == nil || ctr.QueryLicense == nil || ctr.ExecuteWalk == nil {
		t.Fatal("container built without its use cases")
	}
	if dialed := rec.dialed(); len(dialed) != 0 {
		t.Errorf("dialled %v while the env file declares GOPROXY=off", dialed)
	}
}
