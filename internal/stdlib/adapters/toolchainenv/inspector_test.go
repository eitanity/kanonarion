package toolchainenv_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/stdlib/adapters/toolchainenv"
)

// TestLocate_RealToolchain probes the actual `go` on PATH. It is the honest
// integration point — the offline custody path stands on this exact command.
func TestLocate_RealToolchain(t *testing.T) {
	root, version, err := toolchainenv.New("", nil).Locate(context.Background())
	if err != nil {
		t.Skipf("go binary not available: %v", err)
	}
	if root == "" {
		t.Error("GOROOT is empty")
	}
	if !strings.HasPrefix(version, "go") {
		t.Errorf("GOVERSION = %q, want a go-prefixed version", version)
	}
	if _, err := os.Stat(filepath.Join(root, "src")); err != nil {
		t.Errorf("resolved GOROOT has no src dir: %v", err)
	}
}

func TestLocate_BadBinaryIsError(t *testing.T) {
	_, _, err := toolchainenv.New("/nonexistent/go", nil).Locate(context.Background())
	if err == nil {
		t.Error("expected an error when the go binary does not exist")
	}
}
