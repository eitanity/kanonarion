package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// The child opens the store from its own argv, so the store the parent scans
// must be named there; without it the child wrote to the default store.
func TestSpawn_NamesTheParentsStore(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "argv")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"$@\" >&2\nexit 3\n"), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatalf("write fixture: %v", err)
	}
	s := NewOsCallGraphSpawner(bin, time.Minute, nil).
		WithExtraArgs([]string{"--store-root=/scratch/store", "--from-modcache=/scratch/modcache"})
	stderr, err := s.Spawn(t.Context(), coordinatetest.MustNew("example.com/m", "v1.0.0"), false, "walk-1")
	if err == nil {
		t.Fatal("Spawn: want the fixture's exit status")
	}
	got := strings.TrimSpace(string(stderr))
	for _, want := range []string{"callgraph example.com/m@v1.0.0", "--from-walk walk-1", "--store-root=/scratch/store", "--from-modcache=/scratch/modcache"} {
		if !strings.Contains(got, want) {
			t.Errorf("child argv %q lacks %q", got, want)
		}
	}
}
