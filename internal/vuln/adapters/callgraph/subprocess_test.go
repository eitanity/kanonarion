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

// A TinyGo walk's child carries the walk and no frame flag: the child adopts the
// frame from --from-walk, so an exported GOOS/GOARCH or a frame flag added here
// would contradict it.
func TestSpawn_ATinyGoWalksChildCarriesTheWalkAlone(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "argv")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"$@\" >&2\nexit 3\n"), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv("GOOS", "linux")
	t.Setenv("GOARCH", "arm")
	stderr, err := NewOsCallGraphSpawner(bin, time.Minute, nil).
		Spawn(t.Context(), coordinatetest.MustNew("golang.org/x/text", "v0.3.7"), false, "01M54R0TPQAN4S6E08S9SK59V5")
	if err == nil {
		t.Fatal("Spawn: want the fixture's exit status")
	}
	if got, want := strings.TrimSpace(string(stderr)), "callgraph golang.org/x/text@v0.3.7 --narrate-progress --from-walk 01M54R0TPQAN4S6E08S9SK59V5"; got != want {
		t.Errorf("child argv = %q, want %q", got, want)
	}
}
