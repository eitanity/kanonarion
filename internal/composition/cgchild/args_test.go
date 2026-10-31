package cgchild_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/composition/cgchild"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	extextractor "code.eitanity.com/kanonarion/internal/extract/adapters/extractor/local"
	vulncallgraph "code.eitanity.com/kanonarion/internal/vuln/adapters/callgraph"
)

// capturingExecutor records the child argv the extraction stage builds and
// refuses to run it.
type capturingExecutor struct{ args [][]string }

func (c *capturingExecutor) Execute(_ context.Context, args []string) ([]byte, error) {
	c.args = append(c.args, args)
	return nil, errors.New("not run")
}

// Every argv either spawner builds, with every flag a parent can add, is one
// the child parses, to the values the parent meant.
func TestParse_ReadsWhatBothSpawnersSend(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")
	extra := append(extextractor.CallGraphSubprocessArgs("/scratch/store", "/scratch/modcache"),
		"--"+cgports.ChildFlagConfig+"=/scratch/config.yaml")

	exec := &capturingExecutor{}
	if _, err := extextractor.NewAdapterExtractor(nil, nil, exec, nil, "v", extra, nil).
		Extract(t.Context(), coord, "callgraph", true, "walk-1", false); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(exec.args) != 1 {
		t.Fatalf("the extraction stage spawned %d children, want 1", len(exec.args))
	}
	argvs := [][]string{exec.args[0]}

	bin := filepath.Join(t.TempDir(), "argv")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >&2\nexit 3\n"), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatal(err)
	}
	stderr, err := vulncallgraph.NewOsCallGraphSpawner(bin, time.Minute, nil).WithExtraArgs(extra).
		Spawn(t.Context(), coord, true, "walk-1")
	if err == nil {
		t.Fatal("Spawn: want the fixture's exit status")
	}
	argvs = append(argvs, strings.Split(strings.TrimSpace(string(stderr)), "\n"))

	want := cgchild.Args{
		Coordinate: coord.String(), Narrate: true, Force: true, FromWalk: "walk-1",
		StoreRoot: "/scratch/store", FromModcache: "/scratch/modcache", Config: "/scratch/config.yaml",
	}
	for i, argv := range argvs {
		got, err := cgchild.Parse(argv)
		if err != nil {
			t.Errorf("spawner %d argv %q: %v", i, argv, err)
			continue
		}
		if got != want {
			t.Errorf("spawner %d argv %q parsed to %+v, want %+v", i, argv, got, want)
		}
	}
}

// The child refuses anything but its own command line.
func TestParse_RefusesAnythingElse(t *testing.T) {
	for _, argv := range [][]string{
		nil,
		{"walk-list"},
		{"callgraph"},
		{"callgraph", "a@v1", "b@v1"},
		{"callgraph", "a@v1", "--json"},
		{"callgraph", "a@v1", "--force=yes"},
		{"callgraph", "a@v1", "--from-walk"},
	} {
		if got, err := cgchild.Parse(argv); err == nil {
			t.Errorf("Parse(%q) = %+v, want a refusal", argv, got)
		}
	}
	got, err := cgchild.Parse([]string{"callgraph", "--from-walk", "w", "a@v1", "--force=false"})
	if err != nil || got != (cgchild.Args{Coordinate: "a@v1", FromWalk: "w"}) {
		t.Errorf("Parse = %+v, %v", got, err)
	}
}
