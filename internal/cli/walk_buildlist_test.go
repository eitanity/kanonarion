package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The toolchain's own words, as `go list -m -mod=readonly -json all` prints them
// when a go.sum entry is missing. The remedy is the second line, which is why
// the reason is quoted rather than paraphrased.
const buildListToolchainReason = "go list -m -mod=readonly -json all: exit status 1\n" +
	"go: github.com/google/uuid@v1.1.1: missing go.sum entry for go.mod file; to add it:\n" +
	"\tgo mod download github.com/google/uuid"

// A walk that falls back to the go.mod require directives completed without a
// single failure, so nothing in "succeeded depth=full (N nodes, 0 failed)" and
// nothing in exit 0 tells the operator that the module set they are looking at
// is not the one that compiles. The disclosure and exit 1 are what say so.
func TestRunWalkProject_BuildListUnavailableIsStatedAndExitsPartial(t *testing.T) {
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}

	record := func(reason string) walkdomain.WalkRecord {
		status := walkdomain.WalkSucceeded
		if reason != "" {
			status = walkdomain.WalkPartial
		}
		return walkdomain.WalkRecord{
			ID:            "W1",
			Target:        target,
			OverallStatus: status,
			Graph: walkdomain.Graph{
				Target:               target,
				BuildListUnavailable: reason,
			},
			PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
				target: {Coordinate: target, Status: walkdomain.NodeSucceeded},
			},
		}
	}

	run := func(t *testing.T, reason string, allowPartial bool) (stdout, stderr string, err error) {
		t.Helper()
		uc := &testfakes.FakeExecuteWalk{Result: walkapp.ExecuteWalkResult{Record: record(reason)}}
		progress := newWalkProgressReporter(io.Discard, true, activeConfig, logLevel)
		var out, errb bytes.Buffer
		_, rerr := runWalkProject(context.Background(), gomodPath, false, allowPartial, 0, "", "", false,
			scopeComplete, walkdomain.WalkDepthFull, "", false, false, progress, uc,
			unfetchedQueryFetch{}, &out, &errb)
		return out.String(), errb.String(), rerr
	}

	t.Run("states the gap on stdout", func(t *testing.T) {
		out, _, _ := run(t, buildListToolchainReason, true)
		if !strings.Contains(out, "build list unavailable") {
			t.Errorf("stdout does not say the build list was unavailable:\n%s", out)
		}
		if !strings.Contains(out, "go.mod require directives, not the modules that compile") {
			t.Errorf("stdout does not say which module set the walk covers:\n%s", out)
		}
		if !strings.Contains(out, "missing go.sum entry for go.mod file") ||
			!strings.Contains(out, "go mod download github.com/google/uuid") {
			t.Errorf("stdout does not carry the toolchain's own reason and remedy:\n%s", out)
		}
	})

	t.Run("exits partial and says why", func(t *testing.T) {
		_, _, rerr := run(t, buildListToolchainReason, false)
		var ee *exitError
		if !errors.As(rerr, &ee) {
			t.Fatalf("error = %v, want an exitError", rerr)
		}
		if ee.code != ExitPartial {
			t.Errorf("exit code = %d, want %d (partial)", ee.code, ExitPartial)
		}
		if !strings.Contains(ee.msg, "build list was unavailable") {
			t.Errorf("exit message = %q, want it to name the build list", ee.msg)
		}
		if strings.Contains(ee.msg, "could not be fetched") {
			t.Errorf("exit message = %q blames the dependencies; every one of them was fetched", ee.msg)
		}
	})

	t.Run("--allow-partial still lifts the code", func(t *testing.T) {
		_, _, rerr := run(t, buildListToolchainReason, true)
		if rerr != nil {
			t.Errorf("error = %v, want nil under --allow-partial", rerr)
		}
	})

	// stdout under --json is the record's own bytes. The disclosure must reach
	// the reader beside them, never inside them: prose appended to the document
	// is a parse error for every consumer of it.
	t.Run("--json keeps stdout a document", func(t *testing.T) {
		jsonOut = true
		t.Cleanup(func() { jsonOut = false })
		out, errOut, _ := run(t, buildListToolchainReason, true)
		var doc map[string]any
		if uerr := json.Unmarshal([]byte(out), &doc); uerr != nil {
			t.Fatalf("stdout is not one JSON document (%v):\n%s", uerr, out)
		}
		graph, _ := doc["graph"].(map[string]any)
		if graph["build_list_unavailable"] != buildListToolchainReason {
			t.Errorf("the document does not carry the gap at .graph.build_list_unavailable: %v", graph["build_list_unavailable"])
		}
		if !strings.Contains(errOut, "build list unavailable") {
			t.Errorf("stderr does not state the gap:\n%s", errOut)
		}
	})

	// The control: a resolved build list leaves the command exactly as it was.
	t.Run("a resolved build list says nothing and exits 0", func(t *testing.T) {
		out, _, rerr := run(t, "", false)
		if rerr != nil {
			t.Errorf("error = %v, want nil", rerr)
		}
		if strings.Contains(out, "build list") {
			t.Errorf("stdout mentions the build list on a clean walk:\n%s", out)
		}
		if !strings.Contains(out, "succeeded") {
			t.Errorf("stdout does not report the clean walk:\n%s", out)
		}
	})
}

// A run that produced the record is not the only reader of it. The degradation
// is on the walk, so walk-show states it from the store months later.
func TestRunWalkShow_StatesTheBuildListGap(t *testing.T) {
	target, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	rec := walkdomain.WalkRecord{
		ID:            "W1",
		Target:        target,
		OverallStatus: walkdomain.WalkPartial,
		Graph: walkdomain.Graph{
			Target:               target,
			Partial:              true,
			PartialReason:        walkdomain.BuildListUnavailableReason,
			BuildListUnavailable: buildListToolchainReason,
		},
	}
	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(rec)

	var out, errb bytes.Buffer
	if err := runWalkShow(context.Background(), "W1", uc, &out, &errb); err != nil {
		t.Fatalf("runWalkShow: %v", err)
	}
	if !strings.Contains(out.String(), "build list unavailable") {
		t.Errorf("walk-show does not state the build-list gap:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "missing go.sum entry for go.mod file") {
		t.Errorf("walk-show does not carry the toolchain's reason:\n%s", out.String())
	}
}

// A walk whose build list resolved must read back exactly as before.
func TestRunWalkShow_SaysNothingForAResolvedBuildList(t *testing.T) {
	target, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(walkdomain.WalkRecord{
		ID:            "W2",
		Target:        target,
		OverallStatus: walkdomain.WalkSucceeded,
		Graph:         walkdomain.Graph{Target: target},
	})

	var out, errb bytes.Buffer
	if err := runWalkShow(context.Background(), "W2", uc, &out, &errb); err != nil {
		t.Fatalf("runWalkShow: %v", err)
	}
	if strings.Contains(out.String(), "build list unavailable") {
		t.Errorf("walk-show invented a build-list gap:\n%s", out.String())
	}
}

// walkPartialMessage used to be one sentence — "some dependencies could not be
// fetched" — printed for every partial walk. Now that a graph can be incomplete
// for reasons that have nothing to do with fetching, that sentence is false for
// most of them, so each reason gets the message that is true of it.
func TestWalkPartialMessage_SaysWhatTheWalkIsPartialFor(t *testing.T) {
	target, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	rec := func(graph walkdomain.Graph, failures int) walkdomain.WalkRecord {
		results := map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
			target: {Coordinate: target, Status: walkdomain.NodeSucceeded},
		}
		for i := range failures {
			c, cErr := coordinate.NewModuleCoordinate(fmt.Sprintf("example.com/dep%d", i), "v1.0.0")
			if cErr != nil {
				t.Fatal(cErr)
			}
			results[c] = walkdomain.NodeResult{Coordinate: c, Status: walkdomain.NodeFetchFailed}
		}
		return walkdomain.WalkRecord{Target: target, Graph: graph, PerNodeResults: results}
	}

	t.Run("a fetch failure keeps the sentence it always had", func(t *testing.T) {
		got := walkPartialMessage(rec(walkdomain.Graph{
			Partial: true, PartialReason: walkdomain.FetchFailedReason}, 1), "")
		if got != "walk partial: some dependencies could not be fetched" {
			t.Errorf("message = %q, want the unchanged fetch-failure sentence", got)
		}
	})

	t.Run("the build list outranks everything", func(t *testing.T) {
		got := walkPartialMessage(rec(walkdomain.Graph{
			Partial:              true,
			PartialReason:        walkdomain.BuildListUnavailableReason,
			BuildListUnavailable: buildListToolchainReason,
		}, 1), "an ingest failure")
		if got != buildListUnavailablePartialMsg {
			t.Errorf("message = %q, want the build-list sentence", got)
		}
	})

	// A require redirected to a local path is not a fetch that failed, so a walk
	// whose only non-succeeded node is one must not be told dependencies could
	// not be fetched. It is the project's own subpackage.
	t.Run("a local replace is not a failed fetch", func(t *testing.T) {
		local, cErr := coordinate.NewModuleCoordinate("example.com/app/sub", "v0.0.0-20250630054201-94c0ba7b0952")
		if cErr != nil {
			t.Fatal(cErr)
		}
		r := rec(walkdomain.Graph{Partial: true, PartialReason: "shallow_depth: bounded at 2"}, 0)
		r.PerNodeResults[local] = walkdomain.NodeResult{Coordinate: local, Status: walkdomain.NodeLocalReplace}
		if n := walkdomain.CountNodeFailures(r); n != 0 {
			t.Errorf("CountNodeFailures = %d, want 0", n)
		}
		if got := walkPartialMessage(r, ""); strings.Contains(got, "could not be fetched") {
			t.Errorf("message = %q; nothing failed to fetch", got)
		}
	})

	t.Run("a root ingest failure outranks a fetch failure", func(t *testing.T) {
		got := walkPartialMessage(rec(walkdomain.Graph{Partial: true}, 1), "an ingest failure")
		if !strings.Contains(got, "project's own packages were not ingested") {
			t.Errorf("message = %q, want the root-ingest sentence", got)
		}
	})

	// The catch-all is what makes a reason nobody has written yet still produce a
	// true sentence: it quotes the record instead of guessing.
	t.Run("an incomplete graph with no failures quotes its reason", func(t *testing.T) {
		for _, reason := range []string{
			walkdomain.DepthBoundedReason(2),
			"build_list_approximate: no resolution directory",
			"some_future_reason: whatever it says",
		} {
			got := walkPartialMessage(rec(walkdomain.Graph{Partial: true, PartialReason: reason}, 0), "")
			if strings.Contains(got, "could not be fetched") {
				t.Errorf("message for %q blames fetching; nothing failed to fetch: %q", reason, got)
			}
			if !strings.Contains(got, reason) {
				t.Errorf("message = %q, want it to quote %q", got, reason)
			}
		}
	})

	t.Run("an incomplete graph stating no reason says so", func(t *testing.T) {
		got := walkPartialMessage(rec(walkdomain.Graph{Partial: true}, 0), "")
		if !strings.Contains(got, "states no reason") {
			t.Errorf("message = %q, want it to say the record states no reason", got)
		}
	})
}
