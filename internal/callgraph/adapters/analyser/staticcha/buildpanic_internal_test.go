package staticcha

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

// A Build that panics after creating a generic instance leaves the instance's
// task undone; a later package using the same instance then waits forever. The
// analysis must return, with the panicked package named and left without bodies.
func TestAnalyseDir_ABuildPanicCannotHangALaterBuild(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module example.com/panics\n\ngo 1.24\n",
		"g/g.go": "package g\n\nfunc G[T any]() T { var v T; return v }\n",
		// a is ill-typed: F instantiates G[int] in a's builder, and H's undefined call
		// then panics it.
		"a/a.go": "package a\n\nimport \"example.com/panics/g\"\n\nfunc F() int { return g.G[int]() }\n\nfunc H() { undefinedFn() }\n",
		"b/b.go": "package b\n\nimport \"example.com/panics/g\"\n\nfunc B() int { return g.G[int]() }\n",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	coord, err := coordinate.NewLocalCoordinate("example.com/panics")
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		rec domain.CallGraphRecord
		err error
	}
	done := make(chan result, 1)
	go func() {
		rec, aerr := New("0.0.0-test", "", slog.New(slog.NewTextHandler(io.Discard, nil))).AnalyseDir(context.Background(), dir, coord)
		done <- result{rec, aerr}
	}()
	var got result
	select {
	case got = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the analysis did not return: a later Build is waiting on the panicked one")
	}

	if got.err != nil {
		t.Fatalf("AnalyseDir: %v", got.err)
	}
	if !slices.Contains(got.rec.FailedPackages, "example.com/panics/a") {
		t.Errorf("failed packages = %v, want example.com/panics/a named", got.rec.FailedPackages)
	}
	// a's Build panics on what its compile error leaves unresolved, which the
	// detail states as that error's consequence, not as a crash.
	if !strings.Contains(got.rec.FailureDetail, "undefined: undefinedFn") ||
		!strings.Contains(got.rec.FailureDetail, "the errors stated for example.com/panics/a leave code SSA cannot build, so it is analysed without its bodies") ||
		strings.Contains(got.rec.FailureDetail, "SSA construction panic") {
		t.Errorf("failure detail = %s", got.rec.FailureDetail)
	}
	built := false
	for _, n := range got.rec.Nodes {
		if n.ID == "example.com/panics/b.B" {
			built = true
		}
	}
	if !built {
		t.Error("b, which built in the rebuilt program, is missing from the graph")
	}
}

// A panic in a package with no errors of its own is stated as one.
func TestBuildPanicError(t *testing.T) {
	berr := errors.New("runtime error: invalid memory address or nil pointer dereference")
	if got := buildPanicError("example.com/a", false, berr); got !=
		"SSA construction panic for example.com/a: runtime error: invalid memory address or nil pointer dereference; it is analysed without its bodies" {
		t.Errorf("well-typed: %q", got)
	}
	if got := buildPanicError("example.com/a", true, berr); got !=
		"the errors stated for example.com/a leave code SSA cannot build, so it is analysed without its bodies" {
		t.Errorf("ill-typed: %q", got)
	}
}
