package staticcha_test

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinycgo/tinycgotest"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

// Under a TinyGo frame TinyGo's own packages are analysed with bodies: their
// functions stay external and in no module, their edges are recorded, a
// callback they make into the program has them as its caller, and no
// standard-library join covers them. Go's own packages stay standard library.
func TestAnalyseDir_TinyGoPackagesAreBuiltWithBodies(t *testing.T) {
	tinycgotest.RequireClang(t)
	frame := tinycgotest.Frame(t)
	coord, err := coordinate.NewModuleCoordinate("example.com/ok", coordinate.LocalVersion)
	if err != nil {
		t.Fatal(err)
	}
	a := staticcha.New("0.0.0-test", "", slog.Default()).WithTinyGo(frame)

	rec, err := a.AnalyseDir(context.Background(), tinycgotest.Program(t, "ok"), coord)

	if err != nil || rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("AnalyseDir = %v, %v: %s", rec.OverallStatus, err, rec.FailureDetail)
	}
	run, ok := nodeByID(rec, "tinycgofx/full.Run")
	if !ok || !run.IsExternal || run.Module != "" || !strings.HasSuffix(run.Position.File, "/src/tinycgofx/full/full.go") {
		t.Errorf("tinycgofx/full.Run = %+v, want an external node in no module, positioned in the merged GOROOT", run)
	}
	for _, want := range [][2]string{
		{"tinycgofx/full.Run", "example.com/ok.onEvent"},
		{"tinycgofx/full.Run", "tinycgofx/full.helper"},
		{"tinycgofx/full.Copy", "tinycgofx/full._Cgo_fake_copy"},
	} {
		if !hasEdge(rec, want[0], want[1]) {
			t.Errorf("no edge %s -> %s", want[0], want[1])
		}
	}
	for _, p := range rec.StdlibPackages {
		if strings.HasPrefix(p, "tinycgofx/") {
			t.Errorf("TinyGo's package %s is in the stdlib join", p)
		}
	}
	if !slices.Contains(rec.StdlibPackages, "syscall") {
		t.Errorf("stdlib packages = %v, want Go's syscall kept", rec.StdlibPackages)
	}
}

func hasEdge(rec domain.CallGraphRecord, from, to string) bool {
	for _, e := range rec.Edges {
		if e.FromID == from && e.ToID == to {
			return true
		}
	}
	return false
}
