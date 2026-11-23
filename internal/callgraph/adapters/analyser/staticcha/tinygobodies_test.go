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

// A C type the cgo translation refuses is kanonarion's gap: the detail leads
// with it and drops the type errors it causes, and with no compile error of the
// package's own no cause is filed and the record is never served back. A
// compile error beside it keeps the module's cause and its line. Neither
// program imports syscall, which the generated cgo file does.
func TestAnalyseDir_ACgoTranslationGapIsKanonarions(t *testing.T) {
	tinycgotest.RequireClang(t)
	frame := tinycgotest.Frame(t)
	for _, tc := range []struct {
		program, lead string
		cause         domain.FailureCause
		compileErr    string
	}{
		{"gap", "kanonarion's cgo translation does not cover what example.com/gap uses: C.pp_t: struct (unnamed", domain.FailureCauseUnrecorded, ""},
		{"gapbroken", "kanonarion's cgo translation does not cover what example.com/gapbroken uses, beside its own compile errors: C.pp_t: struct (unnamed",
			domain.FailureCauseModule, "undefined: missing"},
	} {
		t.Run(tc.program, func(t *testing.T) {
			coord, err := coordinate.NewModuleCoordinate("example.com/"+tc.program, coordinate.LocalVersion)
			if err != nil {
				t.Fatal(err)
			}
			a := staticcha.New("0.0.0-test", "", slog.Default()).WithTinyGo(frame)

			rec, err := a.AnalyseDir(context.Background(), tinycgotest.Program(t, tc.program), coord)

			if err != nil || rec.OverallStatus != domain.CallGraphStatusPartial {
				t.Fatalf("AnalyseDir = %v, %v: %s", rec.OverallStatus, err, rec.FailureDetail)
			}
			if !strings.HasPrefix(rec.FailureDetail, tc.lead) || strings.Contains(rec.FailureDetail, "_Cgo_pp_t") ||
				!strings.Contains(rec.FailureDetail, tc.compileErr) || strings.Contains(rec.FailureDetail, "syscall") {
				t.Errorf("detail = %q", rec.FailureDetail)
			}
			if rec.FailureCause != tc.cause || domain.RecordIsCacheable(rec) {
				t.Errorf("cause %q, cacheable %v; want %q, never served", rec.FailureCause, domain.RecordIsCacheable(rec), tc.cause)
			}
			if !slices.Equal(rec.FailedPackages, []string{coord.Path()}) {
				t.Errorf("failed packages = %v", rec.FailedPackages)
			}
		})
	}
}
