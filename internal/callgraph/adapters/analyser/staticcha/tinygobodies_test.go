package staticcha_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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

// Under a target whose libc TinyGo has not built, clang's refusal of a preamble
// is this host's: the detail leads with the missing include directory, the
// cause is the environment's and the record is never served back. With the
// libc's headers in place the program is extracted, and a header no libc has
// stays the module's own error.
func TestAnalyseDir_AnUnbuiltLibcIsTheEnvironments(t *testing.T) {
	tinycgotest.RequireClang(t)
	frame := tinycgotest.LibcFrame(t)
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	include := filepath.Join(cache, "tinygo", "wasi-libc-thumbv6m-unknown-unknown-eabi-cortex-m0plus-aapcs", "include")
	analyse := func(program string) (domain.CallGraphRecord, string) {
		t.Helper()
		coord, err := coordinate.NewModuleCoordinate("example.com/"+program, coordinate.LocalVersion)
		if err != nil {
			t.Fatal(err)
		}
		dir := tinycgotest.Program(t, program)
		rec, err := staticcha.New("0.0.0-test", "", slog.Default()).WithTinyGo(frame).AnalyseDir(context.Background(), dir, coord)
		if err != nil {
			t.Fatalf("AnalyseDir: %v", err)
		}
		return rec, dir
	}

	rec, dir := analyse("libc")
	lead := filepath.Join(dir, "main.go") + ": TinyGo has not built wasi-libc for target fakelibc on this host: " + include +
		" does not exist, so clang could not read the preamble of example.com/libc ("
	if !strings.HasPrefix(rec.FailureDetail, lead) || rec.FailureCause != domain.FailureCauseEnvironment || domain.RecordIsCacheable(rec) ||
		strings.Contains(rec.FailureDetail, "SSA construction panic") {
		t.Errorf("cause %q, cacheable %v, detail %q; want the environment's, never served, led by %q",
			rec.FailureCause, domain.RecordIsCacheable(rec), rec.FailureDetail, lead)
	}

	if err := os.MkdirAll(include, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(include, "stdio.h"), []byte("int puts(const char *s);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if built, _ := analyse("libc"); built.OverallStatus != domain.CallGraphStatusExtracted {
		t.Errorf("with the headers built: %v: %s", built.OverallStatus, built.FailureDetail)
	}
	rec, _ = analyse("libcbroken")
	if !strings.Contains(rec.FailureDetail, "clang rejected the preamble, read with TinyGo's wasi-libc headers: ") ||
		!strings.Contains(rec.FailureDetail, "nosuchheader.h") || rec.FailureCause != domain.FailureCauseModule || !domain.RecordIsCacheable(rec) ||
		strings.Contains(rec.FailureDetail, "SSA construction panic") {
		t.Errorf("a header no libc has: cause %q, cacheable %v, detail %q", rec.FailureCause, domain.RecordIsCacheable(rec), rec.FailureDetail)
	}
}

// A TinyGo package whose preamble clang refused is kept without its bodies,
// stated as its errors' consequence rather than as a crash.
func TestAnalyseDir_ARefusedTinyGoPackageStatesNoPanic(t *testing.T) {
	tinycgotest.RequireClang(t)
	coord, err := coordinate.NewModuleCoordinate("example.com/rejected", coordinate.LocalVersion)
	if err != nil {
		t.Fatal(err)
	}
	a := staticcha.New("0.0.0-test", "", slog.Default()).WithTinyGo(tinycgotest.Frame(t))

	rec, err := a.AnalyseDir(context.Background(), tinycgotest.Program(t, "rejected"), coord)

	if err != nil || !strings.Contains(rec.FailureDetail, "clang rejected the preamble, read with no libc headers: ") ||
		!strings.Contains(rec.FailureDetail, "the errors stated for tinycgofx/rejected leave code SSA cannot build") ||
		strings.Contains(rec.FailureDetail, "SSA construction panic") {
		t.Errorf("AnalyseDir = %v, %v: %s", rec.OverallStatus, err, rec.FailureDetail)
	}
}
