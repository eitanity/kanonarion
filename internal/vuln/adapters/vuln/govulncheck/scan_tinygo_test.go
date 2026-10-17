package govulncheck

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Two go list answers in the shape `go list -deps -json` streams them: the
// pico closure lists cgo packages, the wasip1 one does not.
const (
	listWithCgo = `{"ImportPath":"runtime"}
{"ImportPath":"device/arm","CgoFiles":["arm.go"]}
{"ImportPath":"internal/task","CgoFiles":["task_stack_cortexm.go"]}
{"ImportPath":"machine","CgoFiles":["machine_rp2040.go"]}
{"ImportPath":"runtime/interrupt","CgoFiles":["interrupt.go"]}
{"ImportPath":"example.com/proj"}
`
	listWithoutCgo = `{"ImportPath":"runtime"}
{"ImportPath":"example.com/proj"}
`
)

// moduleStream is a module-level govulncheck stream as -scan module emits it:
// one trace frame naming the module and version, no package or function.
const moduleStream = `{"osv": {"id": "GO-2022-1059", "summary": "Denial of service via crafted Accept-Language header in golang.org/x/text/language", "affected": [
  {"package": {"name": "golang.org/x/text"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.8"}]}], "ecosystem_specific": {"imports": [{"path": "golang.org/x/text/language", "symbols": ["Parse"]}]}}
]}}
{"finding": {"osv": "GO-2022-1059", "fixed_version": "v0.3.8", "trace": [{"module": "golang.org/x/text", "version": "v0.3.7"}]}}
`

// tinygoHost is a PATH holding a stub go and a stub govulncheck, each logging
// its invocation to one file so a test can read every child a scan spawned.
type tinygoHost struct {
	log   string
	frame goenv.TinyGo
}

// newTinyGoHost answers `go list` with listOut (or fails it when listExit is
// non-zero) and makes govulncheck print stream.
func newTinyGoHost(t *testing.T, listOut string, listExit int, stream string) tinygoHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the go and govulncheck stubs are POSIX shell scripts")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	frame, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", root, []string{"tinygo", "pico"})
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	data := t.TempDir()
	log := filepath.Join(data, "children")
	writeFile(t, filepath.Join(data, "list.json"), listOut)
	writeFile(t, filepath.Join(data, "stream.json"), stream)
	listBody := "cat " + filepath.Join(data, "list.json")
	if listExit != 0 {
		listBody = "echo 'device/arm: could not import C' 1>&2; exit 1"
	}
	stubs := t.TempDir()
	writeExecutable(t, filepath.Join(stubs, "go"), "#!/bin/sh\n"+
		"echo \"go $*\" >> "+log+"\n"+
		"env | grep -E '^(GOROOT|GOARM|GOOS|GOARCH|CGO_ENABLED)=' | sed 's/^/  env /' >> "+log+"\n"+
		"case \"$1\" in\n"+
		"env) echo go1.27.2 ;;\n"+
		"list) "+listBody+" ;;\n"+
		"esac\nexit 0\n")
	writeExecutable(t, filepath.Join(stubs, "govulncheck"), "#!/bin/sh\n"+
		"echo \"govulncheck $*\" >> "+log+"\n"+
		"env | grep -E '^(GOROOT|GOARM|CGO_ENABLED)=' | sed 's/^/  env /' >> "+log+"\n"+
		"cat "+filepath.Join(data, "stream.json")+"\nexit 0\n")
	t.Setenv("PATH", stubs+string(os.PathListSeparator)+os.Getenv("PATH"))
	return tinygoHost{log: log, frame: frame}
}

// children is every child the scan ran, in order, without the env lines.
func (h tinygoHost) children(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(h.log) // #nosec G304 -- written by this test's own stubs
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !strings.HasPrefix(line, "  env ") {
			out = append(out, line)
		}
	}
	return out
}

func (h tinygoHost) raw(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.log) // #nosec G304 -- written by this test's own stubs
	if err != nil {
		t.Fatalf("no child ran: %v", err)
	}
	return string(raw)
}

// govulncheckLine is the one govulncheck invocation the scan made.
func (h tinygoHost) govulncheckLine(t *testing.T) string {
	t.Helper()
	var lines []string
	for _, c := range h.children(t) {
		if strings.HasPrefix(c, "govulncheck ") {
			lines = append(lines, c)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("govulncheck ran %d times, want 1: %q", len(lines), h.children(t))
	}
	return lines[0]
}

// entryPoint runs one of the three scan entry points and returns its status,
// failure detail and every finding it produced.
type entryPoint func(t *testing.T, s *Scanner) (domain.VulnerabilityStatus, string, []domain.VulnerabilityFinding)

var xtext = coordinatetest.MustNew("golang.org/x/text", "v0.3.7")

func tinygoEntryPoints() map[string]entryPoint {
	grouped := func(res domain.ProjectScanResult) (domain.VulnerabilityStatus, string, []domain.VulnerabilityFinding) {
		return res.Status, res.ErrorDetail, res.FindingsByModule[xtext]
	}
	zip := func(t *testing.T) *bytes.Reader {
		return bytes.NewReader(makeModuleZip(t, map[string]string{
			"golang.org/x/text@v0.3.7/go.mod": "module golang.org/x/text\n\ngo 1.21\n",
			"golang.org/x/text@v0.3.7/t.go":   "package text\n",
		}))
	}
	return map[string]entryPoint{
		"Scan": func(t *testing.T, s *Scanner) (domain.VulnerabilityStatus, string, []domain.VulnerabilityFinding) {
			rec, err := s.Scan(t.Context(), ports.ScanRequest{Coordinate: xtext, ModuleSource: zip(t), Snapshot: fixtureSnapshot(t), ScanMode: domain.ScanModeSource})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			return rec.OverallStatus, rec.ErrorDetail, rec.Findings
		},
		"ScanProject": func(t *testing.T, s *Scanner) (domain.VulnerabilityStatus, string, []domain.VulnerabilityFinding) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/proj\n\ngo 1.21\n")
			res, err := s.ScanProject(t.Context(), ports.ProjectScanRequest{ProjectDir: dir, Snapshot: fixtureSnapshot(t)})
			if err != nil {
				t.Fatalf("ScanProject: %v", err)
			}
			if res.Status != domain.StatusScanFailed && res.ScanMode == "" {
				t.Error("an analysed project result states no scan mode")
			}
			return grouped(res)
		},
		"ScanTargetModule": func(t *testing.T, s *Scanner) (domain.VulnerabilityStatus, string, []domain.VulnerabilityFinding) {
			res, err := s.ScanTargetModule(t.Context(), ports.TargetScanRequest{
				Coordinate: coordinatetest.MustNew("example.com/proj", "v1.0.0"),
				ModuleSource: bytes.NewReader(makeModuleZip(t, map[string]string{
					"example.com/proj@v1.0.0/go.mod": "module example.com/proj\n\ngo 1.21\n",
					"example.com/proj@v1.0.0/p.go":   "package proj\n",
				})),
				Snapshot: fixtureSnapshot(t),
			})
			if err != nil {
				t.Fatalf("ScanTargetModule: %v", err)
			}
			return grouped(res)
		},
	}
}

// A closure listing a cgo package is scanned at module level, with the tags and
// no package pattern; one listing none is scanned from source with the tags.
// Both run under the frame's environment.
func TestTinyGoScan_ModeIsDecidedByTheClosuresCgoFiles(t *testing.T) {
	for name, run := range tinygoEntryPoints() {
		t.Run(name+"/cgo", func(t *testing.T) {
			h := newTinyGoHost(t, listWithCgo, 0, moduleStream)
			var buf bytes.Buffer
			run(t, capturingScanner(t, &buf, slog.LevelInfo).WithTinyGo(h.frame))
			line := h.govulncheckLine(t)
			if !strings.HasSuffix(line, " -scan module -tags=tinygo,pico") || strings.Contains(line, "./...") {
				t.Errorf("govulncheck ran %q, want -scan module -tags=tinygo,pico and no pattern", line)
			}
			if !strings.Contains(h.raw(t), "go list -tags=tinygo,pico -deps -json ./...") {
				t.Errorf("the mode was not decided by go list under the tags:\n%s", h.raw(t))
			}
			for _, w := range []string{"env GOROOT=" + h.frame.GOROOT(), "env GOARM=6", "env CGO_ENABLED=1"} {
				if !strings.Contains(h.raw(t), w) {
					t.Errorf("the children did not see %q:\n%s", w, h.raw(t))
				}
			}
			log := buf.String()
			if !strings.Contains(log, `cgo_packages="device/arm, internal/task, machine"`) || !strings.Contains(log, "cgo_package_count=4") {
				t.Errorf("the log does not name the packages that decided it:\n%s", log)
			}
		})
		t.Run(name+"/no cgo", func(t *testing.T) {
			h := newTinyGoHost(t, listWithoutCgo, 0, "")
			run(t, capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo).WithTinyGo(h.frame))
			if line := h.govulncheckLine(t); !strings.HasSuffix(line, " -tags=tinygo,pico ./...") || strings.Contains(line, "-scan") {
				t.Errorf("govulncheck ran %q, want source mode with the tags", line)
			}
		})
	}
}

// Without a frame no go list runs: the scan spawns exactly the children it
// spawned before, one fewer than the same scan under a frame.
func TestTinyGoScan_NoFrameRunsNoGoList(t *testing.T) {
	for name, run := range tinygoEntryPoints() {
		t.Run(name, func(t *testing.T) {
			h := newTinyGoHost(t, listWithoutCgo, 0, "")
			run(t, capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo))
			plain := h.children(t)
			for _, c := range plain {
				if strings.HasPrefix(c, "go list") {
					t.Errorf("a scan without a frame ran %q", c)
				}
			}
			if line := h.govulncheckLine(t); strings.Contains(line, "-tags") || strings.Contains(line, "-scan") {
				t.Errorf("a scan without a frame ran %q", line)
			}
			if err := os.Remove(h.log); err != nil {
				t.Fatal(err)
			}
			run(t, capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo).WithTinyGo(h.frame))
			if framed := h.children(t); len(framed) != len(plain)+1 {
				t.Errorf("children without a frame %q, with one %q: want exactly one more", plain, framed)
			}
		})
	}
}

// A module-level finding is not a reachability answer: no route, state
// not_determined, derivation govulncheck at module fidelity.
func TestTinyGoScan_AModuleLevelFindingIsNotDetermined(t *testing.T) {
	for name, run := range tinygoEntryPoints() {
		t.Run(name, func(t *testing.T) {
			h := newTinyGoHost(t, listWithCgo, 0, moduleStream)
			status, _, findings := run(t, capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo).WithTinyGo(h.frame))
			if status != domain.StatusAffected || len(findings) != 1 {
				t.Fatalf("status %s, findings %+v; want one Affected finding", status, findings)
			}
			assertModuleLevelFinding(t, findings[0])
		})
	}
}

func assertModuleLevelFinding(t *testing.T, f domain.VulnerabilityFinding) {
	t.Helper()
	if got := domain.FindingReachabilityState(f); got != domain.StateNotDetermined {
		t.Errorf("state = %s, want not_determined", got)
	}
	r := f.Reachable
	if r.IsReachable || len(r.Routes) != 0 {
		t.Errorf("a module-level finding claims a route: %+v", r)
	}
	if r.DerivedBy.Analyser != domain.AnalyserGovulncheck || r.DerivedBy.Fidelity != string(domain.ScanModeModule) {
		t.Errorf("derivation = %+v, want govulncheck at fidelity module", r.DerivedBy)
	}
	if rung, why := domain.NegativeSoundness(f); rung != domain.SoundnessUnconfirmed || !strings.Contains(why, "module level") {
		t.Errorf("soundness = %s %q", rung, why)
	}
}

// A go list that fails is the scan's load failure, naming the command and the
// frame; govulncheck never runs.
func TestTinyGoScan_AFailedGoListIsAScanFailure(t *testing.T) {
	for name, run := range tinygoEntryPoints() {
		t.Run(name, func(t *testing.T) {
			h := newTinyGoHost(t, "", 1, "")
			status, detail, _ := run(t, capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo).WithTinyGo(h.frame))
			if status != domain.StatusScanFailed {
				t.Errorf("status = %s, want ScanFailed", status)
			}
			for _, w := range []string{"go list -deps -json ./... failed", "could not import C", "--tinygo pico"} {
				if !strings.Contains(detail, w) {
					t.Errorf("detail %q does not say %q", detail, w)
				}
			}
			for _, c := range h.children(t) {
				if strings.HasPrefix(c, "govulncheck") {
					t.Errorf("govulncheck ran after go list failed: %q", c)
				}
			}
		})
	}
}

// Output that is not a go list stream settles nothing, so it fails the scan
// rather than reading as a closure without C.
func TestTinyGoScan_UnparsableListOutputIsAScanFailure(t *testing.T) {
	h := newTinyGoHost(t, "not json", 0, "")
	mode, fault, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo).WithTinyGo(h.frame).
		scanModeFor(t.Context(), goenv.NewToolchains(), os.Environ(), t.TempDir())
	if err != nil || mode != "" || fault == nil || !strings.Contains(fault.errorDetail, "did not parse") {
		t.Errorf("mode %q, fault %+v, err %v; want a parse failure", mode, fault, err)
	}
}

// A cancelled scan is stopped, not recorded as a failure of the closure.
func TestTinyGoScan_CancelledListStopsTheScan(t *testing.T) {
	h := newTinyGoHost(t, listWithCgo, 0, "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, fault, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo).WithTinyGo(h.frame).
		scanModeFor(ctx, goenv.NewToolchains(), os.Environ(), t.TempDir())
	if err == nil || fault != nil {
		t.Errorf("fault %+v, err %v; want the stop", fault, err)
	}
}

// The grouped parse under module mode keeps the fixed version and attributes
// the finding to the module the frame names.
func TestParseResultsByModule_ModuleMode(t *testing.T) {
	s := capturingScanner(t, &bytes.Buffer{}, slog.LevelInfo)
	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(moduleStream), domain.ScanModeModule)
	if err != nil {
		t.Fatal(err)
	}
	got := byModule[xtext]
	if len(got) != 1 || got[0].FixedIn != "v0.3.8" {
		t.Fatalf("findings = %+v", got)
	}
	assertModuleLevelFinding(t, got[0])
}
