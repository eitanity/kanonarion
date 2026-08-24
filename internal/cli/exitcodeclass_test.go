package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The class these tables close: a command returning a code that does not
// describe the answer it produced. Every member reached it the same way — a
// switch that enumerated the interesting values and let the rest fall through to
// success, or a sentinel nobody mapped, which the taxonomy's catch-all then
// reported as a broken invocation.
//
// Each table is status-or-sentinel in, exit code out, one row per value, and
// each is paired with a completeness check that reads the enum's own source. A
// value added to a domain enum without a row here fails the check rather than
// arriving silently at 0.

// enumMembers returns the identifiers declared in the const block that declares
// anchor, so a table can be checked against the enum rather than against the
// last count someone wrote down.
func enumMembers(t *testing.T, file, anchor string) []string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	for _, decl := range parsed.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		var names []string
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				names = append(names, n.Name)
			}
		}
		for _, n := range names {
			if n == anchor {
				return names
			}
		}
	}
	t.Fatalf("no const block declaring %s in %s", anchor, file)
	return nil
}

// checkCovers reports any enum member the table did not name.
func checkCovers(t *testing.T, members, covered []string, file string) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range covered {
		seen[c] = true
	}
	var missing []string
	for _, m := range members {
		if !seen[m] {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%s declares %v with no exit code pinned here; a status with no row reaches the mapper's default and a reader cannot tell whether that was decided",
			file, missing)
	}
}

func TestExitCodeClass_CallGraphStatus(t *testing.T) {
	const src = "../callgraph/domain/types.go"
	cases := []struct {
		member    string
		status    cgdomain.CallGraphStatus
		zeroNodes bool
		want      int
	}{
		{"CallGraphStatusExtracted", cgdomain.CallGraphStatusExtracted, false, ExitOK},
		// The operator asked for this module to be skipped, so the missing graph
		// is the outcome requested rather than one the run failed to produce.
		{"CallGraphStatusExcludedByConfig", cgdomain.CallGraphStatusExcludedByConfig, true, ExitOK},
		{"CallGraphStatusPartial", cgdomain.CallGraphStatusPartial, false, ExitPartial},
		{"CallGraphStatusPartial (no nodes)", cgdomain.CallGraphStatusPartial, true, ExitFailed},
		{"CallGraphStatusCancelled", cgdomain.CallGraphStatusCancelled, false, ExitCancelled},
		{"CallGraphStatusLoadFailed", cgdomain.CallGraphStatusLoadFailed, false, ExitFailed},
		{"CallGraphStatusOutOfMemory", cgdomain.CallGraphStatusOutOfMemory, false, ExitFailed},
		{"CallGraphStatusExtractionFailed", cgdomain.CallGraphStatusExtractionFailed, false, ExitFailed},
		{"CallGraphStatusUnknown", cgdomain.CallGraphStatusUnknown, false, ExitFailed},
	}
	var covered []string
	for _, tc := range cases {
		covered = append(covered, strings.Fields(tc.member)[0])
		rec := cgdomain.CallGraphRecord{
			Coordinate:    coordinatetest.MustNew("example.com/m", "v1.0.0"),
			OverallStatus: tc.status,
			NodeCount:     1,
		}
		if tc.zeroNodes {
			rec.NodeCount = 0
		}
		if got := ExitCodeForError(callGraphExtractionExit(rec)); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.member, got, tc.want)
		}
	}
	checkCovers(t, enumMembers(t, src, "CallGraphStatusExtracted"), covered, src)
}

func TestExitCodeClass_ExtractionRunStatus(t *testing.T) {
	const src = "../extract/domain/types.go"
	cases := []struct {
		member string
		status extractdomain.ExtractionRunStatus
		want   int
	}{
		{"ExtractionRunSucceeded", extractdomain.ExtractionRunSucceeded, ExitOK},
		{"ExtractionRunPartial", extractdomain.ExtractionRunPartial, ExitPartial},
		{"ExtractionRunFailed", extractdomain.ExtractionRunFailed, ExitFailed},
		{"ExtractionRunCancelled", extractdomain.ExtractionRunCancelled, ExitCancelled},
	}
	var covered []string
	for _, tc := range cases {
		covered = append(covered, tc.member)
		run := extractdomain.ExtractionRun{
			ID:            "01EXTRACTRUN00000000000001",
			OverallStatus: tc.status,
			PerModuleResults: map[coordinate.ModuleCoordinate]extractdomain.ModuleExtractionResult{
				coordinatetest.MustNew("example.com/m", "v1.0.0"): {
					Stages: map[string]extractdomain.StageResult{
						"interface": {Status: extractdomain.StageFailed},
					},
				},
			},
		}
		if got := ExitCodeForError(extractionExit(run)); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.member, got, tc.want)
		}
	}
	// A status this build does not know is not a completed run.
	if got := ExitCodeForError(extractionExit(extractdomain.ExtractionRun{OverallStatus: 99})); got != ExitPartial {
		t.Errorf("unrecognised extraction status: exit %d, want %d", got, ExitPartial)
	}
	checkCovers(t, enumMembers(t, src, "ExtractionRunSucceeded"), covered, src)
}

func TestExitCodeClass_WalkStatus(t *testing.T) {
	const src = "../walk/domain/walk.go"
	cases := []struct {
		member string
		status walkdomain.WalkStatus
		want   int
	}{
		{"WalkSucceeded", walkdomain.WalkSucceeded, ExitOK},
		{"WalkPartial", walkdomain.WalkPartial, ExitPartial},
		{"WalkFailed", walkdomain.WalkFailed, ExitFailed},
		{"WalkCancelled", walkdomain.WalkCancelled, ExitCancelled},
	}
	var covered []string
	for _, tc := range cases {
		covered = append(covered, tc.member)
		if got := ExitCodeForError(walkExit(tc.status, false, "failed", "partial")); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.member, got, tc.want)
		}
	}
	// --allow-partial lifts Partial's code and nothing else's.
	if got := ExitCodeForError(walkExit(walkdomain.WalkPartial, true, "failed", "partial")); got != ExitOK {
		t.Errorf("--allow-partial on a partial walk: exit %d, want %d", got, ExitOK)
	}
	if got := ExitCodeForError(walkExit(walkdomain.WalkFailed, true, "failed", "partial")); got != ExitFailed {
		t.Errorf("--allow-partial must not lift a failed walk: exit %d, want %d", got, ExitFailed)
	}
	if got := ExitCodeForError(walkExit(walkdomain.WalkStatus(99), false, "failed", "partial")); got != ExitPartial {
		t.Errorf("unrecognised walk status: exit %d, want %d", got, ExitPartial)
	}
	checkCovers(t, enumMembers(t, src, "WalkSucceeded"), covered, src)
}

func TestExitCodeClass_VulnCoverageStatus(t *testing.T) {
	const src = "../vuln/domain/types.go"
	cases := []struct {
		member string
		status vuldomain.CoverageStatus
		want   int
	}{
		{"CoverageComplete", vuldomain.CoverageComplete, ExitOK},
		{"CoveragePartial", vuldomain.CoveragePartial, ExitPartial},
		{"CoverageFailed", vuldomain.CoverageFailed, ExitFailed},
	}
	var covered []string
	for _, tc := range cases {
		covered = append(covered, tc.member)
		got := ExitCodeForError(vulnScanCoverageExit(vuldomain.WalkScanRun{CoverageStatus: tc.status}))
		if got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.member, got, tc.want)
		}
	}
	if got := ExitCodeForError(vulnScanCoverageExit(vuldomain.WalkScanRun{CoverageStatus: "Invented"})); got != ExitPartial {
		t.Errorf("unrecognised coverage status: exit %d, want %d", got, ExitPartial)
	}
	checkCovers(t, enumMembers(t, src, "CoverageComplete"), covered, src)
}

func TestExitCodeClass_InspectRollUp(t *testing.T) {
	const src = "../vuln/domain/types.go"
	cases := []struct {
		member string
		status vuldomain.WalkScanStatus
		want   int
	}{
		{"WalkStatusAllClean", vuldomain.WalkStatusAllClean, ExitOK},
		{"WalkStatusAffected", vuldomain.WalkStatusAffected, ExitOK},
		{"WalkStatusPartial", vuldomain.WalkStatusPartial, ExitPartial},
		// ScanFailed keeps the code it has. inspect's own roll-up carries the
		// vuln-scan verdict forward, and vuln-scan is the command that gates on it.
		{"WalkStatusFailed", vuldomain.WalkStatusFailed, ExitOK},
	}
	var covered []string
	for _, tc := range cases {
		covered = append(covered, tc.member)
		if got := ExitCodeForError(inspectExit(string(tc.status))); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.member, got, tc.want)
		}
	}
	checkCovers(t, enumMembers(t, src, "WalkStatusAllClean"), covered, src)
}

func TestExitCodeClass_LicenceCompatVerdict(t *testing.T) {
	const src = "../license/domain/compatibility.go"
	report := func(v licdomain.CompatibilityVerdict) licdomain.ClosureCompatibilityReport {
		return licdomain.ClosureCompatibilityReport{
			Conflicts: []licdomain.CompatibilityConflict{{Verdict: v}},
		}
	}
	cases := []struct {
		member string
		report licdomain.ClosureCompatibilityReport
		want   int
	}{
		{"VerdictCompatible", licdomain.ClosureCompatibilityReport{Clean: true}, ExitOK},
		{"VerdictIncompatible", report(licdomain.VerdictIncompatible), ExitPartial},
		{"VerdictUnknownPair", report(licdomain.VerdictUnknownPair), ExitFailed},
		{"VerdictElectable", report(licdomain.VerdictElectable), ExitFailed},
	}
	var covered []string
	for _, tc := range cases {
		covered = append(covered, tc.member)
		if got := ExitCodeForError(compatExitCode(tc.report)); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.member, got, tc.want)
		}
	}
	// A not-clean report whose conflicts carry a verdict this build does not
	// recognise fell through to 0 — the one answer the command's own rule says it
	// must never give.
	if got := ExitCodeForError(compatExitCode(report(licdomain.CompatibilityVerdict(99)))); got != ExitFailed {
		t.Errorf("unrecognised verdict on a not-clean report: exit %d, want %d", got, ExitFailed)
	}
	checkCovers(t, enumMembers(t, src, "VerdictCompatible"), covered, src)
}

// Recorded evidence in doubt is ExitIntegrity, whichever domain raised it.
// Only the walk sentinel was mapped; the rest reached ExitConfig, which says the
// invocation was wrong and routes a store problem to whoever fixes command
// lines. The sweep below reads the ports packages, so a sentinel added there
// without a mapping fails here rather than reaching the fallback.
func TestExitCodeClass_EvidenceInDoubtSentinels(t *testing.T) {
	if len(evidenceInDoubt) == 0 {
		t.Fatal("evidenceInDoubt is empty")
	}
	mapped := map[string]bool{}
	for _, sentinel := range evidenceInDoubt {
		mapped[sentinel.Error()] = true
		if got := ExitCodeForError(sentinel); got != ExitIntegrity {
			t.Errorf("%q: exit %d, want %d", sentinel, got, ExitIntegrity)
		}
		// Wrapped, which is how every one of them actually arrives.
		wrapped := &wrapErr{msg: "reading the store", err: sentinel}
		if got := ExitCodeForError(wrapped); got != ExitIntegrity {
			t.Errorf("%q wrapped: exit %d, want %d", sentinel, got, ExitIntegrity)
		}
	}

	var missing []string
	for _, msg := range declaredEvidenceSentinels(t) {
		if !mapped[msg] {
			missing = append(missing, msg)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("ports packages declare %v with no entry in evidenceInDoubt; each would exit %d (the invocation was wrong) instead of %d",
			missing, ExitConfig, ExitIntegrity)
	}
}

// declaredEvidenceSentinels returns the message of every
// `var Err…Integrity/Conflict = errors.New("…")` declared under internal/*/ports.
func declaredEvidenceSentinels(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("../*/ports/*.go")
	if err != nil {
		t.Fatalf("globbing ports packages: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no ports packages found; the sweep would pass vacuously")
	}
	var msgs []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, perr := parser.ParseFile(fset, file, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", file, perr)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				return true
			}
			name := vs.Names[0].Name
			if !strings.HasPrefix(name, "Err") ||
				(!strings.HasSuffix(name, "Integrity") && !strings.HasSuffix(name, "Conflict")) {
				return true
			}
			call, ok := vs.Values[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			msg, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			msgs = append(msgs, msg)
			return true
		})
	}
	return msgs
}

// wrapErr is a minimal wrapper, so the sweep exercises the chain walk rather
// than an identity comparison.
type wrapErr struct {
	msg string
	err error
}

func (w *wrapErr) Error() string { return w.msg + ": " + w.err.Error() }
func (w *wrapErr) Unwrap() error { return w.err }
