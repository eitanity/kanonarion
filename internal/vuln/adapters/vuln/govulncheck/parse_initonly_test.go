package govulncheck

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// symbolPairFixture is the regression fixture PAIR, and the pair is the test.
//
// One advisory attaches to two module paths in one build, and its OSV entry names
// a symbol for one of them and none for the other. govulncheck reports both, and
// the two reports look alike unless the trace is read: the entry naming a symbol
// produces a call chain ending at that symbol, and the entry naming none produces
// a chain of nothing but package-initialisation frames, because with no symbol to
// look for the only thing govulncheck can report is that the package was linked in
// and initialised.
//
// Ingesting both as routes reported both coordinates reachable at High confidence
// in the same run, with 'init' written into the affected symbols of the second — a
// symbol no advisory names. A single fixture cannot show that: whichever one it
// used, the parse would look correct. The distinction only appears when both are
// parsed from the same stream and compared, which is why the fixture carries both.
const symbolPairFixture = `
{"osv": {"id": "GO-2026-9001", "summary": "Excessive memory allocation during header parsing", "affected": [
  {"package": {"name": "example.com/jwt"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
  {"package": {"name": "example.com/jwt/v4"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.5.2"}]}], "ecosystem_specific": {"imports": [{"path": "example.com/jwt/v4", "symbols": ["Parser.ParseUnverified"]}]}}
]}}
{"finding": {"osv": "GO-2026-9001", "trace": [{"module": "example.com/jwt", "version": "v3.2.2+incompatible", "package": "example.com/jwt", "function": "init"}, {"module": "example.com/oauth2", "version": "v4.4.3", "package": "example.com/oauth2/generates", "function": "init"}, {"module": "example.com/proj", "package": "example.com/proj/pkg/auth", "function": "init"}]}}
{"finding": {"osv": "GO-2026-9001", "fixed_version": "v4.5.2", "trace": [{"module": "example.com/jwt/v4", "version": "v4.5.1", "package": "example.com/jwt/v4", "function": "ParseUnverified", "receiver": "*Parser"}, {"module": "example.com/jwt/v4", "version": "v4.5.1", "package": "example.com/jwt/v4", "function": "ParseWithClaims", "receiver": "*Parser"}, {"module": "example.com/proj", "package": "example.com/proj/auth", "function": "CompleteUserAuth"}]}}
`

// TestParseResultsByModule_InitOnlyTraceIsNotARoute parses the pair on the
// project-rooted path and asserts the two coordinates are told apart.
func TestParseResultsByModule_InitOnlyTraceIsNotARoute(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(symbolPairFixture), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}

	pkgLevel := coordinatetest.MustNew("example.com/jwt", "v3.2.2+incompatible")
	symLevel := coordinatetest.MustNew("example.com/jwt/v4", "v4.5.1")

	// --- the entry naming NO symbol: affected at package level, no route ---
	got := byModule[pkgLevel]
	if len(got) != 1 {
		t.Fatalf("findings for %s = %d, want 1 — the coordinate match must stand", pkgLevel, len(got))
	}
	f := got[0]
	if f.ID != "GO-2026-9001" {
		t.Fatalf("finding ID = %q, want GO-2026-9001", f.ID)
	}
	r := f.Reachable
	if r == nil {
		t.Fatal("the package-level finding carries no reachability answer at all")
	}
	if r.IsReachable {
		t.Error("an init-only trace was ingested as reachable: package linkage was reported as the vulnerable code running")
	}
	if r.Confidence == domain.ConfidenceHigh {
		t.Errorf("confidence = %q on a verdict reached with no symbol route", r.Confidence)
	}
	if r.Confidence != domain.ConfidenceUnknown {
		t.Errorf("confidence = %q, want %q — the existing not-determined value", r.Confidence, domain.ConfidenceUnknown)
	}
	if len(r.Routes) != 0 {
		t.Errorf("got %d route(s) from an init-only trace, want 0: %v", len(r.Routes), r.Routes)
	}
	if len(f.AffectedSymbols) != 0 {
		t.Errorf("affected symbols = %v, want none — no advisory names a package initialiser", f.AffectedSymbols)
	}
	if !f.AdvisoryNamesNoSymbols {
		t.Error("the finding does not record that the advisory names no symbols for this path, so the empty route is unexplained")
	}
	// The derivation is still stamped: the answer is undetermined, not absent.
	if r.DerivedBy.Analyser != domain.AnalyserGovulncheck {
		t.Errorf("analyser = %q, want %q", r.DerivedBy.Analyser, domain.AnalyserGovulncheck)
	}

	// --- the entry naming a symbol: a genuine route, reachable ---
	got = byModule[symLevel]
	if len(got) != 1 {
		t.Fatalf("findings for %s = %d, want 1", symLevel, len(got))
	}
	f = got[0]
	r = f.Reachable
	if r == nil || !r.IsReachable {
		t.Fatalf("the symbol-level finding is not reachable: %+v", r)
	}
	if r.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %q on a genuine symbol route, want %q", r.Confidence, domain.ConfidenceHigh)
	}
	if len(r.Routes) != 1 {
		t.Fatalf("got %d route(s) for the symbol-level finding, want 1", len(r.Routes))
	}
	route := r.Routes[0]
	if len(route) != 3 {
		t.Fatalf("route has %d hops, want 3: %v", len(route), route)
	}
	if route[0].Symbol != "CompleteUserAuth" {
		t.Errorf("hop 0 = %v, want the project entry point first", route[0])
	}
	last := route[len(route)-1]
	if last.Symbol != "ParseUnverified" || last.ModuleVersion != "v4.5.1" {
		t.Errorf("last hop = %v, want the advisory's named symbol at v4.5.1", last)
	}
	if len(f.AffectedSymbols) != 1 || f.AffectedSymbols[0] != "*Parser.ParseUnverified" {
		t.Errorf("affected symbols = %v, want [*Parser.ParseUnverified]", f.AffectedSymbols)
	}
	if f.AdvisoryNamesNoSymbols {
		t.Error("an advisory entry that names Parser.ParseUnverified was recorded as naming no symbols")
	}
}

// TestParseResults_InitOnlyTraceIsNotARoute is the single-module counterpart. The
// same stream is parsed once per scanned module, since an isolated scan keeps only
// the findings attributed to the module it scanned.
func TestParseResults_InitOnlyTraceIsNotARoute(t *testing.T) {
	s := New("v1", nil)

	pkgFindings, err := s.parseResults(t.Context(), strings.NewReader(symbolPairFixture), "example.com/jwt", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults for the no-symbol path: %v", err)
	}
	if len(pkgFindings) != 1 {
		t.Fatalf("findings for example.com/jwt = %d, want 1", len(pkgFindings))
	}
	f := pkgFindings[0]
	if f.Reachable == nil {
		t.Fatal("the package-level finding carries no reachability answer at all")
	}
	if f.Reachable.IsReachable {
		t.Error("an init-only trace was ingested as reachable on the single-module path")
	}
	if f.Reachable.Confidence != domain.ConfidenceUnknown {
		t.Errorf("confidence = %q, want %q", f.Reachable.Confidence, domain.ConfidenceUnknown)
	}
	if len(f.Reachable.Routes) != 0 {
		t.Errorf("got %d route(s) from an init-only trace, want 0", len(f.Reachable.Routes))
	}
	if len(f.AffectedSymbols) != 0 {
		t.Errorf("affected symbols = %v, want none", f.AffectedSymbols)
	}
	if !f.AdvisoryNamesNoSymbols {
		t.Error("the finding does not record that the advisory names no symbols for this path")
	}

	symFindings, err := s.parseResults(t.Context(), strings.NewReader(symbolPairFixture), "example.com/jwt/v4", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults for the symbol-naming path: %v", err)
	}
	if len(symFindings) != 1 {
		t.Fatalf("findings for example.com/jwt/v4 = %d, want 1", len(symFindings))
	}
	f = symFindings[0]
	if f.Reachable == nil || !f.Reachable.IsReachable {
		t.Fatalf("the symbol-level finding is not reachable: %+v", f.Reachable)
	}
	if f.Reachable.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %q, want %q", f.Reachable.Confidence, domain.ConfidenceHigh)
	}
	if len(f.Reachable.Routes) != 1 {
		t.Errorf("got %d route(s) for a genuine symbol route, want 1", len(f.Reachable.Routes))
	}
	if len(f.AffectedSymbols) != 1 || f.AffectedSymbols[0] != "*Parser.ParseUnverified" {
		t.Errorf("affected symbols = %v, want [*Parser.ParseUnverified]", f.AffectedSymbols)
	}
	if f.AdvisoryNamesNoSymbols {
		t.Error("an advisory entry naming a symbol was recorded as naming none")
	}
}

// mixedTraceFixture is the other side of the gate: initialisation code does call
// ordinary functions, and a chain that starts in an init frame and ends at a real
// symbol is a path that runs. Narrowing on "the trace mentions init" rather than
// "every frame is init" would discard it.
const mixedTraceFixture = `
{"osv": {"id": "GO-2026-9002", "summary": "Vulnerable parser", "affected": [
  {"package": {"name": "example.com/lib"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}], "ecosystem_specific": {"imports": [{"path": "example.com/lib", "symbols": ["Parse"]}]}}
]}}
{"finding": {"osv": "GO-2026-9002", "trace": [{"module": "example.com/lib", "version": "v1.2.0", "package": "example.com/lib", "function": "Parse"}, {"module": "example.com/proj", "package": "example.com/proj", "function": "init"}]}}
`

// TestParseResultsByModule_InitCallerIntoASymbolIsStillARoute proves the gate is
// not over-broad.
func TestParseResultsByModule_InitCallerIntoASymbolIsStillARoute(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(mixedTraceFixture), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}
	coord := coordinatetest.MustNew("example.com/lib", "v1.2.0")
	got := byModule[coord]
	if len(got) != 1 {
		t.Fatalf("findings for %s = %d, want 1", coord, len(got))
	}
	f := got[0]
	if f.Reachable == nil || !f.Reachable.IsReachable {
		t.Fatalf("a route from an init frame into a named symbol was discarded: %+v", f.Reachable)
	}
	if f.Reachable.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %q, want %q", f.Reachable.Confidence, domain.ConfidenceHigh)
	}
	if len(f.Reachable.Routes) != 1 {
		t.Errorf("got %d route(s), want 1", len(f.Reachable.Routes))
	}
	if len(f.AffectedSymbols) != 1 || f.AffectedSymbols[0] != "Parse" {
		t.Errorf("affected symbols = %v, want [Parse]", f.AffectedSymbols)
	}
	if f.AdvisoryNamesNoSymbols {
		t.Error("an advisory entry naming Parse was recorded as naming no symbols")
	}
}

// TestIsPackageInitFrame covers the names the toolchain gives a package's
// initialisation functions, and the ordinary symbols that merely start with the
// same letters.
func TestIsPackageInitFrame(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		fn   string
		want bool
	}{
		{"init", true},
		{"init#1", true},
		{"init#12", true},
		{"init.0", true},
		{"", false},
		{"init#", false},
		{"init.", false},
		{"initialise", false},
		{"initConfig", false},
		{"Init", false},
		{"init#a", false},
		{"Parse", false},
	} {
		if got := isPackageInitFrame(traceFrame{Function: tc.fn}); got != tc.want {
			t.Errorf("isPackageInitFrame(%q) = %v, want %v", tc.fn, got, tc.want)
		}
	}
}

// TestTraceIsPackageInitOnly_EmptyTraceIsNotInitOnly keeps the predicate from
// answering "yes" for a trace it saw nothing in. An empty trace is rejected
// earlier by both parse paths; answering true here would make a future caller
// that reaches it classify a finding with no evidence at all as package-level.
func TestTraceIsPackageInitOnly_EmptyTraceIsNotInitOnly(t *testing.T) {
	t.Parallel()

	if traceIsPackageInitOnly(nil) {
		t.Error("an empty trace was classified as package-initialisation-only")
	}
}

// TestApplyOSV_UnnamedPathRecordsNothing guards the one way this fix could invent
// an advisory fact: an advisory that says nothing about a module path must not be
// read as naming no symbols for it. The two are different, and only the first is
// silence.
func TestApplyOSV_UnnamedPathRecordsNothing(t *testing.T) {
	t.Parallel()

	entry := &OSV{
		ID:            "GO-2026-9003",
		SymbolsByPath: map[string][]string{"example.com/named": {}},
	}

	var stated domain.VulnerabilityFinding
	applyOSV(&stated, entry, "example.com/named")
	if !stated.AdvisoryNamesNoSymbols {
		t.Error("an entry that names the path with no symbols was not recorded")
	}

	var silent domain.VulnerabilityFinding
	applyOSV(&silent, entry, "example.com/never-mentioned")
	if silent.AdvisoryNamesNoSymbols {
		t.Error("a path the advisory never mentions was recorded as named with no symbols")
	}

	// No advisory read at all states nothing either.
	var unenriched domain.VulnerabilityFinding
	applyOSV(&unenriched, nil, "example.com/named")
	if unenriched.AdvisoryNamesNoSymbols {
		t.Error("a finding whose OSV message never arrived recorded an advisory fact")
	}
}
