package govulncheck

import (
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestApplyOSV_AdvisoryNamingNoSymbolsEmptiesTheField is the regression test for
// one field carrying two different facts.
//
// A finding arrives from the stream carrying the symbols its trace terminated at.
// Where the advisory entry for the matched module path names no symbols, those
// terminals are not the advisory's at-risk list — they are functions of the
// affected package that this build happened to call, and no advisory names them.
// Leaving them in AffectedSymbols files them under the advisory's authority, and
// sets the "the advisory named none" flag beside a list, so nothing on the wire
// says which fact the field holds.
//
// The pair of cases is the test. Emptying the field unconditionally would pass
// the first half and fail the second, and the second is what the field is for.
func TestApplyOSV_AdvisoryNamingNoSymbolsEmptiesTheField(t *testing.T) {
	t.Parallel()

	entry := &OSV{
		ID: "GO-2026-9101",
		SymbolsByPath: map[string][]string{
			"example.com/unnamed": {},
			"example.com/named":   {"Parser.Parse", "Parser.ParseUnverified"},
		},
	}

	// The defect's own shape: the entry names no symbols for this path, and the
	// analysis reached two functions of the package anyway.
	traced := domain.VulnerabilityFinding{
		ID:              "GO-2026-9101",
		AffectedSymbols: []string{"*maybeCompressResponseWriter.Close", "*basicWriter.Status"},
	}
	applyOSV(&traced, entry, "example.com/unnamed")
	if !traced.AdvisoryNamesNoSymbols {
		t.Error("AdvisoryNamesNoSymbols = false: the entry names this path and lists nothing under it")
	}
	if len(traced.AffectedSymbols) != 0 {
		t.Errorf("AffectedSymbols = %v, want empty: the advisory names none for this path, so the trace's terminals must not stand in the field that says what it names", traced.AffectedSymbols)
	}

	// The other half, unchanged: the entry names symbols and the analysis reached
	// none of them, so the advisory's own list is the answer.
	unreached := domain.VulnerabilityFinding{ID: "GO-2026-9101"}
	applyOSV(&unreached, entry, "example.com/named")
	if unreached.AdvisoryNamesNoSymbols {
		t.Error("AdvisoryNamesNoSymbols = true on an entry that names two symbols for this path")
	}
	if want := []string{"Parser.Parse", "Parser.ParseUnverified"}; !slices.Equal(unreached.AffectedSymbols, want) {
		t.Errorf("AffectedSymbols = %v, want %v: an analysis that reached no symbol states the advisory's at-risk list", unreached.AffectedSymbols, want)
	}

	// And a reached list under an entry that names symbols is still never
	// overwritten: it is the more precise answer, and it is drawn from the same
	// advisory's named set.
	reached := domain.VulnerabilityFinding{
		ID:              "GO-2026-9101",
		AffectedSymbols: []string{"Parser.ParseUnverified"},
	}
	applyOSV(&reached, entry, "example.com/named")
	if want := []string{"Parser.ParseUnverified"}; !slices.Equal(reached.AffectedSymbols, want) {
		t.Errorf("AffectedSymbols = %v, want %v: the advisory's whole list overwrote what the analysis reached", reached.AffectedSymbols, want)
	}
}

// packageLevelCallFixture is the non-initialisation half of the same class.
//
// One advisory names two module paths: a symbol for the newer one, and nothing at
// all for the older. The older path's trace is NOT all initialisation frames — the
// build genuinely calls a function of the affected package, so a real route exists
// — and that is exactly the carve-out the init-only gate leaves alone. What the
// trace cannot be is a route to the vulnerable symbol, because the advisory named
// none, so the terminal it reached is a function this build happened to call and
// not something the advisory considers at risk.
//
// The pair is the test again: the same stream must produce a symbol-level answer
// for the entry that names a symbol and a package-level one for the entry that
// does not, and nothing but the advisory entry tells them apart.
const packageLevelCallFixture = `
{"osv": {"id": "GO-2026-9102", "summary": "Open redirect in the router middleware", "affected": [
  {"package": {"name": "example.com/router"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
  {"package": {"name": "example.com/router/v5"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "5.2.2"}, {"fixed": "5.2.4"}]}], "ecosystem_specific": {"imports": [{"path": "example.com/router/v5/middleware", "symbols": ["RedirectSlashes"]}]}}
]}}
{"finding": {"osv": "GO-2026-9102", "trace": [{"module": "example.com/router", "version": "v3.3.4+incompatible", "package": "example.com/router/middleware", "function": "Close", "receiver": "*maybeCompressResponseWriter"}, {"module": "example.com/proj", "package": "example.com/proj/auth", "function": "FetchUser", "receiver": "*Provider"}]}}
{"finding": {"osv": "GO-2026-9102", "fixed_version": "v5.2.4", "trace": [{"module": "example.com/router/v5", "version": "v5.2.3", "package": "example.com/router/v5/middleware", "function": "RedirectSlashes"}, {"module": "example.com/proj", "package": "example.com/proj/http", "function": "Mount"}]}}
`

// TestParseResultsByModule_PackageLevelCallIsARouteWithNoSymbolClaim is the
// regression test for the second fact this class got wrong.
//
// Where the advisory names no symbols for the module path, govulncheck matched at
// package level and had no symbol to search for. A trace that ends in a real call
// frame therefore proves the build calls INTO the affected package and nothing
// about whether the vulnerable code runs — so the stored bit must not read true
// and the confidence must not read High. The route itself survives: it is the
// answer to "which of my dependencies pulls this in", and it is what separates
// this case from the all-initialisation one, where there is no call at all.
func TestParseResultsByModule_PackageLevelCallIsARouteWithNoSymbolClaim(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(packageLevelCallFixture), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}

	pkgLevel := coordinatetest.MustNew("example.com/router", "v3.3.4+incompatible")
	symLevel := coordinatetest.MustNew("example.com/router/v5", "v5.2.3")

	got := byModule[pkgLevel]
	if len(got) != 1 {
		t.Fatalf("findings for %s = %d, want 1 — the coordinate match must stand", pkgLevel, len(got))
	}
	f := got[0]
	if !f.AdvisoryNamesNoSymbols {
		t.Fatal("the entry naming this path with no symbols was not recorded")
	}
	if len(f.AffectedSymbols) != 0 {
		t.Errorf("affected symbols = %v, want none: the trace's terminal is not something the advisory named", f.AffectedSymbols)
	}
	r := f.Reachable
	if r == nil {
		t.Fatal("the package-level finding carries no reachability answer at all")
	}
	if r.IsReachable {
		t.Error("is_reachable = true on a finding whose advisory names no symbol: the analysis had no target, so nothing established that the vulnerable code runs")
	}
	if r.Confidence != domain.ConfidenceUnknown {
		t.Errorf("confidence = %q, want %q — a package-level match weighs a linkage observation, not a call path", r.Confidence, domain.ConfidenceUnknown)
	}
	// The route is the half that must NOT be lost: a real call frame is evidence
	// about which dependency reaches the package, and it is what tells this case
	// apart from an all-initialisation trace.
	if len(r.Routes) != 1 {
		t.Fatalf("got %d route(s), want 1: a real call frame is still a route", len(r.Routes))
	}
	route := r.Routes[0]
	if len(route) != 2 {
		t.Fatalf("route has %d hops, want 2: %v", len(route), route)
	}
	if route[0].Symbol != "FetchUser" {
		t.Errorf("hop 0 = %v, want the project entry point first", route[0])
	}
	if last := route[len(route)-1]; last.Symbol != "Close" || last.ModuleVersion != "v3.3.4+incompatible" {
		t.Errorf("last hop = %v, want the reached function of the affected package", last)
	}
	if state := domain.FindingReachabilityState(f); state != domain.StatePackageLevelOnly {
		t.Errorf("reachability state = %q, want %q", state, domain.StatePackageLevelOnly)
	}

	// The control: the same advisory, on the path whose entry DOES name a symbol,
	// is untouched — reachable, High, one route, the advisory's symbol.
	got = byModule[symLevel]
	if len(got) != 1 {
		t.Fatalf("findings for %s = %d, want 1", symLevel, len(got))
	}
	f = got[0]
	if f.AdvisoryNamesNoSymbols {
		t.Error("an entry that names RedirectSlashes was recorded as naming no symbols")
	}
	r = f.Reachable
	if r == nil || !r.IsReachable {
		t.Fatalf("the symbol-level finding is not reachable: %+v", r)
	}
	if r.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %q on a genuine symbol route, want %q", r.Confidence, domain.ConfidenceHigh)
	}
	if len(f.AffectedSymbols) != 1 || f.AffectedSymbols[0] != "RedirectSlashes" {
		t.Errorf("affected symbols = %v, want [RedirectSlashes]", f.AffectedSymbols)
	}
	if state := domain.FindingReachabilityState(f); state != domain.StateReachable {
		t.Errorf("reachability state = %q, want %q", state, domain.StateReachable)
	}
}

// TestParseResults_PackageLevelCallIsARouteWithNoSymbolClaim is the single-module
// counterpart. The two parse paths build the reachability answer in different
// places, so a fix applied to one and not the other is invisible to either test
// alone.
func TestParseResults_PackageLevelCallIsARouteWithNoSymbolClaim(t *testing.T) {
	s := New("v1", nil)

	findings, err := s.parseResults(t.Context(), strings.NewReader(packageLevelCallFixture), "example.com/router", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings for example.com/router = %d, want 1", len(findings))
	}
	f := findings[0]
	if !f.AdvisoryNamesNoSymbols {
		t.Fatal("the entry naming this path with no symbols was not recorded")
	}
	if len(f.AffectedSymbols) != 0 {
		t.Errorf("affected symbols = %v, want none", f.AffectedSymbols)
	}
	r := f.Reachable
	if r == nil {
		t.Fatal("no reachability answer at all")
	}
	if r.IsReachable {
		t.Error("is_reachable = true on a finding whose advisory names no symbol for this path")
	}
	if r.Confidence != domain.ConfidenceUnknown {
		t.Errorf("confidence = %q, want %q", r.Confidence, domain.ConfidenceUnknown)
	}
	if len(r.Routes) != 1 {
		t.Errorf("got %d route(s), want 1: the call frame is still evidence about which dependency reaches the package", len(r.Routes))
	}
}
