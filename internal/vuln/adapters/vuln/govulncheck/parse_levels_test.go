package govulncheck

import (
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// levelsFixture is a govulncheck stream in the shape a real one has: the
// analysis emits ONE FINDING MESSAGE PER LEVEL for the same advisory.
//
//   - GO-2026-9101 reaches a symbol, so it arrives three times: module level
//     (one frame, no package, no function), package level (one frame, a package,
//     no function) and symbol level (a call chain rooted in the project).
//   - GO-2026-9102 does not, so it arrives twice: module and package level only.
//     That pair IS govulncheck's negative — it loaded the build and traced no
//     call into the vulnerable symbol.
//   - GO-2026-9103 is a third-party module reported at module level only, so the
//     same question is asked of a coordinate that is not the standard library.
//
// Every message carries the branch-correct fixed version the analysis selected
// for the version in hand: v1.26.6, not the v1.27.0-rc.3 the advisory's own
// range list ends with.
const levelsFixture = `
{"osv": {"id": "GO-2026-9101", "summary": "Fix Javascript regexp context tracking in html/template", "affected": [
  {"package": {"name": "stdlib"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.25.13"}, {"introduced": "1.26.0-0"}, {"fixed": "1.26.6"}, {"introduced": "1.27.0-0"}, {"fixed": "1.27.0-rc.3"}]}], "ecosystem_specific": {"imports": [{"path": "html/template", "symbols": ["Template.Execute"]}]}}
]}}
{"osv": {"id": "GO-2026-9102", "summary": "Parsing an invalid record can panic in net", "affected": [
  {"package": {"name": "stdlib"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.26.6"}, {"introduced": "1.27.0-0"}, {"fixed": "1.27.0-rc.3"}]}], "ecosystem_specific": {"imports": [{"path": "net", "symbols": ["Resolver.LookupCNAME"]}]}}
]}}
{"osv": {"id": "GO-2026-9103", "summary": "Excessive CPU in example.com/text", "affected": [
  {"package": {"name": "example.com/text"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.38.1"}, {"introduced": "0.39.0"}, {"fixed": "0.39.2"}]}], "ecosystem_specific": {"imports": [{"path": "example.com/text/unicode", "symbols": ["Form.String"]}]}}
]}}
{"finding": {"osv": "GO-2026-9101", "fixed_version": "v1.26.6", "trace": [{"module": "stdlib", "version": "v1.26.5"}]}}
{"finding": {"osv": "GO-2026-9101", "fixed_version": "v1.26.6", "trace": [{"module": "stdlib", "version": "v1.26.5", "package": "html/template"}]}}
{"finding": {"osv": "GO-2026-9101", "fixed_version": "v1.26.6", "trace": [{"module": "stdlib", "version": "v1.26.5", "package": "html/template", "function": "Execute", "receiver": "*Template"}, {"module": "example.com/proj", "package": "example.com/proj/internal/rest", "function": "Render"}]}}
{"finding": {"osv": "GO-2026-9102", "fixed_version": "v1.26.6", "trace": [{"module": "stdlib", "version": "v1.26.5"}]}}
{"finding": {"osv": "GO-2026-9102", "fixed_version": "v1.26.6", "trace": [{"module": "stdlib", "version": "v1.26.5", "package": "net"}]}}
{"finding": {"osv": "GO-2026-9103", "fixed_version": "v0.39.2", "trace": [{"module": "example.com/text", "version": "v0.39.0"}]}}
`

// findingByID returns the one finding with this id, failing when the set does
// not hold exactly one.
func findingByID(t *testing.T, findings []domain.VulnerabilityFinding, id string) domain.VulnerabilityFinding {
	t.Helper()
	var out []domain.VulnerabilityFinding
	for _, f := range findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("findings with id %s = %d, want 1 (whole set: %v)", id, len(out), findings)
	}
	return out[0]
}

// TestParseResultsByModule_EveryLevelIsRead asserts the project-rooted parse
// keeps what govulncheck said at each level.
//
// Before this, only the symbol level was read. An advisory the analysis reported
// at module or package level was discarded outright, so the record was built as
// though govulncheck had never mentioned it: the advisory reached the record by
// coordinate match instead, carrying the advisory's own highest fixed version —
// a release candidate — and a not-reachable verdict derived from a silence that
// never happened.
func TestParseResultsByModule_EveryLevelIsRead(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(levelsFixture), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}

	stdlib := byModule[coordinate.NewStdlibCoordinate()]
	if len(stdlib) != 2 {
		t.Fatalf("stdlib findings = %d, want 2 — one reached, one reported without a route: %v", len(stdlib), stdlib)
	}

	// --- reached: the control, which must stay reachable with its route ---
	reached := findingByID(t, stdlib, "GO-2026-9101")
	if reached.Reachable == nil || !reached.Reachable.IsReachable {
		t.Fatalf("GO-2026-9101 is not reachable; the symbol-level trace was lost: %+v", reached.Reachable)
	}
	if len(reached.Reachable.Routes) != 1 {
		t.Errorf("routes = %d, want 1", len(reached.Reachable.Routes))
	}
	if reached.Reachable.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %q, want High on a symbol route", reached.Reachable.Confidence)
	}
	if reached.FixedIn != "v1.26.6" {
		t.Errorf("fixed_in = %q, want v1.26.6 — the version the analysis selected", reached.FixedIn)
	}

	// --- reported without a route: kept, negative, and the fix is the analyser's ---
	unreached := findingByID(t, stdlib, "GO-2026-9102")
	r := unreached.Reachable
	if r == nil {
		t.Fatal("GO-2026-9102 carries no reachability answer; govulncheck reported it at two levels")
	}
	if r.IsReachable {
		t.Error("GO-2026-9102 is reachable, but no symbol-level trace was reported for it")
	}
	if r.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %q, want High: the analysis examined this module and said no route reached it", r.Confidence)
	}
	if len(r.Routes) != 0 {
		t.Errorf("routes = %d, want 0", len(r.Routes))
	}
	if r.DerivedBy.Analyser != domain.AnalyserGovulncheck || r.DerivedBy.Fidelity != string(domain.ScanModeSource) {
		t.Errorf("derivation = %+v, want govulncheck/source", r.DerivedBy)
	}
	if unreached.FixedIn != "v1.26.6" {
		t.Errorf("fixed_in = %q, want v1.26.6 — the analysis named the stable point release, not the release candidate", unreached.FixedIn)
	}
	// The analysis reached no symbol, so the advisory's own at-risk list is what
	// the finding states — the same list the coordinate-match route would have
	// supplied for this advisory, so one advisory has one shape whichever route
	// produced it.
	if want := []string{"Resolver.LookupCNAME"}; !slices.Equal(unreached.AffectedSymbols, want) {
		t.Errorf("affected symbols = %v, want %v — the advisory's own at-risk list", unreached.AffectedSymbols, want)
	}

	// --- the same question of a third-party module, not the standard library ---
	text := byModule[coordinatetest.MustNew("example.com/text", "v0.39.0")]
	if len(text) != 1 {
		t.Fatalf("example.com/text findings = %d, want 1 — a module-level report is still a finding: %v", len(text), text)
	}
	if text[0].FixedIn != "v0.39.2" {
		t.Errorf("fixed_in = %q, want v0.39.2", text[0].FixedIn)
	}
	if text[0].Reachable == nil || text[0].Reachable.IsReachable {
		t.Errorf("example.com/text finding reachability = %+v, want a negative", text[0].Reachable)
	}
}

// TestParseResults_EveryLevelIsRead asserts the single-module parse reads the
// same levels. The two paths must weigh one advisory the same way; before this
// the isolated parse dropped a non-symbolic finding message entirely.
func TestParseResults_EveryLevelIsRead(t *testing.T) {
	s := New("v1", nil)

	findings, err := s.parseResults(t.Context(), strings.NewReader(levelsFixture), "stdlib", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2: %v", len(findings), findings)
	}

	reached := findingByID(t, findings, "GO-2026-9101")
	if reached.Reachable == nil || !reached.Reachable.IsReachable {
		t.Errorf("GO-2026-9101 reachability = %+v, want reachable", reached.Reachable)
	}
	if reached.FixedIn != "v1.26.6" {
		t.Errorf("fixed_in = %q, want v1.26.6", reached.FixedIn)
	}

	unreached := findingByID(t, findings, "GO-2026-9102")
	if unreached.Reachable == nil {
		t.Fatal("GO-2026-9102 was dropped: the analysis reported it at two levels")
	}
	if unreached.Reachable.IsReachable {
		t.Error("GO-2026-9102 is reachable, but no symbol-level trace was reported for it")
	}
	if unreached.Reachable.Confidence != domain.ConfidenceHigh {
		t.Errorf("confidence = %q, want High", unreached.Reachable.Confidence)
	}
	if unreached.FixedIn != "v1.26.6" {
		t.Errorf("fixed_in = %q, want v1.26.6", unreached.FixedIn)
	}
}

// TestParseResultsByModule_InitOnlyStaysUndetermined is the control for the
// change above: a trace of nothing but package-initialisation frames is NOT a
// module-level report and must not be promoted to a stated negative. Package
// linkage says the vulnerable package is in the build; it says nothing about
// whether a route to the vulnerable code exists.
func TestParseResultsByModule_InitOnlyStaysUndetermined(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(symbolPairFixture), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}
	got := byModule[coordinatetest.MustNew("example.com/jwt", "v3.2.2+incompatible")]
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if c := got[0].Reachable.Confidence; c != domain.ConfidenceUnknown {
		t.Errorf("confidence = %q, want %q on an init-only trace", c, domain.ConfidenceUnknown)
	}
}
