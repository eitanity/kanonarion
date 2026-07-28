package govulncheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// indentStream re-encodes a stream of compact JSON messages the way govulncheck
// actually writes them: one indented, multi-line JSON object per message,
// concatenated with no separator. This is the shape a real `govulncheck -json`
// run produces, and the shape the parser must read.
func indentStream(t *testing.T, compact string) string {
	t.Helper()
	var out bytes.Buffer
	dec := json.NewDecoder(strings.NewReader(compact))
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "  ")
	for {
		var msg json.RawMessage
		if err := dec.Decode(&msg); err != nil {
			break
		}
		var pretty any
		if err := json.Unmarshal(msg, &pretty); err != nil {
			t.Fatalf("re-decoding fixture message: %v", err)
		}
		if err := enc.Encode(pretty); err != nil {
			t.Fatalf("re-encoding fixture message: %v", err)
		}
	}
	return out.String()
}

// projectStreamFixture is one reachable dependency advisory, in the message
// order govulncheck emits.
const projectStreamFixture = `
{"osv": {"id": "GO-2026-5970", "summary": "Infinite loop on invalid input in golang.org/x/text"}}
{"finding": {"osv": "GO-2026-5970", "fixed_version": "v0.39.0", "trace": [{"module": "golang.org/x/text", "version": "v0.37.0", "package": "golang.org/x/text/unicode/norm", "function": "Append", "receiver": "Form"}, {"module": "example.com/proj", "package": "example.com/proj", "function": "main"}]}}
`

// TestParseResultsByModule_IndentedStreamIsNotDiscarded is the regression guard
// for a false AllClean on the project-rooted path.
//
// govulncheck writes its -json messages indent-formatted, so one finding message
// spans dozens of lines and no single line carries a whole message. The parser
// used to frame the stream by newline and gate each line on `"finding":`
// appearing together with `"function"` — a pair that cannot occur on one line of
// indented output. Every finding was silently discarded, the grouped map came
// back empty, and every module in a vulnerable build was reported Clean.
//
// The identical fixture is parsed compact and indented: the two must agree.
func TestParseResultsByModule_IndentedStreamIsNotDiscarded(t *testing.T) {
	s := New("v1", nil)
	xtext := coordinatetest.MustNew("golang.org/x/text", "v0.37.0")

	indented := indentStream(t, projectStreamFixture)
	if strings.Contains(indented, `"finding"`) && !strings.Contains(indented, "\n") {
		t.Fatal("fixture is not multi-line; the framing regression cannot be reproduced")
	}

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(indented), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule on indented stream: %v", err)
	}
	got := byModule[xtext]
	if len(got) != 1 || got[0].ID != "GO-2026-5970" {
		t.Fatalf("indented stream findings for %s = %+v, want GO-2026-5970", xtext, got)
	}
	if got[0].Summary != "Infinite loop on invalid input in golang.org/x/text" {
		t.Errorf("OSV enrichment lost on indented stream: summary = %q", got[0].Summary)
	}
	if r := got[0].Reachable; r == nil || !r.IsReachable {
		t.Errorf("reachability lost on indented stream: %+v", r)
	}
	if len(got[0].AffectedSymbols) != 1 || got[0].AffectedSymbols[0] != "Form.Append" {
		t.Errorf("affected symbols on indented stream = %v, want [Form.Append]", got[0].AffectedSymbols)
	}

	compact, err := s.parseResultsByModule(t.Context(), strings.NewReader(projectStreamFixture), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule on compact stream: %v", err)
	}
	if len(compact[xtext]) != len(got) {
		t.Errorf("indented and compact parses disagree: %d vs %d findings", len(got), len(compact[xtext]))
	}
}

// TestParseResults_IndentedStreamIsNotDiscarded is the single-module
// counterpart: the same newline framing discarded the scanned module's own
// findings, leaving an isolated source scan structurally unable to report
// anything at all.
func TestParseResults_IndentedStreamIsNotDiscarded(t *testing.T) {
	s := New("v1", nil)
	indented := indentStream(t, projectStreamFixture)

	findings, err := s.parseResults(t.Context(), strings.NewReader(indented), "golang.org/x/text", domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResults on indented stream: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "GO-2026-5970" {
		t.Fatalf("indented stream findings = %+v, want GO-2026-5970", findings)
	}
	if findings[0].Summary == "" {
		t.Error("OSV enrichment lost on indented stream")
	}
}

// TestStreamMessages_TruncatedStreamIsAnError guards the other half of the
// framing change: a stream cut mid-message is a parse that saw less than
// govulncheck emitted, which must never be reported as a clean verdict.
func TestStreamMessages_TruncatedStreamIsAnError(t *testing.T) {
	s := New("v1", nil)
	indented := indentStream(t, projectStreamFixture)
	truncated := indented[:len(indented)-40]

	if _, err := s.parseResultsByModule(t.Context(), strings.NewReader(truncated), domain.ScanModeSource); err == nil {
		t.Fatal("parseResultsByModule on a truncated stream returned nil error; a partial parse must not read as clean")
	}
}

// TestParseResultsByModule_KeepsTheVersionedRoute is the regression for a route
// that arrived in full and was thrown away.
//
// govulncheck reports the whole call chain beside each finding, with a module
// path AND a version at every hop it knows one for. The parser used to unmarshal
// that trace into a struct that kept three fields, read trace[0] to decide
// attribution, and discard every caller frame — so the store held the two ends
// of a reachability answer and nothing between them, and "which of my
// dependencies drags this in" could not be answered from it.
func TestParseResultsByModule_KeepsTheVersionedRoute(t *testing.T) {
	s := New("v1", nil)

	byModule, err := s.parseResultsByModule(t.Context(), strings.NewReader(projectStreamFixture), domain.ScanModeSource)
	if err != nil {
		t.Fatalf("parseResultsByModule: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate("golang.org/x/text", "v0.37.0")
	if err != nil {
		t.Fatalf("building coordinate: %v", err)
	}
	findings := byModule[coord]
	if len(findings) != 1 {
		t.Fatalf("got %d findings for the owning module, want 1", len(findings))
	}
	r := findings[0].Reachable
	if r == nil {
		t.Fatal("the finding carries no reachability answer")
	}

	// The derivation names the instrument and how well it could see.
	if r.DerivedBy.Analyser != domain.AnalyserGovulncheck {
		t.Errorf("analyser = %q, want %q", r.DerivedBy.Analyser, domain.AnalyserGovulncheck)
	}
	if r.DerivedBy.Fidelity != string(domain.ScanModeSource) {
		t.Errorf("fidelity = %q, want %q", r.DerivedBy.Fidelity, domain.ScanModeSource)
	}

	if len(r.Routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(r.Routes))
	}
	route := r.Routes[0]
	if len(route) != 2 {
		t.Fatalf("route has %d hops, want 2: %v", len(route), route)
	}
	// Entry point first: govulncheck emits the reverse, and the stored order is
	// normalised so no consumer has to know which analyser wrote it.
	if route[0].Symbol != "main" || route[0].ModulePath != "example.com/proj" {
		t.Errorf("hop 0 = %v, want the project's main", route[0])
	}
	// The vulnerable hop carries the version, which is the whole point: a reader
	// can check it against their own build, where the module may resolve to a
	// version this advisory does not affect.
	last := route[len(route)-1]
	if last.ModulePath != "golang.org/x/text" || last.ModuleVersion != "v0.37.0" || last.Symbol != "Append" {
		t.Errorf("last hop = %v, want golang.org/x/text@v0.37.0 Append", last)
	}
	if last.Receiver != "Form" {
		t.Errorf("last hop lost the receiver: %v", last)
	}
	// The entry point is a main module and so carries no version; the route is
	// still checkable, because every hop past it names one.
	if !route.IsVersioned() {
		t.Error("a route whose only unversioned hop is the entry point was reported uncheckable")
	}
}
