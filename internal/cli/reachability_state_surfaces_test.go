package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// This file pins one rule across every surface that publishes a stored
// reachability answer: the answer travels as the STATE, in text and in JSON, and
// the state is emitted whatever it is.
//
// The three surfaces disagreed when this was written. 'reachability' derived the
// five-valued state and rendered it faithfully; 'vuln-show' and 'context'
// published the stored is_reachable bit, which has two positions for a question
// with more answers than two. Measured on a working store, 24 findings carry the
// bit true beside an advisory that names no symbols for their module path — so a
// finding nothing showed running was served as reachable, was read as reachable
// by an audit, and was published before the report had to be corrected.

// stateRecord is a stored record holding the three answers that have to be
// distinguishable, in the shapes a working store actually holds them in:
//
//	the-positive          a route to a symbol the advisory names
//	the-negative          the analysis reported no route
//	the-package-level     the advisory names no symbols for this module path, and
//	                      the project-rooted analysis still reported a symbolic
//	                      trace, so the stored bit reads TRUE
//
// The third is the measured shape, not a constructed corner: it is how
// GO-2026-4394 sits against go.opentelemetry.io/otel/sdk@v1.39.0 in walk
// 01M1BSGJ5X1J4TE5FPWKBMC0TY.
func stateRecord() vuldomain.VulnerabilityRecord {
	derived := vuldomain.ReachabilityDerivation{
		Analyser: vuldomain.AnalyserGovulncheck,
		Fidelity: "source",
	}
	answer := func(bit bool) *vuldomain.ReachabilityResult {
		return &vuldomain.ReachabilityResult{
			IsReachable: bit,
			Confidence:  vuldomain.ConfidenceHigh,
			DerivedBy:   derived,
		}
	}
	return vuldomain.VulnerabilityRecord{
		Ecosystem:      "Go",
		Coordinate:     coordinatetest.MustNew("go.opentelemetry.io/otel/sdk", "v1.39.0"),
		Rooting:        vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
		OverallStatus:  vuldomain.StatusAffected,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordAffected,
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:              "GO-2026-0001",
				Summary:         "the positive",
				AffectedSymbols: []string{"example.com/pkg.Dial"},
				Reachable:       answer(true),
			},
			{
				ID:              "GO-2026-0002",
				Summary:         "the negative",
				AffectedSymbols: []string{"example.com/pkg.Handshake"},
				Reachable:       answer(false),
			},
			{
				ID:                     "GO-2026-0003",
				Summary:                "the package-level one",
				AffectedSymbols:        []string{"example.com/pkg.Default"},
				AdvisoryNamesNoSymbols: true,
				Reachable:              answer(true),
			},
		},
	}
}

// wantState is the state each fixture finding must be published as, on every
// surface and in both modes.
var wantState = map[string]vuldomain.ReachabilityState{
	"GO-2026-0001": vuldomain.StateReachable,
	"GO-2026-0002": vuldomain.StateNotReachable,
	"GO-2026-0003": vuldomain.StatePackageLevelOnly,
}

// TestVulnShowJSONPublishesTheState is the record-shaped surface: vuln-show,
// vuln-show --history and vuln-by-id all encode a stored record, and the audit
// that misread this defect read exactly this document.
func TestVulnShowJSONPublishesTheState(t *testing.T) {
	raw, err := json.Marshal(toVulnRecordJSON(stateRecord(), nil))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	findings := decodeFindings(t, raw)
	for id, want := range wantState {
		f, ok := findings[id]
		if !ok {
			t.Fatalf("finding %s absent from the projection: %s", id, raw)
		}
		got, present := f["reachability_state"]
		if !present {
			t.Errorf("%s: no reachability_state key — the answer is published as the stored bit alone", id)
			continue
		}
		if got != want.String() {
			t.Errorf("%s: reachability_state = %v, want %q", id, got, want)
		}
	}

	// The bit stays beside the state, and the pair is exactly why the state is
	// needed: on the package-level finding the bit reads true.
	pkg := findings["GO-2026-0003"]["reachable"].(map[string]any)
	if pkg["is_reachable"] != true {
		t.Fatalf("the fixture no longer reproduces the measured shape: is_reachable = %v, want true", pkg["is_reachable"])
	}
}

// TestVulnShowTextPublishesTheState pins the text form. A person reading a
// terminal was given "[reachable]" for the package-level finding, because the
// label tested the stored bit before it tested the advisory.
func TestVulnShowTextPublishesTheState(t *testing.T) {
	var buf bytes.Buffer
	printVulnRecord(&buf, stateRecord(), nil)
	out := buf.String()

	for id, want := range wantState {
		if !strings.Contains(out, id+" (") && !strings.Contains(out, id+"[") && !strings.Contains(out, id+" [") && !strings.Contains(out, id+":") {
			t.Fatalf("finding %s is not in the text output:\n%s", id, out)
		}
		if !strings.Contains(out, "reachability: "+want.String()+" — ") {
			t.Errorf("%s: the text form does not state %q:\n%s", id, want, out)
		}
	}
	if strings.Contains(out, "the package-level one") && strings.Contains(entryFor(out, "GO-2026-0003"), "[reachable]") {
		t.Errorf("the package-level finding is still tagged [reachable]:\n%s", out)
	}
	if !strings.Contains(entryFor(out, "GO-2026-0001"), "[reachable]") {
		t.Errorf("the positive lost its tag:\n%s", out)
	}
}

// entryFor is the slice of text output belonging to one finding: from its id up
// to the next finding's id, or the end.
func entryFor(out, id string) string {
	i := strings.Index(out, id)
	if i < 0 {
		return ""
	}
	rest := out[i+len(id):]
	if j := strings.Index(rest, "\n  GO-"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestContextPublishesTheState pins the report both an agent and a person read.
// Its JSON carried one boolean per finding, so the positive and the
// package-level finding left this projection as the same document — same
// reachable, same "not stated" rung.
func TestContextPublishesTheState(t *testing.T) {
	rec := stateRecord()
	got := vulnRecordToContext(&rec, "", "")
	byID := map[string]contextCVE{}
	for _, c := range got.Findings {
		byID[c.ID] = c
	}
	for id, want := range wantState {
		if byID[id].ReachabilityState != want {
			t.Errorf("%s: context state = %q, want %q", id, byID[id].ReachabilityState, want)
		}
	}

	raw, err := json.Marshal(byID["GO-2026-0003"])
	if err != nil {
		t.Fatalf("marshalling context finding: %v", err)
	}
	if !strings.Contains(string(raw), `"reachability_state":"package_level_only"`) {
		t.Errorf("context JSON published the package-level finding without its state: %s", raw)
	}

	var buf bytes.Buffer
	w := &errWriter{w: &buf}
	printFullCVE(w, byID["GO-2026-0003"])
	if !strings.Contains(buf.String(), "Reachability: package_level_only") {
		t.Errorf("context text published the package-level finding without its state:\n%s", buf.String())
	}
}

// TestContextAlwaysStatesTheState pins the omitempty decision, on the same terms
// the rung is pinned on. A finding nothing analysed must not serialise to the
// same bytes as a producer that does not derive the state.
func TestContextAlwaysStatesTheState(t *testing.T) {
	raw, err := json.Marshal(contextCVE{ID: "GO-2026-0004"})
	if err != nil {
		t.Fatalf("marshalling an unanalysed finding: %v", err)
	}
	if !strings.Contains(string(raw), `"reachability_state":"not_analysed"`) {
		t.Errorf("the zero state was omitted or serialised blank: %s", raw)
	}
}

// TestTheThreeSurfacesAgreeOnOneFinding is the cross-surface assertion. One
// finding, three surfaces, both modes: every one of the six answers says
// package_level_only and none of them says reachable or not_reachable.
func TestTheThreeSurfacesAgreeOnOneFinding(t *testing.T) {
	rec := stateRecord()
	const id = "GO-2026-0003"

	// reachability --json and its text form.
	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, id, unclassifiedRoutes, nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	reachJSON, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshalling reachability query: %v", err)
	}
	var reachText bytes.Buffer
	printVulnReachability(&reachText, res)

	// vuln-show --json and its text form.
	showJSON, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	var showText bytes.Buffer
	printVulnRecord(&showText, rec, nil)

	// context --json and its text form.
	ctx := vulnRecordToContext(&rec, "", "")
	var cve contextCVE
	for _, c := range ctx.Findings {
		if c.ID == id {
			cve = c
		}
	}
	ctxJSON, err := json.Marshal(cve)
	if err != nil {
		t.Fatalf("marshalling context finding: %v", err)
	}
	var ctxText bytes.Buffer
	printFullCVE(&errWriter{w: &ctxText}, cve)

	// Each surface states the answer in its own form; none of the six may state
	// one of the other two answers for this finding.
	for _, c := range []struct {
		surface string
		body    string
		states  string
		denies  []string
	}{
		{"reachability --json", string(reachJSON), `"reachability_state":"package_level_only"`, []string{`"reachability_state":"reachable"`, `"reachability_state":"not_reachable"`}},
		{"reachability text", reachText.String(), "at PACKAGE level", []string{"is REACHABLE", "but is NOT reachable"}},
		{"vuln-show --json", string(showJSON), `"reachability_state":"package_level_only"`, nil},
		{"vuln-show text", entryFor(showText.String(), id), "reachability: package_level_only", []string{"[reachable]", "[not reachable"}},
		{"context --json", string(ctxJSON), `"reachability_state":"package_level_only"`, nil},
		{"context text", ctxText.String(), "Reachability: package_level_only", nil},
	} {
		if !strings.Contains(c.body, c.states) {
			t.Errorf("%s does not state the answer (%s):\n%s", c.surface, c.states, c.body)
		}
		for _, d := range c.denies {
			if strings.Contains(c.body, d) {
				t.Errorf("%s still states %q for a package-level finding:\n%s", c.surface, d, c.body)
			}
		}
	}

	// The two record-shaped JSON surfaces publish the state under the same key
	// and the same word, so a consumer reading either gets one answer.
	showFinding := decodeFindings(t, showJSON)[id]
	var ctxDoc map[string]any
	if err := json.Unmarshal(ctxJSON, &ctxDoc); err != nil {
		t.Fatalf("decoding context finding: %v", err)
	}
	if showFinding["reachability_state"] != ctxDoc["reachability_state"] {
		t.Errorf("vuln-show says %v and context says %v for the same finding",
			showFinding["reachability_state"], ctxDoc["reachability_state"])
	}
}

// TestTheControlFindingsAreUnchanged is the control the fix owes: a genuinely
// reachable and a genuinely not-reachable finding answer exactly as they did,
// on every surface, apart from carrying the new key.
func TestTheControlFindingsAreUnchanged(t *testing.T) {
	rec := stateRecord()
	for id, want := range map[string]struct{ verdict, text string }{
		"GO-2026-0001": {verdictReachable, "is REACHABLE"},
		"GO-2026-0002": {verdictNotReachable, "but is NOT reachable"},
	} {
		res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, id, unclassifiedRoutes, nil)
		if err != nil {
			t.Fatalf("%s: vulnReachabilityVerdict: %v", id, err)
		}
		if res.ReachabilityState != want.verdict {
			t.Errorf("%s: verdict = %q, want %q", id, res.ReachabilityState, want.verdict)
		}
		var buf bytes.Buffer
		printVulnReachability(&buf, res)
		if !strings.Contains(buf.String(), want.text) {
			t.Errorf("%s: reachability text changed:\n%s", id, buf.String())
		}
	}

	// The stored bit is still on the wire beside the state, in both positions: it
	// is the record's own sealed field and removing it would say the record does
	// not carry it.
	raw, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	findings := decodeFindings(t, raw)
	for id, want := range map[string]bool{"GO-2026-0001": true, "GO-2026-0002": false} {
		r, ok := findings[id]["reachable"].(map[string]any)
		if !ok {
			t.Fatalf("%s: no reachable object on the wire: %s", id, raw)
		}
		if r["is_reachable"] != want {
			t.Errorf("%s: is_reachable = %v, want %v", id, r["is_reachable"], want)
		}
	}
}

// TestWithdrawnIsNotServedAsAReachabilityAnswer pins the fifth value on the
// record-shaped surfaces. A retracted advisory used to be tagged "[not
// reachable — inferred]" beside its retraction line, which offers reachability
// as the mitigation for a report that no longer stands.
func TestWithdrawnIsNotServedAsAReachabilityAnswer(t *testing.T) {
	rec := stateRecord()
	f := rec.Findings[1]
	f.ID = "GO-2026-0005"
	f.WithdrawnAt = rec.ScannedAt.AddDate(0, 0, -1).UTC()
	rec.Findings = []vuldomain.VulnerabilityFinding{f}

	raw, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	if got := decodeFindings(t, raw)["GO-2026-0005"]["reachability_state"]; got != "withdrawn" {
		t.Errorf("reachability_state = %v, want withdrawn", got)
	}

	var buf bytes.Buffer
	printVulnRecord(&buf, rec, nil)
	entry := entryFor(buf.String(), "GO-2026-0005")
	if strings.Contains(entry, "[not reachable") {
		t.Errorf("a retracted advisory is still tagged as a negative:\n%s", entry)
	}
	if !strings.Contains(entry, "reachability: withdrawn") {
		t.Errorf("the text form does not state the withdrawn state:\n%s", entry)
	}
}
