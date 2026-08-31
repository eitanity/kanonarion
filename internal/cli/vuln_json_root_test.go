package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// This file pins the second half of the rule reachability_rung_surfaces_test.go
// states for the rung: a record-shaped JSON surface must publish the route's
// root classification too, in the same shape and under the same key the
// single-advisory query publishes it, because vuln-show's TEXT form has printed
// the kind, the caller count, the entry-point ancestry and the weakest edge on
// that path all along. A machine reading the same command's --json saw none of
// it, so a route beginning three hops under main and one beginning at the node
// the analyser stopped at were the same bytes.

// classifiedRecord is a record holding the three finding shapes the projection
// must tell apart: a reachable finding WITH a route, a reachable finding with
// none, and a negative. Only the first has a root to classify.
func classifiedRecord() vuldomain.VulnerabilityRecord {
	derived := vuldomain.ReachabilityDerivation{
		Analyser: vuldomain.AnalyserGovulncheck,
		Fidelity: "source",
	}
	return vuldomain.VulnerabilityRecord{
		Coordinate:     coordinatetest.MustNew("example.com/dep", "v1.2.0"),
		Rooting:        vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
		OverallStatus:  vuldomain.StatusAffected,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordAffected,
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:      "GO-2026-0001",
				Summary: "reachable, with a route",
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: true,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy:   derived,
					Routes: []vuldomain.ReachabilityRoute{{
						{ModulePath: "example.com/app", Package: "example.com/app/handlers", Receiver: "*Server", Symbol: "Serve"},
						{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
					}},
				},
			},
			{
				ID:                     "GO-2026-0002",
				Summary:                "affected at package level, no route recorded",
				AdvisoryNamesNoSymbols: true,
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: true,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy:   derived,
				},
			},
			{
				ID:      "GO-2026-0003",
				Summary: "not reachable",
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: false,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy:   derived,
				},
			},
		},
	}
}

// classifiedRoot is the classification the fixture's classifier answers: an
// internal root three hops under main, reached over a reference edge whose
// weakest confidence is Unknown. It is the shape an operator most needs from
// the JSON, because every part of it qualifies the verdict.
func classifiedRoot() vuldomain.RouteRoot {
	return vuldomain.RouteRoot{
		Kind:   vuldomain.RootInternal,
		Reason: "called from within the analysed module (14 callers), so the route begins where the analyser stopped, not where execution starts",
		NodeID: "example.com/app/handlers.(*Server).Serve",
		Remedy: "kanonarion callers 'example.com/app/handlers.(*Server).Serve', to walk the hops above the route",
		Ancestry: vuldomain.EntryPointAncestry{
			Computed:         true,
			Found:            true,
			Hops:             3,
			EntryPointID:     "example.com/app.main",
			EntryPointReason: "the process entry point — the runtime invokes it",
			Weakest:          "Unknown",
			ViaReference:     true,
		},
	}
}

// bindAs is the record binder for a fixed classification, standing in for the
// one that reads the stored call graphs.
func bindAs(root vuldomain.RouteRoot) recordRootFunc {
	return func(vuldomain.VulnerabilityRecord) routeRootFunc { return classifyAs(root) }
}

// TestRecordJSONCarriesTheRouteRoot is the ticket's observable. Every
// record-shaped surface — vuln-show, vuln-show --history, vuln-by-id,
// vuln-scan-show --json — encodes a record through this projection, and a routed
// finding must publish the root its own text form prints.
func TestRecordJSONCarriesTheRouteRoot(t *testing.T) {
	raw, err := json.Marshal(toVulnRecordJSON(classifiedRecord(), bindAs(classifiedRoot())))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	findings := decodeFindings(t, raw)

	routed, ok := findings["GO-2026-0001"]
	if !ok {
		t.Fatalf("the routed finding is absent from the projection: %s", raw)
	}
	root, ok := routed["route_root"].(map[string]any)
	if !ok {
		t.Fatalf("the routed finding published route_root = %v, want the classification: %s", routed["route_root"], raw)
	}
	for key, want := range map[string]any{
		"kind":    "internal",
		"reason":  classifiedRoot().Reason,
		"node_id": classifiedRoot().NodeID,
		"remedy":  classifiedRoot().Remedy,
	} {
		if root[key] != want {
			t.Errorf("route_root[%q] = %v, want %v", key, root[key], want)
		}
	}

	// The ancestry is what turns the root into a distance. Without it the JSON
	// states where the route begins and not how far below an entry point that is,
	// which is the reading the text form gives and the machine did not.
	ancestry, ok := root["entry_point_ancestry"].(map[string]any)
	if !ok {
		t.Fatalf("route_root carries no entry_point_ancestry: %s", raw)
	}
	for key, want := range map[string]any{
		"found":              true,
		"hops":               float64(3),
		"entry_point_id":     "example.com/app.main",
		"weakest_confidence": "Unknown",
		"via_reference":      true,
		"search_bound":       float64(0),
	} {
		if ancestry[key] != want {
			t.Errorf("entry_point_ancestry[%q] = %v, want %v", key, ancestry[key], want)
		}
	}
}

// TestRecordJSONStatesTheAbsentRootAsNull pins the absent-versus-null rule. A
// finding with no route has no root to classify, and it says so with a null the
// consumer can read — never by dropping the key, which is the producer's
// statement that it does not derive the root at all.
func TestRecordJSONStatesTheAbsentRootAsNull(t *testing.T) {
	raw, err := json.Marshal(toVulnRecordJSON(classifiedRecord(), bindAs(classifiedRoot())))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	findings := decodeFindings(t, raw)

	for _, id := range []string{"GO-2026-0002", "GO-2026-0003"} {
		f, ok := findings[id]
		if !ok {
			t.Fatalf("finding %s is absent from the projection: %s", id, raw)
		}
		root, present := f["route_root"]
		if !present {
			t.Errorf("%s: no route_root key — a routeless finding is indistinguishable from a producer that never derives the root", id)
			continue
		}
		if root != nil {
			t.Errorf("%s: route_root = %v, want null — the finding records no route to classify", id, root)
		}
	}
}

// TestRecordJSONRouteRootMatchesTheSingleAdvisoryQuery is the anti-drift guard.
// Two renderers computing one classification is how they drift apart, so the
// record projection and 'reachability --json' must put the SAME bytes on the
// wire for the same route and the same classification — same key, same field
// names, same nesting.
func TestRecordJSONRouteRootMatchesTheSingleAdvisoryQuery(t *testing.T) {
	rec := classifiedRecord()
	root := classifiedRoot()

	recordRaw, err := json.Marshal(toVulnRecordJSON(rec, bindAs(root)))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	fromRecord := reserialise(t, decodeFindings(t, recordRaw)["GO-2026-0001"]["route_root"])

	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2026-0001", classifyAs(root), nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	fromQuery := reserialise(t, res.RouteRoot)

	if fromRecord != fromQuery {
		t.Errorf("the two surfaces disagree about one classification:\n  vuln-show:    %s\n  reachability: %s", fromRecord, fromQuery)
	}
}

// reserialise renders a value as JSON and back through a map, so two documents
// are compared on the keys and values they carry rather than on the order a
// struct's fields happen to be declared in.
func reserialise(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling %T: %v", v, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding %T: %v", v, err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshalling %T: %v", v, err)
	}
	return string(out)
}

// TestScanDiffLeavesTheRouteRootOff pins the reasoned exception. A diff delta
// carries a coordinate and no analysis frame, and the frame is what decides
// whether a route is closure-rooted — so the diff publishes no root rather than
// one computed against a frame it had to guess, which would contradict the root
// vuln-show prints for the same finding. The missing key is the true statement:
// this producer does not derive it.
func TestScanDiffLeavesTheRouteRootOff(t *testing.T) {
	rec := classifiedRecord()
	diff := vuldomain.ScanRunDiff{
		NewFindings: []vuldomain.FindingDelta{{Coordinate: rec.Coordinate, Finding: rec.Findings[0]}},
	}
	raw, err := json.Marshal(newScanRunDiffDocument(diff))
	if err != nil {
		t.Fatalf("marshalling scan diff: %v", err)
	}
	var doc struct {
		NewFindings []struct {
			Finding map[string]any `json:"finding"`
		} `json:"new_findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding scan diff: %v", err)
	}
	if len(doc.NewFindings) != 1 {
		t.Fatalf("diff projected %d delta(s), want 1: %s", len(doc.NewFindings), raw)
	}
	if _, present := doc.NewFindings[0].Finding["route_root"]; present {
		t.Errorf("the diff published a route root it has no frame to compute: %s", raw)
	}
	// It still owes the rung, which needs no frame.
	if doc.NewFindings[0].Finding["soundness"] == nil {
		t.Errorf("the diff dropped the rung along with the root: %s", raw)
	}
}

// TestRecordListClassifiesEachRecordInItsOwnFrame pins the per-record binding. A
// history spans generations and vuln-by-id spans projects, so the binder is
// asked per record rather than once for the list: classifying the second record
// against the first's rooting would report a closure-rooted route as a
// project-rooted one.
func TestRecordListClassifiesEachRecordInItsOwnFrame(t *testing.T) {
	first := classifiedRecord()
	second := classifiedRecord()
	second.Rooting = vuldomain.RootingIsolated

	var seen []vuldomain.Rooting
	bind := func(rec vuldomain.VulnerabilityRecord) routeRootFunc {
		seen = append(seen, vuldomain.RecordRooting(rec))
		return classifyAs(classifiedRoot())
	}

	if _, err := json.Marshal(toVulnRecordsJSON([]vuldomain.VulnerabilityRecord{first, second}, bind)); err != nil {
		t.Fatalf("marshalling projected records: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("the binder was asked %d time(s) for 2 records: %v", len(seen), seen)
	}
	if seen[0] == seen[1] {
		t.Errorf("both records were classified in one frame (%s); each states its own", seen[0])
	}
}

// countingGraphs counts the ledger reads a projection provokes, so "the decode
// is triggered by a route" is asserted rather than timed. Timing cannot settle
// it: the store is larger than this machine's page cache, so the same command
// varies by more than a graph decode costs.
type countingGraphs struct {
	*testfakes.FakeQueryCallGraph
	reads int
}

func (c *countingGraphs) GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgdomain.CallGraphRecord, bool, error) {
	c.reads++
	rec, found, err := c.FakeQueryCallGraph.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return cgdomain.CallGraphRecord{}, false, fmt.Errorf("counting graph reader: %w", err)
	}
	return rec, found, nil
}

// TestRoutelessRecordNeverOpensTheLedger pins the cost rule. A finding with no
// route has no root to classify and no graph could change its null, so a record
// whose findings are all routeless must not read the call-graph ledger at all —
// the decode is owed to a route, not to a record being projected.
func TestRoutelessRecordNeverOpensTheLedger(t *testing.T) {
	rec := classifiedRecord()
	rec.Findings = rec.Findings[1:] // the two routeless findings

	graphs := &countingGraphs{FakeQueryCallGraph: testfakes.NewFakeQueryCallGraph()}
	raw, err := json.Marshal(toVulnRecordJSON(rec, newRecordRootFunc(t.Context(), graphs)))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	if graphs.reads != 0 {
		t.Errorf("a routeless record read the call-graph ledger %d time(s); the decode is owed to a route", graphs.reads)
	}
	for id, f := range decodeFindings(t, raw) {
		if root, present := f["route_root"]; !present || root != nil {
			t.Errorf("%s: route_root = %v (present %v), want an emitted null", id, root, present)
		}
	}
}

// TestRoutedRecordsShareOneLedgerRead pins the other half: a route does provoke
// the read, and a list of records rooted in one frame pays it once. The cache
// lives for the command, so a hundred findings of one project cost one decode.
func TestRoutedRecordsShareOneLedgerRead(t *testing.T) {
	graphs := &countingGraphs{FakeQueryCallGraph: testfakes.NewFakeQueryCallGraph()}
	recs := []vuldomain.VulnerabilityRecord{classifiedRecord(), classifiedRecord()}
	if _, err := json.Marshal(toVulnRecordsJSON(recs, newRecordRootFunc(t.Context(), graphs))); err != nil {
		t.Fatalf("marshalling projected records: %v", err)
	}
	if graphs.reads != 1 {
		t.Errorf("two routed records rooted in one frame provoked %d ledger read(s), want 1", graphs.reads)
	}
}
