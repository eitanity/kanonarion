package cli

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// sectionKeys marshals a context section and returns the object it produced, so
// an assertion can be about the KEY's presence rather than only the decoded
// value. A field erased by `omitempty` is absent, and no assertion on a decoded
// zero can tell that apart from a build that never derived the field.
func sectionKeys(t *testing.T, section any) map[string]any {
	t.Helper()
	data, err := json.Marshal(section)
	if err != nil {
		t.Fatalf("marshalling section: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling section: %v", uerr)
	}
	return decoded
}

// requireKey fails when a key is absent, which is the failure this whole file
// exists for, and returns the value so the caller can check it too.
func requireKey(t *testing.T, obj map[string]any, key, why string) any {
	t.Helper()
	v, present := obj[key]
	if !present {
		t.Fatalf("%s is absent: %s", key, why)
	}
	return v
}

// composedFetchStore answers the one read the verification section makes,
// returning a record built by the production composer rather than a literal.
type composedFetchStore struct {
	rec   fetchdomain.CompositeRecord
	found bool
}

func (f composedFetchStore) ComposeFetchRecord(context.Context, coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error) {
	return f.rec, f.found, nil
}

// GetFetchRecord is the pipeline-pinned read, which this section never makes.
func (f composedFetchStore) GetFetchRecord(context.Context, coordinate.ModuleCoordinate, string) (fetchdomain.CompositeRecord, bool, error) {
	return f.rec, f.found, nil
}

// composedFetch composes a real fetch record for coord, retracted or not.
func composedFetch(t *testing.T, coord coordinate.ModuleCoordinate, retracted bool) composedFetchStore {
	t.Helper()
	rec, err := fetchdomain.Compose([]fetchdomain.FactRecord{{
		SchemaVersion:      fetchdomain.SchemaVersion,
		Ecosystem:          fetchdomain.EcosystemGo,
		ModulePath:         coord.Path(),
		ModuleVersion:      coord.Version(),
		ZipSHA256:          "0000000000000000000000000000000000000000000000000000000000000000",
		VerificationStatus: "VerifiedBySumDB",
		FetchedAt:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:    fetchapp.PipelineVersion,
		Retracted:          retracted,
	}})
	if err != nil {
		t.Fatalf("composing fetch record: %v", err)
	}
	return composedFetchStore{rec: rec, found: true}
}

// TestContextJSON_VerificationRetractedIsEmittedAtFalse pins the flag on a
// module its author has NOT withdrawn.
//
// The record either states a retraction or states there is none, and Status
// names the sections where no record could be read at all — so false is a
// measurement with a producer, and omitting it left "not retracted" and "this
// build does not report retractions" as the same document.
func TestContextJSON_VerificationRetractedIsEmittedAtFalse(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	keys := sectionKeys(t, buildVerification(context.Background(), coord, composedFetch(t, coord, false)))
	if got := requireKey(t, keys, "retracted",
		"a fetched module that was not withdrawn is a measurement, and the reader has no other field to read it from"); got != false {
		t.Errorf("retracted = %v on a live module, want false", got)
	}

	// Non-zero control: the same builder, over a record whose author did
	// withdraw the version. The value is read off the record, not written into
	// the section, so this fails if the section stops carrying the fact as well
	// as if the key is erased.
	got := sectionKeys(t, buildVerification(context.Background(), coord, composedFetch(t, coord, true)))
	if got["retracted"] != true {
		t.Errorf("retracted = %v on a withdrawn version, want true", got["retracted"])
	}
}

// walkForContext is a walk record of target holding the given direct
// dependencies, with partial set as asked.
func walkForContext(target string, partial bool, deps ...string) walkdomain.WalkRecord {
	coord := coordinatetest.MustNew(target, "v1.0.0")
	nodes := make([]walkdomain.GraphNode, 0, len(deps))
	for _, d := range deps {
		nodes = append(nodes, walkdomain.GraphNode{
			Coordinate:       coordinatetest.MustNew(d, "v0.1.0"),
			DirectDependency: true,
		})
	}
	return walkdomain.WalkRecord{
		ID:            "01WALKCONTEXT",
		Target:        coord,
		OverallStatus: walkdomain.WalkSucceeded,
		Graph:         walkdomain.Graph{Target: coord, Nodes: nodes, Partial: partial},
	}
}

// dependenciesSection runs the production builder over one walk.
func dependenciesSection(t *testing.T, rec walkdomain.WalkRecord) map[string]any {
	t.Helper()
	uc := testfakes.NewFakeQueryWalks()
	uc.AddWalk(rec)
	uc.SetSummaries([]walkports.WalkSummary{{ID: rec.ID, Target: rec.Target, OverallStatus: rec.OverallStatus}})
	return sectionKeys(t, buildDependencies(context.Background(), rec.Target, uc))
}

// TestContextJSON_DependencyCountAndPartialAreEmittedAtZero pins the pair on a
// module with no direct dependencies, resolved completely.
//
// Both are facts about a walk that ran: zero direct dependencies is a real
// property of a leaf module, and a graph that resolved every node is the
// ordinary case. Status carries the walks that never ran, so neither field
// needed a second way to say "unmeasured" — and both had one, by vanishing.
func TestContextJSON_DependencyCountAndPartialAreEmittedAtZero(t *testing.T) {
	leaf := dependenciesSection(t, walkForContext("example.com/leaf", false))
	if got := requireKey(t, leaf, "count",
		"a module with no direct dependencies still had its dependencies counted"); got.(float64) != 0 {
		t.Errorf("count = %v on a leaf module, want 0", got)
	}
	if got := requireKey(t, leaf, "partial",
		"a fully resolved graph is the answer 'nothing was left unresolved', not the absence of one"); got != false {
		t.Errorf("partial = %v on a complete walk, want false", got)
	}

	// Non-zero control: two direct dependencies, from a walk that left part of
	// the graph unresolved. Both values are derived from the record.
	rich := dependenciesSection(t, walkForContext("example.com/app", true, "example.com/a", "example.com/b"))
	if got := rich["count"]; got.(float64) != 2 {
		t.Errorf("count = %v, want 2", got)
	}
	if got := rich["partial"]; got != true {
		t.Errorf("partial = %v on a partial walk, want true", got)
	}
}

// TestContextJSON_LowConfidenceCoverageIsNullNotAbsent pins the licence
// fragment's coverage.
//
// This one is a pointer rather than a plain float, and the reason is the
// difference between it and the fields above: the fragment search runs only
// when the root licence could not be classified, so on a cleanly classified
// module there is genuinely no coverage to report. Null says that. A plain 0.0
// would claim a recognised fragment covering none of the file, which no
// measurement produces.
func TestContextJSON_LowConfidenceCoverageIsNullNotAbsent(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	classified := testfakes.NewFakeQueryLicense()
	classified.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: licdomain.LicenseStatusDetected,
		PrimarySPDX:   "MIT",
	})
	keys := sectionKeys(t, buildLicense(context.Background(), coord, classified))
	got := requireKey(t, keys, "low_confidence_coverage",
		"the key states whether a sub-threshold match was measured at all; absent, a consumer cannot tell a clean licence from a build that does not look for fragments")
	if got != nil {
		t.Errorf("low_confidence_coverage = %v on a confidently classified module, want null", got)
	}

	// Non-zero control: an unclassified module carrying a recognisable
	// fragment. The value comes from the licence record through the production
	// builder, which also picks the highest-coverage root match.
	unclassified := testfakes.NewFakeQueryLicense()
	unclassified.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: licdomain.LicenseStatusUnclassified,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", LowConfidenceSPDX: "AGPL-3.0-or-later", LowConfidenceCoverage: 0.0279},
		},
	})
	fragment := sectionKeys(t, buildLicense(context.Background(), coord, unclassified))
	if got := fragment["low_confidence_coverage"]; got == nil || got.(float64) != 0.0279 {
		t.Errorf("low_confidence_coverage = %v on a fragment match, want 0.0279", got)
	}
	if fragment["low_confidence_spdx"] != "AGPL-3.0-or-later" {
		t.Errorf("low_confidence_spdx = %v, want the fragment the coverage qualifies", fragment["low_confidence_spdx"])
	}
}

// callGraphFor builds a record with the nodes given, all in one package.
func callGraphFor(pkg string, exported ...string) cgdomain.CallGraphRecord {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	rec := cgdomain.CallGraphRecord{
		Coordinate:    coord,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
	}
	for _, sym := range exported {
		rec.Nodes = append(rec.Nodes, cgdomain.CallNode{
			ID: pkg + "." + sym, Package: pkg, Symbol: sym, IsExportedAPI: true,
		})
	}
	rec.NodeCount = len(rec.Nodes)
	return rec
}

// callGraphSection runs the production builder over one stored record.
func callGraphSection(t *testing.T, rec cgdomain.CallGraphRecord, pkgFilter string) map[string]any {
	t.Helper()
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(rec.Coordinate, cgapp.PipelineVersion, rec)
	return sectionKeys(t, buildCallGraph(context.Background(), rec.Coordinate, uc, false, pkgFilter))
}

// TestContextJSON_CallGraphCountsAreEmittedAtZero pins the three counts.
//
// node_count and edge_count describe the graph that was extracted, and an
// extraction that produced no nodes is a result the store really holds — this
// store held twelve such records when the class was measured. entry_point_count
// is the pointer of the three, because it answers a narrower question: how many
// exported entry points the ONE package --package named has. Without that flag
// no single count is derived at all, so null says "this run counted no single
// package" and 0 says "the package named has none".
func TestContextJSON_CallGraphCountsAreEmittedAtZero(t *testing.T) {
	empty := callGraphSection(t, callGraphFor("example.com/mod"), "")
	for _, key := range []string{"node_count", "edge_count"} {
		if got := requireKey(t, empty, key,
			"an extracted graph with nothing in it is a measurement about the module, not a gap in the report"); got.(float64) != 0 {
			t.Errorf("%s = %v on an empty graph, want 0", key, got)
		}
	}
	if got := requireKey(t, empty, "entry_point_count",
		"the key must state whether a single-package count was derived"); got != nil {
		t.Errorf("entry_point_count = %v on an unfiltered run, want null (entry_points_by_package carries the breakdown)", got)
	}

	// Zero under a filter: the package named exists and exports nothing. That
	// is a count of 0, and it is a different statement from the null above.
	rec := callGraphFor("example.com/mod/api", "Open", "Close")
	rec.Nodes = append(rec.Nodes, cgdomain.CallNode{
		ID: "example.com/mod/internal.helper", Package: "example.com/mod/internal", Symbol: "helper",
	})
	rec.NodeCount = len(rec.Nodes)
	filteredEmpty := callGraphSection(t, rec, "example.com/mod/internal")
	if got := requireKey(t, filteredEmpty, "entry_point_count",
		"a named package that exports nothing was counted, and the count is zero"); got.(float64) != 0 {
		t.Errorf("entry_point_count = %v for a package with no exported API, want 0", got)
	}

	// Non-zero control: the same graph, filtered to the package that does
	// export. The count is derived by the builder from the record's nodes.
	filtered := callGraphSection(t, rec, "example.com/mod/api")
	if got := filtered["entry_point_count"]; got == nil || got.(float64) != 2 {
		t.Errorf("entry_point_count = %v for a package exporting two symbols, want 2", got)
	}
	if got := filtered["node_count"]; got.(float64) != 2 {
		t.Errorf("node_count = %v under --package, want the filtered count 2", got)
	}
}

// TestContextJSON_ExampleCountIsEmittedAtZero pins the harvest tally.
//
// A module that was harvested and has no Example functions is a fact about the
// module. Status says when nothing was harvested at all, so the count needed no
// second encoding of absence.
func TestContextJSON_ExampleCountIsEmittedAtZero(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	none := testfakes.NewFakeQueryExamples()
	none.AddRecord(coord, exapp.PipelineVersion, exdomain.ExampleRecord{
		Coordinate:    coord,
		OverallStatus: exdomain.ExampleStatusNone,
	})
	keys := sectionKeys(t, buildExamples(context.Background(), coord, none, true, ""))
	if got := requireKey(t, keys, "count",
		"a harvested module with no examples is a measurement; absent, it reads as a build that does not harvest"); got.(float64) != 0 {
		t.Errorf("count = %v on a module with no examples, want 0", got)
	}

	// Non-zero control: two harvested examples, counted by the builder after
	// its own package filtering rather than written into the section.
	some := testfakes.NewFakeQueryExamples()
	some.AddRecord(coord, exapp.PipelineVersion, exdomain.ExampleRecord{
		Coordinate:    coord,
		OverallStatus: exdomain.ExampleStatusFound,
		Examples: []exdomain.ExampleEntry{
			{Name: "ExampleOpen", Body: "Open()"},
			{Name: "ExampleClose", Body: "Close()"},
		},
	})
	got := sectionKeys(t, buildExamples(context.Background(), coord, some, true, ""))
	if got["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", got["count"])
	}
}

// vulnSection renders a vulnerability record through the production projection.
func vulnSection(t *testing.T, rec vuldomain.VulnerabilityRecord) map[string]any {
	t.Helper()
	return sectionKeys(t, vulnRecordToContext(&rec, "", ""))
}

// snapshotAt is a database snapshot retrieved at the time given.
func snapshotAt(t *testing.T, at time.Time) vuldomain.DatabaseSnapshot {
	t.Helper()
	snap, err := vuldomain.NewDatabaseSnapshot("osv.dev", "2026-08-14", at, "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return snap
}

// TestContextJSON_SnapshotAgeDaysIsEmittedAtZero pins the freshness figure.
//
// A verdict validated against a snapshot pulled the same day measures zero days
// of age — the best answer this field can carry — and omitting it reported the
// freshest record in the store as having no age at all. It is a pointer because
// a record whose snapshot carries no retrieval time yields no age, and a plain 0
// there would report an undated snapshot as same-day fresh.
func TestContextJSON_SnapshotAgeDaysIsEmittedAtZero(t *testing.T) {
	scanned := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	sameDay := vulnSection(t, vuldomain.VulnerabilityRecord{
		OverallStatus:    vuldomain.StatusClean,
		ScannedAt:        scanned,
		DatabaseSnapshot: snapshotAt(t, scanned.Add(-2*time.Hour)),
	})
	if got := requireKey(t, sameDay, "snapshot_age_days",
		"a same-day snapshot is the freshest measurement this field reports, and it was the one being erased"); got.(float64) != 0 {
		t.Errorf("snapshot_age_days = %v for a snapshot pulled the same day, want 0", got)
	}
	if _, present := sameDay["snapshot_retrieved_at"]; !present {
		t.Error("snapshot_retrieved_at is absent beside an age of 0; the pair must not disagree about whether a snapshot was dated")
	}

	// Non-zero control: the same projection, over a snapshot pulled nine days
	// before validation. The number is computed by vuldomain.SnapshotAgeDays.
	stale := vulnSection(t, vuldomain.VulnerabilityRecord{
		OverallStatus:    vuldomain.StatusClean,
		ScannedAt:        scanned,
		DatabaseSnapshot: snapshotAt(t, scanned.AddDate(0, 0, -9)),
	})
	if got := stale["snapshot_age_days"]; got == nil || got.(float64) != 9 {
		t.Errorf("snapshot_age_days = %v for a nine-day-old snapshot, want 9", got)
	}

	// Null control: a record with no snapshot at all. The key is still present,
	// and null is the answer — this is why the field is a pointer.
	undated := vulnSection(t, vuldomain.VulnerabilityRecord{OverallStatus: vuldomain.StatusClean, ScannedAt: scanned})
	if got := requireKey(t, undated, "snapshot_age_days",
		"a record with no snapshot must still state that it has no age"); got != nil {
		t.Errorf("snapshot_age_days = %v with no snapshot, want null", got)
	}
}

// TestContextJSON_FindingScoreAndReachableStateTheirAbsence pins the two
// three-valued fields on a finding.
//
// Score is a pointer because advisories genuinely publish no severity, and 0.0
// is itself a severity — the lowest one — so the two cannot share an encoding.
// Reachable was already a pointer and still carried `omitempty`, which erased
// exactly the state the pointer exists to express: a finding no reachability
// analysis answered. Soundness cannot stand in for it, because it reads
// "not stated" for a positive verdict too.
func TestContextJSON_FindingScoreAndReachableStateTheirAbsence(t *testing.T) {
	bare := vulnSection(t, vuldomain.VulnerabilityRecord{
		OverallStatus: vuldomain.StatusAffected,
		ScannedAt:     time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC),
		Findings:      []vuldomain.VulnerabilityFinding{{ID: "GO-2026-0001", Summary: "a flaw"}},
	})
	findings, ok := bare["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %v, want one finding", bare["findings"])
	}
	finding := findings[0].(map[string]any)
	if got := requireKey(t, finding, "score",
		"an advisory publishing no severity must say so; absent, it reads as a build that does not report severities"); got != nil {
		t.Errorf("score = %v on an advisory with no severity, want null", got)
	}
	if got := requireKey(t, finding, "reachable",
		"a finding no reachability analysis answered is the state this pointer exists for, and omitempty erased it"); got != nil {
		t.Errorf("reachable = %v on an unanalysed finding, want null", got)
	}

	// Non-zero controls: a scored advisory, one measured reachable and one
	// measured NOT reachable. Both values are read off the record.
	scored := vulnSection(t, vuldomain.VulnerabilityRecord{
		OverallStatus: vuldomain.StatusAffected,
		ScannedAt:     time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC),
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:        "GO-2026-0002",
				Severity:  &vuldomain.Severity{Score: 9.8, Label: "CRITICAL"},
				Reachable: &vuldomain.ReachabilityResult{IsReachable: true, Confidence: vuldomain.ConfidenceHigh},
			},
			{
				ID:        "GO-2026-0003",
				Severity:  &vuldomain.Severity{Score: 0, Label: "NONE"},
				Reachable: &vuldomain.ReachabilityResult{IsReachable: false, Confidence: vuldomain.ConfidenceHigh},
			},
		},
	})
	rows := scored["findings"].([]any)
	if len(rows) != 2 {
		t.Fatalf("findings = %d, want 2", len(rows))
	}
	high := rows[0].(map[string]any)
	if got := high["score"]; got == nil || got.(float64) != 9.8 {
		t.Errorf("score = %v, want 9.8", got)
	}
	if got := high["reachable"]; got != true {
		t.Errorf("reachable = %v on a reachable finding, want true", got)
	}
	// A published severity of 0.0 is the case a plain float could never tell
	// from an advisory with no severity at all.
	none := rows[1].(map[string]any)
	if got := requireKey(t, none, "score", "a published severity of 0.0 is a score"); got == nil || got.(float64) != 0 {
		t.Errorf("score = %v for a published 0.0 severity, want 0", got)
	}
	if got := none["reachable"]; got != false {
		t.Errorf("reachable = %v on a finding measured not reachable, want false", got)
	}
}
