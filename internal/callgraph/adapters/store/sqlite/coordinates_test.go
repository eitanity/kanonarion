package sqlite_test

import (
	"context"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// coordinateOf finds the listed entry for one module path, or fails.
func coordinateOf(t *testing.T, coords []ports.CallGraphCoordinate, path string) ports.CallGraphCoordinate {
	t.Helper()
	for _, c := range coords {
		if c.ModulePath == path {
			return c
		}
	}
	t.Fatalf("no coordinate listed for %q; listed %v", path, coords)
	return ports.CallGraphCoordinate{}
}

// TestCoordinates_OneEntryPerCoordinateWhateverTheHistory is the shape the
// listing promises: the ledger's keys, collapsed, whatever the ledger holds
// under each of them.
func TestCoordinates_OneEntryPerCoordinateWhateverTheHistory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for i, at := range []time.Time{testTime, testTime.Add(time.Hour), testTime.Add(2 * time.Hour)} {
		rec := ledgerRecord(t, ledgerSpec{
			source:       domain2.AnalysisSourceModuleZip,
			completeness: domain2.CompletenessBuiltWithBodies,
			artefact:     "zip:h1:gen",
			at:           at,
			callee:       "example.com/mod.Callee" + string(rune('A'+i)),
		})
		if err := s.PutCallGraphRecord(ctx, rec); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}

	coords, err := s.ListCallGraphCoordinates(ctx, ports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphCoordinates: %v", err)
	}
	if len(coords) != 1 {
		t.Fatalf("coordinates = %d, want 1 (three generations of one coordinate)", len(coords))
	}
	got := coords[0]
	if got.ModulePath != testCoord.Path() || got.ModuleVersion != testCoord.Version() || got.PipelineVersion != testPipeline {
		t.Errorf("coordinate = %s@%s at %s, want %s at %s",
			got.ModulePath, got.ModuleVersion, got.PipelineVersion, testCoord, testPipeline)
	}
}

// TestCoordinates_FlagsAreTrueWhenAnyGenerationStatesTheCondition is the whole
// safety of the two flags.
//
// They are read without composing, so they cannot name the generation
// composition serves. What they can prove is a negative: the served record is
// one of the generations, so a coordinate where none states the condition
// cannot serve one that does, and a reader may skip the record entirely. This
// pins the one-way direction — a Partial generation that is NOT the served one
// still raises the flag.
func TestCoordinates_FlagsAreTrueWhenAnyGenerationStatesTheCondition(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	partialCoord, err := coordinate.NewModuleCoordinate("example.com/partial", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	// The served generation: built with bodies, and clean. The one behind it in
	// the ladder is Partial and metadata-only.
	served := ledgerRecord(t, ledgerSpec{
		coord: partialCoord, source: domain2.AnalysisSourceModuleZip,
		completeness: domain2.CompletenessBuiltWithBodies,
		artefact:     "zip:h1:partial", at: testTime.Add(time.Hour),
	})
	behind := ledgerRecord(t, ledgerSpec{
		coord: partialCoord, source: domain2.AnalysisSourceModuleZip,
		completeness: domain2.CompletenessMetadataOnly,
		artefact:     "zip:h1:partial", at: testTime,
		status: domain2.CallGraphStatusPartial, callee: "example.com/partial.Other",
	})
	clean := ledgerRecord(t, ledgerSpec{
		source:       domain2.AnalysisSourceModuleZip,
		completeness: domain2.CompletenessBuiltWithBodies,
		artefact:     "zip:h1:clean",
	})
	for _, rec := range []domain2.CallGraphRecord{behind, served, clean} {
		if perr := s.PutCallGraphRecord(ctx, rec); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	coords, err := s.ListCallGraphCoordinates(ctx, ports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphCoordinates: %v", err)
	}
	p := coordinateOf(t, coords, "example.com/partial")
	if !p.AnyPartial {
		t.Error("AnyPartial = false for a coordinate holding a Partial generation, want true")
	}
	if !p.AnyBelowFull {
		t.Error("AnyBelowFull = false for a coordinate holding a METADATA_ONLY generation, want true")
	}
	// The composed read still serves the built graph: the flags said "you must
	// look", not "the answer is Partial".
	rec, found, err := s.GetCallGraphRecord(ctx, partialCoord, testPipeline)
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: %v, found=%t", err, found)
	}
	if rec.OverallStatus == domain2.CallGraphStatusPartial {
		t.Error("served record is Partial; the flag would then be the answer rather than a gate")
	}

	c := coordinateOf(t, coords, testCoord.Path())
	if c.AnyPartial || c.AnyBelowFull {
		t.Errorf("clean coordinate flags = {partial:%t belowFull:%t}, want both false — "+
			"a false flag is what lets a reader skip the record",
			c.AnyPartial, c.AnyBelowFull)
	}
}

// TestCoordinates_FilterAndPagingMatchTheSummaryListing keeps the two listings
// answering the same question about which rows are in view. A caller that swaps
// one for the other must not silently change what it sees.
func TestCoordinates_FilterAndPagingMatchTheSummaryListing(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	paths := []string{"example.com/a", "example.com/b", "example.com/c"}
	for i, p := range paths {
		coord, err := coordinate.NewModuleCoordinate(p, "v1.0.0")
		if err != nil {
			t.Fatalf("NewModuleCoordinate: %v", err)
		}
		rec := ledgerRecord(t, ledgerSpec{
			coord: coord, source: domain2.AnalysisSourceModuleZip,
			completeness: domain2.CompletenessBuiltWithBodies,
			artefact:     "zip:h1:" + p, at: testTime.Add(time.Duration(i) * time.Hour),
		})
		if err := s.PutCallGraphRecord(ctx, rec); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}

	for _, filter := range []ports.CallGraphFilter{
		{},
		{ModulePath: "example.com/b"},
		{PipelineVersion: testPipeline},
		{PipelineVersion: "no-such-pipeline"},
		{AnalysisSource: domain2.AnalysisSourceWorktree},
		{Limit: 2},
		{Offset: 1},
		{Limit: 1, Offset: 2},
		{Offset: 99},
	} {
		sums, err := s.ListCallGraphRecords(ctx, filter)
		if err != nil {
			t.Fatalf("ListCallGraphRecords(%+v): %v", filter, err)
		}
		coords, err := s.ListCallGraphCoordinates(ctx, filter)
		if err != nil {
			t.Fatalf("ListCallGraphCoordinates(%+v): %v", filter, err)
		}
		if len(sums) != len(coords) {
			t.Fatalf("filter %+v: %d summaries but %d coordinates", filter, len(sums), len(coords))
		}
		for i := range sums {
			if sums[i].ModulePath != coords[i].ModulePath ||
				sums[i].ModuleVersion != coords[i].ModuleVersion ||
				sums[i].PipelineVersion != coords[i].PipelineVersion {
				t.Errorf("filter %+v, entry %d: summary %s@%s/%s, coordinate %s@%s/%s",
					filter, i,
					sums[i].ModulePath, sums[i].ModuleVersion, sums[i].PipelineVersion,
					coords[i].ModulePath, coords[i].ModuleVersion, coords[i].PipelineVersion)
			}
		}
	}
}

// TestWorktreeRouting_SingleCheckoutReadsNoRecord: a coordinate with one
// analysed tree, read from outside it, has no routing decision for anyone to
// see — and establishing the served generation's root and digest, which nothing
// will render, costs a blob decode plus a reconstruction of the module's whole
// edge set on every text-mode edge query.
//
// The counts are still reported, because they are what decides there is nothing
// to see. WorthReporting is false on what comes back, which is what tells a
// caller the served fields were not established.
func TestWorktreeRouting_SingleCheckoutReadsNoRecord(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	if perr := s.PutCallGraphRecord(ctx, ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree, worktree: "analysed-sha256:a1",
		root: "/src/a/mod", completeness: domain2.CompletenessBuiltWithBodies,
	})); perr != nil {
		t.Fatalf("PutCallGraphRecord: %v", perr)
	}

	r, ok, err := s.WorktreeRouting(ctx, local, testPipeline)
	if err != nil || !ok {
		t.Fatalf("WorktreeRouting: ok=%v err=%v", ok, err)
	}
	if r.LocatedTrees != 1 || r.UnlocatedGenerations != 0 {
		t.Errorf("counts = %d located / %d unlocated, want 1 / 0", r.LocatedTrees, r.UnlocatedGenerations)
	}
	if r.WorthReporting() {
		t.Fatal("one tree, reader outside it: WorthReporting = true, so the notice would render unestablished fields")
	}

	// Standing in the tree makes the decision reportable, and then the served
	// generation IS read — the short circuit must not swallow the case the
	// routing notice exists for.
	s.PreferWorktree(ports.WorktreePreference{ModulePath: "example.com/mod", Root: "/src/a/mod"})
	r, ok, err = s.WorktreeRouting(ctx, local, testPipeline)
	if err != nil || !ok {
		t.Fatalf("WorktreeRouting: ok=%v err=%v", ok, err)
	}
	if r.ServedRoot != "/src/a/mod" || !r.Matched {
		t.Errorf("routing report = %+v, want the served generation read and matched at /src/a/mod", r)
	}
}
