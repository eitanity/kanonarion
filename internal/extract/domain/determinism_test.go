package domain

import (
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/wireshape"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// TestExtractionRun_ContentHashIsIndependentOfInputOrder is the determinism
// guard for the extraction run.
//
// The run's per-module results and per-stage results are MAPS, so their order
// on the wire is decided by the canonical form and not by a producer; the one
// slice it carries, the requested stage names, is sorted there. The guard
// shuffles the slice, re-seals through map iteration many times, and enumerates
// the sealed shape so that a collection added later cannot go unshuffled.
func TestExtractionRun_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	// The walk is over the CANONICAL shape, not over ExtractionRun: the run
	// renders its own JSON through that shape, so the canonical struct is what
	// the seal is taken over. The two map-derived lists are ordered by the
	// canonical form itself, on the map key, which is the coordinate and the
	// stage name — an identity in both cases.
	want := map[string]bool{
		"requested_stages":            true,
		"per_module_results":          true,
		"per_module_results[].stages": true,
	}
	for _, path := range wireshape.Collections(t, reflect.TypeOf(canonicalExtractionRun{})) {
		if !want[path] {
			t.Errorf("ExtractionRun now carries the collection %q, whose order reaches its seal: "+
				"give it a total order in a named comparator and shuffle it here", path)
			continue
		}
		delete(want, path)
	}
	for path := range want {
		t.Errorf("the guard shuffles %q, which the sealed shape no longer carries", path)
	}

	var h ExtractionRunHasher
	var first string
	for i := range determinismShuffles {
		r := makeDeterminismRun(t)
		rng := rand.New(rand.NewSource(int64(i))) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		rng.Shuffle(len(r.RequestedStages), func(a, b int) {
			r.RequestedStages[a], r.RequestedStages[b] = r.RequestedStages[b], r.RequestedStages[a]
		})
		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("shuffle %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			first = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != first {
			t.Fatalf("shuffle %d: content hash %s, shuffle 0 gave %s: the canonical order is not a function of the run alone",
				i, sealed.ContentHash, first)
		}
	}
}

func makeDeterminismRun(t *testing.T) ExtractionRun {
	t.Helper()

	results := map[coordinate.ModuleCoordinate]ModuleExtractionResult{}
	for _, path := range []string{"example.com/a", "example.com/b", "example.com/c", "example.com/d", "example.com/e"} {
		coord, err := coordinate.NewModuleCoordinate(path, "v1.0.0")
		if err != nil {
			t.Fatalf("NewModuleCoordinate: %v", err)
		}
		results[coord] = ModuleExtractionResult{
			Coordinate: coord,
			Stages: map[string]StageResult{
				"iface":   {Status: StageSucceeded, RecordID: "r1"},
				"license": {Status: StageSucceeded, RecordID: "r2"},
				"example": {Status: StageSucceeded, RecordID: "r3"},
			},
		}
	}
	return ExtractionRun{
		SchemaVersion:    ExtractionRunSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		ID:               "run-1",
		WalkID:           "walk-1",
		RequestedStages:  []string{"iface", "license", "example"},
		PerModuleResults: results,
		StartedAt:        time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		CompletedAt:      time.Date(2026, 1, 15, 10, 1, 0, 0, time.UTC),
		PipelineVersions: map[string]string{"iface": "0.1.0", "license": "0.1.0"},
	}
}
