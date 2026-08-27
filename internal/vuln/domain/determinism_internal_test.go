package domain

import (
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; the forward/reversed pair beside this
// one covers two, and two can agree by luck.
const determinismShuffles = 50

// TestVulnerabilityRecord_ContentHashIsIndependentOfInputOrder is the
// determinism guard for the vulnerability record. Its collections were
// canonicalised when the arrangement defect was measured on the store; this
// states the property they were canonicalised for, in the form every hashed
// record type in the repo now states it.
func TestVulnerabilityRecord_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h VulnerabilityRecordHasher
	var want string
	for i := range determinismShuffles {
		r := permutedRecord(t, false)
		shuffleVulnerabilityRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("shuffle %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			want = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != want {
			t.Fatalf("shuffle %d: content hash %s, shuffle 0 gave %s: the canonical order is not a function of the record alone",
				i, sealed.ContentHash, want)
		}
	}
}

// shuffleVulnerabilityRecord permutes every collection the sealed shape
// classifies as a SET. The hops inside one route are deliberately left alone:
// SealedCollections classifies them OrderByMeaning because a route is a call
// stack, and shuffling them would be shuffling the fact.
func shuffleVulnerabilityRecord(rng *rand.Rand, r *VulnerabilityRecord) {
	rng.Shuffle(len(r.Findings), func(i, j int) { r.Findings[i], r.Findings[j] = r.Findings[j], r.Findings[i] })
	for i := range r.Findings {
		f := &r.Findings[i]
		rng.Shuffle(len(f.AffectedSymbols), func(a, b int) {
			f.AffectedSymbols[a], f.AffectedSymbols[b] = f.AffectedSymbols[b], f.AffectedSymbols[a]
		})
		rng.Shuffle(len(f.Aliases), func(a, b int) { f.Aliases[a], f.Aliases[b] = f.Aliases[b], f.Aliases[a] })
		rng.Shuffle(len(f.References), func(a, b int) { f.References[a], f.References[b] = f.References[b], f.References[a] })
		if f.Reachable != nil {
			rt := f.Reachable.Routes
			rng.Shuffle(len(rt), func(a, b int) { rt[a], rt[b] = rt[b], rt[a] })
		}
	}
}

// TestWalkScanRun_ContentHashIsIndependentOfInputOrder is the determinism guard
// for the walk scan run. The run carries a map and no slice, so it has no
// arrangement to canonicalise; this states that, by sealing it repeatedly — map
// iteration order differs between range statements, so a leak would show — and
// by enumerating the sealed shape so that adding a collection fails here.
func TestWalkScanRun_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	found := map[string]bool{}
	walkWireShape(t, reflect.TypeOf(WalkScanRun{}), "", found)
	for path := range found {
		t.Errorf("WalkScanRun now carries the collection %q, whose order reaches its seal: "+
			"canonicalise it and shuffle it here, as VulnerabilityRecord's are", path)
	}

	var h WalkScanRunHasher
	var want string
	for i := range determinismShuffles {
		sealed, err := h.SetContentHash(makeWalkScanRun(t))
		if err != nil {
			t.Fatalf("seal %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			want = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != want {
			t.Fatalf("seal %d: content hash %s, seal 0 gave %s: the seal is not a function of the run alone",
				i, sealed.ContentHash, want)
		}
	}
}

// makeWalkScanRun builds a run whose per-module map holds several coordinates,
// so map iteration order has something to vary.
func makeWalkScanRun(t *testing.T) WalkScanRun {
	t.Helper()

	snapshot, err := NewDatabaseSnapshot("vuln.go.dev", "2026-07-27", time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatalf("NewDatabaseSnapshot: %v", err)
	}
	results := map[coordinate.ModuleCoordinate]string{}
	for _, path := range []string{"example.com/a", "example.com/b", "example.com/c", "example.com/d", "example.com/e"} {
		coord, err := coordinate.NewModuleCoordinate(path, "v1.0.0")
		if err != nil {
			t.Fatalf("NewModuleCoordinate: %v", err)
		}
		results[coord] = "sha256:" + path
	}
	return WalkScanRun{
		ID:               "01KZMJBYXA5RJZZYJW2HQ31KE8",
		WalkID:           "01KZMJBYXA5RJZZYJW2HQ31KE9",
		Snapshot:         snapshot,
		PerModuleResults: results,
		StartedAt:        time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC),
		CompletedAt:      time.Date(2026, 8, 11, 9, 1, 0, 0, time.UTC),
		PipelineVersion:  "vuln-v1",
	}
}

// TestToolchainAdvisoryLess_IsKeyedOnEveryField exercises the toolchain
// advisory comparator against every field an advisory carries. It was keyed on
// the identifier alone.
func TestToolchainAdvisoryLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		key          string
		lower, upper ToolchainAdvisory
	}{
		{"id", ToolchainAdvisory{ID: "GO-1"}, ToolchainAdvisory{ID: "GO-2"}},
		{"summary", ToolchainAdvisory{Summary: "a"}, ToolchainAdvisory{Summary: "b"}},
		{"withdrawn_at", ToolchainAdvisory{WithdrawnAt: early}, ToolchainAdvisory{WithdrawnAt: late}},
		{"ranges count", ToolchainAdvisory{}, ToolchainAdvisory{Ranges: []ToolchainRange{{Introduced: "v1"}}}},
		{"ranges introduced",
			ToolchainAdvisory{Ranges: []ToolchainRange{{Introduced: "v1"}}},
			ToolchainAdvisory{Ranges: []ToolchainRange{{Introduced: "v2"}}}},
		{"ranges fixed",
			ToolchainAdvisory{Ranges: []ToolchainRange{{Fixed: "v1"}}},
			ToolchainAdvisory{Ranges: []ToolchainRange{{Fixed: "v2"}}}},
	}
	for _, tc := range cases {
		if !ToolchainAdvisoryLess(tc.lower, tc.upper) {
			t.Errorf("%s: the comparator does not order two advisories differing only in this field", tc.key)
		}
		if ToolchainAdvisoryLess(tc.upper, tc.lower) {
			t.Errorf("%s: the comparator is not antisymmetric", tc.key)
		}
		if ToolchainAdvisoryLess(tc.lower, tc.lower) {
			t.Errorf("%s: the comparator reports an advisory less than itself", tc.key)
		}
	}
}
