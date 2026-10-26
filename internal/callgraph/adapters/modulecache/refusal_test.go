package modulecache_test

import (
	"context"
	"errors"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/modulecache"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
)

// A stored artefact refused as altered is not a hole to analyse around: every
// leg of the population that reads one stops and names it, so the analysis
// does not load without those bytes.
func TestMaterialise_ARefusedArtefactIsReportedOnEveryLeg(t *testing.T) {
	t.Run("requirement source", func(t *testing.T) {
		facts, blobs, f := newFixture(t)
		dep := coord(t, "example.com/dep", "v1.2.3")
		store(t, facts, blobs, dep, "", true)
		blobs.refuse = map[string]int{fetchtest.ZipIdentity(t, facts.records[dep.String()]).String(): 1}
		report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
			Materialise(context.Background(), t.TempDir(), pruned(dep))
		if !errors.Is(report.Tampered, fetchports.ErrBlobTampered) {
			t.Errorf("Tampered = %v, want the refusal", report.Tampered)
		}
	})

	t.Run("a requirement's go directive", func(t *testing.T) {
		facts, blobs, f := newFixture(t)
		dep := coord(t, "example.com/dep", "v1.2.3")
		store(t, facts, blobs, dep, "", true)
		// The source leg reads the go.mod first; the second read is the one that
		// decides whether the requirement is pre-pruning.
		blobs.refuse = map[string]int{fetchtest.GoModIdentity(t, facts.records[dep.String()]).String(): 2}
		report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
			Materialise(context.Background(), t.TempDir(), pruned(dep))
		if !errors.Is(report.Tampered, fetchports.ErrBlobTampered) {
			t.Errorf("Tampered = %v, want the refusal", report.Tampered)
		}
	})

	t.Run("module-graph go.mod", func(t *testing.T) {
		facts, blobs, f := newFixture(t)
		old := coord(t, "example.com/old", "v1.2.3")
		deeper := coord(t, "example.com/deeper", "v0.4.0")
		store(t, facts, blobs, old, "module example.com/old\n\ngo 1.16\n\nrequire example.com/deeper v0.4.0\n", true)
		store(t, facts, blobs, deeper, "", false)
		blobs.refuse = map[string]int{fetchtest.GoModIdentity(t, facts.records[deeper.String()]).String(): 1}
		report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
			Materialise(context.Background(), t.TempDir(), pruned(old))
		if !errors.Is(report.Tampered, fetchports.ErrBlobTampered) {
			t.Errorf("Tampered = %v, want the refusal", report.Tampered)
		}
	})

	t.Run("unpruned build list", func(t *testing.T) {
		facts, blobs, f := newFixture(t)
		dep := coord(t, "example.com/dep", "v1.2.3")
		deeper := coord(t, "example.com/deeper", "v0.5.0")
		store(t, facts, blobs, dep, "module example.com/dep\n\ngo 1.21\n\nrequire example.com/deeper v0.5.0\n", true)
		store(t, facts, blobs, deeper, "", true)
		blobs.refuse = map[string]int{fetchtest.ZipIdentity(t, facts.records[deeper.String()]).String(): 1}
		report := modulecache.New(facts, blobs, discardLogger()).WithFetcher(f).
			Materialise(context.Background(), t.TempDir(), prePruning(dep))
		if !errors.Is(report.Tampered, fetchports.ErrBlobTampered) {
			t.Errorf("Tampered = %v, want the refusal", report.Tampered)
		}
	})
}
