package modulecache_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/callgraph/adapters/modulecache"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// asideStore holds, for every coordinate it has no readable record of, only
// records this build cannot reproduce.
type asideStore struct{ *factStore }

func (s asideStore) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, _ string) (fetchdomain.CompositeRecord, bool, error) {
	return s.ComposeFetchRecord(ctx, coord)
}

func (s asideStore) ComposeFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error) {
	rec, ok, err := s.factStore.ComposeFetchRecord(ctx, coord)
	if err == nil && !ok {
		return fetchdomain.CompositeRecord{}, false, &recordseal.NothingServable{Kind: "fetch record", ID: coord.String(),
			Aside: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{{ContentHash: "sha256:aa", Reason: recordseal.Drift(errors.New("mismatch"))}}}}
	}
	return rec, ok, err
}

// A requirement whose every record was set aside is fetched, as an absent one
// is, for its source and for its go.mod alike.
func TestMaterialise_EverythingSetAsideIsFetched(t *testing.T) {
	facts, blobs, f := newFixture(t)
	dep := coord(t, "example.com/dep", "v1.2.3")
	f.goModFor[dep.String()] = "module example.com/dep\n\ngo 1.16\n\nrequire example.com/deeper v0.4.0\n"

	report := modulecache.New(asideStore{facts}, blobs, discardLogger()).WithFetcher(f).
		Materialise(context.Background(), t.TempDir(), pruned(dep))

	if len(f.full) != 1 || f.full[0] != dep.String() {
		t.Errorf("full fetches = %v, want the requirement whose records were all set aside", f.full)
	}
	if len(f.goMods) != 1 || f.goMods[0] != "example.com/deeper@v0.4.0" {
		t.Errorf("go.mod-only fetches = %v, want the version reached through the requirement's own file", f.goMods)
	}
	if !report.Complete() {
		t.Errorf("materialise reported %d/%d written: %s", report.Written, report.Requested, report.Failures)
	}
}
