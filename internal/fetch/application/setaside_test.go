package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// asideFacts holds measurements of every coordinate that this build cannot
// reproduce: until one is appended, each read is NothingServable.
type asideFacts struct{ *fakeFacts }

func nothingServable(coord coordinate.ModuleCoordinate) error {
	return &recordseal.NothingServable{Kind: "fetch record", ID: coord.String(),
		Aside: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{{
			Kind: "fetch record", ID: coord.String(), ContentHash: "sha256:aa", Reason: recordseal.Drift(errors.New("mismatch")),
		}}}}
}

func (f asideFacts) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) (domain2.CompositeRecord, bool, error) {
	rec, ok, err := f.fakeFacts.GetFetchRecord(ctx, coord, pv)
	if err == nil && !ok {
		return domain2.CompositeRecord{}, false, nothingServable(coord)
	}
	return rec, ok, err
}

func (f asideFacts) ListFetchRecords(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) ([]domain2.FactRecord, error) {
	out, err := f.fakeFacts.ListFetchRecords(ctx, coord, pv)
	if err == nil && len(out) == 0 {
		return nil, nothingServable(coord)
	}
	return out, err
}

// A coordinate whose every measurement was set aside is measured again, as an
// absent one is, on every acquisition path and under --force; the run appends a
// record this build can serve.
func TestExecute_EverythingSetAsideRemeasures(t *testing.T) {
	coord := modcacheCoord(t)
	zipHash, goModHash := fetchtest.H1("zip-abc="), fetchtest.H1("mod-abc=")
	for _, tc := range []struct {
		name            string
		modcache, force bool
		goModOnly       bool
	}{
		{name: "network"},
		{name: "network go.mod only", goModOnly: true},
		{name: "network forced", force: true},
		{name: "modcache", modcache: true},
		{name: "modcache go.mod only", modcache: true, goModOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := asideFacts{newFakeFacts()}
			uc := newUseCaseWithSumDB(downloadWithHashes(coord, zipHash, goModHash), &fakeVCS{}, newModcacheBlob(t), facts,
				&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash, GoModHash: goModHash}})
			if tc.modcache {
				uc = uc.WithModcacheMode()
			}
			res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord, Force: tc.force, GoModOnly: tc.goModOnly})
			if err != nil {
				t.Fatalf("Execute = %v, want a fresh measurement", err)
			}
			if res.FromCache || res.Record.ContentHash == "" {
				t.Errorf("FromCache = %v, record %q; want a fresh, sealed measurement", res.FromCache, res.Record.ContentHash)
			}
			if _, ok, _ := facts.fakeFacts.GetFetchRecord(context.Background(), coord, "test-0.1.0"); !ok {
				t.Error("no measurement was appended")
			}
		})
	}
}
