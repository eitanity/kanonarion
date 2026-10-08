package localfs_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/adapters/localfs"
)

// asideFacts answers NothingServable for a coordinate it holds nothing
// readable of: every measurement was set aside.
type asideFacts struct{ *fakeFacts }

func (f asideFacts) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) (fetchdomain.CompositeRecord, bool, error) {
	rec, ok, err := f.fakeFacts.GetFetchRecord(ctx, coord, pv)
	if err == nil && !ok {
		return fetchdomain.CompositeRecord{}, false, &recordseal.NothingServable{Kind: "fetch record", ID: coord.String(),
			Aside: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{{ContentHash: "sha256:aa", Reason: recordseal.Drift(errors.New("mismatch"))}}}}
	}
	return rec, ok, err
}

// A local-replace target whose every measurement was set aside is re-read from
// its tree and recorded, as an absent one is.
func TestEnsureFetchedFromPath_EverythingSetAsideRereads(t *testing.T) {
	dir := t.TempDir()
	coord := coordinatetest.MustNew("example.com/local", "v1.0.0")
	writeLocalModule(t, dir, coord.Path(), coord.Version())
	facts := asideFacts{newFakeFacts()}
	f := localfs.New(newFakeBlob(), facts, fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)})

	res, err := f.EnsureFetchedFromPath(context.Background(), coord, dir)
	if err != nil || res.FromCache {
		t.Fatalf("EnsureFetchedFromPath = %+v, %v; want the tree re-read", res.FromCache, err)
	}
	if _, ok, _ := facts.fakeFacts.GetFetchRecord(context.Background(), coord, localfs.PipelineVersion); !ok {
		t.Error("no measurement was recorded")
	}
}
