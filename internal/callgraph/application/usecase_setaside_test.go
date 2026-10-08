package application_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// nothingServableStore answers every composed read as a coordinate whose every
// generation was set aside, the way the store does for drifted rows.
type nothingServableStore struct{ *sqlite.Store }

func (nothingServableStore) GetCallGraphRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (domain2.CallGraphRecord, bool, error) {
	row := recordseal.SetAsideRow{Kind: "call graph record", ID: coord.String(), ContentHash: "sha256:aa"}
	return domain2.CallGraphRecord{}, false, &recordseal.NothingServable{
		Kind: "call graph record", ID: coord.String(), Aside: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{row}},
	}
}

// TestExecute_EveryGenerationSetAsideIsACacheMiss: a ledger whose every
// generation this build cannot reproduce holds nothing to serve, so the run
// measures one it can rather than failing.
func TestExecute_EveryGenerationSetAsideIsACacheMiss(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	storeFetchRecord(t, facts, blobs, testCoord)
	analyser := measuringAnalyser()
	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:           facts,
		Blobs:           blobs,
		Store:           nothingServableStore{openLedger(t)},
		Analyser:        analyser,
		Clock:           fakeClock{t: testTime},
		Stopwatch:       fakeStopwatch{},
		PipelineVersion: testPipelineV,
		Logger:          slog.Default(),
	})

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute = %v, want the run to measure", err)
	}
	if result.FromCache || analyser.calls != 1 {
		t.Errorf("FromCache %v, analyser ran %d times; want a fresh measurement", result.FromCache, analyser.calls)
	}
}
