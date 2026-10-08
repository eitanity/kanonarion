package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// setAsideStub answers the calls under test with fixed results; every other
// method of the port panics through the nil embedded interface.
type setAsideStub struct {
	ports.VulnerabilityStore
	putErr  error
	getRec  domain.VulnerabilityRecord
	getOK   bool
	getErr  error
	runs    map[string]domain.WalkScanRun
	recs    map[string][]domain.VulnerabilityRecord
	listErr map[string]error
}

func (s *setAsideStub) PutVulnerabilityRecord(context.Context, domain.VulnerabilityRecord) error {
	return s.putErr
}

func (s *setAsideStub) GetVulnerabilityRecordAt(context.Context, coordinate.ModuleCoordinate, string, domain.DatabaseSnapshot, domain.Rooting) (domain.VulnerabilityRecord, bool, error) {
	return s.getRec, s.getOK, s.getErr
}

func (s *setAsideStub) GetWalkScanRun(_ context.Context, id string) (domain.WalkScanRun, bool, error) {
	run, ok := s.runs[id]
	return run, ok, nil
}

func (s *setAsideStub) ListVulnerabilityRecords(_ context.Context, id string) ([]domain.VulnerabilityRecord, error) {
	return s.recs[id], s.listErr[id]
}

var driftRow = recordseal.SetAsideRow{
	Kind:        "vulnerability record",
	ID:          "example.com/group@v1.0.0",
	ContentHash: "sha256:a2546bf0",
	Reason:      errors.New("record written by a different canonical shape"),
}

func TestPutRecord_SetAsideIsStatedAndTheWriteSucceeds(t *testing.T) {
	var got []recordseal.SetAsideRow
	store := &setAsideStub{putErr: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{driftRow}}}

	err := putRecord(t.Context(), store, domain.VulnerabilityRecord{}, func(rows []recordseal.SetAsideRow) { got = rows }, slog.Default())
	if err != nil {
		t.Fatalf("putRecord = %v, want nil: the write committed", err)
	}
	if len(got) != 1 || got[0].ContentHash != driftRow.ContentHash {
		t.Errorf("reported %v, want the set-aside generation", got)
	}
}

func TestPutRecord_IntegrityFailureIsNotExcused(t *testing.T) {
	called := false
	store := &setAsideStub{putErr: fmt.Errorf("%w: example.com/group@v1.0.0: content hash mismatch", ports.ErrVulnIntegrity)}

	err := putRecord(t.Context(), store, domain.VulnerabilityRecord{}, func([]recordseal.SetAsideRow) { called = true }, slog.Default())
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Fatalf("putRecord = %v, want the integrity failure", err)
	}
	if called {
		t.Error("an integrity failure was reported as set aside")
	}
}

// With no reporter wired the generation is still stated, at warn level.
func TestPutRecord_NoReporterStillStatesTheGeneration(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	store := &setAsideStub{putErr: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{driftRow}}}

	if err := putRecord(t.Context(), store, domain.VulnerabilityRecord{}, nil, logger); err != nil {
		t.Fatalf("putRecord = %v", err)
	}
	if !strings.Contains(logged.String(), driftRow.ContentHash) {
		t.Errorf("the set-aside generation was not stated:\n%s", logged.String())
	}
}

// A reuse composed around a set-aside generation is served, and the generation
// stated.
func TestTryReuseCachedRecord_ServesAroundASetAsideGeneration(t *testing.T) {
	c, err := coordinate.NewModuleCoordinate("example.com/group", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	stored := domain.VulnerabilityRecord{Coordinate: c, OverallStatus: domain.StatusClean, ScannedAt: time.Unix(0, 0)}
	var got []recordseal.SetAsideRow
	uc := &ScanModuleUseCase{
		vulnStore: &setAsideStub{getRec: stored, getOK: true, getErr: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{driftRow}}},
		logger:    slog.Default(),
		setAside:  func(rows []recordseal.SetAsideRow) { got = rows },
	}
	rec, handled, rerr := uc.tryReuseCachedRecord(t.Context(), ScanModuleParams{Coordinate: c}, domain.DatabaseSnapshot{})
	if rerr != nil || !handled || !rec.Reused {
		t.Fatalf("tryReuseCachedRecord = (%v, handled %v, %v), want the composed record reused", rec.Coordinate, handled, rerr)
	}
	if len(got) != 1 || got[0].ContentHash != driftRow.ContentHash {
		t.Errorf("reported %v, want the set-aside generation", got)
	}
}

// A diff computed without a set-aside generation is returned, with the
// generation named beside it.
func TestDiffScanRuns_ReturnsTheDiffAndNamesTheSetAside(t *testing.T) {
	store := &setAsideStub{
		runs: map[string]domain.WalkScanRun{"a": {ID: "a", WalkID: "w"}, "b": {ID: "b", WalkID: "w"}},
		listErr: map[string]error{
			"b": &recordseal.SetAside{Rows: []recordseal.SetAsideRow{driftRow}},
		},
	}
	diff, err := NewDiffScanRunsUseCase(store).Diff(t.Context(), "a", "b")
	var aside *recordseal.SetAside
	if !errors.As(err, &aside) || len(aside.Rows) != 1 {
		t.Fatalf("Diff error = %v, want the set-aside generation named", err)
	}
	if diff.RunA.ID != "a" || diff.RunB.ID != "b" {
		t.Errorf("diff = %+v, want the diff of the two runs", diff)
	}
}
