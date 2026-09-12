package sqlite_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// The census is the only read that can see across a pipeline bump. Every other
// per-coordinate read takes the version as part of its key, so after a bump they
// answer empty for a coordinate whose whole history is in the table — and a
// caller that could not ask this question reported that emptiness as "never
// scanned".

func generationRecord(t *testing.T, pipeline string, scannedAt time.Time, findings int) domain.VulnerabilityRecord {
	t.Helper()
	fs := make([]domain.VulnerabilityFinding, 0, findings)
	for i := 0; i < findings; i++ {
		fs = append(fs, domain.VulnerabilityFinding{
			ID:          string(rune('A'+i)) + "-2026-0001",
			PublishedAt: scannedAt,
			ModifiedAt:  scannedAt,
		})
	}
	status := domain.StatusClean
	if findings > 0 {
		status = domain.StatusAffected
	}
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord("github.com/foo/bar", "v1.0.0"),
		WalkID:           "walk-1",
		OverallStatus:    status,
		DatabaseSnapshot: ledgerSnapshot(),
		ScannedAt:        scannedAt,
		FirstScannedAt:   scannedAt,
		PipelineVersion:  pipeline,
		Findings:         fs,
	})
}

func TestListVulnerabilityRecordGenerationsForModule_SeesPastTheBump(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	base := time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC)
	recs := []domain.VulnerabilityRecord{
		generationRecord(t, "v19", base, 2),
		generationRecord(t, "v19", base.Add(time.Hour), 1),
		generationRecord(t, "v20", base.Add(2*time.Hour), 0),
	}
	for _, rec := range recs {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	// The control the census exists to contradict: the keyed read is blind to v19.
	at21, err := store.ListVulnerabilityRecordsForModule(ctx, recs[0].Coordinate, "v21")
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModule: %v", err)
	}
	if len(at21) != 0 {
		t.Fatalf("keyed read at v21 returned %d records, want 0", len(at21))
	}

	gens, err := store.ListVulnerabilityRecordGenerationsForModule(ctx, recs[0].Coordinate)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordGenerationsForModule: %v", err)
	}
	if len(gens) != 2 {
		t.Fatalf("census holds %d generations, want 2: %+v", len(gens), gens)
	}
	if gens[0].PipelineVersion != "v19" || gens[0].Records != 2 || gens[0].Findings != 3 {
		t.Errorf("v19 generation = %+v, want 2 records carrying 3 findings", gens[0])
	}
	if gens[1].PipelineVersion != "v20" || gens[1].Records != 1 || gens[1].Findings != 0 {
		t.Errorf("v20 generation = %+v, want 1 record carrying 0 findings", gens[1])
	}
}

// The census names the walks its records were written by, because that is what a
// re-scan is named by: vuln-scan takes a walk id, and its --module form resolves
// only a walk ROOTED at the coordinate. Ordered by the newest record each walk
// wrote, so a refusal naming one names the same one every time.
func TestListVulnerabilityRecordGenerationsForModule_NamesTheWalksNewestFirst(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	base := time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC)
	older := generationRecord(t, "v19", base, 1)
	newer := generationRecord(t, "v19", base.Add(time.Hour), 1)
	newer.WalkID = "walk-2"
	for _, rec := range []domain.VulnerabilityRecord{older, seal(t, newer)} {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	gens, err := store.ListVulnerabilityRecordGenerationsForModule(ctx, older.Coordinate)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordGenerationsForModule: %v", err)
	}
	if len(gens) != 1 {
		t.Fatalf("census holds %d generations, want 1: %+v", len(gens), gens)
	}
	// The counts are the control: grouping by walk as well as by generation must
	// not split one generation into two rows.
	if gens[0].Records != 2 || gens[0].Findings != 2 {
		t.Errorf("generation = %+v, want 2 records carrying 2 findings", gens[0])
	}
	if got := gens[0].Walks; len(got) != 2 || got[0] != "walk-2" || got[1] != "walk-1" {
		t.Errorf("walks = %v, want [walk-2 walk-1] — newest record first", got)
	}
	if !gens[0].LastScannedAt.Equal(base.Add(time.Hour)) {
		t.Errorf("LastScannedAt = %s, want the newest record's instant %s", gens[0].LastScannedAt, base.Add(time.Hour))
	}
}

func TestListVulnerabilityRecordGenerationsForModule_UnknownCoordinateHoldsNothing(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	gens, err := store.ListVulnerabilityRecordGenerationsForModule(ctx, coord("github.com/foo/never", "v0.1.0"))
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordGenerationsForModule: %v", err)
	}
	if len(gens) != 0 {
		t.Errorf("census reports %d generations for a coordinate never scanned: %+v", len(gens), gens)
	}
}

func TestListVulnerabilityRecordGenerationsForModule_RefusesZeroCoordinate(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	if _, err := store.ListVulnerabilityRecordGenerationsForModule(ctx, coordinate.ModuleCoordinate{}); err == nil {
		t.Fatal("zero coordinate names no module; the census must refuse it rather than answer absence")
	}
}

// The census counts what a bump left behind; this read returns it. A history
// listing needs the rows themselves, and taking them one generation at a time
// through the keyed read would put them in the caller's order rather than the
// ledger's.
func TestListVulnerabilityRecordsForModuleAllGenerations_SpansTheBump(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	base := time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC)
	recs := []domain.VulnerabilityRecord{
		generationRecord(t, "v19", base, 2),
		generationRecord(t, "v19", base.Add(time.Hour), 1),
		generationRecord(t, "v20", base.Add(2*time.Hour), 0),
	}
	for _, rec := range recs {
		if err := store.PutVulnerabilityRecord(ctx, rec); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}

	all, err := store.ListVulnerabilityRecordsForModuleAllGenerations(ctx, recs[0].Coordinate)
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModuleAllGenerations: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("read across generations returned %d records, want 3", len(all))
	}
	wantOrder := []string{"v20", "v19", "v19"}
	for i, want := range wantOrder {
		if all[i].PipelineVersion != want {
			t.Errorf("record %d is at %s, want %s — newest first across generations", i, all[i].PipelineVersion, want)
		}
	}
	if !all[0].ScannedAt.Equal(base.Add(2 * time.Hour)) {
		t.Errorf("newest record scanned at %s, want %s", all[0].ScannedAt, base.Add(2*time.Hour))
	}
}

func TestListVulnerabilityRecordsForModuleAllGenerations_UnknownCoordinateHoldsNothing(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	all, err := store.ListVulnerabilityRecordsForModuleAllGenerations(ctx, coord("github.com/foo/never", "v0.1.0"))
	if err != nil {
		t.Fatalf("ListVulnerabilityRecordsForModuleAllGenerations: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("unscanned coordinate returned %d records, want 0", len(all))
	}
}
