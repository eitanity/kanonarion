package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// seedScannableModule gives a coordinate the fetch record and blob an isolated
// scan needs to reach the scanner at all.
func seedScannableModule(t *testing.T, facts *fakeFacts, blobs *fakeBlob, coord coordinate.ModuleCoordinate) {
	t.Helper()
	ctx := t.Context()
	rec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

// TestScanModule_RecordsNameTheAdvisoryCountTheScannerMeasured is the isolated
// path's half of the advisory-count contract.
//
// The walk's shared pre-extraction counts the database once and every record in
// the run names the count. A scan that had to extract a database of its own —
// because that shared extraction could not run — measured the same number and
// then dropped it, so its records carried a snapshot with no count: not
// "measured zero", which is refused outright, but indistinguishable from a row
// written before the field existed. A reader could not tell a clean verdict
// reached against four thousand advisories from one reached against three.
//
// The metadata-only case is the one that regressed most quietly. That record is
// rebuilt from the caller's own snapshot rather than from what the scanner
// returned, so a fix applied only to the scanner's record would leave every
// coverage-fallback verdict uncounted while the happy path looked correct.
func TestScanModule_RecordsNameTheAdvisoryCountTheScannerMeasured(t *testing.T) {
	const measured = 4134
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name    string
		scanned domain.VulnerabilityRecord
	}{
		{
			name:    "an analysed module",
			scanned: domain.VulnerabilityRecord{OverallStatus: domain.StatusClean},
		},
		{
			// The scanner could not analyse the source, so the use case rebuilds
			// the verdict from advisory metadata alone — from its own snapshot.
			name: "a module recovered to metadata-only",
			scanned: domain.VulnerabilityRecord{
				OverallStatus:     domain.StatusUnscannable,
				UnscannableReason: "no go.mod in the module zip",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

			facts := newFakeFacts()
			blobs := newFakeBlob()
			vulnStore := newFakeVulnStore()
			seedScannableModule(t, facts, blobs, coord)

			scanned := tc.scanned
			scanned.Coordinate = coord
			scanner := &fakeScanner{
				results:       map[string]domain.VulnerabilityRecord{coord.String(): scanned},
				advisoryCount: measured,
			}
			db := &fakeDatabase{snapshot: vulntest.MustNewAt("test", "v1", now), content: "vulndb content"}

			uc := application.NewScanModuleUseCase(
				facts, blobs, vulnStore, nil, scanner, db, nil, fixedClock{t: now}, "v1", slog.Default(),
			)

			res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got := res.DatabaseSnapshot.AdvisoryCount(); got != measured {
				t.Errorf("returned record names %d advisories, want %d: the scan measured the database and the verdict must say against how many it was reached",
					got, measured)
			}

			// The sealed row is what a later reader gets, so the count has to
			// survive the write and not merely the return.
			persisted, ok, perr := vulnStore.GetVulnerabilityRecord(ctx, coord, "v1", res.DatabaseSnapshot)
			if perr != nil || !ok {
				t.Fatalf("record not persisted under the snapshot it names: ok=%v err=%v", ok, perr)
			}
			if got := persisted.DatabaseSnapshot.AdvisoryCount(); got != measured {
				t.Errorf("sealed record names %d advisories, want %d", got, measured)
			}
		})
	}
}

// TestScanModule_AnUnmeasuredDatabaseRecordsNoCount states the other half of the
// invariant: only a positive count is representable, so a scan whose database
// was supplied already-extracted (or answered live) records nothing rather than
// asserting a zero the domain refuses.
func TestScanModule_AnUnmeasuredDatabaseRecordsNoCount(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	seedScannableModule(t, facts, blobs, coord)

	scanner := &fakeScanner{} // measured nothing
	db := &fakeDatabase{snapshot: vulntest.MustNewAt("test", "v1", now), content: "vulndb content"}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, fixedClock{t: now}, "v1", slog.Default(),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := res.DatabaseSnapshot.AdvisoryCount(); got != 0 {
		t.Errorf("record names %d advisories from a scan that measured none; an unmeasured reading must stay unstated", got)
	}
}
