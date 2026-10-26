package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	domain2 "code.eitanity.com/kanonarion/internal/license/domain"
	"code.eitanity.com/kanonarion/internal/license/ports"
)

// recordOf is buildRecord with its own artefact and extraction time.
func recordOf(t *testing.T, coord coordinate.ModuleCoordinate, spdx, artefact string, at time.Time) domain2.LicenseRecord {
	t.Helper()
	r := buildRecord(t, coord, spdx, domain2.LicenseStatusDetected)
	r.ArtefactIdentity = fetchtest.ZipArtefact(artefact).String()
	r.ExtractedAt = at
	r.ContentHash = ""
	var h domain2.LicenseRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return r
}

// A generation derived from an artefact the fetch ledger holds only as a
// local-source measurement is left out of the published coordinate's reads; the
// published generation answers, the listing shows it, and the ledger keeps both.
// The controls: with nothing superseded two published artefacts still conflict,
// and with no reader wired the read is what it was.
func TestSupersededGenerationsAreLeftOutOfPublishedReads(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "github.com/foo/uuid", "v1.6.0")
	local := recordOf(t, coord, "", "dir=", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	published := recordOf(t, coord, "BSD-3-Clause", "pub=", time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC))

	s := openTestStore(t)
	for _, r := range []domain2.LicenseRecord{local, published} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	if _, _, err := s.GetLicenseRecord(ctx, coord, "0.1.0"); !errors.Is(err, ports.ErrLicenceConflict) {
		t.Fatalf("control: with no reader the two artefacts must conflict, got %v", err)
	}

	s.WithSupersededArtefacts(func(_ context.Context, c coordinate.ModuleCoordinate) (map[string]bool, error) {
		if c == coord {
			return map[string]bool{local.ArtefactIdentity: true}, nil
		}
		return nil, nil
	})
	got, found, err := s.GetLicenseRecord(ctx, coord, "0.1.0")
	if err != nil || !found || got.ContentHash != published.ContentHash {
		t.Fatalf("GetLicenseRecord = %s, %v, %v; want the published generation", got.ContentHash, found, err)
	}
	sums, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{})
	if err != nil || len(sums) != 1 || sums[0].ContentHash != published.ContentHash {
		t.Errorf("listing = %+v, %v; want the published generation alone", sums, err)
	}
	history, err := s.ListLicenseRecordsFor(ctx, coord, "0.1.0")
	if err != nil || len(history) != 2 {
		t.Errorf("history = %d generations, %v; the ledger keeps both", len(history), err)
	}

	// Nothing superseded: the conflict between two published artefacts stands.
	s.WithSupersededArtefacts(func(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) { return nil, nil })
	if _, _, err := s.GetLicenseRecord(ctx, coord, "0.1.0"); !errors.Is(err, ports.ErrLicenceConflict) {
		t.Errorf("two published artefacts must still conflict, got %v", err)
	}
}

// A coordinate whose only generation is superseded has no answer and is not
// listed.
func TestOnlySupersededGenerationReadsAsAbsent(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "github.com/foo/uuid", "v1.6.0")
	local := recordOf(t, coord, "", "dir=", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	s := openTestStore(t)
	if err := s.PutLicenseRecord(ctx, local); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s.WithSupersededArtefacts(func(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) {
		return map[string]bool{local.ArtefactIdentity: true}, nil
	})
	if _, found, err := s.GetLicenseRecord(ctx, coord, "0.1.0"); err != nil || found {
		t.Errorf("GetLicenseRecord found=%v err=%v, want absent", found, err)
	}
	if sums, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{}); err != nil || len(sums) != 0 {
		t.Errorf("listing = %+v, %v; want empty", sums, err)
	}
}
