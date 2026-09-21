package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	licensesqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// statusRecord builds a sealed record carrying a named copyright status at a
// named pipeline version — the two axes the listing filter selects on.
func statusRecord(
	t *testing.T,
	coord coordinate.ModuleCoordinate,
	spdx, pipeline string,
	copyright domain2.CopyrightStatus,
	at time.Time,
	artefact string,
) domain2.LicenseRecord {
	t.Helper()
	file := domain2.LicenseFileEntry{Path: "LICENSE", SPDX: spdx, Confidence: 0.95, FileHash: "sha256:abc", FileSize: 1000}
	if copyright == domain2.CopyrightStatusFound {
		file.CopyrightStatements = []domain2.CopyrightStatement{{Verbatim: "Copyright 2026 Acme Corp", Holders: []string{"Acme Corp"}}}
	}
	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       spdx,
		PrimaryConfidence: 0.95,
		LicenseFiles:      []domain2.LicenseFileEntry{file},
		OverallStatus:     domain2.LicenseStatusDetected,
		CopyrightStatus:   copyright,
		ExtractedAt:       at,
		PipelineVersion:   pipeline,
		ArtefactIdentity:  artefact,
	}
	var h domain2.LicenseRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// twoGenerationStore holds one coordinate measured at two pipeline versions and
// a second coordinate measured only at the newer one. It is the shape the
// generation default exists for: listing every row shows the first module twice.
func twoGenerationStore(t *testing.T) (*licensesqlite.Store, coordinate.ModuleCoordinate, coordinate.ModuleCoordinate) {
	t.Helper()
	s := openTestStore(t)
	ctx := context.Background()
	old := mustCoord(t, "example.com/old", "v1.0.0")
	fresh := mustCoord(t, "example.com/fresh", "v2.0.0")
	for _, r := range []domain2.LicenseRecord{
		statusRecord(t, old, "MIT", "1.3.0", domain2.CopyrightStatusFound,
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("old-zip=").String()),
		statusRecord(t, old, "MIT", "1.4.0", domain2.CopyrightStatusNoneFound,
			time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("old-zip=").String()),
		statusRecord(t, fresh, "Apache-2.0", "1.4.0", domain2.CopyrightStatusFound,
			time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("fresh-zip=").String()),
	} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}
	return s, old, fresh
}

func listed(t *testing.T, s *licensesqlite.Store, f ports.LicenseFilter) []string {
	t.Helper()
	sums, err := s.ListLicenseRecords(context.Background(), f)
	if err != nil {
		t.Fatalf("ListLicenseRecords: %v", err)
	}
	out := make([]string, 0, len(sums))
	for _, sum := range sums {
		out = append(out, sum.ModulePath+"@"+sum.ModuleVersion+"|"+sum.PipelineVersion)
	}
	return out
}

// A pipeline version on the filter lists that generation and no other, so a
// coordinate re-extracted after a bump appears once rather than once per
// generation.
func TestListLicenseRecords_PipelineVersionRestrictsToOneGeneration(t *testing.T) {
	s, _, _ := twoGenerationStore(t)

	served := listed(t, s, ports.LicenseFilter{PipelineVersion: "1.4.0"})
	want := map[string]bool{"example.com/old@v1.0.0|1.4.0": true, "example.com/fresh@v2.0.0|1.4.0": true}
	if len(served) != 2 {
		t.Fatalf("served generation listed %v, want one row per coordinate at 1.4.0", served)
	}
	for _, row := range served {
		if !want[row] {
			t.Errorf("served generation listed %q, which is not a 1.4.0 record", row)
		}
	}

	every := listed(t, s, ports.LicenseFilter{})
	if len(every) != 3 {
		t.Errorf("unrestricted listing returned %v, want all three generations", every)
	}
}

// The copyright status is on the row, read from the column, and it is the SERVED
// record's — the generation restriction decides which that is.
func TestListLicenseRecords_CopyrightStatusIsOnTheRow(t *testing.T) {
	s, _, _ := twoGenerationStore(t)
	sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{PipelineVersion: "1.4.0"})
	if err != nil {
		t.Fatalf("ListLicenseRecords: %v", err)
	}
	got := map[string]domain2.CopyrightStatus{}
	for _, sum := range sums {
		got[sum.ModulePath] = sum.CopyrightStatus
	}
	if got["example.com/old"] != domain2.CopyrightStatusNoneFound {
		t.Errorf("old module's copyright status = %v, want none_found — the 1.4.0 record's, not the 1.3.0 one's",
			got["example.com/old"])
	}
	if got["example.com/fresh"] != domain2.CopyrightStatusFound {
		t.Errorf("fresh module's copyright status = %v, want found", got["example.com/fresh"])
	}
}

// The filter selects on the copyright_status COLUMN, which holds the enum's
// ordinal. A build comparing it against the status NAME matches nothing and
// reports the empty answer as the truth.
func TestListLicenseRecords_CopyrightStatusFilterSelectsOnTheColumn(t *testing.T) {
	s, _, _ := twoGenerationStore(t)

	blocking := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNoneFound},
	})
	if len(blocking) != 1 || blocking[0] != "example.com/old@v1.0.0|1.4.0" {
		t.Fatalf("none_found listed %v, want only the module whose 1.4.0 record found no copyright", blocking)
	}

	// Several values match any of them, which is what makes "everything that is
	// not a published copyright" one invocation.
	both := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNoneFound, domain2.CopyrightStatusFound},
	})
	if len(both) != 2 {
		t.Errorf("none_found,found listed %v, want both coordinates", both)
	}

	// not_analysed is the zero ordinal, and no record here holds it. A filter
	// that bound the name rather than the ordinal would return everything or
	// nothing regardless of which value was asked for.
	none := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNotAnalysed},
	})
	if len(none) != 0 {
		t.Errorf("not_analysed listed %v, want nothing", none)
	}
}

// The status filter composes with the identifier filter and with paging, over
// the population the two of them left.
func TestListLicenseRecords_StatusFilterComposesWithSPDXAndPaging(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i, name := range []string{"a", "b", "c", "d"} {
		coord := mustCoord(t, "example.com/"+name, "v1.0.0")
		status := domain2.CopyrightStatusNoneFound
		spdx := "MIT"
		if i >= 2 {
			status = domain2.CopyrightStatusFound
		}
		if i == 3 {
			spdx = "Apache-2.0"
		}
		if err := s.PutLicenseRecord(ctx, statusRecord(t, coord, spdx, "1.4.0", status,
			time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC), fetchtest.ZipArtefact(name+"-zip=").String())); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	mitNoneFound := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0", SPDX: "MIT",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNoneFound},
	})
	if len(mitNoneFound) != 2 {
		t.Fatalf("MIT + none_found listed %v, want the two MIT records with no copyright", mitNoneFound)
	}

	// Paging counts the rows the filters left, not the store's records.
	page := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNoneFound},
		Limit:           1, Offset: 1,
	})
	if len(page) != 1 {
		t.Fatalf("--limit 1 --offset 1 over the filtered set returned %v, want one row", page)
	}
	if page[0] == mitNoneFound[0] {
		t.Errorf("the second page returned the first page's row %q", page[0])
	}
	past := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNoneFound},
		Offset:          5,
	})
	if len(past) != 0 {
		t.Errorf("an offset past the filtered population returned %v, want nothing", past)
	}
}

// The SQL clause is a prefilter over ROWS, and a coordinate holding several
// generations at one pipeline version collapses onto the record composition
// serves. A row that matched the column can therefore collapse onto a record
// that does not, and listing it would answer "none_found" with a module whose
// served record found a copyright.
func TestListLicenseRecords_StatusFilterJudgesTheServedRecord(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	// Two generations of one artefact at one pipeline version. The later, more
	// confident one found a copyright; the earlier one did not.
	early := statusRecord(t, coord, "MIT", "1.4.0", domain2.CopyrightStatusNoneFound,
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), artefact)
	early.PrimaryConfidence = 0.5
	late := statusRecord(t, coord, "MIT", "1.4.0", domain2.CopyrightStatusFound,
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), artefact)
	var h domain2.LicenseRecordHasher
	sealed, err := h.SetContentHash(early)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	for _, r := range []domain2.LicenseRecord{sealed, late} {
		if perr := s.PutLicenseRecord(ctx, r); perr != nil {
			t.Fatalf("PutLicenseRecord: %v", perr)
		}
	}

	rows := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNoneFound},
	})
	if len(rows) != 0 {
		t.Errorf("none_found listed %v, but the served record for that coordinate found a copyright", rows)
	}
	kept := listed(t, s, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusFound},
	})
	if len(kept) != 1 {
		t.Errorf("found listed %v, want the coordinate whose served record found one", kept)
	}
}

// A coordinate the filter reached and composition then refused to pick between
// is listed whatever status was asked for. There is no served record to test it
// against, and hiding a disagreement because it could not be shown to match is
// the one outcome a filter must not produce.
func TestListLicenseRecords_StatusFilterKeepsADisputedCoordinate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/disputed", "v1.0.0")
	artefact := fetchtest.ZipArtefact("disputed-zip=").String()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Equally confident readings of the same bytes naming different licences:
	// the disagreement composition will not resolve by picking. Only one of them
	// carries the status the filter asks for, so the filter reaches the
	// coordinate and the dispute is what answers for it.
	for _, r := range []domain2.LicenseRecord{
		statusRecord(t, coord, "MIT", "1.4.0", domain2.CopyrightStatusNoneFound, at, artefact),
		statusRecord(t, coord, "Apache-2.0", "1.4.0", domain2.CopyrightStatusFound, at, artefact),
	} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	sums, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{
		PipelineVersion: "1.4.0",
		CopyrightStatus: []domain2.CopyrightStatus{domain2.CopyrightStatusNoneFound},
	})
	if err != nil {
		t.Fatalf("ListLicenseRecords: %v", err)
	}
	if len(sums) != 1 || sums[0].Conflict == nil {
		t.Fatalf("listed %d row(s), conflict reported=%v, want the disputed coordinate reported",
			len(sums), len(sums) == 1 && sums[0].Conflict != nil)
	}
}
