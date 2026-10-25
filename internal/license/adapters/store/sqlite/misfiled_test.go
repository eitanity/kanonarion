package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	licensesqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// A genuine sealed record filed under a key or a selection value its seal does
// not carry must be refused by every read that decodes it, not served as the
// record of the key it sits under.

// misfiledPair puts two genuine records, a under x/text and b under ulid.
func misfiledPair(t *testing.T) (*licensesqlite.Store, domain2.LicenseRecord, domain2.LicenseRecord) {
	t.Helper()
	s := openTestStore(t)
	a := buildRecord(t, mustCoord(t, "golang.org/x/text", "v0.3.0"), "BSD-3-Clause", domain2.LicenseStatusDetected)
	b := buildRecord(t, mustCoord(t, "github.com/oklog/ulid/v2", "v2.1.2"), "Apache-2.0", domain2.LicenseStatusDetected)
	for _, r := range []domain2.LicenseRecord{a, b} {
		if err := s.PutLicenseRecord(context.Background(), r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}
	return s, a, b
}

// licenceMutation moves a's row: either its blob and seal swap with b's, or one
// selection column is edited to a value the seal does not carry.
type licenceMutation struct {
	name   string
	column string // empty: the key swap
	value  any
	// asked is what a keyed read asks for after the mutation.
	asked func(a domain2.LicenseRecord) (coordinate.ModuleCoordinate, string)
	// fresh is the record a re-extraction would offer IdenticalGeneration so the
	// prefilter selects the moved row.
	fresh func(t *testing.T, a, b domain2.LicenseRecord) domain2.LicenseRecord
}

func reseal(t *testing.T, r domain2.LicenseRecord) domain2.LicenseRecord {
	t.Helper()
	r.ContentHash = ""
	sealed, err := domain2.LicenseRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

func licenceMutations() []licenceMutation {
	keyed := func(a domain2.LicenseRecord) (coordinate.ModuleCoordinate, string) {
		return a.Coordinate, a.PipelineVersion
	}
	withField := func(set func(*domain2.LicenseRecord)) func(*testing.T, domain2.LicenseRecord, domain2.LicenseRecord) domain2.LicenseRecord {
		return func(t *testing.T, a, _ domain2.LicenseRecord) domain2.LicenseRecord {
			set(&a)
			return reseal(t, a)
		}
	}
	return []licenceMutation{
		// The row under a's key keeps a's columns and holds b's bytes, so a
		// re-extraction of a is what the prefilter matches it for.
		{name: "key swap", asked: keyed, fresh: withField(func(*domain2.LicenseRecord) {})},
		{name: "pipeline_version", column: "pipeline_version", value: "0.9.9",
			asked: func(a domain2.LicenseRecord) (coordinate.ModuleCoordinate, string) { return a.Coordinate, "0.9.9" },
			fresh: withField(func(r *domain2.LicenseRecord) { r.PipelineVersion = "0.9.9" })},
		{name: "primary_spdx", column: "primary_spdx", value: "GPL-3.0-only", asked: keyed,
			fresh: withField(func(r *domain2.LicenseRecord) { r.PrimarySPDX = "GPL-3.0-only" })},
		{name: "spdx_expression", column: "spdx_expression", value: "GPL-3.0-only", asked: keyed,
			fresh: withField(func(r *domain2.LicenseRecord) { r.Expression = "GPL-3.0-only" })},
		{name: "overall_status", column: "overall_status", value: int(domain2.LicenseStatusNone), asked: keyed,
			fresh: withField(func(r *domain2.LicenseRecord) { r.OverallStatus = domain2.LicenseStatusNone })},
		{name: "copyright_status", column: "copyright_status", value: 3, asked: keyed,
			fresh: withField(func(r *domain2.LicenseRecord) { r.CopyrightStatus = 3 })},
		{name: "provenance_confidence", column: "provenance_confidence", value: 2, asked: keyed,
			fresh: withField(func(r *domain2.LicenseRecord) { r.Provenance.Confidence = 2 })},
	}
}

func (m licenceMutation) apply(t *testing.T, s *licensesqlite.Store, a domain2.LicenseRecord) {
	t.Helper()
	db := s.InternalDB().DB()
	if m.column == "" {
		if _, err := db.Exec(`UPDATE licence_records
SET serialised = (SELECT serialised FROM licence_records WHERE module_path = 'github.com/oklog/ulid/v2'),
    content_hash = (SELECT content_hash FROM licence_records WHERE module_path = 'github.com/oklog/ulid/v2')
WHERE module_path = 'golang.org/x/text'`); err != nil {
			t.Fatalf("moving the ulid record under x/text: %v", err)
		}
		return
	}
	if _, err := db.Exec(`UPDATE licence_records SET `+m.column+` = ? WHERE content_hash = ?`, m.value, a.ContentHash); err != nil { //nolint:gosec // column is a literal in this file
		t.Fatalf("editing %s: %v", m.column, err)
	}
}

// licenceReadPaths are every read of this store that decodes a sealed record.
// served reports whether a refusal is due: a path that does not select on the
// edited column reads a row whose key and seal still agree.
var licenceReadPaths = []struct {
	name    string
	selects func(column string) bool
	read    func(context.Context, *testing.T, *licensesqlite.Store, licenceMutation, domain2.LicenseRecord, domain2.LicenseRecord) error
}{
	{"GetLicenseRecord", keyColumnsOnly, func(ctx context.Context, _ *testing.T, s *licensesqlite.Store, m licenceMutation, a, _ domain2.LicenseRecord) error {
		coord, pv := m.asked(a)
		_, _, err := s.GetLicenseRecord(ctx, coord, pv)
		return err
	}},
	{"ListLicenseRecordsFor", keyColumnsOnly, func(ctx context.Context, _ *testing.T, s *licensesqlite.Store, m licenceMutation, a, _ domain2.LicenseRecord) error {
		coord, pv := m.asked(a)
		_, err := s.ListLicenseRecordsFor(ctx, coord, pv)
		return err
	}},
	{"ListLicenseRecords", func(c string) bool { return c != "provenance_confidence" }, func(ctx context.Context, _ *testing.T, s *licensesqlite.Store, _ licenceMutation, _, _ domain2.LicenseRecord) error {
		_, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{})
		return err
	}},
	{"IdenticalGeneration", func(string) bool { return true }, func(ctx context.Context, t *testing.T, s *licensesqlite.Store, m licenceMutation, a, b domain2.LicenseRecord) error {
		_, _, err := s.IdenticalGeneration(ctx, m.fresh(t, a, b))
		return err
	}},
}

func keyColumnsOnly(column string) bool { return column == "" || column == "pipeline_version" }

func TestMisfiled_EveryDecodingReadRefusesAMovedRecord(t *testing.T) {
	for _, m := range licenceMutations() {
		for _, p := range licenceReadPaths {
			t.Run(m.name+"/"+p.name, func(t *testing.T) {
				s, a, b := misfiledPair(t)
				m.apply(t, s, a)
				err := p.read(context.Background(), t, s, m, a, b)
				if !p.selects(m.column) {
					if err != nil {
						t.Fatalf("a read that does not select on %s failed: %v", m.column, err)
					}
					return
				}
				var misfiled *recordseal.Misfiled
				if !errors.As(err, &misfiled) || !errors.Is(err, ports.ErrLicenceIntegrity) {
					t.Fatalf("err = %v, want a misfiled refusal under ErrLicenceIntegrity", err)
				}
				if misfiled.Table != "licence_records" || !strings.Contains(err.Error(), "no kanonarion command clears it") {
					t.Errorf("refusal %q does not name the table and the remedy", err)
				}
			})
		}
	}
}

// TestMisfiled_KeySwapNamesBothKeys pins the wording a reader acts on.
func TestMisfiled_KeySwapNamesBothKeys(t *testing.T) {
	s, a, _ := misfiledPair(t)
	licenceMutations()[0].apply(t, s, a)
	_, _, err := s.GetLicenseRecord(context.Background(), a.Coordinate, a.PipelineVersion)
	want := "licence record filed under golang.org/x/text@v0.3.0 is sealed as github.com/oklog/ulid/v2@v2.1.2"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want it to contain %q", err, want)
	}
}
