package sqlite_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	fipssqlite "github.com/eitanity/kanonarion/internal/fips/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/fips/domain"
)

// A fips_records row filed under a project or pipeline_fingerprint its record does not state is
// refused, and re-scanning the project, which overwrites the row, clears it.
func TestMisfiled_GetRefusesAMovedRecordAndAReScanClearsIt(t *testing.T) {
	ctx := context.Background()
	for _, m := range []struct {
		name string
		from func(a, other domain.Record) domain.Record
	}{
		{"key swap", func(_, other domain.Record) domain.Record { return other }},
		{"pipeline_fingerprint", func(a, _ domain.Record) domain.Record { a.CatalogueVersion = "0"; return a }},
	} {
		t.Run(m.name, func(t *testing.T) {
			db, err := sqlitestore.Open(":memory:", fipssqlite.Migrations(), sqlitestore.IntentCreate)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			s := fipssqlite.New(db)
			a, other := mkRecord("example.com/fix", true, "boringcrypto", "go1.24 X:boringcrypto"), mkRecord("example.com/proj2", true, "boringcrypto", "go1.24 X:boringcrypto")
			for _, r := range []domain.Record{a, other} {
				if perr := s.PutFIPSRecord(ctx, r); perr != nil {
					t.Fatalf("PutFIPSRecord: %v", perr)
				}
			}
			raw, err := json.Marshal(m.from(a, other))
			if err != nil {
				t.Fatal(err)
			}
			if _, uerr := db.DB().Exec(`UPDATE fips_records SET serialised = ? WHERE project_module_path = ?`,
				blobcodec.Encode(raw), a.ProjectModulePath); uerr != nil {
				t.Fatalf("moving the row: %v", uerr)
			}
			_, _, err = s.GetFIPSRecord(ctx, a.ProjectModulePath)
			if !recordseal.IsMisfiled(err) || !strings.Contains(err.Error(), "fips_records") {
				t.Fatalf("err = %v, want a misfiled refusal naming the table", err)
			}
			if perr := s.PutFIPSRecord(ctx, a); perr != nil {
				t.Fatalf("PutFIPSRecord: %v", perr)
			}
			got, found, err := s.GetFIPSRecord(ctx, a.ProjectModulePath)
			if err != nil || !found || got.ProjectModulePath != a.ProjectModulePath {
				t.Fatalf("after the re-scan: %q found %v, %v", got.ProjectModulePath, found, err)
			}
		})
	}
}
