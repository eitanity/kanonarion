package sqlite_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/blobcodec"
	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	vendorstore "code.eitanity.com/kanonarion/internal/vendortree/adapters/store/sqlite"
	"code.eitanity.com/kanonarion/internal/vendortree/domain"
)

// A vendor_records row filed under a project or pipeline_version its record does not state is
// refused, and re-scanning the project, which overwrites the row, clears it.
func TestMisfiled_GetRefusesAMovedRecordAndAReScanClearsIt(t *testing.T) {
	ctx := context.Background()
	for _, m := range []struct {
		name string
		from func(a, other domain.Record) domain.Record
	}{
		{"key swap", func(_, other domain.Record) domain.Record { return other }},
		{"pipeline_version", func(a, _ domain.Record) domain.Record { a.PipelineVersion = "0"; return a }},
	} {
		t.Run(m.name, func(t *testing.T) {
			db, err := sqlitestore.Open(":memory:", vendorstore.Migrations(), sqlitestore.IntentCreate)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			s := vendorstore.New(db)
			a, other := mkRecord("example.com/fix"), mkRecord("example.com/proj2")
			for _, r := range []domain.Record{a, other} {
				if perr := s.PutVendorRecord(ctx, r); perr != nil {
					t.Fatalf("PutVendorRecord: %v", perr)
				}
			}
			raw, err := json.Marshal(m.from(a, other))
			if err != nil {
				t.Fatal(err)
			}
			if _, uerr := db.DB().Exec(`UPDATE vendor_records SET serialised = ? WHERE project_module_path = ?`,
				blobcodec.Encode(raw), a.ProjectModulePath); uerr != nil {
				t.Fatalf("moving the row: %v", uerr)
			}
			_, _, err = s.GetVendorRecord(ctx, a.ProjectModulePath)
			if !recordseal.IsMisfiled(err) || !strings.Contains(err.Error(), "vendor_records") {
				t.Fatalf("err = %v, want a misfiled refusal naming the table", err)
			}
			if perr := s.PutVendorRecord(ctx, a); perr != nil {
				t.Fatalf("PutVendorRecord: %v", perr)
			}
			got, found, err := s.GetVendorRecord(ctx, a.ProjectModulePath)
			if err != nil || !found || got.ProjectModulePath != a.ProjectModulePath {
				t.Fatalf("after the re-scan: %q found %v, %v", got.ProjectModulePath, found, err)
			}
		})
	}
}
