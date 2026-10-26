package sqlite_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/blobcodec"
	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	godebugstore "code.eitanity.com/kanonarion/internal/godebug/adapters/store/sqlite"
	"code.eitanity.com/kanonarion/internal/godebug/domain"
)

// A godebug_records row filed under a project or pipeline_fingerprint its record does not state is
// refused, and re-scanning the project, which overwrites the row, clears it.
func TestMisfiled_GetRefusesAMovedRecordAndAReScanClearsIt(t *testing.T) {
	ctx := context.Background()
	for _, m := range []struct {
		name string
		from func(a, other domain.Record) domain.Record
	}{
		{"key swap", func(_, other domain.Record) domain.Record { return other }},
		{"pipeline_fingerprint", func(a, _ domain.Record) domain.Record { a.TaxonomyVersion = "0"; return a }},
	} {
		t.Run(m.name, func(t *testing.T) {
			db, err := sqlitestore.Open(":memory:", godebugstore.Migrations(), sqlitestore.IntentCreate)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			s := godebugstore.New(db)
			a, other := mkRecord("example.com/fix"), mkRecord("example.com/proj2")
			for _, r := range []domain.Record{a, other} {
				if perr := s.PutGoDebugRecord(ctx, r); perr != nil {
					t.Fatalf("PutGoDebugRecord: %v", perr)
				}
			}
			raw, err := json.Marshal(m.from(a, other))
			if err != nil {
				t.Fatal(err)
			}
			if _, uerr := db.DB().Exec(`UPDATE godebug_records SET serialised = ? WHERE project_module_path = ?`,
				blobcodec.Encode(raw), a.ProjectModulePath); uerr != nil {
				t.Fatalf("moving the row: %v", uerr)
			}
			_, _, err = s.GetGoDebugRecord(ctx, a.ProjectModulePath)
			if !recordseal.IsMisfiled(err) || !strings.Contains(err.Error(), "godebug_records") {
				t.Fatalf("err = %v, want a misfiled refusal naming the table", err)
			}
			if perr := s.PutGoDebugRecord(ctx, a); perr != nil {
				t.Fatalf("PutGoDebugRecord: %v", perr)
			}
			got, found, err := s.GetGoDebugRecord(ctx, a.ProjectModulePath)
			if err != nil || !found || got.ProjectModulePath != a.ProjectModulePath {
				t.Fatalf("after the re-scan: %q found %v, %v", got.ProjectModulePath, found, err)
			}
		})
	}
}
