package sqlite_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/blobcodec"
	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	nativesqlite "code.eitanity.com/kanonarion/internal/native/adapters/store/sqlite"
	"code.eitanity.com/kanonarion/internal/native/domain"
	"code.eitanity.com/kanonarion/internal/native/ports"
)

// A native record filed under a key its record does not state is refused by
// both reads, and re-measuring the filed coordinate overwrites the row.
func TestMisfiled_NativeReadsRefuseAMovedRecord(t *testing.T) {
	ctx := context.Background()
	for _, m := range []struct{ name, column, value string }{
		{name: "key swap"},
		{name: "pipeline_fingerprint", column: "pipeline_fingerprint", value: domain.PipelineFingerprint()},
		{name: "artefact_identity", column: "artefact_identity", value: "zip:h1:moved"},
	} {
		for _, path := range []string{"GetNativeRecord", "ListNativeRecords"} {
			t.Run(m.name+"/"+path, func(t *testing.T) {
				s, db := openMisfiledStore(t)
				a := sqliteRecord(t, "zip:h1:a")
				b := sqliteRecord(t, "zip:h1:b")
				b.Coordinate = coord(t, "github.com/other/lib", "v1.0.0")
				for _, r := range []domain.Record{a, b} {
					if err := s.PutNativeRecord(ctx, r); err != nil {
						t.Fatalf("PutNativeRecord: %v", err)
					}
				}
				var err error
				switch m.column {
				case "":
					_, err = db.Exec(`UPDATE native_records SET serialised = (SELECT serialised FROM native_records WHERE module_path = 'github.com/other/lib')
WHERE module_path = ?`, a.Coordinate.Path())
				case "pipeline_fingerprint":
					// The row stays under the served fingerprint while its record
					// states another generation.
					_, err = db.Exec(`UPDATE native_records SET serialised = ? WHERE module_path = ?`,
						mustNativeBlob(t, a, func(r *domain.Record) { r.RecipeCatalogueVersion = "0" }), a.Coordinate.Path())
				default:
					_, err = db.Exec(`UPDATE native_records SET `+m.column+` = ? WHERE module_path = ?`, m.value, a.Coordinate.Path()) //nolint:gosec // column is a literal in this file
				}
				if err != nil {
					t.Fatalf("moving the row: %v", err)
				}
				if path == "GetNativeRecord" {
					_, _, err = s.GetNativeRecord(ctx, a.Coordinate)
				} else {
					_, err = s.ListNativeRecords(ctx, ports.NativeFilter{})
				}
				if !recordseal.IsMisfiled(err) || !strings.Contains(err.Error(), "native_records") {
					t.Fatalf("err = %v, want a misfiled refusal naming the table", err)
				}
			})
		}
	}
}

func TestMisfiled_RemeasuringTheFiledCoordinateClearsTheRow(t *testing.T) {
	ctx := context.Background()
	s, db := openMisfiledStore(t)
	a := sqliteRecord(t, "zip:h1:a")
	b := sqliteRecord(t, "zip:h1:b")
	b.Coordinate = coord(t, "github.com/other/lib", "v1.0.0")
	for _, r := range []domain.Record{a, b} {
		if err := s.PutNativeRecord(ctx, r); err != nil {
			t.Fatalf("PutNativeRecord: %v", err)
		}
	}
	if _, err := db.Exec(`UPDATE native_records SET serialised = (SELECT serialised FROM native_records WHERE module_path = 'github.com/other/lib')
WHERE module_path = ?`, a.Coordinate.Path()); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.GetNativeRecord(ctx, a.Coordinate)
	want := "kanonarion native " + a.Coordinate.String() + " --force"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want the remedy %q", err, want)
	}
	if perr := s.PutNativeRecord(ctx, a); perr != nil {
		t.Fatalf("PutNativeRecord: %v", perr)
	}
	got, found, err := s.GetNativeRecord(ctx, a.Coordinate)
	if err != nil || !found || got.Coordinate != a.Coordinate {
		t.Fatalf("after re-measuring: %v, found %v, %v", got.Coordinate, found, err)
	}
}

// mustNativeBlob is r's stored bytes after edit.
func mustNativeBlob(t *testing.T, r domain.Record, edit func(*domain.Record)) []byte {
	t.Helper()
	edit(&r)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return blobcodec.Encode(raw)
}

// openMisfiledStore is openTestStore with the handle a test edits rows through.
func openMisfiledStore(t *testing.T) (*nativesqlite.Store, *sql.DB) {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", nativesqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return nativesqlite.New(db), db.DB()
}
