package sqlite_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/directive/domain"
)

// A directive scan filed under a project, pipeline or scan id its record does
// not state is refused by every read that decodes it.
func TestMisfiled_DirectiveReadsRefuseAMovedScan(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, m := range []struct {
		name string
		from func(a, other, later domain.Record) domain.Record
	}{
		{"key swap", func(_, other, _ domain.Record) domain.Record { return other }},
		{"pipeline_version", func(a, _, _ domain.Record) domain.Record { a.PipelineVersion = "0.0.1"; return a }},
		{"scan_id", func(_, _, later domain.Record) domain.Record { return later }},
	} {
		for _, path := range []string{"GetDirectiveRecord", "GetScanByID", "ListScans"} {
			t.Run(m.name+"/"+path, func(t *testing.T) {
				s, db := openTestStore(t)
				a := mkRecord(t, "scan-a", "example.com/fix", at.Add(2*time.Hour))
				later := mkRecord(t, "scan-c", "example.com/fix", at)
				other := mkRecord(t, "scan-b", "example.com/proj2", at)
				for _, r := range []domain.Record{a, later, other} {
					if err := s.PutDirectiveRecord(ctx, r); err != nil {
						t.Fatalf("PutDirectiveRecord: %v", err)
					}
				}
				raw, err := json.Marshal(m.from(a, other, later))
				if err != nil {
					t.Fatal(err)
				}
				if _, uerr := db.DB().Exec(`UPDATE directive_scans SET serialised = ? WHERE scan_id = 'scan-a'`, blobcodec.Encode(raw)); uerr != nil {
					t.Fatalf("moving the scan: %v", uerr)
				}
				switch path {
				case "GetDirectiveRecord":
					_, _, err = s.GetDirectiveRecord(ctx, "example.com/fix")
				case "GetScanByID":
					_, _, err = s.GetScanByID(ctx, "scan-a")
				default:
					_, err = s.ListScans(ctx, "example.com/fix", 0, 0)
				}
				if !recordseal.IsMisfiled(err) || !strings.Contains(err.Error(), "directive_scans") {
					t.Fatalf("err = %v, want a misfiled refusal naming the table", err)
				}
			})
		}
	}
}
