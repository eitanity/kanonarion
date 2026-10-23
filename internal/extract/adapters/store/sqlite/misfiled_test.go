package sqlite

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
)

// A genuine run under another run's id, or under a walk id its seal does not
// carry, is refused by both reads that decode a run.
func TestMisfiled_RunReadsRefuseAMovedRun(t *testing.T) {
	for _, m := range []struct{ name, column, value string }{
		{name: "key swap"},
		{name: "walk_id", column: "walk_id", value: "walk-9"},
	} {
		for _, path := range []string{"GetExtractionRun", "ListExtractionRuns"} {
			t.Run(m.name+"/"+path, func(t *testing.T) {
				ctx := t.Context()
				s, err := Open(":memory:")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.db.Close() })
				for _, r := range []domain.ExtractionRun{sealedRun(t, "run-a"), sealedRun(t, "run-b")} {
					if perr := s.PutExtractionRun(ctx, r); perr != nil {
						t.Fatalf("PutExtractionRun: %v", perr)
					}
				}
				if m.column == "" {
					_, err = s.db.DB().Exec(`UPDATE extraction_runs SET raw_record = (SELECT raw_record FROM extraction_runs WHERE id = 'run-b') WHERE id = 'run-a'`)
				} else {
					_, err = s.db.DB().Exec(`UPDATE extraction_runs SET `+m.column+` = ? WHERE id = 'run-a'`, m.value)
				}
				if err != nil {
					t.Fatalf("moving the run: %v", err)
				}
				if path == "GetExtractionRun" {
					_, err = s.GetExtractionRun(ctx, "run-a")
				} else {
					_, err = s.ListExtractionRuns(ctx, ports.ExtractionRunFilter{})
				}
				var misfiled *recordseal.Misfiled
				if !errors.As(err, &misfiled) || !errors.Is(err, ports.ErrExtractionRunIntegrity) || misfiled.Table != "extraction_runs" {
					t.Fatalf("err = %v, want a misfiled refusal under ErrExtractionRunIntegrity", err)
				}
			})
		}
	}
}
