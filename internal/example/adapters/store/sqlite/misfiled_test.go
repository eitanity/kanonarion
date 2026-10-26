package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	examplesqlite "code.eitanity.com/kanonarion/internal/example/adapters/store/sqlite"
	domain2 "code.eitanity.com/kanonarion/internal/example/domain"
	"code.eitanity.com/kanonarion/internal/example/ports"
)

// A genuine sealed record filed under a key or a selection value its seal does
// not carry must be refused by every read that decodes it. Each key holds two
// generations, so the listing composes and decodes too; the swap moves the newer
// one, which a re-extraction's prefilter meets first.

func resealExample(t *testing.T, r domain2.ExampleRecord) domain2.ExampleRecord {
	t.Helper()
	r.ContentHash = ""
	sealed, err := domain2.ExampleRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

func TestMisfiled_EveryDecodingReadRefusesAMovedRecord(t *testing.T) {
	ctx := context.Background()
	type mutation struct {
		name, column string
		value        any
		pipeline     string
		fresh        func(domain2.ExampleRecord) domain2.ExampleRecord
		refusedBy    map[string]bool
	}
	same := func(r domain2.ExampleRecord) domain2.ExampleRecord { return r }
	mutations := []mutation{
		{name: "key swap", pipeline: "0.1.0", fresh: same, refusedBy: map[string]bool{
			"GetExampleRecord": true, "ListExampleRecordsFor": true, "ListExampleRecords": true, "IdenticalGeneration": true}},
		// The edited row leaves its key's group and lists alone from its columns:
		// the listing reads it as a row.
		{name: "pipeline_version", column: "pipeline_version", value: "0.9.9", pipeline: "0.9.9",
			fresh:     func(r domain2.ExampleRecord) domain2.ExampleRecord { r.PipelineVersion = "0.9.9"; return r },
			refusedBy: map[string]bool{"GetExampleRecord": true, "ListExampleRecordsFor": true, "IdenticalGeneration": true}},
		{name: "overall_status", column: "overall_status", value: int(domain2.ExampleStatusNone), pipeline: "0.1.0",
			fresh: func(r domain2.ExampleRecord) domain2.ExampleRecord {
				r.OverallStatus = domain2.ExampleStatusNone
				return r
			},
			refusedBy: map[string]bool{"IdenticalGeneration": true}},
		{name: "example_count", column: "example_count", value: 1, pipeline: "0.1.0",
			fresh:     func(r domain2.ExampleRecord) domain2.ExampleRecord { r.Examples = r.Examples[:1]; return r },
			refusedBy: map[string]bool{"IdenticalGeneration": true}},
	}
	paths := []struct {
		name string
		read func(*examplesqlite.Store, mutation, domain2.ExampleRecord) error
	}{
		{"GetExampleRecord", func(s *examplesqlite.Store, m mutation, a domain2.ExampleRecord) error {
			_, _, err := s.GetExampleRecord(ctx, a.Coordinate, m.pipeline)
			return err
		}},
		{"ListExampleRecordsFor", func(s *examplesqlite.Store, m mutation, a domain2.ExampleRecord) error {
			_, err := s.ListExampleRecordsFor(ctx, a.Coordinate, m.pipeline)
			return err
		}},
		{"ListExampleRecords", func(s *examplesqlite.Store, _ mutation, _ domain2.ExampleRecord) error {
			_, err := s.ListExampleRecords(ctx, ports.ExampleFilter{})
			return err
		}},
		{"IdenticalGeneration", func(s *examplesqlite.Store, m mutation, a domain2.ExampleRecord) error {
			_, _, err := s.IdenticalGeneration(ctx, resealExample(t, m.fresh(a)))
			return err
		}},
	}
	for _, m := range mutations {
		for _, p := range paths {
			t.Run(m.name+"/"+p.name, func(t *testing.T) {
				s := openTestStore(t)
				a := buildRecord(t, mustCoord(t, "golang.org/x/text", "v0.3.0"), 2, domain2.ExampleStatusFound)
				later := a
				later.ExtractedAt = a.ExtractedAt.Add(time.Hour)
				later = resealExample(t, later)
				b := buildRecord(t, mustCoord(t, "github.com/oklog/ulid/v2", "v2.1.2"), 2, domain2.ExampleStatusFound)
				for _, r := range []domain2.ExampleRecord{a, later, b} {
					if err := s.PutExampleRecord(ctx, r); err != nil {
						t.Fatalf("PutExampleRecord: %v", err)
					}
				}
				var err error
				if m.column == "" {
					_, err = s.InternalDB().DB().Exec(`UPDATE example_records
SET serialised = (SELECT serialised FROM example_records WHERE module_path = 'github.com/oklog/ulid/v2'),
    content_hash = (SELECT content_hash FROM example_records WHERE module_path = 'github.com/oklog/ulid/v2')
WHERE content_hash = ?`, later.ContentHash)
				} else {
					_, err = s.InternalDB().DB().Exec(`UPDATE example_records SET `+m.column+` = ? WHERE content_hash = ?`, m.value, a.ContentHash)
				}
				if err != nil {
					t.Fatalf("moving the row: %v", err)
				}

				err = p.read(s, m, a)
				if !m.refusedBy[p.name] {
					if err != nil {
						t.Fatalf("a read that does not decode against %s failed: %v", m.column, err)
					}
					return
				}
				var misfiled *recordseal.Misfiled
				if !errors.As(err, &misfiled) || !errors.Is(err, ports.ErrExampleIntegrity) {
					t.Fatalf("err = %v, want a misfiled refusal under ErrExampleIntegrity", err)
				}
				if misfiled.Table != "example_records" || !strings.Contains(err.Error(), "no kanonarion command clears it") {
					t.Errorf("refusal %q does not name the table and the remedy", err)
				}
			})
		}
	}
}
