package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	walksqlite "code.eitanity.com/kanonarion/internal/walk/adapters/walks/sqlite"
	"code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// A walk is chosen by its id, or by a listing over its columns that then reads
// it by id. A genuine walk under another id, or under a column its seal does not
// carry, must be refused by GetWalk, the one read that decodes a walk.

func TestMisfiled_GetWalkRefusesAMovedWalk(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC)
	const idA, idB = "01MISFILED000000000WALKA01", "01MISFILED000000000WALKB01"
	for _, m := range []struct{ name, column, value, wantField string }{
		{name: "key swap", wantField: "is sealed as " + idB},
		{name: "target", column: "target_version", value: "v9.9.9", wantField: "the sealed target"},
		{name: "scope", column: "scope", value: "all", wantField: "the sealed scope"},
		{name: "pipeline_version", column: "pipeline_version", value: "9.9.9", wantField: "the sealed pipeline_version"},
		{name: "goos", column: "goos", value: "windows", wantField: "the sealed graph.build_env.goos"},
		{name: "goarch", column: "goarch", value: "arm64", wantField: "the sealed graph.build_env.goarch"},
		{name: "go_version", column: "go_version", value: "go1.1", wantField: "the sealed graph.build_env.go_version"},
		{name: "tinygo_target", column: "tinygo_target", value: "wasip1", wantField: "the sealed graph.build_env.tinygo_target"},
		{name: "tinygo_version", column: "tinygo_version", value: "0.1.0", wantField: "the sealed graph.build_env.tinygo_version"},
	} {
		t.Run(m.name, func(t *testing.T) {
			s := openMemStore(t)
			a := buildWalkRecordForPlatform(t, idA, "linux", "amd64", base)
			b := buildWalkRecordForPlatform(t, idB, "darwin", "arm64", base.Add(time.Hour))
			for _, rec := range []domain.WalkRecord{a, b} {
				if err := s.PutWalk(ctx, rec); err != nil {
					t.Fatalf("PutWalk: %v", err)
				}
			}
			db := s.InternalDB().DB()
			var err error
			if m.column == "" {
				_, err = db.Exec(`UPDATE walks SET serialised = (SELECT serialised FROM walks WHERE id = ?),
content_hash = (SELECT content_hash FROM walks WHERE id = ?) WHERE id = ?`, idB, idB, idA)
			} else {
				_, err = db.Exec(`UPDATE walks SET `+m.column+` = ? WHERE id = ?`, m.value, idA) //nolint:gosec // column is a literal in this file
			}
			if err != nil {
				t.Fatalf("moving the walk: %v", err)
			}

			_, err = s.GetWalk(ctx, idA)
			var misfiled *recordseal.Misfiled
			if !errors.As(err, &misfiled) || !errors.Is(err, walkports.ErrWalkIntegrity) {
				t.Fatalf("err = %v, want a misfiled refusal under ErrWalkIntegrity", err)
			}
			if !strings.Contains(err.Error(), m.wantField) || misfiled.Table != "walks" || misfiled.Kind != walksqlite.RecordKind {
				t.Errorf("refusal %q does not name %q and the table", err, m.wantField)
			}
			// The other walk is untouched and still served.
			if _, gerr := s.GetWalk(ctx, idB); gerr != nil {
				t.Errorf("the walk that was not moved: %v", gerr)
			}
		})
	}
}

// The listing is a row read: it answers from the columns, and the walk it names
// is refused when it is read.
func TestMisfiled_ListWalksIsARowRead(t *testing.T) {
	ctx := context.Background()
	s := openMemStore(t)
	rec := buildWalkRecordForPlatform(t, "01MISFILED000000000WALKC01", "linux", "amd64", time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC))
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	if _, err := s.InternalDB().DB().Exec(`UPDATE walks SET goos = 'windows'`); err != nil {
		t.Fatal(err)
	}
	sums, err := s.ListWalks(ctx, walkports.WalkFilter{BuildEnv: &walkports.BuildEnvFilter{GOOS: "windows", GOARCH: "amd64"}})
	if err != nil || len(sums) != 1 {
		t.Fatalf("ListWalks = %d, %v; want the edited row listed from its columns", len(sums), err)
	}
	if _, err := s.GetWalk(ctx, sums[0].ID); !recordseal.IsMisfiled(err) {
		t.Fatalf("GetWalk of the listed walk = %v, want a misfiled refusal", err)
	}
}
