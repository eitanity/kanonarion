package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/iface/adapters/store/sqlite"
	domain2 "code.eitanity.com/kanonarion/internal/iface/domain"
	"code.eitanity.com/kanonarion/internal/iface/ports"
)

// A genuine sealed record filed under a key or a selection value its seal does
// not carry must be refused by every read that decodes it.

func partialRecordAt(t *testing.T, path, version string) domain2.InterfaceRecord {
	t.Helper()
	r := makeRecord(t)
	coord, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	r.Coordinate = coord
	// Partial, so the listing decodes the blob for its analyser limit.
	r.OverallStatus = domain2.InterfaceStatusPartial
	return resealInterface(t, r)
}

func resealInterface(t *testing.T, r domain2.InterfaceRecord) domain2.InterfaceRecord {
	t.Helper()
	r.ContentHash = ""
	sealed, err := domain2.InterfaceRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

type ifaceMutation struct {
	name, column string
	value        any
	pipeline     string // what a keyed read asks for
	fresh        func(domain2.InterfaceRecord) domain2.InterfaceRecord
	selectedBy   map[string]bool
}

func ifaceMutations() []ifaceMutation {
	same := func(r domain2.InterfaceRecord) domain2.InterfaceRecord { return r }
	all := map[string]bool{"GetInterfaceRecord": true, "ListInterfaceRecordsFor": true, "ListInterfaceRecords": true, "IdenticalGeneration": true}
	return []ifaceMutation{
		{name: "key swap", pipeline: "0.1.0", fresh: same, selectedBy: all},
		{name: "pipeline_version", column: "pipeline_version", value: "0.9.9", pipeline: "0.9.9",
			fresh: func(r domain2.InterfaceRecord) domain2.InterfaceRecord { r.PipelineVersion = "0.9.9"; return r }, selectedBy: all},
		// An edited status hides the blob from the listing, which then reads the
		// columns alone: a row read.
		{name: "overall_status", column: "overall_status", value: int(domain2.InterfaceStatusExtracted), pipeline: "0.1.0",
			fresh: func(r domain2.InterfaceRecord) domain2.InterfaceRecord {
				r.OverallStatus = domain2.InterfaceStatusExtracted
				return r
			}, selectedBy: map[string]bool{"IdenticalGeneration": true}},
		{name: "package_count", column: "package_count", value: 3, pipeline: "0.1.0",
			fresh: func(r domain2.InterfaceRecord) domain2.InterfaceRecord {
				for len(r.Packages) < 3 {
					p := r.Packages[0]
					p.ImportPath = fmt.Sprintf("%s/p%d", p.ImportPath, len(r.Packages))
					r.Packages = append(r.Packages, p)
				}
				return r
			}, selectedBy: map[string]bool{"ListInterfaceRecords": true, "IdenticalGeneration": true}},
	}
}

func TestMisfiled_EveryDecodingReadRefusesAMovedRecord(t *testing.T) {
	ctx := context.Background()
	paths := []struct {
		name string
		read func(*sqlite.Store, ifaceMutation, domain2.InterfaceRecord) error
	}{
		{"GetInterfaceRecord", func(s *sqlite.Store, m ifaceMutation, a domain2.InterfaceRecord) error {
			_, _, err := s.GetInterfaceRecord(ctx, a.Coordinate, m.pipeline)
			return err
		}},
		{"ListInterfaceRecordsFor", func(s *sqlite.Store, m ifaceMutation, a domain2.InterfaceRecord) error {
			_, err := s.ListInterfaceRecordsFor(ctx, a.Coordinate, m.pipeline)
			return err
		}},
		{"ListInterfaceRecords", func(s *sqlite.Store, _ ifaceMutation, _ domain2.InterfaceRecord) error {
			_, err := s.ListInterfaceRecords(ctx, ports.InterfaceFilter{})
			return err
		}},
		{"IdenticalGeneration", func(s *sqlite.Store, m ifaceMutation, a domain2.InterfaceRecord) error {
			_, _, err := s.IdenticalGeneration(ctx, resealInterface(t, m.fresh(a)))
			return err
		}},
	}
	for _, m := range ifaceMutations() {
		for _, p := range paths {
			t.Run(m.name+"/"+p.name, func(t *testing.T) {
				s := openStore(t)
				a := partialRecordAt(t, "golang.org/x/text", "v0.3.0")
				b := partialRecordAt(t, "github.com/oklog/ulid/v2", "v2.1.2")
				for _, r := range []domain2.InterfaceRecord{a, b} {
					if err := s.PutInterfaceRecord(ctx, r); err != nil {
						t.Fatalf("PutInterfaceRecord: %v", err)
					}
				}
				db := s.InternalDB().DB()
				var err error
				if m.column == "" {
					_, err = db.Exec(`UPDATE interface_records
SET serialised = (SELECT serialised FROM interface_records WHERE module_path = 'github.com/oklog/ulid/v2'),
    content_hash = (SELECT content_hash FROM interface_records WHERE module_path = 'github.com/oklog/ulid/v2')
WHERE module_path = 'golang.org/x/text'`)
				} else {
					_, err = db.Exec(`UPDATE interface_records SET `+m.column+` = ? WHERE content_hash = ?`, m.value, a.ContentHash) //nolint:gosec // column is a literal in this file
				}
				if err != nil {
					t.Fatalf("moving the row: %v", err)
				}

				err = p.read(s, m, a)
				if !m.selectedBy[p.name] {
					if err != nil {
						t.Fatalf("a read that does not decode against %s failed: %v", m.column, err)
					}
					return
				}
				var misfiled *recordseal.Misfiled
				if !errors.As(err, &misfiled) || !errors.Is(err, ports.ErrInterfaceIntegrity) {
					t.Fatalf("err = %v, want a misfiled refusal under ErrInterfaceIntegrity", err)
				}
				if misfiled.Table != "interface_records" || !strings.Contains(err.Error(), "no kanonarion command clears it") {
					t.Errorf("refusal %q does not name the table and the remedy", err)
				}
			})
		}
	}
}
