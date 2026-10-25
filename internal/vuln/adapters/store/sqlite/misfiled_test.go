package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// A genuine sealed vulnerability record or scan run filed under a key or a
// selection value its seal does not carry must be refused by every read that
// decodes it. A listing names the row rather than serving or dropping it.

const misfiledAdvisory = "GO-2026-0001"

func misfiledSnapshot() domain.DatabaseSnapshot {
	return vulntest.MustSealOver("govulndb", "2026-07-17T19:42:05Z", time.Date(2026, 7, 17, 19, 42, 5, 0, time.UTC), []byte("advisories"))
}

func misfiledRecord(t *testing.T, c coordinate.ModuleCoordinate, findings ...domain.VulnerabilityFinding) domain.VulnerabilityRecord {
	t.Helper()
	at := time.Date(2026, 7, 17, 20, 0, 0, 0, time.UTC)
	status := domain.StatusClean
	if len(findings) > 0 {
		status = domain.StatusAffected
	}
	return seal(t, domain.VulnerabilityRecord{
		Ecosystem: fetchdomain.EcosystemGo, Coordinate: c, WalkID: "walk-1", Findings: findings,
		OverallStatus: status, DatabaseSnapshot: misfiledSnapshot(), ScannedAt: at, FirstScannedAt: at,
		PipelineVersion: "v14", Rooting: domain.RootingTargetRooted,
	})
}

// misfiledVulnStore holds x/text (carrying the advisory) and ulid, and one run
// of walk-1 naming both.
func misfiledVulnStore(ctx context.Context, t *testing.T) (*sqlite.Store, domain.VulnerabilityRecord, domain.VulnerabilityRecord, domain.WalkScanRun) {
	t.Helper()
	store := newTestStore(t)
	text := misfiledRecord(t, coord("golang.org/x/text", "v0.3.0"), finding(misfiledAdvisory))
	ulid := misfiledRecord(t, coord("github.com/oklog/ulid/v2", "v2.1.2"))
	for _, r := range []domain.VulnerabilityRecord{text, ulid} {
		if err := store.PutVulnerabilityRecord(ctx, r); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}
	run := sealRun(t, domain.WalkScanRun{
		ID: "run-1", WalkID: "walk-1", Snapshot: misfiledSnapshot(), OverallStatus: domain.WalkStatusAffected,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{text.Coordinate: text.ContentHash, ulid.Coordinate: ulid.ContentHash},
		StartedAt:        text.ScannedAt, CompletedAt: text.ScannedAt.Add(time.Minute), PipelineVersion: "v14",
	})
	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("PutWalkScanRun: %v", err)
	}
	return store, text, ulid, run
}

// vulnAsk is what a read asks for after a mutation.
type vulnAsk struct {
	pipeline string
	snapshot domain.DatabaseSnapshot
}

type vulnMutation struct {
	name, column, value string
	ask                 func(*vulnAsk)
}

func vulnMutations() []vulnMutation {
	none := func(*vulnAsk) {}
	return []vulnMutation{
		{name: "key swap", ask: none},
		{name: "pipeline_version", column: "pipeline_version", value: "v99", ask: func(a *vulnAsk) { a.pipeline = "v99" }},
		{name: "snapshot_source", column: "snapshot_source", value: "osv", ask: func(a *vulnAsk) {
			a.snapshot = vulntest.MustSealOver("osv", a.snapshot.Version(), a.snapshot.RetrievedAt(), []byte("advisories"))
		}},
		{name: "snapshot_version", column: "snapshot_version", value: "2026-08-01T00:00:00Z", ask: func(a *vulnAsk) {
			a.snapshot = vulntest.MustSealOver(a.snapshot.Source(), "2026-08-01T00:00:00Z", a.snapshot.RetrievedAt(), []byte("advisories"))
		}},
		{name: "rooting", column: "rooting", value: string(domain.RootingIsolated), ask: none},
		{name: "content_hash", column: "content_hash", value: "sha256:0000", ask: none},
	}
}

func (m vulnMutation) move(t *testing.T, s *sqlite.Store, target, from domain.VulnerabilityRecord) {
	t.Helper()
	db := s.InternalDB().DB()
	var err error
	if m.column == "" {
		_, err = db.Exec(`UPDATE vulnerability_records
SET serialised = (SELECT serialised FROM vulnerability_records WHERE module_path = ?),
    content_hash = (SELECT content_hash FROM vulnerability_records WHERE module_path = ?)
WHERE module_path = ?`, from.Coordinate.Path(), from.Coordinate.Path(), target.Coordinate.Path())
	} else {
		_, err = db.Exec(`UPDATE vulnerability_records SET `+m.column+` = ? WHERE module_path = ?`, m.value, target.Coordinate.Path()) //nolint:gosec // column is a literal in this file
	}
	if err != nil {
		t.Fatalf("moving the row: %v", err)
	}
}

// vulnOutcome classifies a read's answer: refused as misfiled, named as an
// unreadable misfiled row in a listing, or answered.
func vulnOutcome(err error) string {
	var rows *ports.UnreadableRows
	switch {
	case err == nil:
		return "answered"
	case errors.As(err, &rows):
		for _, r := range rows.Rows {
			if recordseal.IsMisfiled(r.Reason) && errors.Is(err, ports.ErrVulnIntegrity) {
				return "refused"
			}
		}
		return "other: " + err.Error()
	case recordseal.IsMisfiled(err) && errors.Is(err, ports.ErrVulnIntegrity):
		return "refused"
	default:
		return "other: " + err.Error()
	}
}

func TestMisfiled_RecordReadsRefuseAMovedRecord(t *testing.T) {
	ctx := context.Background()
	paths := []struct {
		name string
		read func(*sqlite.Store, vulnAsk, domain.VulnerabilityRecord) error
	}{
		{"GetVulnerabilityRecordAt", func(s *sqlite.Store, a vulnAsk, r domain.VulnerabilityRecord) error {
			_, _, err := s.GetVulnerabilityRecordAt(ctx, r.Coordinate, a.pipeline, a.snapshot, domain.RootingTargetRooted)
			return err
		}},
		{"ListVulnerabilityRecordsForModule", func(s *sqlite.Store, a vulnAsk, r domain.VulnerabilityRecord) error {
			_, err := s.ListVulnerabilityRecordsForModule(ctx, r.Coordinate, a.pipeline)
			return err
		}},
		{"ListVulnerabilityRecordsForModuleAllGenerations", func(s *sqlite.Store, _ vulnAsk, r domain.VulnerabilityRecord) error {
			_, err := s.ListVulnerabilityRecordsForModuleAllGenerations(ctx, r.Coordinate)
			return err
		}},
		{"ListVulnerabilityRecordsForModuleInWalk", func(s *sqlite.Store, a vulnAsk, r domain.VulnerabilityRecord) error {
			_, err := s.ListVulnerabilityRecordsForModuleInWalk(ctx, r.Coordinate, a.pipeline, "walk-1")
			return err
		}},
		{"ListVulnerabilityRecords", func(s *sqlite.Store, _ vulnAsk, _ domain.VulnerabilityRecord) error {
			_, err := s.ListVulnerabilityRecords(ctx, "run-1")
			return err
		}},
		{"ListVulnerabilityRecordsByFindingID", func(s *sqlite.Store, _ vulnAsk, _ domain.VulnerabilityRecord) error {
			_, err := s.ListVulnerabilityRecordsByFindingID(ctx, misfiledAdvisory, "")
			return err
		}},
		{"ListVulnerabilityRecordsByFindingID in walk", func(s *sqlite.Store, _ vulnAsk, _ domain.VulnerabilityRecord) error {
			_, err := s.ListVulnerabilityRecordsByFindingID(ctx, misfiledAdvisory, "walk-1")
			return err
		}},
	}
	for _, m := range vulnMutations() {
		for _, p := range paths {
			t.Run(m.name+"/"+p.name, func(t *testing.T) {
				s, text, ulid, _ := misfiledVulnStore(ctx, t)
				m.move(t, s, text, ulid)
				ask := vulnAsk{pipeline: "v14", snapshot: misfiledSnapshot()}
				m.ask(&ask)
				got := vulnOutcome(p.read(s, ask, text))
				t.Logf("CELL %s | %s | %s", m.name, p.name, got)
				if want := vulnExpected(m.name, p.name); got != want {
					t.Fatalf("outcome %q, want %q", got, want)
				}
			})
		}
	}
}

// vulnExpected is each cell's outcome. A read answers when it does not select
// on the edited column, or when its join on that column no longer reaches the
// row: the membership and advisory indexes are derived rows, read as rows.
func vulnExpected(mutation, path string) string {
	refused := map[string]map[string]bool{
		// The walk reads join the membership on the record's content hash, so
		// the moved row is not reached by them.
		"key swap": {"GetVulnerabilityRecordAt": true, "ListVulnerabilityRecordsForModule": true,
			"ListVulnerabilityRecordsForModuleAllGenerations": true,
			"ListVulnerabilityRecords":                        true, "ListVulnerabilityRecordsByFindingID": true},
		"pipeline_version": {"GetVulnerabilityRecordAt": true, "ListVulnerabilityRecordsForModule": true},
		"snapshot_source":  {"GetVulnerabilityRecordAt": true},
		"snapshot_version": {"GetVulnerabilityRecordAt": true},
		"rooting":          {},
		"content_hash":     {"ListVulnerabilityRecords": true},
	}
	if refused[mutation][path] {
		return "refused"
	}
	return "answered"
}

func TestMisfiled_RunReadsRefuseAMovedRun(t *testing.T) {
	ctx := context.Background()
	for _, m := range []struct{ name, column, value string }{
		{name: "key swap"},
		{name: "walk_id", column: "walk_id", value: "walk-9"},
	} {
		for _, path := range []string{"GetWalkScanRun", "ListWalkScanRuns", "ListAllWalkScanRuns"} {
			t.Run(m.name+"/"+path, func(t *testing.T) {
				s, text, _, run := misfiledVulnStore(ctx, t)
				other := sealRun(t, domain.WalkScanRun{
					ID: "run-2", WalkID: "walk-2", Snapshot: misfiledSnapshot(), OverallStatus: domain.WalkStatusAffected,
					PerModuleResults: map[coordinate.ModuleCoordinate]string{text.Coordinate: text.ContentHash},
					StartedAt:        text.ScannedAt.Add(time.Hour), CompletedAt: text.ScannedAt.Add(2 * time.Hour), PipelineVersion: "v14",
				})
				if err := s.PutWalkScanRun(ctx, other); err != nil {
					t.Fatalf("PutWalkScanRun: %v", err)
				}
				db := s.InternalDB().DB()
				var err error
				if m.column == "" {
					_, err = db.Exec(`UPDATE walk_scan_runs SET serialised = (SELECT serialised FROM walk_scan_runs WHERE id = 'run-2'),
content_hash = (SELECT content_hash FROM walk_scan_runs WHERE id = 'run-2') WHERE id = 'run-1'`)
				} else {
					_, err = db.Exec(`UPDATE walk_scan_runs SET `+m.column+` = ? WHERE id = 'run-1'`, m.value) //nolint:gosec // column is a literal in this file
				}
				if err != nil {
					t.Fatalf("moving the run: %v", err)
				}
				walkID := run.WalkID
				if m.column == "walk_id" {
					walkID = m.value
				}
				switch path {
				case "GetWalkScanRun":
					_, _, err = s.GetWalkScanRun(ctx, run.ID)
				case "ListWalkScanRuns":
					_, err = s.ListWalkScanRuns(ctx, walkID)
				default:
					_, err = s.ListAllWalkScanRuns(ctx)
				}
				if got := vulnOutcome(err); got != "refused" {
					t.Fatalf("outcome %q, want refused", got)
				}
				if !strings.Contains(err.Error(), "walk_scan_runs") {
					t.Errorf("refusal %q does not name the table", err)
				}
			})
		}
	}
}
