package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// A genuine sealed call graph filed under a key or a selection value its seal
// does not carry must be refused by every read that decodes it. Two published
// records and two working-tree records are held; each mutation moves one of
// them and every read path is asked for it.

var (
	misfiledText  = coordinatetest.MustNew("golang.org/x/text", "v0.3.0")
	misfiledULID  = coordinatetest.MustNew("github.com/oklog/ulid/v2", "v2.1.2")
	misfiledApp   = coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	misfiledOther = coordinatetest.MustNew("example.com/other", coordinate.LocalVersion)
)

// cgAsk is what a read asks for after a mutation.
type cgAsk struct {
	pipeline, root, scanDigest string
	frame                      domain2.BuildFrame
}

type cgMutation struct {
	name   string
	column string // empty: the key swap
	value  string
	ask    func(*cgAsk)
	fresh  func(*domain2.CallGraphRecord)
}

func cgMutations(local bool) []cgMutation {
	ms := []cgMutation{
		{name: "key swap", ask: func(*cgAsk) {}, fresh: func(*domain2.CallGraphRecord) {}},
		{name: "pipeline_version", column: "pipeline_version", value: "9.9.9",
			ask: func(a *cgAsk) { a.pipeline = "9.9.9" }, fresh: func(r *domain2.CallGraphRecord) { r.PipelineVersion = "9.9.9" }},
		{name: "goos", column: "goos", value: "windows",
			ask: func(a *cgAsk) { a.frame.GOOS = "windows" }, fresh: func(r *domain2.CallGraphRecord) { r.Frame.GOOS = "windows" }},
		{name: "goarch", column: "goarch", value: "arm64",
			ask: func(a *cgAsk) { a.frame.GOARCH = "arm64" }, fresh: func(r *domain2.CallGraphRecord) { r.Frame.GOARCH = "arm64" }},
		{name: "goarm", column: "goarm", value: "7",
			ask: func(a *cgAsk) { a.frame.GOARM = "7" }, fresh: func(r *domain2.CallGraphRecord) { r.Frame.GOARM = "7" }},
		{name: "tinygo_target", column: "tinygo_target", value: "wasip1",
			ask: func(a *cgAsk) { a.frame.TinyGoTarget = "wasip1" }, fresh: func(r *domain2.CallGraphRecord) { r.Frame.TinyGoTarget = "wasip1" }},
	}
	if local {
		ms = append(ms,
			cgMutation{name: "analysis_root", column: "analysis_root", value: "/src/moved",
				ask: func(a *cgAsk) { a.root = "/src/moved" }, fresh: func(r *domain2.CallGraphRecord) { r.AnalysisRoot = "/src/moved" }},
			cgMutation{name: "worktree_scan_digest", column: "worktree_scan_digest", value: "scanned-sha256:moved",
				ask:   func(a *cgAsk) { a.scanDigest = "scanned-sha256:moved" },
				fresh: func(r *domain2.CallGraphRecord) { r.WorktreeScanDigest = "scanned-sha256:moved" }})
	}
	return ms
}

func cgFrameColumn(column string) bool {
	return column == "goos" || column == "goarch" || column == "goarm" || column == "tinygo_target"
}

// misfiledStore holds the four records and returns the two each scenario moves.
func misfiledStore(ctx context.Context, t *testing.T) (*sqlite.Store, map[string]domain2.CallGraphRecord) {
	t.Helper()
	s := openTestStore(t)
	zip := func(c coordinate.ModuleCoordinate, callee string) domain2.CallGraphRecord {
		r := framedLedgerRecord(t, ledgerSpec{coord: c, source: domain2.AnalysisSourceModuleZip,
			artefact: "zip:h1:" + c.Path(), completeness: domain2.CompletenessBuiltWithBodies, callee: callee}, frameHost)
		return r
	}
	tree := func(c coordinate.ModuleCoordinate, name, callee string) domain2.CallGraphRecord {
		return framedLedgerRecord(t, ledgerSpec{coord: c, source: domain2.AnalysisSourceWorktree,
			worktree: "analysed-sha256:" + name, scanDigest: "scanned-sha256:" + name, root: "/src/" + name,
			completeness: domain2.CompletenessBuiltWithBodies, callee: callee}, frameHost)
	}
	recs := map[string]domain2.CallGraphRecord{
		"text":  zip(misfiledText, "example.com/mod.Text"),
		"ulid":  zip(misfiledULID, "example.com/mod.ULID"),
		"app":   tree(misfiledApp, "app", "example.com/mod.App"),
		"other": tree(misfiledOther, "other", "example.com/mod.Other"),
	}
	for _, r := range recs {
		if err := s.PutCallGraphRecord(ctx, r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	return s, recs
}

// move applies m to target's row; the key swap files from's blob and seal there.
func (m cgMutation) move(t *testing.T, s *sqlite.Store, target, from domain2.CallGraphRecord) {
	t.Helper()
	db := s.InternalDB().DB()
	var err error
	if m.column == "" {
		_, err = db.Exec(`UPDATE callgraph_records SET serialised = ?, content_hash = ?
WHERE content_hash = ?`, mustBlob(t, s, from.ContentHash), from.ContentHash, target.ContentHash)
	} else {
		_, err = db.Exec(`UPDATE callgraph_records SET `+m.column+` = ? WHERE content_hash = ?`, m.value, target.ContentHash) //nolint:gosec // column is a literal in this file
	}
	if err != nil {
		t.Fatalf("moving the row: %v", err)
	}
}

func mustBlob(t *testing.T, s *sqlite.Store, hash string) []byte {
	t.Helper()
	var b []byte
	if err := s.InternalDB().DB().QueryRow(`SELECT serialised FROM callgraph_records WHERE content_hash = ?`, hash).Scan(&b); err != nil {
		t.Fatalf("reading the blob: %v", err)
	}
	return b
}

func resealCallGraph(t *testing.T, r domain2.CallGraphRecord) domain2.CallGraphRecord {
	t.Helper()
	r.ContentHash = ""
	sealed, err := domain2.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

func requireMisfiled(t *testing.T, err error) {
	t.Helper()
	var misfiled *recordseal.Misfiled
	if !errors.As(err, &misfiled) || !errors.Is(err, ports.ErrCallGraphIntegrity) {
		t.Fatalf("err = %v, want a misfiled refusal under ErrCallGraphIntegrity", err)
	}
	if misfiled.Table != "callgraph_records" || !strings.Contains(err.Error(), "no kanonarion command clears it") {
		t.Errorf("refusal %q does not name the table and the remedy", err)
	}
}

func TestMisfiled_PublishedReadsRefuseAMovedRecord(t *testing.T) {
	ctx := context.Background()
	paths := []struct {
		name string
		// framed reports whether the path selects on the frame.
		framed bool
		read   func(*testing.T, *sqlite.Store, cgAsk, domain2.CallGraphRecord) error
	}{
		{"GetCallGraphRecord", false, func(_ *testing.T, s *sqlite.Store, a cgAsk, r domain2.CallGraphRecord) error {
			_, _, err := s.GetCallGraphRecord(ctx, r.Coordinate, a.pipeline)
			return err
		}},
		{"GetCallGraphRecordFrom", true, func(_ *testing.T, s *sqlite.Store, a cgAsk, r domain2.CallGraphRecord) error {
			_, _, err := s.GetCallGraphRecordFrom(ctx, r.Coordinate, a.pipeline, domain2.ComposeRequest{Frame: a.frame})
			return err
		}},
		{"ListCallGraphRecordsFor", false, func(_ *testing.T, s *sqlite.Store, a cgAsk, r domain2.CallGraphRecord) error {
			_, err := s.ListCallGraphRecordsFor(ctx, r.Coordinate, a.pipeline)
			return err
		}},
		{"LatestCallGraphOutcome", false, func(_ *testing.T, s *sqlite.Store, a cgAsk, r domain2.CallGraphRecord) error {
			_, _, err := s.LatestCallGraphOutcome(ctx, r.Coordinate, a.pipeline)
			return err
		}},
		{"IdenticalGeneration", true, nil},
	}
	for _, m := range cgMutations(false) {
		for _, p := range paths {
			t.Run(m.name+"/"+p.name, func(t *testing.T) {
				s, recs := misfiledStore(ctx, t)
				target := recs["text"]
				m.move(t, s, target, recs["ulid"])
				ask := cgAsk{pipeline: testPipeline, frame: frameHost}
				m.ask(&ask)
				var err error
				if p.read == nil {
					fresh := target
					m.fresh(&fresh)
					_, _, err = s.IdenticalGeneration(ctx, resealCallGraph(t, fresh))
				} else {
					err = p.read(t, s, ask, target)
				}
				if cgFrameColumn(m.column) && !p.framed {
					if err != nil {
						t.Fatalf("a read that does not select on %s failed: %v", m.column, err)
					}
					return
				}
				requireMisfiled(t, err)
			})
		}
	}
}

func TestMisfiled_WorktreeReadsRefuseAMovedRecord(t *testing.T) {
	ctx := context.Background()
	for _, m := range cgMutations(true) {
		for _, path := range []string{"GetCallGraphRecord", "WorktreeGeneration"} {
			t.Run(m.name+"/"+path, func(t *testing.T) {
				s, recs := misfiledStore(ctx, t)
				target := recs["app"]
				m.move(t, s, target, recs["other"])
				ask := cgAsk{pipeline: testPipeline, frame: frameHost, root: target.AnalysisRoot, scanDigest: target.WorktreeScanDigest}
				m.ask(&ask)
				var err error
				if path == "GetCallGraphRecord" {
					// The newest-row path: the row's own root and digest choose it.
					s.WithReadFrame(ask.frame)
					_, _, err = s.GetCallGraphRecord(ctx, target.Coordinate, ask.pipeline)
				} else {
					_, _, err = s.WorktreeGeneration(ctx, target.Coordinate, ask.pipeline, ask.root, ask.scanDigest, ask.frame)
				}
				requireMisfiled(t, err)
			})
		}
	}
}
