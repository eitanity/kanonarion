package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

var (
	frameHost   = domain2.BuildFrame{GOOS: "linux", GOARCH: "amd64"}
	frameWasm   = domain2.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
	frameTinyGo = domain2.BuildFrame{
		GOOS: "wasip1", GOARCH: "wasm", GOARM: "6", TinyGoTarget: "wasip1", TinyGoVersion: "0.42.0",
		TinyGoTags: []string{"tinygo", "tinygo.wasm"},
	}
	frameLocal = coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
)

// framedLedgerRecord is ledgerRecord under a frame, its edge pointing at a
// callee named for it so an edge read shows which frame answered.
func framedLedgerRecord(t *testing.T, spec ledgerSpec, f domain2.BuildFrame) domain2.CallGraphRecord {
	t.Helper()
	r := ledgerRecord(t, spec)
	r.Frame = f
	r.ContentHash = ""
	sealed, err := domain2.CallGraphRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// The build frame is migration 17, counted in this adapter: five columns and
// one index.
func TestMigrations_FrameIsMigrationSeventeen(t *testing.T) {
	t.Parallel()
	migs := sqlite.Migrations()
	if n := len(migs); n != 17 {
		t.Fatalf("callgraph migrations = %d, want 17", n)
	}
	if last := migs[len(migs)-1]; last.Version != 17 {
		t.Errorf("last callgraph migration is %d, want 17", last.Version)
	}
	s := openTestStore(t)
	for _, col := range []string{"goos", "goarch", "goarm", "tinygo_target", "tinygo_version"} {
		if n := countRows(t, s, `SELECT COUNT(*) FROM pragma_table_info('callgraph_records') WHERE name = '`+col+`'`); n != 1 {
			t.Errorf("callgraph_records has %d column(s) named %s, want 1", n, col)
		}
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'callgraph_records_frame_idx'`); n != 1 {
		t.Error("the frame index is missing")
	}
}

// The frame columns are written from the record on insert.
func TestPutCallGraphRecord_WritesTheFrameColumns(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	rec := framedLedgerRecord(t, ledgerSpec{source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies}, frameTinyGo)
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	var goos, goarch, goarm, target, version string
	if err := s.InternalDB().DB().QueryRowContext(ctx,
		`SELECT goos, goarch, goarm, tinygo_target, tinygo_version FROM callgraph_records`).
		Scan(&goos, &goarch, &goarm, &target, &version); err != nil {
		t.Fatalf("reading the frame columns: %v", err)
	}
	if goos != "wasip1" || goarch != "wasm" || goarm != "6" || target != "wasip1" || version != "0.42.0" {
		t.Errorf("columns = %q %q %q %q %q", goos, goarch, goarm, target, version)
	}
}

// twoFrameStore holds a host and a wasip1 graph of testCoord, each with one edge
// into a callee named for its frame.
func twoFrameStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s := openTestStore(t)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, r := range []domain2.CallGraphRecord{
		framedLedgerRecord(t, ledgerSpec{source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
			completeness: domain2.CompletenessBuiltWithBodies, callee: "example.com/mod.Host", at: at}, frameHost),
		framedLedgerRecord(t, ledgerSpec{source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
			completeness: domain2.CompletenessBuiltWithBodies, callee: "example.com/mod.Wasm", at: at.Add(time.Hour)}, frameWasm),
	} {
		if err := s.PutCallGraphRecord(context.Background(), r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	return s
}

// callerCount is how many edges into callee the store serves.
func callerCount(t *testing.T, s *sqlite.Store, callee string) int {
	t.Helper()
	refs, err := s.FindCallers(context.Background(), callee, testPipeline, coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallers(%s): %v", callee, err)
	}
	return len(refs)
}

// A coordinate holding a host and a wasip1 graph answers each read frame from
// its own, on the composing read and on the edge read.
func TestReadFrame_EachFrameAnswersItsOwnRead(t *testing.T) {
	t.Parallel()
	s := twoFrameStore(t)
	for _, tc := range []struct {
		frame          domain2.BuildFrame
		callee, absent string
	}{{frameHost, "example.com/mod.Host", "example.com/mod.Wasm"}, {frameWasm, "example.com/mod.Wasm", "example.com/mod.Host"}} {
		s.WithReadFrame(tc.frame)
		rec, found, err := s.GetCallGraphRecord(context.Background(), testCoord, testPipeline)
		if err != nil || !found || !domain2.SameFrame(rec.Frame, tc.frame) {
			t.Fatalf("GetCallGraphRecord under %s = %s, %v, %v", tc.frame, rec.Frame, found, err)
		}
		if n := callerCount(t, s, tc.callee); n != 1 {
			t.Errorf("FindCallers(%s) under %s = %d edge(s), want that frame's one", tc.callee, tc.frame, n)
		}
		if n := callerCount(t, s, tc.absent); n != 0 {
			t.Errorf("FindCallers(%s) under %s = %d edge(s): the other frame's edge answered", tc.absent, tc.frame, n)
		}
	}
}

// A frame the ledger holds no graph of is no answer: the edge read omits the
// coordinate rather than reporting its rows orphaned, and with no read frame the
// two frames are refused by name.
func TestReadFrame_UnheldAndUndeclaredFrames(t *testing.T) {
	t.Parallel()
	s := twoFrameStore(t)
	ctx := context.Background()
	s.WithReadFrame(frameTinyGo)
	if _, found, err := s.GetCallGraphRecord(ctx, testCoord, testPipeline); err != nil || found {
		t.Errorf("a frame not held was served: found=%v err=%v", found, err)
	}
	if n := callerCount(t, s, "example.com/mod.Host"); n != 0 {
		t.Errorf("FindCallers under a frame not held = %d edge(s)", n)
	}
	if _, found, err := s.ForeignModulesBuilt(ctx, testCoord, testPipeline, ""); err != nil || found {
		t.Errorf("ForeignModulesBuilt under a frame not held: found=%v err=%v", found, err)
	}
	s.WithReadFrame(domain2.BuildFrame{})
	var c domain2.CallGraphConflict
	if _, _, err := s.GetCallGraphRecord(ctx, testCoord, testPipeline); !errors.As(err, &c) || c.Field != domain2.ConflictFieldFrame {
		t.Errorf("no read frame over two frames = %v, want a frame conflict", err)
	}
}

// One working tree holds a record per frame: the tree-scoped read and the
// sequence fast path each answer only from their own frame.
func TestWorktree_OneRecordPerFrame(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	spec := func(callee string, offset time.Duration) ledgerSpec {
		return ledgerSpec{coord: frameLocal, source: domain2.AnalysisSourceWorktree, worktree: "analysed-sha256:t",
			scanDigest: "scanned-sha256:t", root: "/src/app", completeness: domain2.CompletenessBuiltWithBodies,
			callee: callee, at: at.Add(offset)}
	}
	host := framedLedgerRecord(t, spec("example.com/mod.Host", 0), frameHost)
	tiny := framedLedgerRecord(t, spec("example.com/mod.Tiny", time.Hour), frameTinyGo)
	for _, r := range []domain2.CallGraphRecord{host, tiny} {
		if err := s.PutCallGraphRecord(ctx, r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	for _, tc := range []struct {
		frame domain2.BuildFrame
		want  string
	}{{frameHost, host.ContentHash}, {frameTinyGo, tiny.ContentHash}} {
		got, found, err := s.WorktreeGeneration(ctx, frameLocal, testPipeline, "/src/app", "scanned-sha256:t", tc.frame)
		if err != nil || !found || got.ContentHash != tc.want {
			t.Errorf("WorktreeGeneration under %s = %s, %v, %v", tc.frame, got.Frame, found, err)
		}
		s.WithReadFrame(tc.frame)
		served, found, err := s.GetCallGraphRecord(ctx, frameLocal, testPipeline)
		if err != nil || !found || served.ContentHash != tc.want {
			t.Errorf("the newest-row read under %s served %s (%v, %v)", tc.frame, served.Frame, found, err)
		}
	}
	if _, found, err := s.WorktreeGeneration(ctx, frameLocal, testPipeline, "/src/app", "scanned-sha256:t", frameWasm); err != nil || found {
		t.Errorf("a frame the tree was never analysed under was reused: found=%v err=%v", found, err)
	}
	// The fast path stands aside for a read naming no frame, so the refusal is
	// raised rather than the newest frame answering.
	s.WithReadFrame(domain2.BuildFrame{})
	var c domain2.CallGraphConflict
	if _, _, err := s.GetCallGraphRecord(ctx, frameLocal, testPipeline); !errors.As(err, &c) || c.Field != domain2.ConflictFieldFrame {
		t.Errorf("no read frame over a tree analysed in two frames = %v, want a frame conflict", err)
	}
}

// A coordinate held at the asked pipeline only under other frames is unserved
// and names them from the frame columns; one the read frame holds is served,
// and with no read frame set nothing is said about frames.
func TestUnservedCoordinates_OtherFrames(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	wasmOnly := coordinatetest.MustNew("example.com/wasm", "v1.0.0")
	both := coordinatetest.MustNew("example.com/both", "v1.0.0")
	for _, c := range []struct {
		coord coordinate.ModuleCoordinate
		frame domain2.BuildFrame
	}{{wasmOnly, frameWasm}, {wasmOnly, frameTinyGo}, {both, frameWasm}, {both, frameHost}} {
		rec := framedLedgerRecord(t, ledgerSpec{coord: c.coord, source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:" + c.frame.String(),
			completeness: domain2.CompletenessBuiltWithBodies}, c.frame)
		if err := s.PutCallGraphRecord(ctx, rec); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	pv := framedLedgerRecord(t, ledgerSpec{coord: both, source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:x",
		completeness: domain2.CompletenessBuiltWithBodies}, frameHost).PipelineVersion

	if got, err := s.UnservedCoordinates(ctx, []coordinate.ModuleCoordinate{wasmOnly, both}, pv); err != nil || len(got) != 0 {
		t.Errorf("with no read frame: %+v, %v", got, err)
	}
	s.WithReadFrame(frameHost)
	got, err := s.UnservedCoordinates(ctx, []coordinate.ModuleCoordinate{wasmOnly, both}, pv)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Coordinate != wasmOnly || len(got[0].Frames) != 2 {
		t.Fatalf("unserved = %+v", got)
	}
	for _, f := range got[0].Frames {
		if !domain2.SameFrame(f, frameWasm) && !domain2.SameFrame(f, frameTinyGo) {
			t.Errorf("unexpected frame %+v", f)
		}
	}
}
