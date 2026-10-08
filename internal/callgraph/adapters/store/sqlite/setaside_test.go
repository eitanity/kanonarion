package sqlite_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// A generation written by a build whose canonical shape differs hashes to its
// own seal, but this build cannot re-marshal it. These tests build one by hand,
// because a store written by one build never holds one.

// setAsideSink records what the store names through ReportSetAside.
type setAsideSink struct {
	mu   sync.Mutex
	rows []recordseal.SetAsideRow
}

func (s *setAsideSink) report(rows []recordseal.SetAsideRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, rows...)
}

func (s *setAsideSink) hashes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, r.ContentHash)
	}
	return out
}

// generationAt is one zip-sourced generation of testCoord; generations at
// different times state the same graph, so composition serves the newest.
func generationAt(t *testing.T, at time.Time) domain2.CallGraphRecord {
	t.Helper()
	return ledgerRecord(t, ledgerSpec{
		source:       domain2.AnalysisSourceModuleZip,
		completeness: domain2.CompletenessBuiltWithBodies,
		artefact:     "zip:h1:example.com/mod@v1.0.0",
		at:           at,
	})
}

// widen prepends a top-level member this build has no field for.
func widen(canonical []byte) []byte {
	return append([]byte(`{"retired_field":"a shape this build never had",`), canonical[1:]...)
}

// driftStored rewrites rec's stored row the way a build with one more top-level
// field would have written it: sealed over the full record including its edges,
// stored without them, and the edge rows re-keyed to the new seal. It returns
// the new seal.
func driftStored(t *testing.T, s *sqlite.Store, rec domain2.CallGraphRecord) string {
	t.Helper()
	var h domain2.CallGraphRecordHasher
	unsealed := rec
	unsealed.ContentHash = ""
	full, err := h.Marshal(unsealed)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	sum := sha256.Sum256(widen(full))
	seal := "sha256:" + hex.EncodeToString(sum[:])

	stored := rec
	stored.ContentHash = seal
	stored.Edges = nil
	blob, err := h.Marshal(stored)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	db := s.InternalDB().DB()
	if _, err := db.ExecContext(t.Context(),
		`UPDATE callgraph_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blobcodec.Encode(widen(blob)), seal, rec.ContentHash); err != nil {
		t.Fatalf("installing the drifted row: %v", err)
	}
	if _, err := db.ExecContext(t.Context(),
		`UPDATE callgraph_edges SET record_content_hash = ? WHERE record_content_hash = ?`,
		seal, rec.ContentHash); err != nil {
		t.Fatalf("re-keying the drifted row's edges: %v", err)
	}
	return seal
}

// driftedLedger holds two readable generations and, newest, a drifted one.
func driftedLedger(t *testing.T) (*sqlite.Store, *setAsideSink, domain2.CallGraphRecord, domain2.CallGraphRecord, string) {
	t.Helper()
	s := openTestStore(t)
	sink := &setAsideSink{}
	s.ReportSetAside(sink.report)
	older := generationAt(t, testTime)
	newer := generationAt(t, testTime.Add(time.Hour))
	odd := generationAt(t, testTime.Add(2*time.Hour))
	for _, r := range []domain2.CallGraphRecord{older, newer, odd} {
		if err := s.PutCallGraphRecord(t.Context(), r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	return s, sink, newer, odd, driftStored(t, s, odd)
}

// TestDriftedGeneration_ComposedAroundAndNamed is the regression: the composed
// read serves the newest readable generation, names the drifted one, and is not
// an integrity failure.
func TestDriftedGeneration_ComposedAroundAndNamed(t *testing.T) {
	s, sink, newer, _, seal := driftedLedger(t)

	got, found, err := s.GetCallGraphRecord(t.Context(), testCoord, testPipeline)
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord = (found %v, %v), want the composed record", found, err)
	}
	if got.ContentHash != newer.ContentHash {
		t.Errorf("served %s, want the newest readable generation %s", got.ContentHash, newer.ContentHash)
	}
	if hs := sink.hashes(); len(hs) != 1 || hs[0] != seal {
		t.Fatalf("set aside %v, want exactly the drifted generation %s", hs, seal)
	}
	row := sink.rows[0]
	if row.Kind != "call graph record" || row.ID != testCoord.String() || row.Generation.PipelineVersion != testPipeline {
		t.Errorf("set-aside row = %+v, want it named by kind, coordinate and pipeline", row)
	}
	if !errors.Is(row.Reason, recordseal.ErrGenerationDrift) || errors.Is(row.Reason, ports.ErrCallGraphIntegrity) {
		t.Errorf("reason = %v, want drift and never the integrity sentinel", row.Reason)
	}

	history, err := s.ListCallGraphRecordsFor(t.Context(), testCoord, testPipeline)
	if err != nil || len(history) != 2 {
		t.Fatalf("ListCallGraphRecordsFor = (%d, %v), want the two readable generations", len(history), err)
	}
}

// TestDriftedGeneration_EdgeQueryOmitsNothingReadable covers the edge read: a
// coordinate holding several generations resolves the served one through the
// same composition, so its rows still answer.
func TestDriftedGeneration_EdgeQueryOmitsNothingReadable(t *testing.T) {
	s, sink, _, _, seal := driftedLedger(t)

	refs, err := s.FindCallers(t.Context(), "example.com/mod.Bar", testPipeline, coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil || len(refs) != 1 {
		t.Fatalf("FindCallers = (%d refs, %v), want the served generation's one edge", len(refs), err)
	}
	if hs := sink.hashes(); len(hs) == 0 || hs[0] != seal {
		t.Errorf("set aside %v, want the drifted generation %s named", hs, seal)
	}
}

// TestDriftedGeneration_IdenticalCheckSkipsAndNames covers the write leg's
// comparison: a drifted generation cannot be shown to restate a new measurement,
// so it is skipped and named rather than ending the write.
func TestDriftedGeneration_IdenticalCheckSkipsAndNames(t *testing.T) {
	s, sink, _, odd, seal := driftedLedger(t)

	held, found, err := s.IdenticalGeneration(t.Context(), odd)
	if err != nil {
		t.Fatalf("IdenticalGeneration: %v", err)
	}
	if found && held.ContentHash == seal {
		t.Errorf("the drifted generation was offered as restating the measurement")
	}
	named := false
	for _, h := range sink.hashes() {
		named = named || h == seal
	}
	if !named {
		t.Errorf("set aside %v, want the drifted generation %s named", sink.hashes(), seal)
	}
}

// TestEveryGenerationDrifted_NothingServable: with nothing this build can
// reproduce, the answer is no servable record, not absence and not tampering.
func TestEveryGenerationDrifted_NothingServable(t *testing.T) {
	s := openTestStore(t)
	sink := &setAsideSink{}
	s.ReportSetAside(sink.report)
	only := generationAt(t, testTime)
	if err := s.PutCallGraphRecord(t.Context(), only); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	seal := driftStored(t, s, only)

	_, found, err := s.GetCallGraphRecord(t.Context(), testCoord, testPipeline)
	var nothing *recordseal.NothingServable
	if found || !errors.As(err, &nothing) {
		t.Fatalf("GetCallGraphRecord = (found %v, %v), want *recordseal.NothingServable", found, err)
	}
	if errors.Is(err, ports.ErrCallGraphIntegrity) || !errors.Is(err, recordseal.ErrGenerationDrift) {
		t.Errorf("error = %v, want drift and never the integrity sentinel", err)
	}
	if len(nothing.Aside.Rows) != 1 || nothing.Aside.Rows[0].ContentHash != seal {
		t.Errorf("set aside %v, want the drifted generation %s", nothing.Aside.Rows, seal)
	}
}

// TestAlteredGeneration_StillAnIntegrityFailure is the control: bytes that no
// longer hash to their seal — in the blob or in the edge rows — are not excused.
func TestAlteredGeneration_StillAnIntegrityFailure(t *testing.T) {
	for name, alter := range map[string]func(*testing.T, *sqlite.Store, string){
		"blob byte flipped": func(t *testing.T, s *sqlite.Store, seal string) {
			t.Helper()
			db := s.InternalDB().DB()
			var stored []byte
			if err := db.QueryRowContext(t.Context(),
				`SELECT serialised FROM callgraph_records WHERE content_hash = ?`, seal).Scan(&stored); err != nil {
				t.Fatalf("reading the row: %v", err)
			}
			raw, err := blobcodec.Decode(stored)
			if err != nil {
				t.Fatalf("decoding the row: %v", err)
			}
			at := bytes.Index(raw, []byte("a shape this build never had"))
			raw[at] = 'A'
			if _, err := db.ExecContext(t.Context(),
				`UPDATE callgraph_records SET serialised = ? WHERE content_hash = ?`, blobcodec.Encode(raw), seal); err != nil {
				t.Fatalf("altering the row: %v", err)
			}
		},
		"edge row altered": func(t *testing.T, s *sqlite.Store, seal string) {
			t.Helper()
			if _, err := s.InternalDB().DB().ExecContext(t.Context(),
				`UPDATE callgraph_edges SET call_site_line = call_site_line + 1 WHERE record_content_hash = ?`, seal); err != nil {
				t.Fatalf("altering the edge: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, sink, _, _, seal := driftedLedger(t)
			alter(t, s, seal)

			_, _, err := s.GetCallGraphRecord(t.Context(), testCoord, testPipeline)
			if !errors.Is(err, ports.ErrCallGraphIntegrity) || errors.Is(err, recordseal.ErrGenerationDrift) {
				t.Fatalf("GetCallGraphRecord = %v, want the integrity refusal and no drift", err)
			}
			if hs := sink.hashes(); len(hs) != 0 {
				t.Errorf("an altered generation was set aside: %v", hs)
			}
		})
	}
}
