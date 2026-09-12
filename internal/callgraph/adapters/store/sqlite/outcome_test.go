package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// makeWideRecord builds a record with edges edges, so a test can measure what a
// read costs as a function of the graph rather than assert it from the shape of
// the code.
func makeWideRecord(coord coordinate.ModuleCoordinate, pv string, at time.Time, edges int) domain2.CallGraphRecord {
	var h domain2.CallGraphRecordHasher
	nodes := []domain2.CallNode{{
		ID:      coord.Path() + ".Root",
		Module:  coord.Path(),
		Package: coord.Path(),
		Symbol:  "Root",
	}}
	es := make([]domain2.CallEdge, 0, edges)
	for i := range edges {
		es = append(es, domain2.CallEdge{
			FromID:     coord.Path() + ".Root",
			ToID:       fmt.Sprintf("%s.Callee%06d", coord.Path(), i),
			CallSite:   domain2.SourcePosition{File: "root.go", Line: i},
			Confidence: domain2.ConfidenceDirect,
		})
	}
	r := domain2.CallGraphRecord{
		SchemaVersion:    domain2.CallGraphSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Algorithm:        domain2.AlgorithmCHA,
		Nodes:            nodes,
		Edges:            es,
		OverallStatus:    domain2.CallGraphStatusExtracted,
		Completeness:     domain2.CompletenessBuiltWithBodies,
		NodeCount:        len(nodes),
		EdgeCount:        len(es),
		ExtractedAt:      at,
		PipelineVersion:  pv,
		AnalysisSource:   domain2.AnalysisSourceModuleZip,
		ArtefactIdentity: "zip:h1:" + coord.Path() + "@" + coord.Version(),
	}
	hashed, err := h.SetContentHash(r)
	if err != nil {
		panic("SetContentHash: " + err.Error())
	}
	return hashed
}

func TestLatestCallGraphOutcome_NamesTheNewestGeneration(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	older := makeRecord(testCoord, "0.1.0")
	newer := makeRecord(testCoord, "0.1.0")
	newer.ExtractedAt = testTime.Add(time.Hour)
	newer.OverallStatus = domain2.CallGraphStatusLoadFailed
	newer.FailureCause = domain2.FailureCauseModule
	newer.FailureDetail = "no packages found"
	newer.NodeCount = 0
	newer.EdgeCount = 0
	newer.Nodes = nil
	newer.Edges = nil
	var h domain2.CallGraphRecordHasher
	newer, err := h.SetContentHash(newer)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	for _, r := range []domain2.CallGraphRecord{older, newer} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	got, found, oerr := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0")
	if oerr != nil || !found {
		t.Fatalf("LatestCallGraphOutcome = (_, %v, %v), want found", found, oerr)
	}
	if got.ContentHash != newer.ContentHash {
		t.Errorf("ContentHash = %q, want the newest generation's %q", got.ContentHash, newer.ContentHash)
	}
	if got.OverallStatus != domain2.CallGraphStatusLoadFailed {
		t.Errorf("OverallStatus = %v, want LoadFailed", got.OverallStatus)
	}
	if got.FailureCause != domain2.FailureCauseModule {
		t.Errorf("FailureCause = %q, want module", got.FailureCause)
	}
	if got.FailureDetail != "no packages found" {
		t.Errorf("FailureDetail = %q, want the newest generation's detail", got.FailureDetail)
	}

	// The control that makes the assertion above mean something: composition, on
	// this same ledger, names no generation at all. Two analyses of one artefact
	// disagree, which composition must not resolve by picking — a correct refusal
	// to a reader, and no answer whatever to a stage confirming its own write.
	// The narrow read is not a cheaper route to the composed answer; it is the
	// answer to the other question.
	_, cfound, cerr := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if !errors.Is(cerr, ports.ErrCallGraphConflict) {
		t.Fatalf("GetCallGraphRecord = (_, %v, %v), want a conflict: without one this ledger does not "+
			"distinguish the two questions and the assertions above prove nothing", cfound, cerr)
	}
}

func TestLatestCallGraphOutcome_AbsencesAndRefusals(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	t.Run("a ledger holding nothing reports absence, not an error", func(t *testing.T) {
		_, found, err := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0")
		if err != nil {
			t.Fatalf("LatestCallGraphOutcome: %v", err)
		}
		if found {
			t.Error("found = true on an empty ledger")
		}
	})

	t.Run("the zero coordinate is refused", func(t *testing.T) {
		_, _, err := s.LatestCallGraphOutcome(ctx, coordinate.ModuleCoordinate{}, "0.1.0")
		if !errors.Is(err, coordinate.ErrZeroCoordinate) {
			t.Errorf("err = %v, want ErrZeroCoordinate", err)
		}
	})
}

func TestLatestCallGraphOutcome_RefusesABlobFiledUnderAnotherHash(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	// The seal cannot be recomputed without the edges, so the half that can be
	// checked is that the blob's own hash is the key it was filed under. Move the
	// key and the read must refuse rather than attribute this generation's status
	// to another's seal.
	if _, err := s.InternalDB().DB().ExecContext(ctx,
		`UPDATE callgraph_records SET content_hash = ? WHERE module_path = ?`,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", testCoord.Path(),
	); err != nil {
		t.Fatalf("moving the row's key: %v", err)
	}

	_, _, err := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0")
	if !errors.Is(err, ports.ErrCallGraphIntegrity) {
		t.Errorf("err = %v, want ErrCallGraphIntegrity", err)
	}
}

// TestLatestCallGraphOutcome_DoesNotPayForTheGraph is the measurement the whole
// change exists for.
//
// The composed read reconstructs every edge of every generation and re-marshals
// the result to verify the seal, so learning a status through it costs memory
// proportional to the graph — and to how many times the coordinate has been
// re-analysed. The narrow read decodes one blob, which at the current schema
// carries no edges at all.
//
// It asserts a ratio rather than an absolute, because the absolute is the Go
// allocator's business and the ratio is the property being fixed. Both arms run
// against the same store, the same coordinate and the same generation.
func TestLatestCallGraphOutcome_DoesNotPayForTheGraph(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const edges = 40000
	rec := makeWideRecord(testCoord, "0.1.0", testTime, edges)
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	measure := func(read func()) uint64 {
		read() // warm anything cached, so the figure is the read and not the first one
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		read()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	composed := measure(func() {
		if _, _, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0"); err != nil {
			t.Fatalf("GetCallGraphRecord: %v", err)
		}
	})
	narrow := measure(func() {
		if _, _, err := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0"); err != nil {
			t.Fatalf("LatestCallGraphOutcome: %v", err)
		}
	})

	// The control: the composed read must actually be expensive on this record,
	// or the comparison below is between two cheap things and says nothing.
	if composed < uint64(edges)*100 {
		t.Fatalf("the composed read allocated %d bytes for %d edges, which is too little for this "+
			"test to be measuring what it claims", composed, edges)
	}
	if narrow*20 > composed {
		t.Errorf("the narrow read allocated %d bytes against the composed read's %d; it is supposed to "+
			"pay for one blob, not for the graph", narrow, composed)
	}
}

// TestLatestCallGraphOutcome_CostDoesNotGrowWithTheHistory pins the half of the
// defect that made it unbounded rather than merely large.
//
// A composed read loads EVERY generation the coordinate holds, so a coordinate
// re-analysed twelve times costs twelve reconstructions to answer one question,
// and the next run makes it thirteen. The narrow read reads one row whatever the
// history.
func TestLatestCallGraphOutcome_CostDoesNotGrowWithTheHistory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const edges = 20000
	const generations = 6
	for i := range generations {
		rec := makeWideRecord(testCoord, "0.1.0", testTime.Add(time.Duration(i)*time.Hour), edges)
		if err := s.PutCallGraphRecord(ctx, rec); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}

	alloc := func(read func()) uint64 {
		read()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		read()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	oneGeneration := func() uint64 {
		single := openTestStore(t)
		rec := makeWideRecord(testCoord, "0.1.0", testTime, edges)
		if err := single.PutCallGraphRecord(ctx, rec); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
		return alloc(func() {
			if _, _, err := single.GetCallGraphRecord(ctx, testCoord, "0.1.0"); err != nil {
				t.Fatalf("GetCallGraphRecord: %v", err)
			}
		})
	}()

	manyGenerations := alloc(func() {
		if _, _, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0"); err != nil {
			t.Fatalf("GetCallGraphRecord: %v", err)
		}
	})
	narrow := alloc(func() {
		if _, _, err := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0"); err != nil {
			t.Fatalf("LatestCallGraphOutcome: %v", err)
		}
	})

	// The control: composing a six-generation coordinate must cost multiples of
	// composing a one-generation one, or "the cost grows with the history" is not
	// the thing this ledger does and the assertion below is empty.
	if manyGenerations < oneGeneration*3 {
		t.Fatalf("composing %d generations allocated %d bytes against one generation's %d; the history "+
			"term this test is about is not present", generations, manyGenerations, oneGeneration)
	}
	if narrow >= oneGeneration {
		t.Errorf("the narrow read allocated %d bytes on a %d-generation ledger, which is not less than "+
			"the cost of composing a single generation (%d)", narrow, generations, oneGeneration)
	}
}

// A generation written at an older record schema reports absence, not a
// measurement. A stale shape decodes with every later field at its zero value,
// and reading those zeros back as a status is the failure the schema gate
// exists to prevent — so the narrow read applies the same gate the composing
// read does.
func TestLatestCallGraphOutcome_AStaleSchemaIsAbsent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	var h domain2.CallGraphRecordHasher
	stale := rec
	stale.SchemaVersion = "0"
	stale.Edges = nil // the stored blob omits edges at every schema
	raw, err := h.Marshal(stale)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := s.InternalDB().DB().ExecContext(ctx,
		`UPDATE callgraph_records SET serialised = ? WHERE content_hash = ?`,
		blobcodec.Encode(raw), rec.ContentHash,
	); err != nil {
		t.Fatalf("rewriting the row's blob: %v", err)
	}

	_, found, oerr := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0")
	if oerr != nil {
		t.Fatalf("LatestCallGraphOutcome: %v", oerr)
	}
	if found {
		t.Error("a generation at an older record schema was reported as a measurement")
	}
}

// A blob that is not a blob stops the read rather than reporting absence: a row
// that cannot be decoded is a fault, and "no record here" is the wrong answer to
// a coordinate the ledger holds a row for.
func TestLatestCallGraphOutcome_AnUndecodableBlobIsAnError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	if _, err := s.InternalDB().DB().ExecContext(ctx,
		`UPDATE callgraph_records SET serialised = ? WHERE content_hash = ?`,
		[]byte("not a blob"), rec.ContentHash,
	); err != nil {
		t.Fatalf("rewriting the row's blob: %v", err)
	}

	if _, found, err := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0"); err == nil {
		t.Errorf("an undecodable row read as (found=%v, err=nil)", found)
	}
}

// A blob that decodes to something that is not a record stops the read too: the
// envelope being intact says nothing about what is inside it.
func TestLatestCallGraphOutcome_ABlobThatIsNotARecordIsAnError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	if _, err := s.InternalDB().DB().ExecContext(ctx,
		`UPDATE callgraph_records SET serialised = ? WHERE content_hash = ?`,
		blobcodec.Encode([]byte("{not json")), rec.ContentHash,
	); err != nil {
		t.Fatalf("rewriting the row's blob: %v", err)
	}

	if _, found, err := s.LatestCallGraphOutcome(ctx, testCoord, "0.1.0"); err == nil {
		t.Errorf("a blob that is not a record read as (found=%v, err=nil)", found)
	}
}
