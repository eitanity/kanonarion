package sqlite_test

import (
	"context"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// TestEdgeKindSurvivesTheStore is the seam the whole feature hangs on. Edges are
// reconstructed from the satellite table rather than the sealed blob, so a kind
// the writer records and the reader does not select comes back as a call — and
// every registration silently becomes an invocation on the way out.
func TestEdgeKindSurvivesTheStore(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const (
		mount   = "example.com/mod.MountRoutes"
		confirm = "example.com/mod.(*H).confirmEmail"
		helper  = "example.com/mod.helper"
	)
	var h domain2.CallGraphRecordHasher
	rec := domain2.CallGraphRecord{
		SchemaVersion:  domain2.CallGraphSchemaVersion,
		Ecosystem:      fetchdomain.EcosystemGo,
		Coordinate:     testCoord,
		Algorithm:      domain2.AlgorithmCHA,
		Completeness:   domain2.CompletenessBuiltWithBodies,
		ReferenceScope: domain2.ReferenceScopeAnalysed,
		Nodes: []domain2.CallNode{
			{ID: mount, Module: "example.com/mod", Package: "example.com/mod", Symbol: "MountRoutes"},
			{ID: confirm, Module: "example.com/mod", Package: "example.com/mod", Receiver: "*H", Symbol: "confirmEmail"},
			{ID: helper, Module: "example.com/mod", Package: "example.com/mod", Symbol: "helper"},
		},
		Edges: []domain2.CallEdge{
			{FromID: mount, ToID: confirm, Confidence: domain2.ConfidenceDirect, Kind: domain2.EdgeKindReference,
				CallSite: domain2.SourcePosition{File: "mod.go", Line: 10}},
			{FromID: mount, ToID: helper, Confidence: domain2.ConfidenceDirect,
				CallSite: domain2.SourcePosition{File: "mod.go", Line: 11}},
		},
		OverallStatus:    domain2.CallGraphStatusExtracted,
		NodeCount:        3,
		EdgeCount:        2,
		ExtractedAt:      testTime,
		PipelineVersion:  "0.3.0",
		ArtefactIdentity: "zip:h1:" + testCoord.Path() + "@" + testCoord.Version(),
	}
	rec.Sort()
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	// The record read: the kind must come back on the reconstructed edge, and
	// the record must still verify against the hash it was written with.
	got, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.3.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: found=%v err=%v", found, err)
	}
	if !got.ReferenceScope.IsMeasured() {
		t.Errorf("ReferenceScope = %q after a store round trip", got.ReferenceScope)
	}
	kinds := map[string]domain2.EdgeKind{}
	for _, e := range got.Edges {
		kinds[e.ToID] = e.Kind
	}
	if !kinds[confirm].IsReference() {
		t.Errorf("the registration came back as %q, not a reference", kinds[confirm])
	}
	if kinds[helper].IsReference() {
		t.Errorf("the call came back tagged a reference")
	}

	// The edge query read, which answers `callers` and never loads the record.
	refs, err := s.FindCallers(ctx, confirm, "0.3.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallers: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("got %d callers, want 1", len(refs))
	}
	if !refs[0].Kind.IsReference() {
		t.Errorf("FindCallers dropped the kind: %+v", refs[0])
	}

	// The control beside it: the call edge still reads as a call through the
	// same query, so the kind is being carried rather than defaulted.
	callRefs, err := s.FindCallers(ctx, helper, "0.3.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallers: %v", err)
	}
	if len(callRefs) != 1 || callRefs[0].Kind.IsReference() {
		t.Errorf("the call edge did not read back as a call: %+v", callRefs)
	}
}
