package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// edgeQuerySurface is one command that resolves a symbol to its module before
// it looks at an edge.
type edgeQuerySurface struct {
	name string
	// query is the symbol this surface is asked about in the fixture below: the
	// interface for implementers, the function for the rest.
	query string
	run   func(context.Context, string, QueryCallGraphUseCase, *bytes.Buffer) error
}

// edgeQuerySurfaces is every such command. They are exercised together because
// the cost being pinned is a property of that shared resolution, and a fix
// applied to one of them closes nothing.
func edgeQuerySurfaces() []edgeQuerySurface {
	return []edgeQuerySurface{
		{"callers", rootSymbol, func(ctx context.Context, sym string, uc QueryCallGraphUseCase, buf *bytes.Buffer) error {
			return runCallers(ctx, sym, false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		}},
		{"callees", rootSymbol, func(ctx context.Context, sym string, uc QueryCallGraphUseCase, buf *bytes.Buffer) error {
			return runCallees(ctx, sym, false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		}},
		{"callers --transitive", rootSymbol, func(ctx context.Context, sym string, uc QueryCallGraphUseCase, buf *bytes.Buffer) error {
			return runCallersTransitive(ctx, sym, 0, false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		}},
		{"callees --transitive", rootSymbol, func(ctx context.Context, sym string, uc QueryCallGraphUseCase, buf *bytes.Buffer) error {
			return runCalleesTransitive(ctx, sym, 0, false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		}},
		{"implementers", ifaceSymbol, func(ctx context.Context, sym string, uc QueryCallGraphUseCase, buf *bytes.Buffer) error {
			return runImplementers(ctx, sym, false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		}},
	}
}

const (
	rootSymbol  = "example.com/m.Root"
	ifaceSymbol = "example.com/m.Store"
	otherModule = "example.com/nope.NoSuchSymbol"
)

// cleanModuleRecord is a module with nothing to caveat: Extracted, built with
// bodies, one function and one interface.
func cleanModuleRecord() cgdomain.CallGraphRecord {
	rec := builtRecord([]cgdomain.CallNode{{ID: rootSymbol, Symbol: "Root"}}, nil)
	rec.OverallStatus = cgdomain.CallGraphStatusExtracted
	rec.Completeness = cgdomain.CompletenessBuiltWithBodies
	rec.Interfaces = []cgdomain.InterfaceType{{
		ID: ifaceSymbol, Package: "example.com/m", Name: "Store", Methods: []string{"Get"},
	}}
	rec.Implementations = []cgdomain.InterfaceImplementation{{
		InterfaceID: ifaceSymbol, TypeID: "example.com/m.(*memStore)",
	}}
	return rec
}

// TestEdgeQuery_ResolvesFromCoordinatesNotComposedSummaries pins the read an
// edge query is allowed to make of the store.
//
// "Which module owns this symbol, and was it analysed" is a question about the
// ledger's KEYS. Answering it through the summary listing composes every
// generation of every multi-generation coordinate in the store — a blob decode
// plus a full reconstruction of that generation's edge set — to read fields the
// answer never looks at. On a store of 40M edge rows that was the entire cost of
// a caller query, paid two to four times before a single edge was read, and it
// did not vary with what was asked.
func TestEdgeQuery_ResolvesFromCoordinatesNotComposedSummaries(t *testing.T) {
	for _, s := range edgeQuerySurfaces() {
		t.Run(s.name, func(t *testing.T) {
			uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, cleanModuleRecord())
			var buf bytes.Buffer
			if err := s.run(context.Background(), s.query, uc, &buf); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if uc.ListCalls != 0 {
				t.Errorf("the composing summary listing was read %d time(s); an edge query resolves from coordinates",
					uc.ListCalls)
			}
			if uc.CoordinateListCalls == 0 {
				t.Error("no coordinate listing was read at all; the resolution has to come from somewhere")
			}
		})
	}
}

// TestEdgeQuery_RefusalReadsNoRecord is the sharpest case in the ticket: a
// symbol whose module the store has never analysed is not a question about any
// record, so refusing it must not read one.
func TestEdgeQuery_RefusalReadsNoRecord(t *testing.T) {
	for _, s := range edgeQuerySurfaces() {
		t.Run(s.name, func(t *testing.T) {
			uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, cleanModuleRecord())
			var buf bytes.Buffer
			err := s.run(context.Background(), otherModule, uc, &buf)
			if err == nil && !strings.Contains(buf.String(), "not") {
				t.Fatalf("a symbol in an unanalysed module was not refused; output %q", buf.String())
			}
			if uc.ListCalls != 0 {
				t.Errorf("the composing summary listing was read %d time(s) to refuse a symbol", uc.ListCalls)
			}
			if uc.RecordReads != 0 {
				t.Errorf("%d record(s) were composed to refuse a symbol whose module is not in the store", uc.RecordReads)
			}
		})
	}
}

// TestEdgeQuery_CleanModuleNeedsNoRecordForItsNotices is the other half of the
// gate: the Partial and completeness notices are the only things an answered
// edge query reads a record for, and both are decidable as absent from the
// coordinate's columns. A module no generation of which is Partial or below-full
// warrants neither notice, so nothing is decoded to establish that.
//
// The foreign-module qualification on the answer line is decided the same way,
// and had to be: it is read from the store's own column beside the record, not
// from a composed one. Measured when it briefly composed instead — a one-row
// answer over a 213,828-edge record went from 1,710 ms to 2,193 ms. This test is
// the codified form of that decision, which is why it is pinned at zero rather
// than relaxed to admit one more read.
//
// The implementers query is not in this set: it reads the declaring module's
// TYPES out of the record, which is the answer itself rather than a notice
// about it.
func TestEdgeQuery_CleanModuleNeedsNoRecordForItsNotices(t *testing.T) {
	rec := cleanModuleRecord()
	surfaces := edgeQuerySurfaces()[:4] // callers, callees, and both transitive forms
	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			uc := testfakes.NewFakeQueryCallGraph()
			uc.SetList([]cgports.CallGraphSummary{{
				ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
				PipelineVersion: cgapp.PipelineVersion,
				OverallStatus:   cgdomain.CallGraphStatusExtracted,
				Completeness:    cgdomain.CompletenessBuiltWithBodies,
			}})
			uc.AddRecord(coordinatetest.MustNew("example.com/m", "v1.0.0"), cgapp.PipelineVersion, rec)
			// One caller, so the answer is non-empty: an empty answer is classified,
			// and classification legitimately reads the record to tell "no callers"
			// from "not a node in the graph".
			uc.SetCallers([]cgports.CallEdgeRef{{
				ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
				PipelineVersion: cgapp.PipelineVersion,
				FromID:          "example.com/m.Caller", ToID: "example.com/m.Root",
			}})
			uc.SetCallees([]cgports.CallEdgeRef{{
				ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
				PipelineVersion: cgapp.PipelineVersion,
				FromID:          "example.com/m.Root", ToID: "example.com/m.Callee",
			}})
			uc.SetTraverseCallers([]cgports.CallEdgeRef{{
				ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
				PipelineVersion: cgapp.PipelineVersion,
				FromID:          "example.com/m.Caller", ToID: rootSymbol,
			}}, []string{"example.com/m.Caller"})
			uc.SetTraverseCallees([]cgports.CallEdgeRef{{
				ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
				PipelineVersion: cgapp.PipelineVersion,
				FromID:          rootSymbol, ToID: "example.com/m.Callee",
			}}, []string{"example.com/m.Callee"})

			var buf bytes.Buffer
			if err := s.run(context.Background(), s.query, uc, &buf); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if uc.RecordReads != 0 {
				t.Errorf("%d record(s) were composed for a module whose columns already prove "+
					"neither notice applies", uc.RecordReads)
			}
			// And the answer WAS qualified from the column: a zero here would mean the
			// gate passed because nothing asked, not because asking is cheap.
			if uc.ForeignModuleReads == 0 {
				t.Error("the foreign-module column was never read, so this gate proves nothing about it")
			}
			if uc.ListCalls != 0 {
				t.Errorf("the composing summary listing was read %d time(s)", uc.ListCalls)
			}
		})
	}
}

// TestEdgeQuery_PartialModuleStillReadsItsRecord is the gate's other direction.
// The flags prove only a negative, so a coordinate that DOES hold a Partial
// generation must still be read — otherwise the dropped-edges notice, which is
// the whole reason the record is consulted, would silently stop being printed.
func TestEdgeQuery_PartialModuleStillReadsItsRecord(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: rootSymbol, Symbol: "Root"}}, nil)
	rec.OverallStatus = cgdomain.CallGraphStatusPartial
	rec.FailedPackages = []string{"example.com/m/broken"}

	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{{
		ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
		PipelineVersion: cgapp.PipelineVersion,
		OverallStatus:   cgdomain.CallGraphStatusPartial,
	}})
	uc.AddRecord(coordinatetest.MustNew("example.com/m", "v1.0.0"), cgapp.PipelineVersion, rec)

	var buf bytes.Buffer
	if err := runCallers(context.Background(), rootSymbol, false, uc, &buf,
		buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uc.RecordReads == 0 {
		t.Fatal("a Partial coordinate's record was never read; the notice cannot name a failed package it did not load")
	}
	if !strings.Contains(buf.String(), "example.com/m/broken") {
		t.Errorf("the Partial notice does not name the failed package: %q", buf.String())
	}
}
