package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestCompose_AnInputThatShapesTheAnswerSeparatesRatherThanCollides.
//
// A call graph is an analysis of a module RESOLVED AGAINST A BUILD LIST, and the
// record names which. Two walks that pinned different dependency versions handed
// the analyser different closures, so the two graphs are two truthful answers to
// two questions rather than one measurement taken twice — and composition used
// to report the pair as evidence in doubt.
//
// The separation is not a licence to ignore a disagreement. Two records offered
// the SAME build list still contradict each other, and a record that names no
// build list cannot be shown to have been asked a different question, so it goes
// on comparing against everything.
func TestCompose_AnInputThatShapesTheAnswerSeparatesRatherThanCollides(t *testing.T) {
	t.Parallel()
	built := func(buildList, symbol string, at time.Time) domain.CallGraphRecord {
		return composeRecord(t, composeSpec{
			artefact: "zip:h1:a", completeness: domain.CompletenessBuiltWithBodies,
			source: domain.AnalysisSourceModuleZip, buildList: buildList, symbol: symbol,
			extractedAt: at,
		})
	}
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		records []domain.CallGraphRecord
		// wantServed is the symbol the composed record states, empty when the read
		// must refuse.
		wantServed string
	}{
		{
			name:       "two build lists, two graphs: two answers, the newest serves",
			records:    []domain.CallGraphRecord{built("walk-a", "Foo", early), built("walk-b", "Bar", late)},
			wantServed: "Bar",
		},
		{
			name:    "one build list, two graphs: still a disagreement",
			records: []domain.CallGraphRecord{built("walk-a", "Foo", early), built("walk-a", "Bar", late)},
		},
		{
			name:    "a record naming no build list cannot be shown to answer another question",
			records: []domain.CallGraphRecord{built("", "Foo", early), built("walk-b", "Bar", late)},
		},
		{
			name: "a silent record is compared against every build list, not set aside",
			records: []domain.CallGraphRecord{
				built("walk-a", "Foo", early), built("walk-b", "Foo", late), built("", "Bar", late),
			},
		},
		{
			name: "two build lists that resolved the same versions still agree",
			records: []domain.CallGraphRecord{
				built("walk-a", "Foo", early), built("walk-b", "Foo", late),
			},
			wantServed: "Foo",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := domain.Compose(tc.records, domain.ComposeRequest{})
			if tc.wantServed == "" {
				var conflict domain.CallGraphConflict
				if !errors.As(err, &conflict) {
					t.Fatalf("records that disagree about the graph composed to an answer: err=%v", err)
				}
				if conflict.Field != domain.ConflictFieldCallGraph {
					t.Errorf("conflict field %q, want %q", conflict.Field, domain.ConflictFieldCallGraph)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if got.Nodes[0].Symbol != tc.wantServed {
				t.Errorf("served the graph stating %q, want %q", got.Nodes[0].Symbol, tc.wantServed)
			}
		})
	}
}

// TestCompose_WhereAnExternalSymbolIsDeclaredIsNotThisModulesGraph.
//
// The declaration position of a node OUTSIDE the analysed module is a path in
// the analysing host's toolchain and module cache: the same stdlib function
// comes back under whichever GOROOT loaded it. Comparing it made two runs that
// reached the identical symbols by the identical edges report a graph
// disagreement. The module's OWN positions are relative to its root and are a
// claim, so they still separate two records.
func TestCompose_WhereAnExternalSymbolIsDeclaredIsNotThisModulesGraph(t *testing.T) {
	t.Parallel()
	built := func(spec composeSpec) domain.CallGraphRecord {
		spec.artefact = "zip:h1:a"
		spec.completeness = domain.CompletenessBuiltWithBodies
		spec.source = domain.AnalysisSourceModuleZip
		return composeRecord(t, spec)
	}
	tests := []struct {
		name         string
		a, b         domain.CallGraphRecord
		wantConflict bool
		// wantField pins WHICH disagreement was reported. A refusal that names the
		// wrong one sends the reader at the wrong remedy, and the boolean alone
		// cannot tell a toolchain difference from the analyser contradicting itself.
		wantField string
	}{
		{
			// Two GOROOTs and the SAME graph. Where the records describe the same
			// nodes and edges there is nothing for a toolchain to disagree about, so
			// the label alone must not refuse: doing that made 25 of 30 refusals on
			// a real store a named toolchain against an unnamed GOROOT, 18 of them
			// over byte-identical graphs.
			name: "one toolchain's GOROOT against another's, same graph",
			a:    built(composeSpec{externalNodeFile: "usr/local/go/src/bytes/buffer.go"}),
			b:    built(composeSpec{externalNodeFile: "home/u/go/pkg/mod/golang.org/toolchain@v1/src/bytes/buffer.go"}),
		},
		{
			// The same two GOROOTs, now describing DIFFERENT graphs. That is a real
			// difference with a stated cause, and naming the toolchain is better
			// evidence than reporting the analyser as non-deterministic.
			name: "one toolchain's GOROOT against another's, different graphs",
			a:    built(composeSpec{externalNodeFile: "usr/local/go/src/bytes/buffer.go"}),
			b: built(composeSpec{
				externalNodeFile: "home/u/go/pkg/mod/golang.org/toolchain@v1/src/bytes/buffer.go",
				symbol:           "OnlyUnderTheOtherToolchain",
			}),
			wantConflict: true,
			wantField:    domain.ConflictFieldToolchain,
		},
		{
			name: "a record predating recorded positions against one that has them",
			a:    built(composeSpec{externalNodeFile: "usr/local/go/src/bytes/buffer.go"}),
			b:    built(composeSpec{externalNodeFile: "(unrecorded)"}),
		},
		{
			name:         "the module's own declaration moving is still a difference",
			a:            built(composeSpec{inModuleNodeFile: "a.go"}),
			b:            built(composeSpec{inModuleNodeFile: "b.go"}),
			wantConflict: true,
			wantField:    domain.ConflictFieldCallGraph,
		},
		{
			// The record with no external node establishes no toolchain, so it takes
			// no part in the toolchain comparison — and must still be compared for
			// the graph, or a run that reached a symbol the other did not would
			// silently compose.
			name:         "an external symbol one run reached and the other did not",
			a:            built(composeSpec{externalNodeFile: "usr/local/go/src/bytes/buffer.go"}),
			b:            built(composeSpec{}),
			wantConflict: true,
			wantField:    domain.ConflictFieldCallGraph,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := domain.Compose([]domain.CallGraphRecord{tc.a, tc.b}, domain.ComposeRequest{})
			var conflict domain.CallGraphConflict
			gotConflict := errors.As(err, &conflict)
			if gotConflict != tc.wantConflict {
				t.Fatalf("conflict=%v want %v (err=%v)", gotConflict, tc.wantConflict, err)
			}
			if gotConflict && conflict.Field != tc.wantField {
				t.Errorf("conflict field=%q want %q", conflict.Field, tc.wantField)
			}
		})
	}
}

// TestCallGraphConflict_SaysWhatDiffers.
//
// A refusal naming two opaque digests asks an operator to adjudicate a graph by
// eye. The conflict carries the comparison that decided it, so the message says
// which fields and how many members differ, and points at the command that lists
// them.
func TestCallGraphConflict_SaysWhatDiffers(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{
		artefact: "zip:h1:a", completeness: domain.CompletenessBuiltWithBodies,
		source: domain.AnalysisSourceModuleZip, symbol: "Foo",
	})
	b := composeRecord(t, composeSpec{
		artefact: "zip:h1:a", completeness: domain.CompletenessBuiltWithBodies,
		source: domain.AnalysisSourceModuleZip, symbol: "Bar",
	})
	_, err := domain.Compose([]domain.CallGraphRecord{a, b}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("two different graphs composed to an answer: %v", err)
	}
	if conflict.Difference == nil {
		t.Fatal("the refusal carries no comparison, so it names only digests")
	}
	if conflict.Difference.Nodes.Empty() {
		t.Fatal("the comparison reports no node difference between two different graphs")
	}
	for _, want := range []string{"differing:", "node only in", "--diff"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not contain %q:\n%s", want, err)
		}
	}
}

// TestCallGraphConflict_AnUnverifiableRecordIsNotDiffed.
//
// The content hash validates a record; it can never test whether two records
// agree. A record that fails its own seal is not evidence of a disagreement, so
// the refusal reports the digests it always did and states no comparison rather
// than one taken over bytes nothing stands behind.
func TestCallGraphConflict_AnUnverifiableRecordIsNotDiffed(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{
		artefact: "zip:h1:a", completeness: domain.CompletenessBuiltWithBodies,
		source: domain.AnalysisSourceModuleZip, symbol: "Foo",
	})
	b := composeRecord(t, composeSpec{
		artefact: "zip:h1:a", completeness: domain.CompletenessBuiltWithBodies,
		source: domain.AnalysisSourceModuleZip, symbol: "Bar",
	})
	b.Nodes[0].Symbol = "Tampered"
	_, err := domain.Compose([]domain.CallGraphRecord{a, b}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("two different graphs composed to an answer: %v", err)
	}
	if conflict.Difference != nil {
		t.Errorf("an unverifiable record was diffed anyway: %+v", conflict.Difference)
	}
	if strings.Contains(err.Error(), "differing:") {
		t.Errorf("refusal reports a comparison it could not validate:\n%s", err)
	}
}
