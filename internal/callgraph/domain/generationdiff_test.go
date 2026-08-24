package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestDiffGenerations_ValidatesBeforeItCompares.
//
// The content hash is sealed over the time of measurement, so it differs on
// every write and can only ever answer "is this record intact". Here it does
// that one job: a record that fails its own seal is not evidence of anything,
// and a diff of it would read as evidence.
func TestDiffGenerations_ValidatesBeforeItCompares(t *testing.T) {
	t.Parallel()
	good := composeRecord(t, composeSpec{artefact: "zip:h1:a", symbol: "Foo"})
	tampered := composeRecord(t, composeSpec{artefact: "zip:h1:a", symbol: "Bar"})
	tampered.Nodes[0].Symbol = "Rewritten"

	for _, tc := range []struct {
		name string
		a, b domain.CallGraphRecord
	}{
		{name: "the left generation is not intact", a: tampered, b: good},
		{name: "the right generation is not intact", a: good, b: tampered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := domain.DiffGenerations(tc.a, tc.b)
			if !errors.Is(err, domain.ErrUnverifiableGeneration) {
				t.Fatalf("DiffGenerations diffed an unverifiable record: err=%v", err)
			}
		})
	}
}

// TestDiffGenerations_ReportsTheFieldsRatherThanADigest.
//
// This is the whole point of the comparator: two digests tell a reader that two
// measurements disagree and nothing about what. The worked case on the real
// store is two generations of one module whose graphs are identical and whose
// build lists are not — an answer of "a build list", not "sha256:… vs sha256:…".
func TestDiffGenerations_ReportsTheFieldsRatherThanADigest(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{artefact: "zip:h1:a", symbol: "Foo", buildList: "walk-a"})
	b := composeRecord(t, composeSpec{artefact: "zip:h1:a", symbol: "Foo", buildList: "walk-b"})
	diff, err := domain.DiffGenerations(a, b)
	if err != nil {
		t.Fatalf("DiffGenerations: %v", err)
	}
	if len(diff.Fields) != 1 || diff.Fields[0].Field != "build_list_source" {
		t.Fatalf("fields reported %+v, want build_list_source alone", diff.Fields)
	}
	if diff.Fields[0].Left != "walk-a" || diff.Fields[0].Right != "walk-b" {
		t.Errorf("field values %q -> %q, want walk-a -> walk-b", diff.Fields[0].Left, diff.Fields[0].Right)
	}
	if !diff.Nodes.Empty() || !diff.Edges.Empty() {
		t.Errorf("two identical graphs reported a collection difference: %+v", diff.Collections())
	}
	if !strings.Contains(diff.Summary(), "build_list_source differ") {
		t.Errorf("summary %q does not name the field that differs", diff.Summary())
	}
}

// TestDiffGenerations_SeparatesMembershipFromDescription.
//
// "This run reached a symbol the other did not" and "both reached it and
// described it differently" are different findings, and collapsing them is what
// left an operator counting nodes. The first is what a graph disagreement is
// about; the second is usually where the analysis ran, not what it found.
func TestDiffGenerations_SeparatesMembershipFromDescription(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{
		artefact: "zip:h1:a", symbol: "Foo", externalNodeFile: "usr/local/go/src/bytes/buffer.go",
	})
	b := composeRecord(t, composeSpec{artefact: "zip:h1:a", symbol: "Bar"})
	diff, err := domain.DiffGenerations(a, b)
	if err != nil {
		t.Fatalf("DiffGenerations: %v", err)
	}
	if got := diff.Nodes.OnlyLeft; len(got) != 2 {
		t.Errorf("nodes only in the left generation: %v, want the module symbol and the external one", got)
	}
	if got := diff.Nodes.OnlyRight; len(got) != 1 || got[0] != "example.com/mod.Bar" {
		t.Errorf("nodes only in the right generation: %v, want example.com/mod.Bar", got)
	}
	if len(diff.Nodes.Changed) != 0 {
		t.Errorf("nodes described differently: %+v, want none — the two hold no node in common", diff.Nodes.Changed)
	}

	// The same two graphs differing only in where an external symbol is declared
	// are the other finding: one member, present in both, described differently.
	c := composeRecord(t, composeSpec{
		artefact: "zip:h1:a", symbol: "Foo", externalNodeFile: "home/u/toolchain/src/bytes/buffer.go",
	})
	moved, err := domain.DiffGenerations(a, c)
	if err != nil {
		t.Fatalf("DiffGenerations: %v", err)
	}
	if len(moved.Nodes.OnlyLeft) != 0 || len(moved.Nodes.OnlyRight) != 0 {
		t.Errorf("a moved declaration was reported as a membership change: %+v", moved.Nodes)
	}
	if len(moved.Nodes.Changed) != 1 || moved.Nodes.Changed[0].Field != "position" {
		t.Errorf("changed members %+v, want one node differing on position", moved.Nodes.Changed)
	}
}

// TestDiffGenerations_ComparesEveryFieldWithoutBeingToldWhich.
//
// The comparison walks the canonical shape rather than a hand-listed set, so a
// field added tomorrow is diffed without anyone remembering to add it here. The
// two exceptions are the time of measurement and the seal computed over it,
// which differ on every write by construction.
func TestDiffGenerations_ComparesEveryFieldWithoutBeingToldWhich(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{artefact: "zip:h1:a", symbol: "Foo", detail: "one"})
	b := composeRecord(t, composeSpec{artefact: "zip:h1:a", symbol: "Foo", detail: "two"})
	diff, err := domain.DiffGenerations(a, b)
	if err != nil {
		t.Fatalf("DiffGenerations: %v", err)
	}
	var names []string
	for _, f := range diff.Fields {
		names = append(names, f.Field)
	}
	if len(names) != 1 || names[0] != "failure_detail" {
		t.Fatalf("fields reported %v, want failure_detail alone — extracted_at and content_hash are set aside", names)
	}
}
