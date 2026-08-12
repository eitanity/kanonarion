package domain

import (
	"strings"
	"testing"
)

// The commonest fork shape: a republication that keeps the upstream copyright
// line and adds none of its own. One holder can never fire the multiple-holders
// arm, and the holder-matches-path arm could not reach it either while its only
// candidates were paths the licence ledger happened to hold — the upstream of a
// vendored fork is usually not among them. The replace directive names the
// upstream whether or not anybody analysed it.
func TestInferRepublication_ReplaceCounterpartWithSoleUpstreamHolder(t *testing.T) {
	got := InferRepublication("github.com/cortezaproject/gval", []CopyrightAttribution{
		{Holder: "Paessler AG <support@paessler.com>", Verbatim: "Copyright (c) 2017, Paessler AG <support@paessler.com>"},
	}, ReplacedModules([]string{"github.com/PaesslerAG/gval"}))
	if len(got) != 1 {
		t.Fatalf("indicators = %+v, want one for the replaced module", got)
	}
	if got[0].Signal != RepublicationHolderMatchesPath {
		t.Errorf("signal = %v, want holder matches path", got[0].Signal)
	}
	if got[0].Canonical != "github.com/PaesslerAG/gval" {
		t.Errorf("canonical = %q, want the replaced module path", got[0].Canonical)
	}
	if !strings.Contains(got[0].Statement, "replace directive") {
		t.Errorf("statement does not say the candidate came from a replace directive: %q", got[0].Statement)
	}
	if len(got[0].Evidence) != 1 || !strings.Contains(got[0].Evidence[0], "Paessler AG") {
		t.Errorf("evidence = %v, want the copyright line quoted", got[0].Evidence)
	}
}

// The replace directive is the assertion that the two modules stand in for each
// other, so the module names need not match. Requiring them would re-acquire the
// blindness the name-path heuristic has by construction: a fork is free to
// rename itself, and the manifest still says which module it displaces.
func TestInferRepublication_ReplaceCounterpartNeedsNoNameOverlap(t *testing.T) {
	got := InferRepublication("github.com/newowner/expression-engine", []CopyrightAttribution{
		{Holder: "Paessler AG", Verbatim: "Copyright (c) 2017, Paessler AG"},
	}, ReplacedModules([]string{"github.com/PaesslerAG/gval"}))
	if len(got) != 1 {
		t.Fatalf("indicators = %+v, want one: the replace directive ties the two together", got)
	}
	if got[0].Canonical != "github.com/PaesslerAG/gval" {
		t.Errorf("canonical = %q, want the replaced module path", got[0].Canonical)
	}
}

// A replace directive alone is not a republication signal. Forks that wrote
// their own copyright line, and replacements pointing at an unrelated module,
// keep reading as no indicators — the holder still has to name the replaced
// module's owner.
func TestInferRepublication_ReplaceCounterpartWithItsOwnHolderIsSilent(t *testing.T) {
	got := InferRepublication("github.com/cortezaproject/gval", []CopyrightAttribution{
		{Holder: "Corteza Project", Verbatim: "Copyright (c) 2021 Corteza Project"},
	}, ReplacedModules([]string{"github.com/PaesslerAG/gval"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: the holder names nobody in the replaced path", got)
	}
}

// A ledger neighbour still has to share the module name. The two candidate
// sources are read differently and the looser rule must not leak onto the wider
// set: every module the store holds would otherwise be compared against every
// holder on name-free terms.
func TestInferRepublication_LedgerCandidateStillNeedsNameOverlap(t *testing.T) {
	got := InferRepublication("github.com/newowner/expression-engine", []CopyrightAttribution{
		{Holder: "Paessler AG", Verbatim: "Copyright (c) 2017, Paessler AG"},
	}, LedgerModules([]string{"github.com/PaesslerAG/gval"}))
	if len(got) != 0 {
		t.Fatalf("indicators = %+v, want none: nothing but a holder name ties the two paths together", got)
	}
}

// One path reached by both routes yields one indicator, phrased in the terms of
// the stronger relation: the directive is a statement about these two modules,
// while ledger membership is a statement about this store.
func TestInferRepublication_ReplaceRelationWinsOverLedgerForTheSamePath(t *testing.T) {
	related := append(
		LedgerModules([]string{"github.com/PaesslerAG/gval"}),
		ReplacedModules([]string{"github.com/PaesslerAG/gval"})...)
	got := InferRepublication("github.com/cortezaproject/gval", []CopyrightAttribution{
		{Holder: "Paessler AG", Verbatim: "Copyright (c) 2017, Paessler AG"},
	}, related)
	if len(got) != 1 {
		t.Fatalf("indicators = %+v, want exactly one", got)
	}
	if !strings.Contains(got[0].Statement, "replace directive") {
		t.Errorf("statement = %q, want the replace-directive phrasing", got[0].Statement)
	}
}

// An empty candidate path names no module. It reaches the tier from a walk node
// that recorded no original coordinate, and comparing a holder against it would
// compare it against the host-less empty string.
func TestInferRepublication_EmptyCandidatePathIsDropped(t *testing.T) {
	got := InferRepublication("github.com/cortezaproject/gval", []CopyrightAttribution{
		{Holder: "Paessler AG", Verbatim: "Copyright (c) 2017, Paessler AG"},
	}, ReplacedModules([]string{"", "github.com/PaesslerAG/gval"}))
	if len(got) != 1 {
		t.Fatalf("indicators = %+v, want exactly one, for the named path", got)
	}
	if got[0].Canonical != "github.com/PaesslerAG/gval" {
		t.Errorf("canonical = %q, want the named path", got[0].Canonical)
	}
}
