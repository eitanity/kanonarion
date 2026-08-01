package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// paths projects the sorted module set onto "path@version" so an ordering
// assertion reads as the order it is checking.
func paths(ms []domain.VendoredModule) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Path+"@"+m.Version)
	}
	return out
}

// keys projects the sorted finding set onto the four fields the order is
// defined over, in that order.
func keys(fs []domain.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, strings.Join([]string{f.Module, string(f.Kind), f.Version, f.File}, "|"))
	}
	return out
}

func assertOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// A module path can appear more than once in a vendored tree — a module and the
// same module at a second major version resolve to two entries under one path
// prefix, and a tree carrying both must order them the same way on every scan.
// Path alone does not settle that, so version is the tie-break.
func TestSortModules_TieBreaksOnVersion(t *testing.T) {
	ms := []domain.VendoredModule{
		{Path: "example.com/dep", Version: "v1.3.0"},
		{Path: "example.com/aaa", Version: "v0.1.0"},
		{Path: "example.com/dep", Version: "v1.2.0"},
	}
	domain.SortModules(ms)
	assertOrder(t, paths(ms), []string{
		"example.com/aaa@v0.1.0",
		"example.com/dep@v1.2.0",
		"example.com/dep@v1.3.0",
	})
}

// Every level of the finding order, exercised from a single shuffled set: one
// module carries findings of two kinds, one kind carries two versions, and one
// version carries two files (the drift axis emits one finding per file, so
// module/kind/version alone does not identify a finding).
func TestSortFindings_OrdersByModuleThenKindThenVersionThenFile(t *testing.T) {
	fs := []domain.Finding{
		{Module: "example.com/b", Kind: domain.FindingUnverified, Version: "v1.0.0"},
		{Module: "example.com/a", Kind: domain.FindingDrift, Version: "v1.0.0", File: "z.go"},
		{Module: "example.com/a", Kind: domain.FindingDrift, Version: "v1.0.0", File: "a.go"},
		{Module: "example.com/a", Kind: domain.FindingUnverified, Version: "v1.0.0"},
		{Module: "example.com/a", Kind: domain.FindingDrift, Version: "v0.9.0", File: "a.go"},
	}
	domain.SortFindings(fs)
	assertOrder(t, keys(fs), []string{
		"example.com/a|drift|v0.9.0|a.go",
		"example.com/a|drift|v1.0.0|a.go",
		"example.com/a|drift|v1.0.0|z.go",
		"example.com/a|unverified|v1.0.0|",
		"example.com/b|unverified|v1.0.0|",
	})
}

// Two findings identical across all four ordered fields keep their input order:
// the sort is stable, so a set the caller assembled deterministically hashes
// deterministically.
func TestSortFindings_IsStableForIdenticalKeys(t *testing.T) {
	fs := []domain.Finding{
		{Module: "example.com/a", Kind: domain.FindingDrift, Version: "v1.0.0", File: "a.go", Detail: "first"},
		{Module: "example.com/a", Kind: domain.FindingDrift, Version: "v1.0.0", File: "a.go", Detail: "second"},
	}
	domain.SortFindings(fs)
	if fs[0].Detail != "first" || fs[1].Detail != "second" {
		t.Errorf("stable order lost: %q then %q", fs[0].Detail, fs[1].Detail)
	}
}

// FindingSummary is what a blocked CI run reads in the gate message, so it must
// name the file on the per-file drift axis: "drift example.com/dep" leaves the
// operator to find which of the module's files moved.
func TestFinding_SummaryNamesTheFileOnAPerFileAxis(t *testing.T) {
	f := domain.Finding{
		Kind: domain.FindingDrift, Module: "example.com/dep", File: "dep.go",
		Expected: "sha256:aaa", Actual: "sha256:bbb",
	}
	got := f.FindingSummary()
	for _, want := range []string{"drift", "example.com/dep/dep.go", "expected sha256:aaa", "got sha256:bbb"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q does not contain %q", got, want)
		}
	}
}

// A finding with only one of the two hashes still reports the pair, so the
// empty side reads as a value that was not measured rather than being dropped
// and leaving the reader to guess which side is missing.
func TestFinding_SummaryReportsAHalfPresentHashPair(t *testing.T) {
	f := domain.Finding{
		Kind: domain.FindingUnverified, Module: "example.com/dep", Expected: "h1:AAA",
	}
	got := f.FindingSummary()
	if !strings.Contains(got, "expected h1:AAA") || !strings.Contains(got, "got )") {
		t.Errorf("summary %q does not report both sides of the pair", got)
	}
}

// A finding carrying neither hash is summarised without an empty "(expected ,
// got )" tail, which states nothing and reads as a measurement that came back
// blank.
func TestFinding_SummaryOmitsTheHashPairWhenThereIsNone(t *testing.T) {
	f := domain.Finding{Kind: domain.FindingMissingFromVendor, Module: "example.com/dep"}
	got := f.FindingSummary()
	if got != "missing_from_vendor example.com/dep" {
		t.Errorf("summary = %q, want the bare kind and module", got)
	}
	if strings.Contains(got, "expected") {
		t.Errorf("summary %q reports a hash pair that does not exist", got)
	}
}
