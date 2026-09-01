package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestEntryPointAncestry_StatesWhatWasSearchedAndWhatWasFound holds the sentence
// a reader is given about how a root relates to an entry point. Nothing asserted
// it, and every branch of it is a different claim: an unbounded search that found
// nothing says the code is unreachable from any entry point in the graph, while a
// bounded one says only that nothing was found within the bound — reading the
// second as the first is the misreading the bound is recorded to prevent.
func TestEntryPointAncestry_StatesWhatWasSearchedAndWhatWasFound(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		ancestry domain.EntryPointAncestry
		want     []string
		absent   []string
	}{
		{
			name:     "nothing computed says nothing",
			ancestry: domain.EntryPointAncestry{},
			want:     []string{""},
		},
		{
			name:     "an unbounded search that found nothing",
			ancestry: domain.EntryPointAncestry{Computed: true},
			want:     []string{"no entry-point ancestor anywhere in the analysed graph"},
		},
		{
			name:     "a bounded search that found nothing names its bound",
			ancestry: domain.EntryPointAncestry{Computed: true, SearchBound: 12},
			want:     []string{"no entry-point ancestor within 12 hops"},
			absent:   []string{"anywhere"},
		},
		{
			name:     "the root is itself the entry point",
			ancestry: domain.EntryPointAncestry{Computed: true, Found: true},
			want:     []string{"this root IS the entry point"},
		},
		{
			name: "a found path names its distance, its entry point and its weakest edge",
			ancestry: domain.EntryPointAncestry{
				Computed: true, Found: true, Hops: 3,
				EntryPointID: "example.com/app.main", EntryPointReason: "package main",
				Weakest: "Direct",
			},
			want: []string{"3 hops below example.com/app.main", "(package main)", "weakest edge on that path Direct"},
		},
		{
			name: "a reference hop is stated, not laundered into a call chain",
			ancestry: domain.EntryPointAncestry{
				Computed: true, Found: true, Hops: 1,
				EntryPointID: "example.com/app.main", Weakest: "Direct", ViaReference: true,
			},
			want: []string{"the value was registered, not invoked"},
		},
	} {
		got := tc.ancestry.String()
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: String() = %q, want it to contain %q", tc.name, got, want)
			}
		}
		for _, absent := range tc.absent {
			if strings.Contains(got, absent) {
				t.Errorf("%s: String() = %q, must not contain %q", tc.name, got, absent)
			}
		}
	}
}

// TestEntryPointAncestry_IsAllDirectCallPathRefusesAReferenceHop is the one case
// a caller may read as "this is driven by that entry point" without caveat, and
// the one thing that disqualifies it however well the edge itself resolved.
func TestEntryPointAncestry_IsAllDirectCallPathRefusesAReferenceHop(t *testing.T) {
	t.Parallel()
	direct := domain.EntryPointAncestry{Computed: true, Found: true, Hops: 2, Weakest: "Direct"}
	if !direct.IsAllDirectCallPath() {
		t.Error("a computed, found, all-Direct path with no reference hop was not reported as one")
	}
	if !direct.IsRecorded() {
		t.Error("IsRecorded is false for an ancestry that was computed")
	}

	for name, a := range map[string]domain.EntryPointAncestry{
		"a reference hop":     {Computed: true, Found: true, Weakest: "Direct", ViaReference: true},
		"a weaker edge":       {Computed: true, Found: true, Weakest: "Devirtualised"},
		"nothing found":       {Computed: true, Weakest: "Direct"},
		"nothing computed":    {Found: true, Weakest: "Direct"},
		"no weakest recorded": {Computed: true, Found: true},
	} {
		if a.IsAllDirectCallPath() {
			t.Errorf("%s was reported as an all-direct call path", name)
		}
	}
}

// TestRouteRoot_StringCarriesTheAncestryClause: the root line is where a reader
// meets the ancestry at all, and the clause is appended only when there is one,
// so a root with no search behind it does not read as one with an empty answer.
func TestRouteRoot_StringCarriesTheAncestryClause(t *testing.T) {
	t.Parallel()
	root := domain.RouteRoot{
		Kind:   domain.RootExportedAPI,
		Reason: "exported from the analysed module",
		Ancestry: domain.EntryPointAncestry{
			Computed: true, Found: true, Hops: 2, EntryPointID: "example.com/app.main", Weakest: "Direct",
		},
	}

	got := root.String()

	if !strings.Contains(got, "2 hops below example.com/app.main") {
		t.Errorf("RouteRoot.String() = %q, want the ancestry clause appended", got)
	}
	bare := domain.RouteRoot{Kind: domain.RootExportedAPI, Reason: "exported from the analysed module"}
	if strings.Contains(bare.String(), "hops") {
		t.Errorf("a root with no ancestry computed rendered one: %q", bare.String())
	}
}
