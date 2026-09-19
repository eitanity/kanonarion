package application

import (
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestWalker_PartialGraphDegradesUnlessExempt is the fail-safe direction stated
// as a test: the rule is "a Partial graph degrades the walk", and the exemption
// map is the only thing that can hold a reason back. A reason added to the
// resolver without being argued into that map must be caught here rather than on
// a road test, so an invented reason no build has ever produced is exercised
// alongside the real ones.
func TestWalker_PartialGraphDegradesUnlessExempt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		want   domain2.WalkStatus
	}{
		{"fetch_failed", domain2.FetchFailedReason, domain2.WalkPartial},
		{"parse_failed", domain2.ParseFailedReason, domain2.WalkPartial},
		{"cancelled", domain2.CancelledReason, domain2.WalkPartial},
		{"depth_bounded", domain2.DepthBoundedReason(2), domain2.WalkPartial},
		{"build_list_unavailable", domain2.BuildListUnavailableReason, domain2.WalkPartial},
		{"build_list_approximate carries a payload too", "build_list_approximate: no resolution directory", domain2.WalkPartial},
		{"a reason nobody has written yet", "some_future_reason: whatever it says", domain2.WalkPartial},
		{"a Partial graph stating no reason at all", "", domain2.WalkPartial},
		{"two reasons, neither exempt", domain2.BuildListUnavailableReason + "; " + domain2.FetchFailedReason, domain2.WalkPartial},
		{"an exempt reason beside one that is not", domain2.ShallowReason + "; " + domain2.FetchFailedReason, domain2.WalkPartial},

		// The only exemption, and the only way to keep succeeded.
		{"shallow", domain2.ShallowReason, domain2.WalkSucceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := domain2.Graph{Partial: true, PartialReason: tc.reason}
			if got := degradeForIncompleteGraph(domain2.WalkSucceeded, g); got != tc.want {
				t.Errorf("status = %s, want %s for PartialReason %q", got, tc.want, tc.reason)
			}
		})
	}
}

// A graph that is not marked Partial is never degraded, whatever its reason
// string happens to hold — Partial is the signal, the reason only qualifies it.
func TestWalker_UnmarkedGraphIsNeverDegraded(t *testing.T) {
	g := domain2.Graph{Partial: false, PartialReason: domain2.FetchFailedReason}
	if got := degradeForIncompleteGraph(domain2.WalkSucceeded, g); got != domain2.WalkSucceeded {
		t.Errorf("status = %s, want succeeded", got)
	}
}

// A status that is already worse keeps its own reason.
func TestWalker_IncompleteGraphDoesNotOutrankAWorseStatus(t *testing.T) {
	g := domain2.Graph{Partial: true, PartialReason: domain2.BuildListUnavailableReason}
	for _, st := range []domain2.WalkStatus{domain2.WalkFailed, domain2.WalkCancelled} {
		if got := degradeForIncompleteGraph(st, g); got != st {
			t.Errorf("status = %s, want %s left alone", got, st)
		}
	}
}
