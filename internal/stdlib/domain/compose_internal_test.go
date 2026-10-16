package domain

import (
	"errors"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// unsealed is a measurement written before the seal existed: no content hash,
// so nothing about its value tells it apart from a lookalike.
func unsealed(route AcquisitionRoute, status VerificationStatus, commit string) Facts {
	return Facts{
		GoVersion:          "go1.26.5",
		Digests:            fetchdomain.ArtifactDigests{SHA256: "sha-of-the-tarball"},
		VerificationStatus: status,
		AcquisitionRoute:   route,
		VCSCommit:          commit,
		AcquiredAt:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// sameValueKey reports whether two measurements agree on every field a
// value-built identity could use, which is what makes them lookalikes.
func sameValueKey(a, b Facts) bool {
	return a.ContentHash == b.ContentHash && a.Digests.SHA256 == b.Digests.SHA256 &&
		a.AcquiredAt.Equal(b.AcquiredAt)
}

// TestWithRoute_AnExcludedLookalikeStaysOut: membership is decided per element,
// so a measurement on a route not asked for stays out even when every value it
// carries could pass for one that was kept.
func TestWithRoute_AnExcludedLookalikeStaysOut(t *testing.T) {
	t.Parallel()
	godev := unsealed(RouteGoDev, VerifiedGoDevChecksum, "kept")
	local := unsealed(RouteLocalToolchain, VerifiedLocalToolchain, "excluded")
	silent := unsealed(RouteUnrecorded, VerifiedGoDevChecksum, "kept-too")
	if !sameValueKey(godev, local) {
		t.Fatal("premise: the excluded measurement must share the kept one's value key")
	}

	got := withRoute([]Facts{godev, local, silent}, RouteGoDev, RouteUnrecorded)
	if len(got) != 2 || got[0].VCSCommit != "kept" || got[1].VCSCommit != "kept-too" {
		t.Fatalf("withRoute = %+v, want the go.dev and unrecorded measurements only, in append order", got)
	}
}

// TestDefaultRouteGroup_UnsealedLookalikesBothSurvive: two unsealed measurements
// of one artefact taken in the same second are two measurements, and both stay
// in the group in the order they were appended.
func TestDefaultRouteGroup_UnsealedLookalikesBothSurvive(t *testing.T) {
	t.Parallel()
	first := unsealed(RouteUnrecorded, VerifiedGoDevChecksum, "first")
	godev := unsealed(RouteGoDev, VerifiedGoDevChecksum, "godev")
	second := unsealed(RouteUnrecorded, VerifiedGoDevChecksum, "second")
	if first.ContentHash != "" || second.ContentHash != "" || !first.AcquiredAt.Equal(second.AcquiredAt) {
		t.Fatal("premise: both measurements must be unsealed and share an acquired_at")
	}

	got, err := defaultRouteGroup([]Facts{first, godev, second})
	if err != nil {
		t.Fatalf("defaultRouteGroup: %v", err)
	}
	var commits []string
	for _, f := range got {
		commits = append(commits, f.VCSCommit)
	}
	if len(commits) != 3 || commits[0] != "first" || commits[1] != "godev" || commits[2] != "second" {
		t.Fatalf("group = %v, want [first godev second]", commits)
	}

	served, err := Compose([]Facts{first, second}, ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if served.VCSCommit != "second" {
		t.Fatalf("served %q, want the later append when nothing else separates them", served.VCSCommit)
	}
}

// TestCompose_ANamedRouteNothingTookIsNoAnswer: naming a route no measurement
// took is an absence for that question, not the default group's answer.
func TestCompose_ANamedRouteNothingTookIsNoAnswer(t *testing.T) {
	t.Parallel()
	godev := unsealed(RouteGoDev, VerifiedGoDevChecksum, "godev")
	if _, err := Compose([]Facts{godev}, ComposeRequest{Route: RouteLocalToolchain}); !errors.Is(err, ErrNoFactsToCompose) {
		t.Fatalf("err = %v, want ErrNoFactsToCompose", err)
	}
}
