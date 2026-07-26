package application_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// vcsHostProductionFetcher extends productionCacheFetcher with the WithVCSHosts
// hook the walker uses to hand a walk's policy-resolved forge allowlist to the
// fetch stage. It records what it was given so a test can prove the policy
// actually reached the fetcher rather than being resolved and dropped.
type vcsHostProductionFetcher struct {
	*productionCacheFetcher
	applied *domain2.VCSHostAllowlist
}

func (f *vcsHostProductionFetcher) WithVCSHosts(hosts domain2.VCSHostAllowlist) walkports.ModuleFetcher {
	f.applied = &hosts
	return f
}

func buildWalkerWithVCSHostFetcher(pf *vcsHostProductionFetcher, blobs *fakeBlobStore) *application2.Walker {
	resolver := application2.NewGraphResolver(
		newXmodParser(), pf, blobs,
		fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return application2.NewWalker(
		resolver, pf, nil,
		fixedClock{fixedNow}, fakeStopwatch{},
		2, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// policyWithHosts returns the default depth policy with the fetch stage's forge
// allowlist overridden.
func policyWithHosts(hosts []string) *domain.DepthPolicy {
	p := domain.DefaultDepthPolicy()
	fetch := p.Stages["fetch"]
	fetch.AllowedVCSHosts = &hosts
	p.Stages["fetch"] = fetch
	return &p
}

func vcsHostWalkTarget() coordinate.ModuleCoordinate {
	return coord("example.com/target", "v1.0.0")
}

func newVCSHostFetcher(t testing.TB, blobs *fakeBlobStore) *vcsHostProductionFetcher {
	pf := &vcsHostProductionFetcher{productionCacheFetcher: newProductionCacheFetcher(blobs)}
	pf.add(t, "example.com/target", "v1.0.0", "module example.com/target\ngo 1.21\n")
	return pf
}

// A policy that overrides allowed_vcs_hosts must reach the fetcher: this is the
// widen case (add a forge without a rebuild) and the narrow case (trust one
// forge only) at the same seam.
func TestWalker_PolicyVCSHostsReachTheFetcher(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newVCSHostFetcher(t, blobs)
	w := buildWalkerWithVCSHostFetcher(pf, blobs)

	outcome, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: vcsHostWalkTarget(),
		Policy: policyWithHosts([]string{"github.com", "git.example.org"}),
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outcome.OverallStatus != domain.WalkSucceeded {
		t.Fatalf("status = %s, want succeeded", outcome.OverallStatus)
	}
	if pf.applied == nil {
		t.Fatal("the policy's allowed_vcs_hosts never reached the fetcher")
	}
	if !pf.applied.IsAllowed("git.example.org") {
		t.Error("the widened forge did not reach the fetcher")
	}
	if pf.applied.IsAllowed("gitlab.com") {
		t.Error("the override must replace the built-in set, not merge with it")
	}
}

// A policy that leaves the allowlist alone must not clone the fetcher: the
// default set is already what an unconfigured fetcher enforces, and cloning
// would make every walk look like an override in the logs.
func TestWalker_DefaultVCSHostsDoNotTouchTheFetcher(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newVCSHostFetcher(t, blobs)
	w := buildWalkerWithVCSHostFetcher(pf, blobs)

	if _, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: vcsHostWalkTarget(),
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if pf.applied != nil {
		t.Error("a walk with no allowlist override should not configure the fetcher")
	}
}

// An override the fetcher cannot accept must fail the walk. Proceeding would
// cross-verify against forges the operator excluded and report the run clean.
func TestWalker_VCSHostOverrideOnIncapableFetcherFailsTheWalk(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newProductionCacheFetcher(blobs)
	pf.add(t, "example.com/target", "v1.0.0", "module example.com/target\ngo 1.21\n")
	w := buildWalkerWithProductionCache(pf, blobs)

	_, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: vcsHostWalkTarget(),
		Policy: policyWithHosts([]string{"github.com"}),
	})
	if err == nil {
		t.Fatal("expected an unapplicable allowed_vcs_hosts override to fail the walk")
	}
	if !strings.Contains(err.Error(), "allowed_vcs_hosts") {
		t.Errorf("error should name the policy field, got %q", err)
	}
}

// An unusable trust list is a hard stop, not a fall-back to the default set.
func TestWalker_UnusableVCSHostListFailsTheWalk(t *testing.T) {
	blobs := newFakeBlobStore()
	pf := newVCSHostFetcher(t, blobs)
	w := buildWalkerWithVCSHostFetcher(pf, blobs)

	_, err := w.Walk(context.Background(), application2.WalkRequest{
		Target: vcsHostWalkTarget(),
		Policy: policyWithHosts([]string{"https://github.com"}),
	})
	if err == nil {
		t.Fatal("expected a malformed allowed_vcs_hosts entry to fail the walk")
	}
	if pf.applied != nil {
		t.Error("a walk must not fetch anything under an unusable trust list")
	}
}
