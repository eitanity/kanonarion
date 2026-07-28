package application_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// countingVCS records whether a clone URL was ever handed to git, which is what
// the allowlist ultimately governs: a refused host must not reach the
// subprocess at all, not merely fail afterwards.
type countingVCS struct {
	fakeVCS
	resolved  atomic.Int32
	checkouts atomic.Int32
	lastURL   atomic.Value
}

func (c *countingVCS) ResolveTag(ctx context.Context, url, ref string) (string, error) {
	c.resolved.Add(1)
	c.lastURL.Store(url)
	return c.fakeVCS.ResolveTag(ctx, url, ref)
}

func (c *countingVCS) CheckoutToDir(ctx context.Context, url, commit, dir string) error {
	c.checkouts.Add(1)
	c.lastURL.Store(url)
	return c.fakeVCS.CheckoutToDir(ctx, url, commit, dir)
}

// proxyWithOrigin returns a fake proxy that reports a VCS Origin for coord.
func proxyWithOrigin(coord coordinate.ModuleCoordinate, originURL string) *fakeProxy {
	return &fakeProxy{
		infos: map[string]ports.ModuleInfo{
			coord.String(): {
				Version: coord.Version(),
				Origin: &ports.ModuleOrigin{
					URL:  originURL,
					Hash: strings.Repeat("a", 40),
				},
			},
		},
	}
}

func mustAllowlist(t *testing.T, hosts ...string) domain2.VCSHostAllowlist {
	t.Helper()
	a, err := domain2.NewVCSHostAllowlist(hosts)
	if err != nil {
		t.Fatalf("building allowlist: %v", err)
	}
	return a
}

// Narrowing the policy to a subset must provably stop the excluded forge from
// reaching git, and must say so in the record rather than degrading silently.
func TestExecute_NarrowedVCSHostsRejectsExcludedOrigin(t *testing.T) {
	coord := coordinatetest.MustNew("gitlab.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}
	facts := newFakeFacts()

	uc := newUseCase(proxyWithOrigin(coord, "https://gitlab.com/foo/bar"), vcs, newFakeBlob(), facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: coord,
		VCSHosts:   mustAllowlist(t, "github.com"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if vcs.checkouts.Load() != 0 {
		t.Error("a host excluded by policy must never reach a git checkout")
	}
	if !strings.Contains(result.Record.VerificationDetail, "not on the VCS allowlist") {
		t.Errorf("the record must say why verification degraded, got %q", result.Record.VerificationDetail)
	}
	if result.Record.VerificationStatus == string(domain2.Verified) {
		t.Error("a module whose Origin was refused must not be reported Verified")
	}
}

// The same Origin under the default allowlist is accepted, so the test above is
// measuring the policy rather than an unrelated rejection.
func TestExecute_DefaultVCSHostsAcceptTheSameOrigin(t *testing.T) {
	coord := coordinatetest.MustNew("gitlab.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	uc := newUseCase(proxyWithOrigin(coord, "https://gitlab.com/foo/bar"), vcs, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if vcs.checkouts.Load() == 0 {
		t.Fatal("the default allowlist should have accepted this Origin for cross-verification")
	}
	if strings.Contains(result.Record.VerificationDetail, "not on the VCS allowlist") {
		t.Errorf("unexpected allowlist rejection under the default set: %q", result.Record.VerificationDetail)
	}
}

// The policy field NARROWS. Under the built-in advisory set an unknown forge is
// contacted (with a warning); naming allowed_vcs_hosts without it is what
// refuses. This pins both halves against the same forge, so the difference
// measured is the policy and nothing else.
func TestExecute_PolicyNarrowsToRefuseForgeTheDefaultPermits(t *testing.T) {
	coord := coordinatetest.MustNew("git.example.org/foo/bar", "v1.0.0")

	// Default: advisory, so the Origin reaches git.
	permissive := &countingVCS{}
	ucDefault := newUseCase(proxyWithOrigin(coord, "https://git.example.org/foo/bar"), permissive, newFakeBlob(), newFakeFacts())
	before, err := ucDefault.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if permissive.checkouts.Load() == 0 {
		t.Fatal("the advisory default must hand an unlisted forge to git, not refuse it")
	}
	if strings.Contains(before.Record.VerificationDetail, "not on the VCS allowlist") {
		t.Errorf("the default set must not refuse, got %q", before.Record.VerificationDetail)
	}

	// Policy names the forges it will talk to, and this one is not among them.
	strict := &countingVCS{}
	ucNarrow := newUseCase(proxyWithOrigin(coord, "https://git.example.org/foo/bar"), strict, newFakeBlob(), newFakeFacts())
	after, err := ucNarrow.Execute(context.Background(), application.FetchRequest{
		Coordinate: coord,
		VCSHosts:   mustAllowlist(t, "github.com"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strict.checkouts.Load() != 0 {
		t.Error("a host excluded by policy must never reach a git checkout")
	}
	if !strings.Contains(after.Record.VerificationDetail, "not on the VCS allowlist") {
		t.Errorf("the record must say why verification degraded, got %q", after.Record.VerificationDetail)
	}
}

// An inferred clone URL is kanonarion's own guess rather than proxy metadata,
// but it is still handed to git — so the policy must gate it too, or "trust
// github.com only" would still clone gitlab.
func TestExecute_NarrowedVCSHostsGateInferredCloneURL(t *testing.T) {
	coord := coordinatetest.MustNew("gitlab.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	// No Origin in the proxy info: the fetcher infers https://gitlab.com/foo/bar.
	uc := newUseCase(&fakeProxy{}, vcs, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: coord,
		VCSHosts:   mustAllowlist(t, "github.com"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if vcs.resolved.Load() != 0 {
		t.Errorf("an inferred URL on an excluded host must not reach git, but %v was resolved", vcs.lastURL.Load())
	}
	if !strings.Contains(result.Record.VerificationDetail, "refused") {
		t.Errorf("the record must explain the refusal, got %q", result.Record.VerificationDetail)
	}
}

// The control for the test above: the same inferred URL is used when the policy
// allows the host.
func TestExecute_InferredCloneURLUsedWhenHostIsAllowed(t *testing.T) {
	coord := coordinatetest.MustNew("gitlab.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	uc := newUseCase(&fakeProxy{}, vcs, newFakeBlob(), newFakeFacts())
	if _, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: coord,
		VCSHosts:   mustAllowlist(t, "gitlab.com"),
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if vcs.resolved.Load() == 0 {
		t.Error("an inferred URL on an allowed host should have been resolved")
	}
}

// The allowlist governs WHICH forges are trusted, never WHETHER git runs: with
// verification skipped, no host is contacted regardless of the configured set.
func TestExecute_SkipVCSVerifyStillWinsOverTheAllowlist(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	uc := newUseCase(proxyWithOrigin(coord, "https://github.com/foo/bar"), vcs, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate:    coord,
		SkipVCSVerify: true,
		VCSHosts:      mustAllowlist(t, "github.com"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if vcs.checkouts.Load() != 0 {
		t.Error("--skip-vcs-verify must keep git out of the run entirely")
	}
	if result.Record.VerificationStatus == string(domain2.Verified) {
		t.Error("a skipped git leg must not be reported as fully Verified")
	}
}
