package application

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// hostAwareFetcher records the allowlist it was handed, so a test can measure
// what reached the fetch rather than that a method was called.
type hostAwareFetcher struct {
	hosts fetchdomain.VCSHostAllowlist
	bound bool
}

func (f *hostAwareFetcher) FetchModule(context.Context, coordinate.ModuleCoordinate) error {
	return nil
}
func (f *hostAwareFetcher) FetchModuleGoMod(context.Context, coordinate.ModuleCoordinate) error {
	return nil
}

func (f *hostAwareFetcher) WithVCSHosts(hosts fetchdomain.VCSHostAllowlist) ports.ModuleFetcher {
	clone := *f
	clone.hosts = hosts
	clone.bound = true
	return &clone
}

// plainFetcher cannot accept an allowlist. It stands in for any future fetcher
// that forgets the capability.
type plainFetcher struct{}

func (plainFetcher) FetchModule(context.Context, coordinate.ModuleCoordinate) error      { return nil }
func (plainFetcher) FetchModuleGoMod(context.Context, coordinate.ModuleCoordinate) error { return nil }

// The operator's policy must reach the pre-fetch. Without this, which forges a
// coordinate was cross-verified against depended on whether walk or vuln-scan
// happened to fetch it first.
func TestApplyVCSHosts_BindsAnEnforcingPolicyToTheFetcher(t *testing.T) {
	hosts, err := fetchdomain.NewVCSHostAllowlist([]string{"git.example.org"})
	if err != nil {
		t.Fatalf("NewVCSHostAllowlist: %v", err)
	}

	f := &hostAwareFetcher{}
	uc := &ScanWalkUseCase{fetcher: f}
	uc.WithVCSHosts(hosts)

	if err := uc.applyVCSHosts(); err != nil {
		t.Fatalf("applyVCSHosts: %v", err)
	}
	bound, ok := uc.fetcher.(*hostAwareFetcher)
	if !ok {
		t.Fatalf("fetcher = %T, want the clone", uc.fetcher)
	}
	if !bound.bound {
		t.Fatal("the enforcing policy never reached the fetcher")
	}
	if got := bound.hosts.Hosts(); len(got) != 1 || got[0] != "git.example.org" {
		t.Errorf("fetcher received %v, want [git.example.org]", got)
	}
}

// The built-in set is advisory and is already the fetcher's zero-value
// behaviour, so there is nothing to bind and no capability to require.
func TestApplyVCSHosts_AdvisoryDefaultBindsNothing(t *testing.T) {
	uc := &ScanWalkUseCase{fetcher: plainFetcher{}}
	uc.WithVCSHosts(fetchdomain.DefaultVCSHostAllowlist())

	if err := uc.applyVCSHosts(); err != nil {
		t.Fatalf("an advisory default must not require the capability: %v", err)
	}
	if _, ok := uc.fetcher.(plainFetcher); !ok {
		t.Errorf("fetcher = %T, want it left alone", uc.fetcher)
	}
}

// A policy that cannot be applied fails the scan. Continuing would
// cross-verify against forges the operator excluded and record the result as
// though their policy had been honoured — the silent outcome this whole
// change exists to remove.
func TestApplyVCSHosts_UnapplicablePolicyFailsTheScan(t *testing.T) {
	hosts, err := fetchdomain.NewVCSHostAllowlist([]string{"git.example.org"})
	if err != nil {
		t.Fatalf("NewVCSHostAllowlist: %v", err)
	}

	uc := &ScanWalkUseCase{fetcher: plainFetcher{}}
	uc.WithVCSHosts(hosts)

	err = uc.applyVCSHosts()
	if err == nil {
		t.Fatal("a fetcher that cannot apply an enforcing policy must fail the scan")
	}
	if !strings.Contains(err.Error(), "allowed_vcs_hosts") {
		t.Errorf("the error must name the policy field, got %v", err)
	}
	if !strings.Contains(err.Error(), "WithVCSHosts") {
		t.Errorf("the error must name what the fetcher is missing, got %v", err)
	}
}

// A policy naming exactly the built-in hosts is still an operator decision to
// refuse everything else. Gating on "differs from the built-in set" would
// silently downgrade it to the advisory default — the bug this pins.
func TestApplyVCSHosts_PolicyMatchingTheBuiltInSetStillEnforces(t *testing.T) {
	hosts, err := fetchdomain.NewVCSHostAllowlist(fetchdomain.DefaultVCSHosts())
	if err != nil {
		t.Fatalf("NewVCSHostAllowlist: %v", err)
	}
	if !hosts.IsDefault() {
		t.Fatal("fixture assumption: this list should look identical to the built-in set")
	}

	f := &hostAwareFetcher{}
	uc := &ScanWalkUseCase{fetcher: f}
	uc.WithVCSHosts(hosts)

	if err := uc.applyVCSHosts(); err != nil {
		t.Fatalf("applyVCSHosts: %v", err)
	}
	bound, ok := uc.fetcher.(*hostAwareFetcher)
	if !ok || !bound.bound {
		t.Fatal("a policy identical to the built-in set must still be bound: it enforces, the built-in set does not")
	}
}

// The walk stage gates on the same question and got it wrong for the same
// reason. This is the vuln-side twin of that regression: an operator whose
// policy happens to list exactly the built-in hosts has still chosen to
// enforce, and must not be handed the advisory default.
func TestApplyVCSHosts_EnforcingIsTheGateNotDifference(t *testing.T) {
	for name, hosts := range map[string]fetchdomain.VCSHostAllowlist{
		"zero value":   {},
		"built-in set": fetchdomain.DefaultVCSHostAllowlist(),
	} {
		t.Run(name, func(t *testing.T) {
			if hosts.IsEnforcing() {
				t.Error("only a policy-configured list may enforce")
			}
		})
	}

	policy, err := fetchdomain.NewVCSHostAllowlist([]string{"github.com"})
	if err != nil {
		t.Fatalf("NewVCSHostAllowlist: %v", err)
	}
	if !policy.IsEnforcing() {
		t.Error("a policy-configured list must enforce")
	}
}
