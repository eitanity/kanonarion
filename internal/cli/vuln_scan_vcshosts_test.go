package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// noHostScan satisfies the CLI's narrow ScanWalkUseCase and nothing more, which
// is what every existing test fake looks like.
type noHostScan struct{}

func (noHostScan) Scan(context.Context, vulnapp.ScanWalkParams) (vulndomain.WalkScanRun, error) {
	return vulndomain.WalkScanRun{}, nil
}

func (noHostScan) ReusableRun(context.Context, string, bool) (vulndomain.WalkScanRun, bool, error) {
	return vulndomain.WalkScanRun{}, false, nil
}

// The store config is a second source of allowed_vcs_hosts, and it reaches the
// scan through the same loadPolicy path walk and fetch use. An operator who set
// the host list once at the store level — with no policy.yaml anywhere — must be
// bound on this path too; otherwise the fix would cover only half the gap.
func TestApplyScanVCSHosts_ReadsTheStoreConfig(t *testing.T) {
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
	activeConfig = configdomain.Config{
		FetchPolicy: configdomain.FetchPolicy{AllowedVCSHosts: []string{"git.example.org"}},
	}

	// Run from a directory with no .kanonarion/policy.yaml, so the config is
	// demonstrably the only source in play.
	t.Chdir(t.TempDir())

	var stderr bytes.Buffer
	err := applyScanVCSHosts(context.Background(), noHostScan{}, "", &stderr)
	if err == nil {
		t.Fatal("a config-supplied allowlist must be enforcing, so a scan that cannot apply it must fail")
	}
	if !strings.Contains(err.Error(), "allowed_vcs_hosts") {
		t.Errorf("the error must name the policy field, got %v", err)
	}
}

// With no policy file and no config block, nothing is enforced and the narrow
// scan interface is left alone — an unconfigured kanonarion must not start
// demanding a capability from every fake and future implementation.
func TestApplyScanVCSHosts_UnconfiguredRequiresNoCapability(t *testing.T) {
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
	activeConfig = configdomain.Config{}
	t.Chdir(t.TempDir())

	var stderr bytes.Buffer
	if err := applyScanVCSHosts(context.Background(), noHostScan{}, "", &stderr); err != nil {
		t.Errorf("an unconfigured run must not require the capability, got %v", err)
	}
}
