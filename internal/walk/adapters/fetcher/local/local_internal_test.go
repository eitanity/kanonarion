package local

import (
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// The per-walk clones must not mutate the fetcher they were derived from: the
// walker derives them per walk from one shared adapter, so a mutation would
// leak one walk's force mode or trust list into the next.
func TestWithVCSHostsClonesRatherThanMutating(t *testing.T) {
	base := New(nil, true)

	hosts, err := fetchdomain.NewVCSHostAllowlist([]string{"git.example.org"})
	if err != nil {
		t.Fatalf("building allowlist: %v", err)
	}
	clone, ok := base.WithVCSHosts(hosts).(*Fetcher)
	if !ok {
		t.Fatal("WithVCSHosts did not return a *Fetcher")
	}
	if !clone.vcsHosts.IsAllowed("git.example.org") {
		t.Error("the clone did not receive the allowlist")
	}
	if !base.vcsHosts.IsDefault() {
		t.Error("WithVCSHosts mutated the original fetcher")
	}
	if !clone.skipVCSVerify {
		t.Error("the clone lost the skip-vcs-verify setting it was constructed with")
	}
}

// Force mode and the allowlist compose: applying one must not drop the other.
func TestForceAndVCSHostsCompose(t *testing.T) {
	hosts, err := fetchdomain.NewVCSHostAllowlist([]string{"github.com"})
	if err != nil {
		t.Fatalf("building allowlist: %v", err)
	}
	forced, ok := New(nil, false).WithForce(true).(*Fetcher)
	if !ok {
		t.Fatal("WithForce did not return a *Fetcher")
	}
	both, ok := forced.WithVCSHosts(hosts).(*Fetcher)
	if !ok {
		t.Fatal("WithVCSHosts did not return a *Fetcher")
	}
	if !both.force {
		t.Error("applying the allowlist dropped force mode")
	}
	if both.vcsHosts.IsAllowed("gitlab.com") {
		t.Error("applying force dropped the allowlist")
	}
}
