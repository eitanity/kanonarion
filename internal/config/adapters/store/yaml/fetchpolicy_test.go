package yaml_test

import (
	"strings"
	"testing"

	configyaml "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
)

// Absent and empty are different answers. Absent leaves the built-in host set
// advisory — off-list hosts are reported and still contacted — while naming the
// key is what switches the check to enforcing. A loader that read absent as an
// empty list would refuse every forge on a config that said nothing.
func TestParse_FetchPolicyAbsentIsNotEmpty(t *testing.T) {
	cfg, err := configyaml.Parse([]byte("version: \"2\"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.FetchPolicy.AllowedVCSHosts != nil {
		t.Errorf("AllowedVCSHosts = %v, want nil for a config that does not mention it",
			cfg.FetchPolicy.AllowedVCSHosts)
	}
}

func TestParse_FetchPolicyHosts(t *testing.T) {
	cfg, err := configyaml.Parse([]byte(`version: "2"
fetch_policy:
  allowed_vcs_hosts:
    - github.com
    - git.example.org
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := cfg.FetchPolicy.AllowedVCSHosts
	if len(got) != 2 || got[0] != "github.com" || got[1] != "git.example.org" {
		t.Errorf("AllowedVCSHosts = %v, want [github.com git.example.org]", got)
	}
}

// The list is validated while the operator is looking at the config file rather
// than halfway through a walk, and the failure names the entry rather than
// silently dropping it — a silently narrowed list degrades every affected
// module to checksum-DB-only without saying so.
func TestParse_FetchPolicyRejectsUnusableHosts(t *testing.T) {
	for name, body := range map[string]string{
		"scheme":    "fetch_policy:\n  allowed_vcs_hosts: [\"https://github.com\"]\n",
		"port":      "fetch_policy:\n  allowed_vcs_hosts: [\"github.com:443\"]\n",
		"path":      "fetch_policy:\n  allowed_vcs_hosts: [\"github.com/org\"]\n",
		"wildcard":  "fetch_policy:\n  allowed_vcs_hosts: [\"*.github.com\"]\n",
		"uppercase": "fetch_policy:\n  allowed_vcs_hosts: [\"GitHub.com\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configyaml.Parse([]byte("version: \"2\"\n" + body))
			if err == nil {
				t.Fatal("an unusable host list must fail at load time")
			}
			if !strings.Contains(err.Error(), "fetch_policy.allowed_vcs_hosts") {
				t.Errorf("error must name the field, got %v", err)
			}
		})
	}
}

// An empty list is not "trust nobody" — that is --skip-vcs-verify, which never
// runs git at all, rather than a list that resolves an Origin and then rejects
// every host.
func TestParse_FetchPolicyRejectsEmptyList(t *testing.T) {
	_, err := configyaml.Parse([]byte("version: \"2\"\nfetch_policy:\n  allowed_vcs_hosts: []\n"))
	if err == nil {
		t.Fatal("an empty allowed_vcs_hosts must be rejected")
	}
	if !strings.Contains(err.Error(), "skip-vcs-verify") {
		t.Errorf("the error should name the supported way to turn the git leg off, got %v", err)
	}
}
