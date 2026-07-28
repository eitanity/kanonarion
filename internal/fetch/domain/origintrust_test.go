package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateOriginForCheckout_AcceptsHTTPSAllowlistedHost(t *testing.T) {
	commit := strings.Repeat("a", 40)
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://github.com/foo/bar", "refs/tags/v1.0.0", commit); err != nil {
		t.Fatalf("expected allowlisted https Origin to validate, got %v", err)
	}
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://gitlab.com/foo/bar", "", strings.Repeat("b", 64)); err != nil {
		t.Fatalf("expected 64-char sha256 commit to validate, got %v", err)
	}
	// go.googlesource.com is a first-party Go host (golang.org/x, google.golang.org).
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://go.googlesource.com/mod", "", commit); err != nil {
		t.Fatalf("expected go.googlesource.com Origin to validate, got %v", err)
	}
	// codeberg.org (Forgejo) and gopkg.in (git-serving redirector) appear as
	// resolved Origins in real dependency graphs and must cross-verify.
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://codeberg.org/foo/bar", "", commit); err != nil {
		t.Fatalf("expected codeberg.org Origin to validate, got %v", err)
	}
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://gopkg.in/ini.v1", "", commit); err != nil {
		t.Fatalf("expected gopkg.in Origin to validate, got %v", err)
	}
}

func TestValidateOriginForCheckout_RejectsDangerousTransports(t *testing.T) {
	commit := strings.Repeat("a", 40)
	cases := []struct {
		name string
		url  string
	}{
		{"ext", `ext::sh -c "touch /tmp/pwned"`},
		{"file", "file:///etc/passwd"},
		{"ssh", "ssh://git@internal.host/repo"},
		{"git", "git://github.com/foo/bar"},
		{"leading dash", "--upload-pack=touch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout(tc.url, "", commit); err == nil {
				t.Errorf("expected %q to be rejected", tc.url)
			}
		})
	}
}

// The built-in set is advisory: a host outside it is reported and still
// contacted. Refusing by default would cap cross-verification at whichever
// forges kanonarion ships a name for and silently degrade every other ecosystem
// to checksum-DB-only, which is the condition the coverage report exists to
// surface rather than to cause.
func TestCheckOriginForCheckout_DefaultWarnsAndPermitsUnlistedHost(t *testing.T) {
	commit := strings.Repeat("a", 40)
	warning, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://git.example.com/foo/bar", "", commit)
	if err != nil {
		t.Fatalf("the default set must not refuse an unlisted host: %v", err)
	}
	if warning == "" {
		t.Error("an unlisted host must still be reported")
	}
	if !strings.Contains(warning, "git.example.com") {
		t.Errorf("the warning must name the host, got %q", warning)
	}
	if !strings.Contains(warning, "allowed_vcs_hosts") {
		t.Errorf("the warning must name the policy field that would refuse it, got %q", warning)
	}
}

// A policy-configured list means it. This is the same host as above, and the
// only difference is that an operator named the forges they will talk to.
func TestCheckOriginForCheckout_PolicyListRefusesUnlistedHost(t *testing.T) {
	narrowed, err := NewVCSHostAllowlist([]string{"github.com"})
	if err != nil {
		t.Fatalf("NewVCSHostAllowlist: %v", err)
	}
	if !narrowed.IsEnforcing() {
		t.Fatal("a policy-configured list must enforce")
	}
	commit := strings.Repeat("a", 40)
	warning, err := narrowed.CheckOriginForCheckout("https://git.example.com/foo/bar", "", commit)
	if err == nil {
		t.Fatal("an enforcing list must refuse a host outside it")
	}
	if warning != "" {
		t.Errorf("a refusal must not also warn, got %q", warning)
	}
}

// Advisory mode is about host identity only. The URL-shape invariants are the
// RCE vectors and hold in both modes, so a scheme the allowlist has no opinion
// about is still a hard failure under the default set.
func TestCheckCloneURL_ShapeInvariantsHoldInAdvisoryMode(t *testing.T) {
	for _, raw := range []string{
		"ext::sh -c touch/foo",
		"file:///etc/passwd",
		"ssh://git@github.com/foo/bar",
		"git://github.com/foo/bar",
		"http://github.com/foo/bar",
		"-upload-pack=touch",
	} {
		if _, err := DefaultVCSHostAllowlist().CheckCloneURL(raw); err == nil {
			t.Errorf("%q must be refused even by an advisory list", raw)
		}
	}
}

func TestValidateOriginForCheckout_RejectsFlagLikeCommitAndRef(t *testing.T) {
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://github.com/foo/bar", "", "--upload-pack=touch"); err == nil {
		t.Error("expected flag-like commit to be rejected")
	}
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout("https://github.com/foo/bar", "-malicious", strings.Repeat("a", 40)); err == nil {
		t.Error("expected leading-dash ref to be rejected")
	}
}

func TestValidateCommitHash(t *testing.T) {
	if err := ValidateCommitHash(strings.Repeat("a", 40)); err != nil {
		t.Errorf("40-hex should pass: %v", err)
	}
	if err := ValidateCommitHash(strings.Repeat("a", 64)); err != nil {
		t.Errorf("64-hex should pass: %v", err)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", 40), "-" + strings.Repeat("a", 39)} {
		if err := ValidateCommitHash(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestDefaultVCSHosts_MatchesTheDocumentedBuiltInSet(t *testing.T) {
	want := []string{
		"bitbucket.org", "codeberg.org", "github.com",
		"gitlab.com", "go.googlesource.com", "gopkg.in",
	}
	got := DefaultVCSHosts()
	if len(got) != len(want) {
		t.Fatalf("default host set changed: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("default host set changed: got %v, want %v", got, want)
		}
	}
	// The returned slice must be a copy: a caller mutating it must not be able
	// to widen or narrow the built-in trust set for the rest of the process.
	got[0] = "evil.example.com"
	if DefaultVCSHosts()[0] != "bitbucket.org" {
		t.Fatal("DefaultVCSHosts returned an aliased slice; the built-in set is mutable")
	}
}

func TestZeroVCSHostAllowlist_EnforcesTheDefaultSet(t *testing.T) {
	var zero VCSHostAllowlist
	if !zero.IsAllowed("github.com") {
		t.Error("zero allowlist must enforce the built-in set, not an empty one")
	}
	if zero.IsAllowed("evil.example.com") {
		t.Error("zero allowlist must not trust everything")
	}
	if !zero.IsDefault() {
		t.Error("zero allowlist should report as default")
	}
	if len(zero.Hosts()) != len(DefaultVCSHosts()) {
		t.Errorf("zero allowlist should report the default hosts, got %v", zero.Hosts())
	}
}

func TestNewVCSHostAllowlist_NarrowsAndWidens(t *testing.T) {
	narrow, err := NewVCSHostAllowlist([]string{"github.com"})
	if err != nil {
		t.Fatalf("narrowing to a single forge should be accepted: %v", err)
	}
	if !narrow.IsAllowed("github.com") {
		t.Error("github.com should be allowed by the narrowed list")
	}
	if narrow.IsAllowed("gitlab.com") {
		t.Error("gitlab.com must be rejected by a github-only list (override replaces, not merges)")
	}
	if narrow.IsDefault() {
		t.Error("a narrowed list must not report as the default set")
	}

	wide, err := NewVCSHostAllowlist(append(DefaultVCSHosts(), "git.example.org"))
	if err != nil {
		t.Fatalf("widening with a new forge should be accepted: %v", err)
	}
	if !wide.IsAllowed("git.example.org") {
		t.Error("an added forge should be allowed without a rebuild")
	}
	if !wide.IsAllowed("github.com") {
		t.Error("widening must keep the listed defaults")
	}
}

func TestNewVCSHostAllowlist_RejectsEmptyListNamingSkipFlag(t *testing.T) {
	_, err := NewVCSHostAllowlist(nil)
	if err == nil {
		t.Fatal("an empty allowlist must be rejected")
	}
	if !errors.Is(err, ErrEmptyVCSHostAllowlist) {
		t.Fatalf("expected ErrEmptyVCSHostAllowlist, got %v", err)
	}
	if !strings.Contains(err.Error(), "--skip-vcs-verify") {
		t.Errorf("the empty-list error must point at the supported way to disable VCS verification, got %q", err)
	}
	if _, err := NewVCSHostAllowlist([]string{}); err == nil {
		t.Error("an explicitly empty list must be rejected too")
	}
}

func TestNewVCSHostAllowlist_RejectsMalformedEntriesNamingTheEntry(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{"scheme", "https://github.com"},
		{"path", "github.com/foo"},
		{"port", "github.com:443"},
		{"wildcard", "*.github.com"},
		{"uppercase", "GitHub.com"},
		{"user info", "git@github.com"},
		{"empty label", "github..com"},
		{"leading hyphen label", "-github.com"},
		{"trailing hyphen label", "github-.com"},
		{"invalid character", "git_hub.com"},
		{"empty entry", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVCSHostAllowlist([]string{tc.host})
			if err == nil {
				t.Fatalf("expected %q to be rejected", tc.host)
			}
			if tc.host != "" && !strings.Contains(err.Error(), tc.host) {
				t.Errorf("error must name the offending entry %q, got %q", tc.host, err)
			}
		})
	}
}

func TestVCSHostAllowlist_HostsIsSortedAndCopied(t *testing.T) {
	a, err := NewVCSHostAllowlist([]string{"gitlab.com", "github.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hosts := a.Hosts()
	if len(hosts) != 2 || hosts[0] != "github.com" || hosts[1] != "gitlab.com" {
		t.Fatalf("expected sorted hosts, got %v", hosts)
	}
	hosts[0] = "evil.example.com"
	if a.Hosts()[0] != "github.com" {
		t.Error("Hosts returned an aliased slice; the allowlist is mutable from outside")
	}
}

func TestVCSHostAllowlist_IsDefaultDistinguishesSameSizeSets(t *testing.T) {
	swapped := DefaultVCSHosts()
	swapped[0] = "git.example.org"
	a, err := NewVCSHostAllowlist(swapped)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.IsDefault() {
		t.Error("a same-size set with a different member must not report as default")
	}
}

func TestValidateOriginForCheckout_PolicyOverrideGovernsHostOnly(t *testing.T) {
	commit := strings.Repeat("a", 40)
	narrow, err := NewVCSHostAllowlist([]string{"github.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The configured forge still verifies.
	if _, err := narrow.CheckOriginForCheckout("https://github.com/foo/bar", "", commit); err != nil {
		t.Fatalf("expected the configured forge to validate, got %v", err)
	}
	// A default forge left out of the override no longer does.
	if _, err := narrow.CheckOriginForCheckout("https://gitlab.com/foo/bar", "", commit); err == nil {
		t.Error("expected a host excluded by the policy to be rejected")
	}
	// Every non-host invariant still holds under an override.
	if _, err := narrow.CheckOriginForCheckout("ssh://github.com/foo/bar", "", commit); err == nil {
		t.Error("non-https transport must stay rejected regardless of the allowlist")
	}
	if _, err := narrow.CheckOriginForCheckout("https://github.com/foo/bar", "", "--upload-pack=touch"); err == nil {
		t.Error("flag-like commit must stay rejected regardless of the allowlist")
	}
	if _, err := narrow.CheckOriginForCheckout("https://github.com/foo/bar", "-evil", commit); err == nil {
		t.Error("leading-dash ref must stay rejected regardless of the allowlist")
	}
}

func TestValidateCloneURL_RejectsUnparseableURL(t *testing.T) {
	if _, err := DefaultVCSHostAllowlist().CheckCloneURL("https://gith ub.com/\x7f"); err == nil {
		t.Error("expected an unparseable clone URL to be rejected")
	}
}
