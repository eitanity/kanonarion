package domain

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// defaultVCSHosts is the built-in set of https hosts kanonarion is willing to
// hand to a git subprocess for cross-verification. An Origin pointing anywhere
// else is treated as untrusted rather than blindly cloned (the module proxy is
// untrusted, so its Origin metadata is too). This is a superset of the forges
// inferRepoURL can construct URLs for: it also includes go.googlesource.com so
// the golang.org/x and google.golang.org ecosystem keeps full VCS
// cross-verification rather than degrading to checksum-DB-only.
//
// codeberg.org (Forgejo) and gopkg.in (git-serving version redirector) are
// included because real dependency graphs resolve modules there — without them
// a self-audit emits origin_rejected and silently drops to checksum-DB-only for
// those modules instead of cross-verifying the repo against go.sum.
//
// This set is the DEFAULT, not the last word: the fetch-stage policy field
// allowed_vcs_hosts replaces it wholesale when present. Any host in the
// effective, policy-resolved set must stay in sync with the harden-runner
// egress allowlist in .github/workflows/release.yml, or the release-time
// self-audit can resolve the Origin but not reach it. `kanonarion policy show`
// prints the effective set.
var defaultVCSHosts = []string{
	"bitbucket.org",
	"codeberg.org",
	"github.com",
	"gitlab.com",
	"go.googlesource.com",
	"gopkg.in",
}

// DefaultVCSHosts returns a copy of the built-in VCS forge allowlist, sorted.
// It is the fallback used when a policy carries no allowed_vcs_hosts field.
func DefaultVCSHosts() []string {
	out := make([]string, len(defaultVCSHosts))
	copy(out, defaultVCSHosts)
	return out
}

// VCSHostAllowlist is the resolved set of https hosts that may be handed to a
// git subprocess during VCS cross-verification. It is a value, not a package
// global: the effective set comes from the fetch-stage policy, falling back to
// DefaultVCSHosts.
//
// The zero value is usable and enforces the built-in default set. There is no
// such thing as an empty allowlist — "verify nothing" is the orthogonal
// SkipVCSVerify flag, which never runs git at all, rather than a list that
// resolves an Origin and then rejects every host.
type VCSHostAllowlist struct {
	hosts map[string]bool
}

// DefaultVCSHostAllowlist returns the allowlist built from DefaultVCSHosts.
func DefaultVCSHostAllowlist() VCSHostAllowlist {
	return VCSHostAllowlist{hosts: hostSet(defaultVCSHosts)}
}

// NewVCSHostAllowlist builds an allowlist from an operator-supplied host list,
// validating every entry. It fails closed: a malformed entry is rejected naming
// the entry rather than silently dropped, because a silently narrowed trust
// list degrades every affected module to checksum-DB-only verification without
// saying so.
//
// An empty list is rejected: disabling VCS cross-verification is
// --skip-vcs-verify, not an allowlist that trusts nobody.
func NewVCSHostAllowlist(hosts []string) (VCSHostAllowlist, error) {
	if len(hosts) == 0 {
		return VCSHostAllowlist{}, ErrEmptyVCSHostAllowlist
	}
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if err := ValidateVCSHost(h); err != nil {
			return VCSHostAllowlist{}, err
		}
		set[h] = true
	}
	return VCSHostAllowlist{hosts: set}, nil
}

// ErrEmptyVCSHostAllowlist is returned when an allowlist is configured with no
// entries. It names the supported way to turn VCS verification off so the
// operator is not left guessing.
var ErrEmptyVCSHostAllowlist = fmt.Errorf(
	"VCS host allowlist must not be empty: it selects WHICH forges are trusted, not WHETHER " +
		"cross-verification runs; to skip the git leg entirely use --skip-vcs-verify " +
		"(checksum-database verification still runs)")

// ValidateVCSHost checks that host is a bare, lowercased hostname: no scheme,
// no port, no path, no user info, no wildcard. Exact matching is the whole
// point — a subdomain wildcard would widen the set of URLs handed to git beyond
// what the operator can read off the policy file.
func ValidateVCSHost(host string) error {
	switch {
	case host == "":
		return fmt.Errorf("VCS host must not be empty")
	case strings.Contains(host, "://"):
		return fmt.Errorf("VCS host %q must be a bare hostname, not a URL (drop the scheme)", host)
	case strings.Contains(host, "/"):
		return fmt.Errorf("VCS host %q must be a bare hostname, not a path (drop everything after the host)", host)
	case strings.Contains(host, ":"):
		return fmt.Errorf("VCS host %q must not carry a port (https is implied)", host)
	case strings.Contains(host, "*"):
		return fmt.Errorf("VCS host %q must not use a wildcard: hosts are matched exactly", host)
	case strings.Contains(host, "@"):
		return fmt.Errorf("VCS host %q must not carry user info", host)
	case host != strings.ToLower(host):
		return fmt.Errorf("VCS host %q must be lowercase", host)
	}
	for _, label := range strings.Split(host, ".") {
		if err := validateHostLabel(host, label); err != nil {
			return err
		}
	}
	return nil
}

// validateHostLabel checks one dot-separated label of a hostname: non-empty,
// alphanumeric plus internal hyphens.
func validateHostLabel(host, label string) error {
	if label == "" {
		return fmt.Errorf("VCS host %q has an empty label", host)
	}
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return fmt.Errorf("VCS host %q has a label that starts or ends with '-'", host)
	}
	for _, r := range label {
		if !isHostRune(r) {
			return fmt.Errorf("VCS host %q contains an invalid character %q", host, string(r))
		}
	}
	return nil
}

func isHostRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
}

func hostSet(hosts []string) map[string]bool {
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		set[h] = true
	}
	return set
}

// Hosts returns the allowlisted hosts, sorted. The zero value reports the
// built-in default set, which is what it enforces.
func (a VCSHostAllowlist) Hosts() []string {
	if len(a.hosts) == 0 {
		return DefaultVCSHosts()
	}
	out := make([]string, 0, len(a.hosts))
	for h := range a.hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// IsDefault reports whether this allowlist enforces exactly the built-in
// default set rather than a policy override. Used for reporting, never for
// enforcement.
func (a VCSHostAllowlist) IsDefault() bool {
	if len(a.hosts) == 0 {
		return true
	}
	if len(a.hosts) != len(defaultVCSHosts) {
		return false
	}
	for _, h := range defaultVCSHosts {
		if !a.hosts[h] {
			return false
		}
	}
	return true
}

// IsAllowed reports whether host is on the allowlist. The zero value enforces
// the built-in default set, so an unconfigured allowlist never trusts nothing
// (which would silently degrade every module to checksum-DB-only).
func (a VCSHostAllowlist) IsAllowed(host string) bool {
	if len(a.hosts) == 0 {
		return hostSet(defaultVCSHosts)[host]
	}
	return a.hosts[host]
}

// ValidateCommitHash returns an error unless commit is a full 40-character
// SHA-1 or 64-character SHA-256 hex string. This is the gate that keeps a
// proxy-supplied commit from reaching a git subprocess as a flag-like
// positional argument (e.g. "--upload-pack=...") or as an unintended ref.
func ValidateCommitHash(commit string) error {
	if len(commit) != 40 && len(commit) != 64 {
		return fmt.Errorf("commit hash must be 40 or 64 hex chars, got %d", len(commit))
	}
	for _, r := range commit {
		if !isHexDigit(r) {
			return fmt.Errorf("commit hash %q contains a non-hex character", commit)
		}
	}
	return nil
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// ValidateOriginForCheckout validates an untrusted VCS Origin (from a module
// proxy's @v/info metadata) before any of its fields are handed to a git
// subprocess. It enforces the https-only, allowlisted-host, hex-commit
// invariants and rejects URL/ref values git would otherwise interpret as
// options. A nil return means the Origin is safe to check out; a non-nil error
// means the caller must treat the Origin as missing/untrusted, never Verified.
//
// Only the host check is policy-governed. Every other invariant (https-only,
// hex commit, leading-dash / ext:: / file:// / ssh:// / git:// rejection) holds
// regardless of the configured allowlist.

func (a VCSHostAllowlist) ValidateOriginForCheckout(rawURL, ref, commit string) error {
	if err := a.ValidateCloneURL(rawURL); err != nil {
		return err
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("git ref %q must not begin with '-'", ref)
	}
	return ValidateCommitHash(commit)
}

// ValidateCloneURL accepts only https URLs whose host is on the allowlist.
// Non-https schemes (ext::, file://, ssh://, git://) are the RCE/SSRF vectors
// and are rejected here; a leading '-' is rejected before parsing so it can
// never reach git as a flag. It is exported because an inferred clone URL
// (built by kanonarion rather than supplied by the proxy) must clear the same
// host gate before it is handed to git.
func (a VCSHostAllowlist) ValidateCloneURL(rawURL string) error {
	if strings.HasPrefix(rawURL, "-") {
		return fmt.Errorf("clone URL %q must not begin with '-'", rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing clone URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("clone URL scheme must be https, got %q", u.Scheme)
	}
	if !a.IsAllowed(u.Hostname()) {
		return fmt.Errorf("clone URL host %q is not on the VCS allowlist", u.Hostname())
	}
	return nil
}
