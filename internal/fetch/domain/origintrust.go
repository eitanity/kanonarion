package domain

import (
	"fmt"
	"net/url"
	"strings"
)

// allowedVCSHosts is the set of fixed, first-party https hosts kanonarion is
// willing to hand to a git subprocess for cross-verification. An Origin
// pointing anywhere else is treated as untrusted rather than blindly cloned
// (the module proxy is untrusted, so its Origin metadata is too). This is a
// superset of the forges inferRepoURL can construct URLs for: it also includes
// go.googlesource.com so the golang.org/x and google.golang.org ecosystem keeps
// full VCS cross-verification rather than degrading to checksum-DB-only.
//
// codeberg.org (Forgejo) and gopkg.in (git-serving version redirector) are
// added because real dependency graphs resolve modules there — without them a
// self-audit emits origin_rejected and silently drops to checksum-DB-only for
// those modules instead of cross-verifying the repo against go.sum. Any host
// added here must stay in sync with the harden-runner egress allowlist in
// .github/workflows/release.yml, or the release-time self-audit can resolve
// the Origin but not reach it.
var allowedVCSHosts = map[string]bool{
	"github.com":          true,
	"gitlab.com":          true,
	"bitbucket.org":       true,
	"go.googlesource.com": true,
	"codeberg.org":        true,
	"gopkg.in":            true,
}

// IsAllowedVCSHost reports whether host is on the VCS forge allowlist.
func IsAllowedVCSHost(host string) bool {
	return allowedVCSHosts[host]
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
func ValidateOriginForCheckout(rawURL, ref, commit string) error {
	if err := validateCloneURL(rawURL); err != nil {
		return err
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("git ref %q must not begin with '-'", ref)
	}
	return ValidateCommitHash(commit)
}

// validateCloneURL accepts only https URLs whose host is on the forge
// allowlist. Non-https schemes (ext::, file://, ssh://, git://) are the RCE/SSRF
// vectors and are rejected here; a leading '-' is rejected before parsing so it
// can never reach git as a flag.
func validateCloneURL(rawURL string) error {
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
	if !IsAllowedVCSHost(u.Hostname()) {
		return fmt.Errorf("clone URL host %q is not on the VCS allowlist", u.Hostname())
	}
	return nil
}
