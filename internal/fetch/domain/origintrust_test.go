package domain

import (
	"strings"
	"testing"
)

func TestValidateOriginForCheckout_AcceptsHTTPSAllowlistedHost(t *testing.T) {
	commit := strings.Repeat("a", 40)
	if err := ValidateOriginForCheckout("https://github.com/foo/bar", "refs/tags/v1.0.0", commit); err != nil {
		t.Fatalf("expected allowlisted https Origin to validate, got %v", err)
	}
	if err := ValidateOriginForCheckout("https://gitlab.com/foo/bar", "", strings.Repeat("b", 64)); err != nil {
		t.Fatalf("expected 64-char sha256 commit to validate, got %v", err)
	}
	// go.googlesource.com is a first-party Go host (golang.org/x, google.golang.org).
	if err := ValidateOriginForCheckout("https://go.googlesource.com/mod", "", commit); err != nil {
		t.Fatalf("expected go.googlesource.com Origin to validate, got %v", err)
	}
	// codeberg.org (Forgejo) and gopkg.in (git-serving redirector) appear as
	// resolved Origins in real dependency graphs and must cross-verify.
	if err := ValidateOriginForCheckout("https://codeberg.org/foo/bar", "", commit); err != nil {
		t.Fatalf("expected codeberg.org Origin to validate, got %v", err)
	}
	if err := ValidateOriginForCheckout("https://gopkg.in/ini.v1", "", commit); err != nil {
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
			if err := ValidateOriginForCheckout(tc.url, "", commit); err == nil {
				t.Errorf("expected %q to be rejected", tc.url)
			}
		})
	}
}

func TestValidateOriginForCheckout_RejectsNonAllowlistedHost(t *testing.T) {
	commit := strings.Repeat("a", 40)
	if err := ValidateOriginForCheckout("https://evil.example.com/foo/bar", "", commit); err == nil {
		t.Error("expected non-allowlisted host to be rejected")
	}
}

func TestValidateOriginForCheckout_RejectsFlagLikeCommitAndRef(t *testing.T) {
	if err := ValidateOriginForCheckout("https://github.com/foo/bar", "", "--upload-pack=touch"); err == nil {
		t.Error("expected flag-like commit to be rejected")
	}
	if err := ValidateOriginForCheckout("https://github.com/foo/bar", "-malicious", strings.Repeat("a", 40)); err == nil {
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
