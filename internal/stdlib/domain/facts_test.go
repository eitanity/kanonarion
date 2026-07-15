package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

func TestCanonicalGoVersion(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"go1.26.4", "go1.26.4"},
		{"1.26.4", "go1.26.4"},
		{"v1.26.4", "go1.26.4"},
		{"  go1.26.4  ", "go1.26.4"},
		{"1.26", "go1.26"},
		{"", ""},
		{"   ", ""},
		{"v", ""},
		{"go", ""},
	}
	for _, c := range cases {
		if got := domain.CanonicalGoVersion(c.in); got != c.want {
			t.Errorf("CanonicalGoVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSourceTarballHelpers(t *testing.T) {
	if got := domain.SourceTarballName("go1.26.4"); got != "go1.26.4.src.tar.gz" {
		t.Errorf("SourceTarballName = %q", got)
	}
	if got := domain.SourceTarballURL("go1.26.4"); got != "https://go.dev/dl/go1.26.4.src.tar.gz" {
		t.Errorf("SourceTarballURL = %q", got)
	}
}

func TestVerificationStatusVerified(t *testing.T) {
	if !domain.VerifiedGoDevChecksum.Verified() {
		t.Error("VerifiedGoDevChecksum.Verified() = false, want true")
	}
	for _, s := range []domain.VerificationStatus{domain.GoDevChecksumMismatch, domain.UnverifiedGoDevUnavailable} {
		if s.Verified() {
			t.Errorf("%s.Verified() = true, want false", s)
		}
	}
}
