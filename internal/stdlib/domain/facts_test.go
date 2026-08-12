package domain_test

import (
	"strings"
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

// TestAnchorLimitation_NamesOnlyTheAnchorsReached is the regression for an SBOM
// that stated one fixed sentence — "anchored to go.dev/dl published checksum and
// googlesource tag/commit" — whatever the measurement had actually reached. An
// offline run records VerifiedLocalToolchain with neither anchor consulted, so
// the sentence made the document contradict its own detail line in the stronger,
// unsafe direction.
func TestAnchorLimitation_NamesOnlyTheAnchorsReached(t *testing.T) {
	cases := []struct {
		name        string
		status      domain.VerificationStatus
		vcs         bool
		mustContain []string
		mustNotHave []string
		// sharedWording marks a case that deliberately renders the same sentence
		// as another: an absent status and one this build does not recognise are
		// the same state — nothing here names an anchor — and must read alike.
		sharedWording bool
	}{
		{
			name:        "godev checksum with commit anchor",
			status:      domain.VerifiedGoDevChecksum,
			vcs:         true,
			mustContain: []string{"integrity anchored to the source-tarball checksum go.dev/dl publishes", "cross-checked against a go.googlesource.com/go release tag"},
		},
		{
			name:        "godev checksum without commit anchor",
			status:      domain.VerifiedGoDevChecksum,
			mustContain: []string{"integrity anchored to the source-tarball checksum go.dev/dl publishes", "no go.googlesource.com/go tag/commit anchor was established"},
			mustNotHave: []string{"cross-checked"},
		},
		{
			name:        "local toolchain claims neither anchor",
			status:      domain.VerifiedLocalToolchain,
			mustContain: []string{"locally-held toolchain source", "was not consulted", "no go.googlesource.com/go tag/commit anchor was established"},
			mustNotHave: []string{"integrity anchored to", "cross-checked"},
		},
		{
			name:        "mismatch claims no anchor",
			status:      domain.GoDevChecksumMismatch,
			mustContain: []string{"integrity NOT anchored", "did not match"},
			mustNotHave: []string{"integrity anchored to"},
		},
		{
			name:        "manifest unavailable claims no anchor",
			status:      domain.UnverifiedGoDevUnavailable,
			mustContain: []string{"not anchored to a published checksum", "could not be consulted"},
			mustNotHave: []string{"integrity anchored to"},
		},
		{
			name:        "no status recorded claims no anchor",
			status:      "",
			mustContain: []string{"integrity anchor not recorded"},
			mustNotHave: []string{"integrity anchored to", "cross-checked"},
		},
		{
			name:          "status this build does not know claims no anchor",
			status:        domain.VerificationStatus("VerifiedBySomethingLater"),
			mustContain:   []string{"integrity anchor not recorded"},
			mustNotHave:   []string{"integrity anchored to", "cross-checked"},
			sharedWording: true,
		},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := domain.AnchorLimitation(tc.status, tc.vcs)
			for _, want := range tc.mustContain {
				if !strings.Contains(got, want) {
					t.Errorf("limitation for %q missing %q:\n%s", tc.status, want, got)
				}
			}
			for _, unwanted := range tc.mustNotHave {
				if strings.Contains(got, unwanted) {
					t.Errorf("limitation for %q must not claim %q:\n%s", tc.status, unwanted, got)
				}
			}
			// The ceiling holds on every route and is the reason the property
			// exists, so it is never dropped by the derivation.
			if !strings.Contains(got, "weaker than a module sumdb transparency-log entry") ||
				!strings.Contains(got, "never present in go.sum") {
				t.Errorf("limitation for %q dropped the sumdb/go.sum ceiling:\n%s", tc.status, got)
			}
			if tc.sharedWording {
				return
			}
			if prev, dup := seen[got]; dup {
				t.Errorf("limitation for %q is word-for-word the one for %q; the property would not vary with the evidence", tc.name, prev)
			}
			seen[got] = tc.name
		})
	}
}
