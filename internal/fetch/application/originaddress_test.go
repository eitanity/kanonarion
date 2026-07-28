package application_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// A literal address is the easy case; a NAME that answers into private space is
// the form an SSRF attempt actually takes, and it is the one the URL-only guard
// cannot settle. The Origin here looks entirely ordinary.
func TestExecute_OriginNameResolvingIntoPrivateSpaceIsRefused(t *testing.T) {
	// The module lives on github.com; the proxy claims its source is somewhere
	// else entirely. That mismatch is the attack shape — a hostile proxy points
	// the checkout at a host the operator never named — and it is why the guard
	// is on the Origin path rather than the inferred one.
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	const evil = "https://internal-metadata.example.com/foo/bar"
	uc := newUseCase(proxyWithOrigin(coord, evil), vcs, newFakeBlob(), newFakeFacts())
	uc.WithHostResolver(func(_ context.Context, host string) ([]net.IP, error) {
		if host == "internal-metadata.example.com" {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return []net.IP{net.ParseIP("140.82.121.4")}, nil
	})

	if _, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The refused Origin falls through to the inferred URL by design, so the
	// measurement that matters is WHICH host git was given — never the one the
	// proxy named, only the one the module path did.
	last, _ := vcs.lastURL.Load().(string)
	if strings.Contains(last, "internal-metadata.example.com") {
		t.Errorf("git was handed the refused Origin host: %q", last)
	}
	if last != "https://github.com/foo/bar" {
		t.Errorf("last URL = %q, want the inferred URL from the module path", last)
	}
}

// A refused Origin whose fall-through also fails must report the refusal as the
// primary cause, so the record names the real problem rather than the vaguer
// downstream one.
func TestExecute_RefusedOriginIsNamedInTheRecord(t *testing.T) {
	// A bare-host path: nothing can be inferred, so this is the simple case
	// where the refusal is the only thing that could be reported.
	coord := coordinatetest.MustNew("example.com", "v1.0.0")
	vcs := &countingVCS{}

	uc := newUseCase(proxyWithOrigin(coord, "https://10.0.0.7/foo/bar"), vcs, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(result.Record.VerificationDetail, "not a public address") {
		t.Errorf("the record must name the Origin refusal, got %q", result.Record.VerificationDetail)
	}
	if result.Record.VerificationStatus == string(domain2.Verified) {
		t.Error("a refused Origin must not be reported Verified")
	}
}

// The guard must not turn network weather into a verification verdict. A name
// that cannot be resolved may be offline, mid-DNS-outage, or simply moved;
// treating that as a hostile Origin would degrade verification for reasons that
// have nothing to do with the module. git reports the real cause when it dials.
func TestExecute_OriginResolutionFailureIsNotARefusal(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	uc := newUseCase(proxyWithOrigin(coord, "https://github.com/foo/bar"), vcs, newFakeBlob(), newFakeFacts())
	uc.WithHostResolver(func(_ context.Context, _ string) ([]net.IP, error) {
		return nil, errors.New("dns is having a day")
	})

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(result.Record.VerificationDetail, "not a public address") {
		t.Errorf("an unresolvable name must not be reported as a private address: %q", result.Record.VerificationDetail)
	}
	if vcs.checkouts.Load() == 0 {
		t.Error("an unresolvable name must still be handed to git, which reports the real cause")
	}
}

// A public answer passes through untouched, so the test above is measuring the
// guard rather than an unrelated rejection.
func TestExecute_OriginResolvingPubliclyIsUnaffected(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	uc := newUseCase(proxyWithOrigin(coord, "https://github.com/foo/bar"), vcs, newFakeBlob(), newFakeFacts())
	uc.WithHostResolver(func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.4")}, nil
	})

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if vcs.checkouts.Load() == 0 {
		t.Fatal("a publicly-resolving Origin must reach cross-verification")
	}
	if strings.Contains(result.Record.VerificationDetail, "not a public address") {
		t.Errorf("unexpected address refusal: %q", result.Record.VerificationDetail)
	}
}

// The asymmetry is the point: an inferred URL's host comes from a module path
// the operator chose to depend on, so an internal forge there is a dependency,
// not an attack. The resolver would answer privately for it and it must still
// be attempted.
func TestExecute_InferredHostIsNotSubjectToTheAddressGuard(t *testing.T) {
	coord := coordinatetest.MustNew("git.internal.corp/team/lib", "v1.0.0")
	vcs := &countingVCS{}

	// No Origin: the inferred path answers.
	uc := newUseCase(&fakeProxy{}, vcs, newFakeBlob(), newFakeFacts())
	uc.WithHostResolver(func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.7")}, nil
	})

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got, want := result.Record.GitURL, "https://git.internal.corp/team/lib"; got != want {
		t.Errorf("GitURL = %q, want %q: an internal forge named in go.mod must still be attempted", got, want)
	}
	if strings.Contains(result.Record.VerificationDetail, "not a public address") {
		t.Errorf("the address guard must not apply to inferred URLs: %q", result.Record.VerificationDetail)
	}
}

// The masking case, and the reason the refusal is carried separately from the
// detail rather than folded into it.
//
// The drop condition is the inferred fall-through RESOLVING A REF: that returns
// a provisional Verified, so the old code had no failure to attach the refusal
// to and discarded it, and crossVerify then overwrote the detail anyway. A run
// that repelled an SSRF attempt was left indistinguishable on disk from one
// that never faced it. Verified by reverting the fix: without it this record
// reads "disabled in tests; vcs: ..." and never mentions the Origin.
func TestExecute_RefusedOriginSurvivesWhenInferenceResolves(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	vcs := &countingVCS{}

	uc := newUseCase(proxyWithOrigin(coord, "https://10.0.0.7/foo/bar"), vcs, newFakeBlob(), newFakeFacts())
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Inference resolved and the inferred URL reached git: the drop condition.
	if got, want := result.Record.GitURL, "https://github.com/foo/bar"; got != want {
		t.Fatalf("GitURL = %q, want %q — this test is only meaningful when inference resolves", got, want)
	}
	if !strings.Contains(result.Record.VerificationDetail, "not a public address") {
		t.Errorf("the refusal must survive inference resolving a ref, got %q", result.Record.VerificationDetail)
	}
	if !strings.Contains(result.Record.VerificationDetail, "10.0.0.7") {
		t.Errorf("the record must name the Origin it declined, got %q", result.Record.VerificationDetail)
	}
}
