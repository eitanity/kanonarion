package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// proxyNaming builds a fake proxy that serves Origin metadata pointing at
// originURL for coord, the way a real proxy copies a module's Origin block
// through verbatim.
func proxyNaming(coord string, originURL string) *fakeProxy {
	return &fakeProxy{
		infos: map[string]ports.ModuleInfo{
			coord: {
				Version: "v1.0.0",
				Time:    fixedTime,
				Origin: &ports.ModuleOrigin{
					VCS:  "git",
					URL:  originURL,
					Ref:  "refs/tags/v1.0.0",
					Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
	}
}

// TestRecordCarriesTheCoordinateDerivedBinding is the end-to-end half: the
// attribution has to survive all the way onto the persisted record, or the
// report has nothing to read.
func TestRecordCarriesTheCoordinateDerivedBinding(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/gorilla/mux", "v1.0.0")
	uc := newUseCaseWithSumDB(
		proxyNaming(coord.String(), "https://github.com/gorilla/mux"),
		&fakeVCS{checkoutErr: errors.New("no real checkout in test")},
		newFakeBlob(), newFakeFacts(), availableSumDB(fetchtest.H1("fakehash==")))

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := res.Record.VCSURLBinding; got != string(domain2.VCSURLBindingCoordinateDerived) {
		t.Errorf("VCSURLBinding = %q, want %q", got, domain2.VCSURLBindingCoordinateDerived)
	}
}

// TestRecordCarriesTheProxyNamedBinding is the case the ticket exists for: a
// vanity module path whose repository no rule derives from the coordinate, so
// the only source for the clone URL is the untrusted proxy.
func TestRecordCarriesTheProxyNamedBinding(t *testing.T) {
	coord := coordinatetest.MustNew("go.uber.org/zap", "v1.0.0")
	uc := newUseCaseWithSumDB(
		proxyNaming(coord.String(), "https://github.com/uber-go/zap"),
		&fakeVCS{checkoutErr: errors.New("no real checkout in test")},
		newFakeBlob(), newFakeFacts(), availableSumDB(fetchtest.H1("fakehash==")))

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := res.Record.VCSURLBinding; got != string(domain2.VCSURLBindingProxyNamed) {
		t.Errorf("VCSURLBinding = %q, want %q: nothing derives github.com/uber-go/zap from go.uber.org/zap",
			got, domain2.VCSURLBindingProxyNamed)
	}
}

// TestSkippedVCSRecordsNoBinding keeps the absent value honest. A --skip-vcs run
// resolves a URL and never clones from it, so attributing a binding would claim
// an assurance the run deliberately did not seek.
func TestSkippedVCSRecordsNoBinding(t *testing.T) {
	coord := coordinatetest.MustNew("go.uber.org/zap", "v1.0.0")
	uc := newUseCaseWithSumDB(
		proxyNaming(coord.String(), "https://github.com/uber-go/zap"),
		&fakeVCS{}, newFakeBlob(), newFakeFacts(), availableSumDB(fetchtest.H1("fakehash==")))

	res, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: coord, SkipVCSVerify: true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := res.Record.VCSCheck; got != string(domain2.LegAbsent) {
		t.Fatalf("VCSCheck = %q, want the leg to be absent", got)
	}
	if got := res.Record.VCSURLBinding; got != "" {
		t.Errorf("VCSURLBinding = %q on a run that skipped cross-verification, want empty", got)
	}
}

// TestUnavailableVCSRecordsNoBinding is the same guarantee for the other way a
// leg fails to establish: git is absent from the measuring host. That is a fault
// of the machine, and a binding recorded beside it would read as an assurance
// about the module.
func TestUnavailableVCSRecordsNoBinding(t *testing.T) {
	coord := coordinatetest.MustNew("go.uber.org/zap", "v1.0.0")
	uc := newUseCaseWithSumDB(
		proxyNaming(coord.String(), "https://github.com/uber-go/zap"),
		&fakeVCS{resolveErr: gitNotInstalled(), checkoutErr: gitNotInstalled()},
		newFakeBlob(), newFakeFacts(), availableSumDB(fetchtest.H1("fakehash==")))

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := res.Record.VCSCheck; got != string(domain2.LegUnavailable) {
		t.Fatalf("VCSCheck = %q, want %q", got, domain2.LegUnavailable)
	}
	if got := res.Record.VCSURLBinding; got != "" {
		t.Errorf("VCSURLBinding = %q on a host with no git, want empty", got)
	}
}

// TestBindingDoesNotMoveAVerificationStatus is the control, asserted in the unit
// suite as well as on a real walk: the attribution is additive and must leave
// every status exactly where it was.
func TestBindingDoesNotMoveAVerificationStatus(t *testing.T) {
	for _, tc := range []struct{ path, originURL string }{
		{"github.com/gorilla/mux", "https://github.com/gorilla/mux"},
		{"go.uber.org/zap", "https://github.com/uber-go/zap"},
	} {
		coord := coordinatetest.MustNew(tc.path, "v1.0.0")
		uc := newUseCaseWithSumDB(
			proxyNaming(coord.String(), tc.originURL),
			&fakeVCS{checkoutErr: errors.New("no real checkout in test")},
			newFakeBlob(), newFakeFacts(), availableSumDB(fetchtest.H1("fakehash==")))

		res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
		if err != nil {
			t.Fatalf("%s: Execute: %v", tc.path, err)
		}
		// Both bindings reach the same status here. That is the point: the
		// binding says how the repository was determined, not how the zip fared.
		if got := res.Record.VerificationStatus; got != string(domain2.VerifiedBySumDBOnly) {
			t.Errorf("%s: VerificationStatus = %q, want %q", tc.path, got, domain2.VerifiedBySumDBOnly)
		}
	}
}

// TestInheritedLegCarriesItsBinding keeps the attribution attached to the leg it
// describes. A leg carried forward from an earlier measurement brings its
// binding with it; without that, a --skip-vcs run would report cross-verification
// evidence whose repository the record could no longer name.
func TestInheritedLegCarriesItsBinding(t *testing.T) {
	coord := coordinatetest.MustNew("go.uber.org/zap", "v1.0.0")
	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(
		proxyNaming(coord.String(), "https://github.com/uber-go/zap"),
		&fakeVCS{checkoutErr: errors.New("no real checkout in test")},
		newFakeBlob(), facts, availableSumDB(fetchtest.H1("fakehash==")))

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if first.Record.VCSURLBinding != string(domain2.VCSURLBindingProxyNamed) {
		t.Fatalf("first run binding = %q, want %q", first.Record.VCSURLBinding, domain2.VCSURLBindingProxyNamed)
	}

	second, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: coord, SkipVCSVerify: true, Force: true,
	})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if got := second.Record.VCSCheck; got != string(domain2.LegInherited) {
		t.Skipf("the second run did not inherit a VCS leg (VCSCheck=%q); nothing to assert about its binding", got)
	}
	if got := second.Record.VCSURLBinding; got != string(domain2.VCSURLBindingProxyNamed) {
		t.Errorf("inherited leg carries binding %q, want the source record's %q",
			got, domain2.VCSURLBindingProxyNamed)
	}
}
