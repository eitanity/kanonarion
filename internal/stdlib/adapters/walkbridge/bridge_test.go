package walkbridge_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/walkbridge"
	stdlibapp "github.com/eitanity/kanonarion/internal/stdlib/application"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// stub ports for constructing a real Acquirer whose behaviour the bridge maps.
type stubManifest struct{ releases []domain.Release }

func (s stubManifest) FetchReleases(context.Context) ([]domain.Release, error) {
	return s.releases, nil
}

type stubTarball struct{ data []byte }

func (s stubTarball) Download(context.Context, string) ([]byte, error) { return s.data, nil }

type stubCommits struct{ commit string }

func (s stubCommits) ResolveCommit(context.Context, string, string) (string, error) {
	return s.commit, nil
}

type stubLicense struct{ spdx string }

func (s stubLicense) Identify(context.Context, []byte) (string, error) { return s.spdx, nil }

type stubStore struct{ m map[string]domain.Facts }

func (s *stubStore) Get(_ context.Context, v string) (domain.Facts, bool, error) {
	f, ok := s.m[v]
	return f, ok, nil
}
func (s *stubStore) Put(_ context.Context, f domain.Facts) error {
	s.m[f.GoVersion] = f
	return nil
}

func TestBridge_MapsFactsAndDigests(t *testing.T) {
	store := &stubStore{m: map[string]domain.Facts{
		"go1.26.4": {
			GoVersion:          "go1.26.4",
			LicenseSPDX:        "BSD-3-Clause",
			VerificationStatus: domain.VerifiedGoDevChecksum,
			VerificationDetail: "matched",
			PublishedSHA256:    "aa",
			SourceURL:          "https://go.dev/dl/go1.26.4.src.tar.gz",
			VCSURL:             domain.VCSRepoURL,
			VCSRef:             "go1.26.4",
			VCSCommit:          "commit1",
			Digests:            fetchdomain.ArtifactDigests{SHA256: "aa256", SHA384: "bb384", SHA512: "cc512"},
		},
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	acq := stdlibapp.NewAcquirer(stubManifest{}, stubTarball{}, stubCommits{}, stubLicense{}, store, nil, nil, logger)
	bridge := walkbridge.New(acq)

	facts, digests, err := bridge.AcquireStdlib(context.Background(), "v1.26.4", false, false)
	if err != nil {
		t.Fatalf("AcquireStdlib: %v", err)
	}
	if facts.LicenseSPDX != "BSD-3-Clause" {
		t.Errorf("license = %q", facts.LicenseSPDX)
	}
	if facts.VerificationStatus != "VerifiedGoDevChecksum" {
		t.Errorf("verification status = %q, want mapped string", facts.VerificationStatus)
	}
	if facts.VCSCommit != "commit1" {
		t.Errorf("commit = %q", facts.VCSCommit)
	}
	if digests.SHA256 != "aa256" {
		t.Errorf("digests not carried: %+v", digests)
	}
}
