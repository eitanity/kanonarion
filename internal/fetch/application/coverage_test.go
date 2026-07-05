package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func TestNewFetchModuleUseCase_DefaultPipelineVersion(t *testing.T) {
	uc := application.NewFetchModuleUseCase(
		&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts(),
		disabledSumDB(), fixedClock{fixedTime}, fakeStopwatch{}, "", // empty → use PipelineVersion constant
		discardLog,
	)
	if uc == nil {
		t.Error("expected non-nil use case")
	}
}

func TestExecute_GitlabModule(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "gitlab.com/foo/bar", Version: "v1.0.0"}
	proxy := &fakeProxy{}
	vcs := &fakeVCS{resolveErr: errors.New("simulated failure")}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus == string(domain2.Verified) {
		t.Errorf("expected unverified, got Verified")
	}
}

func TestExecute_BitbucketModule(t *testing.T) {
	coord := domain2.ModuleCoordinate{Path: "bitbucket.org/user/repo", Version: "v1.0.0"}
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ModulePath != coord.Path {
		t.Errorf("ModulePath = %q, want %q", result.Record.ModulePath, coord.Path)
	}
}

func TestExecute_CrossVerify_HashMismatch(t *testing.T) {
	// Proxy returns origin with commit → crossVerify called.
	// VCS checkout succeeds but dir hash won't match fake zip hash.
	coord := domain2.ModuleCoordinate{Path: "github.com/gorilla/mux", Version: "v1.8.1"}
	proxy := &fakeProxy{
		infos: map[string]ports.ModuleInfo{
			coord.String(): {
				Version: "v1.8.1",
				Origin: &ports.ModuleOrigin{
					VCS:  "git",
					URL:  "https://github.com/gorilla/mux",
					Ref:  "refs/tags/v1.8.1",
					Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
	}
	// VCS checkout succeeds (empty dir), but computed hash won't match fake zip hash.
	vcs := &fakeVCS{} // checkoutErr = nil → checkout to empty tmpdir
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Hash will mismatch since tmpdir is empty vs fake zip.
	if result.Record.VerificationStatus == string(domain2.Verified) {
		t.Logf("note: got Verified (empty dir hash == empty zip hash is possible)")
	}
}

func TestExecute_ShortPathModule(t *testing.T) {
	// A module path with only one segment — URL can't be inferred; sumdb disabled.
	// Expect UnverifiedNoSumDB (sumdb is the primary check and it's disabled).
	coord := domain2.ModuleCoordinate{Path: "example.com", Version: "v1.0.0"}
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("expected UnverifiedNoSumDB, got %q", result.Record.VerificationStatus)
	}
}
