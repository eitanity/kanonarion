package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/application"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// Tests for inferRepoURL and splitPath via the use case execution paths.

func TestExecute_InferRepoURL_GitHub(t *testing.T) {
	// Module on github.com — URL should be inferable.
	coord := domain.ModuleCoordinate{Path: "github.com/pkg/errors", Version: "v0.9.1"}
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// The VCS client resolves the tag; if GitURL is inferred, it should be set.
	if result.Record.GitURL == "" {
		t.Error("GitURL should be populated for github.com module")
	}
}

func TestExecute_PseudoVersion(t *testing.T) {
	coord := domain.ModuleCoordinate{
		Path:    "github.com/foo/bar",
		Version: "v0.0.0-20210101120000-abcdefabcdef",
	}
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.GitURL == "" {
		t.Error("expected GitURL to be populated for pseudo-version")
	}
	if result.Record.GitCommitHash == "" {
		t.Error("expected GitCommitHash to be populated for pseudo-version")
	}
}
