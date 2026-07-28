package application_test

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
)

// Tests for inferRepoURL and splitPath via the use case execution paths.

func TestExecute_InferRepoURL_GitHub(t *testing.T) {
	// Module on github.com — URL should be inferable.
	coord := coordinatetest.MustNew("github.com/pkg/errors", "v0.9.1")
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
	coord := coordinatetest.MustNew("github.com/foo/bar", "v0.0.0-20210101120000-abcdefabcdef")
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

// gopkg.in is on the default VCS allowlist deliberately — real dependency
// graphs resolve modules there, and without it a self-audit drops those modules
// to checksum-DB-only. A hardcoded forge switch inside inferRepoURL used to
// withhold a candidate URL for it anyway, so the allowlist admitted a host the
// inferrer would never propose. This pins the two back in agreement: a
// two-element path yields the host/repo URL its host serves.
func TestExecute_InferRepoURL_TwoElementPath(t *testing.T) {
	coord := coordinatetest.MustNew("gopkg.in/yaml.v3", "v3.0.1")
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got, want := result.Record.GitURL, "https://gopkg.in/yaml.v3"; got != want {
		t.Errorf("GitURL = %q, want %q", got, want)
	}
}

// The inferrer names no forge, and the built-in host set is advisory, so a host
// neither has heard of still gets a candidate and still reaches git. Correctness
// is settled downstream by reproducing the zip from the checkout, so an unknown
// host cannot make a wrong answer look right — it can only cost a failed clone.
func TestExecute_InferRepoURL_UnlistedHostStillAttempted(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/org/mod", "v1.0.0")
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got, want := result.Record.GitURL, "https://example.com/org/mod"; got != want {
		t.Errorf("GitURL = %q, want %q: the advisory default must not withhold the candidate", got, want)
	}
	if strings.Contains(result.Record.VerificationDetail, "not on the VCS allowlist") {
		t.Errorf("the default set must warn, not refuse: %q", result.Record.VerificationDetail)
	}
}

// The same inferred host under a policy that names its forges is refused before
// it reaches git, and the record says so rather than reporting a vaguer cause.
func TestExecute_InferRepoURL_PolicyRefusesUnlistedHost(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/org/mod", "v1.0.0")
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: coord,
		VCSHosts:   mustAllowlist(t, "github.com"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.GitURL != "" {
		t.Errorf("GitURL = %q: a host excluded by policy must not be handed to git", result.Record.GitURL)
	}
	if !strings.Contains(result.Record.VerificationDetail, "not on the VCS allowlist") {
		t.Errorf("VerificationDetail = %q, want the allowlist refusal named", result.Record.VerificationDetail)
	}
}
