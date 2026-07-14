package domain_test

import (
	"bytes"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestWalkRecordHasher_StdlibFactsRoundTrip verifies the stdlib chain-of-custody
// facts survive the canonical marshal/unmarshal round-trip and are covered by
// the content hash.
func TestWalkRecordHasher_StdlibFactsRoundTrip(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), "")

	std, err := fetchdomain.NewModuleCoordinate(domain3.StdlibModulePath, "v1.26.4")
	if err != nil {
		t.Fatal(err)
	}
	facts := &domain3.StdlibFacts{
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: "VerifiedGoDevChecksum",
		VerificationDetail: "matched go.dev/dl; commit abc",
		PublishedSHA256:    "aa256",
		SourceURL:          "https://go.dev/dl/go1.26.4.src.tar.gz",
		VCSURL:             "https://go.googlesource.com/go",
		VCSRef:             "go1.26.4",
		VCSCommit:          "deadbeef",
	}
	rec.Graph.Nodes = append(rec.Graph.Nodes, domain3.GraphNode{
		Coordinate:       std,
		DirectDependency: true,
		ResolutionSource: domain3.ResolutionStdlib,
		Digests:          fetchdomain.ArtifactDigests{SHA256: "aa256", SHA384: "bb384", SHA512: "cc512"},
		Stdlib:           facts,
	})

	rec, err = hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := hasher.VerifyContentHash(rec); err != nil {
		t.Fatalf("VerifyContentHash: %v", err)
	}

	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	var got *domain3.StdlibFacts
	for _, n := range back.Graph.Nodes {
		if n.ResolutionSource == domain3.ResolutionStdlib {
			got = n.Stdlib
		}
	}
	if got == nil {
		t.Fatal("stdlib facts lost in round-trip")
	}
	if *got != *facts {
		t.Errorf("stdlib facts after round-trip = %+v, want %+v", *got, *facts)
	}
}

// TestWalkRecordHasher_NoStdlibFactsOmitted verifies a walk with no stdlib facts
// omits the "stdlib" key entirely, so pre-custody records hash identically.
func TestWalkRecordHasher_NoStdlibFactsOmitted(t *testing.T) {
	hasher := domain3.WalkRecordHasher{}
	rec, err := hasher.SetContentHash(
		domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, buildOutcome(), domain3.DefaultDepthPolicy(), ""),
	)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("\"stdlib\"")) {
		t.Errorf("a walk with no stdlib facts must omit the stdlib key, got: %s", data)
	}
}
