// Package golden tests byte-identical FactRecord JSON output for known fixtures.
package golden_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// canonicalFixture returns the reference FactRecord for the gorilla/mux fixture.
func canonicalFixture() domain2.FactRecord {
	h := domain2.CanonicalHasher{}
	r := domain2.FactRecord{
		SchemaVersion:      domain2.SchemaVersion,
		Ecosystem:          domain2.EcosystemGo,
		ModulePath:         "github.com/gorilla/mux",
		ModuleVersion:      "v1.8.1",
		ModuleHash:         "h1:fixture-zip-hash==",
		GoModHash:          "h1:fixture-gomod-hash==",
		GitURL:             "https://github.com/gorilla/mux",
		GitRef:             "refs/tags/v1.8.1",
		GitCommitHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		VerificationStatus: "Verified",
		VerificationDetail: "",
		FetchedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:    "0.2.0",
		ContentLocation:    "sha256:" + strings.Repeat("a", 64),
		Retracted:          false,
	}
	var err error
	r, err = h.SetContentHash(r)
	if err != nil {
		panic(err)
	}
	return r
}

func TestGoldenFactRecord(t *testing.T) {
	fixture := canonicalFixture()

	h := domain2.CanonicalHasher{}
	got, err := h.Marshal(fixture)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	goldenPath := "gorilla-mux-v1.8.1.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, append(got, '\n'), 0o600); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
		t.Log("golden file updated")
		return
	}

	want, err := os.ReadFile(goldenPath) //nolint:gosec
	if err != nil {
		t.Skipf("golden file not found (%v); run UPDATE_GOLDEN=1 go test to generate", err)
	}
	// Normalise: compare parsed JSON to avoid trailing-newline issues.
	var gotJSON, wantJSON interface{}
	if err := json.Unmarshal(got, &gotJSON); err != nil {
		t.Fatalf("parsing got: %v", err)
	}
	if err := json.Unmarshal(want, &wantJSON); err != nil {
		t.Fatalf("parsing want: %v", err)
	}
	gotBytes, _ := json.Marshal(gotJSON)
	wantBytes, _ := json.Marshal(wantJSON)
	if string(gotBytes) != string(wantBytes) {
		t.Errorf("golden mismatch\ngot:  %s\nwant: %s", gotBytes, wantBytes)
	}
}
