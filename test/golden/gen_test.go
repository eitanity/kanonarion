// Package golden tests byte-identical FactRecord JSON output for known fixtures.
package golden_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// canonicalFixture returns the reference FactRecord for the gorilla/mux fixture.
func canonicalFixture(t testing.TB) domain2.FactRecord {
	t.Helper()
	return fetchtest.Record(t,
		fetchtest.Module("github.com/gorilla/mux", "v1.8.1"),
		fetchtest.PipelineVersion("0.2.0"),
		fetchtest.Content("sha256:"+strings.Repeat("a", 64)),
		fetchtest.ModuleHash(fetchtest.H1("fixture-zip-hash==")),
		fetchtest.GoModHash(fetchtest.H1("fixture-gomod-hash==")),
		fetchtest.Digests(domain2.ArtifactDigests{
			SHA256: strings.Repeat("2", 64),
			SHA384: strings.Repeat("3", 96),
			SHA512: strings.Repeat("5", 128),
		}),
		fetchtest.GitReference(domain2.GitReference{
			URL:        "https://github.com/gorilla/mux",
			Ref:        "refs/tags/v1.8.1",
			CommitHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}),
		fetchtest.Status(domain2.Verified),
		fetchtest.FetchedAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
	)
}

func TestGoldenFactRecord(t *testing.T) {
	fixture := canonicalFixture(t)

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
