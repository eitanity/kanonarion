package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

var probeLimit = gotoolchain.NewUnreadSource(
	gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}, []string{"example_test.go"})

// A record that met no limit carries no key for it, in the seal or in the
// record's own JSON, so every record written before the field keeps its
// bytes; one that met it round-trips and verifies.
func TestHasher_AnalyserLimitIsAbsentUnlessMet(t *testing.T) {
	var h domain2.ExampleRecordHasher
	plain := buildExampleRecord(t)
	b, err := h.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "analyser_limit") || strings.Contains(string(direct), "AnalyserLimit") {
		t.Errorf("a record without the limit carries the key:\n%s\n%s", b, direct)
	}

	limited := plain
	limited.AnalyserLimit = probeLimit
	sealed, err := h.SetContentHash(limited)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), `{"analyser_limit":{"built":"go1.26.6","files":["example_test.go"],"required":"go1.27.2"},`) {
		t.Errorf("wire shape:\n%s", raw)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.AnalyserLimit == nil || back.AnalyserLimit.Limit != probeLimit.Limit {
		t.Errorf("round trip = %+v", back.AnalyserLimit)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("round-tripped record does not verify: %v", err)
	}
}

// A record short of files this binary could not read never outranks one that
// read them, even when it is newer and has fewer parse failures.
func TestCompose_LimitRecordRanksBelow(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	read := buildExampleRecord(t)
	read.ArtefactIdentity, read.ContentHash, read.ExtractedAt = "zip:h1:a", "sha256:read", t0
	limited := read
	limited.ParseFailures = nil
	limited.AnalyserLimit = probeLimit
	limited.ContentHash, limited.ExtractedAt = "sha256:limit", t0.Add(time.Hour)

	got, err := domain2.Compose([]domain2.ExampleRecord{read, limited})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != "sha256:read" {
		t.Errorf("served %s, want the record that read every file", got.ContentHash)
	}
}

func TestSameMeasurement_LimitRecordIsNotTheFullOne(t *testing.T) {
	full := buildExampleRecord(t)
	full.ArtefactIdentity = "zip:h1:a"
	limited := full
	limited.AnalyserLimit = probeLimit
	if same, err := domain2.SameMeasurement(full, limited); err != nil || same {
		t.Errorf("SameMeasurement = %v, %v; want different measurements", same, err)
	}
}

func TestRecordIsCacheable(t *testing.T) {
	failed := buildExampleRecord(t)
	clean := failed
	clean.ParseFailures = nil
	limited := clean
	limited.AnalyserLimit = probeLimit
	for _, tc := range []struct {
		name      string
		r         domain2.ExampleRecord
		directive string
		want      bool
	}{
		{"clean", clean, "1.27.2", true},
		{"limit", limited, "1.21", false},
		{"failures, directive above the oldest writer", failed, "1.27.2", false},
		{"failures, directive the oldest writer covers", failed, "1.26.4", true},
		{"failures, directive unknown", failed, "", true},
	} {
		if got := domain2.RecordIsCacheable(tc.r, tc.directive, "go1.26.4"); got != tc.want {
			t.Errorf("%s: RecordIsCacheable = %v, want %v", tc.name, got, tc.want)
		}
	}
}
