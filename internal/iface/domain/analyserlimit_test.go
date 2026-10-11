package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/iface/domain"
)

var probeLimit = gotoolchain.NewUnreadSource(
	gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}, []string{"genmeth.go"})

// A record that met no limit carries no key for it, so every record written
// before the field existed keeps its bytes; one that met it round-trips.
func TestHasher_AnalyserLimitIsAbsentUnlessMet(t *testing.T) {
	var h domain.InterfaceRecordHasher
	plain := composedRecord(t, composed{status: domain.InterfaceStatusPartial, artefact: "zip:h1:a", at: time.Unix(0, 0).UTC(), funcName: "F"})
	plain.Ecosystem = "go"
	b, err := h.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "analyser_limit") {
		t.Errorf("a record without the limit serialises the key:\n%s", b)
	}

	limited := plain
	limited.AnalyserLimit = probeLimit
	sealed, err := h.SetContentHash(limited)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.ContentHash == mustSeal(t, plain).ContentHash {
		t.Error("the limit is outside the seal")
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"analyser_limit":{"built":"go1.26.6","files":["genmeth.go"],"required":"go1.27.2"}`) {
		t.Errorf("wire shape:\n%s", raw)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.AnalyserLimit == nil || back.AnalyserLimit.Limit != probeLimit.Limit ||
		strings.Join(back.AnalyserLimit.Files, ",") != "genmeth.go" {
		t.Errorf("round trip = %+v", back.AnalyserLimit)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("round-tripped record does not verify: %v", err)
	}
}

func mustSeal(t *testing.T, r domain.InterfaceRecord) domain.InterfaceRecord {
	t.Helper()
	s, err := domain.InterfaceRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A Partial that is short of files this binary could not read is a weaker
// measurement than a Partial short of files the module failed to parse: a
// newer binary reads them, so it never outranks one, even when newer.
func TestCompose_LimitPartialRanksBelowPlainPartial(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	plain := composedRecord(t, composed{status: domain.InterfaceStatusPartial, artefact: "zip:h1:a", hash: "sha256:plain", at: t0, funcName: "F"})
	limited := composedRecord(t, composed{status: domain.InterfaceStatusPartial, artefact: "zip:h1:a", hash: "sha256:limit", at: t0.Add(time.Hour), funcName: "G"})
	limited.AnalyserLimit = probeLimit

	got, err := domain.Compose([]domain.InterfaceRecord{plain, limited})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != "sha256:plain" {
		t.Errorf("served %s, want the Partial without the limit", got.ContentHash)
	}
}

// A limit record and a full measurement of the same tree are two measurements:
// the after-the-fact read must not take the second for the first.
func TestSameMeasurement_LimitRecordIsNotTheFullOne(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	full := composedRecord(t, composed{status: domain.InterfaceStatusPartial, artefact: "zip:h1:a", at: t0, funcName: "F"})
	limited := full
	limited.AnalyserLimit = probeLimit
	same, err := domain.SameMeasurement(full, limited)
	if err != nil {
		t.Fatal(err)
	}
	if same {
		t.Error("a record carrying the limit was the same measurement as one without it")
	}
}

func TestRecordIsCacheable(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.27.2")
	defer restore()
	failed := composedRecord(t, composed{status: domain.InterfaceStatusPartial, artefact: "zip:h1:a", funcName: "F"})
	failed.Packages[0].ParseFailures = []domain.ParseFailure{{File: "a.go", Error: "x"}}
	for _, tc := range []struct {
		name      string
		toolchain gotoolchain.Version
		limit     *gotoolchain.UnreadSource
		failures  bool
		want      bool
	}{
		{"clean, old toolchain", "go1.26.6", nil, false, true},
		{"failures, older toolchain", "go1.26.6", nil, true, false},
		{"failures, unrecorded toolchain", gotoolchain.Unrecorded, nil, true, false},
		{"failures, this toolchain", "go1.27.2", nil, true, true},
		{"limit, this toolchain", "go1.27.2", probeLimit, false, false},
	} {
		r := failed
		if !tc.failures {
			r = composedRecord(t, composed{status: domain.InterfaceStatusExtracted, artefact: "zip:h1:a", funcName: "F"})
		}
		r.Toolchain, r.AnalyserLimit = tc.toolchain, tc.limit
		if got := domain.RecordIsCacheable(r); got != tc.want {
			t.Errorf("%s: RecordIsCacheable = %v, want %v", tc.name, got, tc.want)
		}
	}
}
