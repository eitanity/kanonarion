package recordseal_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
)

var vulnRow = recordseal.SetAsideRow{
	Kind: "vulnerability record",
	ID:   "stdlib@v1.26.5",
	Generation: recordseal.Generation{
		PipelineVersion: "v25",
		Snapshot:        recordseal.Snapshot{Name: "vuln-db", Source: "govulndb", Version: "2026-09-16T18:00:43Z"},
	},
	ContentHash: "sha256:a2546bf0",
	Reason:      recordseal.Drift(errors.New("content hash mismatch")),
}

// The statement a vulnerability read prints is pinned word for word: the type
// moved here from the vulnerability ports, and its output did not change.
func TestSetAside_StatesEachGenerationAndTheRemedy(t *testing.T) {
	got := (&recordseal.SetAside{Rows: []recordseal.SetAsideRow{vulnRow}}).Error()
	want := "set aside 1 stored vulnerability record generation: stdlib@v1.26.5 (pipeline v25, vuln-db 2026-09-16T18:00:43Z) " +
		"content_hash sha256:a2546bf0 — " + recordseal.SetAsideRemedy
	if got != want {
		t.Errorf("Error() =\n%s\nwant\n%s", got, want)
	}

	cg := recordseal.SetAsideRow{Kind: "call graph record", ID: "example.com/m@v1.0.0",
		Generation: recordseal.Generation{PipelineVersion: "0.7.0"}, ContentHash: "sha256:bb"}
	mixed := (&recordseal.SetAside{Rows: []recordseal.SetAsideRow{vulnRow, cg}}).Error()
	if want := "set aside 2 stored record generations: "; mixed[:len(want)] != want {
		t.Errorf("mixed kinds = %q, want the neutral noun", mixed)
	}
	if got := (&recordseal.SetAside{Rows: []recordseal.SetAsideRow{{}}}).Error(); got != "set aside 1 stored record generation: unidentified record — "+recordseal.SetAsideRemedy {
		t.Errorf("an unnamed row = %q", got)
	}
}

func TestSetAside_UnwrapsToDriftOnly(t *testing.T) {
	sentinel := errors.New("store integrity")
	err := error(&recordseal.SetAside{Rows: []recordseal.SetAsideRow{vulnRow, {ID: "no reason"}}})
	if !errors.Is(err, recordseal.ErrGenerationDrift) || errors.Is(err, sentinel) {
		t.Errorf("errors.Is: drift %v, sentinel %v", errors.Is(err, recordseal.ErrGenerationDrift), errors.Is(err, sentinel))
	}
}

func TestMergeSetAside_OneRowPerGeneration(t *testing.T) {
	err := &recordseal.SetAside{Rows: []recordseal.SetAsideRow{vulnRow}}
	merged, ok := recordseal.MergeSetAside(nil, err)
	merged, _ = recordseal.MergeSetAside(merged, err)
	if !ok || len(merged) != 1 {
		t.Errorf("merged = %v (ok %v), want the generation once", merged, ok)
	}
	if _, ok := recordseal.MergeSetAside(merged, errors.New("other")); ok {
		t.Error("another error was taken for a set-aside")
	}
}

func TestNothingServable_IsAnAbsenceThatSaysWhy(t *testing.T) {
	err := error(&recordseal.NothingServable{Kind: "call graph record", ID: "example.com/m@v1.0.0",
		Aside: &recordseal.SetAside{Rows: []recordseal.SetAsideRow{vulnRow}}})
	want := "no call graph record for example.com/m@v1.0.0 that this build can serve: set aside 1 stored vulnerability record generation"
	if got := err.Error(); got[:len(want)] != want {
		t.Errorf("Error() = %q", got)
	}
	var aside *recordseal.SetAside
	if !errors.As(err, &aside) || !errors.Is(err, recordseal.ErrGenerationDrift) {
		t.Errorf("NothingServable does not unwrap to the set-aside that explains it")
	}
}

func TestGeneration_RendersOnlyWhatItHolds(t *testing.T) {
	for g, want := range map[recordseal.Generation]string{
		{}:                       "",
		{PipelineVersion: "v25"}: "(pipeline v25)",
		{Snapshot: recordseal.Snapshot{Name: "vuln-db", Source: "govulndb"}}: "",
	} {
		if got := g.String(); got != want {
			t.Errorf("%+v.String() = %q, want %q", g, got, want)
		}
	}
}

// TestReporter_NamesThroughTheConfiguredSinkOrTheLog: a configured reporter
// receives the rows; an unset one logs each at warn level, so none is dropped
// unseen; no rows is no call.
func TestReporter_NamesThroughTheConfiguredSinkOrTheLog(t *testing.T) {
	var got []recordseal.SetAsideRow
	r := recordseal.Reporter(func(rows []recordseal.SetAsideRow) { got = append(got, rows...) })
	r.Report(nil)
	r.Report([]recordseal.SetAsideRow{vulnRow})
	if len(got) != 1 || got[0].ContentHash != vulnRow.ContentHash {
		t.Errorf("reporter received %+v, want the one row", got)
	}

	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	var unset recordseal.Reporter
	unset.Report([]recordseal.SetAsideRow{vulnRow})
	if !strings.Contains(logged.String(), "level=WARN") || !strings.Contains(logged.String(), vulnRow.ContentHash) {
		t.Errorf("unset reporter logged %q, want a warning naming %s", logged.String(), vulnRow.ContentHash)
	}
}

// A NothingServable unwraps to the set-aside that explains it, but it is the
// absence of an answer: folding it in as a set-aside would let the caller serve
// the zero answer it came with as complete.
func TestMergeSetAside_RefusesNothingServable(t *testing.T) {
	aside := &recordseal.SetAside{Rows: []recordseal.SetAsideRow{vulnRow}}
	none := fmt.Errorf("reading: %w", &recordseal.NothingServable{Kind: "walk record", ID: "01W", Aside: aside})
	if recordseal.IsSetAside(none) {
		t.Error("IsSetAside(NothingServable) = true")
	}
	if !recordseal.IsSetAside(fmt.Errorf("listing: %w", aside)) {
		t.Error("IsSetAside(SetAside) = false")
	}
	if merged, ok := recordseal.MergeSetAside(nil, none); ok || len(merged) != 0 {
		t.Errorf("MergeSetAside(NothingServable) = %v, %v; want it refused", merged, ok)
	}
}
