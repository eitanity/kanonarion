package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/coordinate"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
)

// This file pins one rule across the two surfaces that used to break it: a
// staleness column nobody measured is null with a reason, never true and never
// false. Each unmeasured leg is paired with the measured control it must not
// resemble, asserted on exact bytes so the fix cannot be paid for by changing
// what a measured row emits.

// failingStalenessLookup is a lookup that cannot answer. A live proxy cannot be
// asked to fail on demand, so the leg the ticket is about is only reachable
// through a fake.
type failingStalenessLookup struct{ err error }

func (f failingStalenessLookup) Resolve(context.Context, string, string) (staleapp.Answer, error) {
	return staleapp.Answer{}, f.err
}

// answeringStalenessLookup is the measured control.
type answeringStalenessLookup struct{ latest string }

func (a answeringStalenessLookup) Resolve(_ context.Context, path, _ string) (staleapp.Answer, error) {
	return staleapp.Answer{Record: staledomain.Record{
		ModulePath:    path,
		LatestVersion: a.latest,
	}}, nil
}

// stubLatestInfo answers fetch's proxy question, or fails to.
type stubLatestInfo struct {
	info proxyadapter.LatestVersionInfo
	err  error
}

func (s stubLatestInfo) LatestInfo(context.Context, string) (proxyadapter.LatestVersionInfo, error) {
	return s.info, s.err
}

// TestLatestGomod_FailedLookupIsNullNotBehind is the `latest` half of the fix.
// The text path was already honest ("(error resolving latest)"); --json
// contradicted it with `"is_latest": false`, the claim "your pin is behind"
// about a module nothing was measured for.
func TestLatestGomod_FailedLookupIsNullNotBehind(t *testing.T) {
	var stderr bytes.Buffer
	row := latestRowFor(context.Background(),
		failingStalenessLookup{err: errStalenessTestProxyDown},
		"github.com/foo/bar", "v1.0.0", &stderr)

	data, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling: %v", uerr)
	}
	got, present := decoded["is_latest"]
	if !present {
		t.Fatal("is_latest is absent; the key must stay, carrying null")
	}
	if got != nil {
		t.Errorf("is_latest = %v, want null: the lookup failed, so nothing was measured", got)
	}
	if decoded["staleness_unmeasured"] != stalenessLookupFailed {
		t.Errorf("staleness_unmeasured = %v, want %q", decoded["staleness_unmeasured"], stalenessLookupFailed)
	}

	// The text path keeps the line it already printed, unchanged.
	var table bytes.Buffer
	if terr := printLatestTable(&table, []latestResult{row}); terr != nil {
		t.Fatalf("printLatestTable: %v", terr)
	}
	if !strings.Contains(table.String(), "(error resolving latest)") {
		t.Errorf("table lost its error cell:\n%s", table.String())
	}
	if !strings.Contains(stderr.String(), "latest github.com/foo/bar:") {
		t.Errorf("the failure was not reported on stderr: %q", stderr.String())
	}
}

// TestLatestGomod_MeasuredRowsStillAnswer is the zero-pair: a measured pin still
// emits true or false, byte-identically to what it emitted before is_latest
// became nullable.
func TestLatestGomod_MeasuredRowsStillAnswer(t *testing.T) {
	tests := []struct {
		name   string
		latest string
		pinned string
		want   bool
		cell   string
	}{
		{name: "current pin", latest: "v1.0.0", pinned: "v1.0.0", want: true, cell: "current"},
		{name: "behind pin", latest: "v1.2.0", pinned: "v1.0.0", want: false, cell: "latest: v1.2.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			row := latestRowFor(context.Background(),
				answeringStalenessLookup{latest: tc.latest},
				"github.com/foo/bar", tc.pinned, &stderr)

			if row.IsLatest == nil {
				t.Fatal("is_latest is null on a measured row")
			}
			if *row.IsLatest != tc.want {
				t.Errorf("is_latest = %v, want %v", *row.IsLatest, tc.want)
			}
			if row.StalenessUnmeasured != "" {
				t.Errorf("staleness_unmeasured = %q on a measured row, want absent", row.StalenessUnmeasured)
			}
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if strings.Contains(string(data), "staleness_unmeasured") {
				t.Errorf("a measured row emits an unmeasured reason: %s", data)
			}
			var table bytes.Buffer
			if terr := printLatestTable(&table, []latestResult{row}); terr != nil {
				t.Fatalf("printLatestTable: %v", terr)
			}
			if !strings.Contains(table.String(), tc.cell) {
				t.Errorf("table cell = %q, want it to contain %q", table.String(), tc.cell)
			}
			if strings.Contains(table.String(), "unmeasured") {
				t.Errorf("a measured row rendered as unmeasured:\n%s", table.String())
			}
		})
	}
}

// TestLatestModules_NoPinIsNotAsked covers the bare-path lookup. `latest
// <module>` names no pin, so there is no comparison to report; it used to hard-
// code is_latest true, which reads as a clean bill of health for a version the
// caller never mentioned.
func TestLatestModules_NoPinIsNotAsked(t *testing.T) {
	prev := jsonOut
	jsonOut = true
	t.Cleanup(func() { jsonOut = prev })

	srv := fakeLatestProxy(t, map[string]string{"github.com/spf13/cobra": "v1.10.2"})
	defer srv.Close()

	var stdout bytes.Buffer
	if err := runLatestModules(context.Background(),
		[]string{"github.com/spf13/cobra"}, latestResolverFor(t, srv), &stdout, io.Discard); err != nil {
		t.Fatalf("runLatestModules: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshalling: %v\noutput: %s", err, stdout.String())
	}
	if got, present := decoded["is_latest"]; !present || got != nil {
		t.Errorf("is_latest = %v (present %v), want null: no pin was named", got, present)
	}
	if decoded["staleness_unmeasured"] != stalenessNotAsked {
		t.Errorf("staleness_unmeasured = %v, want %q", decoded["staleness_unmeasured"], stalenessNotAsked)
	}
	// The answer the command was actually asked for is unaffected.
	if decoded["latest"] != "v1.10.2" {
		t.Errorf("latest = %v, want v1.10.2", decoded["latest"])
	}
}

// TestFetchStaleness_UnmeasuredLegs covers fetch's two absences. Both used to
// stand on `stalenessInfo{IsLatest: true}`, so a failed lookup and an unasked
// question alike reported the fetched module as current, with no note in text.
func TestFetchStaleness_UnmeasuredLegs(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	tests := []struct {
		name      string
		requested string
		proxy     latestInfoLookup
		reason    string
		note      string
		wantErrLn bool
	}{
		{
			name:      "failed lookup",
			requested: "v1.0.0",
			proxy:     stubLatestInfo{err: errStalenessTestProxyDown},
			reason:    stalenessLookupFailed,
			note:      " [staleness unmeasured (lookup failed)]",
			wantErrLn: true,
		},
		{
			name:      "at latest, never asked",
			requested: "latest",
			proxy:     stubLatestInfo{info: proxyadapter.LatestVersionInfo{Version: "v1.0.0"}},
			reason:    stalenessNotAsked,
			note:      " [staleness unmeasured (not asked)]",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			stale := fetchStalenessFor(context.Background(), tc.proxy, coord, tc.requested, &stderr)

			if stale.IsLatest != nil {
				t.Errorf("is_latest = %v, want null", *stale.IsLatest)
			}
			if stale.Unmeasured != tc.reason {
				t.Errorf("staleness_unmeasured = %q, want %q", stale.Unmeasured, tc.reason)
			}
			data, merr := json.Marshal(stale)
			if merr != nil {
				t.Fatalf("marshalling: %v", merr)
			}
			// pin_ahead_of_latest is null alongside is_latest: an unmeasured
			// block made no comparison, so neither question has an answer.
			want := `{"is_latest":null,"pin_ahead_of_latest":null,"staleness_unmeasured":"` + tc.reason + `","days_since_latest":null}`
			if string(data) != want {
				t.Errorf("staleness block = %s, want %s", data, want)
			}
			if got := fetchStalenessNote(stale); got != tc.note {
				t.Errorf("text note = %q, want %q: silence there means measured-and-current", got, tc.note)
			}
			if tc.wantErrLn && !strings.Contains(stderr.String(), "staleness github.com/foo/bar:") {
				t.Errorf("the failed lookup was not reported on stderr: %q", stderr.String())
			}
		})
	}
}

// TestFetchStaleness_MeasuredLegs is the zero-pair for the above: an asked and
// answered question emits exactly the bytes it always has.
func TestFetchStaleness_MeasuredLegs(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	t.Run("pin is the latest", func(t *testing.T) {
		var stderr bytes.Buffer
		stale := fetchStalenessFor(context.Background(),
			stubLatestInfo{info: proxyadapter.LatestVersionInfo{Version: "v1.0.0"}},
			coord, "v1.0.0", &stderr)

		data, merr := json.Marshal(stale)
		if merr != nil {
			t.Fatalf("marshalling: %v", merr)
		}
		// pin_ahead_of_latest is emitted false, not omitted: "measured, and not
		// ahead" must be distinguishable from "this build does not derive it".
		if want := `{"is_latest":true,"pin_ahead_of_latest":false,"days_since_latest":null}`; string(data) != want {
			t.Errorf("staleness block = %s, want %s", data, want)
		}
		if note := fetchStalenessNote(stale); note != "" {
			t.Errorf("text note = %q, want none for a current pin", note)
		}
	})

	t.Run("pin is behind", func(t *testing.T) {
		var stderr bytes.Buffer
		stale := fetchStalenessFor(context.Background(),
			stubLatestInfo{info: proxyadapter.LatestVersionInfo{
				Version: "v1.2.0",
				Time:    time.Now().Add(-72 * time.Hour),
			}},
			coord, "v1.0.0", &stderr)

		data, merr := json.Marshal(stale)
		if merr != nil {
			t.Fatalf("marshalling: %v", merr)
		}
		// The behind pin keeps its age: that is the row the figure means
		// something on, and it is the non-zero control for the ahead row, which
		// carries no days_since_latest at all.
		if want := `{"is_latest":false,"pin_ahead_of_latest":false,"latest_version":"v1.2.0","days_since_latest":3}`; string(data) != want {
			t.Errorf("staleness block = %s, want %s", data, want)
		}
		if note := fetchStalenessNote(stale); note != " [latest: v1.2.0, 3 days ago]" {
			t.Errorf("text note = %q", note)
		}
	})

	t.Run("pin sorts above the latest tag", func(t *testing.T) {
		var stderr bytes.Buffer
		stale := fetchStalenessFor(context.Background(),
			stubLatestInfo{info: proxyadapter.LatestVersionInfo{
				Version: "v0.5.5",
				Time:    time.Now().Add(-2660 * 24 * time.Hour),
			}},
			coord, "v1.0.0", &stderr)

		data, merr := json.Marshal(stale)
		if merr != nil {
			t.Fatalf("marshalling: %v", merr)
		}
		// No days_since_latest. Beside is_latest:false an age reads as "you are
		// this far behind", which is the answer this state exists to withhold —
		// and the text clause beside it offers no age either.
		if want := `{"is_latest":false,"pin_ahead_of_latest":true,"latest_version":"v0.5.5","days_since_latest":null}`; string(data) != want {
			t.Errorf("staleness block = %s, want %s", data, want)
		}
		if note := fetchStalenessNote(stale); note != " [ahead of latest tag: v0.5.5]" {
			t.Errorf("text note = %q", note)
		}
	})
}

// errStalenessTestProxyDown stands in for the transport failure neither surface
// may render as an answer.
var errStalenessTestProxyDown = errors.New("proxy: connection refused")
