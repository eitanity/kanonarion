package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/coordinate"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
)

// A major probe that was never answered used to render as nothing at all —
// which is exactly what a probe that ran and found no newer major renders as.
// Two different states, one shape: on a sweep of hundreds the reader could not
// tell which rows still owed an answer.
//
// Each case here carries its EXPECTED LINE in full rather than a substring. The
// two answered states are the non-zero control: the change must move the
// unprobed row and leave the other two byte for byte where they were.
func TestLatestLine_DistinguishesAnUnansweredProbeFromACleanNegative(t *testing.T) {
	published := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	lookedUp := time.Date(2026, 2, 28, 23, 50, 0, 0, time.UTC)
	base := latestResult{
		Module:     "example.com/mod",
		Latest:     "v1.3.0",
		LatestDate: published,
		LookedUpAt: lookedUp,
	}
	base.LatestReleaseAgeDays = latestReleaseAgeDays(published)
	days := *base.LatestReleaseAgeDays

	probedNone := base
	probedNone.MajorProbed = true

	probedFound := base
	probedFound.MajorProbed = true
	probedFound.NewerMajorModule = "example.com/mod/v2"
	probedFound.NewerMajorLatest = "v2.0.1"

	unprobed := base // MajorProbed false: the probe failed and the answer was lost.

	head := "example.com/mod@v1.3.0 (released " + strconv.Itoa(days) + " days ago, 2025-06-01)"
	tail := "  [as of 2026-02-28 23:50 UTC]"
	cases := []struct {
		name string
		row  latestResult
		want string
	}{
		{"probed, none found (control)", probedNone, head + tail},
		{
			"probed, one found (control)",
			probedFound,
			head + "; newer major: example.com/mod/v2@v2.0.1" + tail,
		},
		{"probe never answered", unprobed, head + "; newer major: not probed" + tail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			if err := writeLatestSingleLine(&buf, tc.row); err != nil {
				t.Fatalf("writeLatestSingleLine: %v", err)
			}
			if got := strings.TrimRight(buf.String(), "\n"); got != tc.want {
				t.Errorf("line =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}

// `audit` renders the same data in a column and a note line beneath the row, and
// it had the same gap: the note was suppressed for an unprobed row, which is
// what a probed-and-none row prints. The control is the same one — the answered
// rows must be untouched.
func TestAuditTable_DistinguishesAnUnansweredProbeFromACleanNegative(t *testing.T) {
	row := func(coord string) auditModuleResult {
		return auditModuleResult{
			Coordinate:    coord,
			Verification:  "VerifiedBySumDBOnly",
			License:       "MIT",
			LicenseStatus: "Detected",
			VulnStatus:    "Clean",
			IsLatest:      measuredIsLatest(true),
		}
	}
	probedNone := row("example.com/none@v1.0.0")
	probedNone.MajorProbed = true

	probedFound := row("example.com/found@v1.0.0")
	probedFound.MajorProbed = true
	probedFound.NewerMajorModule = "example.com/found/v2"
	probedFound.NewerMajorLatest = "v2.0.1"

	unprobed := row("example.com/unprobed@v1.0.0")

	table, _ := renderAudit(t, []auditModuleResult{probedNone, probedFound, unprobed})
	lines := strings.Split(strings.TrimRight(table, "\n"), "\n")

	notes := make([]string, 0, len(lines))
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "newer major") ||
			strings.HasPrefix(trimmed, "same major republished") {
			notes = append(notes, trimmed)
		}
	}
	want := []string{
		"newer major: example.com/found/v2@v2.0.1",
		"newer major: not probed",
	}
	if len(notes) != len(want) {
		t.Fatalf("major-line notes = %v, want %v\n%s", notes, want, table)
	}
	for i, w := range want {
		if notes[i] != w {
			t.Errorf("note %d = %q, want %q\n%s", i+1, notes[i], w, table)
		}
	}
	// The control, stated as an assertion rather than left to the eye: the
	// probed-and-none row still says nothing beyond its column.
	if strings.Contains(lines[0], "newer major") {
		t.Errorf("the probed-and-none row gained a clause:\n%s", lines[0])
	}
}

// The republication half is NOT the same defect, and this pins the reading that
// says so.
//
// Republication.Asked false means the question does not APPLY — only a
// +incompatible pin on a bare path is asked it — and Asked true with no path is
// a measured negative. Both mean "there is no republication move for this pin",
// both are answers, and neither hides an unasked question, so both are silent
// exactly as a probed-and-none major line is. The one state that IS unanswered
// is a failed probe, and a failed probe zeroes the pair, so the row says "newer
// major: not probed" and that covers both questions. There is no row in which
// one of the two was answered and the other was not asked.
func TestMajorNotes_TheRepublicationQuestionHasNoUnansweredState(t *testing.T) {
	cases := []struct {
		name string
		rep  staledomain.Republication
		nm   staledomain.NewerMajor
		want string
	}{
		{
			name: "not applicable: the pin is not +incompatible",
			rep:  staledomain.Republication{},
			nm:   staledomain.NewerMajor{Probed: true},
			want: "",
		},
		{
			name: "asked, and this major is not republished",
			rep:  staledomain.Republication{Asked: true},
			nm:   staledomain.NewerMajor{Probed: true},
			want: "",
		},
		{
			name: "asked and found",
			rep:  staledomain.Republication{Asked: true, Path: "example.com/mod/v3", Version: "v3.3.5"},
			nm:   staledomain.NewerMajor{Probed: true},
			want: "same major republished: example.com/mod/v3@v3.3.5",
		},
		{
			// The state the failure path now produces: one question answered,
			// the other not. The measured half is reported and the unmeasured
			// half says it was not probed — neither is dropped for the other.
			name: "republished, and the walk above it never answered",
			rep:  staledomain.Republication{Asked: true, Path: "example.com/mod/v3", Version: "v3.3.5"},
			nm:   staledomain.NewerMajor{},
			want: "same major republished: example.com/mod/v3@v3.3.5; newer major: not probed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := majorNotes(tc.rep, tc.nm, true); got != tc.want {
				t.Errorf("majorNotes = %q, want %q", got, tc.want)
			}
		})
	}
}

// `fetch`'s staleness note asks the same question `latest` does, and its lookup
// used to be the one @latest call in the product with no retry in front of it:
// it named its own interface over the proxy adapter, which routes around every
// decorator the port carries. This wires the lookup exactly as the command does
// and gives it the transient answer that used to cost the column.
func TestFetchStaleness_SurvivesATransientEmptyProxyAnswer(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, `{"Version":"v1.3.0","Time":"2025-06-01T00:00:00Z"}`)
	}))
	defer srv.Close()

	proxy, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("building proxy client: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}

	var stderr strings.Builder
	stale := fetchStalenessFor(context.Background(),
		newProxyLatestResolver(proxy, discardLogger()), coord, "v1.0.0", &stderr)
	if stale.IsLatest == nil {
		t.Fatalf("the column went unmeasured over a transient answer: %+v (stderr %q)", stale, stderr.String())
	}
	if *stale.IsLatest {
		t.Errorf("is_latest = true for a pin behind v1.3.0")
	}
	if stale.LatestVersion != "v1.3.0" {
		t.Errorf("latest_version = %q, want v1.3.0", stale.LatestVersion)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("proxy asked %d times, want 2", got)
	}
}

// The control for the case above, on the same surface: a definitive 404 is not
// asked again, and the column says what it has always said for a lookup that
// settles nothing to compare against. `fetch`'s rendering is untouched by the
// retry — only how often it is reached.
func TestFetchStaleness_AbsentPathIsNotRetriedAndRendersAsBefore(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "not found: module example.com/gone: no matching versions", http.StatusNotFound)
	}))
	defer srv.Close()

	proxy, err := proxyadapter.New(srv.URL, true)
	if err != nil {
		t.Fatalf("building proxy client: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate("example.com/gone", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}

	var stderr strings.Builder
	stale := fetchStalenessFor(context.Background(),
		newProxyLatestResolver(proxy, discardLogger()), coord, "v1.0.0", &stderr)
	if got := calls.Load(); got != 1 {
		t.Errorf("proxy asked %d times for a definitive answer, want exactly 1", got)
	}
	if stale.IsLatest != nil || stale.Unmeasured != stalenessLookupFailed {
		t.Errorf("staleness = %+v, want the unmeasured lookup_failed row this surface has always rendered", stale)
	}
	if got, want := fetchStalenessNote(stale), " [staleness unmeasured (lookup failed)]"; got != want {
		t.Errorf("note = %q, want %q", got, want)
	}
}
