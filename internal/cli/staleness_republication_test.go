package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The three shapes a +incompatible pin's major-line answer can take, named once
// and used by every surface below. The whole defect was that two of them shared
// one label and one of them was dropped entirely, so no surface may be checked
// against fewer than all three.
var republicationShapes = []struct {
	name string
	row  latestResult
	// wantText is what the clause must read on a text surface, in order.
	wantText []string
	// absentText is what it must NOT read.
	absentText []string
}{
	{
		// gavv/httpexpect: /v2 is published and there is nothing above it. The
		// major NUMBER is unchanged, so nothing here may say "newer major".
		name: "same major republished only",
		row: latestResult{
			Module:            "github.com/gavv/httpexpect",
			Pinned:            "v2.0.0+incompatible",
			Latest:            "v1.1.3",
			IsLatest:          measuredIsLatest(false),
			PinAheadOfLatest:  measuredAhead(true),
			MajorProbed:       true,
			RepublishedProbed: true,
			RepublishedModule: "github.com/gavv/httpexpect/v2",
			RepublishedLatest: "v2.17.0",
			RepublishedDate:   time.Date(2025, 3, 4, 0, 0, 0, 0, time.UTC),
		},
		wantText:   []string{"same major republished: github.com/gavv/httpexpect/v2@v2.17.0 (2025-03-04)"},
		absentText: []string{"newer major"},
	},
	{
		// Masterminds/sprig: the non-zero control. /v2 was never published, /v3
		// was, and that IS a newer major. The label must not move.
		name: "genuine newer major only",
		row: latestResult{
			Module:            "github.com/Masterminds/sprig",
			Pinned:            "v2.22.0+incompatible",
			Latest:            "v2.22.0+incompatible",
			IsLatest:          measuredIsLatest(true),
			MajorProbed:       true,
			NewerMajorModule:  "github.com/Masterminds/sprig/v3",
			NewerMajorLatest:  "v3.3.0",
			NewerMajorDate:    time.Date(2024, 8, 29, 0, 0, 0, 0, time.UTC),
			RepublishedProbed: true,
		},
		wantText:   []string{"newer major: github.com/Masterminds/sprig/v3@v3.3.0 (2024-08-29)"},
		absentText: []string{"same major republished"},
	},
	{
		// go-chi/chi: both hold. The republication comes first — it is the
		// patch-level move — and the two-major migration follows it. The
		// previous shape printed only the second.
		name: "both, republication first",
		row: latestResult{
			Module:            "github.com/go-chi/chi",
			Pinned:            "v3.3.4+incompatible",
			Latest:            "v1.5.5",
			IsLatest:          measuredIsLatest(false),
			PinAheadOfLatest:  measuredAhead(true),
			MajorProbed:       true,
			NewerMajorModule:  "github.com/go-chi/chi/v5",
			NewerMajorLatest:  "v5.3.1",
			NewerMajorDate:    time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC),
			RepublishedProbed: true,
			RepublishedModule: "github.com/go-chi/chi/v3",
			RepublishedLatest: "v3.3.5",
			RepublishedDate:   time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC),
		},
		wantText: []string{
			"same major republished: github.com/go-chi/chi/v3@v3.3.5 (2019-04-01)",
			"newer major: github.com/go-chi/chi/v5@v5.3.1 (2026-07-05)",
		},
	},
}

// measuredAhead is the pointer form the pin-position fields take.
func measuredAhead(v bool) *bool { return &v }

func TestLatestTable_RendersTheThreeMajorLineShapes(t *testing.T) {
	for _, tc := range republicationShapes {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := printLatestTable(&buf, []latestResult{tc.row}); err != nil {
				t.Fatalf("printLatestTable: %v", err)
			}
			out := buf.String()
			last := -1
			for _, want := range tc.wantText {
				at := strings.Index(out, want)
				if at < 0 {
					t.Errorf("output missing %q\ngot: %s", want, out)
					continue
				}
				if at < last {
					t.Errorf("clause %q appears before the one that must precede it\ngot: %s", want, out)
				}
				last = at
			}
			for _, absent := range tc.absentText {
				if strings.Contains(out, absent) {
					t.Errorf("output contains %q, which is not true of this row\ngot: %s", absent, out)
				}
			}
			// The same-major clause on the same row must not be contradicted:
			// "ahead of latest tag" and a republication are both true at once.
			if tc.row.PinAheadOfLatest != nil && *tc.row.PinAheadOfLatest && !strings.Contains(out, "ahead of latest tag") {
				t.Errorf("the latest: clause was dropped\ngot: %s", out)
			}
		})
	}
}

// The single-line surface (`latest <module>`) shares the clause renderer, so it
// must say the same thing. A surface that reads correctly in the table and
// wrongly on the one-liner is the divergence the shared renderer exists to stop.
func TestLatestSingleLine_RendersTheThreeMajorLineShapes(t *testing.T) {
	for _, tc := range republicationShapes {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeLatestSingleLine(&buf, tc.row); err != nil {
				t.Fatalf("writeLatestSingleLine: %v", err)
			}
			out := buf.String()
			for _, want := range tc.wantText {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q\ngot: %s", want, out)
				}
			}
			for _, absent := range tc.absentText {
				if strings.Contains(out, absent) {
					t.Errorf("output contains %q\ngot: %s", absent, out)
				}
			}
		})
	}
}

// The JSON is a second surface with its own acceptance. Text being right is not
// evidence that a consumer reading the document can tell the two facts apart —
// which it could not before, because both reached it under newer_major_module.
func TestLatestJSON_CarriesTheTwoMajorFactsInSeparateKeys(t *testing.T) {
	cases := []struct {
		name    string
		row     latestResult
		want    map[string]any
		absent  []string
		present []string
	}{
		{
			name: "same major republished only",
			row:  republicationShapes[0].row,
			want: map[string]any{
				"republished_module": "github.com/gavv/httpexpect/v2",
				"republished_latest": "v2.17.0",
				"republished_probed": true,
			},
			// The key a consumer budgets a breaking change from must be absent.
			absent:  []string{"newer_major_module", "newer_major_latest"},
			present: []string{"republished_date", "major_probed"},
		},
		{
			name: "genuine newer major only",
			row:  republicationShapes[1].row,
			want: map[string]any{
				"newer_major_module": "github.com/Masterminds/sprig/v3",
				"newer_major_latest": "v3.3.0",
				"republished_probed": true,
			},
			absent: []string{"republished_module", "republished_latest"},
		},
		{
			name: "both",
			row:  republicationShapes[2].row,
			want: map[string]any{
				"republished_module": "github.com/go-chi/chi/v3",
				"republished_latest": "v3.3.5",
				"newer_major_module": "github.com/go-chi/chi/v5",
				"newer_major_latest": "v5.3.1",
				"republished_probed": true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.row)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			for k, want := range tc.want {
				if got[k] != want {
					t.Errorf("%s = %v, want %v\nraw: %s", k, got[k], want, raw)
				}
			}
			for _, k := range tc.absent {
				if _, ok := got[k]; ok {
					t.Errorf("%s is present (%v) on a row it is not true of\nraw: %s", k, got[k], raw)
				}
			}
			for _, k := range tc.present {
				if _, ok := got[k]; !ok {
					t.Errorf("%s is missing\nraw: %s", k, raw)
				}
			}
		})
	}
}

// republished_probed is a derived state, so it is emitted on every row —
// including a row where the question does not apply, where false is the answer
// and not an absence. An `omitempty` here would make "asked, not republished"
// indistinguishable from a build that does not derive the field.
func TestLatestJSON_RepublishedProbedIsEmittedWhenFalse(t *testing.T) {
	raw, err := json.Marshal(latestResult{Module: "example.com/mod", Latest: "v1.0.0"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	v, ok := got["republished_probed"]
	if !ok {
		t.Fatalf("republished_probed is absent\nraw: %s", raw)
	}
	if v != false {
		t.Errorf("republished_probed = %v, want false", v)
	}
}

// `audit` renders the same two facts on its own note line. It must use the same
// labels and the same order: a build where `latest` says "same major
// republished" and `audit` says "newer major" about one module contradicts
// itself, and only one of the two surfaces would be read.
func TestAuditNote_UsesTheSameLabelsAndOrderAsLatest(t *testing.T) {
	cases := []struct {
		name   string
		row    auditModuleResult
		want   string
		absent string
	}{
		{
			name: "same major republished only",
			row: auditModuleResult{
				MajorProbed:       true,
				RepublishedProbed: true,
				RepublishedModule: "github.com/gavv/httpexpect/v2",
				RepublishedLatest: "v2.17.0",
			},
			want:   "same major republished: github.com/gavv/httpexpect/v2@v2.17.0",
			absent: "newer major",
		},
		{
			name: "genuine newer major only",
			row: auditModuleResult{
				MajorProbed:       true,
				RepublishedProbed: true,
				NewerMajorModule:  "github.com/Masterminds/sprig/v3",
				NewerMajorLatest:  "v3.3.0",
			},
			want:   "newer major: github.com/Masterminds/sprig/v3@v3.3.0",
			absent: "same major republished",
		},
		{
			name: "both, republication first",
			row: auditModuleResult{
				MajorProbed:       true,
				RepublishedProbed: true,
				RepublishedModule: "github.com/go-chi/chi/v3",
				RepublishedLatest: "v3.3.5",
				NewerMajorModule:  "github.com/go-chi/chi/v5",
				NewerMajorLatest:  "v5.3.1",
			},
			want: "same major republished: github.com/go-chi/chi/v3@v3.3.5; " +
				"newer major: github.com/go-chi/chi/v5@v5.3.1",
		},
		{
			// An unprobed row claims neither. The zero value of a probe is not
			// an answer. Nothing was measured for this row at all — IsLatest is
			// nil — so the column already reads "unmeasured" and the note adds
			// nothing to it.
			name: "unmeasured row states nothing",
			row: auditModuleResult{
				NewerMajorModule:  "github.com/foo/bar/v2",
				RepublishedModule: "github.com/foo/bar/v1",
			},
			want: "",
		},
		{
			// The row this change exists for: the same-major answer resolved and
			// the probe did not. Printing nothing here is byte-identical to the
			// recorded negative, so the failed probe read as "there is no newer
			// major" — the answer this column exists to stop giving.
			name: "answered row with a failed probe says the question was not answered",
			row: auditModuleResult{
				IsLatest:    measuredIsLatest(true),
				MajorProbed: false,
			},
			want:   "newer major: not probed",
			absent: "@",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auditNewerMajorNote(tc.row)
			if got != tc.want {
				t.Errorf("auditNewerMajorNote = %q, want %q", got, tc.want)
			}
			if tc.absent != "" && strings.Contains(got, tc.absent) {
				t.Errorf("note contains %q, which is not true of this row: %q", tc.absent, got)
			}
		})
	}
}

// The audit JSON carries the pair too, and republished_probed is emitted false
// for the same reason it is on `latest`.
func TestAuditJSON_CarriesTheTwoMajorFactsInSeparateKeys(t *testing.T) {
	raw, err := json.Marshal(auditModuleResult{
		Coordinate:        "github.com/go-chi/chi@v3.3.4+incompatible",
		MajorProbed:       true,
		RepublishedProbed: true,
		RepublishedModule: "github.com/go-chi/chi/v3",
		RepublishedLatest: "v3.3.5",
		NewerMajorModule:  "github.com/go-chi/chi/v5",
		NewerMajorLatest:  "v5.3.1",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for k, want := range map[string]any{
		"republished_module": "github.com/go-chi/chi/v3",
		"republished_latest": "v3.3.5",
		"newer_major_module": "github.com/go-chi/chi/v5",
		"newer_major_latest": "v5.3.1",
		"republished_probed": true,
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v\nraw: %s", k, got[k], want, raw)
		}
	}

	bare, err := json.Marshal(auditModuleResult{Coordinate: "example.com/mod@v1.0.0"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var plain map[string]any
	if err := json.Unmarshal(bare, &plain); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v, ok := plain["republished_probed"]; !ok || v != false {
		t.Errorf("republished_probed = %v present=%v, want false and present\nraw: %s", v, ok, bare)
	}
}
