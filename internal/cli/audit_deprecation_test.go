package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
)

// `audit` is the command a developer runs over a project, so a first-party fact
// the ledger holds about a dependency has to reach it. This file pins the
// deprecation notice on both of audit's surfaces: reproduced, not interpreted;
// stated beside the staleness answer, never merged into it; and with "nobody
// asked" kept distinct from "asked, not deprecated".

// fixedAuditLookup answers every module with one record.
type fixedAuditLookup struct{ rec staledomain.Record }

func (f fixedAuditLookup) Resolve(_ context.Context, path, _ string) (staleapp.Answer, error) {
	rec := f.rec
	rec.ModulePath = path
	return staleapp.Answer{Record: rec}, nil
}

const protobufNotice = "Use the \"google.golang.org/protobuf\" module instead."

// auditRowFor builds one audit row from a staleness record, the way a run does.
func auditRowFor(t *testing.T, coord string, rec staledomain.Record) auditModuleResult {
	t.Helper()
	c, err := coordinate.ParseModuleCoordinate(coord)
	if err != nil {
		t.Fatalf("parsing %s: %v", coord, err)
	}
	res := auditModuleResult{Coordinate: coord}
	var stderr bytes.Buffer
	applyAuditStaleness(context.Background(), &res, c, fixedAuditLookup{rec: rec}, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	return res
}

// The two modules measured in caddy's own closure: both carry a notice in their
// go.mod, both appeared on screen as ordinary rows with nothing said about them.
func TestAudit_ReportsTheNoticeOnBothSurfaces(t *testing.T) {
	cases := []struct{ coord, notice string }{
		{"github.com/aws/aws-sdk-go@v1.55.8", "aws-sdk-go is deprecated. Use aws-sdk-go-v2."},
		{"github.com/golang/protobuf@v1.5.4", protobufNotice},
	}
	for _, tc := range cases {
		t.Run(tc.coord, func(t *testing.T) {
			row := auditRowFor(t, tc.coord, staledomain.Record{
				LatestVersion: "v1.55.8",
				NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
				LookedUpAt:    time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
				Deprecation:   staledomain.Deprecation{Checked: true, Notice: tc.notice},
			})

			var table bytes.Buffer
			if err := printAuditTable(&table, []auditModuleResult{row}); err != nil {
				t.Fatalf("printAuditTable: %v", err)
			}
			// Reproduced, not interpreted: the words are the author's.
			if !strings.Contains(table.String(), "deprecated by its author: "+tc.notice) {
				t.Errorf("the table does not reproduce the notice:\n%s", table.String())
			}

			data, err := json.Marshal(row)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if !strings.Contains(string(data), `"deprecated":`+mustJSON(t, tc.notice)) {
				t.Errorf("--json does not carry the notice: %s", data)
			}
		})
	}
}

// The label is the one `latest` uses, from the one renderer. Two surfaces that
// word a single fact differently is a defect this project has already fixed.
func TestAudit_UsesTheSharedDeprecationWording(t *testing.T) {
	dep := staledomain.Deprecation{Checked: true, Notice: protobufNotice}
	row := auditRowFor(t, "github.com/golang/protobuf@v1.5.4", staledomain.Record{
		LatestVersion: "v1.5.4",
		NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
		LookedUpAt:    time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
		Deprecation:   dep,
	})
	if got, want := auditRowNote(row), deprecationNote(dep); got != want {
		t.Errorf("audit words the notice as %q, `latest` as %q", got, want)
	}
}

// A module can be deprecated AND have a newer major, or deprecated AND be
// current. They are different claims by different mechanisms and the row states
// them as separate clauses rather than collapsing them into one.
func TestAudit_StatesDeprecationBesideTheOtherFacts(t *testing.T) {
	row := auditRowFor(t, "github.com/go-chi/chi@v3.3.4+incompatible", staledomain.Record{
		LatestVersion: "v3.3.4+incompatible",
		NewerMajor: staledomain.NewerMajor{
			Probed: true, FromMajor: 4,
			Path: "github.com/go-chi/chi/v5", Version: "v5.3.1",
		},
		Deprecation: staledomain.Deprecation{Checked: true, Notice: "use github.com/go-chi/chi/v5"},
		LookedUpAt:  time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
	})

	note := auditRowNote(row)
	if !strings.Contains(note, "newer major: github.com/go-chi/chi/v5@v5.3.1") {
		t.Errorf("the newer-major clause was lost beside the deprecation: %q", note)
	}
	if !strings.Contains(note, "deprecated by its author: use github.com/go-chi/chi/v5") {
		t.Errorf("the deprecation clause was lost beside the newer major: %q", note)
	}
	// The staleness column itself is untouched: the answer about this path is
	// still the answer about this path.
	if got := auditStalenessCell(row); got != "current" {
		t.Errorf("staleness column = %q, want the unmerged answer \"current\"", got)
	}
}

// A row never checked must render differently from one checked and found not
// deprecated. `deprecation_checked` exists for that distinction, and absence
// must not read as "not deprecated".
func TestAudit_UncheckedAndCheckedNegativeAreDifferentInJSON(t *testing.T) {
	cases := map[string]struct {
		dep  staledomain.Deprecation
		want string
	}{
		"never asked":          {staledomain.Deprecation{}, `"deprecated":null`},
		"asked, declares none": {staledomain.Deprecation{Checked: true}, `"deprecated":""`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			row := auditRowFor(t, "example.com/mod@v1.0.0", staledomain.Record{
				LatestVersion: "v1.0.0",
				LookedUpAt:    time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
				Deprecation:   tc.dep,
			})
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if !strings.Contains(string(data), tc.want) {
				t.Errorf("JSON does not carry %s\ngot: %s", tc.want, data)
			}
		})
	}
	// The key is on every row, including an unmeasured one: "this build does not
	// derive it" and "this module was not asked about" must not be one absence.
	var unmeasured auditModuleResult
	unmeasured.markStalenessUnmeasured(stalenessOfflineNoEntry)
	data, err := json.Marshal(unmeasured)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	v, present := decoded["deprecated"]
	if !present {
		t.Error("the deprecated key is absent from an unmeasured row; it is emitted on every row")
	}
	if v != nil {
		t.Errorf("an unmeasured row reports deprecated = %v, want null", v)
	}
}

// The non-zero control. Five of 533 checked rows carry a notice, so the
// overwhelming majority must not move: a row that is unchecked, or checked and
// clean, renders byte for byte as it did before the clause existed.
func TestAudit_RowsWithoutANoticeAreUnchanged(t *testing.T) {
	for _, dep := range []staledomain.Deprecation{{}, {Checked: true}} {
		row := auditRowFor(t, "example.com/mod@v1.0.0", staledomain.Record{
			LatestVersion: "v1.0.0",
			NewerMajor:    staledomain.NewerMajor{Probed: true, FromMajor: 2},
			LookedUpAt:    time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
			Deprecation:   dep,
		})
		if note := auditRowNote(row); note != "" {
			t.Errorf("a row with Deprecation %+v grew a note: %q", dep, note)
		}
		var table bytes.Buffer
		if err := printAuditTable(&table, []auditModuleResult{row}); err != nil {
			t.Fatalf("printAuditTable: %v", err)
		}
		if strings.Contains(table.String(), "deprecat") {
			t.Errorf("a row with Deprecation %+v grew a deprecation clause:\n%s", dep, table.String())
		}
	}
}
