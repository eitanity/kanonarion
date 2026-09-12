package ports_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// An unreadable row is rendered by the one path a consuming command takes when
// it prints nothing but the error, so the rendering has to say WHAT kind of row
// it is and WHICH row. Runs and records share this type; calling a record a run
// would be the same class of fault the type exists to report.
func TestUnreadableRow_NamesTheKindAndTheRow(t *testing.T) {
	reason := errors.New("content hash mismatch")

	for name, tc := range map[string]struct {
		row  ports.UnreadableRow
		want string
	}{
		"a named run": {
			row:  ports.UnreadableRow{Kind: ports.RowKindRun, ID: "vscan-1", Reason: reason},
			want: "run vscan-1: content hash mismatch",
		},
		"a named record": {
			row:  ports.UnreadableRow{Kind: ports.RowKindRecord, ID: "example.com/mod@v1.0.0", Reason: reason},
			want: "record example.com/mod@v1.0.0: content hash mismatch",
		},
		"a record placed in its history": {
			row: ports.UnreadableRow{
				Kind:       ports.RowKindRecord,
				ID:         "example.com/mod@v1.0.0",
				Generation: ports.RowGeneration{PipelineVersion: "v25", SnapshotSource: "govulndb", SnapshotVersion: "v2026-01-01"},
				Reason:     reason,
			},
			want: "record example.com/mod@v1.0.0 (pipeline v25, vuln-db v2026-01-01): content hash mismatch",
		},
		"bytes that named a generation but no module": {
			row: ports.UnreadableRow{
				Kind:       ports.RowKindRecord,
				Generation: ports.RowGeneration{PipelineVersion: "v25"},
				Reason:     reason,
			},
			want: "unidentified record (pipeline v25): content hash mismatch",
		},
		"bytes that will not introduce themselves": {
			row:  ports.UnreadableRow{Kind: ports.RowKindRecord, Reason: reason},
			want: "unidentified record: content hash mismatch",
		},
		"a row whose kind was not stated": {
			row:  ports.UnreadableRow{ID: "something", Reason: reason},
			want: "row something: content hash mismatch",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.row.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The aggregate renders every row, because a consuming command that prints only
// the error still owes the reader which rows were at fault — and it keeps
// answering to the integrity sentinel, which is what makes that command fail
// closed exactly as it did before this type existed.
func TestUnreadableRows_RendersEveryRowAndKeepsTheSentinel(t *testing.T) {
	err := &ports.UnreadableRows{Rows: []ports.UnreadableRow{
		{Kind: ports.RowKindRecord, ID: "example.com/a@v1.0.0", Reason: errors.New("first")},
		{Kind: ports.RowKindRecord, ID: "example.com/b@v2.0.0", Reason: errors.New("second")},
	}}

	got := err.Error()
	for _, want := range []string{"example.com/a@v1.0.0", "example.com/b@v2.0.0", "first", "second"} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want it to name %q", got, want)
		}
	}
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Error("errors.Is(err, ErrVulnIntegrity) = false; every consuming caller would stop failing closed")
	}
}

// The generation is prose only where prose is wanted. Its own rendering states
// what it holds and nothing where it holds nothing, so a run — which has no
// generation — never acquires an empty parenthetical.
func TestRowGeneration_RendersOnlyWhatItHolds(t *testing.T) {
	for name, tc := range map[string]struct {
		gen  ports.RowGeneration
		want string
	}{
		"nothing":       {gen: ports.RowGeneration{}, want: ""},
		"pipeline only": {gen: ports.RowGeneration{PipelineVersion: "v25"}, want: "(pipeline v25)"},
		"snapshot only": {gen: ports.RowGeneration{SnapshotVersion: "v2026-01-01"}, want: "(vuln-db v2026-01-01)"},
		"a source with no version is not an identity": {
			gen: ports.RowGeneration{SnapshotSource: "govulndb"}, want: "",
		},
		"both": {
			gen:  ports.RowGeneration{PipelineVersion: "v25", SnapshotVersion: "v2026-01-01"},
			want: "(pipeline v25, vuln-db v2026-01-01)",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.gen.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}
