package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
)

// A module's own deprecation notice is a fact its author published in
// machine-readable form, and this file pins how it is reported: reproduced, not
// interpreted; beside the major-line facts, never merged into them; and with
// "nobody asked" kept distinct from "asked, not deprecated".

// deprecatingLookup answers with a fixed record.
type deprecatingLookup struct{ rec staledomain.Record }

func (d deprecatingLookup) Resolve(_ context.Context, path, _ string) (staleapp.Answer, error) {
	rec := d.rec
	rec.ModulePath = path
	return staleapp.Answer{Record: rec}, nil
}

const awsNotice = "aws-sdk-go is deprecated. Use aws-sdk-go-v2.\n" +
	"See https://aws.amazon.com/blogs/developer/announcing-end-of-support-for-aws-sdk-for-go-v1-on-july-31-2025/."

func rowFor(t *testing.T, rec staledomain.Record) latestResult {
	t.Helper()
	var stderr bytes.Buffer
	row, err := latestRowFor(context.Background(), deprecatingLookup{rec: rec},
		"github.com/aws/aws-sdk-go", "v1.55.8", &stderr)
	if err != nil {
		t.Fatalf("latestRowFor: %v", err)
	}
	return row
}

// The JSON field is three states, and only two of them are answers. A bare
// string could not tell "nobody asked" from "asked, declares none", and
// collapsing them reports every unasked module as actively fine.
func TestLatest_DeprecationIsThreeStatesInJSON(t *testing.T) {
	cases := []struct {
		name string
		dep  staledomain.Deprecation
		want string
	}{
		{
			name: "not established is null, never false",
			dep:  staledomain.Deprecation{},
			want: `"deprecated":null`,
		},
		{
			name: "asked, declares none, is an empty notice",
			dep:  staledomain.Deprecation{Checked: true},
			want: `"deprecated":""`,
		},
		{
			name: "the notice is reproduced verbatim",
			dep:  staledomain.Deprecation{Checked: true, Notice: awsNotice},
			want: `"deprecated":` + mustJSON(t, awsNotice),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := rowFor(t, staledomain.Record{LatestVersion: "v1.55.8", Deprecation: tc.dep})
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if !strings.Contains(string(data), tc.want) {
				t.Errorf("JSON does not carry %s\ngot: %s", tc.want, data)
			}
		})
	}
}

// The field is emitted on EVERY row. "This build does not derive it" and "this
// module was not asked about" would otherwise be the same absence.
func TestLatest_DeprecationFieldIsAlwaysEmitted(t *testing.T) {
	row := rowFor(t, staledomain.Record{LatestVersion: "v1.55.8"})
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, present := decoded["deprecated"]; !present {
		t.Error("the deprecated key is absent; it is emitted on every row")
	}
}

// The text surfaces state the notice, and state it beside the major-line facts
// rather than instead of them: a module can be deprecated AND have a newer
// major, and they are different claims by different mechanisms.
func TestLatest_TextReportsTheNoticeBesideTheMajorFacts(t *testing.T) {
	rec := staledomain.Record{
		LatestVersion:     "v1.55.8",
		LatestPublishedAt: time.Date(2025, 7, 31, 16, 5, 54, 0, time.UTC),
		NewerMajor: staledomain.NewerMajor{
			Probed: true, FromMajor: 2,
			Path: "github.com/aws/aws-sdk-go/v2", Version: "v2.0.0",
		},
		Deprecation: staledomain.Deprecation{Checked: true, Notice: awsNotice},
		LookedUpAt:  time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
	}
	row := rowFor(t, rec)

	var table bytes.Buffer
	if err := printLatestTable(&table, []latestResult{row}); err != nil {
		t.Fatalf("printLatestTable: %v", err)
	}
	var line bytes.Buffer
	if err := writeLatestSingleLine(&line, row); err != nil {
		t.Fatalf("writeLatestSingleLine: %v", err)
	}

	for surface, out := range map[string]string{"table": table.String(), "line": line.String()} {
		if !strings.Contains(out, "deprecated by its author: aws-sdk-go is deprecated. Use aws-sdk-go-v2.") {
			t.Errorf("%s does not reproduce the notice:\n%s", surface, out)
		}
		// The successor is the one the author named. The tool never derives a
		// successor from name similarity, so the string in the output is the
		// string in the notice.
		if !strings.Contains(out, "aws-sdk-go-v2") {
			t.Errorf("%s lost the successor the author named:\n%s", surface, out)
		}
		if !strings.Contains(out, "newer major: github.com/aws/aws-sdk-go/v2@v2.0.0") {
			t.Errorf("%s dropped the newer-major fact beside the deprecation:\n%s", surface, out)
		}
	}
}

// The non-zero control: a module whose deprecation state is not established
// says nothing at all on the text surfaces. "Not deprecated" is not the answer
// to a question nobody put, and the overwhelming majority of rows are in that
// state or in the recorded-negative one — neither may grow a clause.
func TestLatest_UndeprecatedAndUnaskedRowsSayNothing(t *testing.T) {
	for _, dep := range []staledomain.Deprecation{{}, {Checked: true}} {
		row := rowFor(t, staledomain.Record{
			LatestVersion: "v1.55.8",
			LookedUpAt:    time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC),
			Deprecation:   dep,
		})
		var table bytes.Buffer
		if err := printLatestTable(&table, []latestResult{row}); err != nil {
			t.Fatalf("printLatestTable: %v", err)
		}
		if strings.Contains(table.String(), "deprecat") {
			t.Errorf("a row with Deprecation %+v grew a deprecation clause:\n%s", dep, table.String())
		}
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshalling %q: %v", s, err)
	}
	return string(b)
}
