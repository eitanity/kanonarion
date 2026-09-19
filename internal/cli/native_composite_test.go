package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
)

// The second half of the defect this file pins: `audit`, `inspect` and
// `context` had no native awareness at all. A user running audit over a build
// that links libxml2 and ships eight megabytes of SQLite was told nothing about
// either, on the text path or under --json.

// Every composite reports it on the machine-readable surface under the same
// key, so a consumer reads one name wherever it meets the fact. An agent cannot
// read prose, and a key that differs per command is a key nobody can look up.
func TestComposites_PublishNativeCoverageUnderOneKey(t *testing.T) {
	cov := nativeCoverageOf(natSubject, natRecord(nativedomain.PresenceAbsent, nil, 0), true)
	roll := &nativeWalkRollup{}

	for _, tc := range []struct {
		name  string
		value any
	}{
		{"context", contextOutput{Native: &cov}},
		{"audit", auditRunJSON{Native: roll}},
		{"inspect", inspectSummary{Native: roll}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			var obj map[string]json.RawMessage
			if derr := json.Unmarshal(raw, &obj); derr != nil {
				t.Fatalf("decoding: %v", derr)
			}
			if _, ok := obj["native_coverage"]; !ok {
				t.Fatalf("%s publishes no native_coverage key: %s", tc.name, raw)
			}
			if string(obj["native_coverage"]) == "null" {
				t.Errorf("%s published native_coverage as null though it holds a statement", tc.name)
			}
		})
	}
}

// A producer that derives the statement publishes a complete one; a producer
// that does not publishes null. The two absences say different things, and a
// reader must be able to tell them apart.
func TestComposites_NativeCoverageIsNullOnlyWhenNothingDerivedIt(t *testing.T) {
	raw, err := json.Marshal(contextOutput{})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !strings.Contains(string(raw), `"native_coverage":null`) {
		t.Errorf("a document with no derivation does not say so: %s", raw)
	}
}

// context states it on the text path too, at every state, including the
// measured absences. A module that ships SQLite and a module that ships no C at
// all read identically without the line.
func TestContextText_StatesTheNativeReading(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  nativedomain.Record
		held bool
		want []string
	}{
		{
			name: "ships a named library",
			rec:  natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.38.0"), 4),
			held: true,
			want: []string{"Native code:     present_identified", "SQLite 3.38.0", "advisories not searched"},
		},
		{
			name: "links what it does not ship",
			rec:  natLinked("libxml-2.0"),
			held: true,
			want: []string{"Native code:     linked_not_shipped", "libxml-2.0"},
		},
		{
			name: "measured, nothing there",
			rec:  natRecord(nativedomain.PresenceAbsent, nil, 0),
			held: true,
			want: []string{"Native code:     absent", "no native source is compiled into"},
		},
		{
			name: "nobody looked",
			held: false,
			want: []string{"Native code:     not_examined", "kanonarion native " + natSubject.String()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cov := nativeCoverageOf(natSubject, tc.rec, tc.held)
			out := makeNotRunOutput(contextCommands{})
			out.Native = &cov

			var buf strings.Builder
			if err := printContextText(out, true, &buf); err != nil {
				t.Fatalf("printContextText: %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("the context text does not state %q:\n%s", want, buf.String())
				}
			}
		})
	}
}

// A document from a producer that derives nothing prints no native line at all,
// rather than a line asserting an absence nothing measured.
func TestContextText_NoDerivationPrintsNoNativeLine(t *testing.T) {
	var buf strings.Builder
	if err := printContextText(makeNotRunOutput(contextCommands{}), true, &buf); err != nil {
		t.Fatalf("printContextText: %v", err)
	}
	if strings.Contains(buf.String(), "Native code:") {
		t.Errorf("a document with no native statement printed one:\n%s", buf.String())
	}
}

// The ticket's own example, end to end over the rollup the composites publish:
// a build that links libxml2 and ships SQLite is told about both, and told that
// nothing searched advisories for either.
func TestCompositeSummary_ReportsTheLinkedAndTheShipped(t *testing.T) {
	ships := natCoord(t, "github.com/mattn/go-sqlite3", "v1.14.12")
	links := natCoord(t, "github.com/terminalstatic/go-xsd-validate", "v0.1.6")
	plain := natCoord(t, "example.com/plain", "v1.0.0")
	reader := &fakeNativeReader{recs: map[coordinate.ModuleCoordinate]nativedomain.Record{
		ships: natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.38.0"), 4),
		links: natLinked("libxml-2.0"),
		plain: natRecord(nativedomain.PresenceAbsent, nil, 0),
	}}

	roll := nativeRollupOver(context.Background(), reader,
		[]coordinate.ModuleCoordinate{ships, links, plain})

	var buf strings.Builder
	if err := writeNativeCoverageSummary(&buf, roll); err != nil {
		t.Fatalf("writeNativeCoverageSummary: %v", err)
	}
	for _, want := range []string{
		"1 with an identified component",
		"1 linking an external library it does not ship",
		"github.com/mattn/go-sqlite3@v1.14.12",
		"SQLite 3.38.0",
		"github.com/terminalstatic/go-xsd-validate@v0.1.6",
		"libxml-2.0",
		"no advisories were searched for any of it",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the composite summary does not state %q:\n%s", want, buf.String())
		}
	}

	// And the same facts on the machine-readable surface, because an agent
	// cannot read the prose above.
	raw, err := json.Marshal(roll)
	if err != nil {
		t.Fatalf("marshalling rollup: %v", err)
	}
	for _, want := range []string{
		`"linked_not_shipped"`, `"libxml-2.0"`, `"unsearched"`, `"SQLite"`,
		`"examined":3`, `"not_examined":0`, `"libraries":1`, `"components":1`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the rollup document does not carry %s:\n%s", want, raw)
		}
	}
}
