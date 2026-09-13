package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
)

// A module that ships SQLite and a module that ships no C at all both read
// "Clean". These tests lock the five readings apart, and lock the rule that
// stating them moves no verdict.

func natCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeNativeReader answers with whatever a test seeded, or with a read failure.
type fakeNativeReader struct {
	recs map[coordinate.ModuleCoordinate]nativedomain.Record
	err  error
}

func (f *fakeNativeReader) Get(_ context.Context, coord coordinate.ModuleCoordinate) (nativedomain.Record, bool, error) {
	if f.err != nil {
		return nativedomain.Record{}, false, f.err
	}
	rec, ok := f.recs[coord]
	return rec, ok, nil
}

func natRecord(presence nativedomain.Presence, comps []nativedomain.Component, sources int) nativedomain.Record {
	rec := nativedomain.Record{
		ArtefactIdentity:       "zip:h1:deadbeef=",
		PipelineVersion:        "0.3.0",
		RecipeCatalogueVersion: "1",
		Presence:               presence,
		Components:             comps,
	}
	for range sources {
		rec.Sources = append(rec.Sources, nativedomain.Source{File: "x.c"})
	}
	return rec
}

func sqliteComponent(version string) []nativedomain.Component {
	return []nativedomain.Component{{
		Name: "SQLite", Version: version, Confidence: nativedomain.ConfidenceDeclared,
		Evidence: []nativedomain.Evidence{{File: "sqlite3-binding.c", Declaration: `#define SQLITE_VERSION "` + version + `"`}},
	}}
}

// TestNativeCoverage_FiveReadingsAreDistinct is the acceptance in one table.
// Four presences a record can carry, plus "no record at all" — which must never
// fold into any of them, because it means nobody looked.
func TestNativeCoverage_FiveReadingsAreDistinct(t *testing.T) {
	cases := []struct {
		name       string
		rec        nativedomain.Record
		found      bool
		wantState  nativeCoverageState
		wantUnsrch int
	}{
		{"nobody looked", nativedomain.Record{}, false, nativeStateNotExamined, 0},
		{"measured: no native code", natRecord(nativedomain.PresenceAbsent, nil, 0), true, nativeStateAbsent, 0},
		{"links what it does not ship", natRecord(nativedomain.PresenceLinkedNotShipped, nil, 0), true, nativeStateLinkedNotShipped, 0},
		{"ships C nothing could name", natRecord(nativedomain.PresenceUnidentified, nil, 4), true, nativeStateUnidentified, 0},
		{"ships a named library", natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.53.0"), 4), true, nativeStateIdentified, 1},
	}
	seenState := map[nativeCoverageState]string{}
	seenStatement := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nativeCoverageOf(tc.rec, tc.found)
			if got.State != tc.wantState {
				t.Errorf("state = %q, want %q", got.State, tc.wantState)
			}
			if got.UnsearchedComponents != tc.wantUnsrch {
				t.Errorf("unsearched_components = %d, want %d", got.UnsearchedComponents, tc.wantUnsrch)
			}
			if got.Statement == "" {
				t.Error("no statement; every reading owes the text surface a sentence")
			}
			if prev, dup := seenState[got.State]; dup {
				t.Errorf("state %q is shared with %q; the readings must be distinguishable", got.State, prev)
			}
			seenState[got.State] = tc.name
			if prev, dup := seenStatement[got.Statement]; dup {
				t.Errorf("statement is identical to %q's; the readings must be distinguishable in prose too", prev)
			}
			seenStatement[got.Statement] = tc.name
		})
	}
}

// TestNativeCoverage_NotExaminedIsNeverReportedAsAbsent. The two answers carry
// opposite instructions, and collapsing them is this product's own defect class.
func TestNativeCoverage_NotExaminedIsNeverReportedAsAbsent(t *testing.T) {
	got := nativeCoverageOf(nativedomain.Record{}, false)
	if got.State == nativeStateAbsent {
		t.Fatal("an unexamined module reported as absent")
	}
	if !strings.Contains(got.Statement, "not examined") {
		t.Errorf("statement = %q; it must say the module was not examined", got.Statement)
	}
	// It names the command that would answer, so the refusal ends at a command
	// rather than at a wall.
	if !strings.Contains(got.Statement, "kanonarion native") {
		t.Errorf("statement = %q; it must name the command that produces the record", got.Statement)
	}
	// And it attributes nothing, because there is no record to attribute to.
	if got.Generation != "" || got.ArtefactIdentity != "" {
		t.Errorf("an unexamined module carries generation %q / artefact %q; both must be empty",
			got.Generation, got.ArtefactIdentity)
	}
}

// TestNativeCoverage_IdentifiedNamesTheComponentAndThePURL. The purl is the
// string a reader joins this statement to the SBOM component on.
func TestNativeCoverage_IdentifiedNamesTheComponentAndThePURL(t *testing.T) {
	got := nativeCoverageOf(natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.53.0"), 4), true)
	if len(got.Components) != 1 {
		t.Fatalf("got %d components, want 1", len(got.Components))
	}
	c := got.Components[0]
	if c.Name != "SQLite" || c.Version != "3.53.0" || c.Confidence != "declared" {
		t.Errorf("component = %+v, want SQLite 3.53.0 declared", c)
	}
	if c.PURL != "pkg:generic/sqlite@3.53.0" {
		t.Errorf("purl = %q, want pkg:generic/sqlite@3.53.0", c.PURL)
	}
	if c.AdvisoriesSearched {
		t.Error("advisories_searched = true; nothing searched them")
	}
	if !strings.Contains(got.Statement, "NOT searched") {
		t.Errorf("statement = %q; it must say the advisories were not searched", got.Statement)
	}
	if got.Generation != "0.3.0+recipes.1" {
		t.Errorf("generation = %q, want 0.3.0+recipes.1", got.Generation)
	}
}

// TestNativeCoverage_UnrecognisedPresenceIsReportedAsItself. An answer this
// build does not know is not an absence, and guessing which neighbour it is
// closest to is how a coverage gap becomes an all-clear.
func TestNativeCoverage_UnrecognisedPresenceIsReportedAsItself(t *testing.T) {
	got := nativeCoverageOf(natRecord(nativedomain.Presence("from_the_future"), nil, 0), true)
	if got.State != nativeCoverageState("from_the_future") {
		t.Errorf("state = %q, want it echoed back as itself", got.State)
	}
	if got.UnsearchedComponents != 0 || len(got.Components) != 0 {
		t.Error("an unrecognised presence must contribute no component")
	}
	if !strings.Contains(got.Statement, "does not recognise") {
		t.Errorf("statement = %q; it must say the presence was not recognised", got.Statement)
	}
}

// TestNativeCoverage_ComponentsSerialiseAsAnArrayNeverNull, so a consumer
// iterates uniformly whatever the answer was.
func TestNativeCoverage_ComponentsSerialiseAsAnArrayNeverNull(t *testing.T) {
	for _, p := range []nativedomain.Presence{
		nativedomain.PresenceAbsent, nativedomain.PresenceLinkedNotShipped, nativedomain.PresenceUnidentified,
	} {
		b, err := json.Marshal(nativeCoverageOf(natRecord(p, nil, 1), true))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"components":[]`) {
			t.Errorf("%s serialises components as null, not []: %s", p, b)
		}
	}
	// And the two keys a machine reads are on the wire in every state.
	b, _ := json.Marshal(nativeCoverageOf(natRecord(nativedomain.PresenceAbsent, nil, 0), true))
	for _, key := range []string{`"state"`, `"unsearched_components"`, `"statement"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("%s is missing from the payload: %s", key, b)
		}
	}
}

// TestDeriveNativeCoverage_NoReaderPublishesNothing. An absent key says "this
// producer does not derive it", which is a different statement from an absence
// nothing measured.
func TestDeriveNativeCoverage_NoReaderPublishesNothing(t *testing.T) {
	if got := deriveNativeCoverage(context.Background(), nil, natCoord(t, "example.com/a", "v1.0.0")); got != nil {
		t.Errorf("deriveNativeCoverage(nil reader) = %+v, want nil", got)
	}
}

// TestDeriveNativeCoverage_AReadFailureIsNotAnAbsence. The one error this read
// produces is the store holding records that describe two different artefacts
// for one pinned version; answering "not examined" there would report a
// contradiction as an absence.
func TestDeriveNativeCoverage_AReadFailureIsNotAnAbsence(t *testing.T) {
	r := &fakeNativeReader{err: errors.New("conflicting records")}
	if got := deriveNativeCoverage(context.Background(), r, natCoord(t, "example.com/a", "v1.0.0")); got != nil {
		t.Errorf("a failed read produced %+v, want nil", got)
	}
}

// TestDeriveNativeCoverage_ReadsTheRecordForTheCoordinateAsked.
func TestDeriveNativeCoverage_ReadsTheRecordForTheCoordinateAsked(t *testing.T) {
	want := natCoord(t, "example.com/go-sqlite3", "v1.14.12")
	other := natCoord(t, "example.com/other", "v1.0.0")
	r := &fakeNativeReader{recs: map[coordinate.ModuleCoordinate]nativedomain.Record{
		want: natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.38.0"), 4),
	}}
	got := deriveNativeCoverage(context.Background(), r, want)
	if got == nil || got.State != nativeStateIdentified {
		t.Fatalf("deriveNativeCoverage = %+v, want the identified record", got)
	}
	if miss := deriveNativeCoverage(context.Background(), r, other); miss == nil || miss.State != nativeStateNotExamined {
		t.Errorf("a coordinate with no record = %+v, want not_examined", miss)
	}
}

// TestPrintNativeCoverage_PrintsInEveryState. Leaving the line off where there
// is nothing to report would make its PRESENCE the signal, and a reader would
// have to know the tool's conventions to read an absent line as an answer.
func TestPrintNativeCoverage_PrintsInEveryState(t *testing.T) {
	for _, p := range []nativedomain.Presence{
		nativedomain.PresenceAbsent, nativedomain.PresenceLinkedNotShipped,
		nativedomain.PresenceUnidentified, nativedomain.PresenceIdentified,
	} {
		var out bytes.Buffer
		cov := nativeCoverageOf(natRecord(p, sqliteComponent("3.53.0"), 4), true)
		printNativeCoverage(&out, &cov)
		if !strings.Contains(out.String(), "Native code:") {
			t.Errorf("%s printed no native line:\n%s", p, out.String())
		}
	}
	// A nil statement prints nothing at all.
	var none bytes.Buffer
	printNativeCoverage(&none, nil)
	if none.Len() != 0 {
		t.Errorf("a nil statement printed %q", none.String())
	}
}

// TestPrintNativeCoverage_TextAndJSONStateTheSameClaim. Two surfaces disagreeing
// about one record is worse than either being terse.
func TestPrintNativeCoverage_TextAndJSONStateTheSameClaim(t *testing.T) {
	cov := nativeCoverageOf(natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.53.0"), 4), true)
	var out bytes.Buffer
	printNativeCoverage(&out, &cov)
	text := out.String()
	if !strings.Contains(text, cov.Statement) {
		t.Errorf("the text surface does not carry the statement the payload states:\n%s", text)
	}
	for _, want := range []string{string(cov.State), "SQLite", "3.53.0", "pkg:generic/sqlite@3.53.0", "0.3.0+recipes.1"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text surface omits %q:\n%s", want, text)
		}
	}
}

// TestNativeComponentList_ReadsAsProse for one, two and three components.
func TestNativeComponentList_ReadsAsProse(t *testing.T) {
	c := func(names ...string) []nativeCoverageComponent {
		out := make([]nativeCoverageComponent, 0, len(names))
		for _, n := range names {
			out = append(out, nativeCoverageComponent{Name: n, Version: "1"})
		}
		return out
	}
	for _, tc := range []struct {
		in   []nativeCoverageComponent
		want string
	}{
		{c(), "a native component"},
		{c("SQLite"), "SQLite 1"},
		{c("SQLite", "zlib"), "SQLite 1 and zlib 1"},
		{c("SQLite", "zlib", "icu"), "SQLite 1, zlib 1 and icu 1"},
	} {
		if got := nativeComponentList(tc.in); got != tc.want {
			t.Errorf("nativeComponentList(%d) = %q, want %q", len(tc.in), got, tc.want)
		}
	}
}

// TestNativeRollup_SortsTheExceptionsAndCountsTheRest. The rollup is what a
// scan report carries: a reader of a 300-module scan needs the exception, not a
// line per module.
func TestNativeRollup_SortsTheExceptionsAndCountsTheRest(t *testing.T) {
	zzz := natCoord(t, "example.com/zzz", "v1.0.0")
	aaa := natCoord(t, "example.com/aaa", "v1.0.0")
	unidZ := natCoord(t, "example.com/unid-z", "v1.0.0")
	unidA := natCoord(t, "example.com/unid-a", "v1.0.0")
	plain := natCoord(t, "example.com/plain", "v1.0.0")
	linked := natCoord(t, "example.com/linked", "v1.0.0")
	unknown := natCoord(t, "example.com/unknown", "v1.0.0")

	r := &fakeNativeReader{recs: map[coordinate.ModuleCoordinate]nativedomain.Record{
		zzz:    natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.53.0"), 4),
		aaa:    natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.38.0"), 4),
		unidZ:  natRecord(nativedomain.PresenceUnidentified, nil, 2),
		unidA:  natRecord(nativedomain.PresenceUnidentified, nil, 2),
		plain:  natRecord(nativedomain.PresenceAbsent, nil, 0),
		linked: natRecord(nativedomain.PresenceLinkedNotShipped, nil, 0),
	}}
	// Deliberately unsorted input: the report must not inherit the caller's order.
	got := nativeRollupOver(context.Background(), r, []coordinate.ModuleCoordinate{
		zzz, unidZ, plain, unknown, aaa, linked, unidA,
	})
	if got == nil {
		t.Fatal("nativeRollupOver = nil")
	}
	if len(got.Unsearched) != 2 || got.Unsearched[0].Module != "example.com/aaa@v1.0.0" {
		t.Errorf("unsearched = %+v, want aaa then zzz", got.Unsearched)
	}
	if got.Components != 2 {
		t.Errorf("components = %d, want 2", got.Components)
	}
	want := []string{"example.com/unid-a@v1.0.0", "example.com/unid-z@v1.0.0"}
	if len(got.Unidentified) != 2 || got.Unidentified[0] != want[0] || got.Unidentified[1] != want[1] {
		t.Errorf("unidentified = %v, want %v", got.Unidentified, want)
	}
	// absent and linked_not_shipped are measured and unsearched of nothing, so
	// neither joins a rollup of exceptions; the module nobody examined is counted.
	if got.NotExamined != 1 {
		t.Errorf("not_examined = %d, want 1", got.NotExamined)
	}
}

// TestNativeRollup_NoReaderPublishesNothing, and an empty build publishes an
// empty statement rather than none — a measured answer is not the absence of one.
func TestNativeRollup_NoReaderPublishesNothing(t *testing.T) {
	if got := nativeRollupOver(context.Background(), nil, nil); got != nil {
		t.Errorf("nativeRollupOver(nil reader) = %+v, want nil", got)
	}
	got := nativeRollupOver(context.Background(), &fakeNativeReader{}, nil)
	if got == nil {
		t.Fatal("a wired reader over an empty build produced nil, not an empty statement")
	}
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), `"unsearched":[]`) || !strings.Contains(string(b), `"unidentified":[]`) {
		t.Errorf("empty collections serialise as null: %s", b)
	}
}

// TestNativeRollup_AFailedReadDoesNotWithholdTheReport. The scan's own answer is
// still true; the alternative is a whole report withheld because one record
// disagreed with itself.
func TestNativeRollup_AFailedReadDoesNotWithholdTheReport(t *testing.T) {
	r := &fakeNativeReader{err: errors.New("conflicting records")}
	got := nativeRollupOver(context.Background(), r, []coordinate.ModuleCoordinate{natCoord(t, "example.com/a", "v1.0.0")})
	if got == nil {
		t.Fatal("a failed read withheld the whole rollup")
	}
	if !got.empty() || got.NotExamined != 0 {
		t.Errorf("a failed read contributed to a bucket: %+v", got)
	}
}

// TestWriteNativeRollup_PrintsOnlyTheExceptionsAndNeverCallsThemFindings.
// An SBOM never asserts vulnerabilities and neither does this: it states a gap.
func TestWriteNativeRollup_PrintsOnlyTheExceptionsAndNeverCallsThemFindings(t *testing.T) {
	var quiet bytes.Buffer
	writeNativeRollup(&quiet, &nativeWalkRollup{NotExamined: 9})
	if quiet.Len() != 0 {
		t.Errorf("a rollup with no exceptions printed %q", quiet.String())
	}
	writeNativeRollup(&quiet, nil)
	if quiet.Len() != 0 {
		t.Errorf("a nil rollup printed %q", quiet.String())
	}

	var out bytes.Buffer
	writeNativeRollup(&out, &nativeWalkRollup{
		Unsearched: []nativeWalkModule{{Module: "example.com/a@v1.0.0",
			Components: []nativeCoverageComponent{{Name: "SQLite", Version: "3.38.0", Confidence: "declared", PURL: "pkg:generic/sqlite@3.38.0"}}}},
		Unidentified: []string{"example.com/b@v1.0.0"},
		Components:   1,
	})
	got := out.String()
	for _, want := range []string{
		"advisories NOT searched", "example.com/a@v1.0.0", "SQLite 3.38.0",
		"pkg:generic/sqlite@3.38.0", "not an all-clear",
		"not identified", "example.com/b@v1.0.0", "kanonarion native",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rollup omits %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"vulnerab", "CVE-", "Findings ("} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the rollup states %q; it reports a coverage gap, never a finding:\n%s", forbidden, got)
		}
	}
}

// TestWriteNativeUnidentifiedCaveat_NamesTheModulesAndTheRemedy. An SBOM is an
// inventory and CycloneDX has no field for "something is here and we cannot say
// what", so the run states it on its own channel.
func TestWriteNativeUnidentifiedCaveat_NamesTheModulesAndTheRemedy(t *testing.T) {
	var quiet bytes.Buffer
	if err := writeNativeUnidentifiedCaveat(&quiet, nil); err != nil {
		t.Fatal(err)
	}
	if err := writeNativeUnidentifiedCaveat(&quiet, &nativeWalkRollup{Components: 3}); err != nil {
		t.Fatal(err)
	}
	if quiet.Len() != 0 {
		t.Errorf("a walk with nothing unidentified printed %q", quiet.String())
	}

	var out bytes.Buffer
	if err := writeNativeUnidentifiedCaveat(&out, &nativeWalkRollup{
		Unidentified: []string{"example.com/a@v1.0.0", "example.com/b@v2.0.0"},
	}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"2 module(s)", "NO component", "present and unidentified, not absent",
		"example.com/a@v1.0.0", "example.com/b@v2.0.0", "kanonarion native",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the caveat omits %q:\n%s", want, got)
		}
	}
}

// TestIsNativeComponentPURL separates the two halves of the component list, and
// is what keeps the licence gate measured over the Go components alone.
func TestIsNativeComponentPURL(t *testing.T) {
	for purl, want := range map[string]bool{
		"pkg:generic/sqlite@3.53.0":             true,
		"pkg:golang/github.com/a/b@v1.0.0":      false,
		"pkg:golang/example.com/generic@v1.0.0": false,
		"":                                      false,
	} {
		if got := isNativeComponentPURL(purl); got != want {
			t.Errorf("isNativeComponentPURL(%q) = %v, want %v", purl, got, want)
		}
	}
}
