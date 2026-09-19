package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	nativeports "github.com/eitanity/kanonarion/internal/native/ports"
)

// The defect this file pins: the native fact could be read one module at a
// time and no further. A store holding 186 records held ten that reported
// anything, and finding them meant invoking the single-module command 186
// times.

// fakeNativeLister is a store survey that honours the filter it is given.
// Honouring it is the point: a fake that ignored the limit would let a listing
// that ignored the limit pass.
type fakeNativeLister struct {
	rows      []nativeports.NativeSummary
	err       error
	listCalls int
	sawFilter nativeports.NativeFilter
}

func (f *fakeNativeLister) List(_ context.Context, filter nativeports.NativeFilter) ([]nativeports.NativeSummary, error) {
	f.listCalls++
	f.sawFilter = filter
	if f.err != nil {
		return nil, f.err
	}
	out := make([]nativeports.NativeSummary, 0, len(f.rows))
	want := map[string]bool{}
	for _, p := range filter.Presence {
		want[p] = true
	}
	for _, r := range f.rows {
		if !filter.AllGenerations && r.Generation != nativedomain.PipelineFingerprint() {
			continue
		}
		if len(want) > 0 && !want[string(r.Presence)] {
			continue
		}
		out = append(out, r)
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return []nativeports.NativeSummary{}, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

// nativeSummaryFixture builds one row at the generation this build serves.
func nativeSummaryFixture(t *testing.T, path string, presence nativedomain.Presence) nativeports.NativeSummary {
	t.Helper()
	return nativeports.NativeSummary{
		Coordinate:       mustCoord(t, path, "v1.0.0"),
		Generation:       nativedomain.PipelineFingerprint(),
		ArtefactIdentity: "zip:h1:" + path,
		Presence:         presence,
		Components:       []nativedomain.Component{},
		ExtractedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ContentHash:      "sha256:abc",
	}
}

// nativeSurface is native-list's entry in the shared listing corpus, so it is
// held to the same paging, truncation and zero-result rules as every sibling
// rather than to a set of its own.
func nativeSurface(t *testing.T) listingSurface {
	t.Helper()
	rows := make([]nativeports.NativeSummary, 0, truncPopulation)
	for i := range truncPopulation {
		rows = append(rows, nativeSummaryFixture(t, fmt.Sprintf("example.com/mod%d", i), nativedomain.PresenceAbsent))
	}
	uc := &fakeNativeLister{rows: rows}
	return listingSurface{
		name:       "native-list",
		population: truncPopulation,
		subject:    "native records at generation " + nativedomain.PipelineFingerprint(),
		listCalls:  func() int { return uc.listCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := nativeListWith(context.Background(),
				nativeListFlags{limit: limit, offset: offset}, uc, &stdout, &stderr); err != nil {
				t.Fatalf("nativeListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

// runNativeListFor drives the listing over a fixed corpus and returns both
// streams and the error, so a case can assert the exit as well as the words.
func runNativeListFor(t *testing.T, rows []nativeports.NativeSummary, f nativeListFlags, asJSON bool) (string, string, error) {
	t.Helper()
	withJSON(t, asJSON)
	var stdout, stderr bytes.Buffer
	err := nativeListWith(context.Background(), f, &fakeNativeLister{rows: rows}, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

// The whole point of the listing, asserted as one command: a store of many
// modules, a filter naming the three presences that are not an absence, and
// the answer is the modules that report something.
func TestNativeList_PresenceFilterFindsTheModulesThatReportSomething(t *testing.T) {
	rows := []nativeports.NativeSummary{
		nativeSummaryFixture(t, "example.com/plain", nativedomain.PresenceAbsent),
		nativeSummaryFixture(t, "example.com/ships", nativedomain.PresenceIdentified),
		nativeSummaryFixture(t, "example.com/quiet", nativedomain.PresenceAbsent),
		nativeSummaryFixture(t, "example.com/links", nativedomain.PresenceLinkedNotShipped),
		nativeSummaryFixture(t, "example.com/unnamed", nativedomain.PresenceUnidentified),
	}
	stdout, _, err := runNativeListFor(t, rows, nativeListFlags{limit: 50, presence: []string{
		string(nativedomain.PresenceLinkedNotShipped),
		string(nativedomain.PresenceIdentified),
		string(nativedomain.PresenceUnidentified),
	}}, true)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}

	var doc struct {
		Records []nativeListEntry `json:"records"`
	}
	if derr := json.Unmarshal([]byte(stdout), &doc); derr != nil {
		t.Fatalf("decoding listing: %v", derr)
	}
	if len(doc.Records) != 3 {
		t.Fatalf("listed %d records, want the 3 that report something", len(doc.Records))
	}
	for _, r := range doc.Records {
		if r.Presence == string(nativedomain.PresenceAbsent) {
			t.Errorf("%s@%s is absent and matched a filter that named no absence", r.Module, r.Version)
		}
		// Presence is the field the listing exists to filter on. Without it on
		// the row a caller cannot tell which of the three they are looking at.
		if r.Presence == "" {
			t.Errorf("%s@%s carries no presence", r.Module, r.Version)
		}
	}
}

// The document is one object holding one array, not a stream of objects. A
// newline-delimited listing has nowhere to state what the request did.
func TestNativeList_JSONIsOneDocumentHoldingOneArray(t *testing.T) {
	rows := []nativeports.NativeSummary{
		nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceAbsent),
		nativeSummaryFixture(t, "example.com/b", nativedomain.PresenceAbsent),
	}
	stdout, _, err := runNativeListFor(t, rows, nativeListFlags{limit: 50}, true)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}

	var obj map[string]json.RawMessage
	if derr := json.Unmarshal([]byte(stdout), &obj); derr != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", derr, stdout)
	}
	var records []json.RawMessage
	if derr := json.Unmarshal(obj["records"], &records); derr != nil {
		t.Fatalf("records is not an array: %v", derr)
	}
	if len(records) != 2 {
		t.Fatalf("records holds %d rows, want 2", len(records))
	}
	// A second decoder pass must find nothing after the document: one object
	// per line would leave a second one here.
	dec := json.NewDecoder(strings.NewReader(stdout))
	if derr := dec.Decode(&map[string]any{}); derr != nil {
		t.Fatalf("decoding the document: %v", derr)
	}
	if dec.More() {
		t.Error("stdout carries more than one JSON value: the listing emits a stream, not a document")
	}
}

// The envelope is the one this store's listings already have. A third shape is
// a decision nobody needs to make twice, so it is compared key for key against
// two siblings rather than described in a comment.
func TestNativeList_EnvelopeMatchesItsSiblingsKeyForKey(t *testing.T) {
	native, _, err := runNativeListFor(t,
		[]nativeports.NativeSummary{nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceAbsent)},
		nativeListFlags{limit: 50}, true)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}

	for _, sibling := range []listingSurface{interfaceSurface(), vulnScanSurface()} {
		t.Run(sibling.name, func(t *testing.T) {
			other, _ := sibling.run(t, 3, 0, true)
			if got, want := jsonKeySet(t, native), jsonKeySet(t, other); got != want {
				t.Errorf("native-list envelope keys = %s, %s emits %s", got, sibling.name, want)
			}
		})
	}
}

// jsonKeySet renders a JSON object's top-level keys, sorted, as one comparable
// string.
func jsonKeySet(t *testing.T, doc string) string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &obj); err != nil {
		t.Fatalf("decoding document: %v\n%s", err, doc)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	return strings.Join(sortedStrings(keys), ",")
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// A filter that matched nothing says what it compared against and how, rather
// than printing an empty page a reader would take for "nothing is there".
func TestNativeList_FilterMissStatesWhatWasSearched(t *testing.T) {
	rows := []nativeports.NativeSummary{
		nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceAbsent),
		nativeSummaryFixture(t, "example.com/b", nativedomain.PresenceLinkedNotShipped),
	}
	stdout, _, err := runNativeListFor(t, rows,
		nativeListFlags{limit: 50, presence: []string{string(nativedomain.PresenceIdentified)}}, false)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	for _, want := range []string{
		`no native record matched presence "present_identified"`,
		"for exact equality",
		"all 2 native record(s) in the store",
		// The vocabulary the corpus actually holds, so a reader who mistyped a
		// value learns the set rather than guessing again.
		"absent, linked_not_shipped",
		"kanonarion native-list",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("zero-result notice does not say %q:\n%s", want, stdout)
		}
	}
}

// The same statement on the data channel, inside the document, beside the empty
// array. A consumer reading stdout must be able to tell an empty answer from an
// unasked question.
func TestNativeList_FilterMissTravelsInTheDocument(t *testing.T) {
	rows := []nativeports.NativeSummary{nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceAbsent)}
	stdout, stderr, err := runNativeListFor(t, rows,
		nativeListFlags{limit: 50, presence: []string{string(nativedomain.PresenceIdentified)}}, true)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Errorf("a listing wrote to stderr under --json: %q", stderr)
	}
	var doc struct {
		Records []json.RawMessage `json:"records"`
		Zero    *struct {
			Subject           string `json:"subject"`
			RecordsConsidered int    `json:"records_considered"`
			StoreEmpty        bool   `json:"store_empty"`
			Filter            *struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"filter"`
		} `json:"zero_result"`
	}
	if derr := json.Unmarshal([]byte(stdout), &doc); derr != nil {
		t.Fatalf("decoding listing: %v", derr)
	}
	if len(doc.Records) != 0 {
		t.Fatalf("records holds %d rows on a miss", len(doc.Records))
	}
	if doc.Zero == nil {
		t.Fatal("no zero_result on an empty page")
	}
	if doc.Zero.RecordsConsidered != 1 || doc.Zero.StoreEmpty {
		t.Errorf("zero_result = %+v, want 1 record considered and a non-empty store", doc.Zero)
	}
	if doc.Zero.Filter == nil || doc.Zero.Filter.Name != "presence" {
		t.Errorf("zero_result names no presence filter: %+v", doc.Zero)
	}
}

// A store holding no native record at all is a different zero, with a different
// remedy: produce one, rather than check the filter.
func TestNativeList_EmptyStoreSaysProduceARecord(t *testing.T) {
	stdout, _, err := runNativeListFor(t, nil, nativeListFlags{limit: 50}, false)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	if !strings.Contains(stdout, "the store holds no native record at all") {
		t.Errorf("empty store did not say so:\n%s", stdout)
	}
	if !strings.Contains(stdout, "kanonarion native <module>@<version>") {
		t.Errorf("empty store named no way to produce a record:\n%s", stdout)
	}
}

// A page starting past the last MATCHING record is a paging zero, not a filter
// miss. Reporting it as a miss would be false about a filter that matched.
func TestNativeList_PagePastTheFilteredEndIsNotReportedAsAMiss(t *testing.T) {
	rows := []nativeports.NativeSummary{
		nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceIdentified),
		nativeSummaryFixture(t, "example.com/b", nativedomain.PresenceAbsent),
		nativeSummaryFixture(t, "example.com/c", nativedomain.PresenceAbsent),
	}
	stdout, _, err := runNativeListFor(t, rows,
		nativeListFlags{limit: 50, offset: 5, presence: []string{string(nativedomain.PresenceIdentified)}}, false)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	if strings.Contains(stdout, "no native record matched") {
		t.Errorf("a paging zero was reported as a filter miss:\n%s", stdout)
	}
	if !strings.Contains(stdout, `--offset 5 starts past the last of the 1 matching presence "present_identified"`) {
		t.Errorf("the paging zero does not name the matching population:\n%s", stdout)
	}
}

// Every listing states which generation its rows came from, whether or not
// anything was excluded. A count of native records reads as a count of what is
// known, and a restricted count that does not say so is read as a whole one.
func TestNativeList_StatesTheGenerationItIsShowing(t *testing.T) {
	rows := []nativeports.NativeSummary{nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceAbsent)}
	stdout, _, err := runNativeListFor(t, rows, nativeListFlags{limit: 50}, false)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	want := "listing native records at generation " + nativedomain.PipelineFingerprint()
	if !strings.Contains(stdout, want) {
		t.Errorf("listing does not name its generation (%q):\n%s", want, stdout)
	}
	if !strings.Contains(stdout, "--all-generations") {
		t.Errorf("listing does not name the flag that lifts the restriction:\n%s", stdout)
	}
}

// A record from a superseded generation is hidden by default and marked when
// asked for. It answers no query this build serves, so listing it unmarked
// would pad the count of what is known with a row that cannot answer.
func TestNativeList_SupersededGenerationIsHiddenThenMarked(t *testing.T) {
	old := nativeSummaryFixture(t, "example.com/old", nativedomain.PresenceIdentified)
	old.Generation = "0.1.0+recipes.1"
	rows := []nativeports.NativeSummary{
		nativeSummaryFixture(t, "example.com/current", nativedomain.PresenceAbsent),
		old,
	}

	hidden, _, err := runNativeListFor(t, rows, nativeListFlags{limit: 50}, false)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	if strings.Contains(hidden, "example.com/old") {
		t.Errorf("a superseded record was listed by default:\n%s", hidden)
	}

	shown, _, err := runNativeListFor(t, rows, nativeListFlags{limit: 50, allGenerations: true}, false)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	if !strings.Contains(shown, "[superseded generation 0.1.0+recipes.1]") {
		t.Errorf("--all-generations did not mark the superseded row:\n%s", shown)
	}
	if !strings.Contains(shown, "1 of 2 listed record(s) were taken at a superseded detection generation") {
		t.Errorf("--all-generations did not count the superseded rows:\n%s", shown)
	}

	doc, _, jerr := runNativeListFor(t, rows, nativeListFlags{limit: 50, allGenerations: true}, true)
	if jerr != nil {
		t.Fatalf("nativeListWith: %v", jerr)
	}
	var out struct {
		Records []nativeListEntry `json:"records"`
	}
	if derr := json.Unmarshal([]byte(doc), &out); derr != nil {
		t.Fatalf("decoding listing: %v", derr)
	}
	// Both halves on every row: the false one says "this record IS servable",
	// which a consumer cannot read from an absent key.
	marked := map[string]bool{}
	for _, r := range out.Records {
		marked[r.Module] = r.Superseded
	}
	if !marked["example.com/old"] || marked["example.com/current"] {
		t.Errorf("superseded flags = %v, want only the old record marked", marked)
	}
}

// A coordinate the store holds two measurements of is listed, marked, and the
// command fails. Every other row still answers; a store that disagrees with
// itself must not read as a clean run.
func TestNativeList_DisputedCoordinateIsListedMarkedAndFails(t *testing.T) {
	disputed := nativeSummaryFixture(t, "example.com/disputed", nativedomain.PresenceAbsent)
	disputed.Conflict = fmt.Errorf("%w: two artefacts", nativeports.ErrNativeConflict)
	rows := []nativeports.NativeSummary{
		nativeSummaryFixture(t, "example.com/fine", nativedomain.PresenceAbsent),
		disputed,
	}

	stdout, _, err := runNativeListFor(t, rows, nativeListFlags{limit: 50}, false)
	if err == nil {
		t.Fatal("a listing holding a disputed coordinate exited clean")
	}
	if !errors.Is(err, nativeports.ErrNativeConflict) {
		t.Errorf("error = %v, want it to carry ErrNativeConflict", err)
	}
	if !strings.Contains(stdout, "example.com/fine") {
		t.Errorf("one disputed coordinate deleted the answers for the others:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[CONFLICT:") {
		t.Errorf("the disputed row is not marked:\n%s", stdout)
	}

	doc, _, jerr := runNativeListFor(t, rows, nativeListFlags{limit: 50}, true)
	if jerr == nil {
		t.Fatal("the JSON path exited clean on a disputed coordinate")
	}
	if !strings.Contains(doc, `"conflict"`) {
		t.Errorf("the document does not mark the disputed row:\n%s", doc)
	}
}

// The row names what was found rather than counting it: a reader of the listing
// should not have to open a module to learn which library it is.
func TestNativeList_RowNamesTheComponentAndTheLibraries(t *testing.T) {
	ships := nativeSummaryFixture(t, "example.com/ships", nativedomain.PresenceIdentified)
	ships.Components = []nativedomain.Component{
		{Name: "SQLite", Version: "3.38.0", Confidence: nativedomain.ConfidenceDeclared},
	}
	ships.SourceCount = 4
	links := nativeSummaryFixture(t, "example.com/links", nativedomain.PresenceLinkedNotShipped)
	links.LinkedExternal = []string{"libxml-2.0"}

	stdout, _, err := runNativeListFor(t, []nativeports.NativeSummary{ships, links}, nativeListFlags{limit: 50}, false)
	if err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	for _, want := range []string{"4 native source file(s); SQLite 3.38.0", "links libxml-2.0"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("row does not state %q:\n%s", want, stdout)
		}
	}

	// A measured absence prints an answer, not an empty cell.
	plain, _, perr := runNativeListFor(t,
		[]nativeports.NativeSummary{nativeSummaryFixture(t, "example.com/plain", nativedomain.PresenceAbsent)},
		nativeListFlags{limit: 50}, false)
	if perr != nil {
		t.Fatalf("nativeListWith: %v", perr)
	}
	if !strings.Contains(plain, "absent") || !strings.Contains(plain, "—") {
		t.Errorf("an absent row does not read as a measured answer:\n%s", plain)
	}
}

// A presence value outside the four is refused rather than matched. In a list
// of values a typo would otherwise narrow the answer with nothing in the output
// to say so.
func TestNativePresenceFilter_RefusesAValueNoRecordCanHold(t *testing.T) {
	if _, err := nativePresenceFilter([]string{"present_identified", "presentidentified"}); err == nil {
		t.Fatal("an unrecognised presence was accepted into the filter")
	} else {
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != ExitConfig {
			t.Errorf("error = %v, want an ExitConfig refusal", err)
		}
		for _, want := range []string{"presentidentified", "absent", "linked_not_shipped", "present_unidentified"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %q: %v", want, err)
			}
		}
	}

	got, err := nativePresenceFilter([]string{"absent", " absent ", "", "present_identified"})
	if err != nil {
		t.Fatalf("nativePresenceFilter: %v", err)
	}
	if len(got) != 2 || got[0] != "absent" || got[1] != "present_identified" {
		t.Errorf("nativePresenceFilter = %v, want the two distinct values", got)
	}
}

// The corpus survey that sizes a zero result runs only on a zero. A listing
// that returned rows must not pay for a statement it never prints.
func TestNativeList_CorpusIsNotSurveyedWhenRowsCameBack(t *testing.T) {
	uc := &fakeNativeLister{rows: []nativeports.NativeSummary{
		nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceAbsent),
	}}
	withJSON(t, false)
	var stdout, stderr bytes.Buffer
	if err := nativeListWith(context.Background(), nativeListFlags{limit: 50}, uc, &stdout, &stderr); err != nil {
		t.Fatalf("nativeListWith: %v", err)
	}
	if uc.listCalls != 1 {
		t.Errorf("the store was asked %d times for a listing that returned rows, want 1", uc.listCalls)
	}
}

// The store's failure is the caller's answer, not an empty listing.
func TestNativeList_StoreFailureIsReportedNotSwallowed(t *testing.T) {
	boom := errors.New("the survey fell over")
	withJSON(t, false)
	var stdout, stderr bytes.Buffer
	err := nativeListWith(context.Background(), nativeListFlags{limit: 50},
		&fakeNativeLister{err: boom}, &stdout, &stderr)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to carry %v", err, boom)
	}
}
