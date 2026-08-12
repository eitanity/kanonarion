package domain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// opaqueWireTypes are the types on the sealed shape that render their own JSON
// and therefore end the walk below. Each is listed with why it can be trusted
// to hide no collection: all three emit scalars only.
var opaqueWireTypes = map[string]string{
	"time.Time":                     "an RFC3339 string",
	"domain.DatabaseSnapshot":       "an object of four scalars, see its MarshalJSON",
	"coordinate.ModuleCoordinate":   "the \"path@version\" string, see its MarshalJSON",
	"domain.ReachabilityConfidence": "a string",
}

// TestSealedCollections_ClassifiesEverySlice establishes the ordering
// classification FROM the sealed record shape rather than from a list somebody
// kept in their head.
//
// Every slice the shape carries is either a set — whose order is an arrangement
// the seal must not depend on — or an ordered statement whose order is the
// fact. This enumerates the shape by reflection so that adding a collection
// without deciding which fails here. The failure it prevents is silent: an
// unclassified collection misbehaves only when two runs happen to emit it in
// two orders, and by then the store already holds records that disagree about a
// measurement that did not change.
func TestSealedCollections_ClassifiesEverySlice(t *testing.T) {
	t.Parallel()

	found := map[string]bool{}
	walkWireShape(t, reflect.TypeOf(VulnerabilityRecord{}), "", found)

	classified := SealedCollections()
	for path := range found {
		order, ok := classified[path]
		if !ok {
			t.Errorf("the sealed shape carries the collection %q, which SealedCollections classifies neither way: "+
				"decide whether its order is an arrangement (OrderUnordered, and sort it in canonicalOrder) "+
				"or the fact itself (OrderByMeaning)", path)
			continue
		}
		if order != OrderUnordered && order != OrderByMeaning {
			t.Errorf("collection %q is classified %q, which is neither order", path, order)
		}
	}
	for path := range classified {
		if !found[path] {
			t.Errorf("SealedCollections classifies %q, which the sealed shape does not carry, so it orders nothing", path)
		}
	}
}

// TestSealedRunCarriesNoCollection pins the other sealed shape in this domain.
// A WalkScanRun holds a map, which encoding/json emits in key order, and no
// slice at all — so it has no arrangement to canonicalise. Adding one fails
// here, which is where the same decision would have to be made for it.
func TestSealedRunCarriesNoCollection(t *testing.T) {
	t.Parallel()

	found := map[string]bool{}
	walkWireShape(t, reflect.TypeOf(WalkScanRun{}), "", found)
	for path := range found {
		t.Errorf("WalkScanRun now carries the collection %q, whose order reaches its seal: "+
			"classify it and canonicalise it as VulnerabilityRecord's are", path)
	}
}

// walkWireShape records the JSON path of every slice reachable from typ,
// stopping at types that render their own JSON.
func walkWireShape(t *testing.T, typ reflect.Type, path string, found map[string]bool) {
	t.Helper()

	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Implements(reflect.TypeFor[json.Marshaler]()) {
		if _, ok := opaqueWireTypes[typ.String()]; !ok {
			t.Errorf("%s renders its own JSON at %q and is not listed in opaqueWireTypes: "+
				"state what it emits, or the walk cannot say whether it hides a collection", typ, path)
		}
		return
	}
	switch typ.Kind() {
	case reflect.Slice, reflect.Array:
		found[path] = true
		walkWireShape(t, typ.Elem(), path+"[]", found)
	case reflect.Map:
		walkWireShape(t, typ.Elem(), path+"{}", found)
	case reflect.Struct:
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				t.Fatalf("field %s.%s carries no json name, so its wire path cannot be stated", typ, field.Name)
			}
			child := name
			if path != "" {
				child = path + "." + name
			}
			walkWireShape(t, field.Type, child, found)
		}
	}
}

// orderRefs arranges advisory references forward or reversed, as order does for
// the string collections.
func orderRefs(refs []AdvisoryReference, reversed bool) []AdvisoryReference {
	out := slices.Clone(refs)
	if reversed {
		slices.Reverse(out)
	}
	return out
}

// permutedRecord is one module's record built with every unordered collection
// in the arrangement the caller asks for: forward, or reversed.
func permutedRecord(t *testing.T, reversed bool) VulnerabilityRecord {
	t.Helper()

	coord, err := coordinate.NewModuleCoordinate("golang.org/x/net", "v0.33.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	snapshot, err := NewDatabaseSnapshot("vuln.go.dev", "2026-07-27", time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatalf("NewDatabaseSnapshot: %v", err)
	}
	order := func(s []string) []string {
		out := slices.Clone(s)
		if reversed {
			slices.Reverse(out)
		}
		return out
	}
	routes := []ReachabilityRoute{
		{{ModulePath: "example.com/app", Symbol: "main"}, {ModulePath: "golang.org/x/net", ModuleVersion: "v0.33.0", Symbol: "Parse"}},
		{{ModulePath: "example.com/app", Symbol: "serve"}, {ModulePath: "golang.org/x/net", ModuleVersion: "v0.33.0", Receiver: "*Tokenizer", Symbol: "Next"}},
	}
	if reversed {
		slices.Reverse(routes)
	}
	findings := []VulnerabilityFinding{
		{
			ID:              "GO-2025-3595",
			AffectedRange:   "< v0.38.0",
			AffectedSymbols: order([]string{"Parse", "*Tokenizer.Next"}),
			Aliases:         order([]string{"CVE-2025-22872", "GHSA-vvgc-356p-c3xw"}),
			// Two references sharing a URL prefix but differing in type, so an
			// arrangement that survives to the seal shows up as a different hash:
			// the pair is what is ordered, not the URL alone.
			References: orderRefs([]AdvisoryReference{
				{Type: "FIX", URL: "https://example.com/commit"},
				{Type: "WEB", URL: "https://example.com/a"},
				{Type: "ADVISORY", URL: "https://example.com/commit"},
			}, reversed),
			Reachable: &ReachabilityResult{IsReachable: true, Confidence: ConfidenceHigh, Routes: routes},
		},
		{ID: "GO-2024-2687", AffectedRange: "< v0.23.0"},
	}
	if reversed {
		slices.Reverse(findings)
	}
	return VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		WalkID:           "01KZMJBYXA5RJZZYJW2HQ31KE8",
		Findings:         findings,
		DatabaseSnapshot: snapshot,
		ScannedAt:        time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC),
		PipelineVersion:  "vuln-v1",
	}
}

// TestSetContentHash_SealsOneOrderForEveryArrangement is the defect: two scans
// of one module against one snapshot emitted the same values in two orders and
// sealed two different records. Sealing puts the sets into one order, so the two
// arrangements are one record.
func TestSetContentHash_SealsOneOrderForEveryArrangement(t *testing.T) {
	t.Parallel()

	var h VulnerabilityRecordHasher
	forward, err := h.SetContentHash(permutedRecord(t, false))
	if err != nil {
		t.Fatalf("SetContentHash forward: %v", err)
	}
	reversed, err := h.SetContentHash(permutedRecord(t, true))
	if err != nil {
		t.Fatalf("SetContentHash reversed: %v", err)
	}
	if forward.ContentHash != reversed.ContentHash {
		t.Errorf("two arrangements of one measurement sealed differently:\n forward  %s\n reversed %s",
			forward.ContentHash, reversed.ContentHash)
	}
	forwardBytes, err := h.Marshal(forward)
	if err != nil {
		t.Fatalf("Marshal forward: %v", err)
	}
	reversedBytes, err := h.Marshal(reversed)
	if err != nil {
		t.Fatalf("Marshal reversed: %v", err)
	}
	if string(forwardBytes) != string(reversedBytes) {
		t.Errorf("the sealed record is handed back in an arrangement its own seal does not describe:\n forward  %s\n reversed %s",
			forwardBytes, reversedBytes)
	}
}

// TestSetContentHash_KeepsRouteHopsInCallOrder guards the one collection that
// must NOT be sorted. A route is a call stack, entry point first; sorting its
// hops would turn a path into a bag and read as a different call order.
func TestSetContentHash_KeepsRouteHopsInCallOrder(t *testing.T) {
	t.Parallel()

	// The entry point sorts AFTER the vulnerable hop on every field a hop puts
	// on the wire, so a sort of the hops would visibly reverse this route.
	route := ReachabilityRoute{
		{ModulePath: "zzz.example/app", Symbol: "zzz_entry"},
		{ModulePath: "aaa.example/lib", ModuleVersion: "v0.33.0", Symbol: "aaa_vulnerable"},
	}
	record := permutedRecord(t, false)
	record.Findings[0].Reachable = &ReachabilityResult{IsReachable: true, Routes: []ReachabilityRoute{route}}

	sealed, err := VulnerabilityRecordHasher{}.SetContentHash(record)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	idx := slices.IndexFunc(sealed.Findings, func(f VulnerabilityFinding) bool { return f.ID == "GO-2025-3595" })
	if idx < 0 {
		t.Fatalf("the finding carrying the route is not in the sealed record")
	}
	got := sealed.Findings[idx].Reachable.Routes[0]
	if got[0].Symbol != "zzz_entry" || got[1].Symbol != "aaa_vulnerable" {
		t.Errorf("the hops of a route were reordered: got %v, want entry point first", got)
	}
}

// TestVerifyContentHash_ReproducesAStoredArrangement is the reason the canonical
// order is taken at the seal and not inside the hash recipe.
//
// Verification recomputes from the record as it was read back, so a recipe that
// canonicalised would rearrange a stored record on the way to checking it, and
// every record already stored in another arrangement would fail to reproduce its
// own seal — 51 of the 2,006 vulnerability records on the working store when this
// was measured. Those records are not wrong about what they measured; they are
// arranged differently.
//
// The fixture is one of those 51, lifted byte for byte out of the store, so this
// is the real case and not a reconstruction of it.
func TestVerifyContentHash_ReproducesAStoredArrangement(t *testing.T) {
	t.Parallel()

	stored, err := os.ReadFile(filepath.Join("testdata", "stored_precanonical_record.json"))
	if err != nil {
		t.Fatalf("reading the stored record: %v", err)
	}
	var h VulnerabilityRecordHasher
	record, err := h.Unmarshal(stored)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// The fixture only makes its point while it is in a pre-canonical
	// arrangement. If a future edit sorts it, this test would pass for the wrong
	// reason.
	arranged := false
	for _, f := range record.Findings {
		if !slices.IsSorted(f.AffectedSymbols) {
			arranged = true
		}
	}
	if !arranged {
		t.Fatal("the stored fixture is in canonical order, so it no longer stands for the records this decision protects")
	}

	if verr := h.VerifyContentHash(record); verr != nil {
		t.Errorf("a record already in the store no longer verifies, so the canonical order has moved into the hash "+
			"recipe and every record stored in another arrangement is now read as tampered: %v", verr)
	}
}

// TestSortFindings_DecidesASharedID gives SortFindings the tiebreak its doc
// comment used to claim and never had. Keyed on ID alone with an unstable sort,
// two findings sharing an ID ordered by whichever arrangement arrived.
func TestSortFindings_DecidesASharedID(t *testing.T) {
	t.Parallel()

	a := VulnerabilityFinding{ID: "GO-2025-0001", AffectedRange: "< v1.0.0", Summary: "first"}
	b := VulnerabilityFinding{ID: "GO-2025-0001", AffectedRange: "< v2.0.0", Summary: "second"}

	forward := []VulnerabilityFinding{a, b}
	reversed := []VulnerabilityFinding{b, a}
	SortFindings(forward)
	SortFindings(reversed)

	if forward[0].Summary != reversed[0].Summary || forward[1].Summary != reversed[1].Summary {
		t.Errorf("two findings sharing an ID ordered by their input arrangement: %q,%q vs %q,%q",
			forward[0].Summary, forward[1].Summary, reversed[0].Summary, reversed[1].Summary)
	}
}

// TestCompareFinding_IsKeyedOnEveryWireField walks the comparator key by key.
//
// A comparator that stops short of some field lets two findings differing only
// in that field compare equal, and an unstable sort then orders them by the
// arrangement they arrived in — the defect this file exists to close, one level
// down. Each case differs from its partner in exactly one field, so a key that
// is dropped from CompareFinding makes its own case fail and nothing else.
func TestCompareFinding_IsKeyedOnEveryWireField(t *testing.T) {
	t.Parallel()

	early := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	route := ReachabilityRoute{{ModulePath: "example.com/a", Symbol: "f"}}

	cases := []struct {
		name         string
		lower, upper VulnerabilityFinding
	}{
		{"id", VulnerabilityFinding{ID: "GO-1"}, VulnerabilityFinding{ID: "GO-2"}},
		{"affected_range", VulnerabilityFinding{AffectedRange: "< v1"}, VulnerabilityFinding{AffectedRange: "< v2"}},
		{"fixed_in", VulnerabilityFinding{FixedIn: "v1"}, VulnerabilityFinding{FixedIn: "v2"}},
		{"summary", VulnerabilityFinding{Summary: "a"}, VulnerabilityFinding{Summary: "b"}},
		{"details", VulnerabilityFinding{Details: "a"}, VulnerabilityFinding{Details: "b"}},
		{"severity absent before stated", VulnerabilityFinding{}, VulnerabilityFinding{Severity: &Severity{}}},
		{"severity label", VulnerabilityFinding{Severity: &Severity{Label: "LOW"}}, VulnerabilityFinding{Severity: &Severity{Label: "MODERATE"}}},
		{"severity score", VulnerabilityFinding{Severity: &Severity{Score: 1}}, VulnerabilityFinding{Severity: &Severity{Score: 2}}},
		{"severity vector", VulnerabilityFinding{Severity: &Severity{Vector: "a"}}, VulnerabilityFinding{Severity: &Severity{Vector: "b"}}},
		{"affected_symbols", VulnerabilityFinding{AffectedSymbols: []string{"a"}}, VulnerabilityFinding{AffectedSymbols: []string{"b"}}},
		{"aliases", VulnerabilityFinding{Aliases: []string{"a"}}, VulnerabilityFinding{Aliases: []string{"b"}}},
		{"references url", VulnerabilityFinding{References: []AdvisoryReference{{Type: "FIX", URL: "a"}}}, VulnerabilityFinding{References: []AdvisoryReference{{Type: "FIX", URL: "b"}}}},
		// The type is keyed as well as the URL. Without it two references to one
		// URL under different types compare equal, and the pair the field exists to
		// carry stops deciding anything.
		{"references type", VulnerabilityFinding{References: []AdvisoryReference{{Type: "ADVISORY", URL: "a"}}}, VulnerabilityFinding{References: []AdvisoryReference{{Type: "FIX", URL: "a"}}}},
		{"advisory_names_no_symbols", VulnerabilityFinding{}, VulnerabilityFinding{AdvisoryNamesNoSymbols: true}},
		{"reachability_note", VulnerabilityFinding{ReachabilityNote: "a"}, VulnerabilityFinding{ReachabilityNote: "b"}},
		{"published_at", VulnerabilityFinding{PublishedAt: early}, VulnerabilityFinding{PublishedAt: late}},
		{"modified_at", VulnerabilityFinding{ModifiedAt: early}, VulnerabilityFinding{ModifiedAt: late}},
		{"withdrawn_at", VulnerabilityFinding{WithdrawnAt: early}, VulnerabilityFinding{WithdrawnAt: late}},
		{"reachable absent before stated", VulnerabilityFinding{}, VulnerabilityFinding{Reachable: &ReachabilityResult{}}},
		{"reachable is_reachable", VulnerabilityFinding{Reachable: &ReachabilityResult{}}, VulnerabilityFinding{Reachable: &ReachabilityResult{IsReachable: true}}},
		{"reachable confidence", VulnerabilityFinding{Reachable: &ReachabilityResult{Confidence: ConfidenceHigh}}, VulnerabilityFinding{Reachable: &ReachabilityResult{Confidence: ConfidenceLow}}},
		{"reachable analyser", VulnerabilityFinding{Reachable: &ReachabilityResult{DerivedBy: ReachabilityDerivation{Analyser: AnalyserCallGraphBFS}}}, VulnerabilityFinding{Reachable: &ReachabilityResult{DerivedBy: ReachabilityDerivation{Analyser: AnalyserGovulncheck}}}},
		{"reachable fidelity", VulnerabilityFinding{Reachable: &ReachabilityResult{DerivedBy: ReachabilityDerivation{Fidelity: "binary"}}}, VulnerabilityFinding{Reachable: &ReachabilityResult{DerivedBy: ReachabilityDerivation{Fidelity: "source"}}}},
		{"reachable rooting", VulnerabilityFinding{Reachable: &ReachabilityResult{DerivedBy: ReachabilityDerivation{Rooting: RootingIsolated}}}, VulnerabilityFinding{Reachable: &ReachabilityResult{DerivedBy: ReachabilityDerivation{Rooting: RootingTargetRooted}}}},
		{"reachable routes", VulnerabilityFinding{Reachable: &ReachabilityResult{}}, VulnerabilityFinding{Reachable: &ReachabilityResult{Routes: []ReachabilityRoute{route}}}},
		{"route hop module_path", routeFinding(ReachabilityRoute{{ModulePath: "a"}}), routeFinding(ReachabilityRoute{{ModulePath: "b"}})},
		{"route hop module_version", routeFinding(ReachabilityRoute{{ModuleVersion: "v1"}}), routeFinding(ReachabilityRoute{{ModuleVersion: "v2"}})},
		{"route hop package", routeFinding(ReachabilityRoute{{Package: "a"}}), routeFinding(ReachabilityRoute{{Package: "b"}})},
		{"route hop receiver", routeFinding(ReachabilityRoute{{Receiver: "a"}}), routeFinding(ReachabilityRoute{{Receiver: "b"}})},
		{"route hop symbol", routeFinding(ReachabilityRoute{{Symbol: "a"}}), routeFinding(ReachabilityRoute{{Symbol: "b"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CompareFinding(tc.lower, tc.upper); got >= 0 {
				t.Errorf("CompareFinding did not order two findings differing only in %s: got %d, want < 0", tc.name, got)
			}
			if got := CompareFinding(tc.upper, tc.lower); got <= 0 {
				t.Errorf("CompareFinding is not antisymmetric on %s: got %d, want > 0", tc.name, got)
			}
			if got := CompareFinding(tc.lower, tc.lower); got != 0 {
				t.Errorf("CompareFinding does not report a finding equal to itself on %s: got %d", tc.name, got)
			}
		})
	}
}

// routeFinding is a finding whose only distinguishing content is one route.
func routeFinding(r ReachabilityRoute) VulnerabilityFinding {
	return VulnerabilityFinding{Reachable: &ReachabilityResult{Routes: []ReachabilityRoute{r}}}
}
