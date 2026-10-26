package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	exapp "code.eitanity.com/kanonarion/internal/example/application"
	exports "code.eitanity.com/kanonarion/internal/example/ports"
	ifaceapp "code.eitanity.com/kanonarion/internal/iface/application"
	ifacedomain "code.eitanity.com/kanonarion/internal/iface/domain"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
	licapp "code.eitanity.com/kanonarion/internal/license/application"
	licdomain "code.eitanity.com/kanonarion/internal/license/domain"
	licports "code.eitanity.com/kanonarion/internal/license/ports"
	nativedomain "code.eitanity.com/kanonarion/internal/native/domain"
	nativeports "code.eitanity.com/kanonarion/internal/native/ports"
)

// A listing's zero census used to be taken under the same served-generation
// filter as the page, so a store holding only superseded records said it held
// none. Each of the five generation-aware listings is driven over the same five
// stores here.

// genRow is one record a fixture store holds: a module path and the generation
// it was produced at. old marks it superseded; the driver supplies the version.
type genRow struct {
	path string
	old  bool
}

// generationListing drives one listing over a fixture store.
type generationListing struct {
	name, subject, served string
	// filter is a value for the listing's filter that matches the rows whose
	// path is "example.com/match", empty for a listing that takes none.
	filter string
	run    func(t *testing.T, rows []genRow, filtered bool, offset int, asJSON bool) string
}

const (
	oldGenA = "0.0.1-old"
	oldGenB = "0.0.2-old"
)

func oldGen(i int) string {
	if i%2 == 0 {
		return oldGenA
	}
	return oldGenB
}

func generationListings() []generationListing {
	return []generationListing{
		interfaceGenListing(),
		examplesGenListing(),
		callGraphGenListing(),
		licenseGenListing(),
		nativeGenListing(),
	}
}

func interfaceGenListing() generationListing {
	ctx := context.Background()
	return generationListing{
		name: "interface-list", subject: "interface record", served: ifaceapp.PipelineVersion,
		run: func(t *testing.T, rows []genRow, _ bool, offset int, asJSON bool) string {
			t.Helper()
			uc := testfakes.NewFakeQueryInterface()
			var sums []ifaceports.InterfaceSummary
			for i, r := range rows {
				v := ifaceapp.PipelineVersion
				if r.old {
					v = oldGen(i)
				}
				sums = append(sums, ifaceports.InterfaceSummary{ModulePath: r.path, ModuleVersion: "v1.0.0",
					PipelineVersion: v, OverallStatus: ifacedomain.InterfaceStatusExtracted})
			}
			uc.SetList(sums)
			withJSON(t, asJSON)
			var out bytes.Buffer
			if err := interfaceListWith(ctx, 50, offset, false, uc, &out, io.Discard); err != nil {
				t.Fatalf("interface-list: %v", err)
			}
			return out.String()
		},
	}
}

func examplesGenListing() generationListing {
	ctx := context.Background()
	return generationListing{
		name: "examples-list", subject: "example record", served: exapp.PipelineVersion,
		run: func(t *testing.T, rows []genRow, _ bool, offset int, asJSON bool) string {
			t.Helper()
			uc := testfakes.NewFakeQueryExamples()
			var sums []exports.ExampleSummary
			for i, r := range rows {
				v := exapp.PipelineVersion
				if r.old {
					v = oldGen(i)
				}
				sums = append(sums, exports.ExampleSummary{ModulePath: r.path, ModuleVersion: "v1.0.0", PipelineVersion: v})
			}
			uc.SetList(sums)
			withJSON(t, asJSON)
			var out bytes.Buffer
			if err := runExamplesList(ctx, 50, offset, false, uc, &out, io.Discard); err != nil {
				t.Fatalf("examples-list: %v", err)
			}
			return out.String()
		},
	}
}

func callGraphGenListing() generationListing {
	ctx := context.Background()
	return generationListing{
		name: "callgraph-list", subject: "call graph record", served: cgapp.PipelineVersion,
		filter: "example.com/match",
		run: func(t *testing.T, rows []genRow, filtered bool, offset int, asJSON bool) string {
			t.Helper()
			uc := testfakes.NewFakeQueryCallGraph()
			var sums []cgports.CallGraphSummary
			for i, r := range rows {
				v := cgapp.PipelineVersion
				if r.old {
					v = oldGen(i)
				}
				sums = append(sums, cgports.CallGraphSummary{ModulePath: r.path, ModuleVersion: "v1.0.0", PipelineVersion: v})
			}
			uc.SetList(sums)
			filter := ""
			if filtered {
				filter = "example.com/match"
			}
			withJSON(t, asJSON)
			var out bytes.Buffer
			if err := runCallGraphList(ctx, filter, 50, offset, false, uc, &out, io.Discard); err != nil {
				t.Fatalf("callgraph-list: %v", err)
			}
			return out.String()
		},
	}
}

func licenseGenListing() generationListing {
	ctx := context.Background()
	return generationListing{
		name: "license-list", subject: "license record", served: licapp.PipelineVersion,
		filter: "Apache-2.0",
		run: func(t *testing.T, rows []genRow, filtered bool, offset int, asJSON bool) string {
			t.Helper()
			uc := testfakes.NewFakeQueryLicense()
			var sums []licports.LicenseSummary
			for i, r := range rows {
				v := licapp.PipelineVersion
				if r.old {
					v = oldGen(i)
				}
				spdx := "MIT"
				if r.path == "example.com/match" {
					spdx = "Apache-2.0"
				}
				sums = append(sums, licports.LicenseSummary{ModulePath: r.path, ModuleVersion: "v1.0.0",
					PipelineVersion: v, PrimarySPDX: spdx, OverallStatus: licdomain.LicenseStatusDetected})
			}
			uc.SetList(sums)
			f := licenseListFlags{limit: 50, offset: offset}
			if filtered {
				f.spdx = "Apache-2.0"
			}
			withJSON(t, asJSON)
			var out bytes.Buffer
			if err := runLicenseList(ctx, f, nil, uc, licdomain.NewLicenseOverrideSet(nil), &out, io.Discard); err != nil {
				t.Fatalf("license-list: %v", err)
			}
			return out.String()
		},
	}
}

func nativeGenListing() generationListing {
	ctx := context.Background()
	return generationListing{
		name: "native-list", subject: "native record", served: nativedomain.PipelineFingerprint(),
		filter: string(nativedomain.PresenceIdentified),
		run: func(t *testing.T, rows []genRow, filtered bool, offset int, asJSON bool) string {
			t.Helper()
			var sums []nativeports.NativeSummary
			for i, r := range rows {
				presence := nativedomain.PresenceAbsent
				if r.path == "example.com/match" {
					presence = nativedomain.PresenceIdentified
				}
				s := nativeSummaryFixture(t, r.path, presence)
				if r.old {
					s.Generation = oldGen(i)
				}
				sums = append(sums, s)
			}
			f := nativeListFlags{limit: 50, offset: offset}
			if filtered {
				f.presence = []string{string(nativedomain.PresenceIdentified)}
			}
			withJSON(t, asJSON)
			var out bytes.Buffer
			if err := nativeListWith(ctx, f, &fakeNativeLister{rows: sums}, &out, io.Discard); err != nil {
				t.Fatalf("native-list: %v", err)
			}
			return out.String()
		},
	}
}

// zeroResultOf decodes the zero_result of a listing document, nil when absent.
func zeroResultOf(t *testing.T, doc string) *listZeroJSON {
	t.Helper()
	var out struct {
		ZeroResult *listZeroJSON `json:"zero_result"`
	}
	if err := json.Unmarshal([]byte(doc), &out); err != nil {
		t.Fatalf("decoding the listing document: %v\n%s", err, doc)
	}
	return out.ZeroResult
}

func TestGenerationListings_OnlySupersededRecordsAreNotAnEmptyStore(t *testing.T) {
	rows := []genRow{{"example.com/a", true}, {"example.com/b", true}}
	for _, l := range generationListings() {
		t.Run(l.name, func(t *testing.T) {
			text := l.run(t, rows, false, 0, false)
			if strings.Contains(text, "holds no "+l.subject+" at all") {
				t.Errorf("a store holding superseded records said it holds none:\n%s", text)
			}
			wantContains(t, "the text zero", text,
				"none of the 2 "+l.subject+"(s) the store holds is at ",
				l.served+", the ",
				"(held at "+oldGenA+", "+oldGenB+")",
				"to list them: kanonarion "+l.name+" --all-generations",
				"listing "+l.subject+"s at ",
				"not shown (--all-generations)")
			z := zeroResultOf(t, l.run(t, rows, false, 0, true))
			if z == nil || z.StoreEmpty || z.Superseded == nil || *z.Superseded != 2 ||
				z.SupersededGenerations == nil || strings.Join(*z.SupersededGenerations, ",") != oldGenA+","+oldGenB {
				t.Errorf("zero_result = %+v, want store_empty false, 2 superseded at both generations", z)
			}
			if z != nil && (len(z.Remedy) != 2 || z.Remedy[0] != "kanonarion "+l.name+" --all-generations") {
				t.Errorf("remedy = %v, want the --all-generations listing then the re-derivation", z.Remedy)
			}
		})
	}
}

func TestGenerationListings_EmptyStoreIsUnchanged(t *testing.T) {
	for _, l := range generationListings() {
		t.Run(l.name, func(t *testing.T) {
			text := l.run(t, nil, false, 0, false)
			wantContains(t, "the text zero", text, "the store holds no "+l.subject+" at all", "to produce one: ")
			z := zeroResultOf(t, l.run(t, nil, false, 0, true))
			if z == nil || !z.StoreEmpty || z.Superseded == nil || *z.Superseded != 0 ||
				z.SupersededGenerations == nil || len(*z.SupersededGenerations) != 0 {
				t.Errorf("zero_result = %+v, want store_empty, 0 superseded and an empty generations array", z)
			}
		})
	}
}

func TestGenerationListings_OneServedRecordIsListed(t *testing.T) {
	rows := []genRow{{"example.com/a", false}, {"example.com/b", true}}
	for _, l := range generationListings() {
		t.Run(l.name, func(t *testing.T) {
			text := l.run(t, rows, false, 0, false)
			if !strings.Contains(text, "example.com/a") || strings.Contains(text, "example.com/b") {
				t.Errorf("the page must list the served record only:\n%s", text)
			}
			if strings.Contains(text, "none of the") || strings.Contains(text, "holds no") {
				t.Errorf("a listing that returned rows printed a zero notice:\n%s", text)
			}
			if z := zeroResultOf(t, l.run(t, rows, false, 0, true)); z != nil {
				t.Errorf("a listing that returned rows carried a zero_result: %+v", z)
			}
		})
	}
}

func TestGenerationListings_PagedPastIsUnchanged(t *testing.T) {
	rows := []genRow{{"example.com/a", false}, {"example.com/b", true}}
	for _, l := range generationListings() {
		t.Run(l.name, func(t *testing.T) {
			text := l.run(t, rows, false, 5, false)
			wantContains(t, "the text zero", text,
				"no "+l.subject+" on this page — the store holds 1 "+l.subject+"(s), and --offset 5 starts past the last one")
			if strings.Contains(text, "superseded "+l.subject) || strings.Contains(text, "none of the") {
				t.Errorf("a paging zero borrowed the superseded statement:\n%s", text)
			}
		})
	}
}

func TestGenerationListings_FilterMatchingNothingIsUnchanged(t *testing.T) {
	// A served record that does not match, and a superseded one that does not
	// either: the filter is the cause, and the superseded record is not about it.
	rows := []genRow{{"example.com/a", false}, {"example.com/b", true}}
	for _, l := range generationListings() {
		if l.filter == "" {
			continue
		}
		t.Run(l.name, func(t *testing.T) {
			text := l.run(t, rows, true, 0, false)
			wantContains(t, "the text zero", text, "no "+l.subject+" matched ", "all 1 "+l.subject+"(s) in the store")
			if strings.Contains(text, "superseded "+l.subject) || strings.Contains(text, "held only") {
				t.Errorf("a filter that matched nothing in any generation named superseded records:\n%s", text)
			}
			z := zeroResultOf(t, l.run(t, rows, true, 0, true))
			if z == nil || z.StoreEmpty || z.Superseded == nil || *z.Superseded != 0 {
				t.Errorf("zero_result = %+v, want a filter miss with nothing superseded", z)
			}
		})
	}
}

func TestGenerationListings_FilterMatchingOnlySupersededSaysSo(t *testing.T) {
	served := []genRow{{"example.com/a", false}, {"example.com/match", true}}
	onlyOld := []genRow{{"example.com/a", true}, {"example.com/match", true}}
	unmatched := []genRow{{"example.com/a", true}}
	for _, l := range generationListings() {
		if l.filter == "" {
			continue
		}
		t.Run(l.name, func(t *testing.T) {
			// Served records exist and the filter's match is superseded.
			text := l.run(t, served, true, 0, false)
			wantContains(t, "served store", text, "; 1 "+l.subject+"(s) matching it is held only at a superseded",
				"to list them: kanonarion "+l.name+" --all-generations")
			z := zeroResultOf(t, l.run(t, served, true, 0, true))
			if z == nil || z.Superseded == nil || *z.Superseded != 1 || len(z.Remedy) != 2 {
				t.Errorf("zero_result = %+v, want 1 superseded match and both remedies", z)
			}
			// Nothing is served, and the filter matches a superseded record.
			text = l.run(t, onlyOld, true, 0, false)
			wantContains(t, "superseded store", text, "none of the 1 "+l.subject+"(s) matching ")
			// Nothing is served, and the filter matches nothing in any generation.
			text = l.run(t, unmatched, true, 0, false)
			wantContains(t, "unmatched store", text, "matched ", " in any generation, and none of the 1 ")
			if strings.Contains(text, "at all") {
				t.Errorf("a store holding a superseded record was called empty:\n%s", text)
			}
		})
	}
}

// A surface with no generation contract leaves both superseded fields null.
func TestListZeroStatementJSON_NoGenerationNoSupersededFields(t *testing.T) {
	z := listZeroStatementJSON(listZeroScope{subject: "walk record", listAll: "kanonarion walk-list"})
	if z.Superseded != nil || z.SupersededGenerations != nil {
		t.Errorf("zero_result = %+v, want no superseded fields", z)
	}
}

func TestDistinctGenerations_OrdersVersionsAsVersions(t *testing.T) {
	got := strings.Join(distinctGenerations([]string{
		"0.10.0", "0.9.0", "0.9.0", "zeta", "alpha", "0.10.0+recipes.1", "0.9.0+recipes.1",
	}), ",")
	if got != "alpha,zeta,0.9.0,0.9.0+recipes.1,0.10.0,0.10.0+recipes.1" {
		t.Errorf("distinctGenerations = %s", got)
	}
}

func TestListZeroStatement_CountsSeveralSupersededMatches(t *testing.T) {
	s := listZeroScope{
		subject: "call graph record", filterName: "module path", filterValue: "m", field: "module path",
		matchKind: matchExact, considered: 3, listAll: "kanonarion callgraph-list",
		superseded: listZeroSuperseded{gen: callGraphListGeneration(false), held: []string{"0.1.0", "0.2.0"}, matched: []string{"0.2.0", "0.1.0"}},
	}
	line, remedies := listZeroStatement(s)
	if !strings.Contains(line, "2 call graph record(s) matching it are held only at a superseded pipeline version (0.1.0, 0.2.0)") || len(remedies) != 2 {
		t.Errorf("line = %q, remedies = %v", line, remedies)
	}
	if err := writeListZeroWithGeneration(failingWriter{}, s, callGraphListGeneration(false)); err == nil {
		t.Error("a failed notice write must be reported")
	}
}
