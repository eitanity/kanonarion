package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestClassifyNegativeVerdict_UnmeasuredTestScopeDowngrades is the verdict
// rule: over a module whose _test.go declarations were never analysed,
// an empty callers answer is not a measurement. Test fakes are a systematic part
// of what calls a port, so reporting RESOLVED-ABSENT would claim coverage the
// analysis did not have.
func TestClassifyNegativeVerdict_UnmeasuredTestScopeDowngrades(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope domain.TestScope
	}{
		{"not recorded", domain.TestScopeUnknown},
		{"explicitly excluded", domain.TestScopeExcluded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := domain.ClassifyNegativeVerdict(domain.NegativeVerdictInputs{
				MethodName:  "Root",
				QueriedNode: domain.CallNode{ID: "m.Root", Symbol: "Root"},
				Found:       true,
				ModuleLevel: domain.CompletenessBuiltWithBodies,
				TestScope:   tc.scope,
			})
			if v.Outcome != domain.VerdictUnresolved {
				t.Fatalf("outcome = %s, want UNRESOLVED", v.Outcome)
			}
			var found bool
			for _, s := range v.Sinks {
				if s.Kind == domain.SinkTestScopeUnmeasured {
					found = true
				}
			}
			if !found {
				t.Errorf("no test-scope sink among %v", v.Sinks)
			}
		})
	}
}

// TestClassifyNegativeVerdict_ExcludedByRequestIsNotASink separates a scope the
// caller chose from one the analysis missed. Asking for production-only results
// narrows the question; it does not make the answer unsound, so the outcome
// stays a confident absent and the narrowing is stated elsewhere.
func TestClassifyNegativeVerdict_ExcludedByRequestIsNotASink(t *testing.T) {
	v := domain.ClassifyNegativeVerdict(domain.NegativeVerdictInputs{
		MethodName:             "Root",
		QueriedNode:            domain.CallNode{ID: "m.Root", Symbol: "Root"},
		Found:                  true,
		ModuleLevel:            domain.CompletenessBuiltWithBodies,
		TestScope:              domain.TestScopeUnknown,
		ReferenceScope:         domain.ReferenceScopeAnalysed,
		TestsExcludedByRequest: true,
	})
	if v.Outcome != domain.VerdictResolvedAbsent {
		t.Fatalf("outcome = %s (%s), want RESOLVED-ABSENT", v.Outcome, v.Reason())
	}
}

// TestClassifyNegativeVerdict_TestScopeDetailIsCarried keeps the reason the
// axis went unmeasured in front of the reader: an unmeasured axis named is worth
// more than one merely flagged.
func TestClassifyNegativeVerdict_TestScopeDetailIsCarried(t *testing.T) {
	v := domain.ClassifyNegativeVerdict(domain.NegativeVerdictInputs{
		MethodName:      "Root",
		QueriedNode:     domain.CallNode{ID: "m.Root", Symbol: "Root"},
		Found:           true,
		ModuleLevel:     domain.CompletenessBuiltWithBodies,
		TestScope:       domain.TestScopeExcluded,
		TestScopeDetail: "loading the module with test files failed: boom",
	})
	if !strings.Contains(v.Reason(), "boom") {
		t.Errorf("reason %q does not carry the recorded detail", v.Reason())
	}
}

func TestParseInterfaceMethodID(t *testing.T) {
	for _, tc := range []struct {
		in        string
		wantIface string
		wantMeth  string
		wantOK    bool
	}{
		{"pkg/path.(Store).Put", "pkg/path.Store", "Put", true},
		{"example.com/m/internal/vuln/ports.(VulnerabilityStore).PutVulnerabilityRecord",
			"example.com/m/internal/vuln/ports.VulnerabilityStore", "PutVulnerabilityRecord", true},
		// A pointer receiver names a concrete method — a node — not an
		// interface method, so it must not be read as the per-method form.
		{"pkg/path.(*Store).Put", "", "", false},
		{"pkg/path.Store", "", "", false},
		{"pkg/path.Fn", "", "", false},
		{"", "", "", false},
		{"pkg/path.().Put", "", "", false},
		{"pkg/path.(Store).", "", "", false},
	} {
		gotIface, gotMeth, gotOK := domain.ParseInterfaceMethodID(tc.in)
		if gotOK != tc.wantOK || gotIface != tc.wantIface || gotMeth != tc.wantMeth {
			t.Errorf("ParseInterfaceMethodID(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, gotIface, gotMeth, gotOK, tc.wantIface, tc.wantMeth, tc.wantOK)
		}
	}
}

// TestImplementersOf_DeclaredVsUnknown pins the two-result contract: an
// interface the module does not declare is outside the measurement, and must
// not be reported the same way as a declared one with no implementers.
func TestImplementersOf_DeclaredVsUnknown(t *testing.T) {
	rec := domain.CallGraphRecord{
		Interfaces: []domain.InterfaceType{
			{ID: "m/ports.Store", Name: "Store", Package: "m/ports", Methods: []string{"Put"}},
			{ID: "m/ports.Unused", Name: "Unused", Package: "m/ports", Methods: []string{"Nope"}},
		},
		Implementations: []domain.InterfaceImplementation{
			{InterfaceID: "m/ports.Store", TypeID: "m/adapter.(*Store)"},
		},
	}

	impls, declared := domain.ImplementersOf(rec, "m/ports.Store")
	if !declared || len(impls) != 1 {
		t.Errorf("Store: declared=%v impls=%d, want true/1", declared, len(impls))
	}
	impls, declared = domain.ImplementersOf(rec, "m/ports.Unused")
	if !declared || len(impls) != 0 {
		t.Errorf("Unused: declared=%v impls=%d, want true/0", declared, len(impls))
	}
	if _, declared = domain.ImplementersOf(rec, "m/ports.NeverHeardOf"); declared {
		t.Error("an interface the module does not declare was reported as declared")
	}
}

// TestInterfaceType_MethodID keeps the addressable form the query accepts in
// step with the one the record advertises.
func TestInterfaceType_MethodID(t *testing.T) {
	it := domain.InterfaceType{ID: "m/ports.Store", Package: "m/ports", Name: "Store"}
	got := it.MethodID("Put")
	if want := "m/ports.(Store).Put"; got != want {
		t.Fatalf("MethodID = %q, want %q", got, want)
	}
	iface, method, ok := domain.ParseInterfaceMethodID(got)
	if !ok || iface != it.ID || method != "Put" {
		t.Errorf("round trip of %q gave (%q, %q, %v)", got, iface, method, ok)
	}
}
