package domain_test

import (
	"sort"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

// expectedPermissive is the compatibility dataset's permissive tier, written
// out longhand.
//
// It is deliberately a literal rather than a filter over the dataset: a table
// derived from the thing it checks asserts nothing. Adding a licence to the
// dataset means adding it here too, which is the point — the diff then shows a
// reviewer exactly which identifier gained a "no copyleft obligations" verdict.
var expectedPermissive = []string{
	"0BSD",
	"Apache-2.0",
	"BSD-2-Clause",
	"BSD-2-Clause-Views",
	"BSD-3-Clause",
	"BSD-4-Clause",
	"BSL-1.0",
	"BlueOak-1.0.0",
	"CC0-1.0",
	"ISC",
	"MIT",
	"Python-2.0",
	"Unlicense",
	"WTFPL",
	"Zlib",
}

// TestCheckPairCompatibility_PermissiveDepsAreCompatible is the regression for
// the false review item: a permissive dependency licence must never be reported
// as an unmodelled pair against a permissive target. BSL-1.0 is the reported
// case (gonum ships a Boost-licensed component); the rest are its family.
func TestCheckPairCompatibility_PermissiveDepsAreCompatible(t *testing.T) {
	t.Parallel()
	targets := []string{"Apache-2.0", "MIT", "BSD-3-Clause"}
	for _, dep := range expectedPermissive {
		for _, target := range targets {
			t.Run(dep+"_vs_"+target, func(t *testing.T) {
				t.Parallel()
				got := domain.CheckPairCompatibility(dep, target)
				if got != domain.VerdictCompatible {
					t.Errorf("CheckPairCompatibility(%q, %q) = %v, want compatible — a permissive dependency must never raise a review item",
						dep, target, got)
				}
			})
		}
	}
}

// TestCompatibilityDataset_PermissiveTierIsKnownAndNone asserts every
// identifier in the permissive tier is in the dataset AND carries
// CopyleftNone. A new detector-visible licence added without a dataset entry
// fails here rather than surfacing as a review item in the field.
func TestCompatibilityDataset_PermissiveTierIsKnownAndNone(t *testing.T) {
	t.Parallel()
	for _, id := range expectedPermissive {
		strength, known := domain.CopyleftStrengthOf(id)
		if !known {
			t.Errorf("%s is not in the compatibility dataset", id)
			continue
		}
		if strength != domain.CopyleftNone {
			t.Errorf("%s has copyleft strength %v, want none", id, strength)
		}
	}

	// And the other direction: nothing outside the list is silently permissive.
	var actual []string
	for _, id := range domain.ModelledSPDXIDs() {
		if s, _ := domain.CopyleftStrengthOf(id); s == domain.CopyleftNone {
			actual = append(actual, id)
		}
	}
	sort.Strings(actual)
	want := append([]string(nil), expectedPermissive...)
	sort.Strings(want)
	if len(actual) != len(want) {
		t.Fatalf("permissive tier is %v, want %v", actual, want)
	}
	for i := range actual {
		if actual[i] != want[i] {
			t.Fatalf("permissive tier is %v, want %v", actual, want)
		}
	}
}

// TestCompatibilityDataset_CoversTheObligationsCatalogue sweeps the
// compatibility dataset against the obligations catalogue: a licence
// researched well enough to state its obligations must either have a copyleft
// strength or be recorded as deliberately unmodelled with a reason. Neither is
// a gap, and this is where it surfaces.
func TestCompatibilityDataset_CoversTheObligationsCatalogue(t *testing.T) {
	t.Parallel()
	for _, id := range domain.ObligationCatalogueSPDXIDs() {
		if _, known := domain.CopyleftStrengthOf(id); known {
			continue
		}
		if _, deliberate := domain.UnmodelledReason(id); deliberate {
			continue
		}
		t.Errorf("%s has obligations but no compatibility verdict and no recorded reason for having none — "+
			"add it to copyleftStrengths, or to unmodelledDeliberately with why", id)
	}
}

// TestCompatibilityDataset_CoversEveryEmbeddedLicenceText sweeps the same way
// over the identifiers kanonarion ships verbatim licence text for. Shipping a
// licence's text is a statement that the tool knows the licence.
func TestCompatibilityDataset_CoversEveryEmbeddedLicenceText(t *testing.T) {
	t.Parallel()
	for _, id := range domain.KnownSPDXTextIDs() {
		if _, known := domain.CopyleftStrengthOf(id); known {
			continue
		}
		if _, deliberate := domain.UnmodelledReason(id); deliberate {
			continue
		}
		t.Errorf("verbatim licence text is shipped for %s but the compatibility dataset neither models it nor records why not", id)
	}
}

// TestUnmodelledReason_DecisionVersusGap asserts the two are distinguishable.
// CC-BY-SA-4.0 is unmodelled on purpose — it must stay unmodelled, and must
// carry a reason.
func TestUnmodelledReason_DecisionVersusGap(t *testing.T) {
	t.Parallel()
	if _, known := domain.CopyleftStrengthOf("CC-BY-SA-4.0"); known {
		t.Error("CC-BY-SA-4.0 must remain unmodelled: a share-alike content licence is a legal question, not a dataset entry")
	}
	reason, deliberate := domain.UnmodelledReason("CC-BY-SA-4.0")
	if !deliberate {
		t.Fatal("CC-BY-SA-4.0 must be recorded as deliberately unmodelled so the result reads as a decision")
	}
	if reason == "" {
		t.Error("a deliberate exclusion with no reason is indistinguishable from a gap")
	}

	if _, deliberate := domain.UnmodelledReason("Definitely-Not-A-Licence-1.0"); deliberate {
		t.Error("an identifier nobody has ruled on must not report as a decision")
	}
	for _, id := range domain.DeliberatelyUnmodelledSPDXIDs() {
		if _, known := domain.CopyleftStrengthOf(id); known {
			t.Errorf("%s is both modelled and recorded as deliberately unmodelled — the dataset contradicts itself", id)
		}
	}
}

// TestCheckClosureCompatibility_CoverageHolesCountedOncePerIdentifier is the
// second half of the false-review-item fix: one identifier the dataset has
// never been taught is ONE gap, however many modules carry it. Reading it off
// the per-module rows makes a single gap look like N legal questions.
func TestCheckClosureCompatibility_CoverageHolesCountedOncePerIdentifier(t *testing.T) {
	t.Parallel()
	modules := []domain.CompatibilityInput{
		{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", SPDX: "CC-BY-SA-4.0"},
		{ModulePath: "example.com/b", ModuleVersion: "v1.0.0", SPDX: "CC-BY-SA-4.0"},
		{ModulePath: "example.com/c", ModuleVersion: "v1.0.0", SPDX: "CC-BY-SA-4.0"},
		{ModulePath: "example.com/d", ModuleVersion: "v1.0.0", SPDX: "Totally-Unknown-1.0"},
		{ModulePath: "example.com/e", ModuleVersion: "v1.0.0", SPDX: "MIT"},
		// No licence record at all: a missing measurement, not a dataset gap.
		{ModulePath: "example.com/f", ModuleVersion: "v1.0.0", SPDX: ""},
	}
	report := domain.CheckClosureCompatibility(modules, "Apache-2.0")

	if len(report.Conflicts) != 5 {
		t.Fatalf("want 5 per-module review items, got %d: %+v", len(report.Conflicts), report.Conflicts)
	}
	if len(report.CoverageHoles) != 2 {
		t.Fatalf("want 2 coverage holes, got %d: %+v", len(report.CoverageHoles), report.CoverageHoles)
	}
	cc := report.CoverageHoles[0]
	if cc.SPDX != "CC-BY-SA-4.0" || cc.Modules != 3 {
		t.Errorf("want CC-BY-SA-4.0 on 3 modules, got %+v", cc)
	}
	if !cc.Deliberate || cc.Reason == "" {
		t.Errorf("CC-BY-SA-4.0 is unmodelled by decision and must say so: %+v", cc)
	}
	unknown := report.CoverageHoles[1]
	if unknown.SPDX != "Totally-Unknown-1.0" || unknown.Modules != 1 {
		t.Errorf("want Totally-Unknown-1.0 on 1 module, got %+v", unknown)
	}
	if unknown.Deliberate {
		t.Errorf("an unresearched identifier must report as a gap, not a decision: %+v", unknown)
	}
	if !report.TargetModelled {
		t.Error("Apache-2.0 is in the dataset; the target must report as modelled")
	}
}

// TestCheckClosureCompatibility_UnmodelledTargetIsNamedAsSuch: when the TARGET
// is the unmodelled identifier every row below follows from that one fact.
func TestCheckClosureCompatibility_UnmodelledTargetIsNamedAsSuch(t *testing.T) {
	t.Parallel()
	report := domain.CheckClosureCompatibility([]domain.CompatibilityInput{
		{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", SPDX: "MIT"},
	}, "Totally-Unknown-1.0")
	if report.TargetModelled {
		t.Error("an unmodelled target must report as unmodelled")
	}
	if len(report.CoverageHoles) != 0 {
		t.Errorf("MIT is modelled; the closure has no dep-side coverage hole: %+v", report.CoverageHoles)
	}
}

// TestIsTestCorpusPath covers the segment-exact rule the compatibility
// consumer applies: "testdata" at any depth is a corpus, a longer name that
// merely starts with it is not.
func TestIsTestCorpusPath(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]bool{
		"testdata":                           true,
		"graph/formats/sigmajs/testdata":     true,
		"a/testdata/b":                       true,
		"vendor/testdataloader":              false,
		"vendor/github.com/google/snappy":    false,
		"THIRD_PARTY_LICENSES":               false,
		"internal/mytestdata":                false,
		"testdata-fixtures":                  false,
		"graph/formats/cytoscapejs/testdata": true,
	} {
		if got := domain.IsTestCorpusPath(path); got != want {
			t.Errorf("IsTestCorpusPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestLicenceOrigin_String pins the wire names: they are read by JSON
// consumers, so a rename is a breaking change and must show up in a diff here.
func TestLicenceOrigin_String(t *testing.T) {
	t.Parallel()
	if got := domain.OriginModuleRoot.String(); got != "module_root" {
		t.Errorf("OriginModuleRoot = %q, want module_root", got)
	}
	if got := domain.OriginBundledComponent.String(); got != "bundled_component" {
		t.Errorf("OriginBundledComponent = %q, want bundled_component", got)
	}
	// The zero value is the module root: an entry carrying no component
	// attribution reports the module's own licence, never "unknown".
	var zero domain.LicenceOrigin
	if zero.String() != "module_root" {
		t.Errorf("zero LicenceOrigin = %q, want module_root", zero.String())
	}
}
