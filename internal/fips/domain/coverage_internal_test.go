package domain

import (
	"fmt"
	"strings"
	"testing"
)

func TestClassifyFinding_EveryKind(t *testing.T) {
	for k, want := range map[FindingKind]Category{
		FindingDirectRandom: CategoryCompliant,
		FindingCgoCrypto:    CategoryUnknown,
		"unrecognised":      CategoryUnknown,
	} {
		if got := ClassifyFinding(k, false); got != want {
			t.Errorf("ClassifyFinding(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestKindRank_UnknownKindSortsLast(t *testing.T) {
	if kindRank(FindingDirectRandom) >= kindRank(FindingCgoCrypto) || kindRank("unrecognised") <= kindRank(FindingCgoCrypto) {
		t.Error("an unknown kind does not sort after every known one")
	}
}

func TestCatalogueAccessors(t *testing.T) {
	if len(NonFIPSAlgorithmPackages()) == 0 {
		t.Error("the embedded catalogue lists no non-FIPS algorithm package")
	}
	if got := PipelineFingerprint(); got != PipelineVersion+"+cat."+CatalogueVersion() {
		t.Errorf("PipelineFingerprint() = %q", got)
	}
	if RecogniseToolchain("") != "" {
		t.Error("a blank toolchain was recognised")
	}
}

func TestLoadCatalogue_RefusesEachMalformedShape(t *testing.T) {
	for name, raw := range map[string]string{
		"malformed":       "{",
		"no version":      `{"version":""}`,
		"no toolchains":   `{"version":"1"}`,
		"unnamed entry":   `{"version":"1","toolchains":[{"name":"","match_contains":"x"}]}`,
		"empty algorithm": `{"version":"1","toolchains":[{"name":"n","match_contains":"x"}],"non_fips_algorithm_packages":[""]}`,
	} {
		if _, err := loadCatalogue([]byte(raw)); err == nil {
			t.Errorf("%s: catalogue loaded", name)
		}
	}
}

func TestMustLoadCatalogue_PanicsOnABadFile(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "catalogue.json") {
			t.Errorf("a bad catalogue did not panic naming the file: %v", r)
		}
	}()
	mustLoadCatalogue([]byte("{"))
}
