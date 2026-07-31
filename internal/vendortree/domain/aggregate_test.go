package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

func base() domain.ParseResult {
	return domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		VendorDir:         "vendor",
		ModulesTxt: []domain.VendoredModule{
			{Path: "example.com/dep", Version: "v1.2.0", Explicit: true},
		},
		GoModRequires: map[string]string{"example.com/dep": "v1.2.0"},
		GoSum:         map[string]string{"example.com/dep@v1.2.0": "h1:EXPECTED"},
		PresentDirs:   map[string]bool{"example.com/dep": true},
		Files: map[string]domain.ModuleFiles{
			"example.com/dep": {
				ZipHeld: true,
				// The published module carries a go.mod, a README and
				// test files that `go mod vendor` strips, plus a package
				// the build never imports.
				Zip: map[string]string{
					"go.mod":          "sha256:gomod",
					"README.md":       "sha256:readme",
					"dep.go":          "sha256:dep",
					"dep_test.go":     "sha256:deptest",
					"unused/other.go": "sha256:other",
					"LICENSE":         "sha256:licence",
				},
				// The vendored tree holds the pruned subset, byte-identical.
				Vendored: map[string]string{
					"dep.go":  "sha256:dep",
					"LICENSE": "sha256:licence",
				},
			},
		},
	}
}

func kinds(fs []domain.Finding) map[domain.FindingKind]domain.Finding {
	m := map[domain.FindingKind]domain.Finding{}
	for _, f := range fs {
		m[f.Kind] = f
	}
	return m
}

// TestAggregate_Clean: vendor matches the go.sum checksum and modules.txt
// agrees with go.mod — zero findings, confident clean.
func TestAggregate_Clean(t *testing.T) {
	mods, fs := domain.Aggregate(base())
	if len(fs) != 0 {
		t.Fatalf("want clean, got findings %+v", fs)
	}
	if domain.OverallStatus(fs) != "clean" {
		t.Errorf("status = %q, want clean", domain.OverallStatus(fs))
	}
	if mods[0].Dir != "vendor/example.com/dep" {
		t.Errorf("reachability dir = %q", mods[0].Dir)
	}
}

// TestAggregate_PrunedTreeIsNotDrift is the first of three fixtures that
// together fix the distinction the whole-tree hash could not make. Here the
// vendored tree is intact but pruned: it holds a strict subset of the published
// module, byte for byte. Pruning is what `go mod vendor` does to every module,
// so this fixture stands for the ordinary case, and it must be clean.
func TestAggregate_PrunedTreeIsNotDrift(t *testing.T) {
	in := base()
	_, fs := domain.Aggregate(in)
	if len(fs) != 0 {
		t.Fatalf("a pruned but intact vendored tree must report nothing, got %+v", fs)
	}
}

// TestAggregate_EditedFileIsDrift is the second fixture: a file vendor/ and the
// published module both hold, with different bytes. This is the axis the check
// exists for, and correcting the comparison must not cost it.
func TestAggregate_EditedFileIsDrift(t *testing.T) {
	in := base()
	in.Files["example.com/dep"].Vendored["dep.go"] = "sha256:edited"

	_, fs := domain.Aggregate(in)
	d, ok := kinds(fs)[domain.FindingDrift]
	if !ok {
		t.Fatalf("an edited vendored file must be drift, got %+v", fs)
	}
	if d.File != "dep.go" {
		t.Errorf("drift finding names file %q, want dep.go", d.File)
	}
	if d.Expected != "sha256:dep" || d.Actual != "sha256:edited" {
		t.Errorf("drift must report the published and vendored digests: %+v", d)
	}
	if d.Kind.PolicyCategory() != "drift" {
		t.Errorf("drift maps to %q, want drift", d.Kind.PolicyCategory())
	}
}

// TestAggregate_FileTheModuleNeverPublishedIsDrift is the third fixture: a file
// under vendor/ that the published module has no entry for at all. It is an
// insertion into the tree the project compiles, so it is drift — and it is the
// case the pruning exemption must not swallow, since "in one side and not the
// other" describes both it and ordinary pruning.
func TestAggregate_FileTheModuleNeverPublishedIsDrift(t *testing.T) {
	in := base()
	in.Files["example.com/dep"].Vendored["backdoor.go"] = "sha256:inserted"

	_, fs := domain.Aggregate(in)
	d, ok := kinds(fs)[domain.FindingDrift]
	if !ok {
		t.Fatalf("a vendored file the module never published must be drift, got %+v", fs)
	}
	if d.File != "backdoor.go" {
		t.Errorf("drift finding names file %q, want backdoor.go", d.File)
	}
	if d.Expected != "" || d.Actual != "sha256:inserted" {
		t.Errorf("an unpublished file has no expected digest to report: %+v", d)
	}
}

// TestAggregate_IrregularFileIsDrift: a vendored entry that is not a regular
// file carries the irregular marker instead of a digest. Whatever it resolves
// to was not measured, and the published module holds only regular files, so it
// must be drift even when the zip publishes a file of the same name.
func TestAggregate_IrregularFileIsDrift(t *testing.T) {
	in := base()
	in.Files["example.com/dep"].Vendored["dep.go"] = domain.DigestIrregularPrefix + "symlink"

	_, fs := domain.Aggregate(in)
	d, ok := kinds(fs)[domain.FindingDrift]
	if !ok {
		t.Fatalf("a non-regular vendored file must be drift, got %+v", fs)
	}
	if d.File != "dep.go" {
		t.Errorf("drift finding names file %q, want dep.go", d.File)
	}
	if d.Actual != domain.DigestIrregularPrefix+"symlink" {
		t.Errorf("drift must report what the entry is: %+v", d)
	}
}

// TestAggregate_UnheldZipIsUnverifiedNotClean: go.sum names a checksum but
// kanonarion holds no zip to compare against. There is no oracle, so there is
// no clean answer to give.
func TestAggregate_UnheldZipIsUnverifiedNotClean(t *testing.T) {
	in := base()
	in.Files["example.com/dep"] = domain.ModuleFiles{
		Vendored: map[string]string{"dep.go": "sha256:dep"},
	}
	_, fs := domain.Aggregate(in)
	u, ok := kinds(fs)[domain.FindingUnverified]
	if !ok {
		t.Fatalf("want unverified finding, got %+v", fs)
	}
	if u.Expected != "h1:EXPECTED" {
		t.Errorf("the unverified finding must name the checksum it could not check against: %+v", u)
	}
	if domain.OverallStatus(fs) == "clean" {
		t.Error("an absent oracle must not be reported clean")
	}
}

// TestAggregate_MissingFromVendor: modules.txt references a module absent
// from vendor/ → inconsistency reported (case 3).
func TestAggregate_MissingFromVendor(t *testing.T) {
	in := base()
	in.PresentDirs = map[string]bool{}
	_, fs := domain.Aggregate(in)
	f, ok := kinds(fs)[domain.FindingMissingFromVendor]
	if !ok {
		t.Fatalf("want missing-from-vendor, got %+v", fs)
	}
	if f.Kind.PolicyCategory() != "inconsistency" {
		t.Errorf("maps to %q, want inconsistency", f.Kind.PolicyCategory())
	}
}

// TestAggregate_Unverified: a vendored module with no go.sum entry is
// surfaced as uncertainty, never silently clean.
func TestAggregate_Unverified(t *testing.T) {
	in := base()
	in.GoSum = map[string]string{}
	_, fs := domain.Aggregate(in)
	if _, ok := kinds(fs)[domain.FindingUnverified]; !ok {
		t.Fatalf("want unverified finding, got %+v", fs)
	}
	if domain.OverallStatus(fs) == "clean" {
		t.Error("missing checksum must not be reported clean")
	}
}

// TestAggregate_VersionAndModulesTxtDisagree: go.mod and vendor disagree on
// both presence and version (case 4: both views reported).
func TestAggregate_VersionAndModulesTxtDisagree(t *testing.T) {
	in := base()
	in.GoModRequires = map[string]string{
		"example.com/dep":   "v1.3.0", // version mismatch vs modules.txt v1.2.0
		"example.com/other": "v0.1.0", // required but not vendored/listed
	}
	_, fs := domain.Aggregate(in)
	k := kinds(fs)
	if vm, ok := k[domain.FindingVersionMismatch]; !ok || vm.Expected != "v1.3.0" || vm.Actual != "v1.2.0" {
		t.Errorf("version mismatch not reported with both views: %+v", fs)
	}
	if _, ok := k[domain.FindingMissingFromModulesTxt]; !ok {
		t.Errorf("go.mod require missing from modules.txt not reported: %+v", fs)
	}
}

// TestSortDeterministic guards stable ordering for the content hash.
func TestSortDeterministic(t *testing.T) {
	ms := []domain.VendoredModule{{Path: "b"}, {Path: "a"}}
	fs := []domain.Finding{{Module: "b", Kind: domain.FindingDrift}, {Module: "a", Kind: domain.FindingUnverified}}
	domain.SortModules(ms)
	domain.SortFindings(fs)
	h1 := domain.Hash(ms, fs)

	ms2 := []domain.VendoredModule{{Path: "a"}, {Path: "b"}}
	fs2 := []domain.Finding{{Module: "a", Kind: domain.FindingUnverified}, {Module: "b", Kind: domain.FindingDrift}}
	domain.SortModules(ms2)
	domain.SortFindings(fs2)
	if domain.Hash(ms2, fs2) != h1 {
		t.Error("hash not permutation-invariant after sort")
	}
}
