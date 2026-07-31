package localfs_test

import (
	"archive/zip"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"

	blobstorefs "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	zipsource "github.com/eitanity/kanonarion/internal/vendortree/adapters/zipsource/blobstore"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
	"github.com/eitanity/kanonarion/internal/vendortree/ports"
	"golang.org/x/mod/sumdb/dirhash"
)

const (
	depPath    = "example.com/dep"
	depVersion = "v1.2.0"
)

// published is the complete module example.com/dep@v1.2.0 as it ships: the
// package the project imports, a licence, plus the go.mod, the readme, the test
// file and a second package that `go mod vendor` strips. The gap between this
// and what a vendored tree holds is the whole point of the fixtures below.
var published = map[string]string{
	"go.mod":          "module example.com/dep\n\ngo 1.23\n",
	"README.md":       "# dep\n",
	"LICENSE":         "MIT\n",
	"dep.go":          "package dep\n\nconst Version = \"v1.2.0\"\n",
	"dep_test.go":     "package dep\n",
	"unused/other.go": "package unused\n",
}

// pruned is what `go mod vendor` leaves behind: the imported package and the
// licence, byte-identical to what the module publishes.
var pruned = map[string]string{
	"LICENSE": published["LICENSE"],
	"dep.go":  published["dep.go"],
}

// project writes a vendored project whose vendor/example.com/dep holds exactly
// vendored, and whose go.sum carries the checksum of the zip the blob store is
// seeded with. It returns the go.mod path and a scanner wired to that store.
func project(t *testing.T, vendored map[string]string) (string, ports.VendorScanner) {
	t.Helper()
	root := t.TempDir()

	h1 := seedZip(t, filepath.Join(root, "store"))
	write(t, filepath.Join(root, "go.mod"), "module example.com/proj\n\ngo 1.23\n\nrequire "+depPath+" "+depVersion+"\n")
	write(t, filepath.Join(root, "go.sum"),
		depPath+" "+depVersion+" "+h1+"\n"+
			depPath+" "+depVersion+"/go.mod h1:abcdefghijklmnopqrstuvwxyzABCDEF0123456789+/=\n")
	write(t, filepath.Join(root, "vendor", "modules.txt"), "# "+depPath+" "+depVersion+"\n## explicit\n"+depPath+"\n")
	for name, body := range vendored {
		write(t, filepath.Join(root, "vendor", filepath.FromSlash(depPath), filepath.FromSlash(name)), body)
	}

	blobs := blobstorefs.New(filepath.Join(root, "store"))
	return filepath.Join(root, "go.mod"), localfs.New(zipsource.New(blobs))
}

// seedZip builds the published module zip, puts it in a blob store rooted at
// storeRoot under its own h1, and returns that h1 for go.sum.
func seedZip(t *testing.T, storeRoot string) string {
	t.Helper()
	zipPath := filepath.Join(t.TempDir(), "module.zip")

	f, err := os.Create(zipPath) //nolint:gosec // a test-owned temp path
	if err != nil {
		t.Fatalf("creating module zip: %v", err)
	}
	w := zip.NewWriter(f)
	for name, body := range published {
		e, werr := w.Create(depPath + "@" + depVersion + "/" + name)
		if werr != nil {
			t.Fatalf("adding %s to the module zip: %v", name, werr)
		}
		if _, werr := e.Write([]byte(body)); werr != nil {
			t.Fatalf("writing %s to the module zip: %v", name, werr)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing the module zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the module zip file: %v", err)
	}

	h1, err := dirhash.HashZip(zipPath, dirhash.Hash1)
	if err != nil {
		t.Fatalf("hashing the module zip: %v", err)
	}
	hash, err := fetchdomain.ParseModuleHash(h1)
	if err != nil {
		t.Fatalf("parsing the module zip hash: %v", err)
	}
	identity, err := fetchports.NewBlobIdentity(fetchports.BlobKindZip, hash)
	if err != nil {
		t.Fatalf("addressing the module zip: %v", err)
	}
	src, err := os.Open(zipPath) //nolint:gosec // a test-owned temp path
	if err != nil {
		t.Fatalf("reopening the module zip: %v", err)
	}
	defer func() { _ = src.Close() }()
	if err := blobstorefs.New(storeRoot).Put(t.Context(), identity, src); err != nil {
		t.Fatalf("storing the module zip: %v", err)
	}
	return h1
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func findingsFor(t *testing.T, vendored map[string]string) []domain.Finding {
	t.Helper()
	goMod, scanner := project(t, vendored)
	res, err := scanner.ScanProject(t.Context(), goMod, true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if !res.VendorOnly {
		t.Error("vendor-only flag not recorded")
	}
	_, findings := domain.Aggregate(res)
	return findings
}

func with(base map[string]string, name, body string) map[string]string {
	out := make(map[string]string, len(base)+1)
	maps.Copy(out, base)
	out[name] = body
	return out
}

// TestScan_PrunedTreeIsClean is fixture one of three. `go mod vendor` prunes
// every module to the packages the build imports and strips its test files and
// go.mod, so a vendored tree holding a strict subset of the published module is
// the ordinary, intact case — and must report nothing.
//
// It is the case the previous whole-tree hash comparison could never pass: that
// comparison hashed the pruned directory and required it to equal go.sum's h1
// over the complete zip, which is structurally impossible for a pruned tree.
func TestScan_PrunedTreeIsClean(t *testing.T) {
	if findings := findingsFor(t, pruned); len(findings) != 0 {
		t.Fatalf("a pruned but intact vendored tree must be clean, got %+v", findings)
	}
}

// TestScan_EditedFileIsDrift is fixture two: a file the module publishes,
// vendored with different bytes. Correcting the comparison must not cost this
// axis — an edited vendored file is what it exists to catch.
func TestScan_EditedFileIsDrift(t *testing.T) {
	edited := published["dep.go"] + "\nfunc backdoor() string { return \"tampered\" }\n"
	findings := findingsFor(t, with(pruned, "dep.go", edited))

	drift := only(t, findings, domain.FindingDrift)
	if drift.File != "dep.go" {
		t.Errorf("drift names file %q, want dep.go", drift.File)
	}
	if drift.Expected == "" || drift.Actual == "" || drift.Expected == drift.Actual {
		t.Errorf("drift must report the published and vendored digests: %+v", drift)
	}
}

// TestScan_FileAbsentFromTheZipIsDrift is fixture three: a file under vendor/
// that the published module has no entry for. It is an insertion into the tree
// the project compiles, and it is the case the pruning exemption must not
// swallow — "present on one side only" describes both it and ordinary pruning,
// and only the direction tells them apart.
func TestScan_FileAbsentFromTheZipIsDrift(t *testing.T) {
	findings := findingsFor(t, with(pruned, "injected.go", "package dep\n"))

	drift := only(t, findings, domain.FindingDrift)
	if drift.File != "injected.go" {
		t.Errorf("drift names file %q, want injected.go", drift.File)
	}
	if drift.Expected != "" {
		t.Errorf("a file the module never published has no expected digest: %+v", drift)
	}
}

// only returns the single finding of the given kind, failing if there is not
// exactly one. The count matters as much as the kind: the defect being fixed
// was an axis that fired on modules it had nothing to say about.
func only(t *testing.T, fs []domain.Finding, kind domain.FindingKind) domain.Finding {
	t.Helper()
	var found []domain.Finding
	for _, f := range fs {
		if f.Kind == kind {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s finding, got %d of them in %+v", kind, len(found), fs)
	}
	return found[0]
}

// TestScan_SymlinkedFileIsDrift: a vendored file replaced by a symlink is a
// substitution, not a file — the build resolves it to bytes outside the tree
// this scan measured. The previous whole-tree hash read through symlinks; the
// per-file comparison must not do worse by skipping them silently.
func TestScan_SymlinkedFileIsDrift(t *testing.T) {
	goMod, scanner := project(t, pruned)
	root := filepath.Dir(goMod)
	target := filepath.Join(root, "elsewhere.go")
	write(t, target, published["dep.go"])
	linked := filepath.Join(root, "vendor", filepath.FromSlash(depPath), "dep.go")
	if err := os.Remove(linked); err != nil {
		t.Fatalf("removing the vendored file: %v", err)
	}
	if err := os.Symlink(target, linked); err != nil {
		t.Fatalf("symlinking the vendored file: %v", err)
	}

	res, err := scanner.ScanProject(t.Context(), goMod, true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	_, findings := domain.Aggregate(res)
	drift := only(t, findings, domain.FindingDrift)
	if drift.File != "dep.go" {
		t.Errorf("drift names file %q, want dep.go", drift.File)
	}
	if drift.Actual != domain.DigestIrregularPrefix+"symlink" {
		t.Errorf("drift must name the entry a symlink even when its target's bytes match: %+v", drift)
	}
}

// TestScan_UnheldZipIsUnverified: go.sum names a checksum but kanonarion holds
// no zip to compare the tree against. There is no oracle, so there is no clean
// answer — the module is reported as uncertain, never as verified.
func TestScan_UnheldZipIsUnverified(t *testing.T) {
	goMod, _ := project(t, pruned)
	scanner := localfs.New(zipsource.New(blobstorefs.New(t.TempDir())))

	res, err := scanner.ScanProject(t.Context(), goMod, true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	_, findings := domain.Aggregate(res)
	if u := only(t, findings, domain.FindingUnverified); u.Expected == "" {
		t.Errorf("the unverified finding must name the checksum it could not check against: %+v", u)
	}
}

// TestScan_NestedModuleFilesBelongToTheNestedModule: module paths nest, so
// vendor/example.com/dep/v2 is a separate module living inside dep's directory.
// Its files must not be attributed to dep, which never published them and would
// otherwise report every one of them as drift.
func TestScan_NestedModuleFilesBelongToTheNestedModule(t *testing.T) {
	goMod, scanner := project(t, with(pruned, "v2/dep.go", "package dep\n"))
	write(t, filepath.Join(filepath.Dir(goMod), "vendor", "modules.txt"),
		"# "+depPath+" "+depVersion+"\n## explicit\n"+depPath+"\n"+
			"# "+depPath+"/v2 v2.0.0\n## explicit\n"+depPath+"/v2\n")

	res, err := scanner.ScanProject(t.Context(), goMod, true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if _, ok := res.Files[depPath].Vendored["v2/dep.go"]; ok {
		t.Error("the nested module's file was attributed to its parent")
	}
	_, findings := domain.Aggregate(res)
	for _, f := range findings {
		if f.Kind == domain.FindingDrift {
			t.Errorf("a separately vendored nested module must not read as drift in its parent: %+v", f)
		}
	}
}

// TestScan_ReplacementFooterIsNotAModuleEntry: go mod vendor appends trailing
// `# path => target version` lines restating the go.mod replace directives that
// carry no left-side version. They are not module entries — the replaced module
// already has its own `# path version => …` line — and taking one as an entry
// fabricates a module whose version is the literal "=>", which then reports
// bogus unverified and version-mismatch findings.
func TestScan_ReplacementFooterIsNotAModuleEntry(t *testing.T) {
	goMod, scanner := project(t, pruned)
	write(t, filepath.Join(filepath.Dir(goMod), "vendor", "modules.txt"),
		"# "+depPath+" "+depVersion+" => example.com/fork "+depVersion+"\n## explicit\n"+depPath+"\n"+
			"# "+depPath+" => example.com/fork "+depVersion+"\n")

	res, err := scanner.ScanProject(t.Context(), goMod, true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if len(res.ModulesTxt) != 1 {
		t.Fatalf("want one module entry, got %+v", res.ModulesTxt)
	}
	if got := res.ModulesTxt[0]; got.Path != depPath || got.Version != depVersion {
		t.Errorf("module entry = %+v, want %s %s", got, depPath, depVersion)
	}
}

// TestScan_MissingModule: modules.txt references a module with no files under
// vendor/ → missing-from-vendor inconsistency.
func TestScan_MissingModule(t *testing.T) {
	const corpus = "../../../../../test/fixtures/supplychain/vendor"
	scanner := localfs.New(zipsource.New(blobstorefs.New(t.TempDir())))
	res, err := scanner.ScanProject(t.Context(), filepath.Join(corpus, "missing-module", "go.mod"), true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	_, findings := domain.Aggregate(res)
	found := false
	for _, f := range findings {
		if f.Kind == domain.FindingMissingFromVendor && f.Module == depPath {
			found = true
		}
	}
	if !found {
		t.Fatalf("want missing-from-vendor for %s, got %+v", depPath, findings)
	}
}

// TestScan_NotVendored: a project with no vendor/modules.txt yields the
// distinct ErrNotVendored sentinel, not a misleading empty-clean result.
func TestScan_NotVendored(t *testing.T) {
	scanner := localfs.New(zipsource.New(blobstorefs.New(t.TempDir())))
	_, err := scanner.ScanProject(t.Context(),
		filepath.Join("../../../../../test/fixtures/supplychain/godebug/clean", "go.mod"), false)
	if !errors.Is(err, ports.ErrNotVendored) {
		t.Fatalf("want ErrNotVendored, got %v", err)
	}
}
