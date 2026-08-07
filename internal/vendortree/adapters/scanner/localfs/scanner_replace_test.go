package localfs_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	blobstorefs "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	zipsource "github.com/eitanity/kanonarion/internal/vendortree/adapters/zipsource/blobstore"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
	"golang.org/x/mod/sumdb/dirhash"
)

// The fork the project actually builds. Its bytes differ from example.com/dep's
// in the one place that matters: the constant. A tree vendored from this fork
// and checked against upstream's zip therefore reports drift on dep.go, which is
// what makes the wrong-coordinate lookup visible rather than merely weaker.
const (
	forkPath    = "example.com/fork"
	forkVersion = "v1.4.0"
)

var forkPublished = map[string]string{
	"go.mod":      "module " + forkPath + "\n\ngo 1.23\n",
	"LICENSE":     "MIT\n",
	"dep.go":      "package dep\n\nconst Version = \"v1.4.0-fork\"\n",
	"dep_test.go": "package dep\n",
}

// forkPruned is what `go mod vendor` writes under vendor/example.com/dep for a
// module replaced by the fork: the fork's files, under the ORIGINAL module's
// directory name. That mismatch between the name and the bytes is the whole
// defect this file covers.
var forkPruned = map[string]string{
	"LICENSE": forkPublished["LICENSE"],
	"dep.go":  forkPublished["dep.go"],
}

// replaceProject writes a vendored project whose single dependency is replaced.
//
// Both zips are seeded and BOTH coordinates are in go.sum. That is deliberate:
// a project that once required upstream keeps upstream's go.sum line, so a
// verifier keying on the directory's name finds a checksum, finds a held zip,
// compares a fork's files against upstream's, and reports drift for a tree that
// is exactly what the build resolves. Seeding only the replacement would let a
// lookup that never resolved the replace pass by falling through to "no entry".
//
// replacement is the right-hand side of the `=>` clause exactly as
// vendor/modules.txt spells it, so a filesystem replace is expressed by passing
// a path with no version.
func replaceProject(t *testing.T, replacement string, vendored map[string]string) (string, *localfs.Scanner) {
	t.Helper()
	root := t.TempDir()
	store := filepath.Join(root, "store")

	upstreamH1 := seedNamedZip(t, store, depPath, depVersion, published)
	forkH1 := seedNamedZip(t, store, forkPath, forkVersion, forkPublished)

	write(t, filepath.Join(root, "go.mod"),
		"module example.com/proj\n\ngo 1.23\n\nrequire "+depPath+" "+depVersion+"\n")
	write(t, filepath.Join(root, "go.sum"),
		depPath+" "+depVersion+" "+upstreamH1+"\n"+
			forkPath+" "+forkVersion+" "+forkH1+"\n")
	write(t, filepath.Join(root, "vendor", "modules.txt"),
		"# "+depPath+" "+depVersion+" => "+replacement+"\n## explicit\n"+depPath+"\n"+
			"# "+depPath+" => "+replacement+"\n")
	for name, body := range vendored {
		write(t, filepath.Join(root, "vendor", filepath.FromSlash(depPath), filepath.FromSlash(name)), body)
	}

	return filepath.Join(root, "go.mod"), localfs.New(zipsource.New(blobstorefs.New(store)))
}

// seedNamedZip is seedZip for an arbitrary coordinate and file set, so a fixture
// can hold the two competing zips a replace puts in play at once.
func seedNamedZip(t *testing.T, storeRoot, path, version string, files map[string]string) string {
	t.Helper()
	zipPath := filepath.Join(t.TempDir(), "module.zip")

	f, err := os.Create(zipPath) //nolint:gosec // a test-owned temp path
	if err != nil {
		t.Fatalf("creating the module zip for %s@%s: %v", path, version, err)
	}
	w := zip.NewWriter(f)
	for name, body := range files {
		e, werr := w.Create(path + "@" + version + "/" + name)
		if werr != nil {
			t.Fatalf("adding %s: %v", name, werr)
		}
		if _, werr := e.Write([]byte(body)); werr != nil {
			t.Fatalf("writing %s: %v", name, werr)
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

// reconcileReplace scans and aggregates a replaced-module fixture.
func reconcileReplace(t *testing.T, replacement string, vendored map[string]string) ([]domain.VendoredModule, []domain.Finding) {
	t.Helper()
	goMod, scanner := replaceProject(t, replacement, vendored)
	res, err := scanner.ScanProject(t.Context(), goMod, true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	mods, findings, _ := domain.Aggregate(res)
	return mods, findings
}

func moduleNamed(t *testing.T, mods []domain.VendoredModule, path string) domain.VendoredModule {
	t.Helper()
	for _, m := range mods {
		if m.Path == path {
			return m
		}
	}
	t.Fatalf("no module %q in %+v", path, mods)
	return domain.VendoredModule{}
}

// TestScan_ModuleReplaceIsVerifiedAgainstTheReplacement is the failing scenario.
//
// `go mod vendor` writes the fork's source under the original module's
// directory, so the coordinate go.sum attests is the fork and the coordinate the
// directory is named for is upstream. Keying the lookup on the directory's name
// asks go.sum about bytes the tree does not hold — and the modules a project
// most needs verified, the ones whose bytes are NOT upstream's, are exactly the
// ones that go wrong.
//
// The fixture seeds upstream's zip too, so the pre-fix lookup succeeds and
// compares the fork's dep.go against upstream's: the failure is a drift finding
// for an intact tree, not merely a weaker answer.
func TestScan_ModuleReplaceIsVerifiedAgainstTheReplacement(t *testing.T) {
	mods, findings := reconcileReplace(t, forkPath+" "+forkVersion, forkPruned)

	if len(findings) != 0 {
		t.Fatalf("a tree vendored from the replacement its go.sum attests must reconcile clean, got %+v", findings)
	}

	m := moduleNamed(t, mods, depPath)
	if m.ReplacementPath != forkPath || m.ReplacementVersion != forkVersion {
		t.Errorf("module records replacement %q %q, want %q %q — the record must name both coordinates or a reader cannot see that upstream's name covers a fork's bytes",
			m.ReplacementPath, m.ReplacementVersion, forkPath, forkVersion)
	}
	if path, version, attested := m.AttestedCoordinate(); !attested || path != forkPath || version != forkVersion {
		t.Errorf("attested coordinate is (%q, %q, %t), want the replacement", path, version, attested)
	}
}

// TestScan_FilesystemReplaceStaysHonestlyUnverifiable is the zero's control.
//
// `=> ../fork` publishes no module, so no checksum for it can exist anywhere.
// The honest answer is that there is nothing to check against — which must NOT
// be reached by falling back to the original coordinate's checksum. Upstream's
// line is in this fixture's go.sum and its zip is held, so a fallback would
// report the tree clean: a fix that turned honest unverifiability into false
// confidence would pass every other test in this file.
func TestScan_FilesystemReplaceStaysHonestlyUnverifiable(t *testing.T) {
	mods, findings := reconcileReplace(t, "../fork", forkPruned)

	if len(findings) != 1 || findings[0].Kind != domain.FindingUnverified {
		t.Fatalf("a filesystem replacement must report exactly one unverified finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, "../fork") {
		t.Errorf("the finding must name the filesystem path it cannot verify: %q", findings[0].Detail)
	}

	m := moduleNamed(t, mods, depPath)
	if _, _, attested := m.AttestedCoordinate(); attested {
		t.Error("a filesystem replacement reports an attested coordinate; there is no published artefact behind it")
	}
	if m.ExpectedHash != "" {
		t.Errorf("expected hash %q borrowed from another coordinate; a filesystem replacement has none", m.ExpectedHash)
	}
	if m.FilesCompared != 0 {
		t.Errorf("files compared = %d, want 0: nothing was compared", m.FilesCompared)
	}
}

// TestScan_DriftUnderAReplacementStillStops is the other control. Resolving the
// replace must make the verifier look in the right place, not stop looking: an
// edited file under a replaced module is still drift, and the finding names the
// replacement so a reader can reproduce the comparison.
func TestScan_DriftUnderAReplacementStillStops(t *testing.T) {
	edited := make(map[string]string, len(forkPruned))
	for k, v := range forkPruned {
		edited[k] = v
	}
	edited["dep.go"] = forkPublished["dep.go"] + "\nfunc backdoor() string { return \"tampered\" }\n"

	_, findings := reconcileReplace(t, forkPath+" "+forkVersion, edited)

	if len(findings) != 1 || findings[0].Kind != domain.FindingDrift {
		t.Fatalf("an edited file under a replaced module must still be drift, got %+v", findings)
	}
	if findings[0].File != "dep.go" {
		t.Errorf("drift names file %q, want dep.go", findings[0].File)
	}
	if !strings.Contains(findings[0].Detail, forkPath) {
		t.Errorf("the drift detail must name the zip it was held against: %q", findings[0].Detail)
	}
}

// TestScan_FilesComparedIsTheSizeOfTheMeasurement is the second ticket's
// failing scenario: a record that reports "clean" without saying how much it
// looked at is a claim with no size, and cannot be argued with. The count is
// checked against an independent walk of the vendored directory, not against the
// value the scanner happened to produce.
func TestScan_FilesComparedIsTheSizeOfTheMeasurement(t *testing.T) {
	goMod, scanner := replaceProject(t, forkPath+" "+forkVersion, forkPruned)
	res, err := scanner.ScanProject(t.Context(), goMod, true)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	mods, findings, _ := domain.Aggregate(res)
	if len(findings) != 0 {
		t.Fatalf("fixture must reconcile clean, got %+v", findings)
	}

	want := countFiles(t, filepath.Join(filepath.Dir(goMod), "vendor", filepath.FromSlash(depPath)))
	if got := moduleNamed(t, mods, depPath).FilesCompared; got != want {
		t.Errorf("files compared = %d, want %d — every file the tree holds for the module is compared, and the count is the measurement's own size", got, want)
	}
}

// countFiles counts the regular files under dir, independently of anything the
// scanner recorded.
func countFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	if err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	}); err != nil {
		t.Fatalf("counting files under %s: %v", dir, err)
	}
	return n
}
