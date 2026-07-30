package vendortree_test

import (
	"os"
	"path/filepath"
	"testing"

	venlocalfs "github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	vulnvendorclosure "github.com/eitanity/kanonarion/internal/vuln/adapters/vendorclosure/vendortree"
)

// TestVendoredClosure_ReadsListedAndPresent asserts the reader answers the one
// question the vuln stage asks — which modules the vendored tree actually holds
// — and keeps a listed-but-absent module in Listed while leaving it out of
// Present. That distinction is what lets the scan tell an incomplete vendor tree
// apart from a module `go mod vendor` pruned as unimported.
func TestVendoredClosure_ReadsListedAndPresent(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module example.com/proj\n\ngo 1.21\n\nrequire (\n\texample.com/held v1.0.0\n\texample.com/absent v1.5.0\n)\n")
	write(t, dir, "vendor/example.com/held/held.go", "package held\n")
	write(t, dir, "vendor/modules.txt",
		"# example.com/held v1.0.0\n## explicit; go 1.21\nexample.com/held\n"+
			"# example.com/absent v1.5.0\n## explicit; go 1.21\nexample.com/absent\n")

	// No zip source: this asks only which modules the tree holds, never whether
	// their bytes match what was published.
	got, err := vulnvendorclosure.New(venlocalfs.New(nil)).VendoredClosure(t.Context(), filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("VendoredClosure: %v", err)
	}

	if !got.Vendored {
		t.Fatal("a project with vendor/modules.txt read as unvendored")
	}
	if got.Listed["example.com/held"] != "v1.0.0" || got.Listed["example.com/absent"] != "v1.5.0" {
		t.Errorf("Listed = %v, want both modules.txt entries with their versions", got.Listed)
	}
	if !got.Present["example.com/held"] {
		t.Error("example.com/held has files under vendor/ but read as absent")
	}
	if got.Present["example.com/absent"] {
		t.Error("example.com/absent has no files under vendor/ but read as present")
	}
}

// TestVendoredClosure_UnvendoredProjectIsNotAnError asserts that a project with
// no vendor tree is an answer rather than a failure: the vuln stage must be able
// to ask every project this question and route on the reply.
func TestVendoredClosure_UnvendoredProjectIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module example.com/proj\n\ngo 1.21\n")

	got, err := vulnvendorclosure.New(venlocalfs.New(nil)).VendoredClosure(t.Context(), filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("an unvendored project must not be an error: %v", err)
	}
	if got.Vendored {
		t.Error("a project with no vendor/modules.txt read as vendored")
	}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("creating %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %q: %v", path, err)
	}
}

// TestVendoredClosure_ReplacedModuleMapsToItsOriginalPath asserts the mapping a
// replaced dependency needs to be found at all.
//
// `go mod vendor` writes a replaced module's files under the ORIGINAL module
// path and names the replacement only on the comment line, while a resolved
// build list keys on the REPLACEMENT coordinate. The two names meet nowhere
// else, so without this mapping a fully vendored replaced dependency reads as a
// module the tree does not hold. The fixture uses the two line shapes a real
// vendored project produces: a replacement with a version, and a plain entry.
func TestVendoredClosure_ReplacedModuleMapsToItsOriginalPath(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module example.com/proj\n\ngo 1.21\n\nrequire github.com/PaesslerAG/gval v1.2.1\n\n"+
		"replace github.com/PaesslerAG/gval => github.com/cortezaproject/gval v1.2.4\n")
	write(t, dir, "vendor/github.com/PaesslerAG/gval/gval.go", "package gval\n")
	write(t, dir, "vendor/example.com/plain/plain.go", "package plain\n")
	write(t, dir, "vendor/modules.txt",
		"# github.com/PaesslerAG/gval v1.2.1 => github.com/cortezaproject/gval v1.2.4\n"+
			"## explicit; go 1.21\ngithub.com/PaesslerAG/gval\n"+
			"# example.com/plain v1.0.0\n## explicit; go 1.21\nexample.com/plain\n"+
			"# github.com/PaesslerAG/gval => github.com/cortezaproject/gval v1.2.4\n")

	got, err := vulnvendorclosure.New(venlocalfs.New(nil)).VendoredClosure(t.Context(), filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("VendoredClosure: %v", err)
	}

	if got.ReplacedBy["github.com/cortezaproject/gval"] != "github.com/PaesslerAG/gval" {
		t.Errorf("ReplacedBy = %v, want the replacement path mapped to the original it is vendored under", got.ReplacedBy)
	}
	// The replacement name is deliberately absent from the faithful reading of
	// modules.txt: the tree lists the original, and the aliasing is applied where
	// a coordinate is resolved, not folded into what the file says.
	if _, listed := got.Listed["github.com/cortezaproject/gval"]; listed {
		t.Error("the replacement path was folded into Listed; Listed must report what modules.txt says")
	}
	if !got.Present["github.com/PaesslerAG/gval"] {
		t.Error("the replaced module has files under its original path but read as absent")
	}
	// The trailing `# path => target version` footer is not a module entry: taking
	// it as one fabricates a module whose version is the literal "=>".
	if v, ok := got.Listed["github.com/PaesslerAG/gval"]; !ok || v != "v1.2.1" {
		t.Errorf("Listed[gval] = %q (present=%v), want v1.2.1 from the entry line, not the footer", v, ok)
	}
	if _, ok := got.ReplacedBy["v1.2.4"]; ok {
		t.Error("the replacement footer was mapped as though its version were a module path")
	}
}
