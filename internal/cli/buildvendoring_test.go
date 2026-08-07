package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vendoredProject writes a project tree with a go.mod and, when vendored, a
// vendor/modules.txt beside it — which is exactly what the toolchain keys
// -mod=vendor on and therefore what the disclosure keys on.
func vendoredProject(t *testing.T, vendored bool) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/proj\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if vendored {
		if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o750); err != nil {
			t.Fatalf("creating vendor/: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte("# example.test/dep v1.0.0\n"), 0o600); err != nil {
			t.Fatalf("writing modules.txt: %v", err)
		}
	}
	return filepath.Join(root, "go.mod")
}

// TestBuildVendoring_AVendoredProjectSaysSo is the failing scenario: nothing on
// the manifest-resolving path said a project was vendored, so an answer about
// the modules go.mod resolves read as an answer about the bytes that ship, and
// the reader had no way to tell the two apart.
func TestBuildVendoring_AVendoredProjectSaysSo(t *testing.T) {
	v := detectBuildVendoringForGoMod(vendoredProject(t, true))
	if !v.Known || !v.Vendored {
		t.Fatalf("a project with vendor/modules.txt beside go.mod must report as vendored, got %+v", v)
	}

	var buf bytes.Buffer
	if err := writeBuildVendoring(&buf, v); err != nil {
		t.Fatalf("writeBuildVendoring: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"vendor/modules.txt",                // where the answer was keyed
		"compiles the bytes under vendor/",  // what the project actually builds
		"the modules the manifest resolves", // what the surrounding answer describes
		"kanonarion vendor",                 // the command that measures the other one
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the disclosure does not say %q; it must name what the answer describes and what measures the rest:\n%s", want, out)
		}
	}
}

// TestBuildVendoring_AnUnvendoredProjectSaysNothing is the zero's control. The
// surrounding commands' wording already describes resolved modules, so an
// unvendored project has no ambiguity to resolve — and a line printed on every
// run is a line readers learn to skip.
func TestBuildVendoring_AnUnvendoredProjectSaysNothing(t *testing.T) {
	v := detectBuildVendoringForGoMod(vendoredProject(t, false))
	if !v.Known {
		t.Fatalf("a readable project directory must be a known answer, got %+v", v)
	}
	if v.Vendored {
		t.Fatalf("a project with no vendor/modules.txt must not report as vendored, got %+v", v)
	}

	var buf bytes.Buffer
	if err := writeBuildVendoring(&buf, v); err != nil {
		t.Fatalf("writeBuildVendoring: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("an unvendored project must state nothing, got %q", buf.String())
	}
}

// TestBuildVendoring_AnAbsentDirectoryIsUnknownNotUnvendored keeps the third
// answer distinct. A stored walk names the tree it was taken from, and that tree
// may since have moved; degrading to "not vendored" would let a missing checkout
// answer a question about the build, which is the absence-as-answer defect.
func TestBuildVendoring_AnAbsentDirectoryIsUnknownNotUnvendored(t *testing.T) {
	for name, v := range map[string]buildVendoring{
		"a directory that is not there": detectBuildVendoringInDir(filepath.Join(t.TempDir(), "gone")),
		"no directory at all":           detectBuildVendoringInDir(""),
		"no manifest at all":            detectBuildVendoringForGoMod(""),
	} {
		if v.Known {
			t.Errorf("%s reports a known answer %+v; it was never asked", name, v)
		}
		if v.Vendored {
			t.Errorf("%s reports vendored %+v", name, v)
		}
	}
}
