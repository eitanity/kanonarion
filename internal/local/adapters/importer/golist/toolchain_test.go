package golist_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/adapters/importer/golist"
	"github.com/eitanity/kanonarion/internal/local/localtest"
)

// TestAnalyseImports_UsesAToolchainAlreadyOnThisHost is the defect on the import
// lister: the tree's own environment pins the toolchain so no child can download
// one, which also refused a toolchain unpacked on the same disk. A project whose
// go directive is a point release ahead of the installed toolchain could not be
// listed at all — `kanonarion context .` on this repository, on a host that had
// what it needed.
//
// The assertion is on the environments the children were handed. The first is
// pinned as it always was; the second is given the toolchain directory in front
// of its PATH and the one selection mode that can use it and still cannot
// download.
func TestAnalyseImports_UsesAToolchainAlreadyOnThisHost(t *testing.T) {
	h := localtest.NewHost(t, true)

	mods, err := golist.New(h.GoBinary).AnalyseImports(context.Background(), h.Tree)

	if err != nil {
		t.Fatalf("AnalyseImports: %v", err)
	}
	if len(mods) != 0 {
		t.Errorf("imported modules = %v, want none for a dependency-free tree", mods)
	}
	h.AssertEscalated(t)
}

// TestBuildModules_UsesAToolchainAlreadyOnThisHost covers the other projection,
// which is what `reachability --local` lists its build with. It is a separate
// child, and before the shared decision existed each one would have needed its
// own copy of it.
func TestBuildModules_UsesAToolchainAlreadyOnThisHost(t *testing.T) {
	h := localtest.NewHost(t, true)

	if _, err := golist.New(h.GoBinary).BuildModules(context.Background(), h.Tree); err != nil {
		t.Fatalf("BuildModules: %v", err)
	}
	h.AssertEscalated(t)
}

// TestAnalyseImports_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk. Without
// this the reader is shown GOTOOLCHAIN inside the go command's sentence and
// cannot tell their own shell from this tool's posture.
func TestAnalyseImports_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk(t *testing.T) {
	h := localtest.NewHost(t, false)

	_, err := golist.New(h.GoBinary).AnalyseImports(context.Background(), h.Tree)

	if err == nil {
		t.Fatal("AnalyseImports succeeded with no toolchain on this host that could serve the tree")
	}
	for _, want := range []string{"kanonarion pins the toolchain", "go >= 1.99.0", "golang.org/dl/go1.99.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	h.AssertNeverEscalated(t)
}

// TestAnalyseImports_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheTree is
// the control that must not move: a toolchain is on disk here too and must stay
// unused, or every host that has ever switched toolchains would start measuring
// under a different one.
func TestAnalyseImports_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheTree(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go command on PATH: %v", err)
	}
	h := localtest.NewHost(t, true)
	h.NeverRefuse(t)

	if _, err := golist.New(h.GoBinary).AnalyseImports(context.Background(), h.Tree); err != nil {
		t.Fatalf("AnalyseImports: %v", err)
	}
	h.AssertNeverEscalated(t)
}
