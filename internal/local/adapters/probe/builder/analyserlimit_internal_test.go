package builder

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// Under a go directive newer than this binary's Go, export data this binary's
// go/types cannot read is the analyser limit, not a harness to give up on: the
// build would compile it, so only this binary could not read it.
func TestLibraryHarness_AnalyserLimitRefuses(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "bogus")
	if err := os.WriteFile(bogus, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs := []goListPackage{{ImportPath: "example.com/lib", Export: bogus}}
	restore := gotoolchain.SetAnalysingGo("go1.21.0")
	defer restore()

	_, _, err := libraryHarness(pkgs, []byte("module example.com/lib\n\ngo 1.22\n"))
	var lim *gotoolchain.AnalyserLimitError
	if !errors.As(err, &lim) || lim.Limit.Required != "go1.22" {
		t.Fatalf("err = %v, want the analyser limit for go1.22", err)
	}

	_, _, err = libraryHarness(pkgs, []byte("module example.com/lib\n\ngo 1.20\n"))
	if err == nil || errors.As(err, &lim) || !strings.Contains(err.Error(), "generating harness") {
		t.Errorf("err = %v, want a plain generation error under a directive this binary covers", err)
	}
	_, _, err = libraryHarness(pkgs, nil)
	if err == nil || errors.As(err, &lim) {
		t.Errorf("err = %v, want a plain generation error with no go.mod", err)
	}
}
