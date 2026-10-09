package builder

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// Under a go directive newer than this binary's Go, a file the parser refuses
// is the analyser limit, not a file to drop from the harness: dropping it left
// its exports, and every symbol they reach, out of the probe without a word.
func TestEnumerateExportedFuncs_AnalyserLimitRefuses(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.go", "package mypkg\n\nfunc Ok() {}\n")
	writeFile(t, dir, "new.go", "package mypkg\n\nfunc (b Box) Map[T any](f func(int) T) T {\n")
	pkgs := []goListPackage{{ImportPath: "example.com/mypkg", Dir: dir, GoFiles: []string{"ok.go", "new.go"}}}
	l := gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}

	_, err := enumerateExportedFuncs(pkgs, l, true)
	var lim *gotoolchain.AnalyserLimitError
	if !errors.As(err, &lim) || lim.Limit != l {
		t.Fatalf("err = %v, want the analyser limit %+v", err, l)
	}

	// The control: under a directive this binary covers, the file is one the
	// harness build will report, and enumeration carries on as before.
	got, err := enumerateExportedFuncs(pkgs, gotoolchain.AnalyserLimit{}, false)
	if err != nil || len(got["example.com/mypkg"]) != 1 {
		t.Errorf("unlimited: %v, %v; want Ok alone", got, err)
	}
}
