package gotoolchain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// The two sentences a go1.26-built binary printed over a go 1.27 module, as
// measured: go/types' refusal and go/packages' warning.
const (
	realRefusal = "/src/probe/main.go:1:1: package requires newer Go version go1.27 (application built with go1.26)"
	realWarning = "-: This application uses version go1.26 of the source-processing packages but runs version " +
		"go1.27 of 'go list'. It may fail to process source files that rely on newer language features. " +
		"If so, rebuild the application using a newer version of Go."
)

func TestReadAnalyserLimit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, detail, required, built string
		ok                            bool
	}{
		{name: "refusal", detail: realRefusal, required: "go1.27", built: "go1.26", ok: true},
		// The standard library has no go version of its own, so only the warning is said.
		{name: "warning alone", detail: "x.go:1:1: unknown field rfd; " + realWarning, required: "go1.27", built: "go1.26", ok: true},
		{name: "both", detail: realRefusal + "; " + realWarning, required: "go1.27", built: "go1.26", ok: true},
		{name: "highest wins", detail: realRefusal + "; b.go:1:1: package requires newer Go version go1.28 (application built with go1.26)",
			required: "go1.28", built: "go1.26", ok: true},
		{name: "own statement", detail: "error: m@v1: Partial — " +
			gotoolchain.AnalyserLimit{Required: "go1.27.1", Built: "go1.26"}.Statement(), required: "go1.27.1", built: "go1.26", ok: true},
		{name: "half the refusal is prose", detail: "README: package requires newer Go version go1.27"},
		{name: "a compile error", detail: "main.go:3:2: undefined: x"},
		{name: "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, ok := gotoolchain.ReadAnalyserLimit(tc.detail)
			if ok != tc.ok || l.Required != tc.required || l.Built != tc.built {
				t.Errorf("ReadAnalyserLimit(%q) = %+v, %v; want {%s %s}, %v", tc.detail, l, ok, tc.required, tc.built, tc.ok)
			}
		})
	}
}

// govulncheck reads only go/types' refusal: its statement names the tool's build.
func TestReadNewerSourceRefusal_IgnoresTheWarning(t *testing.T) {
	t.Parallel()
	if _, ok := gotoolchain.ReadNewerSourceRefusal(realWarning); ok {
		t.Error("the go/packages warning was read as go/types' refusal")
	}
	if l, ok := gotoolchain.ReadNewerSourceRefusal(realRefusal); !ok || l.Required != "go1.27" {
		t.Errorf("the refusal was not read: %+v %v", l, ok)
	}
}

func TestAnalyserLimit_ClearedBy(t *testing.T) {
	t.Parallel()
	l := gotoolchain.AnalyserLimit{Required: "go1.27", Built: "go1.26"}
	for v, want := range map[string]bool{"go1.26.6": false, "go1.27.0": true, "go1.27.1": true, "go1.28": true, "devel": false} {
		if got := l.ClearedBy(v); got != want {
			t.Errorf("ClearedBy(%q) = %v, want %v", v, got, want)
		}
	}
}

// The statement names both versions and the remedy names a build of this
// binary, never a fix to the source.
func TestAnalyserLimit_StatementAndRemedy(t *testing.T) {
	t.Parallel()
	l := gotoolchain.AnalyserLimit{Required: "go1.27", Built: "go1.26"}
	for _, s := range []string{l.Statement(), l.Remedy(), (&gotoolchain.AnalyserLimitError{Limit: l}).Error()} {
		for _, bad := range []string{"Fix the package", "compiles"} {
			if strings.Contains(s, bad) {
				t.Errorf("%q names a source fix: %s", bad, s)
			}
		}
	}
	if !strings.Contains(l.Clause(), "built with go1.26 and the code requires go1.27") {
		t.Errorf("clause does not name both versions: %s", l.Clause())
	}
	if !strings.Contains(l.Statement(), "built with go1.26") || !strings.Contains(l.Statement(), "requires go1.27") {
		t.Errorf("statement does not name both versions: %s", l.Statement())
	}
	if !strings.Contains(l.Remedy(), "go install github.com/eitanity/kanonarion@latest") || !strings.Contains(l.Remedy(), "go1.27 or newer") {
		t.Errorf("remedy does not name a build with a new enough Go: %s", l.Remedy())
	}
}
