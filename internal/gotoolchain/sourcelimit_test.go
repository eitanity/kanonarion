package gotoolchain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// A parse refusal is this binary's limit only when the module asks for a newer
// Go than the binary was built with; equal, older, absent or unreadable claim none.
func TestLimitForDirective(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()
	for _, tc := range []struct {
		directive string
		want      bool
	}{
		{"1.27.2", true},
		{"1.27", true},
		{"1.26.7", true},
		{"1.26.6", false},
		{"1.26", false},
		{"1.21.0", false},
		{"", false},
		{"not-a-version", false},
	} {
		l, ok := gotoolchain.LimitForDirective(tc.directive)
		if ok != tc.want {
			t.Errorf("LimitForDirective(%q) = %v, want %v", tc.directive, ok, tc.want)
			continue
		}
		if ok && (l.Required != "go"+tc.directive || l.Built != "go1.26.6") {
			t.Errorf("LimitForDirective(%q) = %+v", tc.directive, l)
		}
	}
}

// A development build names no comparable release, so it claims no limit and
// never re-measures a record on the strength of one.
func TestLimitForDirective_DevelBuild(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("devel go1.28-abcdef")
	defer restore()
	if _, ok := gotoolchain.LimitForDirective("1.99"); ok {
		t.Error("a devel build claimed a limit")
	}
	if gotoolchain.MayPredateThisGo(gotoolchain.Unrecorded) {
		t.Error("a devel build treated an unrecorded toolchain as older")
	}
}

func TestMayPredateThisGo(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.27.2")
	defer restore()
	for v, want := range map[gotoolchain.Version]bool{
		gotoolchain.Unrecorded: true,
		"go1.26.6":             true,
		"go1.27.1":             true,
		"go1.27.2":             false,
		"go1.28.0":             false,
	} {
		if got := gotoolchain.MayPredateThisGo(v); got != want {
			t.Errorf("MayPredateThisGo(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNewUnreadSource(t *testing.T) {
	l := gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}
	if gotoolchain.NewUnreadSource(l, nil) != nil {
		t.Error("no refused file still made an unread source")
	}
	u := gotoolchain.NewUnreadSource(l, []string{"b/x.go", "a.go"})
	if strings.Join(u.Files, ",") != "a.go,b/x.go" {
		t.Errorf("files not sorted: %v", u.Files)
	}
	want := "not analysed: 2 files (a.go, b/x.go): the kanonarion that ran was built with go1.26.6 and the code requires go1.27.2"
	if got := u.Summary(); got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	if one := gotoolchain.NewUnreadSource(l, []string{"a.go"}); !strings.HasPrefix(one.Summary(), "not analysed: 1 file (a.go)") {
		t.Errorf("Summary() = %q", one.Summary())
	}
}

// The statement a stage writes reads back as the limit, so a run's exit can
// be decided from the stage errors it stored.
func TestStatementReadsBack(t *testing.T) {
	l := gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}
	got, ok := gotoolchain.ReadAnalyserLimit("interface stage status=Partial: x; " + l.Statement())
	if !ok || got != l {
		t.Errorf("ReadAnalyserLimit(statement) = %+v, %v; want %+v", got, ok, l)
	}
}

func TestGoDirective(t *testing.T) {
	for in, want := range map[string]string{
		"module m\n\ngo 1.27.2\n":               "1.27.2",
		"module m\n":                            "",
		"this is not a go.mod {":                "",
		"module m\ngo 1.21\ntoolchain go1.27\n": "1.21",
	} {
		if got := gotoolchain.GoDirective([]byte(in)); got != want {
			t.Errorf("GoDirective(%q) = %q, want %q", in, got, want)
		}
	}
}

// A limit binds this binary until it is built with the Go the code requires.
func TestBinds(t *testing.T) {
	l := gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}
	for built, want := range map[string]bool{"go1.26.6": true, "go1.27.1": true, "go1.27.2": false, "go1.28.0": false} {
		restore := gotoolchain.SetAnalysingGo(built)
		if got := l.Binds(); got != want || gotoolchain.AnalysingGo() != built {
			t.Errorf("built %s: Binds = %v, want %v", built, got, want)
		}
		restore()
	}
}

func TestDirectiveNewerThan(t *testing.T) {
	for _, tc := range []struct {
		directive, built string
		want             bool
	}{
		{"1.27.2", "go1.26.4", true},
		{"1.26.4", "go1.26.4", false},
		{"1.26", "go1.26.4", false},
		{"", "go1.26.4", false},
		{"1.27", "devel go1.28-x", false},
	} {
		if got := gotoolchain.DirectiveNewerThan(tc.directive, tc.built); got != tc.want {
			t.Errorf("DirectiveNewerThan(%q, %q) = %v, want %v", tc.directive, tc.built, got, tc.want)
		}
	}
}
