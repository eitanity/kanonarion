package xmod_test

import (
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/directive/adapters/parser/xmod"
	"github.com/eitanity/kanonarion/internal/directive/domain"
)

const corpus = "../../../../../test/fixtures/supplychain/directives"

// TestParseProject_LocalReplaceWithWorkPrecedence is the regression
// for the trickiest case: a go.mod local-path replace overridden by a go.work
// replace. Both must be recorded; the go.mod one is marked not-applied
// (workspace precedence), never silently dropped.
func TestParseProject_LocalReplaceWithWorkPrecedence(t *testing.T) {
	res, err := xmod.New().ParseProject(filepath.Join(corpus, "local-replace", "go.mod"))
	if err != nil {
		t.Fatalf("ParseProject: %v", err)
	}
	if res.ProjectModulePath == "" {
		t.Error("project module path not parsed")
	}

	var gomodRepl, workRepl *domain.Directive
	for i := range res.Directives {
		d := &res.Directives[i]
		switch d.Source {
		case "go.mod":
			if d.Kind == domain.KindReplace {
				gomodRepl = d
			}
		case "go.work":
			workRepl = d
		}
	}
	if gomodRepl == nil || workRepl == nil {
		t.Fatalf("expected both a go.mod and a go.work replace, got %+v", res.Directives)
	}
	if !gomodRepl.IsLocal || gomodRepl.LocalPath == "" {
		t.Errorf("go.mod replace should be local: %+v", gomodRepl)
	}
	if gomodRepl.Line == 0 {
		t.Error("go.mod replace missing line number")
	}
	if gomodRepl.Applied {
		t.Error("go.mod replace overridden by go.work must be not-applied")
	}
	if !workRepl.Applied {
		t.Error("go.work replace must be applied")
	}
}

func TestParseProject_ExcludeNewer(t *testing.T) {
	res, err := xmod.New().ParseProject(filepath.Join(corpus, "exclude-newer", "go.mod"))
	if err != nil {
		t.Fatalf("ParseProject: %v", err)
	}
	var exc *domain.Directive
	for i := range res.Directives {
		if res.Directives[i].Kind == domain.KindExclude {
			exc = &res.Directives[i]
		}
	}
	if exc == nil {
		t.Fatal("expected an exclude directive")
	}
	if exc.OldPath == "" || exc.OldVersion == "" || exc.Line == 0 {
		t.Errorf("exclude missing provenance: %+v", exc)
	}
	if got, ok := res.ResolvedVersions[exc.OldPath]; !ok || got == "" {
		t.Errorf("resolved version for %q not captured from require set", exc.OldPath)
	}
}

func TestParseProject_Clean(t *testing.T) {
	res, err := xmod.New().ParseProject(filepath.Join(corpus, "clean", "go.mod"))
	if err != nil {
		t.Fatalf("ParseProject: %v", err)
	}
	if len(res.Directives) != 0 {
		t.Errorf("clean fixture should have no directives, got %+v", res.Directives)
	}
}
