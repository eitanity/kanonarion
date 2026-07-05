package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

func TestDetectScope(t *testing.T) {
	tests := []struct {
		name string
		kind domain.WorkspaceKind
		want domain.Scope
	}{
		{
			name: "library package returns exported",
			kind: domain.WorkspaceKind{IsMain: false, HasTestFiles: false},
			want: domain.ScopeExported,
		},
		{
			name: "binary package returns main",
			kind: domain.WorkspaceKind{IsMain: true, HasTestFiles: false},
			want: domain.ScopeMain,
		},
		{
			name: "test files present returns tests",
			kind: domain.WorkspaceKind{IsMain: false, HasTestFiles: true},
			want: domain.ScopeTests,
		},
		{
			name: "test files take priority over main",
			kind: domain.WorkspaceKind{IsMain: true, HasTestFiles: true},
			want: domain.ScopeTests,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.DetectScope(tt.kind)
			if got != tt.want {
				t.Errorf("DetectScope(%+v) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}

func TestSelectRoots_Main(t *testing.T) {
	decls := []domain.FuncDecl{
		{Package: "p", Name: "main"},
		{Package: "p", Name: "init"},
		{Package: "p", Name: "Exported", IsExported: true},
		{Package: "p", Name: "unexported"},
		{Package: "p", Name: "TestFoo", IsTestFile: true},
	}
	got := domain.SelectRoots(domain.ScopeMain, decls)
	want := []domain.FuncDecl{
		{Package: "p", Name: "main"},
		{Package: "p", Name: "init"},
	}
	assertFuncDecls(t, got, want)
}

func TestSelectRoots_Exported(t *testing.T) {
	decls := []domain.FuncDecl{
		{Package: "p", Name: "init"},
		{Package: "p", Name: "Exported", IsExported: true},
		{Package: "p", Name: "unexported"},
		{Package: "p", Name: "init", IsTestFile: true},
		{Package: "p", Name: "TestFoo", IsExported: false, IsTestFile: true},
		{Package: "p", Name: "ExportedTest", IsExported: true, IsTestFile: true},
	}
	got := domain.SelectRoots(domain.ScopeExported, decls)
	// only non-test-file inits and exported funcs
	want := []domain.FuncDecl{
		{Package: "p", Name: "init"},
		{Package: "p", Name: "Exported", IsExported: true},
	}
	assertFuncDecls(t, got, want)
}

func TestSelectRoots_Tests(t *testing.T) {
	decls := []domain.FuncDecl{
		{Package: "p", Name: "TestFoo", IsTestFile: true},
		{Package: "p", Name: "TestBar", IsTestFile: true},
		{Package: "p", Name: "BenchmarkFoo", IsTestFile: true},
		{Package: "p", Name: "FuzzFoo", IsTestFile: true},
		{Package: "p", Name: "ExampleFoo", IsTestFile: true},
		{Package: "p", Name: "Test", IsTestFile: true},                       // no suffix — valid
		{Package: "p", Name: "Testfoo", IsTestFile: true},                    // lowercase after prefix — not a testing func
		{Package: "p", Name: "helper", IsTestFile: true},                     // not a testing func
		{Package: "p", Name: "TestFoo", IsExported: true, IsTestFile: false}, // not a test file
	}
	got := domain.SelectRoots(domain.ScopeTests, decls)
	want := []domain.FuncDecl{
		{Package: "p", Name: "TestFoo", IsTestFile: true},
		{Package: "p", Name: "TestBar", IsTestFile: true},
		{Package: "p", Name: "BenchmarkFoo", IsTestFile: true},
		{Package: "p", Name: "FuzzFoo", IsTestFile: true},
		{Package: "p", Name: "ExampleFoo", IsTestFile: true},
		{Package: "p", Name: "Test", IsTestFile: true},
	}
	assertFuncDecls(t, got, want)
}

func TestSelectRoots_All(t *testing.T) {
	decls := []domain.FuncDecl{
		{Package: "p", Name: "main"},
		{Package: "p", Name: "init"},
		{Package: "p", Name: "Exported", IsExported: true},
		{Package: "p", Name: "unexported"},
		{Package: "p", Name: "TestFoo", IsTestFile: true},
		{Package: "p", Name: "helper", IsTestFile: true},
	}
	got := domain.SelectRoots(domain.ScopeAll, decls)
	want := []domain.FuncDecl{
		{Package: "p", Name: "main"},
		{Package: "p", Name: "init"},
		{Package: "p", Name: "Exported", IsExported: true},
		{Package: "p", Name: "TestFoo", IsTestFile: true},
	}
	assertFuncDecls(t, got, want)
}

func assertFuncDecls(t *testing.T, got, want []domain.FuncDecl) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d decls, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for i, g := range got {
		w := want[i]
		if g != w {
			t.Errorf("decls[%d]: got %+v, want %+v", i, g, w)
		}
	}
}
