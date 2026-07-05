package goast_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/adapters/workspace/goast"
	"github.com/eitanity/kanonarion/internal/local/domain"
)

func TestAnalyser_LibraryPackage(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/proj/go.mod": []byte("module github.com/foo/bar\n\ngo 1.22\n"),
		"/proj/lib.go": []byte(`package bar

func Exported() {}
func unexported() {}
func init() {}
`),
	})

	info, err := goast.Analyser{}.Analyse(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if info.Kind.IsMain {
		t.Error("expected IsMain=false for library package")
	}
	if info.Kind.HasTestFiles {
		t.Error("expected HasTestFiles=false")
	}

	byName := funcsByName(info.Funcs)
	assertFunc(t, byName, "Exported", "github.com/foo/bar", "", true, false)
	assertFunc(t, byName, "unexported", "github.com/foo/bar", "", false, false)
	assertFunc(t, byName, "init", "github.com/foo/bar", "", false, false)
}

func TestAnalyser_BinaryPackage(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/proj/go.mod":      []byte("module github.com/foo/cmd\n\ngo 1.22\n"),
		"/proj/cmd/main.go": []byte("package main\n\nfunc main() {}\nfunc init() {}\n"),
	})

	info, err := goast.Analyser{}.Analyse(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !info.Kind.IsMain {
		t.Error("expected IsMain=true for package main")
	}
	byName := funcsByName(info.Funcs)
	assertFunc(t, byName, "main", "github.com/foo/cmd/cmd", "", false, false)
	assertFunc(t, byName, "init", "github.com/foo/cmd/cmd", "", false, false)
}

func TestAnalyser_TestFiles(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/proj/go.mod":         []byte("module github.com/foo/bar\n\ngo 1.22\n"),
		"/proj/lib.go":         []byte("package bar\n\nfunc Exported() {}\n"),
		"/proj/lib_test.go":    []byte("package bar\n\nfunc TestExported(t *testing.T) {}\nfunc helper() {}\n"),
		"/proj/export_test.go": []byte("package bar_test\n\nfunc BenchmarkExported(b *testing.B) {}\n"),
	})

	info, err := goast.Analyser{}.Analyse(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !info.Kind.HasTestFiles {
		t.Error("expected HasTestFiles=true")
	}

	byName := funcsByName(info.Funcs)
	assertFunc(t, byName, "TestExported", "github.com/foo/bar", "", true, true)
	assertFunc(t, byName, "BenchmarkExported", "github.com/foo/bar", "", true, true)
	assertFunc(t, byName, "helper", "github.com/foo/bar", "", false, true)
}

func TestAnalyser_Method(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/proj/go.mod": []byte("module github.com/foo/bar\n\ngo 1.22\n"),
		"/proj/svc.go": []byte(`package bar

type Service struct{}

func (s *Service) Handle() {}
func (s Service) Info() {}
`),
	})

	info, err := goast.Analyser{}.Analyse(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	byName := funcsByName(info.Funcs)
	if d, ok := byName["Handle"]; !ok {
		t.Error("Handle method not found")
	} else if d.Receiver != "*Service" {
		t.Errorf("Handle receiver: got %q, want %q", d.Receiver, "*Service")
	}
	if d, ok := byName["Info"]; !ok {
		t.Error("Info method not found")
	} else if d.Receiver != "Service" {
		t.Errorf("Info receiver: got %q, want %q", d.Receiver, "Service")
	}
}

func TestAnalyser_SubPackage(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/proj/go.mod":       []byte("module github.com/foo/bar\n\ngo 1.22\n"),
		"/proj/util/util.go": []byte("package util\n\nfunc Helper() {}\n"),
	})

	info, err := goast.Analyser{}.Analyse(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	byName := funcsByName(info.Funcs)
	if d, ok := byName["Helper"]; !ok {
		t.Error("Helper not found")
	} else if d.Package != "github.com/foo/bar/util" {
		t.Errorf("Helper package: got %q, want %q", d.Package, "github.com/foo/bar/util")
	}
}

func TestAnalyser_NoGoMod(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/proj/main.go": []byte("package main\n\nfunc main() {}\n"),
	})

	_, err := goast.Analyser{}.Analyse(context.Background(), snap)
	if err == nil {
		t.Error("expected error when go.mod is absent")
	}
}

// funcsByName builds a name→FuncDecl index for assertions.
func funcsByName(decls []domain.FuncDecl) map[string]domain.FuncDecl {
	m := make(map[string]domain.FuncDecl, len(decls))
	for _, d := range decls {
		m[d.Name] = d
	}
	return m
}

func assertFunc(t *testing.T, index map[string]domain.FuncDecl, name, pkg, receiver string, exported, testFile bool) {
	t.Helper()
	d, ok := index[name]
	if !ok {
		t.Errorf("function %q not found", name)
		return
	}
	if d.Package != pkg {
		t.Errorf("%s: package = %q, want %q", name, d.Package, pkg)
	}
	if d.Receiver != receiver {
		t.Errorf("%s: receiver = %q, want %q", name, d.Receiver, receiver)
	}
	if d.IsExported != exported {
		t.Errorf("%s: IsExported = %v, want %v", name, d.IsExported, exported)
	}
	if d.IsTestFile != testFile {
		t.Errorf("%s: IsTestFile = %v, want %v", name, d.IsTestFile, testFile)
	}
}
