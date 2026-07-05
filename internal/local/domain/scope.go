package domain

import (
	"strings"
	"unicode"
)

// Scope identifies which functions to use as callgraph roots for a local
// workspace analysis. The scope is either auto-detected from the workspace
// or overridden via a CLI flag.
type Scope string

const (
	// ScopeMain targets main and all init functions. Applied automatically
	// when the workspace contains a package main binary.
	ScopeMain Scope = "main"
	// ScopeExported targets every exported function/method and all init
	// functions in non-test files. Applied automatically for library packages.
	ScopeExported Scope = "exported"
	// ScopeTests targets functions matching the testing signatures
	// (TestXxx, BenchmarkXxx, FuzzXxx, ExampleXxx) in *_test.go files.
	// Applied automatically when the snapshot contains test files.
	ScopeTests Scope = "tests"
	// ScopeAll is the union of all other scopes.
	ScopeAll Scope = "all"
)

// WorkspaceKind carries the characteristics of a local workspace needed for
// scope auto-detection. Both fields may be true simultaneously (e.g., a main
// package that also has test files).
type WorkspaceKind struct {
	// IsMain is true when at least one non-test package declaration is "main".
	IsMain bool
	// HasTestFiles is true when at least one *_test.go file is present.
	HasTestFiles bool
}

// FuncDecl is a lightweight representation of a declared function or method
// in the local workspace, used for root selection.
type FuncDecl struct {
	// Package is the import path of the package containing the declaration.
	Package string
	// Name is the unqualified function name (e.g., "main", "init", "DoThing").
	Name string
	// Receiver is the receiver type name for methods; empty for free functions.
	Receiver string
	// IsExported reports whether the function name is exported (starts with an
	// uppercase letter).
	IsExported bool
	// IsTestFile reports whether the declaration is in a *_test.go file.
	IsTestFile bool
}

// DetectScope infers the appropriate Scope from workspace characteristics.
// Priority order: tests > main > exported.
func DetectScope(kind WorkspaceKind) Scope {
	if kind.HasTestFiles {
		return ScopeTests
	}
	if kind.IsMain {
		return ScopeMain
	}
	return ScopeExported
}

// SelectRoots returns the subset of decls that should serve as callgraph
// entry points for the given scope.
func SelectRoots(scope Scope, decls []FuncDecl) []FuncDecl {
	var out []FuncDecl
	for _, d := range decls {
		if includeInScope(scope, d) {
			out = append(out, d)
		}
	}
	return out
}

func includeInScope(scope Scope, d FuncDecl) bool {
	switch scope {
	case ScopeMain:
		return d.Name == "main" || d.Name == "init"
	case ScopeExported:
		return !d.IsTestFile && (d.Name == "init" || d.IsExported)
	case ScopeTests:
		return d.IsTestFile && isTestingFunc(d.Name)
	case ScopeAll:
		return includeInScope(ScopeMain, d) ||
			includeInScope(ScopeExported, d) ||
			includeInScope(ScopeTests, d)
	default:
		return false
	}
}

// isTestingFunc reports whether name matches the Go testing conventions:
// TestXxx, BenchmarkXxx, FuzzXxx, or ExampleXxx where Xxx is empty or
// starts with an uppercase letter.
func isTestingFunc(name string) bool {
	return matchesTestingPrefix(name, "Test") ||
		matchesTestingPrefix(name, "Benchmark") ||
		matchesTestingPrefix(name, "Fuzz") ||
		matchesTestingPrefix(name, "Example")
}

func matchesTestingPrefix(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	rest := name[len(prefix):]
	return rest == "" || unicode.IsUpper([]rune(rest)[0])
}
