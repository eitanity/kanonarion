package goast

import (
	"go/ast"
	"testing"
)

// Tests for unexported helpers: parseModulePath, receiverName, exprName.

// -- parseModulePath --

func TestParseModulePath_ReturnsPath(t *testing.T) {
	got, err := parseModulePath([]byte("module github.com/foo/bar\n\ngo 1.21\n"))
	if err != nil {
		t.Fatalf("parseModulePath: %v", err)
	}
	if got != "github.com/foo/bar" {
		t.Errorf("got %q, want github.com/foo/bar", got)
	}
}

func TestParseModulePath_StripInlineComment(t *testing.T) {
	got, err := parseModulePath([]byte("module example.com/app // a comment\n"))
	if err != nil {
		t.Fatalf("parseModulePath: %v", err)
	}
	if got != "example.com/app" {
		t.Errorf("got %q, want example.com/app", got)
	}
}

func TestParseModulePath_NoModuleDirective_Error(t *testing.T) {
	_, err := parseModulePath([]byte("go 1.21\n"))
	if err == nil {
		t.Fatal("expected error for go.mod with no module directive")
	}
}

func TestParseModulePath_EmptyContent_Error(t *testing.T) {
	_, err := parseModulePath([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty content")
	}
}

func TestParseModulePath_EmptyModuleName_Error(t *testing.T) {
	// "module " with nothing after it
	_, err := parseModulePath([]byte("module \n"))
	if err == nil {
		t.Fatal("expected error for empty module name")
	}
}

// -- receiverName --

func TestReceiverName_Ident(t *testing.T) {
	got := receiverName(&ast.Ident{Name: "MyType"})
	if got != "MyType" {
		t.Errorf("got %q, want MyType", got)
	}
}

func TestReceiverName_StarIdent(t *testing.T) {
	got := receiverName(&ast.StarExpr{X: &ast.Ident{Name: "MyType"}})
	if got != "*MyType" {
		t.Errorf("got %q, want *MyType", got)
	}
}

func TestReceiverName_IndexExpr(t *testing.T) {
	got := receiverName(&ast.IndexExpr{X: &ast.Ident{Name: "Stack"}, Index: &ast.Ident{Name: "T"}})
	if got != "Stack" {
		t.Errorf("got %q, want Stack", got)
	}
}

func TestReceiverName_IndexListExpr(t *testing.T) {
	got := receiverName(&ast.IndexListExpr{
		X:       &ast.Ident{Name: "Pair"},
		Indices: []ast.Expr{&ast.Ident{Name: "K"}, &ast.Ident{Name: "V"}},
	})
	if got != "Pair" {
		t.Errorf("got %q, want Pair", got)
	}
}

func TestReceiverName_Unknown_ReturnsEmpty(t *testing.T) {
	got := receiverName(&ast.SelectorExpr{X: &ast.Ident{Name: "pkg"}, Sel: &ast.Ident{Name: "Type"}})
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// -- exprName --

func TestExprName_Ident(t *testing.T) {
	got := exprName(&ast.Ident{Name: "Foo"})
	if got != "Foo" {
		t.Errorf("got %q, want Foo", got)
	}
}

func TestExprName_NonIdent_ReturnsEmpty(t *testing.T) {
	got := exprName(&ast.SelectorExpr{X: &ast.Ident{Name: "pkg"}, Sel: &ast.Ident{Name: "Type"}})
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
