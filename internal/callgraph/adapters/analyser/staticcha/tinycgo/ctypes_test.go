package tinycgo

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func (t *cType) String() string {
	switch t.kind {
	case cPointer:
		return "*" + t.elem.String()
	case cArray:
		return "[" + strconv.FormatInt(t.n, 10) + "]" + t.elem.String()
	case cFunction:
		return "func"
	case cVoid:
		return "void"
	case cTagged:
		return t.tag + " " + t.name
	case cTypedef:
		return "typedef " + t.name
	}
	return t.name
}

func TestParseCType_TheSpellingsClangWrites(t *testing.T) {
	for in, want := range map[string]string{
		"unsigned long":         "unsigned long",
		"long unsigned int":     "unsigned long",
		"const unsigned char *": "*unsigned char",
		"signed char":           "signed char",
		"short":                 "short",
		"unsigned short int":    "unsigned short",
		"unsigned":              "unsigned int",
		"long long":             "long long",
		"unsigned long long":    "unsigned long long",
		"long double":           "long double",
		"_Bool":                 "_Bool",
		"bool":                  "_Bool",
		"char *const *":         "**char",
		"char[4]":               "[4]char",
		"char *[2]":             "[2]*char",
		"void *":                "*void",
		"struct pt *":           "*struct pt",
		"enum mode":             "enum mode",
		"volatile uint32_t":     "typedef uint32_t",
		"void (*)(int)":         "*func",
		"void (int, int)":       "func",
		"void (*)(uint32_t) __attribute__((noreturn))": "*func",
	} {
		got, err := parseCType(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("%q = %s, want %s", in, got, want)
		}
	}
	for _, in := range []string{
		"_Complex float", "__int128", "int (*)[4]", "char[]", "struct (unnamed struct at a.c:1:1)",
		"struct", "int * x", "void (*(int))(void)", "", "unsigned float", "long void", "_Float16",
	} {
		if got, err := parseCType(in); !errors.Is(err, errUnsupportedType) {
			t.Errorf("%q = %v, %v; want it refused", in, got, err)
		}
	}
}

func TestFunctionResult(t *testing.T) {
	for in, want := range map[string]string{
		"void (const uint8_t *, uint8_t *, size_t)": "void",
		"void *(uint32_t)":                          "void *",
		"int (void) __attribute__((noreturn))":      "int",
	} {
		if got, err := functionResult(in); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := functionResult("int"); err == nil {
		t.Error("a non-function type gave a result")
	}
}

func TestParseMacros(t *testing.T) {
	m := parseMacros([]byte("#define A 1\n#define F(a, b) ((a) + (b))\n#define EMPTY\n# 1 x\n#define S \"s\"\n"))
	if m["A"].value != "1" || m["A"].funcLike {
		t.Errorf("A = %+v", m["A"])
	}
	if m["F"].value != "(a, b) ((a) + (b))" || !m["F"].funcLike {
		t.Errorf("F = %+v", m["F"])
	}
	if m["EMPTY"] == nil || m["EMPTY"].value != "" || m["S"].value != `"s"` {
		t.Errorf("EMPTY = %+v, S = %+v", m["EMPTY"], m["S"])
	}
	if _, err := readSizes(m); err == nil {
		t.Error("sizes were read from macros that predefine none")
	}
	m["__SIZEOF_SHORT__"] = &macroDef{value: "two"}
	if _, err := readSizes(m); err == nil || !strings.Contains(err.Error(), "__SIZEOF_SHORT__") {
		t.Errorf("a size that is not a number = %v", err)
	}
}

// The constant parser without a file to resolve names in: every form it
// accepts, rendered as the Go expression it becomes, and the errors it gives.
func TestParseConst_TheExpressionsItAccepts(t *testing.T) {
	fset := token.NewFileSet()
	for in, want := range map[string]string{
		"0x10000000":            "0x10000000",
		"5u":                    "5",
		"10UL":                  "10",
		"1.5f":                  "1.5",
		`"text"`:                `"text"`,
		"'c'":                   "'c'",
		"-3":                    "-3",
		"(1 << 8)":              "(1 << 8)",
		"1 | 2 ^ 3 & 4":         "1 | (2 ^ 3&4)",
		"8 >> 1":                "8 >> 1",
		"1 + 2 * 3 - 4 / 2 % 1": "1 + 2*3 - 4/2%1",
		"OTHER":                 "C.OTHER",
	} {
		expr, err := parseConst(token.NoPos, fset, in, nil, token.NoPos, nil)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := render(t, expr); got != want {
			t.Errorf("%q = %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"":     "empty constant",
		"1 2":  "unexpected token INT, expected end of expression",
		"(1":   "unexpected token EOF, expected )",
		"&& 1": "unexpected token INT, expected end of expression",
		"1 +":  "empty constant",
		"$":    "unexpected token ILLEGAL, expected end of expression",
	} {
		if _, err := parseConst(token.NoPos, fset, in, nil, token.NoPos, nil); err == nil || err.Msg != want {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
	params := []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "2"}}
	expr, err := parseConst(token.NoPos, fset, "(n) ((n) << 4)", params, token.NoPos, nil)
	if err != nil || render(t, expr) != "((2) << 4)" {
		t.Errorf("a function-like macro = %v, %v", expr, err)
	}
	for in, want := range map[string]string{
		"(a b) a":  "unexpected token IDENT inside macro parameters, expected ',' or ')'",
		"(a, b) a": "unexpected number of parameters: expected 2, got 1",
		"a":        "unexpected token IDENT, expected (",
		"(1) a":    "unexpected token INT, expected IDENT",
	} {
		if _, err := parseConst(token.NoPos, fset, in, params, token.NoPos, nil); err == nil || err.Msg != want {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
	if _, err := parseConst(token.NoPos, fset, "() 1", []ast.Expr{}, token.NoPos, nil); err != nil {
		t.Errorf("a macro of no parameters: %v", err)
	}
}

func render(t *testing.T, e ast.Expr) string {
	t.Helper()
	var b strings.Builder
	if err := printer.Fprint(&b, token.NewFileSet(), e); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestReadCGoLine_RefusesWhatItDoesNotRead(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", "package x\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	p := newCgoPackage([]*ast.File{f}, "/d", "x", "linux", fset)
	for _, line := range []string{"#cgo ", "#cgo noescape", "#cgo nocallback f", "#cgo CFLAGS -x", "#cgo : x", "#cgo linux CFLAGS: -x", "#cgo FFLAGS: -x", "#cgo LDFLAGS: -lm"} {
		p.readCGoLine(line, "", f.Package)
	}
	var got []string
	for _, e := range p.errors {
		got = append(got, e.Error())
	}
	want := []string{
		"x.go:1:1: invalid #cgo line",
		"x.go:1:1: a #cgo noescape line names exactly one function",
		"x.go:1:1: missing colon in #cgo line",
		"x.go:1:1: invalid #cgo line",
		"x.go:1:1: not implemented: build constraints in #cgo line",
		"x.go:1:1: invalid #cgo line: FFLAGS",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("errors:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if win := newCgoPackage([]*ast.File{f}, "/d", "x", "windows", fset); len(win.generated.Decls) <= len(p.generated.Decls) {
		t.Error("the windows prefix declares no errno mapping")
	}
}

func TestEnumIntegerType_TheLowestRankOfTheSize(t *testing.T) {
	s := cSizes{short: 2, int: 4, long: 4, longLong: 8}
	for _, tc := range []struct {
		size   int
		signed bool
		want   string
	}{{1, true, "signed char"}, {1, false, "unsigned char"}, {2, false, "unsigned short"}, {4, true, "int"}, {4, false, "unsigned int"}, {8, true, "long long"}} {
		if got, ok := s.enumIntegerType(tc.size, tc.signed); !ok || got != tc.want {
			t.Errorf("%d/%v = %q, want %q", tc.size, tc.signed, got, tc.want)
		}
	}
	if _, ok := s.enumIntegerType(3, true); ok {
		t.Error("a three-byte enum was given a type")
	}
	if _, _, err := readEnumProbe([]byte(`{"inner":[]}`), 1); err == nil {
		t.Error("an AST answering no probe was accepted")
	}
	if _, _, err := readEnumProbe([]byte(`{`), 1); err == nil {
		t.Error("an AST that is not JSON was accepted")
	}
	if got := rawValue([]byte(`12`)); got != "12" {
		t.Errorf("a numeric value = %q", got)
	}
}
