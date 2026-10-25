package tinylower

import "sort"

// Op is one runtime call TinyGo's compiler emits.
type Op string

// Callee is a function TinyGo's compiler calls for an Op.
type Callee struct {
	Pkg  string
	Name string
}

// Table is the runtime functions one TinyGo release calls for each Op, and the
// functions it exports by name rather than by directive.
type Table struct {
	version string
	callees map[Op][]Callee
	wasm    []NamedExport
}

// NamedExport is a function the compiler exports to the WebAssembly host under
// Symbol although its source carries no directive.
type NamedExport struct {
	Callee
	Symbol string
}

// WasmExports lists the functions the release exports by name in a wasm build.
func (t *Table) WasmExports() []NamedExport { return t.wasm }

// Version is the TinyGo release the table was read from.
func (t *Table) Version() string { return t.version }

// Callees returns the functions TinyGo calls for op, nil for an op the release
// does not lower to a call.
func (t *Table) Callees(op Op) []Callee { return t.callees[op] }

// ForVersion returns the table for a TinyGo version as `tinygo version` prints
// it, and false for a version no table covers.
func ForVersion(version string) (*Table, bool) {
	t, ok := tables[version]
	return t, ok
}

// Versions lists the TinyGo versions a table covers, sorted.
func Versions() []string {
	out := make([]string, 0, len(tables))
	for v := range tables {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

var tables = map[string]*Table{
	v0420.version: v0420,
}

func rt(name string) Callee   { return Callee{Pkg: "runtime", Name: name} }
func task(name string) Callee { return Callee{Pkg: "internal/task", Name: name} }
