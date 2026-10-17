package tinycgo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// astNode is the part of a node of clang's -ast-dump=json this package reads.
type astNode struct {
	ID                  string          `json:"id"`
	Kind                string          `json:"kind"`
	Name                string          `json:"name"`
	TagUsed             string          `json:"tagUsed"`
	IsImplicit          bool            `json:"isImplicit"`
	CompleteDefinition  bool            `json:"completeDefinition"`
	IsBitfield          bool            `json:"isBitfield"`
	StorageClass        string          `json:"storageClass"`
	Variadic            bool            `json:"variadic"`
	Value               json.RawMessage `json:"value"`
	Type                *qualType       `json:"type"`
	FixedUnderlyingType *qualType       `json:"fixedUnderlyingType"`
	OwnedTagDecl        *declRef        `json:"ownedTagDecl"`
	Inner               []*astNode      `json:"inner"`
}

type qualType struct {
	QualType  string `json:"qualType"`
	Desugared string `json:"desugaredQualType"`
}

type declRef struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// macroDef is one #define from clang's -dM output. value is what follows the
// name, the parameter list included for a function-like macro.
type macroDef struct {
	name     string
	funcLike bool
	value    string
}

// fileDecls indexes one preamble's translation unit.
type fileDecls struct {
	byID     map[string]*astNode
	records  map[string]*astNode
	typedefs map[string]*astNode
	enums    map[string]*astNode
	macros   map[string]*macroDef
	// enumTypes is each enum's integer type as clang chose it, filled when an
	// enum type is first needed: the JSON AST does not carry it.
	enumTypes map[string]string
}

// parseTranslationUnit reads clang's JSON AST into the names TinyGo's globals
// visitor collects, and the indexes the type translation reads.
func parseTranslationUnit(raw []byte) (*fileDecls, map[string]cursor, error) {
	var tu astNode
	if err := json.Unmarshal(raw, &tu); err != nil {
		return nil, nil, fmt.Errorf("reading clang's AST: %w", err)
	}
	d := &fileDecls{
		byID: map[string]*astNode{}, records: map[string]*astNode{}, typedefs: map[string]*astNode{},
		enums: map[string]*astNode{}, macros: map[string]*macroDef{}, enumTypes: map[string]string{},
	}
	names := map[string]cursor{}
	for _, n := range tu.Inner {
		d.index(n)
		d.collect(n, names)
	}
	return d, names, nil
}

func (d *fileDecls) index(n *astNode) {
	if n.ID != "" && (n.Kind == "RecordDecl" || n.Kind == "EnumDecl") {
		d.byID[n.ID] = n
	}
	for _, c := range n.Inner {
		if c.Kind == "RecordDecl" || c.Kind == "EnumDecl" {
			d.index(c)
		}
	}
}

// collect is TinyGo's tinygo_clang_globals_visitor over the JSON AST.
func (d *fileDecls) collect(n *astNode, names map[string]cursor) {
	switch n.Kind {
	case "FunctionDecl", "VarDecl":
		names[n.Name] = cursor{node: n}
	case "RecordDecl":
		if n.Name == "" {
			return
		}
		key := n.TagUsed + "_" + n.Name
		if prev, ok := d.records[key]; !ok || n.CompleteDefinition || !prev.CompleteDefinition {
			d.records[key] = n
		}
		names[key] = cursor{node: d.records[key]}
	case "TypedefDecl":
		d.typedefs[n.Name] = n
		names[n.Name] = cursor{node: n}
	case "EnumDecl":
		if n.Name != "" {
			d.enums["enum_"+n.Name] = n
			names["enum_"+n.Name] = cursor{node: n}
		}
		for _, c := range enumConstants(n) {
			names[c.Name] = cursor{node: c}
		}
	}
}

// enumConstants are an enum's constants, each with its value filled in: clang
// writes a value only for a constant with an initialiser, and C numbers the
// rest from the previous one.
func enumConstants(n *astNode) []*astNode {
	var out []*astNode
	next := big.NewInt(0)
	for _, c := range n.Inner {
		if c.Kind != "EnumConstantDecl" {
			continue
		}
		v := next
		for _, e := range c.Inner {
			if e.Kind != "ConstantExpr" {
				continue
			}
			if parsed, ok := new(big.Int).SetString(rawValue(e.Value), 10); ok {
				v = parsed
			}
		}
		c.Value = json.RawMessage(strconv.Quote(v.String()))
		next = new(big.Int).Add(v, big.NewInt(1))
		out = append(out, c)
	}
	return out
}

// parseMacros reads clang's -dM -E output.
func parseMacros(raw []byte) map[string]*macroDef {
	out := map[string]*macroDef{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "#define ")
		if !ok {
			continue
		}
		end := strings.IndexAny(rest, " (")
		if end < 0 {
			out[rest] = &macroDef{name: rest}
			continue
		}
		name := rest[:end]
		m := &macroDef{name: name, funcLike: rest[end] == '(', value: strings.TrimPrefix(rest[end:], " ")}
		out[name] = m
	}
	return out
}

// cSizes are the sizes of the C fundamental types on the target, read from
// clang's predefined macros.
type cSizes struct {
	short, int, long, longLong, float, double, longDouble int
	charUnsigned                                          bool
}

func readSizes(macros map[string]*macroDef) (cSizes, error) {
	get := func(name string) (int, error) {
		m, ok := macros[name]
		if !ok {
			return 0, fmt.Errorf("clang did not predefine %s", name)
		}
		n, err := strconv.Atoi(strings.TrimSpace(m.value))
		if err != nil {
			return 0, fmt.Errorf("clang predefined %s as %q: %w", name, m.value, err)
		}
		return n, nil
	}
	var s cSizes
	var err error
	for _, f := range []struct {
		name string
		dst  *int
	}{
		{"__SIZEOF_SHORT__", &s.short}, {"__SIZEOF_INT__", &s.int}, {"__SIZEOF_LONG__", &s.long},
		{"__SIZEOF_LONG_LONG__", &s.longLong}, {"__SIZEOF_FLOAT__", &s.float}, {"__SIZEOF_DOUBLE__", &s.double},
		{"__SIZEOF_LONG_DOUBLE__", &s.longDouble},
	} {
		if *f.dst, err = get(f.name); err != nil {
			return cSizes{}, err
		}
	}
	_, s.charUnsigned = macros["__CHAR_UNSIGNED__"]
	return s, nil
}

// enumProbeSource declares one array per enum whose lengths clang evaluates to
// the enum's size and signedness; the AST then states both as char[N].
func enumProbeSource(spellings []string) string {
	var b strings.Builder
	b.WriteString("\n# 1 \"<cgo enum probe>\"\n")
	for i, s := range spellings {
		fmt.Fprintf(&b, "char _Cgo_enum_size_%d[sizeof(%s)];\nchar _Cgo_enum_sign_%d[(%s)-1 < 0 ? 1 : 2];\n", i, s, i, s)
	}
	return b.String()
}

// readEnumProbe reads back the arrays enumProbeSource declared: size and
// signedness per index.
func readEnumProbe(raw []byte, n int) ([]int, []bool, error) {
	var tu astNode
	if err := json.Unmarshal(raw, &tu); err != nil {
		return nil, nil, fmt.Errorf("reading clang's AST: %w", err)
	}
	sizes, signed := make([]int, n), make([]bool, n)
	seen := 0
	for _, v := range tu.Inner {
		if v.Kind != "VarDecl" || v.Type == nil {
			continue
		}
		var i, length int
		if _, err := fmt.Sscanf(v.Name, "_Cgo_enum_size_%d", &i); err == nil && i < n {
			if _, err := fmt.Sscanf(v.Type.QualType, "char[%d]", &length); err == nil {
				sizes[i] = length
				seen++
			}
		}
		if _, err := fmt.Sscanf(v.Name, "_Cgo_enum_sign_%d", &i); err == nil && i < n {
			if _, err := fmt.Sscanf(v.Type.QualType, "char[%d]", &length); err == nil {
				signed[i] = length == 1
				seen++
			}
		}
	}
	if seen != 2*n {
		return nil, nil, fmt.Errorf("clang answered %d of the %d enum probes", seen, 2*n)
	}
	return sizes, signed, nil
}

// enumIntegerType is the C integer type clang gives an enum of that size and
// signedness: the lowest-ranked type of the size, as Sema picks it.
func (s cSizes) enumIntegerType(size int, signed bool) (string, bool) {
	for _, c := range []struct {
		size          int
		signed, plain string
	}{
		{1, "signed char", "unsigned char"}, {s.short, "short", "unsigned short"}, {s.int, "int", "unsigned int"},
		{s.long, "long", "unsigned long"}, {s.longLong, "long long", "unsigned long long"},
	} {
		if c.size == size {
			if signed {
				return c.signed, true
			}
			return c.plain, true
		}
	}
	return "", false
}

// rawValue is a node's "value", which clang writes as a string or a number.
func rawValue(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}
