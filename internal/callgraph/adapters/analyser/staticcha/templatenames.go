package staticcha

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template/parse"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// templateParse is each template Parse method, whose constant text is read.
var templateParse = map[string]bool{
	"text/template.(*Template).Parse": true,
	"html/template.(*Template).Parse": true,
}

// templateUnbounded is each call that gives a template text this analysis
// cannot read, or reads it with other delimiters: a module making one has no
// known name set.
var templateUnbounded = map[string]bool{}

// templateExecute is each call that runs a template's lookups.
var templateExecute = map[string]bool{}

func init() {
	for _, pkg := range []string{"text/template", "html/template"} {
		for _, fn := range []string{"ParseFiles", "ParseGlob", "ParseFS"} {
			templateUnbounded[pkg+"."+fn] = true
			templateUnbounded[pkg+".(*Template)."+fn] = true
		}
		templateUnbounded[pkg+".(*Template).Delims"] = true
		templateUnbounded[pkg+".(*Template).AddParseTree"] = true
		templateExecute[pkg+".(*Template).Execute"] = true
		templateExecute[pkg+".(*Template).ExecuteTemplate"] = true
	}
}

// templateNames collects, per caller module, the field and method names its
// constant template texts use, so a template Execute edge can name the methods
// it can call. A module that parses text it cannot read has no name set.
type templateNames struct {
	names     map[string]map[string]bool
	unbounded map[string]bool
	cg        *callgraph.Graph
	embeds    map[types.Object]string
	// uses is how the program touches each global, collected on the first
	// Parse that reads one so a module without one pays nothing.
	uses map[*ssa.Global]*globalUse
}

// globalUse is every value stored to a global, and whether it is ever used
// other than by a load or a store, which could write it through a pointer.
type globalUse struct {
	stores  []ssa.Value
	escaped bool
}

func newTemplateNames(cg *callgraph.Graph, embeds map[types.Object]string) *templateNames {
	return &templateNames{names: map[string]map[string]bool{}, unbounded: map[string]bool{}, cg: cg, embeds: embeds}
}

// observe reads one recorded edge out of module.
func (t *templateNames) observe(edge *callgraph.Edge, module, calleeID string) {
	switch {
	case templateUnbounded[calleeID]:
		t.unbounded[module] = true
	case templateParse[calleeID]:
		text, ok := t.parseText(edge.Site)
		if !ok {
			t.unbounded[module] = true
			return
		}
		ids, ok := templateIdentifiers(text)
		if !ok {
			t.unbounded[module] = true
			return
		}
		set := t.names[module]
		if set == nil {
			set = map[string]bool{}
			t.names[module] = set
		}
		for _, id := range ids {
			set[id] = true
		}
	}
}

// stamp records each template Execute edge's name set in its LookupName, or
// leaves it empty where its caller's module has none.
func (t *templateNames) stamp(edges []domain.CallEdge, nodes map[string]domain.CallNode) {
	for i, e := range edges {
		if !templateExecute[e.ToID] {
			continue
		}
		module := nodes[e.FromID].Module
		set, parsed := t.names[module]
		if !parsed || t.unbounded[module] {
			continue
		}
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		edges[i].LookupName = domain.TemplateLookupNames(names)
	}
}

// constantLastArg is the string constant a call passes last, if it is one. It
// is asked only of a recorded call to MethodByName or Parse, which always has a
// site and an argument.
func constantLastArg(site ssa.CallInstruction) (string, bool) {
	args := site.Common().Args
	c, ok := args[len(args)-1].(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(c.Value), true
}

// parseText is the text a Parse call passes: a constant, an unexported
// package-level var whose only store is a constant, or an unexported //go:embed
// var's single file.
func (t *templateNames) parseText(site ssa.CallInstruction) (string, bool) {
	if text, ok := constantLastArg(site); ok {
		return text, true
	}
	args := site.Common().Args
	g, ok := loadedGlobal(args[len(args)-1])
	if !ok {
		return "", false
	}
	// A global only test code touches has no entry: no store, no escape.
	use := t.globalUses()[g]
	if use == nil {
		use = &globalUse{}
	}
	if use.escaped {
		return "", false
	}
	if path, embedded := t.embeds[g.Object()]; embedded {
		// A store replaces the embedded bytes, so the file is the text only
		// while nothing stores.
		if len(use.stores) > 0 {
			return "", false
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- the file a //go:embed in the analysed source names
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
	if len(use.stores) != 1 {
		return "", false
	}
	c, ok := use.stores[0].(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(c.Value), true
}

// loadedGlobal is the unexported package-level var a value loads, directly or
// through string(...). Another module can assign an exported var, and no store
// it makes is in this program, so only an unexported one can be read.
func loadedGlobal(v ssa.Value) (*ssa.Global, bool) {
	if conv, ok := v.(*ssa.Convert); ok {
		v = conv.X
	}
	load, ok := v.(*ssa.UnOp)
	if !ok || load.Op != token.MUL {
		return nil, false
	}
	g, ok := load.X.(*ssa.Global)
	if !ok || g.Object().Exported() {
		return nil, false
	}
	return g, true
}

// globalUses reads every function in the graph once for the stores to and
// other uses of each global. Test code is skipped: no consumer's build holds
// it, so what it writes is never the text a consumer's Execute runs.
func (t *templateNames) globalUses() map[*ssa.Global]*globalUse {
	if t.uses != nil {
		return t.uses
	}
	t.uses = map[*ssa.Global]*globalUse{}
	var rands []*ssa.Value
	for fn := range t.cg.Nodes {
		if fn == nil || isTestFunc(fn, fn.Prog.Fset, funcPackagePath(fn)) {
			continue
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(rands[:0]) {
					g, ok := (*op).(*ssa.Global)
					if !ok {
						continue
					}
					use := t.uses[g]
					if use == nil {
						use = &globalUse{}
						t.uses[g] = use
					}
					switch i := instr.(type) {
					case *ssa.UnOp:
						if i.Op == token.MUL {
							continue
						}
					case *ssa.Store:
						if op == &i.Addr {
							use.stores = append(use.stores, i.Val)
							continue
						}
					}
					use.escaped = true
				}
			}
		}
	}
	return t.uses
}

// readEmbeds is the file each //go:embed var holds, where its directive names
// one pattern matching one regular file. An embed.FS is never a Parse text, so
// its type needs no check. The file is read when a Parse needs it.
func readEmbeds(loaded []*packages.Package) map[types.Object]string {
	out := map[types.Object]string{}
	for _, p := range loaded {
		if p.TypesInfo == nil || len(p.GoFiles) == 0 {
			continue
		}
		dir := filepath.Dir(p.GoFiles[0])
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 {
						continue
					}
					doc := vs.Doc
					if doc == nil && len(gd.Specs) == 1 {
						doc = gd.Doc
					}
					obj := p.TypesInfo.Defs[vs.Names[0]]
					if path, ok := embedFile(doc, dir); ok && obj != nil {
						out[obj] = path
					}
				}
			}
		}
	}
	return out
}

// embedFile is the one regular file a doc comment's //go:embed patterns name.
// A quoted pattern is left unread, so its var stays unknown.
func embedFile(doc *ast.CommentGroup, dir string) (string, bool) {
	if doc == nil {
		return "", false
	}
	var patterns []string
	for _, c := range doc.List {
		rest, ok := strings.CutPrefix(c.Text, "//go:embed")
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		if strings.ContainsAny(rest, "\"`") {
			return "", false
		}
		patterns = append(patterns, strings.Fields(rest)...)
	}
	if len(patterns) != 1 {
		return "", false
	}
	pattern := strings.TrimPrefix(patterns[0], "all:")
	matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
	if err != nil || len(matches) != 1 {
		return "", false
	}
	if info, err := os.Lstat(matches[0]); err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return matches[0], true
}

// templateIdentifiers is every field or method name a template text uses, and
// false where the text does not parse. Functions are not checked: the text is
// read without the FuncMap it runs with.
func templateIdentifiers(text string) ([]string, bool) {
	// Each {{define}} lands in trees beside the text's own root.
	trees := map[string]*parse.Tree{}
	tree := parse.New("t")
	tree.Mode = parse.SkipFuncCheck
	if _, err := tree.Parse(text, "", "", trees); err != nil {
		return nil, false
	}
	var ids []string
	var visit func(parse.Node)
	visit = func(n parse.Node) {
		ids = append(ids, templateIdents(n)...)
		for _, c := range templateChildren(n) {
			visit(c)
		}
	}
	visit(tree.Root)
	for _, def := range trees {
		visit(def.Root)
	}
	return ids, true
}

// templateIdents is the field and method names a node names itself.
func templateIdents(n parse.Node) []string {
	switch n := n.(type) {
	case *parse.FieldNode:
		return n.Ident
	case *parse.ChainNode:
		return n.Field
	case *parse.VariableNode:
		return n.Ident[1:]
	}
	return nil
}

// templateChildren is the nodes below n that can name a field or method.
func templateChildren(n parse.Node) []parse.Node {
	switch n := n.(type) {
	case *parse.ListNode:
		if n != nil {
			return n.Nodes
		}
	case *parse.ActionNode:
		return []parse.Node{n.Pipe}
	case *parse.PipeNode:
		if n != nil {
			out := make([]parse.Node, 0, len(n.Cmds))
			for _, c := range n.Cmds {
				out = append(out, c)
			}
			return out
		}
	case *parse.CommandNode:
		return n.Args
	case *parse.ChainNode:
		return []parse.Node{n.Node}
	case *parse.IfNode:
		return branchChildren(&n.BranchNode)
	case *parse.RangeNode:
		return branchChildren(&n.BranchNode)
	case *parse.WithNode:
		return branchChildren(&n.BranchNode)
	case *parse.TemplateNode:
		return []parse.Node{n.Pipe}
	}
	return nil
}

// branchChildren is an if, range or with node's pipeline and both lists.
func branchChildren(b *parse.BranchNode) []parse.Node {
	return []parse.Node{b.Pipe, b.List, b.ElseList}
}
