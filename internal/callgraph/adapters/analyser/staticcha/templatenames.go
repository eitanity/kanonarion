package staticcha

import (
	"go/constant"
	"sort"
	"text/template/parse"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"

	"golang.org/x/tools/go/callgraph"
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
}

func newTemplateNames() *templateNames {
	return &templateNames{names: map[string]map[string]bool{}, unbounded: map[string]bool{}}
}

// observe reads one recorded edge out of module.
func (t *templateNames) observe(edge *callgraph.Edge, module, calleeID string) {
	switch {
	case templateUnbounded[calleeID]:
		t.unbounded[module] = true
	case templateParse[calleeID]:
		text, ok := constantLastArg(edge.Site)
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
