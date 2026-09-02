package cmd_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/cli"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// architectureDoc is the design specification these guards hold to the code.
const architectureDoc = "../docs/ARCHITECTURE.md"

// readArchitectureDoc returns the document's text.
func readArchitectureDoc(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(architectureDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", architectureDoc, err)
	}
	return string(raw)
}

// docSection returns the body of the "## <heading>" section, up to the next
// heading of the same level. It fails rather than returning nothing, because a
// renamed heading would otherwise silence the guard reading it.
func docSection(t *testing.T, doc, heading string) string {
	t.Helper()
	marker := "\n## " + heading + "\n"
	start := strings.Index(doc, marker)
	if start < 0 {
		t.Fatalf("%s has no %q section: a guard reads it, so renaming the heading needs the guard updated too", architectureDoc, heading)
	}
	body := doc[start+len(marker):]
	if end := strings.Index(body, "\n## "); end >= 0 {
		body = body[:end]
	}
	return body
}

// backticked reports every `code span` in text.
var backticked = regexp.MustCompile("`([^`\n]+)`")

// snakeCase matches the shape an audit event type is spelled in.
var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`)

// TestArchitectureDocumentsEveryAuditEventType fails when the audit vocabulary
// and the document's account of it disagree, in either direction.
//
// The vocabulary is READ from audit.KnownEventTypes rather than restated here,
// as internal/cli/store_ledger.go reads it for the `--event-type` set. A
// hand-copied list is how the section came to describe three event types while
// the package defined twenty-three: nothing failed, and the log grew twenty
// kinds of entry an operator reading the specification had no account of.
//
// The reverse direction catches a name the document keeps after the code drops
// it. A snake_case span in the section that is not an event type must at least
// be something the tree says — a payload key, a route, a status — so a constant
// renamed out of existence leaves a documented name with nothing behind it.
func TestArchitectureDocumentsEveryAuditEventType(t *testing.T) {
	section := docSection(t, readArchitectureDoc(t), "Audit Log")

	named := map[string]bool{}
	for _, m := range backticked.FindAllStringSubmatch(section, -1) {
		if snakeCase.MatchString(m[1]) {
			named[m[1]] = true
		}
	}

	known := map[string]bool{}
	for _, et := range audit.KnownEventTypes() {
		known[string(et)] = true
		if !named[string(et)] {
			t.Errorf("audit event type %q is emitted and has no account in the %q section of %s: "+
				"say what it records and what its payload carries, or the log grows an entry kind the "+
				"specification cannot explain", et, "Audit Log", architectureDoc)
		}
	}

	tree := treeText(t)
	for name := range named {
		if known[name] {
			continue
		}
		if !strings.Contains(tree, name) {
			t.Errorf("the %q section names %q, which is not an audit event type and appears nowhere under internal/: "+
				"it reads as a live event and is behind the code", "Audit Log", name)
		}
	}
}

// TestArchitectureDocumentsEveryBoundedContext fails when the context table and
// the tree disagree.
//
// The table is the document's inventory of what exists, and it is exactly the
// kind of hand-kept list that drifts: two contexts had application and domain
// layers, records, adapters and a CLI surface while the table did not mention
// them. The set here is the same one the guards in architecture_test.go derive,
// so a context added later is documented or the build says so.
func TestArchitectureDocumentsEveryBoundedContext(t *testing.T) {
	section := docSection(t, readArchitectureDoc(t), "Bounded Contexts")
	// The table's Package column is the only place a context's directory is
	// spelled, which is what makes it readable without parsing markdown.
	pkgRef := regexp.MustCompile("`internal/([a-z][a-z0-9]*)`")

	tabled := map[string]bool{}
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		for _, m := range pkgRef.FindAllStringSubmatch(line, -1) {
			tabled[m[1]] = true
		}
	}
	if len(tabled) == 0 {
		t.Fatal("no contexts read out of the Bounded Contexts table: the table's shape changed and this guard reads nothing")
	}

	for _, ctx := range sortedKeys(boundedContexts()) {
		if !tabled[ctx] {
			t.Errorf("internal/%s has an application or domain layer and is not in the Bounded Contexts table of %s: "+
				"add its row and its prose, or exempt it in notBoundedContexts with the reason it is not a context",
				ctx, architectureDoc)
		}
	}
	for ctx := range tabled {
		if !boundedContexts()[ctx] {
			t.Errorf("the Bounded Contexts table of %s lists internal/%s, which has neither an application nor a domain layer",
				architectureDoc, ctx)
		}
	}
}

// TestArchitectureDocNamesLiveTests fails when the document names a test that
// no longer exists under that name.
//
// The Determinism section states each invariant together with the test that
// enforces it, which is only worth stating while the test is real: a renamed or
// deleted guard would otherwise leave an invariant reading as enforced by
// something nobody runs, which is a worse claim than not naming a test at all.
//
// A Test-prefixed span that also appears in production source is a code
// identifier and not a reference to a guard — TestScope, the call-graph record's
// axis, is the one in the document today. Production source is where the two are
// told apart, because a test function's name lives only in a _test.go file.
func TestArchitectureDocNamesLiveTests(t *testing.T) {
	doc := readArchitectureDoc(t)
	testRef := regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")

	tree := treeText(t)
	named := map[string]bool{}
	for _, m := range testRef.FindAllStringSubmatch(doc, -1) {
		if strings.Contains(tree, m[1]) {
			continue
		}
		named[m[1]] = true
	}
	if len(named) == 0 {
		t.Fatalf("%s names no test: every invariant it asserts must name the test that enforces it", architectureDoc)
	}

	live := repoTestFuncs(t)
	for _, name := range sortedKeys(named) {
		if !live[name] {
			t.Errorf("%s names %s as an enforcing test and no such test function exists: "+
				"restore the name, or state the invariant against the test that now enforces it",
				architectureDoc, name)
		}
	}
}

// repoTestFuncs returns the name of every test function in the repository.
func repoTestFuncs(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, path := range goTestFiles(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

// goTestFiles lists every _test.go file in the repository, skipping testdata
// and the module cache the golden fixtures live beside.
func goTestFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "testdata", "vendor", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository for test files: %v", err)
	}
	return out
}

// treeText returns the concatenated text of every non-test Go file under
// internal/, which is what a documented name is checked for existence against.
//
// The walk collects paths and the reads happen after it, not inside the
// callback, so no filesystem operation races the walk it was handed a path by.
func treeText(t *testing.T) string {
	t.Helper()
	var paths []string
	err := filepath.Walk("../internal", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if info.IsDir() {
			if info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/ for documented names: %v", err)
	}
	var b strings.Builder
	for _, path := range paths {
		raw, rerr := os.ReadFile(path) // #nosec G304 -- path comes from walking this repository's own internal/ tree
		if rerr != nil {
			t.Fatalf("reading %s: %v", path, rerr)
		}
		b.Write(raw)
	}
	return b.String()
}

// sortedKeys returns m's keys in order, so a failure list reads the same twice.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- guards over the shipped command surface -------------------------------
//
// Three properties tie the documents to the CLI they describe: a document names
// no command that does not exist, an example coordinate is not one a dependency
// bump strands, and a shipped command is documented or explicitly exempt.

// onboardingDocs are the two documents that teach the tool rather than
// reference it. The coordinate guard reads these; the command guards read every
// shipped document.
var onboardingDocs = []string{"../docs/getting-started.md", "../docs/writing-quality-code.md"}

// undocumentedByDecision names the shipped commands no document has to show
// being run, with the reason each is exempt. It is a list of decisions: a
// command that arrives without documentation belongs here only when someone
// decided it needs none, which is what stops the list becoming a blanket.
var undocumentedByDecision = map[string]string{
	"help":                  "cobra's built-in; it prints the help every other command already carries",
	"completion bash":       "cobra's built-in shell-completion generator, not a kanonarion answer",
	"completion fish":       "cobra's built-in shell-completion generator, not a kanonarion answer",
	"completion powershell": "cobra's built-in shell-completion generator, not a kanonarion answer",
	"completion zsh":        "cobra's built-in shell-completion generator, not a kanonarion answer",
}

// shippedDocs lists every document the repository ships: the README and every
// page under docs/. The list is walked rather than written down, so a page
// added later is covered without anyone remembering to add it.
func shippedDocs(t *testing.T) []string {
	t.Helper()
	out := []string{"../README.md"}
	err := filepath.Walk("../docs", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if !info.IsDir() && strings.HasSuffix(path, ".md") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking docs/: %v", err)
	}
	sort.Strings(out)
	return out
}

// docInvocation is one `kanonarion …` command line taken from a fenced code
// block, carrying where it was found so a failure can be opened at the line.
type docInvocation struct {
	doc  string
	line int
	text string
	args []string // everything after the program name, flags included
}

// fencedInvocations returns every kanonarion command line inside a fenced code
// block of doc.
//
// Fenced blocks ONLY. Prose says things like "kanonarion never reports a
// verdict" and "kanonarion at a pinned version", and a match on the program
// name followed by a word reads both of those as commands: that is how a count
// of the commands in one document came back as eighteen while the document
// named sixteen. A fence is where a document puts what it means to be typed.
//
// The line is reduced to the command a shell would run: a `$ ` prompt, a
// trailing comment, a line continuation and anything past a pipe or redirect
// are all removed, because none of them is part of the command's name.
func fencedInvocations(t *testing.T, doc string) []docInvocation {
	t.Helper()
	raw, err := os.ReadFile(doc) // #nosec G304 -- doc comes from walking this repository's own docs/
	if err != nil {
		t.Fatalf("reading %s: %v", doc, err)
	}
	var out []docInvocation
	inFence := false
	for i, line := range strings.Split(string(raw), "\n") {
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			continue
		}
		text = strings.TrimPrefix(text, "$ ")
		for _, op := range []string{" | ", " > ", " >> ", " < ", " && ", " ; "} {
			if j := strings.Index(text, op); j >= 0 {
				text = text[:j]
			}
		}
		if j := strings.Index(text, " #"); j >= 0 {
			text = text[:j]
		}
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text), "\\"))
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "kanonarion" && fields[0] != "./kanonarion" {
			continue
		}
		out = append(out, docInvocation{doc: doc, line: i + 1, text: text, args: fields[1:]})
	}
	return out
}

// commandTree indexes the registered command set by the path a caller types,
// with each level's aliases folded in so `licence` reaches `license`.
type commandTree struct {
	byPath map[string]cli.RegisteredCommand
	// child maps a parent path to the names AND aliases accepted beneath it,
	// each resolving to the canonical name.
	child map[string]map[string]string
}

// registeredCommands builds the tree from the CLI's own registration, so the
// guards below ask the code what exists instead of restating it.
func registeredCommands(t *testing.T) commandTree {
	t.Helper()
	tree := commandTree{
		byPath: map[string]cli.RegisteredCommand{},
		child:  map[string]map[string]string{},
	}
	for _, c := range cli.RegisteredCommands() {
		path := strings.Join(c.Path, " ")
		tree.byPath[path] = c
		parent := strings.Join(c.Path[:len(c.Path)-1], " ")
		if tree.child[parent] == nil {
			tree.child[parent] = map[string]string{}
		}
		name := c.Path[len(c.Path)-1]
		tree.child[parent][name] = name
		for _, alias := range c.Aliases {
			tree.child[parent][alias] = name
		}
	}
	if len(tree.byPath) == 0 {
		t.Fatal("the CLI registered no commands: the guards below would then hold every document to nothing")
	}
	return tree
}

// resolve walks args down the command tree the way cobra does, returning the
// command path reached and the first argument that was not a subcommand.
//
// Descent stops at the first command with no subcommands, so a positional
// argument that happens to spell a sibling's name cannot be mistaken for one.
func (tree commandTree) resolve(args []string) (path []string, rest string) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		here := strings.Join(path, " ")
		name, ok := tree.child[here][arg]
		if !ok {
			return path, arg
		}
		path = append(path, name)
		if len(tree.byPath[strings.Join(path, " ")].Children) == 0 {
			return path, ""
		}
	}
	return path, ""
}

// TestShippedDocsNameOnlyRegisteredCommands fails when a document tells a
// reader to run something the CLI does not register.
//
// A renamed or removed command leaves the instruction reading as live, and the
// reader discovers it by being refused. The registered set is read from the
// CLI, so the rename fails here instead.
func TestShippedDocsNameOnlyRegisteredCommands(t *testing.T) {
	tree := registeredCommands(t)
	total := 0
	for _, doc := range shippedDocs(t) {
		for _, inv := range fencedInvocations(t, doc) {
			total++
			path, rest := tree.resolve(inv.args)
			if len(path) == 0 {
				t.Errorf("%s:%d runs `%s`, and %q is not a registered command: "+
					"rename it to the command that now does this, or drop the line",
					inv.doc, inv.line, inv.text, rest)
				continue
			}
			named := strings.Join(path, " ")
			if !tree.byPath[named].Runnable {
				t.Errorf("%s:%d runs `%s`, and `%s` is a grouping command that does not run on its own "+
					"(%q is not one of its subcommands): name the subcommand",
					inv.doc, inv.line, inv.text, named, rest)
			}
		}
	}
	if total == 0 {
		t.Fatal("no kanonarion invocation was read out of any shipped document: the fence or prompt shape changed and this guard reads nothing")
	}
}

// TestEveryShippedCommandIsDocumented fails when a command ships without a
// document showing it being run.
//
// Both sides are derived: the commands from the CLI's registration, the
// documentation from the fenced blocks of every shipped page. A command added
// without documentation then becomes a decision — put it in
// undocumentedByDecision with the reason — rather than an oversight nobody
// sees. Only runnable paths are required: a grouping command such as `store`
// cannot be typed on its own, and is documented through its subcommands.
func TestEveryShippedCommandIsDocumented(t *testing.T) {
	tree := registeredCommands(t)

	documented := map[string]bool{}
	for _, doc := range shippedDocs(t) {
		for _, inv := range fencedInvocations(t, doc) {
			if path, _ := tree.resolve(inv.args); len(path) > 0 {
				documented[strings.Join(path, " ")] = true
			}
		}
	}

	for _, path := range sortedKeys(tree.byPath) {
		if !tree.byPath[path].Runnable || documented[path] {
			continue
		}
		if reason, exempt := undocumentedByDecision[path]; exempt {
			if reason == "" {
				t.Errorf("`kanonarion %s` is exempt from documentation with no reason given: state why it needs none", path)
			}
			continue
		}
		t.Errorf("`kanonarion %s` ships and no document under docs/ shows it being run: "+
			"add a fenced example, or name it in undocumentedByDecision with the reason it needs none", path)
	}

	for path, reason := range undocumentedByDecision {
		if _, live := tree.byPath[path]; !live {
			t.Errorf("undocumentedByDecision exempts %q (%s), which is not a registered command: the exemption outlived what it exempted", path, reason)
		}
	}
}

// pinnedExampleByDecision names the example coordinates that are deliberately a
// version this repository pins, keyed by "<doc> <coordinate>", with the reason.
// `dependents` answers about the build you are standing in, and the output
// recorded beneath it is this repository's own walk, so that one example has to
// name a coordinate this go.mod resolves. Every other example must survive a
// bump, which is why this is a list of decisions and not a rule.
var pinnedExampleByDecision = map[string]string{
	"../docs/getting-started.md github.com/spf13/pflag@v1.0.10": "`dependents` is answered from the build you are in, and the output recorded beneath it is this repository's own walk",
}

// TestOnboardingExampleCoordinatesAreNotThisModulesOwnPins fails when a teaching
// document uses a module version this repository itself pins.
//
// Such an example is strandable: the store holds that version because this
// repository's own walks put it there, and the next bump of that dependency
// takes it away. The reader then runs the documented command and is told the
// coordinate has no record — which is how `golang.org/x/mod@v0.36.0` came to be
// the one example in the quality guide while the go.mod had moved to v0.40.0.
//
// The pins are read from go.mod, so the guard cannot go stale against it.
//
// It does NOT check that each coordinate resolves against a populated store:
// that store is the operator's ~/.kanonarion, and a test that opens it would
// migrate a production database on every `make test`. What is checkable
// offline is the property that makes an example survive a bump at all.
func TestOnboardingExampleCoordinatesAreNotThisModulesOwnPins(t *testing.T) {
	raw, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	mf, err := modfile.Parse("go.mod", raw, nil)
	if err != nil {
		t.Fatalf("parsing go.mod: %v", err)
	}
	pinned := map[string]string{}
	for _, req := range mf.Require {
		pinned[req.Mod.Path] = req.Mod.Version
	}
	if len(pinned) == 0 {
		t.Fatal("go.mod requires nothing: this guard would then pass over any example")
	}

	seen := 0
	exempted := map[string]bool{}
	for _, doc := range onboardingDocs {
		for _, inv := range fencedInvocations(t, doc) {
			for _, arg := range inv.args {
				arg = strings.Trim(arg, "'\"")
				if strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, "<>") || !strings.Contains(arg, "@") {
					continue
				}
				coord, cerr := coordinate.ParseModuleCoordinate(arg)
				if cerr != nil || !strings.HasPrefix(coord.Version(), "v") {
					continue
				}
				seen++
				if pinned[coord.Path()] != coord.Version() {
					continue
				}
				key := doc + " " + arg
				if reason, ok := pinnedExampleByDecision[key]; ok {
					exempted[key] = true
					if reason == "" {
						t.Errorf("%s:%d is exempt from the stranding rule with no reason given: state why the example has to name a pinned version", inv.doc, inv.line)
					}
					continue
				}
				t.Errorf("%s:%d uses %s as an example, which is the version this repository's own go.mod pins: "+
					"the next bump of %s strands it, so pick a version this module does not depend on, "+
					"or name it in pinnedExampleByDecision with the reason it has to be pinned",
					inv.doc, inv.line, arg, coord.Path())
			}
		}
	}
	if seen == 0 {
		t.Fatalf("no example coordinate was read out of %v: the guard reads nothing", onboardingDocs)
	}
	for key, reason := range pinnedExampleByDecision {
		if !exempted[key] {
			t.Errorf("pinnedExampleByDecision exempts %q (%s), and no such pinned example is there any more: the exemption outlived what it exempted", key, reason)
		}
	}
}

// docFlags returns the long flag names written on one documented invocation.
//
// A synopsis line writes its optional flags in brackets and its exclusive ones
// as an alternation - `[--tool|--project]` - and a worked example attaches the
// value with `=`. None of that is part of the flag's name, so it is stripped
// here rather than in the guard. Short flags and a bare `--` are out of scope:
// a single letter says too little to be worth holding a document to.
func docFlags(args []string) []string {
	var out []string
	for _, arg := range args {
		for _, tok := range strings.Split(arg, "|") {
			tok = strings.Trim(tok, "[](),'\"`")
			if !strings.HasPrefix(tok, "--") || tok == "--" {
				continue
			}
			name := strings.Trim(strings.SplitN(tok[2:], "=", 2)[0], "[](),'\"`")
			if name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

// TestShippedDocsUseOnlyRealFlags fails when a document writes a long flag on a
// command that does not accept it.
//
// The flag is resolved against the command it is WRITTEN ON, subcommand
// included: `--event-type` belongs to `store ledger` and not to `store`, and
// checking it against the parent would pass a flag the reader cannot use. The
// accepted set is read from the assembled command tree, persistent and
// inherited flags included, because `--json` and `--store-root` are declared on
// the root and are legitimately typed on every command beneath it.
//
// Fenced blocks only, for the reason the command guard reads them: prose
// discusses flags it is not telling anyone to type.
func TestShippedDocsUseOnlyRealFlags(t *testing.T) {
	tree := registeredCommands(t)
	uses, commands := 0, map[string]bool{}
	for _, doc := range shippedDocs(t) {
		for _, inv := range fencedInvocations(t, doc) {
			path, _ := tree.resolve(inv.args)
			if len(path) == 0 {
				continue // the command guard reports this line
			}
			named := strings.Join(path, " ")
			accepted := map[string]bool{}
			for _, f := range tree.byPath[named].Flags {
				accepted[f] = true
			}
			for _, f := range docFlags(inv.args) {
				uses++
				commands[named] = true
				if !accepted[f] {
					t.Errorf("%s:%d writes --%s on `kanonarion %s`, which does not accept it: "+
						"`%s`\n\tuse the flag the command has, or move the line to the command that has this one",
						inv.doc, inv.line, f, named, inv.text)
				}
			}
		}
	}
	if uses == 0 {
		t.Fatal("no flag was read off any documented invocation: the guard reads nothing")
	}
	t.Logf("checked %d flag uses across %d commands", uses, len(commands))
}

// TestDocumentedFlagsResolveToTheSubcommand pins the case the flag guard exists
// to get right, with the real invocation from the shipped documentation.
//
// `--event-type` is declared on `store ledger`. Its parent `store` does not
// have it, so a guard that resolved a flag to the first word after the program
// name would accept `kanonarion store --event-type …`, which is refused when a
// reader types it. The assertion is on the tree, not on a copy of it.
func TestDocumentedFlagsResolveToTheSubcommand(t *testing.T) {
	tree := registeredCommands(t)
	has := func(path, flag string) bool {
		for _, f := range tree.byPath[path].Flags {
			if f == flag {
				return true
			}
		}
		return false
	}
	if !has("store ledger", "event-type") {
		t.Error("`store ledger` no longer declares --event-type: the documented invocation this guard is built on has moved")
	}
	if has("store", "event-type") {
		t.Error("`store` now declares --event-type, so it no longer distinguishes a flag resolved to the parent from one resolved to the subcommand")
	}

	found := false
	for _, doc := range shippedDocs(t) {
		for _, inv := range fencedInvocations(t, doc) {
			path, _ := tree.resolve(inv.args)
			if strings.Join(path, " ") != "store ledger" {
				continue
			}
			for _, f := range docFlags(inv.args) {
				if f == "event-type" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("no shipped document writes --event-type on `store ledger` any more: this guard is pinned to a case the documentation no longer contains")
	}
}

// TestEveryCommandDeclaresItsStoreIntent fails when a runnable command says
// nothing about whether running it may create the store root.
//
// The declaration is a cobra annotation on the command, so it lives beside the
// command and a new one carries it without editing a list here. This guard is
// what makes "beside the command" a rule rather than a habit: a command added
// with no annotation still fails safe at runtime — the default is read, which
// refuses a root that is not there — but silently inheriting a default is not
// the same as having decided, and the difference is exactly what goes wrong
// when the next writing command is added and refuses to run on a clean machine.
//
// Only runnable commands are checked. A grouping command such as `store` is
// never executed, so cobra returns its help before any PersistentPreRunE, and
// nothing it could declare would ever be read.
func TestEveryCommandDeclaresItsStoreIntent(t *testing.T) {
	valid := map[string]bool{
		cli.StoreIntentRead:   true,
		cli.StoreIntentCreate: true,
		cli.StoreIntentNone:   true,
	}

	checked := 0
	for _, c := range cli.RegisteredCommands() {
		if !c.Runnable {
			continue
		}
		checked++
		path := strings.Join(c.Path, " ")
		switch {
		case c.StoreIntent == "":
			t.Errorf("`kanonarion %s` declares no store intent: add %q to its cobra Annotations with %s if it writes records into the store root, %s if it reads them, or %s if it opens no store",
				path, "kanonarion/store-intent", "cli.StoreIntentCreate", "cli.StoreIntentRead", "cli.StoreIntentNone")
		case !valid[c.StoreIntent]:
			t.Errorf("`kanonarion %s` declares store intent %q, which this build does not know: it will be treated as %q and refuse a store root that does not exist",
				path, c.StoreIntent, cli.StoreIntentRead)
		}
	}

	if checked == 0 {
		t.Fatal("the CLI registered no runnable commands: this guard would then hold nothing to anything")
	}
}

// hiddenFlagNames is every long flag name the CLI registers somewhere and hides
// there.
//
// Hiding is this codebase's marker for a flag registered to be EXPLAINED rather
// than offered: registerRecordedTestScopeFlag installs --exclude-tests hidden on
// the commands that record a walk precisely so the refusal can say why. The set
// is therefore the set of flags a command may decline at runtime, and it is read
// off the command tree rather than restated, so a flag that joins the class
// joins this guard with it.
func hiddenFlagNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, c := range cli.RegisteredCommands() {
		for _, name := range c.HiddenFlags {
			out[name] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("the CLI hides no flag: the guard below would then execute nothing and hold every document to nothing")
	}
	return out
}

// TestShippedDocsNameNoRefusedFlag catches the case TestShippedDocsUseOnlyRealFlags
// cannot: a flag the command REGISTERS and then REFUSES.
//
// `audit` registers --exclude-tests and declines it at runtime, because it
// records a walk and a walk record names its scope but not its test axis. The
// flag is therefore in the command's flag set, so a guard that asks the command
// tree "do you accept this flag" answers yes, and documentation advertising
// `kanonarion audit --exclude-tests` passes. It was written into
// writing-quality-code.md that way and shipped through the flag guard untouched.
//
// The distinction the tree cannot make is made by running the invocation. The
// refusal is raised after the go.mod scope resolves, not during flag parsing, so
// the invocation is given this repository's own go.mod when it names no scope of
// its own - without that it dies on "./go.mod not found" and never reaches the
// check. Any other failure - no store, no walk, no network - is not this guard's
// business and is ignored, which is what lets a documented invocation that simply
// needs data pass here.
//
// Only invocations naming a HIDDEN flag are run, and running is the whole cost
// of this guard. Executing every flag-bearing line in the shipped docs walks
// module graphs and fills a store for each one: it fetched 122MB of blobs per
// run and it is not what the guard reads, because a flag no command hides is a
// flag no command declines. Hidden is the marker - see hiddenFlagNames - so the
// narrowing follows the refusals rather than guessing at them.
func TestShippedDocsNameNoRefusedFlag(t *testing.T) {
	const refusal = "does not act on --"
	hidden := hiddenFlagNames(t)
	store := t.TempDir()
	checked := 0
	for _, doc := range shippedDocs(t) {
		for _, inv := range fencedInvocations(t, doc) {
			if !slices.ContainsFunc(docFlags(inv.args), func(f string) bool { return hidden[f] }) {
				continue // no flag any command declines
			}
			checked++
			args := append([]string{}, inv.args...)
			if !slices.Contains(args, "--gomod") && !slices.Contains(args, "--walk-id") {
				args = append(args, "--gomod", "../go.mod")
			}
			args = append(args, "--store-root", store)
			var stdout, stderr bytes.Buffer
			err := cli.Run(args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), refusal) {
				continue
			}
			t.Errorf("%s:%d documents an invocation the command refuses: `%s`\n\t%v"+
				"\n\tthe flag is registered on the command, so the flag guard accepts it;"+
				" only running it shows the refusal. Move the line to a command that acts on the flag.",
				inv.doc, inv.line, inv.text, err)
		}
	}
	t.Logf("executed %d documented invocations naming a hidden flag", checked)
}
