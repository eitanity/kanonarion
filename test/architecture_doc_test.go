package cmd_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
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
