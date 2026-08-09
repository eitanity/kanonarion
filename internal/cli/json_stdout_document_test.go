package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// assertSingleJSONDocument checks that b is exactly one JSON document and
// nothing else: no prose before it, and nothing after it but whitespace.
//
// It is the shared guard for the defect class where a command closes its JSON
// object and then appends a caveat, tip or warning to stdout — output that
// reads fine to a human and fails every parser. The decoder is used rather
// than json.Unmarshal because Unmarshal on a prefix of the stream is not the
// test: the trailing bytes are exactly what has to fail.
func assertSingleJSONDocument(t *testing.T, what string, b []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%s: stdout is not a JSON document: %v\nstdout:\n%s", what, err, b)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		rest := strings.TrimSpace(string(b[dec.InputOffset():]))
		t.Fatalf("%s: stdout carries %d bytes after the JSON document — a parser sees this and fails:\n%s",
			what, len(rest), rest)
	}
	return doc
}

// assertSingleJSONValue is assertSingleJSONDocument for commands whose document
// is an array rather than an object (the list commands). The trailing-bytes
// assertion is the same; only the top-level shape differs.
func assertSingleJSONValue(t *testing.T, what string, b []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%s: stdout is not a JSON document: %v\nstdout:\n%s", what, err, b)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		rest := strings.TrimSpace(string(b[dec.InputOffset():]))
		t.Fatalf("%s: stdout carries %d bytes after the JSON document — a parser sees this and fails:\n%s",
			what, len(rest), rest)
	}
}

// jsonStdoutCase is how one command is exercised under --json, or the stated
// reason it is not.
type jsonStdoutCase struct {
	// args are the arguments after the command path. Empty means the command
	// is run bare.
	args []string
	// skip, when non-empty, states why this command is not run here. It is a
	// sentence, not a flag: a command excluded without a reason is a hole in
	// the guard that nobody can see.
	skip string
}

// jsonStdoutCases enumerates EVERY command in the cobra tree, because --json is
// a persistent flag on the root: every command accepts it, so every command is
// a candidate for the defect. The completeness test below asserts this map and
// the tree name the same set, so a command added later fails the build until
// somebody decides how it behaves under --json.
//
// Commands are run against an empty store in an empty working directory. Most
// therefore fail before producing output, which is a real result for this
// guard — a command that writes nothing to stdout writes no prose to stdout
// either. The ones that do produce a document (the list commands, config show,
// store info) are where the assertion bites, and license-compat has its own
// fixture-driven test that drives a full document with conflicts, coverage
// holes and the pre-modules caveat all present at once.
var jsonStdoutCases = map[string]jsonStdoutCase{
	"audit":                 {},
	"callees":               {},
	"callers":               {},
	"callgraph":             {},
	"callgraph-list":        {},
	"callgraph-show":        {},
	"capability":            {},
	"config":                {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"config get":            {},
	"config init":           {skip: "no JSON rendering: it writes a plain-text status line even under --json, which is a different question from prose appended to a JSON document"},
	"config set":            {},
	"config show":           {},
	"context":               {},
	"dependents":            {},
	"directives":            {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"directives diff":       {},
	"directives list":       {},
	"directives show":       {},
	"examples":              {},
	"examples-find":         {},
	"examples-list":         {},
	"examples-show":         {},
	"extract":               {},
	"extract list":          {},
	"extract show":          {},
	"fetch":                 {},
	"fips":                  {},
	"godebug":               {},
	"implementers":          {},
	"inspect":               {},
	"interface":             {},
	"interface-diff":        {},
	"interface-list":        {},
	"interface-show":        {},
	"latest":                {},
	"license":               {},
	"license-compat":        {},
	"license-diff":          {},
	"license-list":          {},
	"local":                 {skip: "ingests the working tree's call graph; the guard runs in an empty directory, so this would measure the harness rather than the command"},
	"notice":                {},
	"policy":                {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"policy show":           {},
	"policy validate":       {},
	"provenance":            {},
	"reachability":          {},
	"sbom":                  {},
	"sbom-list":             {},
	"sbom-show":             {},
	"store":                 {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"store clean":           {skip: "no JSON rendering: it writes a plain-text status line even under --json, which is a different question from prose appended to a JSON document"},
	"store config":          {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"store config show":     {},
	"store info":            {},
	"store ledger":          {},
	"symbol-context":        {},
	"symbol-find":           {},
	"use":                   {},
	"vendor":                {},
	"verification-coverage": {},
	"vuln":                  {},
	"vuln-by-id":            {},
	"vuln-scan":             {},
	"vuln-scan-diff":        {},
	"vuln-scan-history":     {},
	"vuln-scan-list":        {},
	"vuln-scan-rescan":      {},
	"vuln-scan-show":        {},
	"vuln-show":             {},
	"vuln-snapshot-list":    {},
	"vuln-snapshot-show":    {},
	"walk":                  {},
	"walk-diff":             {},
	"walk-list":             {},
	"walk-show":             {},
}

// commandPaths returns every command in the tree by the path a caller types,
// root name stripped.
func commandPaths(root *cobra.Command) []string {
	var out []string
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		if c != root {
			out = append(out, strings.TrimPrefix(c.CommandPath(), root.Name()+" "))
		}
		for _, sub := range c.Commands() {
			visit(sub)
		}
	}
	visit(root)
	sort.Strings(out)
	return out
}

// TestJSONStdoutGuard_CoversEveryCommand keeps the guard honest. A helper
// applied to a hand-written list silently misses the command added next month;
// this fails instead, naming it.
func TestJSONStdoutGuard_CoversEveryCommand(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	inTree := map[string]bool{}
	for _, p := range commandPaths(root) {
		inTree[p] = true
		if _, ok := jsonStdoutCases[p]; !ok {
			t.Errorf("command %q is in the tree but not in jsonStdoutCases: decide how it behaves under --json", p)
		}
	}
	for p := range jsonStdoutCases {
		if !inTree[p] {
			t.Errorf("jsonStdoutCases names %q, which is not a command: remove it", p)
		}
	}
}

// TestJSONStdoutIsExactlyOneDocument runs every enumerated command under --json
// and asserts stdout is either empty or exactly one JSON document. It is the
// regression guard for prose appended to stdout after the document.
func TestJSONStdoutIsExactlyOneDocument(t *testing.T) {
	names := make([]string, 0, len(jsonStdoutCases))
	for name := range jsonStdoutCases {
		names = append(names, name)
	}
	sort.Strings(names)

	// An empty working directory: the commands that default to ./go.mod fail on
	// its absence rather than resolving a build list or reaching the network.
	chdirWithGoMod(t, "")
	store := t.TempDir()

	var ran, documents int
	for _, name := range names {
		tc := jsonStdoutCases[name]
		if tc.skip != "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			args := append(strings.Fields(name), tc.args...)
			args = append(args, "--json", "--store-root", store)
			var stdout, stderr bytes.Buffer
			// The error is deliberately ignored: a command that refuses is a
			// valid outcome here. What it wrote to stdout is the assertion.
			_ = Run(args, &stdout, &stderr)
			ran++
			if strings.TrimSpace(stdout.String()) == "" {
				return
			}
			documents++
			assertSingleJSONValue(t, name, stdout.Bytes())
		})
	}
	// Reported so the guard's real reach is visible rather than assumed: the
	// commands that produced nothing were exercised, but proved nothing.
	t.Logf("enumerated %d commands, ran %d, %d produced a document on an empty store",
		len(jsonStdoutCases), ran, documents)
}
