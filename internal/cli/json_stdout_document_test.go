package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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
	// the guard that nobody can see. It names what it would take to make the
	// command answer, because a reason that restates the symptom — "it writes
	// nothing", "it fails early" — is the hole with a sentence in front of it.
	skip string
	// argsFn builds arguments that only exist at run time, such as a path into
	// the fixture. It replaces args when set.
	argsFn func(t *testing.T, fx jsonStdoutFixture) []string
}

// policyValidateFixtureArgs names a directory of valid policy files.
//
// Without it `policy validate` runs bare in the guard's empty working
// directory and fails on the missing <path> before writing anything. A temp
// directory is used rather than the repository's own docs/examples/policies
// because the guard chdirs away from the package directory first, so a
// repository-relative path would resolve to nothing.
func policyValidateFixtureArgs(t *testing.T, _ jsonStdoutFixture) []string {
	t.Helper()
	dir := t.TempDir()
	const policy = "version: \"1\"\nstages:\n  fetch:\n    max_depth: 1\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(policy), 0o600); err != nil {
		t.Fatalf("writing policy fixture: %v", err)
	}
	return []string{dir}
}

// localTreeArgs names the fixture's working tree for `local`, which analyses a
// directory rather than a go.mod.
func localTreeArgs(_ *testing.T, fx jsonStdoutFixture) []string {
	return []string{fx.treeDir}
}

// goModArgs scopes a command to the fixture's working tree. The tree's module
// requires nothing, so the build list resolves without leaving the directory
// and the command reaches its rendering without a proxy.
func goModArgs(_ *testing.T, fx jsonStdoutFixture) []string {
	return []string{"--gomod", fx.goMod()}
}

// jsonStdoutCases enumerates EVERY command in the cobra tree, because --json is
// a persistent flag on the root: every command accepts it, so every command is
// a candidate for the defect. The completeness test below asserts this map and
// the tree name the same set, so a command added later fails the build until
// somebody decides how it behaves under --json.
//
// Every case that runs must produce a document. A command is given whatever it
// needs to reach its rendering — a coordinate, an identifier the fixture store
// holds a record under, a path into the fixture's working tree — because a
// refusal writes nothing to stdout, and a case that passed on silence proved
// only that the command had failed before the code under test ran.
//
// The commands that record a run are here too, and stay off the network: walk
// and callgraph serve the record the fixture already holds rather than
// re-analysing, and extract and vuln-scan render a run over artefacts whose
// bytes the fixture does not carry. Each renders through its real writer, which
// is what this guard reads.
//
// A command that cannot be made to answer here carries a skip naming what it
// would take. Two classes account for all of them: a command with no JSON
// rendering at all, which is a different question from prose appended to a JSON
// document, and a command that must leave the fixture for the network.
var jsonStdoutCases = map[string]jsonStdoutCase{
	"audit":          {argsFn: goModArgs},
	"callees":        {args: []string{jsonDocNodeID}},
	"callers":        {args: []string{jsonDocMethodID}},
	"callgraph":      {args: []string{jsonDocDepCoord}},
	"callgraph-list": {},
	"callgraph-show": {args: []string{jsonDocDepCoord}},
	"capability":     {args: []string{jsonDocDepCoord}},
	"config":         {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"config get": {skip: "no JSON rendering: it prints the value in force for one key as plain text — a bare string for a scalar, a YAML fragment for a structured one — under --json as well. " +
		"Answering here needs a document defined for a single configuration value, which is the question config init raises"},
	"config init":     {skip: "no JSON rendering: it writes a plain-text status line even under --json, which is a different question from prose appended to a JSON document"},
	"config set":      {skip: "no JSON rendering: it acknowledges the write with a plain-text line even under --json, the same question config init raises"},
	"config show":     {},
	"context":         {args: []string{jsonDocDepCoord}},
	"dependents":      {args: []string{jsonDocDepCoord, "--walk-id", jsonDocWalkID}},
	"directives":      {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"directives diff": {args: []string{jsonDocDirScanID, jsonDocDirScanID}},
	"directives list": {args: []string{"--project", jsonDocRootPath}},
	"directives show": {args: []string{jsonDocDirScanID}},
	"examples":        {args: []string{jsonDocDepCoord}},
	"examples-find":   {args: []string{jsonDocSymbol}},
	"examples-list":   {},
	"examples-show":   {args: []string{jsonDocDepCoord, jsonDocExample}},
	"extract":         {args: []string{jsonDocWalkID}},
	"extract list":    {},
	"extract show":    {args: []string{jsonDocExtractID}},
	"fetch": {skip: "acquires module bytes from a proxy: it does not serve the fixture's fetch record in their place, and --from-modcache only moves the source of the bytes off the network onto a module cache the guard does not populate. " +
		"Answering here needs a proxy the guard stands up itself"},
	"fips":           {argsFn: goModArgs},
	"godebug":        {argsFn: goModArgs},
	"implementers":   {args: []string{jsonDocIfaceID}},
	"inspect":        {argsFn: goModArgs},
	"interface":      {args: []string{jsonDocDepCoord}},
	"interface-diff": {args: []string{jsonDocDepCoord, jsonDocDepCoord}},
	"interface-list": {},
	"interface-show": {args: []string{jsonDocDepCoord}},
	"latest":         {argsFn: goModArgs},
	"license":        {args: []string{jsonDocDepCoord}},
	"license-compat": {args: []string{jsonDocRootCoord}},
	"license-diff":   {args: []string{jsonDocDepCoord, jsonDocDepCoord}},
	"license-list":   {},
	"local":          {argsFn: localTreeArgs},
	"native":         {args: []string{jsonDocDepCoord}},
	"notice": {skip: "no JSON rendering: stdout is the THIRD-PARTY-LICENSES attribution document, which is plain text because that is the form it is published in, and --json does not change it. " +
		"Answering here needs a decision about what an attribution document is as JSON"},
	"policy":                {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"policy show":           {},
	"policy validate":       {argsFn: policyValidateFixtureArgs},
	"provenance":            {args: []string{jsonDocDepCoord}},
	"reachability":          {args: []string{jsonDocDepCoord, "--vuln", jsonDocFindingID}},
	"sbom":                  {args: []string{jsonDocWalkID}},
	"sbom-list":             {},
	"sbom-show":             {args: []string{jsonDocSBOMID}},
	"store":                 {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"store clean":           {skip: "no JSON rendering: it writes a plain-text status line even under --json, which is a different question from prose appended to a JSON document"},
	"store config":          {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"store config show":     {},
	"store info":            {},
	"store ledger":          {},
	"symbol-context":        {args: []string{jsonDocDepCoord, jsonDocSymbol}},
	"symbol-find":           {args: []string{jsonDocSymbol}},
	"use":                   {skip: "no JSON rendering: stdout is one plain path line per module copied into a module cache, and --json does not change it. Answering here needs a document defined for a copy"},
	"vendor":                {argsFn: goModArgs},
	"verification-coverage": {args: []string{jsonDocWalkID}},
	"vuln":                  {args: []string{jsonDocDepCoord}},
	"vuln-by-id":            {args: []string{jsonDocFindingID}},
	"vuln-scan":             {args: []string{jsonDocWalkID}},
	"vuln-scan-diff":        {args: []string{jsonDocScanRunID, jsonDocScanRunID}},
	"vuln-scan-history":     {args: []string{jsonDocWalkID}},
	"vuln-scan-list":        {},
	"vuln-scan-rescan": {skip: "no JSON rendering: it writes three plain-text lines — completion summary, run id, snapshot — even under --json. " +
		"--snapshot-source/--snapshot-version already pin it to a stored snapshot and keep it off the network, so a document is the only thing missing"},
	"vuln-scan-show":     {args: []string{jsonDocScanRunID}},
	"vuln-show":          {args: []string{jsonDocDepCoord}},
	"vuln-snapshot-list": {},
	"vuln-snapshot-show": {args: []string{jsonDocSnapSource, jsonDocSnapshotV}},
	"walk":               {args: []string{jsonDocRootCoord}},
	"walk-diff":          {args: []string{jsonDocWalkID, jsonDocWalkID}},
	"walk-list":          {},
	"walk-show":          {args: []string{jsonDocWalkID}},
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
// and asserts stdout is exactly one JSON document. It is the regression guard
// for prose appended to stdout after the document.
//
// There is no third path: a case either produces a document or carries a skip.
// Empty stdout is a failure, because a command that wrote nothing rendered
// nothing, and a case that accepted that asserted nothing about the rendering.
func TestJSONStdoutIsExactlyOneDocument(t *testing.T) {
	names := make([]string, 0, len(jsonStdoutCases))
	for name := range jsonStdoutCases {
		names = append(names, name)
	}
	sort.Strings(names)

	// One store and one working tree for the whole guard. The commands that
	// record a run write into the same store the readers read, which is the
	// state a real operator's store is in.
	fx := newJSONStdoutFixture(t)
	// The working directory is empty and outside any module: a command that
	// defaults to ./go.mod is then scoped by the --gomod its case passes, not by
	// whatever tree the test binary happens to be run from.
	chdirWithGoMod(t, "")

	var ran, documents int
	for _, name := range names {
		tc := jsonStdoutCases[name]
		if tc.skip != "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			extra := tc.args
			if tc.argsFn != nil {
				extra = tc.argsFn(t, fx)
			}
			args := append(strings.Fields(name), extra...)
			args = append(args, "--json", "--store-root", fx.storeRoot)
			var stdout, stderr bytes.Buffer
			// The error is deliberately ignored: a command that reports a
			// non-clean finding is a valid outcome here. What it wrote to stdout
			// is the assertion.
			_ = Run(args, &stdout, &stderr)
			ran++
			if strings.TrimSpace(stdout.String()) == "" {
				t.Fatalf("%s wrote nothing to stdout, so this case asserts nothing about its JSON rendering: "+
					"give it what it needs to answer, or a skip saying what that would take.\nstderr:\n%s",
					name, stderr.String())
			}
			documents++
			assertSingleJSONValue(t, name, stdout.Bytes())
		})
	}
	// The floor, not a warning: every command that ran answered. A later change
	// that silences one fails here rather than quietly shrinking the guard.
	if documents != ran {
		t.Errorf("%d of %d commands that ran produced a document; every one must", documents, ran)
	}
	t.Logf("enumerated %d commands, ran %d, %d produced a document", len(jsonStdoutCases), ran, documents)
}
