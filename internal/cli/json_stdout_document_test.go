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
// assertion is the same; only the top-level shape differs. It returns the
// decoded value so a caller can go on to ask what is in it.
func assertSingleJSONValue(t *testing.T, what string, b []byte) any {
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
	return doc
}

// assertSeveralRecords checks that a several-record case really put more than
// one record in the answer, and that the answer holding them is one document
// with the records in an array.
//
// Both halves are the point. An invocation that yielded one record after all
// leaves the case looking covered while asking the same question as the
// single-record case above it. And a several-record answer whose records are not
// in an array is the defect itself: a top-level type that follows the result
// count, or a stream of documents one per line, which no parser reads as one
// answer.
//
// Two framings are accepted, because the tree holds both and the distinction is
// not this guard's question. A listing answers with the array itself. A command
// that also has facts about the RUN to state — which scope resolved the rows,
// which build they were read in — answers with an envelope whose `modules` holds
// them, because an array has nowhere to put those. What is asserted either way
// is that the records are in one array of one document, whatever their number.
func assertSeveralRecords(t *testing.T, what string, doc any) {
	t.Helper()
	arr, ok := recordsOf(doc)
	if !ok {
		t.Fatalf("%s: the top-level JSON type is %T with no modules array in it, want an array of records "+
			"or an envelope carrying one: a command answering per module must not change shape with the "+
			"number of records", what, doc)
	}
	if len(arr) < 2 {
		t.Fatalf("%s: the answer holds %d record(s), so the several-record case asked the same question "+
			"as the single-record one: point it at a scope with more than one module", what, len(arr))
	}
}

// recordsOf finds the per-record array in a decoded answer: the document itself
// when it is one, or its `modules` member when the records are enveloped.
func recordsOf(doc any) ([]any, bool) {
	switch t := doc.(type) {
	case []any:
		return t, true
	case map[string]any:
		arr, ok := t["modules"].([]any)
		return arr, ok
	default:
		return nil, false
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
	// setup runs before the command and puts the process in a state the case
	// needs. It exists for the one command whose blast radius reaches outside
	// the fixture; see isolateTempDir.
	setup func(t *testing.T, fx jsonStdoutFixture)
}

// isolateTempDir points os.TempDir at a directory of the case's own.
//
// `store clean` sweeps the system temp directory by prefix without asking
// whether an entry is in use, so a guard that let it run against the real one
// would delete the working files of any kanonarion process scanning on the same
// machine — which is what the command's own help warns about, and what a
// measurement run was once lost to. The isolated directory is empty, so the
// sweep answers zero, which is exactly the state the document has to be able to
// state rather than leave to inference.
func isolateTempDir(t *testing.T, _ jsonStdoutFixture) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
}

// policyValidateFixtureArgs names a directory of valid policy files.
//
// Without it `policy validate` runs bare in the guard's empty working
// directory and fails on the missing <path> before writing anything. A temp
// directory is used rather than the repository's own docs/examples/policies
// because the guard chdirs away from the package directory first, so a
// repository-relative path would resolve to nothing.
// useCopyArgs points `use` at the fixture's walk and at a module cache the test
// owns.
//
// The cache is not optional. Without --mod-cache the command writes into the
// operator's own GOMODCACHE, so the guard would populate a real module cache on
// every run. The fixture holds fetch records and no blobs, so every module fails
// to copy — which is the case worth exercising here: it is the outcome that used
// to appear on stderr only, leaving stdout reading like a complete copy.
func useCopyArgs(t *testing.T, _ jsonStdoutFixture) []string {
	t.Helper()
	return []string{jsonDocRootCoord, "--recursive", "--walk-id", jsonDocWalkID, "--mod-cache", t.TempDir()}
}

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
	"config get":     {args: []string{"preferences.json"}},
	"config init":    {},
	// A key set to the value it already resolves to. The guard's commands share
	// one store, so a write that changed a preference would change what every
	// case after this one runs under.
	"config set":      {args: []string{"preferences.log_level", "warn"}},
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
	"notice": {skip: "renders one form by design: stdout is the THIRD-PARTY-LICENSES attribution document, the deliverable artefact itself, and --json is a documented no-op that returns the same bytes. " +
		"There is no machine-readable projection and there will not be one; the underlying data is served by license-list --json and sbom"},
	"policy":                {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"policy show":           {},
	"policy validate":       {argsFn: policyValidateFixtureArgs},
	"provenance":            {args: []string{jsonDocDepCoord}},
	"reachability":          {args: []string{jsonDocDepCoord, "--vuln", jsonDocFindingID}},
	"sbom":                  {args: []string{jsonDocWalkID}},
	"sbom-list":             {},
	"sbom-show":             {args: []string{jsonDocSBOMID}},
	"store":                 {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"store clean":           {setup: isolateTempDir},
	"store config":          {skip: "command group: cobra prints its help text; it renders no answer of its own"},
	"store config show":     {},
	"store info":            {},
	"store ledger":          {},
	"symbol-context":        {args: []string{jsonDocDepCoord, jsonDocSymbol}},
	"symbol-find":           {args: []string{jsonDocSymbol}},
	"use":                   {argsFn: useCopyArgs},
	"vendor":                {argsFn: goModArgs},
	"verification-coverage": {args: []string{jsonDocWalkID}},
	"vuln":                  {args: []string{jsonDocDepCoord}},
	"vuln-by-id":            {args: []string{jsonDocFindingID}},
	"vuln-scan":             {args: []string{jsonDocWalkID}},
	"vuln-scan-diff":        {args: []string{jsonDocScanRunID, jsonDocScanRunID}},
	"vuln-scan-history":     {args: []string{jsonDocWalkID}},
	"vuln-scan-list":        {},
	"vuln-scan-rescan":      {args: []string{jsonDocWalkID, "--snapshot-source", jsonDocSnapSource, "--snapshot-version", jsonDocSnapshotV}},
	"vuln-scan-show":        {args: []string{jsonDocScanRunID}},
	"vuln-show":             {args: []string{jsonDocDepCoord}},
	"vuln-snapshot-list":    {},
	"vuln-snapshot-show":    {args: []string{jsonDocSnapSource, jsonDocSnapshotV}},
	"walk":                  {args: []string{jsonDocRootCoord}},
	"walk-diff":             {args: []string{jsonDocWalkID, jsonDocWalkID}},
	"walk-list":             {},
	"walk-show":             {args: []string{jsonDocWalkID}},
}

// walkScopeArgs scopes a command to the fixture's walk, whose graph holds two
// modules. It is how a command that answers per module is made to answer about
// more than one of them without leaving the fixture.
func walkScopeArgs(_ *testing.T, _ jsonStdoutFixture) []string {
	return []string{"--walk-id", jsonDocWalkID}
}

// latestMultiArgs names the two modules the fixture holds recorded lookups for,
// so `latest` answers about both of them from the store rather than the proxy.
func latestMultiArgs(_ *testing.T, _ jsonStdoutFixture) []string {
	return []string{jsonDocRootPath, jsonDocDep.Path()}
}

// jsonStdoutMultiCases is the second invocation for the commands whose answer
// holds one record PER MODULE, chosen to put more than one record in it.
//
// The single-record invocation above cannot see the defect these commands are
// prone to: a command that frames one record as a document and a sequence of
// them as one document per line, or as a bare object at one result and an array
// at two, passes there and fails for every caller who asked a question with
// more than one answer. The shape has to be exercised at the count that varies
// it, or the guard reports a command as covered that was never asked the
// question.
//
// Every key must also appear in jsonStdoutCases; the completeness test asserts
// it, so a command cannot be exercised here and left undecided there.
var jsonStdoutMultiCases = map[string]jsonStdoutCase{
	"context": {argsFn: walkScopeArgs},
	"latest":  {argsFn: latestMultiArgs},
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
	for p := range jsonStdoutMultiCases {
		if _, ok := jsonStdoutCases[p]; !ok {
			t.Errorf("jsonStdoutMultiCases names %q, which jsonStdoutCases does not: "+
				"a command exercised at several records must be decided at one too", p)
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
	run := func(t *testing.T, what, name string, tc jsonStdoutCase, several bool) {
		t.Helper()
		if tc.setup != nil {
			tc.setup(t, fx)
		}
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
				what, stderr.String())
		}
		documents++
		doc := assertSingleJSONValue(t, what, stdout.Bytes())
		if several {
			assertSeveralRecords(t, what, doc)
		}
	}

	for _, name := range names {
		tc := jsonStdoutCases[name]
		if tc.skip != "" {
			continue
		}
		t.Run(name, func(t *testing.T) { run(t, name, name, tc, false) })
	}

	// The commands that answer per module, asked a question with more than one
	// answer. Run after the single-record cases so a failure names which of the
	// two counts broke.
	multi := make([]string, 0, len(jsonStdoutMultiCases))
	for name := range jsonStdoutMultiCases {
		multi = append(multi, name)
	}
	sort.Strings(multi)
	for _, name := range multi {
		tc := jsonStdoutMultiCases[name]
		if tc.skip != "" {
			continue
		}
		what := name + " (several records)"
		t.Run(name+"_multi", func(t *testing.T) { run(t, what, name, tc, true) })
	}

	// The floor, not a warning: every command that ran answered. A later change
	// that silences one fails here rather than quietly shrinking the guard.
	if documents != ran {
		t.Errorf("%d of %d commands that ran produced a document; every one must", documents, ran)
	}
	t.Logf("enumerated %d commands and %d several-record cases, ran %d, %d produced a document",
		len(jsonStdoutCases), len(jsonStdoutMultiCases), ran, documents)
}
