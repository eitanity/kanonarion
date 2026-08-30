package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The parity guard: every fact a person reads off the screen must be readable
// off the --json document.
//
// kanonarion's product is evidence, and a run states two kinds of thing. The
// rows of the answer, which --json already carries, and statements ABOUT the
// run — which walk answered, which scope resolved, what was not re-resolved,
// what was chosen because the caller named nothing. Those go to stderr, or into
// the text rendering, and a --json consumer never sees them. That is a verdict
// dressed as evidence on the surface an agent reads.
//
// The surface is not identifiable by reading the code: counting "notice:"
// literals, stderr writes, and notice helpers gives three different answers,
// and two helpers reach JSON under names no grep would guess. So the guard
// enumerates it by RUNNING every command instead — the same cobra-tree
// enumeration the JSON-stdout guard uses, so a command added later is decided
// here rather than missed.
//
// -- what counts as a fact --
//
// A "statement" is a fact about the run rather than a row of the answer. Two
// channels, two rules, because the channels differ in what they carry.
//
//	stderr: EVERY line. stderr holds no rows — a command's answer goes to
//	stdout — so everything on it is by construction a statement about the run.
//	This is deliberately not restricted to the "notice:" vocabulary: measured
//	here, `callgraph` states which walk it pinned and `local` states what it
//	derived, both on stderr and both with no prefix at all. A vocabulary rule
//	reports those commands as silent, which is how the surface stayed
//	unmeasured.
//
//	stdout, text run: the lines opening with the project's statement vocabulary
//	— notice:, warning:, note:, caveat:, tip:, info:, hint: — plus their wrapped
//	continuations. stdout carries the rows, so an unmarked line there cannot be
//	assumed to be a statement.
//
// -- what is not a statement about this run --
//
// Three kinds of line reach these channels without being a fact the answer
// owes, and each is excluded by a SEAM the tree already declares, never by
// matching the sentence. A phrase list is a second place to be wrong, and it
// goes stale the first time somebody rewords a line.
//
//	logger output, excluded by its own encoding (isLogLine). It is governed by
//	--log-level, identical in both output modes, and no document is expected to
//	carry it.
//
//	progress, excluded by running every command that accepts --no-progress with
//	it. That flag routes the progress writer to io.Discard, so what is left on
//	stderr is by construction what the command states rather than what it
//	narrates while working. Nothing here knows what a progress line SAYS: a
//	narration line written straight to stderr instead of through the writer
//	survives the flag and is reported, which is right, because --no-progress
//	does not silence it for a caller either.
//
//	advice, excluded by what it points at (isAdviceStatement). A remedy names
//	the flag or the argument that changes the answer the caller just got, and
//	every such token is an identifier this guard already extracts. A line that
//	extracts no identifier at all and instead sends the reader to a DIFFERENT
//	command in the tree is describing that command, which the tree's own help
//	already publishes; it asserts nothing about this run and there is no field a
//	document could carry it in.
//
// This leaves one class the guard does NOT reach, and it is stated rather than
// hidden: caveats written INTO the text rendering with no vocabulary marking
// them — `implementers` printing "scope: ... types in other modules ... are not
// measured", `interface-show` printing "build frame: unrecorded", `config show`
// printing its absent-file statement as a YAML comment. Reaching those is a
// full line-by-line text-versus-JSON audit, a larger measurement than this one.
//
// -- what counts as carried --
//
// Two tiers, because "carried" has two useful meanings and only one of them is
// exactly checkable.
//
//	tier 1, carried at all: the statement's text appears verbatim as a string
//	value in the JSON document. This is the `notices` array — an exact
//	comparison with no heuristic in it, and the reason a verbatim array is
//	worth having: it makes parity total and testable before any field exists.
//
//	tier 2, carried as data: every identifier inside the statement — the walk
//	id, the count, the coordinate, the manifest path, the flag being offered —
//	is readable off the document as a value. This is what upgrades a fact from
//	prose a machine must parse to data a machine can read.
//
// Tier 2 is a substring test against the document's scalar values, deliberately
// generous: a false gap would send somebody to add a field that is already
// there, and the guard's job is to be believed.
//
// -- the hole that is stated, not counted --
//
// A command that states nothing on the fixture proves nothing, exactly like the
// empty-stdout hole in the JSON-stdout guard. Those are reported as SILENT and
// are not passes: the fixture did not put the command in a position to state
// anything, so its parity is unmeasured.

// statementPrefixes is the project's vocabulary for a line about the run rather
// than a row of it. Taken from the code, not invented: every one of these
// appears as a literal prefix in a writer under internal/cli.
var statementPrefixes = []string{"notice:", "warning:", "note:", "caveat:", "tip:", "info:", "hint:"}

// isStatementLine reports whether a line opens a run-level statement.
func isStatementLine(line string) bool {
	l := strings.ToLower(strings.TrimSpace(line))
	// A YAML-comment statement (config show writes its rejection that way) still
	// opens with the vocabulary once the comment marker is off.
	l = strings.TrimSpace(strings.TrimPrefix(l, "#"))
	for _, p := range statementPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// statementsIn extracts the run-level statements from one channel's output.
//
// A statement absorbs the indented lines that follow it, because the wrapped
// notices break one sentence across several lines and the continuation carries
// identifiers the opening line does not.
//
// everyLine selects the stderr rule: every non-empty line opens a statement,
// because stderr carries no rows to confuse one with.
func statementsIn(out string, everyLine bool) []string {
	var stmts []string
	var cur *strings.Builder
	flush := func() {
		if cur != nil {
			stmts = append(stmts, normaliseStatement(cur.String()))
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case (everyLine && strings.TrimSpace(line) != "" && line[0] != ' ' && line[0] != '\t') || isStatementLine(line):
			flush()
			cur = &strings.Builder{}
			cur.WriteString(line)
		case cur != nil && strings.TrimSpace(line) != "" && (line[0] == ' ' || line[0] == '\t' || line[0] == '#'):
			cur.WriteString(" " + strings.TrimSpace(line))
		default:
			flush()
		}
	}
	flush()
	return stmts
}

// normaliseStatement collapses whitespace so a wrapped statement and the same
// sentence on one line compare equal.
func normaliseStatement(s string) string { return strings.Join(strings.Fields(s), " ") }

// statementBody strips the vocabulary prefix, which is framing rather than
// fact: a `notices` array of sentences need not repeat the word "notice".
func statementBody(s string) string {
	t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "#"))
	for _, p := range statementPrefixes {
		if len(t) >= len(p) && strings.EqualFold(t[:len(p)], p) {
			return strings.TrimSpace(t[len(p):])
		}
	}
	return t
}

// identifierPatterns name the things inside a statement that a machine would
// act on. Prose is not compared; these are.
var identifierPatterns = []*regexp.Regexp{
	regexp.MustCompile(`"([^"]{2,})"`),                                                           // quoted: ids, paths, scopes
	regexp.MustCompile("`([^`]{2,})`"),                                                           // backquoted commands and flags
	regexp.MustCompile(`\b([0-9A-HJKMNP-TV-Z]{26})\b`),                                           // ULIDs: walk, run, scan ids
	regexp.MustCompile(`\b((?:GO|CVE)-\d{4}-\d+)\b`),                                             // advisory ids
	regexp.MustCompile(`(\S*\bgo\.mod)\b`),                                                       // manifest paths
	regexp.MustCompile(`\b([a-z0-9.-]+\.[a-z]{2,}(?:/[^\s,;()"]+)*@[^\s,;()".]+)`),               // module@version
	regexp.MustCompile(`\b(go1\.\d+(?:\.\d+)?)\b`),                                               // toolchains
	regexp.MustCompile(`\b(v\d+\.\d+\.\d+[^\s,;()"]*)`),                                          // versions
	regexp.MustCompile(`\b((?:linux|darwin|windows|freebsd|js)/(?:amd64|arm64|386|arm|wasm))\b`), // frames
	regexp.MustCompile(`(--[a-z][a-z0-9-]+)`),                                                    // flags being offered
	regexp.MustCompile(`\b(\d+)\b`),                                                              // counts
}

// identifiersIn pulls the machine-actionable tokens out of a statement.
func identifiersIn(stmt string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, re := range identifierPatterns {
		for _, m := range re.FindAllStringSubmatch(stmt, -1) {
			id := strings.TrimSpace(m[1])
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// jsonScalars collects every scalar a JSON document holds, as text, together
// with its object keys. It is what tier 2 is checked against: a fact is data
// when it is a value in the document, wherever that value sits.
func jsonScalars(v any, into *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			*into = append(*into, k)
			jsonScalars(sub, into)
		}
	case []any:
		for _, sub := range t {
			jsonScalars(sub, into)
		}
	case string:
		*into = append(*into, t)
	case float64:
		*into = append(*into, strconv.FormatFloat(t, 'f', -1, 64))
	case bool:
		*into = append(*into, strconv.FormatBool(t))
	case nil:
	}
}

// jsonStrings collects only the string values, which is what tier 1 compares
// against: a notices array holds sentences, and a sentence matched against a
// key or a number would be a false pass.
func jsonStrings(v any, into *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for _, sub := range t {
			jsonStrings(sub, into)
		}
	case []any:
		for _, sub := range t {
			jsonStrings(sub, into)
		}
	case string:
		*into = append(*into, t)
	}
}

// decodeJSONStream decodes stdout as one or more JSON values, so a command that
// still writes a document per line is measured rather than skipped. Whether it
// SHOULD be one document is the JSON-stdout guard's question, not this one.
func decodeJSONStream(b []byte) ([]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var out []any
	for {
		var v any
		err := dec.Decode(&v)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("decoding stdout as JSON: %w", err)
		}
		out = append(out, v)
	}
}

// topLevelShape names what the command's JSON document is, because it decides
// the remedy. An object has somewhere to put a run-level fact; an array does
// not, and needs an envelope before a field can be added at all.
func topLevelShape(docs []any, raw []byte) string {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" {
		return "no-json"
	}
	if len(docs) == 0 {
		return "unparseable"
	}
	if len(docs) > 1 {
		return "stream-of-documents"
	}
	switch docs[0].(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return "scalar"
	}
}

// isLogLine reports whether a line came from the process logger rather than
// from a command stating a fact about its answer.
//
// Excluded deliberately: log output is governed by --log-level, is the same in
// both output modes, and is a diagnostic channel rather than part of the
// answer. Counting it would bury the statements in a run's warnings, and no
// JSON document is expected to carry them.
func isLogLine(line string) bool {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "time=") && strings.Contains(t, "level=") {
		return true
	}
	// A prefix decode, not a whole-line one: a progress writer that leaves no
	// newline puts its own text on the end of the log line, and a whole-line
	// parse then reports the logger's output as a statement the answer owes.
	obj, ok := decodeLeadingObject(t)
	if !ok {
		return false
	}
	_, hasLevel := obj["level"]
	_, hasTime := obj["time"]
	return hasLevel && hasTime
}

// decodeLeadingObject decodes the JSON object a line opens with, ignoring
// whatever follows it.
func decodeLeadingObject(t string) (map[string]any, bool) {
	if !strings.HasPrefix(t, "{") {
		return nil, false
	}
	var obj map[string]any
	if json.NewDecoder(strings.NewReader(t)).Decode(&obj) != nil {
		return nil, false
	}
	return obj, true
}

// commandsByPath indexes the assembled cobra tree by the path a caller types,
// so a question about one command's flags is answered from the tree rather than
// from a list kept beside it.
func commandsByPath(root *cobra.Command) map[string]*cobra.Command {
	out := map[string]*cobra.Command{}
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		if c != root {
			out[strings.TrimPrefix(c.CommandPath(), root.Name()+" ")] = c
		}
		for _, sub := range c.Commands() {
			visit(sub)
		}
	}
	visit(root)
	return out
}

// acceptsNoProgress reports whether cmd registers the shared --no-progress
// flag, which is how the guard asks the tree — not a list — which commands
// route narration through the progress writer.
func acceptsNoProgress(cmd *cobra.Command) bool {
	return cmd != nil && cmd.Flags().Lookup("no-progress") != nil
}

// isCommandNameByte reports whether b can continue a command path, so a
// reference to `walk` is not found inside `walk-list`.
func isCommandNameByte(b byte) bool {
	return b == '-' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// referencesOtherCommand reports whether stmt sends the reader to a command in
// the tree other than the one that was run. The paths come from the tree, so a
// command renamed or added later is recognised without editing anything here.
func referencesOtherCommand(stmt, binary, self string, paths []string) bool {
	for _, p := range paths {
		if p == self {
			continue
		}
		needle := binary + " " + p
		for i := 0; i < len(stmt); {
			j := strings.Index(stmt[i:], needle)
			if j < 0 {
				break
			}
			end := i + j + len(needle)
			if end == len(stmt) || !isCommandNameByte(stmt[end]) {
				return true
			}
			i = end
		}
	}
	return false
}

// isAdviceStatement reports whether a statement is advice rather than a fact or
// a remedy: it points the reader at a DIFFERENT command and carries nothing
// from this run.
//
// The two halves are what separate `kanonarion walk-list lists every walk in
// the store` — true of the store on any day, and already published by that
// command's own help — from `name the build you mean: kanonarion callgraph
// example.com/dep@v1.2.0 --from-walk <walk>`, which names the flag and the
// argument that change the answer just given. A remedy states the thing to
// type, and a flag, a coordinate, an id or a count is an identifier by the
// patterns above; so a statement holding no identifier at all is offering the
// caller nothing to do. Requiring BOTH halves is what keeps a fact with no
// identifiers in it — `local` stating that a derivation was derived by this run
// — a reported gap: it names no other command, so it is not advice.
//
// The residual risk is stated rather than hidden: a remedy phrased as a bare
// pointer to another command, with no flag and no argument in it, reads as
// advice here. Such a line is also indistinguishable from advice to a reader,
// which is a reason to phrase the remedy with what to type in it.
func isAdviceStatement(body, self, binary string, paths []string) bool {
	return len(identifiersIn(body)) == 0 && referencesOtherCommand(body, binary, self, paths)
}

// isStructuredStatement reports whether a statement is already a JSON object —
// a command that renders its run-level fact as data, but writes it to stderr.
//
// It is its own class because the remedy differs. The fact is not prose that
// needs a field invented for it; it is data on a channel the consumer reading
// stdout never sees, so the fix is to move it into the document rather than to
// name it.
func isStructuredStatement(stmt string) bool {
	_, ok := decodeLeadingObject(strings.TrimSpace(stmt))
	return ok
}

// parityGap is one fact stated to a person and missing from the document.
type parityGap struct {
	command string
	channel string // where the fact is stated
	// shape is the command's top-level JSON type, i.e. whether it has anywhere
	// to put the fact without a shape change first.
	shape     string
	statement string
	// verbatim reports whether the sentence itself is in the document.
	verbatim bool
	// missingIDs are the identifiers inside it that no value in the document
	// carries.
	missingIDs []string
	// structured says the statement is already a JSON object on stderr.
	structured bool
}

// class names what has to change for this gap to close, which is the only thing
// that decides how it is fixed.
func (g parityGap) class() string {
	switch {
	case g.structured:
		return "B-channel"
	case len(g.missingIDs) > 0:
		return "A-fact-absent"
	default:
		return "C-prose-absent"
	}
}

// offlineCommands is the set of commands that declare they open no network,
// taken from the assembled cobra tree rather than listed by hand.
//
// It gates the populated-manifest state below, and the property it asks about
// is the network, not the store. It used to ask store-intent, on the reasoning
// that a command which RECORDS would, against a manifest that resolves a real
// dependency, go and acquire it — but creation is not reach, and store-intent's
// own doc comment says so. Measured under GOPROXY=off against a scratch store,
// `fips`, `godebug` and `vendor` all answer at exit 0: they create the store
// root and read the working tree, and were being withheld from the only state
// that puts a go.mod read in front of them for a property they do not have.
//
// `avoidable` is deliberately NOT admitted here. Its flags are declared and
// this guard could read them, but the two on this tree — --from-modcache on
// `audit` and `sbom` — make a run offline by pointing it at a populated module
// cache and the go.sum beside the manifest, neither of which the fixture
// carries. Passing them would refuse before the command rendered anything,
// which measures nothing; admitting those commands needs a fixture that builds
// a module cache, not a wider gate.
func offlineCommands(root *cobra.Command) map[string]bool {
	out := map[string]bool{}
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		if c != root && networkUseOf(c) == NetworkNever {
			out[strings.TrimPrefix(c.CommandPath(), root.Name()+" ")] = true
		}
		for _, sub := range c.Commands() {
			visit(sub)
		}
	}
	visit(root)
	return out
}

// repointGoMod returns args with the --gomod path replaced, and reports whether
// there was one to replace.
func repointGoMod(args []string, path string) ([]string, bool) {
	out := append([]string{}, args...)
	for i, a := range out {
		if a == "--gomod" && i+1 < len(out) {
			out[i+1] = path
			return out, true
		}
	}
	return out, false
}

// parityGapEntry is one gap this build is known to have, tolerated until the
// work that closes it lands.
//
// statement is a FRAGMENT of the sentence, matched as a substring, because two
// of these carry a temp path or a timestamp that changes per run; it must be
// distinctive enough to name one gap, which the drain below enforces.
//
// reason is what has to change for the gap to close, not what the gap is. An
// entry with no reason is a hole with a sentence in front of it: the next
// reader cannot tell a decision from an omission, and the list stops being a
// queue and becomes a permission.
type parityGapEntry struct {
	command   string
	statement string
	reason    string
}

// knownParityGaps is the ledger, and it fails in BOTH directions.
//
//   - a gap on this list is tolerated, so the guard is green and the surface
//     stays measured;
//   - a gap NOT on it fails, so a statement added tomorrow without a field
//     behind it is caught on the commit that adds it;
//   - an entry that no longer reproduces ALSO fails, by name, so the list
//     drains as the work lands instead of rotting into a set of exemptions
//     nobody can date.
//
// Each entry was measured on the guard's own fixture, not copied from a
// description of it.
var knownParityGaps = []parityGapEntry{
	{
		command:   "audit",
		statement: "code scope resolved 0 module(s); test-scope dependencies included",
		reason: "audit's document is a bare array of findings, so there is nowhere to put a fact about the run: " +
			"it needs a top-level object whose envelope carries the resolved scope, the module count and whether test-scope dependencies were included.",
	},
	{
		command:   "callgraph",
		statement: "in 3 builds, and this question names none",
		reason: "the ambiguous-build refusal renders its candidates as prose on stderr; the refusal document has to carry them as data — " +
			"one entry per candidate with the walk id and the root it is rooted at, plus the count.",
	},
	{
		command:   "callgraph",
		statement: "so name the build you mean",
		reason: "the remedy is a command line inside a sentence; the refusal document has to name the flag (--from-walk) and the coordinate it applies to as fields, " +
			"so a consumer can retry without parsing prose.",
	},
	{
		command:   "latest",
		statement: "code scope resolved 0 module(s); test-scope dependencies included (narrow with --exclude-tests)",
		reason: "latest answers with a bare array of modules, so the scope it resolved, the count and the --exclude-tests remedy have no envelope to sit in; " +
			"the same envelope audit needs closes this one.",
	},
	{
		command:   "local",
		statement: "re-read the working tree and found it identical to the tree analysed",
		reason: "the document already names the derivation, but not that this run reused a record rather than measuring, nor the flag that forces a re-measurement; " +
			"each derivation entry needs a reused/derived field and the --force remedy beside it.",
	},
	{
		command:   "local",
		statement: "derivation: call graph: derived by this run",
		reason: "the counterpart of the entry above: the document carries the derivation's name but no field saying THIS run derived it, " +
			"so a consumer cannot tell a fresh measurement from a served one.",
	},
	{
		command:   "context (populated --gomod)",
		statement: "code scope resolved 1 module(s); test-scope dependencies included (narrow with --exclude-tests)",
		reason: "context answers with an array of per-module records and no envelope, so the scope this run resolved and the --exclude-tests remedy are stated only to a person; " +
			"the envelope audit and latest need is the same one.",
	},
	{
		command:   "context (populated --gomod)",
		statement: "vulnerability verdicts read in walk",
		reason: "the rooting is partly carried — the walk id is a value — but the manifest that named the build, the toolchain the count of candidate walks was taken under, " +
			"and the --walk-id remedy are not; the rooting object has to carry the manifest path, the toolchain and the flag.",
	},
}

// parityResult is one command's measurement.
type parityResult struct {
	command    string
	shape      string
	statements int
	gaps       []parityGap
	runErr     string
	// textErr and textOut are kept for the SILENT report: a command that stated
	// nothing has to show what it did write, or "silent" is a claim the reader
	// cannot check.
	textErr string
	textOut string
}

// TestRunLevelFactParity is the enumeration. It runs every command in the tree
// twice against one seeded store — once plain, once under --json — and reports
// every run-level statement the document does not carry.
func TestRunLevelFactParity(t *testing.T) {
	fx := newJSONStdoutFixture(t)
	chdirWithGoMod(t, "")

	root := newRootCmd(io.Discard, io.Discard)
	byPath := commandsByPath(root)
	treePaths := commandPaths(root)
	binary := root.Name()

	names := make([]string, 0, len(jsonStdoutCases))
	for name := range jsonStdoutCases {
		names = append(names, name)
	}
	sort.Strings(names)

	var results, silent []parityResult
	var skipped []string

	measure := func(t *testing.T, label, name string, extra []string) parityResult {
		t.Helper()
		base := append(strings.Fields(name), extra...)
		base = append(base, "--store-root", fx.storeRoot)
		// Measured with the progress writer routed to a sink wherever the
		// command offers that. What survives the flag is what the command
		// STATES; what it narrates while working is written through a seam the
		// caller can silence, and a document owes none of it.
		if acceptsNoProgress(byPath[name]) {
			base = append(base, "--no-progress")
		}

		var textOut, textErr bytes.Buffer
		_ = Run(append([]string{}, base...), &textOut, &textErr)

		var jsonOutBuf, jsonErrBuf bytes.Buffer
		_ = Run(append(append([]string{}, base...), "--json"), &jsonOutBuf, &jsonErrBuf)

		docs, derr := decodeJSONStream(jsonOutBuf.Bytes())
		shape := topLevelShape(docs, jsonOutBuf.Bytes())
		res := parityResult{command: label, shape: shape,
			textErr: strings.TrimSpace(textErr.String()), textOut: strings.TrimSpace(textOut.String())}
		if derr != nil && shape != "no-json" {
			res.runErr = derr.Error()
		}

		var scalars, strs []string
		for _, d := range docs {
			jsonScalars(d, &scalars)
			jsonStrings(d, &strs)
		}

		// The three channels a run-level fact is stated on. stderr under --json
		// is included because that is the channel the defect actually uses:
		// the statement is printed beside the document the consumer reads.
		channels := []struct {
			name      string
			body      string
			everyLine bool
		}{
			{"stderr(--json)", jsonErrBuf.String(), true},
			{"stderr(text)", textErr.String(), true},
			{"stdout(text)", textOut.String(), false},
		}

		seen := map[string]struct{}{}
		for _, ch := range channels {
			for _, stmt := range statementsIn(ch.body, ch.everyLine) {
				if isLogLine(stmt) {
					continue
				}
				body := statementBody(stmt)
				if isAdviceStatement(body, name, binary, treePaths) {
					continue
				}
				if _, dup := seen[body]; dup {
					continue
				}
				seen[body] = struct{}{}
				res.statements++
				gap := parityGap{
					command: label, channel: ch.name, shape: shape, statement: body,
					verbatim: containsSentence(strs, body), structured: isStructuredStatement(body),
				}
				for _, id := range identifiersIn(body) {
					if !carriesIdentifier(scalars, id) {
						gap.missingIDs = append(gap.missingIDs, id)
					}
				}
				if !gap.verbatim {
					res.gaps = append(res.gaps, gap)
				}
			}
		}
		return res
	}

	offline := offlineCommands(root)
	record := func(res parityResult) {
		if res.statements == 0 {
			silent = append(silent, res)
			return
		}
		results = append(results, res)
	}

	for _, name := range names {
		tc := jsonStdoutCases[name]
		if tc.skip != "" {
			skipped = append(skipped, name+" — "+tc.skip)
			continue
		}
		extra := tc.args
		if tc.argsFn != nil {
			extra = tc.argsFn(t, fx)
		}
		record(measure(t, name, name, extra))

		// The same command against a manifest whose scope resolves a module.
		// An empty scope answers and stops before the walk it would have
		// selected, so the statements a go.mod read owes are only reachable
		// here.
		if repointed, ok := repointGoMod(extra, fx.populatedGoMod()); ok && offline[name] {
			record(measure(t, name+" (populated --gomod)", name, repointed))
		}
	}

	// `context` is enumerated by coordinate and multi-record by walk, so neither
	// reaches its go.mod form. It is the form the brief measured the defect on,
	// so it is measured here in the same terms as every other --gomod command.
	record(measure(t, "context (populated --gomod)", "context", []string{"--gomod", fx.populatedGoMod()}))

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
		extra := tc.args
		if tc.argsFn != nil {
			extra = tc.argsFn(t, fx)
		}
		record(measure(t, name+" (several records)", name, extra))
	}

	matches, unlisted := drainParityLedger(results)
	t.Log(parityReport(results, silent, skipped, matches, unlisted))
	reportParityLedger(t, matches, unlisted)
}

// drainParityLedger pairs the measured gaps with the ledger entries: matches[i]
// is how many gaps entry i named, and unlisted is every gap no entry named.
func drainParityLedger(results []parityResult) (matches []int, unlisted []parityGap) {
	matches = make([]int, len(knownParityGaps))
	for _, r := range results {
		for _, g := range r.gaps {
			hits := 0
			for i, e := range knownParityGaps {
				if e.command == g.command && strings.Contains(g.statement, e.statement) {
					matches[i]++
					hits++
				}
			}
			if hits == 0 {
				unlisted = append(unlisted, g)
			}
		}
	}
	return matches, unlisted
}

// reportParityLedger is the drain's verdict, and it fails in both directions: a
// gap nobody listed, and an entry that no longer reproduces.
func reportParityLedger(t *testing.T, matches []int, unlisted []parityGap) {
	t.Helper()
	for _, g := range unlisted {
		t.Errorf("%s states this to a person and the --json document does not carry it, and it is not on the known-open ledger:\n"+
			"    (%s) [%s] %s\n"+
			"carry it in the document, or add a knownParityGaps entry saying what has to change to close it",
			g.command, g.class(), g.channel, truncateStatement(g.statement))
	}
	for i, e := range knownParityGaps {
		switch {
		case matches[i] == 0:
			t.Errorf("knownParityGaps entry %q / %q no longer reproduces — delete it: a tolerated gap that has closed is a list rotting, "+
				"and the next reader cannot tell it from one still open", e.command, e.statement)
		case matches[i] > 1:
			t.Errorf("knownParityGaps entry %q / %q matches %d gaps — one reason is tolerating more than one gap; "+
				"lengthen the statement fragment until it names exactly one", e.command, e.statement, matches[i])
		}
	}
}

// parityReport renders the whole measurement, gaps and holes alike, so a
// failure is read off one document rather than reconstructed from assertions.
func parityReport(results, silent []parityResult, skipped []string, matches []int, unlisted []parityGap) string {
	var b strings.Builder
	byClass := map[string]int{}
	totalStatements, totalGaps := 0, 0
	fmt.Fprintf(&b, "\n=== run-level fact parity ===\n")
	for _, r := range results {
		totalStatements += r.statements
		totalGaps += len(r.gaps)
		fmt.Fprintf(&b, "\n%s  [json: %s]  %d statement(s), %d not carried\n", r.command, r.shape, r.statements, len(r.gaps))
		if r.runErr != "" {
			fmt.Fprintf(&b, "    json decode: %s\n", r.runErr)
		}
		for _, g := range r.gaps {
			byClass[g.class()]++
			fmt.Fprintf(&b, "    - (%s) [%s] %s\n", g.class(), g.channel, truncateStatement(g.statement))
			fmt.Fprintf(&b, "        %s\n", gapRemedyLine(g))
		}
	}
	fmt.Fprintf(&b, "\n--- commands that stated nothing on this fixture (parity UNMEASURED, not passing) ---\n")
	for _, s := range silent {
		fmt.Fprintf(&b, "    %s  [json: %s]\n", s.command, s.shape)
		fmt.Fprintf(&b, "        stderr(text): %s\n", truncateStatement(normaliseStatement(s.textErr)))
		fmt.Fprintf(&b, "        stdout(text): %s\n", truncateStatement(normaliseStatement(s.textOut)))
	}
	fmt.Fprintf(&b, "\n--- commands skipped upstream (no --json rendering, or off-fixture) ---\n")
	for _, s := range skipped {
		fmt.Fprintf(&b, "    %s\n", s)
	}
	fmt.Fprintf(&b, "\nby class: A-fact-absent %d (an identifier is in no value of the document), "+
		"B-channel %d (rendered as JSON, but onto stderr), C-prose-absent %d (identifiers present, sentence absent)\n",
		byClass["A-fact-absent"], byClass["B-channel"], byClass["C-prose-absent"])
	fmt.Fprintf(&b, "\n--- known-open ledger (%d entry(ies)) ---\n", len(knownParityGaps))
	for i, e := range knownParityGaps {
		fmt.Fprintf(&b, "    [%d gap(s)] %s — %s\n        to close: %s\n", matches[i], e.command, e.statement, e.reason)
	}
	fmt.Fprintf(&b, "\ntotals: %d command(s) measured, %d silent, %d skipped, %d statement(s), %d not carried, %d unlisted\n",
		len(results), len(silent), len(skipped), totalStatements, totalGaps, len(unlisted))
	return b.String()
}

// gapRemedyLine says what the gap's class means for whoever closes it.
func gapRemedyLine(g parityGap) string {
	switch g.class() {
	case "B-channel":
		return "already data, but on stderr: a consumer reading stdout never sees it"
	case "A-fact-absent":
		return "identifiers no value in the document carries: " + strings.Join(g.missingIDs, ", ")
	default:
		return "every identifier is in the document; the sentence stating what they mean is not"
	}
}

// TestAdviceIsSeparatedFromRemedy pins the distinction the guard turns on,
// because getting it backwards is worse than the noise it removes: a guard that
// drops remedies stops reporting the facts a --json consumer most needs, and
// does it silently.
//
// A remedy names what to type. Advice names a command and describes it.
func TestAdviceIsSeparatedFromRemedy(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	paths, binary := commandPaths(root), root.Name()

	for _, tc := range []struct {
		name string
		self string
		body string
		want bool
	}{
		{
			name: "advice: describes another command",
			self: "callgraph",
			body: "kanonarion walk-list lists every walk in the store",
			want: true,
		},
		{
			name: "remedy: names the flag and the argument to retry with",
			self: "callgraph",
			body: "what a coordinate is surrounded by is a property of one build, so name the build you mean: " +
				"kanonarion callgraph example.com/dep@v1.2.0 --from-walk <walk of that build>",
			want: false,
		},
		{
			name: "remedy: a flag offered inline",
			self: "latest",
			body: "code scope resolved 0 module(s); test-scope dependencies included (narrow with --exclude-tests)",
			want: false,
		},
		{
			name: "fact with no identifier in it, naming no other command",
			self: "local",
			body: "derivation: call graph: derived by this run",
			want: false,
		},
		{
			name: "a remedy that re-runs THIS command is not advice",
			self: "walk",
			body: "kanonarion walk --force",
			want: false,
		},
		{
			name: "a command name is not found inside a longer one",
			self: "walk-list",
			body: "kanonarion walk-list lists every walk in the store",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAdviceStatement(tc.body, tc.self, binary, paths); got != tc.want {
				t.Errorf("isAdviceStatement(%q, self=%q) = %v, want %v", tc.body, tc.self, got, tc.want)
			}
		})
	}
}

// containsSentence reports whether the document carries the statement itself.
// Substring rather than equality, so a document that carries the sentence
// inside a longer one still counts as carrying it.
func containsSentence(strs []string, body string) bool {
	if body == "" {
		return false
	}
	for _, s := range strs {
		if strings.Contains(normaliseStatement(s), body) {
			return true
		}
	}
	return false
}

// carriesIdentifier reports whether any value in the document holds id.
func carriesIdentifier(scalars []string, id string) bool {
	for _, s := range scalars {
		if strings.Contains(s, id) {
			return true
		}
	}
	return false
}

func truncateStatement(s string) string {
	const max = 220
	if len(s) <= max {
		return s
	}
	return s[:max] + " …"
}
