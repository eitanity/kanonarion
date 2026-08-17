package golden_test

// The golden-file change detector for COMMAND OUTPUT.
//
// What this is: a recorded copy of what a command prints, compared byte for
// byte against what it prints now. It promises nothing to a consumer — there is
// no version, no schema and no compatibility claim. It says "this output
// changed, is that what you meant", and costs one reviewed diff per intentional
// change.
//
// Why it exists: four JSON surfaces moved in one commit — three gained fields
// and one silently STOPPED emitting a field for a module whose publication date
// the proxy did not supply — and nothing in the suite reported any of it. The
// invariant guards in internal/cli hold no copy of what a command prints, so
// none of them can.
//
// How to update: run
//
//	UPDATE_GOLDEN=1 go test ./test/golden/ -run TestCommandGolden
//
// and READ the diff before committing it. A golden that gets regenerated
// without being read is a golden that detects nothing.
//
// Every case runs against the hermetic fixture store in fixture_test.go, with
// the CLI's wall clock pinned, so a diff here is a change in the product and
// never a change in the weather.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli"
)

// goldenDir holds one file per recorded case, beside the record golden this
// package already keeps. One convention, one directory.
const goldenDir = "cmd"

// updateEnv is the switch that regenerates every golden in place.
const updateEnv = "UPDATE_GOLDEN"

// regenerating reports whether this run rewrites the goldens rather than
// checking them.
func regenerating() bool { return os.Getenv(updateEnv) == "1" }

// cmdCase is one recorded invocation.
type cmdCase struct {
	// name is the golden file's base name and the subtest's name.
	name string
	// args is the command line, exactly as a caller would type it after
	// `kanonarion`.
	args []string
	// prime is the command lines run against this case's store BEFORE the
	// recorded one, with their output discarded.
	//
	// It exists because some output is only produced by a command that finds
	// work already done — a scan served from a stored run rather than measured.
	// A case cannot record that without a populated store, and the alternative
	// was to let a second case read the store a first case wrote, which makes
	// each case's output depend on which case ran before it. Priming keeps the
	// dependency inside one case, where it is stated rather than inferred from
	// declaration order.
	//
	// A priming command that fails FAILS the case. A prime that silently did
	// not populate the store would leave the recorded run measuring for itself,
	// and the golden would then be a recording of the wrong run.
	prime [][]string
	// env is set for this case only and restored afterwards.
	env map[string]string
	// storeRoot overrides the fixture store. The empty string means the fixture
	// store; a case that needs a store with nothing in it names its own.
	storeRoot string
	// why states what this case exists to detect. It is recorded in the golden
	// so the next reader knows what a diff here means before they reach for
	// UPDATE_GOLDEN.
	why string
	// mintedValues opts this case into the pattern normalisation described by
	// mintedValuePatterns. It is opt-in rather than global because the fixture
	// store's own identifiers are FIXED — a case served from records must record
	// them literally, so that a change to which record answers shows as a diff
	// rather than being generalised away.
	mintedValues bool
}

// runResult is everything one invocation produced.
type runResult struct {
	stdout string
	stderr string
	err    error
}

// runCommand runs the CLI in process with args, capturing both streams.
//
// In process rather than as a subprocess: the wall clock this package pins is a
// variable in the CLI package, and a subprocess would not see it. The store
// root is passed through the environment, never through --store-root, so the
// resolution order an operator gets is the one under test.
func runCommand(t *testing.T, c cmdCase, storeRoot string) runResult {
	t.Helper()

	for k, v := range c.env {
		t.Setenv(k, v)
	}
	t.Setenv("KANONARION_STORE", storeRoot)

	var stdout, stderr bytes.Buffer
	err := cli.Run(c.args, &stdout, &stderr)
	return runResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

// runPriming runs a case's priming command lines against its store, discarding
// what they print and failing the case if any of them errors.
//
// The output is discarded rather than recorded because it is not the subject:
// what the prime leaves behind is the store the recorded run reads. It is still
// checked — a prime whose exit code is non-zero has not populated anything, and
// the run that follows would quietly record a first measurement instead of a
// served one.
func runPriming(t *testing.T, c cmdCase, storeRoot string) {
	t.Helper()
	for i, args := range c.prime {
		res := runCommand(t, cmdCase{args: args, env: c.env}, storeRoot)
		if res.err != nil {
			t.Fatalf("priming command %d for %s (`kanonarion %s`) failed: %v\nstderr:\n%s",
				i+1, c.name, strings.Join(args, " "), res.err, res.stderr)
		}
	}
}

// record renders one invocation as the text a golden holds.
func record(c cmdCase, res runResult, norm *normaliser) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", c.why)
	fmt.Fprintf(&b, "$ kanonarion %s\n", norm.apply(strings.Join(c.args, " ")))
	fmt.Fprintf(&b, "exit %d\n", cli.ExitCodeForError(res.err))
	if res.err != nil {
		fmt.Fprintf(&b, "--- error ---\n%s\n", norm.apply(res.err.Error()))
	}
	b.WriteString("--- stdout ---\n")
	b.WriteString(section(norm.apply(res.stdout)))
	b.WriteString("--- stderr ---\n")
	b.WriteString(section(norm.apply(res.stderr)))
	return b.String()
}

// section renders one captured stream, naming an empty one rather than leaving
// a blank the reader has to interpret.
func section(s string) string {
	if s == "" {
		return "(empty)\n"
	}
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

// normaliser replaces the paths that differ between machines and runs with
// stable placeholders — and refuses to record anything that still names a temp
// directory afterwards.
//
// The refusal is the point. A golden holding a path under /tmp is a golden that
// fails on the next run for a reason that has nothing to do with the product,
// and a golden that fails for the wrong reason is one that gets regenerated
// unread.
type normaliser struct {
	replacements [][2]string
	patterns     []patternReplacement
}

// patternReplacement replaces a value a run MINTS — an identifier, a version the
// host supplies — with a stable token.
//
// A pattern replaces the value; it never removes the key or the line. That
// distinction is the whole design: dropping a volatile field from the recording
// hides the field most likely to change, and a golden that cannot see a field
// cannot report that it moved. A token keeps the field's presence, its position
// and its absence all visible, and only the value nobody can pin is generalised.
type patternReplacement struct {
	re *regexp.Regexp
	// stable is what the matched text is replaced with. The field is not called
	// `token`: gosec's credential heuristic reads a struct field of that name
	// holding a literal as a hardcoded secret, and a suppression comment would
	// leave the next reader wondering which of these is the secret.
	stable string
}

func (n *normaliser) apply(s string) string {
	for _, r := range n.replacements {
		s = strings.ReplaceAll(s, r[0], r[1])
	}
	for _, p := range n.patterns {
		s = p.re.ReplaceAllString(s, p.stable)
	}
	return s
}

// mintedValuePatterns are the values a recorded run produces that no fixture can
// fix: the identifiers a walk and a scan run are named by, and the Go toolchain
// the machine happens to hold.
func mintedValuePatterns() []patternReplacement {
	return []patternReplacement{
		{
			// A ULID: 26 characters of Crockford base32. A walk id is minted from
			// the wall clock AND 80 bits of entropy, so it is the one part of
			// audit's derivation statement that cannot be a fixture. A scan run's
			// identifier is that ULID with the run's completion second appended,
			// and this pattern replaces its ULID half only: the seconds come from
			// the injected clock, so a recorded run names them literally and a
			// change to WHICH run answered moves the golden.
			re:     regexp.MustCompile(`\b[0-7][0-9A-HJKMNP-TV-Z]{25}\b`),
			stable: "$$ULID",
		},
		{
			// The stdlib coordinate carries the toolchain's own version, which
			// is a property of the machine and not of the fixture.
			re:     regexp.MustCompile(`stdlib@v\d+\.\d+(\.\d+)?`),
			stable: "stdlib@$$GOVERSION",
		},
		{
			re:     regexp.MustCompile(`\bgo1\.\d+(\.\d+)?\b`),
			stable: "$$GOVERSION",
		},
		// A log line's own timestamp, on either handler. The two patterns are
		// anchored to the handlers' key syntax rather than matching bare
		// RFC3339, because the recorded payloads carry timestamps of their own
		// — staleness_looked_up_at among them — and those are answers the
		// fixture fixes, not values the run mints.
		{
			re:     regexp.MustCompile(`"time":"[^"]*"`),
			stable: `"time":"$$TIME"`,
		},
		{
			re: regexp.MustCompile(`(^|\s)time=\S+`),
			// ${1} keeps the leading space or line start the pattern had to
			// match to anchor on a key. It is NOT $${1}: $$ is the escape for a
			// literal dollar, so that form emitted the four characters ${1} and
			// swallowed the separator rather than putting it back.
			stable: "${1}time=$$TIME",
		},
	}
}

// assertNoTempPaths fails when a recorded output still names a temp directory.
func assertNoTempPaths(t *testing.T, name, recorded string) {
	t.Helper()
	tmp := os.TempDir()
	if tmp != "" && strings.Contains(recorded, tmp) {
		t.Errorf("golden %s records a temp path (%s); it would differ on the next run.\n%s", name, tmp, recorded)
	}
}

// checkGolden compares a recorded invocation against its stored copy, or
// rewrites that copy under UPDATE_GOLDEN=1.
func checkGolden(t *testing.T, c cmdCase, recorded string) {
	t.Helper()
	path := filepath.Join(goldenDir, c.name+".golden")
	remedy := fmt.Sprintf("re-record it with:\n\tUPDATE_GOLDEN=1 go test ./test/golden/ -run 'TestCommandGolden/%s'\nand READ the diff before committing it.", c.name)

	if regenerating() {
		if err := os.MkdirAll(goldenDir, 0o750); err != nil {
			t.Fatalf("creating %s: %v", goldenDir, err)
		}
		if err := os.WriteFile(path, []byte(recorded), 0o600); err != nil {
			t.Fatalf("writing golden %s: %v", path, err)
		}
		t.Logf("golden updated: %s", path)
		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // the path is built from a case name in this file.
	if err != nil {
		// A MISSING golden is a failure, never a skip. A harness that skips
		// what it cannot find reports "0 diffs" for a suite it never ran.
		t.Fatalf("no golden for `kanonarion %s` at %s: %v\n%s",
			strings.Join(c.args, " "), path, err, remedy)
	}
	if recorded == string(want) {
		return
	}
	t.Errorf("output of `kanonarion %s` changed.\n%s\n%s",
		strings.Join(c.args, " "), unifiedish(string(want), recorded), remedy)
}

// unifiedish renders the lines that moved between two texts.
//
// It aligns on a longest common subsequence rather than comparing line N with
// line N, because a golden diff is read by a person deciding whether a change
// was intended: a single inserted key must show as one added line, not as every
// following line reported as changed.
func unifiedish(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")

	// Guard the quadratic table. A golden this large is a golden nobody reads
	// line by line anyway, and the whole-text fallback still says what changed.
	const maxLines = 2000
	if len(wantLines) > maxLines || len(gotLines) > maxLines {
		return fmt.Sprintf("--- golden (%d lines)\n+++ this run (%d lines)\n(too large to align; compare the file directly)\n",
			len(wantLines), len(gotLines))
	}

	lcs := make([][]int, len(wantLines)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(gotLines)+1)
	}
	for i := len(wantLines) - 1; i >= 0; i-- {
		for j := len(gotLines) - 1; j >= 0; j-- {
			if wantLines[i] == gotLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
		}
	}

	var b strings.Builder
	b.WriteString("--- golden\n+++ this run\n")
	shown := 0
	i, j := 0, 0
	for i < len(wantLines) && j < len(gotLines) {
		switch {
		case wantLines[i] == gotLines[j]:
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			fmt.Fprintf(&b, "-%s\n", wantLines[i])
			i++
			shown++
		default:
			fmt.Fprintf(&b, "+%s\n", gotLines[j])
			j++
			shown++
		}
		if shown > maxDiffLines {
			b.WriteString("... (further differences suppressed)\n")
			return b.String()
		}
	}
	for ; i < len(wantLines); i++ {
		fmt.Fprintf(&b, "-%s\n", wantLines[i])
	}
	for ; j < len(gotLines); j++ {
		fmt.Fprintf(&b, "+%s\n", gotLines[j])
	}
	return b.String()
}

// maxDiffLines bounds what one failure prints.
const maxDiffLines = 60
