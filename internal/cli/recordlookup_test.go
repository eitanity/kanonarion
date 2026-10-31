package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// recordLookupExempt are the reads whose Use line names an id or a coordinate
// but whose answer to an unknown one is not a missing record, each for the
// reason given. The test fails on an entry the tree no longer derives.
var recordLookupExempt = map[string]string{
	"callers":      "names a symbol; a module nothing analysed has no version to fill a runnable remedy, so it is a 20",
	"callees":      "names a symbol; a module nothing analysed has no version to fill a runnable remedy, so it is a 20",
	"implementers": "names an interface symbol; the same 20 as callers",
	"vuln-by-id":   "a survey over every vulnerability record: zero rows is its answer, at exit 0",
	"dependents":   "asks whether a found build holds a module; a build that lacks it is a 20 naming the builds that do",
	"context":      "a projection: every absent record is stated in place beside its remedy, at exit 0",
	"provenance":   "the name-path heuristic always answers; an absent licence record is stated in place, at exit 0",
}

// recordLookup is one read handed an id or coordinate no store holds.
type recordLookup struct {
	name string
	args []string
}

// recordLookups derives, from the command tree alone, every read whose Use line
// names a stored record by id or coordinate, filled with values no store holds.
func recordLookups(t *testing.T) []recordLookup {
	t.Helper()
	var out []recordLookup
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			visit(sub)
		}
		if c.RunE == nil || c.Annotations[annotationStoreIntent] != StoreIntentRead {
			return
		}
		path := strings.Fields(strings.TrimPrefix(c.CommandPath(), "kanonarion "))
		args, names := absentRecordArgs(c.Use)
		if !names {
			return
		}
		out = append(out, recordLookup{name: strings.Join(path, " "), args: append(path, args...)})
	}
	visit(newRootCmd(io.Discard, io.Discard))
	return out
}

// absentRecordArgs fills a Use line's positionals and the flags it spells out,
// taking the alternative that names a record, and reports whether any of them
// is an id or a coordinate.
func absentRecordArgs(use string) ([]string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(use, strings.Fields(use)[0]))
	alts := strings.Split(strings.Trim(rest, "()[]"), "|")
	form := alts[0]
	for _, alt := range alts {
		if strings.Contains(alt, "@") || strings.Contains(alt, "id") {
			form = alt
			break
		}
	}
	var args []string
	names, coords := false, 0
	for _, tok := range strings.Fields(form) {
		bare := strings.Trim(tok, "<>[]()")
		switch {
		case strings.HasPrefix(bare, "--"):
			args = append(args, bare)
		case strings.Contains(bare, "@"):
			names = true
			coords++
			args = append(args, "example.com/absent@v1."+string(rune('0'+coords-1))+".0")
		case idToken.MatchString(bare):
			names = true
			args = append(args, absentWalkID)
		default:
			args = append(args, "Absent")
		}
	}
	return args, names
}

// idToken is a placeholder naming an id: <id>, <run-id>, <scan-id-a>.
var idToken = regexp.MustCompile(`(^|-)id($|-)`)

// remedyCommand is the first `kanonarion <command>` a message names.
var remedyCommand = regexp.MustCompile(`kanonarion ([a-z][a-z-]*)`)

// printedInvocation is one invocation a message prints, up to its clause end.
var printedInvocation = regexp.MustCompile(`kanonarion [^;\n]*`)

// templateRemedies are the printed invocations holding a <placeholder>. With
// emptyKindAllowed the one designed template passes: the produce line of a
// store holding no record of the kind at all, which has nothing to fill it from.
func templateRemedies(msg string, emptyKindAllowed bool) []string {
	var out []string
	for _, loc := range printedInvocation.FindAllStringIndex(msg, -1) {
		inv := msg[loc[0]:loc[1]]
		if !strings.ContainsAny(inv, "<>") {
			continue
		}
		if emptyKindAllowed && strings.HasSuffix(msg[:loc[0]], "to produce one: ") && strings.Contains(msg, " at all") {
			continue
		}
		out = append(out, inv)
	}
	return out
}

// Every read handed an id or coordinate the store does not hold exits 4 and
// names a command that exists and runs as printed, text and --json alike: over
// a store holding only a walk, and over one holding a record of every kind,
// where the unknown value sits beside real ones and no template is accepted.
func TestEveryRecordLookup_AnswersAnAbsentRecordWithItsRemedy(t *testing.T) {
	lookups := recordLookups(t)
	// 34 at the time of writing, exemptions included.
	if len(lookups) < 25 {
		t.Fatalf("derived only %d record lookups from the command tree; the derivation is not reaching it", len(lookups))
	}
	derived := map[string]bool{}
	for _, l := range lookups {
		derived[l.name] = true
	}
	for name := range recordLookupExempt {
		if !derived[name] {
			t.Errorf("exemption %q names no derived lookup; remove it", name)
		}
	}
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte("module example.com/app\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx := newJSONStdoutFixture(t)
	t.Chdir(work)
	rootCmd := newRootCmd(io.Discard, io.Discard)
	for _, store := range []struct {
		name             string
		root             string
		emptyKindAllowed bool
	}{
		{"one walk", seedOneWalkStore(t), true},
		{"every kind", fx.storeRoot, false},
	} {
		for _, l := range lookups {
			if _, exempt := recordLookupExempt[l.name]; exempt {
				continue
			}
			for _, mode := range []string{"text", "json"} {
				t.Run(store.name+"/"+l.name+" "+mode, func(t *testing.T) {
					lookupAnswersAbsentRecord(t, rootCmd, l, copyOfStore(t, store.root), mode == "json", store.emptyKindAllowed)
				})
			}
		}
	}
}

// lookupAnswersAbsentRecord runs one lookup and checks its refusal.
func lookupAnswersAbsentRecord(t *testing.T, rootCmd *cobra.Command, l recordLookup, root string, asJSON, emptyKindAllowed bool) {
	t.Helper()
	args := append(slices.Clone(l.args), "--store-root", root)
	if asJSON {
		args = append(args, "--json")
	}
	var stdout, stderr bytes.Buffer
	err := Run(args, &stdout, &stderr)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("%v: exit %d, want %d: %v", args, code, ExitNotFound, err)
	}
	m := remedyCommand.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("%v: the refusal names no command that produces or lists the record: %v", args, err)
	}
	if found, _, ferr := rootCmd.Find([]string{m[1]}); ferr != nil || found == rootCmd {
		t.Errorf("%v: the remedy names %q, which is not a command", args, m[1])
	}
	for _, inv := range templateRemedies(err.Error(), emptyKindAllowed) {
		t.Errorf("%v: the remedy %q cannot run as printed", args, inv)
	}
}

// The misses that had no statement now make the one every selector makes:
// the corpus counted, the remedies, and under --json the object on stderr.
func TestShowMisses_StateTheCorpusAndTheRemedy(t *testing.T) {
	root := seedOneWalkStore(t)
	for _, tc := range []struct {
		args    []string
		line    string
		subject string
	}{
		{[]string{"extract", "show", absentWalkID},
			`the store holds no extraction run at all, so run id "` + absentWalkID + `" is not what made this empty; to produce one: kanonarion extract <walk-id>`,
			"extraction run"},
		{[]string{"sbom-show", absentWalkID},
			`the store holds no SBOM record at all, so SBOM id "` + absentWalkID + `" is not what made this empty; to produce one: kanonarion sbom <walk-id>`,
			"SBOM record"},
		{[]string{"directives", "diff", absentWalkID, "01JYYYYYYYYYYYYYYYYYYYYYYY"},
			`both arguments named a directive scan the store does not hold; the store holds no directive scan at all`,
			"directive scan"},
	} {
		for _, asJSON := range []bool{false, true} {
			args := append(append([]string(nil), tc.args...), "--store-root", copyOfStore(t, root))
			if asJSON {
				args = append(args, "--json")
			}
			var stdout, stderr bytes.Buffer
			err := Run(args, &stdout, &stderr)
			requireExit(t, err, ExitNotFound)
			if !strings.Contains(err.Error(), tc.line) {
				t.Errorf("%v: got %q, want it to contain %q", args, err, tc.line)
			}
			if stdout.Len() != 0 {
				t.Errorf("%v: the data channel carried %q", args, stdout.String())
			}
			if asJSON && !strings.Contains(stderr.String(), `"subject":"`+tc.subject+`"`) {
				t.Errorf("%v: no statement object on stderr: %q", args, stderr.String())
			}
		}
	}
}

// A read that needs a project walk the store does not hold names the walk that
// produces it, so the refusal is an absent record wherever it is raised.
func TestNoProjectWalk_IsAnAbsentRecord(t *testing.T) {
	err := &wrapErr{msg: "selecting the walk", err: noProjectWalkError{errors.New("no succeeded project walk")}}
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Errorf("exit %d, want %d", code, ExitNotFound)
	}
}

// vuln-show's miss names the scan that writes the record: the walk holding the
// module, each consumer build when several do, or a walk of the module itself.
func TestVulnScanRemedy_NamesARunnableScan(t *testing.T) {
	target := mustCoord(t, "example.com/dep", "v1.2.3")
	ctx := context.Background()
	if got, want := vulnScanRemedy(ctx, walkSearchFixture(t, 3, 1, target), target), "kanonarion vuln-scan walk-001"; got != want {
		t.Errorf("one build holds it: got %q, want %q", got, want)
	}
	two := walkSearchFixture(t, 3, 0, target)
	rec, err := two.GetWalk(ctx, "walk-002")
	if err != nil {
		t.Fatal(err)
	}
	rec.Graph.Nodes = append(rec.Graph.Nodes, walkdomain.GraphNode{Coordinate: target})
	two.AddWalk(rec)
	several := vulnScanRemedy(ctx, two, target)
	for _, want := range []string{"2 builds hold example.com/dep@v1.2.3", "kanonarion vuln-scan walk-000", "kanonarion vuln-scan walk-002"} {
		if !strings.Contains(several, want) {
			t.Errorf("two builds hold it: %q lacks %q", several, want)
		}
	}
	if got, want := vulnScanRemedy(ctx, walkSearchFixture(t, 3, -1, target), target),
		"kanonarion walk example.com/dep@v1.2.3 && kanonarion vuln-scan --module example.com/dep@v1.2.3"; got != want {
		t.Errorf("no walk holds it: got %q, want %q", got, want)
	}
	if templateRemedies(several, false) != nil {
		t.Errorf("a remedy holds a placeholder: %q", several)
	}
}
