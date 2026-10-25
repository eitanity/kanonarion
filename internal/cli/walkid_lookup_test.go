package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// absentWalkID is a walk id no fixture store holds.
const absentWalkID = "01JZZZZZZZZZZZZZZZZZZZZZZZ"

// walkIDInvocation is one way a command is handed a walk id.
type walkIDInvocation struct {
	name string
	args []string
}

// walkIDInvocations derives, from the command tree alone, every way a command
// takes a walk id: a Use-line positional naming one or declared as one, and
// every flag whose name says it holds one. Each is filled with absentWalkID;
// the command's other positionals get the fewest coordinate stand-ins its own
// validation accepts.
func walkIDInvocations(t *testing.T) []walkIDInvocation {
	t.Helper()
	var out []walkIDInvocation
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			visit(sub)
		}
		if c.RunE == nil {
			return
		}
		path := strings.Fields(strings.TrimPrefix(c.CommandPath(), "kanonarion "))
		if positions := walkIDPositions(c); len(positions) > 0 {
			args := make([]string, 0, len(positions))
			for range positions {
				args = append(args, absentWalkID)
			}
			out = append(out, walkIDInvocation{name: c.CommandPath() + " <walk-id>", args: append(path, args...)})
		}
		c.Flags().VisitAll(func(fl *pflag.Flag) {
			if !strings.Contains(fl.Name, "walk") || fl.Value.Type() != "string" {
				return
			}
			out = append(out, walkIDInvocation{name: c.CommandPath() + " --" + fl.Name, args: flagInvocation(t, c, path, fl.Name)})
		})
	}
	visit(newRootCmd(io.Discard, io.Discard))
	return out
}

// walkIDPositions is the positionals a command reads as walk ids: those its Use
// line names as one, and those it declares.
func walkIDPositions(c *cobra.Command) map[int]bool {
	out := map[int]bool{}
	for i, tok := range strings.Fields(c.Use)[1:] {
		if strings.Contains(tok, "walk-id") {
			out[i] = true
		}
	}
	for _, field := range strings.Split(c.Annotations[annotationWalkIDArgs], ",") {
		if i, err := strconv.Atoi(field); err == nil {
			out[i] = true
		}
	}
	return out
}

// flagInvocation is the command's own example that passes the flag, its value
// replaced by absentWalkID, so the command's argument checks are met by an
// invocation it documents. A command with no such example gets its first
// example and the flag; one with no example gets coordinate stand-ins.
func flagInvocation(t *testing.T, c *cobra.Command, path []string, flag string) []string {
	t.Helper()
	var first []string
	for _, line := range strings.Split(c.Example, "\n") {
		if strings.Contains(line, "|") {
			continue
		}
		fields := splitInvocation(strings.TrimSpace(line))
		if len(fields) <= len(path) || fields[0] != "kanonarion" || !slices.Equal(fields[1:1+len(path)], path) {
			continue
		}
		rest := slices.Clone(fields[1+len(path):])
		if i := slices.Index(rest, "--"+flag); i >= 0 && i+1 < len(rest) {
			rest[i+1] = absentWalkID
			return append(slices.Clone(path), rest...)
		}
		if first == nil {
			first = append(slices.Clone(path), rest...)
		}
	}
	if first == nil {
		first = append(slices.Clone(path), fillPositionals(t, c)...)
	}
	return append(first, "--"+flag, absentWalkID)
}

// fillPositionals is the fewest coordinate stand-ins c's own validation takes.
func fillPositionals(t *testing.T, c *cobra.Command) []string {
	t.Helper()
	var args []string
	for len(args) < 3 && c.ValidateArgs(args) != nil {
		args = append(args, standInCoordinate)
	}
	return args
}

// seedOneWalkStore is a store holding one walk, so a miss is measured against a
// corpus rather than an empty store.
func seedOneWalkStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatalf("migrating the store: %v", aerr)
	}
	nsSeedWalk(t, context.Background(), db)
	return root
}

// copyOfStore is a fresh root holding a copy of the closed store at template,
// so a table seeds once and each subtest may still write to or poison its own.
func copyOfStore(t *testing.T, template string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(template)); err != nil {
		t.Fatalf("copying the seeded store: %v", err)
	}
	return root
}

// Every command that takes a walk id answers one the store does not hold the
// same way: exit 4, the matched-walk statement, no remedy naming the id, and —
// for a writer — nothing written.
func TestEveryWalkIDCommand_AnswersAMissingWalkAsMissing(t *testing.T) {
	invocations := walkIDInvocations(t)
	// 10 positional forms and 22 flag forms at the time of writing.
	if len(invocations) < 30 {
		t.Fatalf("derived only %d walk-id invocations from the command tree; the derivation is not reaching it", len(invocations))
	}
	root := seedOneWalkStore(t)
	for _, inv := range invocations {
		t.Run(inv.name, func(t *testing.T) {
			before := storeFootprint(t, root)
			var stdout, stderr bytes.Buffer
			err := Run(append(inv.args, "--store-root", root), &stdout, &stderr)
			if code := ExitCodeForError(err); code != ExitNotFound {
				t.Fatalf("exit %d, want %d: %v\nstderr: %s", code, ExitNotFound, err, stderr.String())
			}
			said := err.Error() + stderr.String() + stdout.String()
			if !strings.Contains(said, "no walk record matched walk id") {
				t.Errorf("the miss is not the matched-walk statement: %v", err)
			}
			if rest := strings.ReplaceAll(said, strconv.Quote(absentWalkID), ""); strings.Contains(rest, absentWalkID) {
				t.Errorf("a line names the missing walk id as something to run:\n%s", said)
			}
			if after := storeFootprint(t, root); after != before {
				t.Errorf("the refusal wrote to the store: %s, then %s", before, after)
			}
		})
	}
}

// storeFootprint is what a write would move: the ledger's events and the
// walks the store lists. A write-intent open gives a store its (empty) ledger
// file, which records nothing.
func storeFootprint(t *testing.T, root string) string {
	t.Helper()
	ledger, err := os.ReadFile(filepath.Join(root, "audit.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("reading the ledger: %v", err)
	}
	events := bytes.Count(ledger, []byte("\n"))
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	walks, err := walksqlite.New(db).ListWalks(context.Background(), walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("listing walks: %v", err)
	}
	return "ledger events=" + strconv.Itoa(events) + " walks=" + strconv.Itoa(len(walks))
}

// A root that holds no store holds no walk: the miss is answered from an empty
// corpus, and nothing is created there.
func TestMissingWalk_OnARootWithNoStoreCreatesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "never")
	var stdout, stderr bytes.Buffer
	err := Run([]string{"vuln-scan", absentWalkID, "--store-root", root}, &stdout, &stderr)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d, want %d: %v", code, ExitNotFound, err)
	}
	if !strings.Contains(err.Error(), "the store holds no walk record at all") {
		t.Errorf("the miss does not size the empty corpus: %v", err)
	}
	if _, serr := os.Stat(root); !os.IsNotExist(serr) {
		t.Errorf("the refusal created %s (stat: %v)", root, serr)
	}
}

// A store that cannot be opened is the command's to report, as it always was;
// the lookup never reads it as a walk it does not hold.
func TestMissingWalk_AnUnopenableStoreIsTheCommandsToReport(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "mirror.db"), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"walk-show", absentWalkID, "--store-root", root}, &stdout, &stderr)
	if err == nil || strings.Contains(err.Error(), "no walk record matched") {
		t.Errorf("an unopenable store was answered as a missing walk: %v", err)
	}
}

// A walk-not-found that reaches a use case without the lookup still exits 4.
func TestExitCode_AWalkNotFoundIsAnAbsentRecord(t *testing.T) {
	if code := ExitCodeForError(errors.Join(errors.New("deep"), walkports.ErrWalkNotFound)); code != ExitNotFound {
		t.Errorf("exit %d, want %d", code, ExitNotFound)
	}
}

// stubRuns and stubSBOMs are the records that can outlive a walk.
type stubRuns struct {
	runs []vuldomain.WalkScanRun
	err  error
}

func (s stubRuns) ListWalkScanRuns(context.Context, string) ([]vuldomain.WalkScanRun, error) {
	return s.runs, s.err
}

type stubSBOMs struct {
	sboms []sbomdomain.SBOMRecord
	err   error
}

func (s stubSBOMs) ListSBOMRecords(context.Context, string) ([]sbomdomain.SBOMRecord, error) {
	return s.sboms, s.err
}

// A walk whose scan runs or SBOMs outlived it is still named by evidence, so
// the command answers from that evidence instead of being refused; a store
// where nothing names it is refused.
func TestMissingWalk_EvidenceThatOutlivedItIsStillServed(t *testing.T) {
	cmd := &cobra.Command{Use: "probe [walk-id]", Annotations: map[string]string{annotationWalkIDArgs: "0"}}
	for _, tc := range []struct {
		name    string
		held    walkHolders
		refused bool
	}{
		{"nothing names it", walkHolders{walks: noWalks{}, runs: stubRuns{}, sboms: stubSBOMs{}}, true},
		{"a scan run outlived it", walkHolders{walks: noWalks{}, runs: stubRuns{runs: make([]vuldomain.WalkScanRun, 1)}}, false},
		{"an SBOM outlived it", walkHolders{walks: noWalks{}, sboms: stubSBOMs{sboms: make([]sbomdomain.SBOMRecord, 1)}}, false},
		{"the runs cannot be read", walkHolders{walks: noWalks{}, runs: stubRuns{err: errors.New("planted")}}, false},
		{"the SBOMs cannot be read", walkHolders{walks: noWalks{}, sboms: stubSBOMs{err: errors.New("planted")}}, false},
		{"no walk store", walkHolders{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseMissingWalks(context.Background(), cmd, []string{absentWalkID}, tc.held, io.Discard)
			if got := err != nil; got != tc.refused {
				t.Errorf("refused = %v, want %v (%v)", got, tc.refused, err)
			}
		})
	}
}
