package cli

import (
	"io"
	"strings"
	"testing"
)

// The round trip this closes: a caller who reaches for the flag spelling their
// last command used gets "unknown flag: --walk-id" and has to guess again. Both
// spellings name the same walk, and giving both is refused rather than resolved
// by precedence — the two values can differ and nothing here can say which was
// meant.
func TestOneWalkID_TakesTheWalkFromEitherSpelling(t *testing.T) {
	cmd := newVerificationCoverageCmd(io.Discard, io.Discard)
	const id = "01KQDBVW092ER1HNXZ60X27CMD"
	const other = "01M0VG1267S1XDJGDFZTVRPM84"

	got, err := oneWalkID(cmd, []string{id}, "")
	if err != nil || got != id {
		t.Errorf("positional: got %q, %v; want %q", got, err, id)
	}
	got, err = oneWalkID(cmd, nil, id)
	if err != nil || got != id {
		t.Errorf("--walk-id: got %q, %v; want %q", got, err, id)
	}
	if _, err := oneWalkID(cmd, []string{id}, other); err == nil {
		t.Error("two different walks named, and one of them was picked")
	} else if !strings.Contains(err.Error(), "two walks named") {
		t.Errorf("refusal does not say what is wrong: %v", err)
	}
	if _, err := oneWalkID(cmd, nil, ""); err == nil {
		t.Error("no walk named, and the command ran anyway")
	}
}

// The flag exists on the command, not just in the helper: a test over the helper
// alone would pass with the flag unregistered.
func TestVerificationCoverage_DeclaresBothSpellings(t *testing.T) {
	cmd := newVerificationCoverageCmd(io.Discard, io.Discard)
	if cmd.Flags().Lookup("walk-id") == nil {
		t.Error("verification-coverage declares no --walk-id")
	}
	if !strings.Contains(cmd.Use, "[<walk-id>]") {
		t.Errorf("the Use line still requires the positional: %q", cmd.Use)
	}
	if err := cmd.ValidateArgs(nil); err != nil {
		t.Errorf("the positional is still mandatory: %v", err)
	}
}

// A walk id parsed as a module path produced "use <id>@latest", advice whose
// second failure was the reader following it. Refusing the shape is what stops
// the second round trip, and the line it prints instead has to run.
func TestModuleVersionRequired_RefusesAWalkIDAsOne(t *testing.T) {
	const id = "01KQDBVW092ER1HNXZ60X27CMD"
	err := moduleVersionRequired("fetch", id)
	if err == nil {
		t.Fatal("a walk id was accepted as a module path")
	}
	msg := err.Error()
	if strings.Contains(msg, "@latest") || strings.Contains(msg, "@<version>") {
		t.Errorf("the refusal still tells the reader to version a walk id:\n%s", msg)
	}
	if !strings.Contains(msg, "is a walk id") {
		t.Errorf("the refusal does not say what the argument is:\n%s", msg)
	}
	// The line it prints instead has to run. The coordinate handed to the guard
	// only decides which half of the acquiring-command rule applies; the line
	// names a walk.
	assertRunnableFor(t, mustCoord(t, "github.com/spf13/cobra", "v1.8.1"), "kanonarion walk-show "+id)

	// A module path that simply named no version keeps the advice it had: there
	// is no version in hand and the reader has to choose one.
	plain := moduleVersionRequired("fetch", "github.com/spf13/cobra").Error()
	if !strings.Contains(plain, "@latest") {
		t.Errorf("a path with no version lost its advice:\n%s", plain)
	}
}

// inspect is the command that PRODUCES a walk, so a walk id in its positional
// slot is a question asked of the wrong command. Read as a module path it
// produced "use <id>@latest" — advice whose second failure was the reader
// following it — so the shape is refused and the commands that consume an
// existing walk are named instead.
func TestInspect_RefusesAWalkIDWithALineThatRuns(t *testing.T) {
	const id = "01KQDBVW092ER1HNXZ60X27CMD"
	cmd := newInspectCmd(io.Discard, io.Discard)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{id})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("a walk id was accepted as a module coordinate")
	}
	msg := err.Error()
	if strings.Contains(msg, "@latest") {
		t.Errorf("the refusal still tells the reader to version a walk id:\n%s", msg)
	}
	if !strings.Contains(msg, "is a walk id") {
		t.Errorf("the refusal does not say what the argument is:\n%s", msg)
	}
	coord := mustCoord(t, "github.com/spf13/cobra", "v1.8.1")
	named := 0
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "kanonarion ") {
			continue
		}
		named++
		assertRunnableFor(t, coord, line)
		if !strings.HasSuffix(line, id) {
			t.Errorf("printed line drops the id the reader gave: %q", line)
		}
	}
	if named == 0 {
		t.Errorf("the refusal names no command at all:\n%s", msg)
	}
}
