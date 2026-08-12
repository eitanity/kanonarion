package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestLocalDerivation_NamesTheReusedRecordAndItsDate: a run that served a held
// record and one that measured the tree print the same summary line above this,
// so without the statement a reader cannot tell which they are holding — and for
// a call graph that decides whether "no callers" is about the code in front of
// them or about the code as it was.
func TestLocalDerivation_NamesTheReusedRecordAndItsDate(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 12, 0, 48, 14, 0, time.UTC)

	var out bytes.Buffer
	if err := writeDerivation(&out, localDerivationLine(cgapp.ExtractResult{
		FromCache: true,
		Record:    cgdomain.CallGraphRecord{ExtractedAt: at},
	})); err != nil {
		t.Fatalf("writeDerivation: %v", err)
	}

	got := out.String()
	for _, want := range []string{"derivation:", "2026-08-12T00:48:14Z", "reused", "--force"} {
		if !strings.Contains(got, want) {
			t.Errorf("the derivation statement does not name %q:\n%s", want, got)
		}
	}
}

// TestLocalDerivation_SaysWhenItMeasured pins the other word: a run that analysed
// the tree must not read as a served one.
func TestLocalDerivation_SaysWhenItMeasured(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if err := writeDerivation(&out, localDerivationLine(cgapp.ExtractResult{})); err != nil {
		t.Fatalf("writeDerivation: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "derived by this run") {
		t.Errorf("a fresh analysis does not say it measured:\n%s", got)
	}
	if strings.Contains(got, "reused") {
		t.Errorf("a fresh analysis claims a record was reused:\n%s", got)
	}
}

// TestLocalCommand_DeclaresForce: the reuse it now does is only safe to ship with
// a way past it, because what the tree's digest cannot see — a changed toolchain,
// a repopulated module cache — is invisible to the reuse key by construction. The
// refusal machinery also builds "kanonarion local <dir> --force" as a remedy, and
// a remedy naming a flag the command does not declare is one cobra rejects.
func TestLocalCommand_DeclaresForce(t *testing.T) {
	t.Parallel()
	cmd := newLocalCmd(&bytes.Buffer{}, &bytes.Buffer{})
	if cmd.Flags().Lookup("force") == nil {
		t.Fatal("local declares no --force")
	}
}
