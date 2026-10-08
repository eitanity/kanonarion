package domain

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// analysingGo is the Go this binary was compiled with: it decides whether a
// recorded analyser limit still binds, or was written by an older build.
var analysingGo = runtime.Version()

// SetAnalysingGo replaces the Go this binary reports itself built with and
// returns the restore. It is a test seam: a suite runs on one toolchain and
// must still exercise a limit that binds and one that does not.
func SetAnalysingGo(v string) (restore func()) {
	prev := analysingGo
	analysingGo = v
	return func() { analysingGo = prev }
}

// DroppedPackageReason says why a package's edges are missing, read from the
// failure detail of the record that dropped them: a package the analysing
// binary could not read was never judged, so it is not said to fail.
func DroppedPackageReason(detail string) string {
	if l, ok := gotoolchain.ReadAnalyserLimit(detail); ok {
		return "was not analysed: " + l.Clause()
	}
	return "did not typecheck"
}

// AnalyserLimitCaveat states a record's analyser limit for a caveat line, and
// the remedy when it still binds this binary ("" when this binary clears it).
func AnalyserLimitCaveat(detail string) (clause, remedy string, ok bool) {
	l, ok := gotoolchain.ReadAnalyserLimit(detail)
	if !ok {
		return "", "", false
	}
	if _, binding := AnalyserLimitOf(detail); binding {
		remedy = l.Remedy()
	}
	return l.Clause(), remedy, true
}

// AnalyserLimitOf reads a record's failure detail as an analyser toolchain limit
// that still binds this binary. A limit an older build recorded and this binary
// clears is not one: re-analysing lifts it.
func AnalyserLimitOf(detail string) (gotoolchain.AnalyserLimit, bool) {
	l, ok := gotoolchain.ReadAnalyserLimit(detail)
	return l, ok && !l.ClearedBy(analysingGo)
}

// LocalDirPlaceholder is the token a remedy must never contain. No builder
// emits it; it is named here so the guards that forbid it share one spelling.
const LocalDirPlaceholder = "<dir>"

// UnnamedWorkingTreeLead opens the instruction given when a local coordinate's
// working tree is not recorded anywhere. Exported so the guards recognise it
// without re-spelling it.
const UnnamedWorkingTreeLead = "no stored record names the working tree"

// ReanalysisInstruction names the one thing that re-derives coord's call graph,
// as a line a reader can act on. The answer is a property of the coordinate:
// 'callgraph' fetches a published module and refuses a local one, so every
// refusal routes through here rather than choosing per site.
//
// dir is the working tree behind a local coordinate; when the caller does not
// know it the line says so, because a bare 'kanonarion local' would silently
// analyse whatever directory the reader is standing in. Ignored when published.
func ReanalysisInstruction(coord coordinate.ModuleCoordinate, dir string) string {
	return reanalysis(coord, dir, "")
}

// ForcedReanalysisInstruction is ReanalysisInstruction for a refusal raised BY a
// stored record. Both commands serve a held record for an unchanged input, so
// without --force the re-run returns the record the refusal was about.
func ForcedReanalysisInstruction(coord coordinate.ModuleCoordinate, dir string) string {
	return reanalysis(coord, dir, " --force")
}

// ReanalysisCommand is ReanalysisInstruction for a caller that is filling a
// REMEDY SLOT rather than writing a sentence: it returns the invocation and
// true, or "" and false where no command can be named.
//
// The two forms exist because the fallback is not an invocation. A local
// coordinate whose working tree nothing names produces a SENTENCE, and splicing
// a sentence into "extract it with: …" composes text that reads as a command
// and is not one — measured on a live store, a refusal ended "extract it with:
// no stored record names the working tree, so run kanonarion local from inside
// it". A slot takes a command or takes nothing.
//
// force asks for the form that re-measures past a held record. It is owed
// exactly where a stored record would otherwise answer the re-run, which is the
// question RecordIsCacheable decides, so remedy and reuse gate cannot disagree.
func ReanalysisCommand(coord coordinate.ModuleCoordinate, dir string, force bool) (string, bool) {
	flags := ""
	if force {
		flags = " --force"
	}
	if !coord.IsLocal() {
		return "kanonarion callgraph " + coord.String() + flags, true
	}
	if dir == "" {
		return "", false
	}
	return "kanonarion local " + dir + flags, true
}

// reanalysis is the single construction both sentence forms use. There is no
// path through it that yields a placeholder: an unnamed working tree produces a
// sentence, so no caller can emit one by passing the empty string.
func reanalysis(coord coordinate.ModuleCoordinate, dir, flags string) string {
	if line, ok := ReanalysisCommand(coord, dir, flags == " --force"); ok {
		return line
	}
	return UnnamedWorkingTreeLead + ", so run kanonarion local" + flags + " from inside it"
}

// IsReFetchable reports whether coord names bytes 'kanonarion fetch' can go and
// get. A project coordinate names a working tree, never a published artefact,
// and the standard library arrives with the toolchain, so a remedy that tells
// its reader to fetch either names a command that cannot succeed however often
// it is run — `fetch stdlib@…` does not even parse the path.
func IsReFetchable(coord coordinate.ModuleCoordinate) bool {
	return !coord.IsLocal() && !coord.IsStdlib() && !coord.IsZero()
}

// ColdModuleCacheRemedy makes every module a load needs available on this host,
// in one step.
//
// One step is the point of it. The loader stops at the first unresolved imports
// of each package, so a reader told to fetch the modules it named fetches those,
// re-runs, and is told about the next few — with nothing anywhere saying how many
// rounds are left. Downloading the whole requirement graph ends that in one
// command, and it is the same command whatever the load happened to reach first.
const ColdModuleCacheRemedy = "go mod download all"

// The two halves of the go command's sentence for a module the tree's go.sum
// does not cover. Both are required so a module quoting the phrase cannot match.
const (
	missingChecksumPhrase = "missing go.sum entry"
	missingChecksumRemedy = "; to add"
)

// IsMissingChecksumEntry reports whether a failure detail is the go command
// refusing a module the tree's go.sum does not cover. It files under the same
// cause as a package that does not compile but needs the opposite advice.
func IsMissingChecksumEntry(detail string) bool {
	return strings.Contains(detail, missingChecksumPhrase) &&
		strings.Contains(detail, missingChecksumRemedy)
}

// MissingChecksumRemedy makes the tree's go.sum cover what it imports.
const MissingChecksumRemedy = "go mod tidy"

// IncompleteGraphRemedy states what to do about a call graph that came back
// incomplete. cause decides both halves: a module that does not typecheck is
// fixed in its source, a graph cut short by a cold cache is fixed by warming it,
// and sending the second reader after a compile error wastes their time.
//
// --force is owed exactly when the stored record would otherwise answer the
// re-run, the same question RecordIsCacheable decides, so remedy and reuse gate
// cannot disagree. dir is the working tree when the caller knows it.
func IncompleteGraphRemedy(coord coordinate.ModuleCoordinate, cause FailureCause, detail, dir string) string {
	rerun := ReanalysisInstruction(coord, dir)
	if cause == FailureCauseModule && !coord.IsLocal() {
		rerun = ForcedReanalysisInstruction(coord, dir)
	}
	// Ahead of every branch: the source was never judged, so advice about the
	// source or the cache would send the reader after a fault that is not there.
	if l, ok := gotoolchain.ReadAnalyserLimit(detail); ok {
		if !l.ClearedBy(analysingGo) {
			// No --force: such a record is never served back, so a plain re-run measures.
			return "  " + l.Statement() + "\n  " + l.Remedy() + " Then re-analyse:\n  " + ReanalysisInstruction(coord, dir)
		}
		return "  A kanonarion built with " + l.Built + " wrote this record and could not read code requiring " +
			l.Required + "; this one was built with " + analysingGo + ". Re-analyse:\n  " +
			ReanalysisInstruction(coord, dir)
	}
	// Ahead of the cause branches below: this shares their axis and contradicts
	// the advice they give.
	if IsMissingChecksumEntry(detail) {
		return "  The tree's go.sum does not cover every module the load needs, so the gap is in the\n" +
			"  checksums and not in the source. Close it, then re-analyse:\n" +
			"  " + MissingChecksumRemedy + "\n" +
			"  " + rerun
	}
	if coord.IsLocal() {
		if cause == FailureCauseEnvironment {
			return "  This host's module cache did not hold every module the load needed, so the gap is in\n" +
				"  the environment and not in the source. Make them all available, then re-analyse:\n" +
				"  " + ColdModuleCacheRemedy + "\n" +
				"  " + rerun
		}
		return "  Fix the package so it compiles, then re-analyse:\n  " + rerun
	}
	whose := fmt.Sprintf("  %s is a fetched dependency, so the failure is in its own sources, not in your tree.", coord)
	if cause == FailureCauseEnvironment {
		whose = fmt.Sprintf(
			"  %s is a fetched dependency, and this host's module cache did not hold every module its\n"+
				"  analysis needed, so the gap is in the environment and not in what it published.\n"+
				"  Populating the cache — %s in a tree that requires it — is what closes it.",
			coord, ColdModuleCacheRemedy)
	}
	return fmt.Sprintf("%s\n  See it: kanonarion callgraph-show %s\n  Re-measure it: %s", whose, coord, rerun)
}
