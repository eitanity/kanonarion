package domain

import (
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

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

// reanalysis is the single construction both forms use. There is no path through
// it that yields a placeholder: an unnamed working tree produces a sentence, so
// no caller can emit one by passing the empty string.
func reanalysis(coord coordinate.ModuleCoordinate, dir, flags string) string {
	if !coord.IsLocal() {
		return "kanonarion callgraph " + coord.String() + flags
	}
	if dir == "" {
		return UnnamedWorkingTreeLead + ", so run kanonarion local" + flags + " from inside it"
	}
	return "kanonarion local " + dir + flags
}

// IsReFetchable reports whether coord names bytes 'kanonarion fetch' can go and
// get. A project coordinate names a working tree, never a published artefact,
// so a remedy that tells its reader to fetch it names a command that cannot
// succeed however often it is run.
func IsReFetchable(coord coordinate.ModuleCoordinate) bool {
	return !coord.IsLocal() && !coord.IsZero()
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
