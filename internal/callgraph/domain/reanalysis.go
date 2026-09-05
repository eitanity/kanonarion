package domain

import (
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// LocalDirPlaceholder is the token a remedy must never contain.
//
// No builder emits it. It is named here so the guard that refuses it, and the
// tests that assert its absence, share one spelling with the thing they forbid:
// a reader cannot run a line with "<dir>" in it, and a remedy that cannot be run
// is not a remedy.
const LocalDirPlaceholder = "<dir>"

// UnnamedWorkingTreeLead opens the instruction given when a local coordinate's
// working tree is not recorded anywhere. It is exported so a guard can
// recognise that answer without re-spelling it, and so the two forms of the
// sentence cannot drift apart.
const UnnamedWorkingTreeLead = "no stored record names the working tree"

// ReanalysisInstruction names the one thing that re-derives coord's call graph,
// as a line a reader can act on.
//
// The answer is a property of the COORDINATE, not of the site asking. A
// published module is fetched and analysed by 'callgraph <module>@<version>'. A
// project's own module carries the synthetic 'local' version, which names no
// published artefact: 'callgraph' cannot fetch it and refuses, and 'fetch'
// cannot satisfy it either, so a remedy built by concatenating the coordinate
// onto "kanonarion callgraph " is an instruction that exits non-zero for every
// project coordinate it is handed. 'local <dir>' is the command that re-derives
// that graph.
//
// Every refusal that tells a reader to re-derive a graph goes through here, so
// the decision is made once and a new refusal cannot get it wrong on its own.
//
// dir is the working tree behind a local coordinate, when the caller knows it.
// When it does not, the line says so rather than printing a template: there is
// no argument the reader could be expected to fill in, and a bare
// "kanonarion local" is worse still — it is a valid invocation that analyses
// whatever directory the reader happens to be standing in. dir is ignored for a
// published coordinate, which has no working tree.
func ReanalysisInstruction(coord coordinate.ModuleCoordinate, dir string) string {
	return reanalysis(coord, dir, "")
}

// ForcedReanalysisInstruction names what re-derives coord's call graph even
// though the store already holds one, for a refusal raised BY a stored record:
// without bypassing the cache the run is served the very record the refusal was
// about, and reads as the remedy having been tried and failed.
//
// Both forms take --force, and 'local' has one for the same reason 'callgraph'
// does: it no longer analyses the tree it is pointed at every time. It serves
// the record it already holds of an unchanged tree, so a remedy that omitted the
// flag would hand back the record the refusal was raised about.
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
// refusing a module the tree's go.sum does not cover. Asked at the boundary, to
// put that sentence on the record, and again by the remedy, because this files
// under the same cause as a package that does not compile and needs the
// opposite advice.
func IsMissingChecksumEntry(detail string) bool {
	return strings.Contains(detail, missingChecksumPhrase) &&
		strings.Contains(detail, missingChecksumRemedy)
}

// MissingChecksumRemedy makes the tree's go.sum cover what it imports.
const MissingChecksumRemedy = "go mod tidy"

// IncompleteGraphRemedy states what to do about a call graph that came back
// incomplete, for a reader looking at an answer computed from it.
//
// cause decides both halves of the answer, and getting it wrong is worse than
// saying nothing. A module whose own sources do not typecheck is fixed by fixing
// them; a graph cut short because this host's module cache did not hold a
// dependency is fixed by warming the cache, and telling that reader to go and
// find a compile error sends them looking for a fault that is not there.
//
// The re-derivation command carries --force exactly when the stored record would
// otherwise answer the re-run — which is the same question RecordIsCacheable
// decides, asked here so the printed remedy and the reuse gate can never
// disagree. An incompleteness this host caused is not served back, so the plain
// command re-derives; a module fault is served back, so the flag is owed. For a
// working tree the source fix moves the tree's digest, which is itself enough to
// make the plain command re-analyse.
//
// dir is the working tree behind a local coordinate when the caller knows it.
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
