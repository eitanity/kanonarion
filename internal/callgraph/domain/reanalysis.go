package domain

import (
	"fmt"
	"runtime"
	"strings"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
)

// SetAnalysingGo is gotoolchain.SetAnalysingGo, kept for this package's callers.
func SetAnalysingGo(v string) (restore func()) { return gotoolchain.SetAnalysingGo(v) }

// DroppedPackageReason says why a package's edges are missing, read from the
// failure detail of the record that dropped them: a package the analysing
// binary could not read was never judged, so it is not said to fail.
func DroppedPackageReason(detail string) string {
	if l, ok := gotoolchain.ReadAnalyserLimit(detail); ok {
		return "was not analysed: " + l.Clause()
	}
	return "did not typecheck"
}

// DroppedPackageReasonFor is DroppedPackageReason for one package, which a
// cgo translation gap alone may have dropped.
func DroppedPackageReasonFor(pkg, detail string) string {
	if g, ok := ReadCgoTranslationGap(detail); ok && g.DroppedBy(pkg) {
		return "was not analysed: kanonarion's cgo translation does not cover what it uses"
	}
	return DroppedPackageReason(detail)
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
	return l, ok && !l.ClearedBy(gotoolchain.AnalysingGo())
}

// LocalDirPlaceholder is the token a remedy must never contain. No builder
// emits it; it is named here so the guards that forbid it share one spelling.
const LocalDirPlaceholder = "<dir>"

// UnnamedWorkingTreeLead opens the instruction given when a local coordinate's
// working tree is not recorded anywhere. Exported so the guards recognise it
// without re-spelling it.
const UnnamedWorkingTreeLead = "no stored record names the working tree"

// ReanalysisInstruction names what re-derives coord's call graph, as a line a
// reader can act on. The answer is a property of the coordinate: a published
// module is fetched then analysed, a local one is re-ingested, so every refusal
// routes through here rather than choosing per site.
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
	if IsReFetchable(coord) {
		// callgraph reads bytes the store already holds and refuses a module it
		// has not fetched; fetching a held module returns at once, so the pair is
		// right either way.
		return "kanonarion fetch " + coord.String() + " && kanonarion callgraph " + coord.String() + flags, true
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
	return frameReanalysis(coord, dir, BuildFrame{}, false, flags == " --force")
}

// TinyGoReanalysisInstruction is ReanalysisInstruction for the TinyGo build: the
// re-run with --tinygo, which no stored standard-frame record answers. An empty
// target is one the caller cannot name, and the line says <target>.
func TinyGoReanalysisInstruction(coord coordinate.ModuleCoordinate, dir, target string) string {
	return frameReanalysis(coord, dir, BuildFrame{TinyGoTarget: target}, true, false)
}

// FrameReanalysisInstruction is the re-run of a record extracted under frame:
// it keeps the flag that selects the frame, which a plain re-run would drop. This
// host's own frame needs none, as no flag selects it.
func FrameReanalysisInstruction(coord coordinate.ModuleCoordinate, dir string, frame BuildFrame, force bool) string {
	return frameReanalysis(coord, dir, frame, false, force)
}

func frameReanalysis(coord coordinate.ModuleCoordinate, dir string, frame BuildFrame, tinyGo, force bool) string {
	flags := ""
	if force {
		flags = " --force"
	}
	switch {
	case frame.TinyGoTarget != "":
		flags += " --tinygo " + frame.TinyGoTarget
	case tinyGo:
		flags += gotoolchain.TinyGoFlag
	case !frame.IsZero() && (frame.GOOS != runtime.GOOS || frame.GOARCH != runtime.GOARCH):
		flags += " " + frame.FlagSpelling()
	}
	if line, ok := ReanalysisCommand(coord, dir, force); ok {
		return line + strings.TrimPrefix(flags, " --force")
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
func IncompleteGraphRemedy(coord coordinate.ModuleCoordinate, cause FailureCause, detail, dir string, frame BuildFrame) string {
	rerun := FrameReanalysisInstruction(coord, dir, frame, false)
	if cause == FailureCauseModule && !coord.IsLocal() {
		rerun = FrameReanalysisInstruction(coord, dir, frame, true)
	}
	// Ahead of every branch: the source was never judged, so advice about the
	// source or the cache would send the reader after a fault that is not there.
	if l, ok := gotoolchain.ReadAnalyserLimit(detail); ok {
		if !l.ClearedBy(gotoolchain.AnalysingGo()) {
			// No --force: such a record is never served back, so a plain re-run measures.
			return "  " + l.Statement() + "\n  " + l.Remedy() + " Then re-analyse:\n  " + FrameReanalysisInstruction(coord, dir, frame, false)
		}
		return "  A kanonarion built with " + l.Built + " wrote this record and could not read code requiring " +
			l.Required + "; this one was built with " + gotoolchain.AnalysingGo() + ". Re-analyse:\n  " +
			FrameReanalysisInstruction(coord, dir, frame, false)
	}
	// Ahead of the cause branches: kanonarion's own limit, stated beside any
	// failure the load reported, whose remedy follows. Such a record is never
	// served back, so a plain re-run measures.
	if g, ok := ReadTinyGoLoweringGap(detail); ok {
		gap := "  " + g.Statement() + "\n  " + g.Remedy()
		if g.ClosedByThisBinary() {
			gap = "  A kanonarion without a lowering table for TinyGo " + g.Found + " wrote this record; this one has one."
		}
		if rest := withoutTinyGoLoweringGap(detail); rest != "" {
			return gap + "\n" + IncompleteGraphRemedy(coord, cause, rest, dir, frame)
		}
		return gap + " Then re-analyse:\n  " + FrameReanalysisInstruction(coord, dir, frame, false)
	}
	// The same for the cgo translation's refusals. A package with compile errors
	// of its own files the module's cause, and their remedy follows; such a record
	// is never served back, so the re-run needs no --force.
	if g, ok := ReadCgoTranslationGap(detail); ok {
		gap := "  " + g.Statement() + "\n  " + g.Remedy()
		if !g.Legacy && cause == FailureCauseModule {
			return gap + "\n" + causeRemedy(coord, cause, detail, FrameReanalysisInstruction(coord, dir, frame, false))
		}
		return gap + " Re-analyse:\n  " + FrameReanalysisInstruction(coord, dir, frame, false)
	}
	return causeRemedy(coord, cause, detail, rerun)
}

// causeRemedy is IncompleteGraphRemedy's advice by cause, once no limit of
// kanonarion's own explains the gap.
func causeRemedy(coord coordinate.ModuleCoordinate, cause FailureCause, detail, rerun string) string {
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
