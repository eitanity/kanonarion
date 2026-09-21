package cli

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licports "github.com/eitanity/kanonarion/internal/license/ports"
)

// This file scopes `license-list` to the modules a build compiles.
//
// The resolution is `notice`'s, called rather than copied: the two commands
// answer the same question about the same build — which modules must be
// attributed — and a second resolver is how they would come to disagree about a
// replaced module, a test-only dependency or a local-path replace.

// licenceScopeFlags are the three mutually exclusive ways to name a build.
type licenceScopeFlags struct {
	walkID         string
	gomodPath      string
	packagePattern string
}

// named reports whether the caller asked for a scope at all. Unset, the listing
// is over the whole store, which is what it has always been.
func (f licenceScopeFlags) named() bool {
	return f.walkID != "" || f.gomodPath != "" || f.packagePattern != ""
}

// validate refuses two scopes at once.
//
// Silently picking one of two builds is the same defect as silently discarding
// the argument: the rows would be right about a question nobody asked.
func (f licenceScopeFlags) validate() error {
	given := 0
	for _, v := range []string{f.walkID, f.gomodPath, f.packagePattern} {
		if v != "" {
			given++
		}
	}
	if given > 1 {
		return &exitError{code: ExitConfig,
			msg: "--walk-id, --gomod and --package are mutually exclusive: each names a different build, so pass one"}
	}
	return nil
}

// licenceListScope is a resolved scope: how the build was named, and the
// modules it compiles.
type licenceListScope struct {
	// kind and value are the question that picked the modules, as the document
	// and the text statement report it.
	kind  string
	value string
	// mods are the modules in scope, de-duplicated and ordered.
	//
	// They are kept as resolved, not reduced to coordinates: a local-path replace
	// carries the directory the build compiles instead of the coordinate, and
	// that field is what says no extraction of the coordinate can ever produce
	// its record. Discarding it is what let one remedy be printed for modules it
	// could not fill.
	mods []scopeModule
	// walkID is the walk this scope came from, empty for the two scopes derived
	// by running `go list` over a working tree. It is kept because it is the one
	// argument that turns a per-module remedy into a single runnable command.
	walkID string
	// build is the go.mod this scope's modules are resolved under, read through
	// the directive parser so a local-path replace can be given the remedy that
	// populates it. The zero value means this run could not read one, and a
	// remedy written against it is withheld rather than guessed.
	build licenceRemedyBuild
}

// coords is the coordinate each module in scope is ANSWERED ABOUT, in order.
func (s *licenceListScope) coords() []coordinate.ModuleCoordinate {
	out := make([]coordinate.ModuleCoordinate, 0, len(s.mods))
	for _, m := range s.mods {
		out = append(out, m.answering())
	}
	return out
}

// bulkExtraction is the one invocation that produces a licence record for every
// ORDINARY fetched module in scope, or "" where the scope holds no argument
// that could name one.
//
// Only a walk scope has it. --package and --gomod are resolved by running `go
// list` over the working tree, which yields modules and no walk, so there is no
// id to put in that line; those fall back to the per-module command.
//
// It is written as literals around the id so the printed-invocation guard
// renders and parses the whole line rather than a slot it cannot resolve.
func (s *licenceListScope) bulkExtraction() string {
	if s.walkID == "" {
		return ""
	}
	return "kanonarion extract " + s.walkID + " --stages license"
}

// resolveLicenceListScope resolves the caller's scope flags to the modules the
// build compiles, or nil when no scope was named.
func resolveLicenceListScope(ctx context.Context, f licenceScopeFlags, ctr *Container) (*licenceListScope, error) {
	if !f.named() {
		return nil, nil
	}
	scope := &licenceListScope{}
	switch {
	case f.walkID != "":
		scope.kind, scope.value, scope.walkID = "walk", f.walkID, f.walkID
		scope.build = licenceRemedyBuildForWalk(ctx, ctr, f.walkID)
	case f.packagePattern != "":
		scope.kind, scope.value = "package", f.packagePattern
		// A package pattern is resolved against the working tree, so the go.mod
		// that declares its replaces is the working tree's. A tree with none
		// leaves the build unknown, which withholds a remedy rather than
		// inventing one.
		if resolved, rerr := resolveGoModPath(""); rerr == nil {
			scope.build = licenceRemedyBuildFor(ctr.DirectiveParser, resolved)
		}
	default:
		// Everything downstream takes the path's DIRECTORY to run `go list`, so
		// an unresolved path that is not there would scope the listing to
		// whatever sat beside it.
		resolved, rerr := resolveGoModPath(f.gomodPath)
		if rerr != nil {
			return nil, rerr
		}
		f.gomodPath = resolved
		scope.kind, scope.value = "go.mod", resolved
		scope.build = licenceRemedyBuildFor(ctr.DirectiveParser, resolved)
	}

	mods, _, err := resolveNoticeModules(ctx, f.walkID, f.gomodPath, f.packagePattern, ctr)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, m := range mods {
		coord := m.answering()
		if coord.IsZero() || seen[coord.String()] {
			continue
		}
		seen[coord.String()] = true
		scope.mods = append(scope.mods, m)
	}
	sort.Slice(scope.mods, func(i, j int) bool {
		return scope.mods[i].answering().String() < scope.mods[j].answering().String()
	})
	return scope, nil
}

// keep narrows a listing's rows to the modules in scope. A nil scope keeps
// every row, so callers need no branch.
func (s *licenceListScope) keep(sums []licports.LicenseSummary) []licports.LicenseSummary {
	if s == nil {
		return sums
	}
	in := s.members()
	out := make([]licports.LicenseSummary, 0, len(sums))
	for _, sum := range sums {
		if in[sum.ModulePath+"@"+sum.ModuleVersion] {
			out = append(out, sum)
		}
	}
	return out
}

// members is the scope's coordinates as a lookup set.
func (s *licenceListScope) members() map[string]bool {
	in := make(map[string]bool, len(s.mods))
	for _, m := range s.mods {
		in[m.answering().String()] = true
	}
	return in
}

// Why one in-scope module holds no licence record. The four are not
// interchangeable: only the first is filled by running an extraction over the
// build, and printing that extraction beside the other three is a remedy that
// runs and does not do the thing.
const (
	// absenceNotExtracted is a published module nothing has extracted yet.
	absenceNotExtracted = "not_extracted"
	// absenceLocalReplace is a module the build resolves from a directory. Its
	// source was never published, so a fetch by coordinate cannot reach it.
	absenceLocalReplace = "local_replace"
	// absenceLocalRoot is the build's own main module, which is not published
	// either and is analysed by re-walking the project.
	absenceLocalRoot = "local_root"
	// absenceStdlib is the standard library, which holds no licence record by
	// design and never will.
	absenceStdlib = "stdlib"
)

// licenceAbsence is one in-scope module holding no licence record: which kind
// of absence it is, the statement a reader acts on, and the invocation that
// produces the record — empty where no invocation does.
type licenceAbsence struct {
	coord  coordinate.ModuleCoordinate
	kind   string
	reason string
	remedy string
}

// withoutRecord names the modules in scope that hold no licence record among
// the generations being listed, and says of each why and what fills it.
//
// They are named rather than dropped. A listing scoped to a binary is read as
// that binary's licence position, and a module missing from it because nothing
// has extracted it is indistinguishable from one that is not in the build — the
// difference being that the first one still has to be attributed.
//
// The classification is the one `notice` already makes about the same modules:
// the local-path target comes off the resolved scope, the main module off the
// coordinate, the standard library off the shared statement, and the remedy for
// the unpublished two off missingLicenceRecordRemedy. Deciding it again here
// would be a second classifier, and the two would drift.
func (s *licenceListScope) withoutRecord(census []licports.LicenseSummary) []licenceAbsence {
	if s == nil {
		return nil
	}
	held := make(map[string]bool, len(census))
	for _, sum := range census {
		held[sum.ModulePath+"@"+sum.ModuleVersion] = true
	}
	var out []licenceAbsence
	for _, m := range s.mods {
		coord := m.answering()
		if held[coord.String()] {
			continue
		}
		out = append(out, s.classifyAbsence(m, coord))
	}
	return out
}

// classifyAbsence decides which of the four absences one module is in.
//
// The order is the order of certainty. The standard library is settled by its
// path. A local-path replace is settled by the resolved scope, which carries
// the directory the build compiles; the directive parse is consulted only as a
// second source, for the scopes resolved without a walk record.
func (s *licenceListScope) classifyAbsence(m scopeModule, coord coordinate.ModuleCoordinate) licenceAbsence {
	build := s.build
	switch {
	case isStdlibCoordinate(coord):
		// No remedy: nothing fetches or extracts the toolchain, so no invocation
		// produces this record. The statement says where the identity is read.
		return licenceAbsence{coord: coord, kind: absenceStdlib,
			reason: licapp.StdlibMissingRecordReason(coord)}

	case m.localPath != "" || build.replacesLocally(coord):
		a := licenceAbsence{coord: coord, kind: absenceLocalReplace,
			reason: "replaced by a local path: what builds is that directory, not this coordinate, " +
				"so extracting the coordinate never produces its record"}
		if m.localPath != "" {
			a.reason = "replaced by the local path " + m.localPath +
				": what builds is that directory, not this coordinate, " +
				"so extracting the coordinate never produces its record"
		}
		// The remedy needs the go.mod the replace is declared in. Where this run
		// could not read one, the absence is still stated and no invocation is
		// offered: a line that runs and cannot fill the record is worse than none.
		if build.replacesLocally(coord) {
			a.remedy = missingLicenceRecordRemedy(coord, build)
		}
		return a

	case coord.IsLocal():
		return licenceAbsence{coord: coord, kind: absenceLocalRoot,
			reason: "the build's own main module, which is not a published module, " +
				"so extraction by coordinate never reaches it",
			remedy: missingLicenceRecordRemedy(coord, build)}

	default:
		remedy := s.bulkExtraction()
		if remedy == "" {
			remedy = missingLicenceRecordRemedy(coord, build)
		}
		return licenceAbsence{coord: coord, kind: absenceNotExtracted,
			reason: "extraction has not produced a licence record for it",
			remedy: remedy}
	}
}

// licenceListMissingJSON is one module in scope holding no licence record.
//
// It is an object rather than a bare coordinate with one blanket remedy beside
// the list, because the four absences are filled by different commands and two
// of them by none: a single remedy could only ever be true of a subset, and a
// consumer running it would find the same modules listed again. A parallel
// array of reasons was the alternative and was rejected — it would have to be
// zipped by index, and an index alignment is a contract a consumer cannot read.
type licenceListMissingJSON struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	// Reason says why no record is held, in the same words the text path uses.
	Reason string `json:"reason"`
	// Kind is the machine-readable form of that: "not_extracted",
	// "local_replace", "local_root" or "stdlib".
	Kind string `json:"kind"`
	// Remedy is an invocation that PRODUCES the record. It is empty where none
	// does — the standard library holds no record by design, and a local-path
	// replace whose go.mod this run could not read has no invocation to name —
	// and `reason` beside it says which, per conventions.md's reading of an
	// empty string.
	Remedy string `json:"remedy,omitempty"`
}

// licenceListScopeJSON is the scope as the listing document states it.
type licenceListScopeJSON struct {
	// Kind is "package", "go.mod" or "walk", and Value what the caller gave.
	Kind  string `json:"kind"`
	Value string `json:"value"`
	// ModuleCount is how many modules the build compiles, which is not the row
	// count: a module holding no record is in the scope and not in the rows.
	ModuleCount int `json:"module_count"`
	// WithoutRecord names those modules, each with why and what fills it. It is
	// an array at every count, including none — an empty one is the measured
	// answer that every module in scope has been extracted.
	WithoutRecord []licenceListMissingJSON `json:"without_record"`
}

// statement renders the scope for the listing document, or nil when the listing
// was not scoped.
func (s *licenceListScope) statement(census []licports.LicenseSummary) any {
	if s == nil {
		return nil
	}
	without := make([]licenceListMissingJSON, 0, len(s.mods))
	for _, a := range s.withoutRecord(census) {
		without = append(without, licenceListMissingJSON{
			Module:  a.coord.Path(),
			Version: a.coord.Version(),
			Reason:  a.reason,
			Kind:    a.kind,
			Remedy:  a.remedy,
		})
	}
	return licenceListScopeJSON{
		Kind:          s.kind,
		Value:         s.value,
		ModuleCount:   len(s.mods),
		WithoutRecord: without,
	}
}

// writeTextStatement names the scope and the modules in it holding no record,
// before the rows they qualify.
//
// The modules are grouped by the statement that applies to them, so the
// extraction that fills a build's unextracted dependencies is printed once with
// the count it actually fills, and the modules it cannot fill are somewhere
// else with their own statement.
func (s *licenceListScope) writeTextStatement(stdout io.Writer, census []licports.LicenseSummary) error {
	if s == nil {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "scope: %s %s (%d module(s))\n", s.kind, s.value, len(s.mods)); err != nil {
		return fmt.Errorf("writing scope: %w", err)
	}
	without := s.withoutRecord(census)
	if len(without) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"%d module(s) in scope hold no licence record among the generations listed:\n", len(without)); err != nil {
		return fmt.Errorf("writing scope: %w", err)
	}
	for _, g := range groupAbsences(without) {
		if err := writeAbsenceGroup(stdout, g); err != nil {
			return err
		}
	}
	return nil
}

// absenceGroup is the modules one statement applies to, unchanged.
type absenceGroup struct {
	reason  string
	remedy  string
	members []coordinate.ModuleCoordinate
}

// groupAbsences collapses the modules sharing a statement, keeping the order
// they were classified in so two readings of one store group identically.
func groupAbsences(in []licenceAbsence) []absenceGroup {
	var out []absenceGroup
	index := map[string]int{}
	for _, a := range in {
		key := a.reason + "\x00" + a.remedy
		i, seen := index[key]
		if !seen {
			index[key] = len(out)
			out = append(out, absenceGroup{reason: a.reason, remedy: a.remedy})
			i = len(out) - 1
		}
		out[i].members = append(out[i].members, a.coord)
	}
	return out
}

// writeAbsenceGroup prints one statement and the modules it applies to.
//
// A group of one leads with the module and reads as a sentence about it; a
// group leads with its count, because the count is what tells a reader how much
// of the listing the line below it accounts for.
func writeAbsenceGroup(stdout io.Writer, g absenceGroup) error {
	single := len(g.members) == 1
	if single {
		if _, err := fmt.Fprintf(stdout, "  %s\n    %s\n", g.members[0], g.reason); err != nil {
			return fmt.Errorf("writing scope: %w", err)
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "  %d module(s): %s\n", len(g.members), g.reason); err != nil {
			return fmt.Errorf("writing scope: %w", err)
		}
		for _, c := range g.members {
			if _, err := fmt.Fprintf(stdout, "    %s\n", c); err != nil {
				return fmt.Errorf("writing scope: %w", err)
			}
		}
	}
	line := "    to produce them: " + g.remedy
	if single {
		line = "    to produce it: " + g.remedy
	}
	if g.remedy == "" {
		// Said rather than left blank: a group with no line under it reads as an
		// oversight, and this one is a measurement.
		line = "    no invocation produces these records"
		if single {
			line = "    no invocation produces this record"
		}
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing scope: %w", err)
	}
	return nil
}
