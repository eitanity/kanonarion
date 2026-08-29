package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/eitanity/kanonarion/internal/coordinate"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licports "github.com/eitanity/kanonarion/internal/license/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// provenanceSelection says which licence record a provenance answer read its
// copyright lines off, and — where the caller named no version — that a choice
// was made on their behalf, out of what, and how to make it themselves.
//
// A module-level provenance question has as many answers as the store holds
// versions, and the reader cannot tell from a coordinate alone whether it was
// asked for, resolved by a rule, or arrived at by accident. Naming the basis
// without naming the rule is the shape that let write recency pass for an
// answer about the module.
type provenanceSelection struct {
	// Rule is "pinned" when the caller named the version, "newest_version"
	// otherwise.
	Rule string `json:"rule"`
	// Basis is the coordinate whose record answered.
	Basis string `json:"basis"`
	// Candidates are the versions the store holds records for, newest first.
	// Empty for a pinned read, which chose nothing.
	Candidates []string `json:"candidates,omitempty"`
	// Disagreement is set only when the candidate records do not all report the
	// same copyright signal, one "version: status" entry per candidate. The
	// disagreement is the answer to a module-level question, so it is carried
	// rather than resolved by picking.
	Disagreement []string `json:"disagreement,omitempty"`
	// Statement is the human-readable form of the same facts, empty when nothing
	// was chosen.
	Statement string `json:"statement,omitempty"`
}

// provenanceSelectionPinned and provenanceSelectionNewest name the two rules.
const (
	provenanceSelectionPinned = "pinned"
	provenanceSelectionNewest = "newest_version"
)

// statement renders the notice a defaulting read prints above its answer.
//
// Silent for a pinned read and for a module the store holds one version of:
// there was no choice to disclose, and a notice printed where nothing was chosen
// teaches the reader to skip it where something was.
func (s provenanceSelection) statement(path string) string {
	if s.Rule != provenanceSelectionNewest || len(s.Candidates) <= 1 {
		return ""
	}
	pin := fmt.Sprintf("pin one with: kanonarion provenance %s@<version>", path)
	if len(s.Disagreement) > 0 {
		return fmt.Sprintf(
			"notice: no version was named and the store holds licence records for %d versions of %s whose copyright signals disagree (%s) — the answer below is %s, the newest version; %s\n",
			len(s.Candidates), path, strings.Join(s.Disagreement, "; "), s.Basis, pin)
	}
	return fmt.Sprintf(
		"notice: no version was named and the store holds licence records for %d versions of %s (%s), so one was chosen: %s, the newest version; %s\n",
		len(s.Candidates), path, strings.Join(s.Candidates, ", "), s.Basis, pin)
}

// licenceBasis is a resolved licence record together with the coordinate it came
// from and the candidates it was chosen out of.
type licenceBasis struct {
	rec    licdomain.LicenseRecord
	coord  coordinate.ModuleCoordinate
	pinned bool
	// candidates are the versions the store holds records for at this path,
	// newest first. Empty for a pinned read.
	candidates []string
}

// resolveLicenceBasis resolves the licence record to read copyright lines off.
//
// With a version it is the record for that coordinate. Without one it is the
// record for the NEWEST version the store holds, not the most recently extracted
// one: extraction order is a fact about when this store was busy, and a
// module-level claim resting on it changes when an unrelated walk lands, naming a
// version nobody asked about. Newest version is a property of the module and
// answers the same way tomorrow.
//
// The candidate versions are returned with it, so the caller can say a choice was
// made and out of what.
func resolveLicenceBasis(
	ctx context.Context,
	path, version string,
	uc QueryLicenseUseCase,
	summaries []licports.LicenseSummary,
	listErr error,
) (licenceBasis, bool, string) {
	// The standard library holds no licence record and never will: it ships with
	// the toolchain rather than through the module proxy, so no extraction runs
	// over it. The tier says what it could not read and names where the licence
	// identity IS reported, rather than a remedy that would leave this answer
	// exactly where it is on the next run.
	if isStdlibPath(path) {
		return licenceBasis{}, false, "the standard library holds no licence record — " +
			"its licence identity comes from the recorded chain of custody, reported by: " +
			"kanonarion license " + path + "@<version>"
	}
	if version != "" {
		coord, cerr := coordinate.NewModuleCoordinate(path, version)
		if cerr != nil {
			return licenceBasis{}, false, fmt.Sprintf("%s@%s is not a module coordinate: %v", path, version, cerr)
		}
		rec, found, gerr := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
		switch {
		case gerr != nil:
			return licenceBasis{}, false, fmt.Sprintf("reading the licence record for %s: %v", coord, gerr)
		case !found:
			return licenceBasis{}, false, fmt.Sprintf("no licence record for %s; run: kanonarion license %s", coord, coord)
		}
		return licenceBasis{rec: rec, coord: coord, pinned: true}, true, ""
	}

	if listErr != nil {
		return licenceBasis{}, false, fmt.Sprintf("listing licence records: %v", listErr)
	}
	candidates := candidateVersions(path, summaries)
	if len(candidates) == 0 {
		return licenceBasis{}, false, fmt.Sprintf(
			"no licence record for %s at any version; give a version or run: kanonarion license %s@<version>", path, path)
	}
	coord, cerr := coordinate.NewModuleCoordinate(path, candidates[0])
	if cerr != nil {
		return licenceBasis{}, false, fmt.Sprintf("the stored licence summary for %s names no usable coordinate: %v", path, cerr)
	}
	rec, found, gerr := uc.GetLicenseRecord(ctx, coord, licapp.PipelineVersion)
	if gerr != nil || !found {
		return licenceBasis{}, false, fmt.Sprintf("reading the licence record for %s: not readable", coord)
	}
	return licenceBasis{rec: rec, coord: coord, candidates: candidates}, true, ""
}

// candidateVersions returns the distinct versions the ledger holds records for
// at path, newest first.
//
// Rows written by an older extraction pipeline are dropped whenever the current
// one has produced any, because the record read back is always the current
// pipeline's: a candidate selected off a stale row would resolve to a coordinate
// this command then reports as unreadable. Where the current pipeline has
// produced none, every row stays a candidate and the miss is reported as it
// always was.
func candidateVersions(path string, summaries []licports.LicenseSummary) []string {
	var current, all []string
	seenCurrent, seenAll := map[string]struct{}{}, map[string]struct{}{}
	for _, s := range summaries {
		if s.ModulePath != path || s.ModuleVersion == "" {
			continue
		}
		if _, ok := seenAll[s.ModuleVersion]; !ok {
			seenAll[s.ModuleVersion] = struct{}{}
			all = append(all, s.ModuleVersion)
		}
		if s.PipelineVersion != licapp.PipelineVersion {
			continue
		}
		if _, ok := seenCurrent[s.ModuleVersion]; !ok {
			seenCurrent[s.ModuleVersion] = struct{}{}
			current = append(current, s.ModuleVersion)
		}
	}
	out := current
	if len(out) == 0 {
		out = all
	}
	sort.Slice(out, func(i, j int) bool { return newerVersion(out[i], out[j]) })
	return out
}

// newerVersion reports whether a is a newer module version than b.
//
// Versions semver cannot order — a local coordinate, a pseudo-name — sort below
// every version it can, and among themselves by string, so the ordering is total
// and stable rather than dependent on listing order. They are never silently
// treated as newest: a version the comparison does not understand must not become
// the basis of an answer ahead of one it does.
func newerVersion(a, b string) bool {
	av, bv := semver.IsValid(a), semver.IsValid(b)
	switch {
	case av && bv:
		if c := semver.Compare(a, b); c != 0 {
			return c > 0
		}
		return a > b
	case av != bv:
		return av
	default:
		return a > b
	}
}

// replacedModulePaths returns the module paths that path replaces under a go.mod
// replace directive, as the walks in this store recorded them.
//
// This is what lets the holder-matches-path rule reach the commonest fork shape.
// That rule compares a copyright holder against the owner of a related module,
// and its only source of related modules was the licence ledger — so a fork whose
// upstream was never licence-analysed here had nothing to be compared against,
// and a republication carrying the upstream holder's line and no other read as a
// module with no indicators. The replace directive names the upstream whether or
// not anybody ever ran `kanonarion license` over it.
// The second return value is what the search did not cover, in words, so a
// "no indicators" answer that rests on it can say how thorough it was rather
// than presenting a bounded search as an exhausted one. It is empty when the
// search read every walk in the store.
func replacedModulePaths(ctx context.Context, walks QueryWalksUseCase, path string) ([]string, string) {
	if walks == nil {
		return nil, "no walk store available to this command, so no go.mod replace directive was consulted"
	}
	summaries, err := walks.ListWalks(ctx, walkports.WalkFilter{Limit: truncationFetchLimit(walkSearchLimit)})
	if err != nil {
		return nil, fmt.Sprintf("the walks holding go.mod replace directives could not be listed: %v", err)
	}
	searched, bounded := truncateList(summaries, walkSearchLimit)
	limit := ""
	if bounded {
		limit = fmt.Sprintf("go.mod replace directives were read from the %d most recent walks only", walkSearchLimit)
	}
	seen := make(map[string]struct{})
	var out []string
	for _, s := range searched {
		rec, rerr := walks.GetWalk(ctx, s.ID)
		if rerr != nil {
			continue
		}
		for _, node := range rec.Graph.Nodes {
			if node.Coordinate.Path() != path {
				continue
			}
			orig := node.OriginalCoordinate.Path()
			if orig == "" || orig == path {
				continue
			}
			if _, done := seen[orig]; done {
				continue
			}
			seen[orig] = struct{}{}
			out = append(out, orig)
		}
	}
	sort.Strings(out)
	return out, limit
}
