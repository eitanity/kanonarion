package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// walkChoiceProbeLimit bounds how many candidate walks a default frame choice
// will read records for.
//
// The comparison itself is one file parse, but each candidate costs a record
// read out of the store, and a project walked daily for a year has hundreds. The
// bound is stated in the notice whenever it applied, so a caller can tell "no
// stored walk matches your tree" from "none of the eight most recent does".
const walkChoiceProbeLimit = 8

// walkChoiceRule names the rule that picked a walk for a caller who named none.
type walkChoiceRule int

const (
	// walkChosenSole is the target having exactly one walk. Nothing was chosen,
	// so nothing is stated.
	walkChosenSole walkChoiceRule = iota
	// walkChosenManifestMatch is a walk whose recorded resolution still agrees
	// with the manifest on disk, preferred over a more recent one that does not.
	walkChosenManifestMatch
	// walkChosenRecencyNoMatch is the fallback when a manifest was read and no
	// probed walk agreed with it. The most recent answers, and says so.
	walkChosenRecencyNoMatch
	// walkChosenRecencyUnchecked is the fallback when there was no manifest to
	// compare against — a walk of a published coordinate, a walk that recorded no
	// project directory, or a go.mod that could not be read.
	walkChosenRecencyUnchecked
)

// walkChoice is the walk a read answered from when the caller named none, and
// the rule that picked it.
//
// Recency alone picked it before, and recency alone is what let a walk of a
// temporarily-edited manifest become a project's permanent default frame: walk
// identity reuses an existing record when the resolution is unchanged, which
// preserves that record's original started_at, so re-walking the restored tree
// can never make the matching walk the newest again. Refreshing the timestamp on
// reuse would restore the default and would also make started_at mean two
// things — when the analysis was performed, and when it was last confirmed — so
// the rule moved here instead, to the read that defaults.
//
// Recency remains the fallback and the tiebreak. It is the only rule available
// for a published coordinate, which has no manifest anywhere on disk, and the
// only sensible one when several walks all still describe the tree.
type walkChoice struct {
	summary walkports.WalkSummary
	// record is the chosen walk's record when the choice loaded it, so a caller
	// that needs the graph does not read it a second time. loaded says whether it
	// holds anything.
	record walkdomain.WalkRecord
	loaded bool

	rule walkChoiceRule
	// candidates is how many walks of this target the store holds, and probed how
	// many of them were compared against a manifest.
	candidates int
	probed     int
	// manifestPath is the go.mod the comparison was made against, empty when none
	// could be read.
	manifestPath string
	// disagreements are the version disagreements between the manifest and the
	// walk recency would have picked, set only when that walk was compared and
	// lost.
	disagreements []string
	// uncheckable says why no comparison was possible, in words, so an answer
	// that fell back to recency says what it could not check rather than only
	// that it did not.
	uncheckable string
	// toolchains are the distinct Go toolchains the candidate walks were
	// resolved by, sorted. More than one means the candidates disagree about
	// which standard library the target links, and the choice between them
	// decides which toolchain advisories the answer is about.
	toolchains []string
}

// chooseWalk picks the walk a read answers from out of a store-ordered
// (newest-first) candidate list, preferring one whose recorded resolution still
// agrees with the manifest on disk.
//
// manifest names the go.mod to compare against. Empty means "each candidate's
// own recorded project directory", which is how a coordinate-rooted command —
// one that was handed a module, not a path — finds the tree a project walk was
// taken from.
//
// summaries must be non-empty; a caller with no walks has a different answer to
// give and gives it before reaching here.
func chooseWalk(
	ctx context.Context,
	walks QueryWalksUseCase,
	summaries []walkports.WalkSummary,
	manifest string,
) walkChoice {
	c := walkChoice{
		summary:      summaries[0],
		rule:         walkChosenSole,
		candidates:   len(summaries),
		manifestPath: manifest,
		toolchains:   distinctToolchains(summaries),
	}
	if len(summaries) == 1 {
		return c
	}
	c.rule = walkChosenRecencyUnchecked

	probed := summaries
	if len(probed) > walkChoiceProbeLimit {
		probed = probed[:walkChoiceProbeLimit]
	}
	c.probed = len(probed)

	for i, candidate := range probed {
		if err := ctx.Err(); err != nil {
			c.noteUncheckable(fmt.Sprintf("the comparison was cancelled: %v", err))
			break
		}
		rec, err := walks.GetWalk(ctx, candidate.ID)
		if err != nil {
			c.noteUncheckable(fmt.Sprintf("walk %s could not be read back: %v", candidate.ID, err))
			continue
		}
		path := manifest
		if path == "" {
			if rec.ProjectDir == "" {
				c.noteUncheckable(fmt.Sprintf("walk %s records no project directory, so it names no manifest to compare against", rec.ID))
				continue
			}
			path = filepath.Join(rec.ProjectDir, "go.mod")
		}
		disagreements, err := manifestRequireDisagreement(path, rec)
		if err != nil {
			c.noteUncheckable(err.Error())
			continue
		}
		if c.manifestPath == "" {
			c.manifestPath = path
		}
		if len(disagreements) == 0 {
			c.summary, c.record, c.loaded = candidate, rec, true
			c.rule = walkChosenManifestMatch
			return c
		}
		if i == 0 {
			// The walk recency would have served, and what it disagrees with. It is
			// carried whether or not a later candidate matches, because the notice
			// names the walk that answered and the reason another was passed over.
			c.record, c.loaded = rec, true
			c.disagreements = disagreements
			c.rule = walkChosenRecencyNoMatch
		}
	}
	if c.rule == walkChosenRecencyNoMatch && len(c.disagreements) == 0 {
		c.rule = walkChosenRecencyUnchecked
	}
	return c
}

// distinctToolchains returns the toolchains the candidates were resolved by,
// sorted and deduplicated. A candidate that recorded none is named as such
// rather than dropped: "some walks under go1.26.6 and some under no recorded
// toolchain" is a disagreement, and hiding the unrecorded half would make it
// read as agreement.
func distinctToolchains(summaries []walkports.WalkSummary) []string {
	seen := make(map[string]struct{}, len(summaries))
	out := make([]string, 0, len(summaries))
	for _, s := range summaries {
		t := s.Toolchain()
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// toolchainNote states the toolchain the chosen walk was resolved by, and is
// empty unless the candidates disagreed about it.
//
// It is conditional because that is where the harm is. Where every walk of a
// target was resolved by one toolchain there is nothing to have chosen, and a
// line printed anyway is boilerplate. Where they were not, the choice silently
// decides which standard library — and therefore which toolchain advisories —
// the answer is about, and an unstated choice there is how one project came to
// be reported both affected and clean.
func (c walkChoice) toolchainNote() string {
	if len(c.toolchains) < 2 {
		return ""
	}
	return fmt.Sprintf("the candidates were resolved by %s and this one by %s, which is the standard library the answer is about",
		strings.Join(c.toolchains, " and "), c.summary.Toolchain())
}

// noteUncheckable keeps the FIRST reason a comparison could not be made. The
// notice states one reason, and the first is the one belonging to the walk
// nearest the front of the candidate list — the one the answer came from.
func (c *walkChoice) noteUncheckable(reason string) {
	if c.uncheckable == "" {
		c.uncheckable = reason
	}
}

// walkRecord returns the chosen walk's record, reading it only if the choice did
// not already load it.
func (c walkChoice) walkRecord(ctx context.Context, walks QueryWalksUseCase) (walkdomain.WalkRecord, error) {
	if c.loaded {
		return c.record, nil
	}
	rec, err := walks.GetWalk(ctx, c.summary.ID)
	if err != nil {
		return walkdomain.WalkRecord{}, fmt.Errorf("loading walk %q: %w", c.summary.ID, err)
	}
	return rec, nil
}

// statement is the line a defaulting read prints to say that the walk it
// answered in was picked for the caller, and by which rule.
//
// Empty when the target has one walk. A store with a single walk of a project
// leaves the caller nothing to have chosen differently, and a notice printed
// there would be read as boilerplate everywhere else.
func (c walkChoice) statement() string {
	if c.candidates <= 1 {
		return ""
	}
	head := fmt.Sprintf("no walk was named and the store holds %d for this target, so one was chosen", c.candidates)
	pin := fmt.Sprintf("pin one with --walk-id (kanonarion walk-list --target %s lists them)", c.summary.Target)
	// The toolchain note rides in front of the pin so it lands in every branch:
	// the choice it describes was made whichever rule made it.
	if note := c.toolchainNote(); note != "" {
		pin = note + "; " + pin
	}
	switch c.rule {
	case walkChosenManifestMatch:
		return fmt.Sprintf("notice: %s: walk %q (frame %s), the most recent whose recorded resolution still agrees with %s; %s\n",
			head, c.summary.ID, c.summary.BuildFrame(), c.manifestPath, pin)
	case walkChosenRecencyNoMatch:
		scanned := "none of them records"
		if c.probed < c.candidates {
			scanned = fmt.Sprintf("none of the %d most recent records", c.probed)
		}
		return fmt.Sprintf("notice: %s: walk %q (frame %s), the most recent — %s the resolution %s has now (it disagrees on %s); %s, or run 'kanonarion walk --gomod %s' to record the current resolution\n",
			head, c.summary.ID, c.summary.BuildFrame(), scanned, c.manifestPath, driftSample(c.disagreements), pin, c.manifestPath)
	default:
		return fmt.Sprintf("notice: %s: walk %q (frame %s), the most recent — their recorded resolutions could not be compared against a manifest (%s); %s\n",
			head, c.summary.ID, c.summary.BuildFrame(), c.uncheckable, pin)
	}
}

// stalenessNote is the clause a --gomod read appends where it names the walk it
// answered in: what this read did, and did not, prove about the walk still
// describing the manifest.
//
// It replaces a flat "the manifest was not re-resolved" everywhere a choice was
// actually made, because that sentence is now too pessimistic in one case and
// too quiet in another. Where a walk was preferred BECAUSE its recorded
// resolution agrees with the require directives, the read checked something and
// should say what. Where none agreed, the read is answering about a build that
// is not the one on disk, and that is the fact the reader most needs.
func (c walkChoice) stalenessNote() string {
	switch c.rule {
	case walkChosenManifestMatch:
		return fmt.Sprintf("; the require directives in %s agree with that walk, though the manifest was not re-resolved through the toolchain for this read", c.manifestPath)
	case walkChosenRecencyNoMatch:
		return fmt.Sprintf("; no walk of this target records the resolution %s has now — the one used disagrees on %s, so kanonarion walk --gomod %s records the current resolution",
			c.manifestPath, driftSample(c.disagreements), c.manifestPath)
	case walkChosenSole, walkChosenRecencyUnchecked:
	}
	return manifestStalenessNote(c.manifestPath)
}

// statementClause condenses the choice into a clause a notice can append to a
// sentence that already names the walk. Empty when there was one candidate and
// therefore no choice.
//
// It says only that a choice was made and how to make it yourself; the rule that
// made it is in stalenessNote, which the same notices already carry, and saying
// it twice in one sentence is how a reader learns to skip the sentence.
func (c walkChoice) statementClause() string {
	if c.candidates <= 1 {
		return ""
	}
	toolchain := c.toolchainNote()
	if toolchain != "" {
		toolchain = "; " + toolchain
	}
	return fmt.Sprintf("; the store holds %d walks of this target and none was named, so this one was chosen%s — name one with --walk-id to choose it yourself",
		c.candidates, toolchain)
}

// selectionJSON is the machine-readable form of the same statement, for the
// documents that carry a walk id as a field.
//
// It is a field rather than a line because a consumer reading the walk id has to
// be able to tell an id the caller pinned from one the tool picked, and prose on
// the JSON stream is not readable by the thing that reads the id.
type selectionJSON struct {
	// Rule is "pinned", "sole", "manifest-match", "recency-no-match" or
	// "recency-unchecked".
	Rule string `json:"rule"`
	// Candidates is how many walks of this target the store holds. It is a
	// pointer emitted always, and null is the answer for a caller-pinned walk:
	// nothing was enumerated, and 0 would state a count that is never true of a
	// document carrying a walk id — the store holds at least the walk it names.
	Candidates *int `json:"candidates"`
	// ManifestPath is the go.mod the recorded resolutions were compared against.
	ManifestPath string `json:"manifest_path,omitempty"`
	// Disagreements are the versions the chosen walk and the manifest differ on,
	// present only when the answer fell back to recency despite a readable
	// manifest.
	Disagreements []string `json:"disagreements,omitempty"`
	// Reason says why no comparison could be made, present only for
	// "recency-unchecked".
	Reason string `json:"reason,omitempty"`
}

// selection renders the choice for a JSON document.
func (c walkChoice) selection() selectionJSON {
	candidates := c.candidates
	out := selectionJSON{Candidates: &candidates, ManifestPath: c.manifestPath}
	switch c.rule {
	case walkChosenSole:
		out.Rule = "sole"
		out.ManifestPath = ""
	case walkChosenManifestMatch:
		out.Rule = "manifest-match"
	case walkChosenRecencyNoMatch:
		out.Rule = "recency-no-match"
		out.Disagreements = c.disagreements
	default:
		out.Rule = "recency-unchecked"
		out.Reason = c.uncheckable
	}
	return out
}

// pinnedWalkChoice is the choice a caller made with --walk-id.
func pinnedWalkChoice(rec walkdomain.WalkRecord) walkChoice {
	return walkChoice{
		summary: walkports.WalkSummary{
			ID:            rec.ID,
			Target:        rec.Target,
			Scope:         rec.Scope,
			Depth:         rec.Depth,
			OverallStatus: rec.OverallStatus,
			GOOS:          rec.Graph.BuildEnv.GOOS,
			GOARCH:        rec.Graph.BuildEnv.GOARCH,
		},
		record:     rec,
		loaded:     true,
		candidates: 1,
	}
}

// pinnedSelection is the JSON form of a caller-named walk. It reports no
// candidate count: nothing was enumerated, because nothing was chosen.
func pinnedSelection() selectionJSON {
	return selectionJSON{Rule: "pinned"}
}

// resolvePinnedWalk loads the walk a caller named with --walk-id and refuses,
// naming the remedy, when it is not a walk that can answer for target.
//
// Two refusals, because they are two mistakes. An id the store does not hold is
// a typo or a purged record. An id the store does hold but which is rooted
// somewhere else is the worse one: it would answer confidently, about a
// different build, and a licence position or a reachability verdict read out of
// the wrong build is wrong in the way that is hardest to notice.
func resolvePinnedWalk(
	ctx context.Context,
	walks QueryWalksUseCase,
	walkID string,
	target coordinate.ModuleCoordinate,
) (walkdomain.WalkRecord, error) {
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		if errors.Is(err, walkports.ErrWalkNotFound) {
			return walkdomain.WalkRecord{}, &exitError{
				code: ExitConfig,
				msg: fmt.Sprintf("no walk %q in the store — kanonarion walk-list --target %s lists the walks of this target",
					walkID, target),
			}
		}
		return walkdomain.WalkRecord{}, fmt.Errorf("loading walk %q: %w", walkID, err)
	}
	if rec.Target != target {
		return walkdomain.WalkRecord{}, &exitError{
			code: ExitConfig,
			msg: fmt.Sprintf("walk %q is rooted at %s, not at %s — the answer is a property of one build, so this walk cannot give it for that coordinate; kanonarion walk-list --target %s lists the walks of this target",
				walkID, rec.Target, target, target),
		}
	}
	return rec, nil
}
