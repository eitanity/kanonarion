package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// vulnFrameAnchor is the build a stored vulnerability read answers in: a walk,
// and the analysis frame that walk's scans were rooted at.
//
// A stored record answers "is this advisory reachable in THIS build". A store
// that holds scans of two projects holds two such answers for the same
// coordinate, and they disagree — measured: one project's build reached
// jwt/v4's ParseUnverified through a SAML session codec while another's did not
// reach it at all. Which one a read serves is not a detail the tool may settle
// on the reader's behalf, so it is carried explicitly.
type vulnFrameAnchor struct {
	walkID  string
	rooting vuldomain.Rooting
	// source names the anchor for the notice, e.g.
	// `walk "01K…" (frame target-rooted:example.com/app@local)`.
	source string
}

// resolveVulnFrameAnchor turns --walk-id / --gomod into the frame a read is
// answered in. ok is false when neither was passed.
//
// --gomod resolves to the newest succeeded project walk for that go.mod, which
// is the same resolution the six build-scoped query commands already perform;
// both routes end at a walk, and the frame is read off the walk record so the
// two say the same thing.
func resolveVulnFrameAnchor(
	ctx context.Context,
	walks QueryWalksUseCase,
	walkID, gomod string,
	gomodSet bool,
) (vulnFrameAnchor, bool, error) {
	if walkID == "" && !gomodSet {
		return vulnFrameAnchor{}, false, nil
	}
	if walkID != "" && gomodSet {
		return vulnFrameAnchor{}, false, &exitError{code: ExitConfig,
			msg: "--walk-id and --gomod are mutually exclusive: both name a build, and they may name different ones"}
	}
	if walks == nil {
		return vulnFrameAnchor{}, false, &exitError{code: ExitConfig,
			msg: "no walk store is available, so a build cannot be named"}
	}

	if gomodSet {
		resolved, err := latestWalkForGoMod(ctx, walks, gomod)
		if err != nil {
			return vulnFrameAnchor{}, false, err
		}
		walkID = resolved.ID
	}

	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		if errors.Is(err, walkports.ErrWalkNotFound) {
			// The vulnerability ledger and the walk ledger are separate stores, and
			// a walk can be purged from one while its scan records remain in the
			// other. The pin still restricts the read to that walk's records — what
			// is lost is the frame, which is read off the walk's target. So the
			// anchor is returned frameless and selection falls back to consumer-frame
			// ranking, which refuses rather than guesses when it is ambiguous.
			return vulnFrameAnchor{
				walkID: walkID,
				source: fmt.Sprintf("walk %q (frame unknown — the walk record is not in the store)", walkID),
			}, true, nil
		}
		return vulnFrameAnchor{}, false, fmt.Errorf("loading walk %q: %w", walkID, err)
	}

	rooting := vuldomain.TargetRootedAt(rec.Target)
	return vulnFrameAnchor{
		walkID:  walkID,
		rooting: rooting,
		source:  fmt.Sprintf("walk %q (frame %s)", walkID, rooting),
	}, true, nil
}

// writeFrameAnchorNotice states, on the text surface, which build the answer
// below was restricted to.
//
// A pinned answer looks exactly like an unpinned one, and the pin is the whole
// difference between "reachable in your build" and "reachable in someone
// else's". Text only: the JSON shapes are published contracts and a prose line
// on that stream is not parseable.
func writeFrameAnchorNotice(stdout io.Writer, anchor vulnFrameAnchor, ok bool) {
	if !ok {
		return
	}
	_, _ = fmt.Fprintf(stdout, "notice: results restricted to the records %s scanned\n", anchor.source)
}

// selectRecordInFrame picks the record answering for one frame out of a
// candidate set, together with the isolated-frame record it declined to answer
// from. found is false when the candidates hold nothing this frame's question
// can be answered from.
//
// The isolated frame is the one legitimate fallback, and it is not a relaxation
// of the rule. An isolated record answers "does the module, built alone, reach
// the advisory" — a question with no consumer in it, so it belongs to no
// project and misattributes nothing. Another consumer's target-rooted record is
// the opposite: it answers a question about a build the caller did not ask
// about, and is never served here. The fallback matters because a walk rooted
// at a published module scans its dependencies through an isolated per-module
// pool, so its own frame legitimately holds nothing for most coordinates.
//
// The isolated aside is carried on the anchored path for the same reason it is
// carried on the composed one: the two frames disagreeing is information, and a
// reader who has seen the isolated verdict elsewhere is owed the reason it is
// not the headline.
func selectRecordInFrame(
	recs []vuldomain.VulnerabilityRecord,
	rooting vuldomain.Rooting,
) (vuldomain.VulnerabilityRecord, vuldomain.VulnerabilityRecord, bool, bool) {
	if len(recs) == 0 {
		return vuldomain.VulnerabilityRecord{}, vuldomain.VulnerabilityRecord{}, false, false
	}
	rec, found, err := vuldomain.ComposeAt(recs, rooting)
	if err != nil {
		return vuldomain.VulnerabilityRecord{}, vuldomain.VulnerabilityRecord{}, false, false
	}
	if !found {
		isolated, hasIsolated, ierr := vuldomain.ComposeAt(isolatedOnly(recs), vuldomain.RootingIsolated)
		if ierr != nil || !hasIsolated {
			return vuldomain.VulnerabilityRecord{}, vuldomain.VulnerabilityRecord{}, false, false
		}
		// Served as the answer, not as an aside: it IS the answer, and the record
		// states the isolated frame itself on every surface that prints one.
		return isolated, vuldomain.VulnerabilityRecord{}, false, true
	}
	if vuldomain.RecordRooting(rec) == vuldomain.RootingIsolated {
		// An aside drawn from the frame that produced the answer is the same
		// record printed twice.
		return rec, vuldomain.VulnerabilityRecord{}, false, true
	}
	isolated, hasIsolated, ierr := vuldomain.ComposeAt(isolatedOnly(recs), vuldomain.RootingIsolated)
	if ierr != nil {
		return rec, vuldomain.VulnerabilityRecord{}, false, true
	}
	return rec, isolated, hasIsolated, true
}

// isolatedOnly narrows a candidate set to the records that state the isolated
// frame.
//
// The filter is why the isolated reads above cannot be a bare ComposeAt over
// the whole set: ComposeAt falls back to the entire group when NO record states
// a frame, so on a store written before the frame existed it would hand back a
// record that never claimed the isolated frame and label it as one.
func isolatedOnly(recs []vuldomain.VulnerabilityRecord) []vuldomain.VulnerabilityRecord {
	out := make([]vuldomain.VulnerabilityRecord, 0, len(recs))
	for _, r := range recs {
		if vuldomain.RecordRooting(r) == vuldomain.RootingIsolated {
			out = append(out, r)
		}
	}
	return out
}

// recordInWalkFrame reads one coordinate's verdict in a walk's own frame, for
// the batch surfaces that report a walk's modules rather than answering a
// question about one.
//
// They take anchored selection without the refusal the single-coordinate
// commands carry: the walk they are reporting IS the anchor, so there is
// nothing for a caller to disambiguate and a per-module refusal would replace a
// report with an error about a question nobody asked. A walk whose record the
// store no longer holds has no frame to select on, so those fall back to
// consumer-frame selection — still never a frame-blind pick.
func recordInWalkFrame(
	ctx context.Context,
	uc QueryVulnUseCase,
	coord coordinate.ModuleCoordinate,
	anchor vulnFrameAnchor,
) (vuldomain.VulnerabilityRecord, bool, error) {
	candidates, err := uc.ListRecordsForModuleInWalk(ctx, coord, vulnPipelineVersion, anchor.walkID)
	if err != nil {
		return vuldomain.VulnerabilityRecord{}, false, fmt.Errorf("reading vulnerability records for %s in walk %s: %w", coord, anchor.walkID, err)
	}
	if len(candidates) == 0 {
		return vuldomain.VulnerabilityRecord{}, false, nil
	}
	if anchor.rooting.IsRecorded() {
		rec, _, _, ok := selectRecordInFrame(candidates, anchor.rooting)
		return rec, ok, nil
	}
	rec, _, _, ok := selectConsumerRecord(candidates, coord)
	return rec, ok, nil
}

// walkFrameAnchor is the frame of one walk, for a caller that already holds the
// walk record. It is the anchor constructor the batch surfaces use, where the
// walk is not a flag the operator passed but the subject of the report.
func walkFrameAnchor(walkID string, target coordinate.ModuleCoordinate) vulnFrameAnchor {
	rooting := vuldomain.TargetRootedAt(target)
	return vulnFrameAnchor{
		walkID:  walkID,
		rooting: rooting,
		source:  fmt.Sprintf("walk %q (frame %s)", walkID, rooting),
	}
}

// selectAnchoredRecord picks the answer out of one walk's candidate records.
//
// With a frame in hand it is the frame that decides, and nothing else: the
// candidate set spans every frame the coordinate was measured in at that
// generation, so ranking it blind is what let a walk-pinned read answer from a
// different walk. A frameless anchor — a walk whose record the store no longer
// holds — falls back to consumer-frame ranking within the walk's own candidates,
// and refuses if those hold more than one consumer's build.
func selectAnchoredRecord(
	candidates []vuldomain.VulnerabilityRecord,
	coord coordinate.ModuleCoordinate,
	anchor vulnFrameAnchor,
	cmdline string,
) (vuldomain.VulnerabilityRecord, vuldomain.VulnerabilityRecord, bool, bool, error) {
	if anchor.rooting.IsRecorded() {
		rec, aside, has, ok := selectRecordInFrame(candidates, anchor.rooting)
		return rec, aside, has, ok, nil
	}
	if frames := consumerFrames(candidates, coord); len(frames) > 1 {
		return vuldomain.VulnerabilityRecord{}, vuldomain.VulnerabilityRecord{}, false, false,
			ambiguousFrameRefusal(cmdline, coord, frames)
	}
	rec, aside, has, ok := selectConsumerRecord(candidates, coord)
	return rec, aside, has, ok, nil
}

// framesPresent lists, deduplicated and in a stable order, the frames the
// candidate records were measured in. It is what a refusal names so the reader
// can pick one.
func framesPresent(recs []vuldomain.VulnerabilityRecord) []vuldomain.Rooting {
	seen := map[vuldomain.Rooting]struct{}{}
	out := make([]vuldomain.Rooting, 0, 4)
	for _, r := range recs {
		rooting := vuldomain.RecordRooting(r)
		if _, dup := seen[rooting]; dup {
			continue
		}
		seen[rooting] = struct{}{}
		out = append(out, rooting)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// consumerFrames lists the distinct CONSUMER frames the candidates hold for
// coord: frames rooted at some build that depends on the module.
//
// A frame rooted at coord itself is excluded — the module is its own root there,
// so no consumer sits above it — and so is the isolated frame, which answers a
// different question and is already reported as an aside. What is left is the
// set of builds whose answer a reader might have meant; more than one of them
// makes an unanchored question unanswerable.
func consumerFrames(recs []vuldomain.VulnerabilityRecord, coord coordinate.ModuleCoordinate) []vuldomain.Rooting {
	seen := map[vuldomain.Rooting]struct{}{}
	out := make([]vuldomain.Rooting, 0, 2)
	for _, r := range recs {
		rooting := vuldomain.RecordRooting(r)
		if !rooting.IsTargetRooted() || rooting.IsRootedAt(coord) {
			continue
		}
		if _, dup := seen[rooting]; dup {
			continue
		}
		seen[rooting] = struct{}{}
		out = append(out, rooting)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ambiguousFrameRefusal is the error a read returns when the store holds the
// coordinate in more than one consumer frame and the caller named none.
//
// It refuses rather than picking the newest. Newest is not yours: the newest
// scan of a shared dependency belongs to whichever project was scanned last, and
// serving it silently answered a corteza triage from a langchaingo build — with
// the opposite verdict, at full confidence, at exit 0. The frames are named
// because the remedy is to pick one, and the selectors are named because the
// reader has to be able to.
func ambiguousFrameRefusal(cmdline string, coord coordinate.ModuleCoordinate, frames []vuldomain.Rooting) error {
	msg := fmt.Sprintf("the store holds %s in %d consumer frames, and this question names none:", coord, len(frames))
	for _, f := range frames {
		msg += "\n  " + f.String()
	}
	msg += fmt.Sprintf(
		"\nname the build you mean: %s --walk-id <walk of that build>, or %s --gomod <path/to/go.mod>"+
			"\nkanonarion vuln-show %s --history lists every stored record and the frame it was measured in",
		cmdline, cmdline, coord)
	return &exitError{code: ExitConfig, msg: msg}
}
