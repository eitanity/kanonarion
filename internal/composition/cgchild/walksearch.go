package cgchild

import (
	"context"
	"fmt"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/exitcode"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// WalkReader reads walks: the two reads the extraction and the walk search make.
type WalkReader interface {
	GetWalk(ctx context.Context, id string) (walkdomain.WalkRecord, error)
	ListWalks(ctx context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error)
}

// WalkSearchLimit is how many of the newest walks the containment search reads.
// It is a bound on cost — each candidate costs a whole walk record read — and
// not a statement that older walks hold nothing.
const WalkSearchLimit = 50

// Holding is the walk a search found holding a coordinate.
type Holding struct {
	WalkID string
	// SelfRootedOnly is set when the only walks holding the coordinate are
	// rooted at it; otherwise a walk rooted at a consuming build answered.
	SelfRootedOnly bool
	// Root is the answering walk's target: the build the answer is about.
	Root coordinate.ModuleCoordinate
	// SelfRootedPassedOver counts the walks rooted at the coordinate that a
	// consumer build outranked; FramePassedOver, the walks of another frame a
	// frame-scoped search left out.
	SelfRootedPassedOver int
	FramePassedOver      int
}

// Ambiguity is the refusal a search returns when more than one consumer build
// holds the coordinate and the caller named none. It carries Config.
type Ambiguity struct {
	Coord      coordinate.ModuleCoordinate
	Candidates []walkports.WalkSummary
	msg        string
}

func (e *Ambiguity) Error() string { return e.msg }

func (e *Ambiguity) Unwrap() error { return &exitcode.Error{Code: exitcode.Config, Msg: e.msg} }

// NewAmbiguity builds that refusal, naming every build and the walk that would
// answer for it.
//
// It refuses rather than picking the newest: newest is not yours. Serving
// whichever project was walked last answers one project's question from
// another project's build, at exit 0. The walks are named because the remedy
// is to pick one.
func NewAmbiguity(coord coordinate.ModuleCoordinate, remedy string, candidates []walkports.WalkSummary) *Ambiguity {
	msg := fmt.Sprintf("the store holds %s in %d builds, and this question names none:", coord, len(candidates))
	for _, c := range candidates {
		msg += fmt.Sprintf("\n  walk %s  rooted at %s", c.ID, c.Target)
	}
	msg += fmt.Sprintf(
		"\nwhat a coordinate is surrounded by is a property of one build, so name the build you mean:"+
			"\n  %s"+
			"\nkanonarion walk-list lists every walk in the store", remedy)
	return &Ambiguity{Coord: coord, Candidates: candidates, msg: msg}
}

// FindWalkHolding returns the walk a question about coord is answered in, out
// of the newest WalkSearchLimit walks whose graph holds it, restricted to walks
// resolved for frame when frame is non-nil.
//
// Candidates are ranked by rooting first and by recency only within a rooting:
// a walk rooted at a build that consumes coord outranks one rooted at coord
// itself, which holds no consumer to name. Two consumer builds are two answers,
// so the search refuses with an *Ambiguity. A walk that resolved no platform is
// in no frame and stays a candidate. A negative from a bounded search says it
// was bounded, so it is never read as the store never having seen coord.
func FindWalkHolding(
	ctx context.Context,
	uc WalkReader,
	coord coordinate.ModuleCoordinate,
	remedy string,
	frame *cgdomain.BuildFrame,
) (Holding, error) {
	// One extra row tells the search whether its own bound bit.
	summaries, err := uc.ListWalks(ctx, walkports.WalkFilter{Limit: WalkSearchLimit + 1})
	if err != nil {
		return Holding{}, fmt.Errorf("listing walks: %w", err)
	}
	searched, bounded := summaries, false
	if len(summaries) > WalkSearchLimit {
		searched, bounded = summaries[:WalkSearchLimit], true
	}

	consumers, selfRooted, framePassedOver := holders(ctx, uc, coord, searched, frame)
	switch {
	case len(consumers) > 1:
		return Holding{}, NewAmbiguity(coord, remedy, consumers)
	case len(consumers) == 1:
		return Holding{
			WalkID: consumers[0].ID, Root: consumers[0].Target,
			SelfRootedPassedOver: len(selfRooted), FramePassedOver: framePassedOver,
		}, nil
	case len(selfRooted) > 0:
		return Holding{WalkID: selfRooted[0].ID, SelfRootedOnly: true, Root: coord, FramePassedOver: framePassedOver}, nil
	}

	if !bounded {
		return Holding{}, fmt.Errorf("no walk in this store contains %s (all %d walk(s) searched)", coord, len(searched))
	}
	// Only now is the store's own size worth a read: it is what turns "the
	// search stopped" into a number the caller can act on.
	total := len(searched)
	if all, aerr := uc.ListWalks(ctx, walkports.WalkFilter{}); aerr == nil {
		total = len(all)
	}
	return Holding{}, fmt.Errorf("no walk containing %s among the %d most recent walks searched — the store holds %d; "+
		"name the walk to query with --walk-id, or list them with: kanonarion walk-list --limit 0",
		coord, WalkSearchLimit, total)
}

// holders sorts the searched walks holding coord into the consumer builds and
// the walks rooted at coord, counting those of another frame passed over.
func holders(ctx context.Context, uc WalkReader, coord coordinate.ModuleCoordinate, searched []walkports.WalkSummary, frame *cgdomain.BuildFrame) (consumers, selfRooted []walkports.WalkSummary, framePassedOver int) {
	held := make(map[coordinate.ModuleCoordinate]bool, len(searched))
	for _, s := range searched {
		if frame != nil && s.GOOS != "" && !WalkFrameMatches(
			walkdomain.BuildEnv{GOOS: s.GOOS, GOARCH: s.GOARCH, TinyGoTarget: s.TinyGoTarget}, *frame) {
			framePassedOver++
			continue
		}
		if s.Target == coord {
			// A walk's root is a node of its own graph, so a walk rooted at the
			// coordinate holds it by construction — known from the summary, at no
			// record read.
			selfRooted = append(selfRooted, s)
			continue
		}
		if held[s.Target] {
			// An older walk of a build already known to hold the coordinate can
			// neither name a build the refusal is missing nor win the recency
			// tiebreak, so it is not worth a record read.
			continue
		}
		rec, rerr := uc.GetWalk(ctx, s.ID)
		if rerr != nil {
			continue
		}
		if !GraphHolds(rec.Graph, coord) {
			continue
		}
		held[s.Target] = true
		consumers = append(consumers, s)
	}

	return consumers, selfRooted, framePassedOver
}

// GraphHolds reports whether g has coord as a node.
func GraphHolds(g walkdomain.Graph, coord coordinate.ModuleCoordinate) bool {
	for _, node := range g.Nodes {
		if node.Coordinate == coord {
			return true
		}
	}
	return false
}
