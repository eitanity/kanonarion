package domain

import (
	"slices"
	"strings"
)

// BuildFrame is the platform a call graph was extracted under: the GOOS, GOARCH
// and GOARM the loader's own go command resolved, and the TinyGo target when one
// was declared. Build constraints decide which files a package compiles, so two
// frames are two graphs of one module.
//
// The zero value is "unrecorded": a record written before the field existed. It
// is never read as the host.
type BuildFrame struct {
	GOOS          string
	GOARCH        string
	GOARM         string
	TinyGoTarget  string
	TinyGoVersion string
	TinyGoTags    []string
}

// frameTextUnrecorded is how a zero frame renders, the word the walk uses.
const frameTextUnrecorded = "unrecorded"

// IsZero reports whether the frame records no platform.
func (f BuildFrame) IsZero() bool { return f.GOOS == "" && f.GOARCH == "" }

// String renders the frame the way a walk renders its own, so the two surfaces
// name one platform in one spelling.
func (f BuildFrame) String() string {
	switch {
	case f.IsZero():
		return frameTextUnrecorded
	case f.TinyGoTarget != "":
		return "tinygo/" + f.TinyGoTarget + " (" + f.GOOS + "/" + f.GOARCH + ")"
	}
	return f.GOOS + "/" + f.GOARCH
}

// FlagSpelling is the declaration that selects this frame on a command line,
// empty for a zero frame, which no flag selects.
func (f BuildFrame) FlagSpelling() string {
	switch {
	case f.IsZero():
		return ""
	case f.TinyGoTarget != "":
		return "--tinygo " + f.TinyGoTarget
	}
	return "--target " + f.GOOS + "/" + f.GOARCH
}

// SameFrame reports whether a and b are one frame for selection. The TinyGo
// version and tags are recorded and printed but not selected on: the target
// name is what a reader declares, and the tinygo command defines the rest.
func SameFrame(a, b BuildFrame) bool {
	return a.GOOS == b.GOOS && a.GOARCH == b.GOARCH && a.GOARM == b.GOARM && a.TinyGoTarget == b.TinyGoTarget
}

// frameKey is the selection key as one comparable value.
type frameKey struct{ goos, goarch, goarm, tinygo string }

func keyOf(f BuildFrame) frameKey { return frameKey{f.GOOS, f.GOARCH, f.GOARM, f.TinyGoTarget} }

// withFrame keeps the records extracted under want, in append order.
func withFrame(records []CallGraphRecord, want BuildFrame) []CallGraphRecord {
	out := make([]CallGraphRecord, 0, len(records))
	for _, r := range records {
		if SameFrame(r.Frame, want) {
			out = append(out, r)
		}
	}
	return out
}

// frameConflict refuses a read that named no frame over records of more than
// one: a graph of one platform is no answer about another, and nothing ranks
// them.
func frameConflict(records []CallGraphRecord) *CallGraphConflict {
	seen := map[frameKey]int{}
	var frames []BuildFrame
	var hashes []string
	for _, r := range records {
		k := keyOf(r.Frame)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = len(frames)
		frames = append(frames, r.Frame)
		hashes = append(hashes, r.ContentHash)
	}
	if len(frames) < 2 {
		return nil
	}
	order := make([]int, len(frames))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int { return compareFrames(frames[a], frames[b]) })
	c := &CallGraphConflict{
		Coordinate:      records[0].Coordinate,
		PipelineVersion: records[0].PipelineVersion,
		AnalysisRoot:    agreedAnalysisRoot(records),
		Field:           ConflictFieldFrame,
	}
	for _, i := range order {
		c.Values = append(c.Values, frames[i].String())
		c.ContentHashes = append(c.ContentHashes, hashes[i])
		c.Frames = append(c.Frames, frames[i])
	}
	return c
}

// compareFrames orders frames on every field of the selection key. Frames are
// deduplicated on that key first, so no two compare equal.
func compareFrames(a, b BuildFrame) int {
	for _, c := range [][2]string{
		{a.GOOS, b.GOOS}, {a.GOARCH, b.GOARCH}, {a.GOARM, b.GOARM}, {a.TinyGoTarget, b.TinyGoTarget},
	} {
		if r := strings.Compare(c[0], c[1]); r != 0 {
			return r
		}
	}
	return 0
}
