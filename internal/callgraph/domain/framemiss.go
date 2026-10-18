package domain

import (
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// HeldFrames names the distinct frames recs were extracted under other than
// want, in first-seen order, and the flag that selects each. Every read that
// reports a frame miss names them through here, so the spellings cannot drift.
func HeldFrames(recs []CallGraphRecord, want BuildFrame) (frames, flags []string) {
	seen := map[string]bool{}
	for _, r := range recs {
		if r.Frame.IsZero() || SameFrame(r.Frame, want) || seen[r.Frame.String()] {
			continue
		}
		seen[r.Frame.String()] = true
		frames = append(frames, r.Frame.String())
		flags = append(flags, r.Frame.FlagSpelling())
	}
	return frames, flags
}

// AgreedRoot is the working tree every generation naming one agrees on, empty
// when they disagree or none names one; a remedy names only a tree they share.
func AgreedRoot(recs []CallGraphRecord) string {
	root := ""
	for _, r := range recs {
		switch {
		case r.AnalysisRoot == "":
		case root == "":
			root = r.AnalysisRoot
		case root != r.AnalysisRoot:
			return ""
		}
	}
	return root
}

// FrameMissReason states that coord's call graph is held only under frames
// other than want, and the remedy that produces want's. whose names the reader
// of want ("this scan's", "this read's"); wantFlag is the declaration selecting
// want, empty for an undeclared host. ok is false when recs hold no other frame.
func FrameMissReason(coord coordinate.ModuleCoordinate, recs []CallGraphRecord, want BuildFrame, wantFlag, whose string) (reason, remedy string, ok bool) {
	frames, flags := HeldFrames(recs, want)
	if len(frames) == 0 {
		return "", "", false
	}
	reason = fmt.Sprintf("the call graph of %s is held under %s, not under %s frame %s; read it with %s",
		coord, strings.Join(frames, ", "), whose, want, strings.Join(flags, " or "))
	// The working-tree lead is reached only when no generation names a tree.
	if line, named := ReanalysisCommand(coord, AgreedRoot(recs), false); named {
		return reason, line + wantFlag, true
	}
	return reason, ReanalysisInstruction(coord, ""), true
}
