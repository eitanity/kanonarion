package cli

import (
	"code.eitanity.com/kanonarion/internal/composition/cgchild"
	"context"
	"fmt"
	"io"
	"strings"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// frameDescription is a record's build frame as text output names it: the
// platform, then the TinyGo release and tags a TinyGo frame was resolved with.
func frameDescription(f cgdomain.BuildFrame) string {
	text := f.String()
	if f.TinyGoTarget == "" {
		return text
	}
	if f.TinyGoVersion != "" {
		text += "  tinygo " + f.TinyGoVersion
	}
	if len(f.TinyGoTags) > 0 {
		text += "  tags " + strings.Join(f.TinyGoTags, ",")
	}
	return text
}

// writeFrameLine prints the frame a record was extracted under. A record that
// states none prints nothing: it predates the field, and its pipeline is never
// served beside one that does.
func writeFrameLine(stdout io.Writer, r cgdomain.CallGraphRecord) error {
	line := recordFrameLine(r)
	if line == "" {
		return nil
	}
	if _, err := io.WriteString(stdout, line); err != nil {
		return fmt.Errorf("writing frame: %w", err)
	}
	return nil
}

// recordFrameLine is the line writeFrameLine prints, "" for a record that states no frame.
func recordFrameLine(r cgdomain.CallGraphRecord) string {
	if r.Frame.IsZero() {
		return ""
	}
	return fmt.Sprintf("  frame: %s%s\n", frameDescription(r.Frame), tinyGoEdgeCounts(r))
}

// historyFrame is the frame line of one generation in --history, empty for a
// generation that states none.
func historyFrame(r cgdomain.CallGraphRecord) string {
	if r.Frame.IsZero() {
		return ""
	}
	return "    frame:    " + frameDescription(r.Frame) + "\n"
}

// summaryFrame is the frame clause the local and callgraph summaries carry.
func summaryFrame(r cgdomain.CallGraphRecord) string {
	if r.Frame.IsZero() {
		return ""
	}
	return " frame " + r.Frame.String()
}

// frameJSON is the build frame on the --json surfaces; absent for a record
// that states none.
type frameJSON struct {
	Text          string   `json:"text"`
	GOOS          string   `json:"goos"`
	GOARCH        string   `json:"goarch"`
	GOARM         string   `json:"goarm,omitempty"`
	TinyGoTarget  string   `json:"tinygo_target,omitempty"`
	TinyGoVersion string   `json:"tinygo_version,omitempty"`
	TinyGoTags    []string `json:"tinygo_tags,omitempty"`
}

func toFrameJSON(f cgdomain.BuildFrame) *frameJSON {
	if f.IsZero() {
		return nil
	}
	return &frameJSON{
		Text: f.String(), GOOS: f.GOOS, GOARCH: f.GOARCH, GOARM: f.GOARM,
		TinyGoTarget: f.TinyGoTarget, TinyGoVersion: f.TinyGoVersion, TinyGoTags: f.TinyGoTags,
	}
}

// adoptBuildEnv sets the invocation's declaration from a walk's frame.
func adoptBuildEnv(ctx context.Context, env walkdomain.BuildEnv) error {
	return asExitError(cgchild.AdoptBuildEnv(ctx, env, declare))
}

// frameReanalysis is the re-analysis line for coord under this invocation's
// frame, so the remedy produces a record the refused read would select.
func frameReanalysis(coord coordinate.ModuleCoordinate, dir string) string {
	if line, ok := cgdomain.ReanalysisCommand(coord, dir, false); ok {
		return line + targetFlagHint()
	}
	return cgdomain.ReanalysisInstruction(coord, dir)
}

// frameMiss is the refusal for a read whose frame selects none of the records
// the ledger holds for coord at this pipeline, in the shape the toolchain
// refusal uses. It is nil when no other frame is held, and the ordinary
// absence applies.
func frameMiss(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryCallGraphUseCase) error {
	recs, err := uc.CallGraphHistory(ctx, coord, cgapp.PipelineVersion)
	if err != nil || len(recs) == 0 {
		return nil //nolint:nilerr // an unreadable history leaves the ordinary refusal to say what is absent
	}
	want := invocationFrame()
	held, flags := cgdomain.HeldFrames(recs, want)
	if len(held) == 0 {
		return nil
	}
	msg := fmt.Sprintf("no callgraph record for %s extracted under %s — the ledger holds one extracted under %s; try --history",
		coord, want, strings.Join(held, ", "))
	if len(flags) > 0 {
		msg += ", or read that frame with " + strings.Join(flags, " or ")
	}
	// A generation that also failed to decode is a second reason, stated after the frame.
	if note, nerr := supersededGenerationsNote(ctx, coord, uc, recs, nil); nerr == nil && note != "" {
		msg += "; " + note
	}
	msg += ". Produce one under " + want.String() + ":\n  " + frameReanalysis(coord, cgdomain.AgreedRoot(recs))
	return &exitError{code: ExitNotFound, msg: msg}
}

// moduleFrameMiss is frameMiss for a read that resolved a symbol to modulePath
// and found no record of it under the read frame: the first of versions, in the
// caller's order, held under another frame names the refusal.
func moduleFrameMiss(ctx context.Context, uc QueryCallGraphUseCase, modulePath string, versions []string) error {
	for _, v := range versions {
		coord, err := coordinate.NewModuleCoordinate(modulePath, v)
		if err != nil {
			continue
		}
		if miss := frameMiss(ctx, coord, uc); miss != nil {
			return miss
		}
	}
	return nil
}

// adoptNamedWalkFrame makes the walk --walk-id names supply the call-graph read
// frame, so the module set and the graphs come from one build. A walk that
// resolved no platform names no frame, and a missing walk is the read's to
// report, so both leave the frame as it is.
func adoptNamedWalkFrame(ctx context.Context, walks QueryWalksUseCase, walkID string) error {
	if walkID == "" {
		return nil
	}
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return nil //nolint:nilerr // the read that follows reports the missing walk in its own words
	}
	env := rec.Graph.BuildEnv
	if env.GOOS == "" || env.GOARCH == "" {
		return nil
	}
	return adoptBuildEnv(ctx, env)
}

// tinyGoEdgeCounts is the frame line's count of the edges TinyGo supplies, ""
// when the record holds none.
func tinyGoEdgeCounts(r cgdomain.CallGraphRecord) string {
	var compiler, linkname int
	for i := range r.Edges {
		switch r.Edges[i].Kind {
		case cgdomain.EdgeKindCompilerInserted:
			compiler++
		case cgdomain.EdgeKindLinkname:
			linkname++
		}
	}
	if compiler == 0 && linkname == 0 {
		return ""
	}
	return fmt.Sprintf(" — %d compiler-inserted and %d linkname edges", compiler, linkname)
}
