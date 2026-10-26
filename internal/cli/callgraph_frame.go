package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
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

// walkFrameMatches reports whether a walk's build environment is the frame f.
// A standard walk records no GOARM, so GOARM is compared only where the walk
// states one.
func walkFrameMatches(env walkdomain.BuildEnv, f cgdomain.BuildFrame) bool {
	if env.GOOS != f.GOOS || env.GOARCH != f.GOARCH || env.TinyGoTarget != f.TinyGoTarget {
		return false
	}
	return env.GOARM == "" || env.GOARM == f.GOARM
}

// walkFrameText names a walk's frame in the spelling a record uses.
func walkFrameText(env walkdomain.BuildEnv) string {
	if env.TinyGoTarget != "" {
		return walkdomain.TinyGoFrameText(env.TinyGoTarget, env.GOOS, env.GOARCH)
	}
	return env.GOOS + "/" + env.GOARCH
}

// adoptWalkFrame makes the walk --from-walk names the extraction frame.
//
// A declared frame that disagrees with the walk is refused by name: the build
// list is a property of that walk's frame, and analysing it under another would
// record a graph of a build nobody resolved. With no declaration the walk's
// frame is adopted, and a non-host one is announced.
func adoptWalkFrame(ctx context.Context, ctr *Container, coord coordinate.ModuleCoordinate, walkID string, declared bool, stderr io.Writer) error {
	// The standard library resolves no build list, so a walk names no frame for it.
	if walkID == "" || coord.IsStdlib() {
		return nil
	}
	rec, err := ctr.QueryWalks.GetWalk(ctx, walkID)
	if err != nil {
		return fmt.Errorf("--from-walk: loading walk %q: %w", walkID, err)
	}
	env := rec.Graph.BuildEnv
	if env.GOOS == "" || env.GOARCH == "" {
		// A walk that resolved no platform names no frame to adopt or contradict.
		return nil
	}
	current := invocationFrame()
	if walkFrameMatches(env, current) {
		return nil
	}
	if declared {
		return &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"walk %s was resolved for %s, and this invocation declares %s; the build list is that walk's, "+
				"so declare its frame or drop the flag:\n  kanonarion callgraph %s --from-walk %s%s",
			walkID, walkFrameText(env), current, coord, walkID, walkFlagSpelling(env))}
	}
	if err := adoptBuildEnv(ctx, env); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "notice: walk %s was resolved for %s, so the analysis runs under that frame\n",
		walkID, walkFrameText(env))
	return nil
}

// walkFlagSpelling is the declaration that names a walk's frame.
func walkFlagSpelling(env walkdomain.BuildEnv) string {
	if env.TinyGoTarget != "" {
		return " --tinygo " + env.TinyGoTarget
	}
	return " --target " + env.GOOS + "/" + env.GOARCH
}

// adoptBuildEnv sets the invocation's declaration from a walk's frame. A TinyGo
// frame is asked of the tinygo command again: its GOROOT is this host's, and
// the walk does not record it.
func adoptBuildEnv(ctx context.Context, env walkdomain.BuildEnv) error {
	if env.TinyGoTarget != "" {
		return resolveTinyGoTarget(ctx, env.TinyGoTarget)
	}
	t, err := goenv.NewTarget(env.GOOS, env.GOARCH)
	if err != nil {
		return fmt.Errorf("the walk's frame: %w", err)
	}
	declare(t, goenv.TinyGo{})
	return nil
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
