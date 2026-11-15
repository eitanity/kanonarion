package cgchild

import (
	"context"
	"fmt"
	"io"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/exitcode"
	"code.eitanity.com/kanonarion/internal/walk/adapters/buildlist/tinygo"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// Frame is the build frame an extraction runs under: Current reads it, and
// Declare settles it and re-wires whatever analyses under it.
type Frame struct {
	Current func() cgdomain.BuildFrame
	Declare func(goenv.Target, goenv.TinyGo)
}

// WalkFrameMatches reports whether a walk's build environment is the frame f.
// A standard walk records no GOARM, so GOARM is compared only where the walk
// states one.
func WalkFrameMatches(env walkdomain.BuildEnv, f cgdomain.BuildFrame) bool {
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

// walkFlagSpelling is the declaration that names a walk's frame.
func walkFlagSpelling(env walkdomain.BuildEnv) string {
	if env.TinyGoTarget != "" {
		return " --tinygo " + env.TinyGoTarget
	}
	return " --target " + env.GOOS + "/" + env.GOARCH
}

// ProbeTinyGo settles a TinyGo target through the tinygo command rather than
// `go tool dist list`, which knows no board names, merged from the toolchain the
// tree at dir resolves; an empty dir is a tree with no go.mod. Every refusal is
// an invocation error: the command, the target name or the host's Go is what
// has to change.
func ProbeTinyGo(ctx context.Context, name, goBinary, dir string) (goenv.Target, goenv.TinyGo, error) {
	tc, err := tinygo.Toolchain(ctx, goBinary, dir)
	if err != nil {
		return goenv.Target{}, goenv.TinyGo{}, &exitcode.Error{Code: exitcode.Config, Msg: err.Error()}
	}
	return probeFrame(ctx, name, tc)
}

// probeFrame is ProbeTinyGo for a toolchain already chosen.
func probeFrame(ctx context.Context, name string, tc goenv.OnDiskToolchain) (goenv.Target, goenv.TinyGo, error) {
	frame, err := tinygo.Probe(ctx, "", name, tc)
	if err != nil {
		return goenv.Target{}, goenv.TinyGo{}, &exitcode.Error{Code: exitcode.Config, Msg: err.Error()}
	}
	pair, err := goenv.NewTarget(frame.GOOS(), frame.GOARCH())
	if err != nil {
		return goenv.Target{}, goenv.TinyGo{}, &exitcode.Error{Code: exitcode.Config, Msg: fmt.Sprintf("tinygo target %q: %v", name, err)}
	}
	return pair, frame, nil
}

// AdoptBuildEnv declares a walk's frame. A TinyGo frame is asked of the
// tinygo command again: its GOROOT is this host's, and the walk does not
// record it. It merges from the toolchain the walk resolved under, so the
// dependency graphs match the project's; a walk naming none uses the installed Go.
func AdoptBuildEnv(ctx context.Context, env walkdomain.BuildEnv, declare func(goenv.Target, goenv.TinyGo)) error {
	if env.TinyGoTarget != "" {
		pair, frame, err := probeWalkFrame(ctx, env)
		if err != nil {
			return err
		}
		declare(pair, frame)
		return nil
	}
	t, err := goenv.NewTarget(env.GOOS, env.GOARCH)
	if err != nil {
		return fmt.Errorf("the walk's frame: %w", err)
	}
	declare(t, goenv.TinyGo{})
	return nil
}

// probeWalkFrame resolves a walk's TinyGo frame for the toolchain it names.
func probeWalkFrame(ctx context.Context, env walkdomain.BuildEnv) (goenv.Target, goenv.TinyGo, error) {
	if env.GoVersion == "" {
		return ProbeTinyGo(ctx, env.TinyGoTarget, "", "")
	}
	tc, err := tinygo.NamedToolchain(ctx, "", env.GoVersion)
	if err != nil {
		return goenv.Target{}, goenv.TinyGo{}, &exitcode.Error{Code: exitcode.Config, Msg: err.Error()}
	}
	return probeFrame(ctx, env.TinyGoTarget, tc)
}

// adoptWalkFrame makes the walk --from-walk names the extraction frame.
//
// A declared frame that disagrees with the walk is refused by name: the build
// list is a property of that walk's frame, and analysing it under another would
// record a graph of a build nobody resolved. With no declaration the walk's
// frame is adopted, and a non-host one is announced.
func adoptWalkFrame(ctx context.Context, walks WalkReader, frame Frame, coord coordinate.ModuleCoordinate, walkID string, declared bool, stderr io.Writer) error {
	// The standard library resolves no build list, so a walk names no frame for it.
	if walkID == "" || coord.IsStdlib() {
		return nil
	}
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return fmt.Errorf("--from-walk: loading walk %q: %w", walkID, err)
	}
	env := rec.Graph.BuildEnv
	if env.GOOS == "" || env.GOARCH == "" {
		// A walk that resolved no platform names no frame to adopt or contradict.
		return nil
	}
	current := frame.Current()
	if WalkFrameMatches(env, current) {
		return nil
	}
	if declared {
		return &exitcode.Error{Code: exitcode.Config, Msg: fmt.Sprintf(
			"walk %s was resolved for %s, and this invocation declares %s; the build list is that walk's, "+
				"so declare its frame or drop the flag:\n  kanonarion callgraph %s --from-walk %s%s",
			walkID, walkFrameText(env), current, coord, walkID, walkFlagSpelling(env))}
	}
	if err := AdoptBuildEnv(ctx, env, frame.Declare); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "notice: walk %s was resolved for %s, so the analysis runs under that frame\n",
		walkID, walkFrameText(env))
	return nil
}
