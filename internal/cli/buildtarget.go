package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/gotoolchain"
	"github.com/spf13/cobra"
)

// declaredTarget is the platform this invocation declared, or the zero value
// when it declared none.
//
// It is process-wide for the same reason the module-cache mode is: one process
// runs one command, everything that resolves has to agree about the platform it
// resolved for, and the container wires its adapters from what the command
// settled before it opened the store. resolveBuildTarget CLEARS it when no flag
// is given, so a test binary running several commands cannot have a later
// invocation inherit an earlier one's target and record a platform nobody asked
// for.
var declaredTarget goenv.Target

// buildTargetFlags are the three spellings of one declaration. --target is the
// canonical one — it is the pair, and the pair is what `go tool dist list`
// prints and what the docs use; --goos/--goarch exist because the two halves
// have names of their own and a script that already holds them separately
// should not have to join them.
type buildTargetFlags struct {
	goos   string
	goarch string
	target string
}

// registerBuildTargetFlags registers the declaration on cmd. Every resolving
// command shares this one registration so the names, the defaults and the help
// cannot drift apart.
func registerBuildTargetFlags(cmd *cobra.Command, f *buildTargetFlags) {
	cmd.Flags().StringVar(&f.target, "target", "", "build target as GOOS/GOARCH, e.g. wasip1/wasm (default: this host's platform)")
	cmd.Flags().StringVar(&f.goos, "goos", "", "target operating system; the GOOS half of --target (default: this host's)")
	cmd.Flags().StringVar(&f.goarch, "goarch", "", "target architecture; the GOARCH half of --target (default: this host's)")
}

// declared reports whether the caller named anything at all, so the default path
// can be told apart from a declaration that happens to name the host.
func (f buildTargetFlags) declared() bool {
	return f.target != "" || f.goos != "" || f.goarch != ""
}

// target reads the declaration out of the flags, refusing the combinations that
// mean two different things at once.
//
// --target and the halves are mutually exclusive rather than merged: a caller
// who wrote both has stated the platform twice, and a rule about which wins
// would make one of the two lines they typed do nothing.
func (f buildTargetFlags) parse() (goenv.Target, error) {
	if f.target != "" {
		if f.goos != "" || f.goarch != "" {
			return goenv.Target{}, fmt.Errorf("--target and --goos/--goarch both declare the build target; pass one of them")
		}
		t, err := goenv.ParseTarget(f.target)
		if err != nil {
			return goenv.Target{}, fmt.Errorf("--target: %w", err)
		}
		return t, nil
	}
	if !f.declared() {
		return goenv.Target{}, nil
	}
	t, err := goenv.NewTarget(f.goos, f.goarch)
	if err != nil {
		return goenv.Target{}, fmt.Errorf("--goos/--goarch: %w", err)
	}
	return t, nil
}

// resolveBuildTarget settles the platform this invocation resolves for, before
// the store is opened and before any child is spawned.
//
// With no flag it clears the declaration and returns immediately: the default
// path asks the toolchain nothing it did not already ask, which is what "zero
// added time on an existing path" means here. With a flag it validates the pair
// against `go tool dist list` taken from the toolchain in hand — one subprocess,
// paid only by the caller who asked for it — and refuses an unlisted pair by
// name.
//
// dir is the directory the toolchain is asked in, so a project pinning its own
// toolchain is validated against the Go that will actually resolve it.
func resolveBuildTarget(ctx context.Context, f buildTargetFlags, goBinary, dir string) error {
	declaredTarget = goenv.Target{}
	if !f.declared() {
		return nil
	}
	t, err := f.parse()
	if err != nil {
		return err
	}
	supported, offered, err := gotoolchain.New(goBinary, nil).Supports(ctx, t)
	if err != nil {
		return fmt.Errorf("validating the build target %s: %w", t, err)
	}
	if !supported {
		return unsupportedTargetError(t, offered)
	}
	declaredTarget = t
	return nil
}

// unsupportedTargetError is the refusal for a pair this toolchain does not build
// for.
//
// It names the pair it rejected and the command that lists the alternatives,
// because a refusal is only actionable when it says what would make it stop. The
// toolchain does refuse an unknown pair — `go list` exits 1 and resolves nothing
// — but its sentence names a cgo linking mode or a build constraint inside some
// dependency, never GOOS or GOARCH. So an operator who mistyped an architecture
// is shown a symptom with nothing pointing at the cause. This refusal names the
// cause, and arrives before any resolution is attempted.
func unsupportedTargetError(t goenv.Target, offered []goenv.Target) error {
	var b strings.Builder
	fmt.Fprintf(&b, "build target %s is not one this Go toolchain builds for", t)
	if near := nearestTargets(t, offered); len(near) > 0 {
		fmt.Fprintf(&b, " (it does build %s)", strings.Join(near, ", "))
	}
	fmt.Fprintf(&b, "; run `go tool dist list` for the %d pairs it offers", len(offered))
	return fmt.Errorf("%s", b.String())
}

// nearestTargets are the offered pairs sharing a half with the one refused, at
// most four of them. A reader who mistyped an architecture is looking for the
// architectures their OS has, and a 47-line list in an error message is a list
// nobody reads.
func nearestTargets(t goenv.Target, offered []goenv.Target) []string {
	var out []string
	for _, s := range offered {
		if s.GOOS() != t.GOOS() && s.GOARCH() != t.GOARCH() {
			continue
		}
		out = append(out, s.String())
		if len(out) == 4 {
			break
		}
	}
	return out
}

// targetClause names the declared platform in a refusal raised by a child that
// resolved for it.
//
// It is empty for the host, declared or not. The toolchain's own sentence about
// a cross-target resolution names neither GOOS nor GOARCH — it names a cgo
// linking mode, or a build constraint inside a dependency five levels down — so
// an operator who mistyped a target is shown the symptom with nothing pointing
// at the cause. This is the pointer, and it is added only where the target IS
// the cause: a host resolution that fails fails for its own reasons.
func targetClause() string {
	if !declaredTarget.Declared() || declaredTarget.IsHost() {
		return ""
	}
	return fmt.Sprintf(" (resolving for the declared build target %s; this failure may be the target's rather than the project's)", declaredTarget)
}

// targetFlagHint is the declaration a printed remedy has to carry to reach the
// answer the read refused to give.
//
// A read selects a stored walk by platform, so a refusal raised under a declared
// target is about a walk for THAT target. A remedy that named `kanonarion walk
// --gomod ./go.mod` alone records a walk for the host instead, leaving the walk
// the reader asked about exactly as unreachable as before — the printed-remedy
// class this project has already closed once. Everything that prints a walk or
// scope-scan invocation as advice appends this, so the string the reader runs is
// the one that answers their question.
//
// Empty for an undeclared target, which is what keeps the no-flag output
// byte-identical. The canonical --target spelling is used whichever spelling the
// caller typed: both halves are known here, and one pair is easier to read than
// two flags.
func targetFlagHint() string {
	if !declaredTarget.Declared() {
		return ""
	}
	return " --target " + declaredTarget.String()
}

// resolveReadTarget settles the build target a walk-READING command selects its
// walk in.
//
// selectsByManifest says whether this invocation reaches a manifest-led walk
// selection at all. A target declared beside --walk-id, or on a form that names
// no build, filters nothing: the walk is already named, or none is chosen. Such
// a declaration is refused by name rather than accepted and discarded, on the
// same terms as every other flag this CLI refuses where it cannot act — a
// platform the caller stated and the read ignored is a silent wrong answer, and
// this command produces evidence.
//
// The undeclared path returns before it touches the filesystem or the toolchain.
// That is what "zero added time on the existing path" means here: no manifest is
// located, no `go tool dist list` is run, and declaredTarget is cleared so a
// test binary running several commands cannot inherit an earlier one's target.
func resolveReadTarget(ctx context.Context, f buildTargetFlags, path string, selectsByManifest bool, gomod string) error {
	if !f.declared() {
		return resolveBuildTarget(ctx, f, "", "")
	}
	if !selectsByManifest {
		return refuseInapplicableFlags(path, []inapplicableFlag{{
			flag:  "--target/--goos/--goarch",
			where: "a read that selects its walk by manifest (--gomod); a walk named by id already records the platform it resolved under",
		}})
	}
	// The toolchain is asked in the project's own directory, so a project pinning
	// its own Go is validated against the Go that resolved its walks. A manifest
	// that cannot be located is left to the read itself to refuse, with the
	// message it already has for that.
	dir := ""
	if p, perr := resolveGoModPath(gomod); perr == nil {
		dir = filepath.Dir(p)
	}
	return resolveBuildTarget(ctx, f, "", dir)
}
