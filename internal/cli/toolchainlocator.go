package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// toolchainLocator finds the installed Go toolchain whose standard library a
// coordinate names.
//
// It lives at the composition root because answering means running a toolchain:
// a GOROOT is upgraded in place, so the directory holding one says where it came
// from and only the toolchain itself says which version it is. Every candidate
// is therefore asked, and a directory whose name promises a version its command
// does not report is refused rather than used.
//
// configured is the --go-binary this run was given, empty when none was: it is
// tried first, because an operator who named a toolchain named the one they
// meant.
type toolchainLocator struct {
	configured string
}

// newToolchainLocator returns a locator that prefers goBinary when set.
func newToolchainLocator(goBinary string) *toolchainLocator {
	return &toolchainLocator{configured: goBinary}
}

// LocateToolchain returns the toolchain reporting goVersion, searching the
// command this run was given or found on PATH first, then the two places a
// toolchain is unpacked offline — ~/sdk and the module cache.
//
// A toolchain with no standard-library source is not a candidate: a stripped
// install can run builds from its own pre-compiled packages and has nothing for
// an analysis to read.
func (l *toolchainLocator) LocateToolchain(ctx context.Context, goVersion string) (cgports.ToolchainSource, error) {
	want := stdlibdomain.CanonicalGoVersion(goVersion)
	if want == "" {
		return cgports.ToolchainSource{}, fmt.Errorf("%q names no toolchain version", goVersion)
	}
	var tried []string
	for _, bin := range l.candidateBinaries() {
		src, ok := toolchainAt(ctx, bin)
		if !ok {
			continue
		}
		if src.Version == want {
			return src, nil
		}
		tried = append(tried, src.Version)
	}
	return cgports.ToolchainSource{}, fmt.Errorf(
		"%w: %s is not installed on this host (searched the go command on PATH, ~/sdk and the module cache%s); "+
			"install it with `go install golang.org/dl/%s@latest` and run `%s download`",
		cgports.ErrToolchainSourceUnavailable, want, foundVersions(tried), want, want)
}

// foundVersions renders the versions the search did find, so a refusal says
// what is here rather than only what is not.
func foundVersions(tried []string) string {
	if len(tried) == 0 {
		return ""
	}
	seen := make(map[string]bool, len(tried))
	var out []string
	for _, v := range tried {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return ", which holds " + strings.Join(out, ", ")
}

// candidateBinaries lists the go commands worth asking, most deliberate first.
func (l *toolchainLocator) candidateBinaries() []string {
	var out []string
	if l.configured != "" {
		out = append(out, l.configured)
	}
	out = append(out, "go")
	// Every toolchain unpacked offline. The minimum is the lowest version this
	// comparison accepts, so the listing is "all of them" and the version test
	// below is what selects.
	for _, tc := range goenv.OnDiskToolchainsAtLeast("1.0") {
		out = append(out, filepath.Join(tc.Root, "bin", "go"))
	}
	return out
}

// toolchainAt asks one go command where its GOROOT is and which version it is,
// and reports it unusable when either answer is missing or its source tree is
// not there.
func toolchainAt(ctx context.Context, binary string) (cgports.ToolchainSource, bool) {
	// Through childproc, like every other child an analysis spawns, and pinned to
	// GOTOOLCHAIN=local: an unpinned probe switches to whatever the directory it
	// runs in asks for and answers about a toolchain nothing selected.
	cmd := childproc.CommandContext(ctx, binary, "env", "GOROOT", "GOVERSION") // #nosec G204 -- the binary is this run's --go-binary, "go" on PATH, or a GOROOT this process enumerated
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := cmd.Output()
	if err != nil {
		return cgports.ToolchainSource{}, false
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 2 {
		return cgports.ToolchainSource{}, false
	}
	root, version := strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
	if root == "" || version == "" {
		return cgports.ToolchainSource{}, false
	}
	if _, serr := os.Stat(filepath.Join(root, "src", "go.mod")); serr != nil {
		return cgports.ToolchainSource{}, false
	}
	return cgports.ToolchainSource{GoRoot: root, GoBinary: filepath.Join(root, "bin", "go"), Version: version}, true
}

// stdlibCustodyProjection adapts the stdlib fact ledger to the narrow anchor
// the call-graph stage reads.
//
// The call-graph context must not take a dependency on another bounded
// context's record shape to stamp two strings on a record, so the projection is
// made here, where both are already in scope.
type stdlibCustodyProjection struct {
	reader StdlibCustodyReader
}

// StdlibCustody returns the custody anchor recorded for goVersion.
func (p stdlibCustodyProjection) StdlibCustody(ctx context.Context, goVersion string) (cgports.StdlibCustody, bool, error) {
	if p.reader == nil {
		return cgports.StdlibCustody{}, false, nil
	}
	facts, found, err := p.reader.Get(ctx, goVersion)
	if err != nil {
		return cgports.StdlibCustody{}, false,
			fmt.Errorf("reading the standard-library chain of custody for %s: %w", goVersion, err)
	}
	if !found {
		return cgports.StdlibCustody{}, false, nil
	}
	identity := stdlibdomain.ArtefactIdentity(facts)
	if identity == "" {
		// A measurement that computed no digest names no bytes, and an anchor that
		// names no bytes is not one.
		return cgports.StdlibCustody{}, false, nil
	}
	return cgports.StdlibCustody{
		ArtefactIdentity: "sha256:" + identity,
		MeasurementHash:  facts.ContentHash,
		Verification:     string(facts.VerificationStatus),
	}, true, nil
}

// walkProjectDirs answers where a walk's working tree is, for the refusals that
// have to name the command analysing it.
//
// It reads one column of the walk the record names. The directory is recorded
// and was being ignored: a project-rooted frame whose tree the ledger names was
// being told "no stored record names the working tree", which the store itself
// contradicts.
type walkProjectDirs struct {
	walks QueryWalksUseCase
}

// WalkProjectDir returns the directory the walk was rooted at. A walk that
// records none — a coordinate walk — answers false, and so does a store that
// would not answer: a directory that is not known is never guessed.
func (w walkProjectDirs) WalkProjectDir(ctx context.Context, walkID string) (string, bool, error) {
	if w.walks == nil || walkID == "" {
		return "", false, nil
	}
	rec, err := w.walks.GetWalk(ctx, walkID)
	if err != nil {
		return "", false, fmt.Errorf("reading walk %s for its project directory: %w", walkID, err)
	}
	if rec.ProjectDir == "" {
		return "", false, nil
	}
	return rec.ProjectDir, true, nil
}

// WalkModules returns the modules the walk selected, the standard library and
// the walk's own target excluded. It reads the same record WalkProjectDir does.
func (w walkProjectDirs) WalkModules(ctx context.Context, walkID string) ([]vulnports.BuildModule, bool, error) {
	if w.walks == nil || walkID == "" {
		return nil, false, nil
	}
	rec, err := w.walks.GetWalk(ctx, walkID)
	if errors.Is(err, walkports.ErrWalkNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading walk %s for its build list: %w", walkID, err)
	}
	var out []vulnports.BuildModule
	for _, n := range rec.Graph.Nodes {
		if n.ResolutionSource == walkdomain.ResolutionStdlib || n.Coordinate.IsLocal() || n.Coordinate.IsZero() {
			continue
		}
		out = append(out, vulnports.BuildModule{
			Coordinate:   n.Coordinate,
			LocalReplace: n.ResolutionSource == walkdomain.ResolutionLocalReplace,
		})
	}
	return out, true, nil
}
