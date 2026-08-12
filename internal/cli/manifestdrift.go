package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// manifestDrift is the comparison between what a go.mod resolves to now and
// what a stored walk resolved when it was taken.
//
// A project walk is rooted at a local coordinate, which pins no content: the
// working tree's go.mod changes under it and the walk keeps its name. Every
// lookup that finds a walk "for this go.mod" therefore finds it by name alone,
// and a name is not evidence that the walk still describes the build in front
// of the caller. This is that evidence, or its absence — measured by resolving
// the manifest again and comparing the module set against the walk's own nodes.
type manifestDrift struct {
	// resolved is how many module versions the manifest resolves to now, and
	// walked how many the walk recorded. Both are reported even when the sets
	// agree: "identical" is a claim about a measurement, and the counts are what
	// make it checkable.
	resolved int
	walked   int
	// added, removed and changed are the disagreements, each rendered as text
	// the reason line can name. added holds coordinates the manifest resolves
	// that the walk does not carry, removed those the walk carries that the
	// manifest no longer resolves, and changed the paths both hold at different
	// versions ("path v1 -> v2").
	added   []string
	removed []string
	changed []string
}

// drifted reports whether the manifest resolves to something other than what
// the walk recorded.
func (d manifestDrift) drifted() bool {
	return len(d.added) > 0 || len(d.removed) > 0 || len(d.changed) > 0
}

// reason states the drift in one line, naming enough of it to be actionable
// without printing a whole build list. It is what the command prints instead of
// serving, so it says what changed rather than only that something did.
func (d manifestDrift) reason(walkID string) string {
	parts := make([]string, 0, 3)
	if len(d.changed) > 0 {
		parts = append(parts, fmt.Sprintf("%d changed (%s)", len(d.changed), driftSample(d.changed)))
	}
	if len(d.added) > 0 {
		parts = append(parts, fmt.Sprintf("%d added (%s)", len(d.added), driftSample(d.added)))
	}
	if len(d.removed) > 0 {
		parts = append(parts, fmt.Sprintf("%d removed (%s)", len(d.removed), driftSample(d.removed)))
	}
	return fmt.Sprintf("the manifest no longer resolves to walk %s: %s; it now resolves %d module versions, that walk recorded %d",
		walkID, strings.Join(parts, ", "), d.resolved, d.walked)
}

// agreement states the checked identity, with the count it was checked over.
// A served answer that says only "reusing" leaves the reader to assume the
// manifest was consulted; this says it was, and over how much.
func (d manifestDrift) agreement(walkID string) string {
	return fmt.Sprintf("manifest re-resolved: %d module versions, identical to walk %s", d.resolved, walkID)
}

// driftMaxNamed is how many coordinates a reason line names per class before it
// starts counting instead. A build list can move by hundreds of modules at once
// (a `go get -u`), and a reason line that printed all of them would bury the
// statement it exists to make.
const driftMaxNamed = 3

// driftSample renders up to driftMaxNamed entries, then says how many it left
// out rather than truncating silently.
func driftSample(entries []string) string {
	if len(entries) <= driftMaxNamed {
		return strings.Join(entries, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(entries[:driftMaxNamed], ", "), len(entries)-driftMaxNamed)
}

// manifestDriftAgainstWalk resolves gomodPath's scope through the same resolver
// every go.mod command uses and compares it against the walk record's nodes.
//
// The resolution is the cost: on a 320-module project it is around a second,
// against the fraction of one a stored answer takes to serve. It is paid because
// the alternative is serving an answer about a build the caller no longer has,
// which is not a faster answer to the same question.
func manifestDriftAgainstWalk(
	ctx context.Context,
	walks QueryWalksUseCase,
	walkID, gomodPath string,
	scope depScope,
) (manifestDrift, walkdomain.WalkRecord, error) {
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return manifestDrift{}, walkdomain.WalkRecord{}, fmt.Errorf("loading walk %q: %w", walkID, err)
	}
	if err := ctx.Err(); err != nil {
		return manifestDrift{}, rec, fmt.Errorf("checking whether walk %s still describes %s: %w", walkID, gomodPath, err)
	}
	// A manifest that does not resolve is not evidence that the stored walk still
	// describes it, so the failure is the answer rather than a reason to fall
	// back on the walk. The toolchain's own diagnostic carries the remedy — a
	// vendored tree whose go.mod moved without `go mod vendor` says exactly that
	// — and it is named here as what it stopped: the check, not the scan.
	resolved, err := resolveScopeModules(gomodPath, scope)
	if err != nil {
		return manifestDrift{}, rec, fmt.Errorf("checking whether walk %s still describes %s (resolving the %s scope): %w", walkID, gomodPath, scope, err)
	}
	return driftAgainstWalk(resolved, rec), rec, nil
}

// driftAgainstWalk compares a resolved "path@version" set against a walk's
// recorded module set.
//
// Two nodes are excluded from the walk's side because the manifest resolution
// never names them: the synthetic standard-library node, which has no require
// line behind it, and any local coordinate — the main module itself and
// local-path replace targets, which carry no version. That is the same exclusion
// Graph.SelectedVersions makes for the same reason.
//
// A replaced node is matched on the coordinate the manifest names, not the one
// the walk fetched: `go list` reports the require entry (goqu/v9@v9.18.0) while
// the walk records the replacement it actually fetched (cortezaproject/goqu/v9
// @v9.18.4). Comparing the fetched coordinate would report every replace
// directive as drift on every run, and a check that always fires is a check that
// gets ignored.
func driftAgainstWalk(resolved []string, rec walkdomain.WalkRecord) manifestDrift {
	walked := walkdomain.NamedVersions(rec)

	d := manifestDrift{resolved: len(resolved), walked: len(walked)}
	seen := make(map[string]struct{}, len(resolved))
	for _, coord := range resolved {
		path, version, ok := strings.Cut(coord, "@")
		if !ok {
			// The resolver emits "path@version" and drops anything else, so this
			// cannot come from it; a bare path is treated as a module the walk has
			// no version for rather than silently skipped.
			path, version = coord, ""
		}
		seen[path] = struct{}{}
		walkedVersion, present := walked[path]
		switch {
		case !present:
			d.added = append(d.added, coord)
		case walkedVersion != version:
			d.changed = append(d.changed, fmt.Sprintf("%s %s -> %s", path, walkedVersion, version))
		}
	}
	for path, version := range walked {
		if _, ok := seen[path]; !ok {
			d.removed = append(d.removed, path+"@"+version)
		}
	}
	sort.Strings(d.added)
	sort.Strings(d.removed)
	sort.Strings(d.changed)
	return d
}

// manifestStalenessNote is the clause a read appends when it answered from a
// walk found by the manifest's module path alone.
//
// The read is still anchored — it names the walk and the frame — but the walk
// was not proved to describe the manifest as it stands now, and on a local
// coordinate that is a real gap: the go.mod can be edited between the walk and
// the read without either one noticing. Stating it is the alternative to paying
// a full re-resolution on every query; the surface that measures rather than
// reads (vuln-scan --gomod) pays it instead.
func manifestStalenessNote(gomodPath string) string {
	return fmt.Sprintf("; %s was not re-resolved for this read, so an edit made to it since that walk is not reflected — kanonarion walk --gomod %s records the current resolution",
		gomodPath, gomodPath)
}

// manifestRequireDisagreement compares the require directives of the go.mod at
// path against what a walk recorded, and returns the versions the two disagree
// on ("path walked -> required"). An empty result means the manifest and the
// walk agree on every module both name.
//
// It is deliberately weaker than manifestDriftAgainstWalk, and cheaper by the
// same amount: that one re-resolves the manifest through the toolchain, which
// costs about a second on a 320-module project, and is paid by the surfaces that
// MEASURE. This one parses one file and is paid by the surfaces that READ, on
// every default frame choice — so it has to cost nothing a reader would notice.
//
// A module the manifest requires but the walk does not carry is NOT a
// disagreement. That is the difference between a code-scope walk and a
// complete-scope one of the same tree, and reading it as drift would declare
// every narrower walk stale against the manifest it was taken from.
//
// A manifest naming no module the walk resolved cannot settle anything, so it is
// an error rather than an agreement: an empty comparison and a clean one are the
// same value and not the same fact.
func manifestRequireDisagreement(path string, rec walkdomain.WalkRecord) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 — the path comes from --gomod or from the walk's own recorded project directory
	if err != nil {
		return nil, fmt.Errorf("reading %s to compare it against walk %s: %w", path, rec.ID, err)
	}
	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing %s to compare it against walk %s: %w", path, rec.ID, err)
	}
	disagreements, cerr := walkdomain.RequireDisagreement(manifestRequiredVersions(f), rec)
	if cerr != nil {
		return nil, fmt.Errorf("comparing %s against walk %s: %w", path, rec.ID, cerr)
	}
	return disagreements, nil
}

// manifestRequiredVersions reduces a parsed go.mod to the module path/version
// pairs its require directives name, which is the whole of what the agreement
// comparison reads from a manifest.
func manifestRequiredVersions(f *modfile.File) map[string]string {
	required := make(map[string]string, len(f.Require))
	for _, r := range f.Require {
		if r == nil {
			continue
		}
		required[r.Mod.Path] = r.Mod.Version
	}
	return required
}
