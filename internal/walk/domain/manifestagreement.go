package domain

import (
	"fmt"
	"sort"
)

// NamedVersions maps each module a walk resolved to the version it resolved it
// at, under the name the MANIFEST uses for it.
//
// Two node classes are dropped because no require line names them: the synthetic
// standard-library node, and any local coordinate — the main module itself and
// local-path replace targets, which carry no version. A replaced node is keyed
// on the require entry the replace acted on rather than on the replacement that
// was fetched, so a replace directive is not read as a disagreement.
func NamedVersions(rec WalkRecord) map[string]string {
	walked := make(map[string]string, len(rec.Graph.Nodes))
	for _, n := range rec.Graph.Nodes {
		if n.ResolutionSource == ResolutionStdlib || n.Coordinate.IsLocal() {
			continue
		}
		named := n.Coordinate
		if !n.OriginalCoordinate.IsZero() {
			named = n.OriginalCoordinate
		}
		if named.IsLocal() {
			continue
		}
		walked[named.Path()] = named.Version()
	}
	return walked
}

// RequireDisagreement compares a manifest's require directives — required, a
// module path to version map — against what a walk recorded, and returns the
// versions the two disagree on ("path walked -> required") together with how
// many modules the two both name and could therefore be compared.
//
// An empty disagreement list with a non-zero compared count is agreement. A zero
// compared count is neither: the manifest names no module the walk resolved, so
// nothing was established, and a caller must not read the empty list as a clean
// answer. The error says which walk could not be compared.
//
// A module the manifest requires but the walk does not carry is NOT a
// disagreement. That is the difference between a code-scope walk and a
// complete-scope one of the same tree, and reading it as drift would declare
// every narrower walk stale against the manifest it was taken from. A module the
// walk carries that the manifest does not require is likewise not compared: in a
// pruned (go >= 1.17) module those are the modules contributing no imported
// package, which no analysis of the tree reaches either way.
//
// This is the cheap half of the agreement question — one already-parsed manifest
// against one already-loaded walk, no toolchain, no network. Its expensive
// counterpart re-resolves the manifest through the go command; see the read
// path's manifestDriftAgainstWalk, which pays that where the added second is
// affordable.
func RequireDisagreement(required map[string]string, rec WalkRecord) ([]string, error) {
	walked := NamedVersions(rec)
	compared := 0
	var disagreements []string
	for path, version := range required {
		walkedVersion, ok := walked[path]
		if !ok {
			continue
		}
		compared++
		if walkedVersion != version {
			disagreements = append(disagreements, fmt.Sprintf("%s %s -> %s", path, walkedVersion, version))
		}
	}
	if compared == 0 {
		return nil, fmt.Errorf("the manifest requires no module walk %s resolved, so the two cannot be compared", rec.ID)
	}
	sort.Strings(disagreements)
	return disagreements, nil
}
