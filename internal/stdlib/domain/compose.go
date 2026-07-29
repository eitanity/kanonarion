package domain

import (
	"errors"
	"fmt"
	"sort"
)

// ErrNoFactsToCompose is returned by Compose when handed no measurements. It is
// a programming error rather than an absence: absence is reported by the store
// as "not found", and composing nothing has no meaningful answer.
var ErrNoFactsToCompose = errors.New("no stdlib facts to compose")

// FactsConflict is two standard-library measurements that composition must not
// resolve by picking.
//
// It reports two disagreements, and keeping them apart matters:
//
//   - "artefact_identity": one toolchain version, one route, two different sets
//     of bytes. Go republished the tarball, or one of the two downloads was
//     corrupt. There is no ladder between answers about different bytes.
//   - "verification_status": the SAME bytes, both runs consulted the published
//     checksum, and they disagree about whether it matched. One says verified and
//     the other says mismatch, which cannot both be true of one digest — the
//     published checksum itself changed, or one measurement is wrong. This is the
//     narrow case worth surfacing rather than absorbing.
//
// A mismatch reported alongside an "unavailable" is NOT a conflict: one run
// could not consult the manifest and the other could, so the mismatch is strictly
// more informative and the ladder resolves it. Only two definite and opposing
// answers about identical bytes are a finding.
//
// It mirrors fetch's Divergence and the interface and call-graph conflicts,
// including reporting the content hashes of the records carrying each value.
type FactsConflict struct {
	// GoVersion is the toolchain version the disagreeing measurements describe.
	GoVersion string
	// Route is the acquisition route every conflicting measurement took.
	Route AcquisitionRoute
	// Field names what they disagree on: "artefact_identity" or
	// "verification_status".
	Field string
	// Values are the distinct values recorded for Field, sorted, so the report is
	// stable across runs.
	Values []string
	// ContentHashes name the measurements carrying each of Values, in the same
	// order. Empty entries are measurements written before the seal existed.
	ContentHashes []string
}

// Error renders the conflict as a message. FactsConflict satisfies error so the
// store can return it directly.
func (c FactsConflict) Error() string {
	return fmt.Sprintf(
		"conflicting stdlib facts for %s via %s: %s disagrees (%v; records %v)",
		c.GoVersion, c.Route, c.Field, c.Values, c.ContentHashes,
	)
}

// ComposeRequest asks for the measurement a reader gets for one toolchain
// version. Its zero value is the unrestricted read.
type ComposeRequest struct {
	// Route restricts composition to measurements that took one acquisition
	// route. The zero value names none, and the default below decides.
	Route AcquisitionRoute
}

// Compose returns the standard-library facts a reader gets for one toolchain
// version, given every measurement the ledger holds for it.
//
// Measurements must be supplied in the order they were appended.
//
// The ladder is HOW DEFINITE THE ANCHOR WAS, then recency. A measurement that
// consulted the published checksum — whether it matched or not — outranks one
// that could not consult it, regardless of which was written later. That is the
// rule this conversion exists for: a transient go.dev failure used to overwrite a
// verified record and then be served from cache on every later run until --force,
// and now it is appended beside it and loses.
//
// The acquisition route is NOT on that ladder. The published tarball and the
// local toolchain's source tree are different bytes answering different
// questions, so composition selects a route first and ladders only within it.
func Compose(measurements []Facts, req ComposeRequest) (Facts, error) {
	if len(measurements) == 0 {
		return Facts{}, ErrNoFactsToCompose
	}

	var candidates []Facts
	if req.Route != RouteUnrecorded {
		candidates = withRoute(measurements, req.Route)
		if len(candidates) == 0 {
			return Facts{}, ErrNoFactsToCompose
		}
	} else {
		var err error
		if candidates, err = defaultRouteGroup(measurements); err != nil {
			return Facts{}, err
		}
	}

	if c := findConflict(candidates); c != nil {
		return Facts{}, *c
	}

	ordered := make([]Facts, len(candidates))
	copy(ordered, candidates)
	sort.SliceStable(ordered, func(i, j int) bool { return servesBefore(ordered[i], ordered[j]) })
	return ordered[0], nil
}

// withRoute keeps the measurements that took one acquisition route.
func withRoute(measurements []Facts, want AcquisitionRoute) []Facts {
	out := make([]Facts, 0, len(measurements))
	for _, f := range measurements {
		if f.AcquisitionRoute == want {
			out = append(out, f)
		}
	}
	return out
}

// defaultRouteGroup picks which measurements answer a read that named no route.
//
// The published tarball is what an online run writes and is the answer a reader
// asking "what is Go's standard library at this version" wants, so it is the
// default. The local toolchain answers only when the ledger holds no published
// measurement — otherwise an offline run would quietly redirect every later read
// away from the anchor that consulted the published checksum.
//
// A measurement that names NO route is not a third route: it is one written
// before the field existed, and every row in an un-migrated store is one. When
// only one real route is present they are laddered alongside it — only one route
// is in play, so they cannot be answering a different question. When both real
// routes are present a silent measurement cannot be attributed to either and
// steps aside, because a measurement that says what it read is better evidence
// than one that does not. Nothing is deleted either way; a history read still
// returns every generation.
func defaultRouteGroup(measurements []Facts) ([]Facts, error) {
	godev := withRoute(measurements, RouteGoDev)
	local := withRoute(measurements, RouteLocalToolchain)
	silent := withRoute(measurements, RouteUnrecorded)

	if len(godev)+len(local)+len(silent) != len(measurements) {
		// A measurement names a route this build does not define — written by a
		// newer binary, or corrupt. Refusing is the only honest answer: picking a
		// group would serve an answer about a route nothing here can name.
		return nil, FactsConflict{
			GoVersion:     measurements[0].GoVersion,
			Route:         measurements[0].AcquisitionRoute,
			Field:         "acquisition_route",
			Values:        distinctRoutes(measurements),
			ContentHashes: hashesForRoutes(measurements),
		}
	}

	switch {
	case len(godev) > 0 && len(local) > 0:
		return godev, nil
	case len(godev) > 0:
		return inAppendOrder(measurements, godev, silent), nil
	case len(local) > 0:
		return inAppendOrder(measurements, local, silent), nil
	default:
		return silent, nil
	}
}

// inAppendOrder merges two subsets back into the order they were appended in, so
// recency as a tiebreaker means what it says.
func inAppendOrder(all, a, b []Facts) []Facts {
	keep := make(map[string]bool, len(a)+len(b))
	key := func(f Facts) string {
		return f.ContentHash + "\x00" + f.Digests.SHA256 + "\x00" + f.AcquiredAt.UTC().String()
	}
	for _, f := range a {
		keep[key(f)] = true
	}
	for _, f := range b {
		keep[key(f)] = true
	}
	out := make([]Facts, 0, len(keep))
	for _, f := range all {
		if keep[key(f)] {
			out = append(out, f)
		}
	}
	return out
}

// findConflict reports the first disagreement composition must not resolve by
// picking, or nil when the measurements can be laddered.
func findConflict(measurements []Facts) *FactsConflict {
	if len(measurements) < 2 {
		return nil
	}

	// One toolchain version, one route, two different sets of bytes. Nothing
	// orders answers about different bytes.
	if c := disagreement(measurements, "artefact_identity", ArtefactIdentity); c != nil {
		return c
	}

	// Within one artefact, only measurements the ladder cannot separate can
	// conflict. An "unavailable" disagreeing with a definite answer is the
	// refinement case the ladder exists to resolve; two DEFINITE answers about
	// identical bytes that differ is a contradiction.
	definite := make([]Facts, 0, len(measurements))
	for _, f := range measurements {
		if anchorRung(f) == rungDefinite {
			definite = append(definite, f)
		}
	}
	return disagreement(definite, "verification_status",
		func(f Facts) string { return string(f.VerificationStatus) })
}

// disagreement reports the distinct values of one field across measurements, as
// a conflict, when there is more than one.
func disagreement(measurements []Facts, field string, value func(Facts) string) *FactsConflict {
	if len(measurements) < 2 {
		return nil
	}
	seen := map[string]string{} // value -> content hash of a measurement carrying it
	for _, f := range measurements {
		v := value(f)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = f.ContentHash
		}
	}
	if len(seen) < 2 {
		return nil
	}
	values := make([]string, 0, len(seen))
	for v := range seen {
		values = append(values, v)
	}
	sort.Strings(values)
	hashes := make([]string, 0, len(values))
	for _, v := range values {
		hashes = append(hashes, seen[v])
	}
	return &FactsConflict{
		GoVersion:     measurements[0].GoVersion,
		Route:         measurements[0].AcquisitionRoute,
		Field:         field,
		Values:        values,
		ContentHashes: hashes,
	}
}

// distinctRoutes lists the routes present across measurements, sorted.
func distinctRoutes(measurements []Facts) []string {
	seen := map[string]bool{}
	for _, f := range measurements {
		seen[f.AcquisitionRoute.String()] = true
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// hashesForRoutes names one measurement carrying each route in distinctRoutes'
// order, so a reported conflict can be examined row by row.
func hashesForRoutes(measurements []Facts) []string {
	first := map[string]string{}
	for _, f := range measurements {
		if _, ok := first[f.AcquisitionRoute.String()]; !ok {
			first[f.AcquisitionRoute.String()] = f.ContentHash
		}
	}
	routes := distinctRoutes(measurements)
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, first[r])
	}
	return out
}

// The anchor ladder. Higher is a more definite statement about the artefact.
const (
	rungUnknown  = 0
	rungAbsent   = 1
	rungDefinite = 2
)

// anchorRung orders measurements by how definite an answer their anchor produced.
//
// The three definite statuses share a rung on purpose. VerifiedGoDevChecksum and
// GoDevChecksumMismatch both consulted the published checksum and got an answer;
// a mismatch is EVIDENCE, not a weaker verification, and ranking it below
// "unavailable" would let a later run that simply could not reach go.dev bury
// tamper evidence. VerifiedLocalToolchain is equally definite about the bytes it
// read — it just read different bytes, which is why the route separates it before
// this function is ever reached.
//
// UnverifiedGoDevUnavailable is the only rung below them: the anchor was not
// consulted at all, so the measurement states nothing about the published
// checksum.
func anchorRung(f Facts) int {
	switch f.VerificationStatus {
	case VerifiedGoDevChecksum, GoDevChecksumMismatch, VerifiedLocalToolchain:
		return rungDefinite
	case UnverifiedGoDevUnavailable:
		return rungAbsent
	default:
		return rungUnknown
	}
}

// servesBefore orders two measurements by which should be served first.
func servesBefore(a, b Facts) bool {
	if ra, rb := anchorRung(a), anchorRung(b); ra != rb {
		return ra > rb
	}
	if !a.AcquiredAt.Equal(b.AcquiredAt) {
		return a.AcquiredAt.After(b.AcquiredAt)
	}
	// Neither the ladder nor the clock separates these. The content hash is not
	// authority and is not claimed to be — it is here so the served measurement
	// does not depend on the order rows happen to come back in.
	return a.ContentHash < b.ContentHash
}

// ServesAsCacheHit reports whether a composed measurement is good enough to
// answer a later run without re-acquiring.
//
// This is the read-side home of the rule a persisted "the lookup failed" flag
// would otherwise have to carry. A measurement whose anchor was never consulted
// is not a fact about the toolchain, it is a record of a run that could not
// establish one — so serving it from cache turns one transient go.dev failure
// into a permanent downgrade that survives every later run until --force. It is
// stored (the walk completes, and the attempt is evidence) and it does not
// satisfy the cache.
//
// It is a free function over a measurement rather than control flow inside the
// acquirer, so the rule is one predicate a reader can find, and so both the
// online and offline acquirers apply exactly the same one.
func ServesAsCacheHit(f Facts) bool { return anchorRung(f) == rungDefinite }
