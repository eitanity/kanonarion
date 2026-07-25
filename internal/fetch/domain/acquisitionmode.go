package domain

// AcquisitionMode names the path a module's bytes arrived by. It is persisted
// on the fact record because the record's contents depend on it: the proxy path
// writes content-addressed "sha256:<hex>" handles into the local blob store,
// while the module-cache path derives "modcache:zip:<coord>" handles that only
// the module-cache adapter resolves. Without the mode on the record a reader has
// to parse the handle to learn which store can produce the bytes, and a log
// entry cannot say which mode wrote what.
type AcquisitionMode string

const (
	// AcquisitionProxy is the network path: bytes come from a module proxy and
	// are stored in the content-addressed blob store.
	AcquisitionProxy AcquisitionMode = "proxy"

	// AcquisitionModcache is the --from-modcache path: bytes are read from an
	// existing Go module cache and the recorded handles are coordinate-derived,
	// resolvable only by the module-cache blob adapter.
	AcquisitionModcache AcquisitionMode = "modcache"

	// AcquisitionLocal is the local-source path: the artefact was built from a
	// filesystem path rather than fetched, and carries LocalSource verification.
	AcquisitionLocal AcquisitionMode = "local"
)

// verificationStrength ranks a verification status by the strength of the trust
// anchor behind it, strongest first: Verified (transparency log AND git source),
// VerifiedBySumDBOnly (transparency log), VerifiedByGoSum (a local go.sum, itself
// populated under a prior transparency-log check), LocalSource (no anchor
// applies), then every Unverified* status and the empty status as equal-lowest.
//
// The absolute numbers carry no meaning beyond their order; only comparisons are
// used.
func verificationStrength(s VerificationStatus) int {
	switch s {
	case Verified:
		return 4
	case VerifiedBySumDBOnly:
		return 3
	case VerifiedByGoSum:
		return 2
	case LocalSource:
		return 1
	case UnverifiedNoSumDB, UnverifiedMissingOrigin, UnverifiedHashMismatch,
		UnverifiedGoModInconsistent, UnverifiedNoVCS, UnverifiedVCSToolMissing:
		return 0
	default:
		// An empty status, or one this build does not know, ranks equal-lowest.
		// Unknown must never outrank a known anchor: that would let a foreign or
		// malformed record displace a verified one.
		return 0
	}
}

// ReplacementWeakensAnchor reports whether replacing existing with incoming
// would trade a stronger verification anchor for a weaker one.
//
// A fact record is keyed on (module path, version, pipeline version) and nothing
// else, so a re-measurement of the same coordinate overwrites its predecessor in
// place — including a re-measurement made in a mode that cannot reach the same
// anchor. A --from-modcache run tops out at VerifiedBySumDBOnly (local go.sum is
// its only anchor); replacing a network run's Verified record with it demotes the
// module's chain of custody and swaps a portable, content-addressed handle for a
// mode-locked one. The write side consults this before overwriting and keeps the
// stronger record instead.
//
// Equal strength is not a weakening: a genuine re-verification, a status upgrade,
// and a same-mode refresh all still land.
//
// It is a free function rather than a method, on the same terms as
// RecordIsCacheable and RecordDigests: overwrite policy is fetch-pipeline policy,
// not the read-shape plumbing a graduated result alias is allowed to carry, so it
// must not reach the public API.
func ReplacementWeakensAnchor(existing, incoming FactRecord) bool {
	return verificationStrength(VerificationStatus(incoming.VerificationStatus)) <
		verificationStrength(VerificationStatus(existing.VerificationStatus))
}
