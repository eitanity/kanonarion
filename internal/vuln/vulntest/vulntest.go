// Package vulntest builds vulnerability-database snapshots for tests. Import it
// from any test in the module that needs a snapshot as a fixture; it is a normal
// package rather than a _test one for the same reason internal/fetch/fetchtest
// and internal/coordinate/coordinatetest are.
//
// It exists because DatabaseSnapshot's fields are unexported: a test can no
// longer write a struct literal, and the validating constructor returns an error
// that a fixture line has no useful way to handle. The Must* helpers panic
// instead, which in a test is a failure with a stack trace pointing at the bad
// fixture — the outcome an error check would have produced anyway, without the
// three lines.
//
// They take no testing.TB deliberately. Snapshots are built in table-driven test
// cases and package-level vars where no testing handle is in scope, and
// requiring one there would push tests into init-time indirection to satisfy a
// helper. The cost is that a panic here is attributed to the test that first
// touches the fixture rather than to the fixture's own line.
//
// Nothing in the production tree may import this package: it is the one place
// that turns an invalid snapshot into a panic rather than an error, which is
// acceptable in a test and never acceptable in a running pipeline.
package vulntest

import (
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// MustNew returns the snapshot naming source at version, with no retrieval time
// and no seal. It is the fixture most tests want: they care which pin a record
// is keyed on, not when it was fetched or what its bytes hash to.
func MustNew(source, version string) domain.DatabaseSnapshot {
	return MustSeal(source, version, time.Time{}, "")
}

// MustNewAt returns the snapshot naming source at version, retrieved at
// retrievedAt and unsealed. Use it where the retrieval time is the subject —
// snapshot age, and the composition rule that ranks the later fetch first.
func MustNewAt(source, version string, retrievedAt time.Time) domain.DatabaseSnapshot {
	return MustSeal(source, version, retrievedAt, "")
}

// MustSeal returns the fully stated snapshot, panicking if it is not a valid
// one. Use it wherever a test needs a snapshot that is a fixture rather than the
// subject; a test whose subject is the validation itself should call
// domain.NewDatabaseSnapshot and assert on the error.
func MustSeal(source, version string, retrievedAt time.Time, contentHash string) domain.DatabaseSnapshot {
	s, err := domain.NewDatabaseSnapshot(source, version, retrievedAt, contentHash)
	if err != nil {
		panic(fmt.Sprintf("vulntest: invalid database snapshot %s@%s: %v", source, version, err))
	}
	return s
}

// MustSealOver returns the snapshot naming source at version, sealed against
// blob's own hash. It is the fixture for a test that then stores blob, so the
// seal and the bytes agree by construction rather than by a hand-copied digest.
func MustSealOver(source, version string, retrievedAt time.Time, blob []byte) domain.DatabaseSnapshot {
	return MustSeal(source, version, retrievedAt, domain.HashSnapshotContent(blob))
}
