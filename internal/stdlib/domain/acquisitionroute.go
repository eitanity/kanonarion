package domain

// AcquisitionRoute names where a standard-library measurement got its bytes.
//
// It is a DIMENSION, not a ladder. The published source tarball and the local
// toolchain's `$GOROOT/src` are different bytes answering different questions —
// "what does Go publish for this version" and "what is this machine actually
// compiling with" — and neither supersedes the other. Composition therefore
// never picks between routes; a reader asks for the one it wants, and a read
// that names none is answered from the published route, because that is what an
// online run writes.
//
// It is recorded explicitly rather than derived from VerificationStatus, even
// though the local route happens to be the only writer of VerifiedLocalToolchain
// today. Reading a dimension out of a status field is how the call-graph stage
// ended up encoding "this came from a working tree" in a version string: it
// works until a second value shares the field, and then it is wrong silently.
// The route is cheap to state and impossible to misread.
type AcquisitionRoute string

const (
	// RouteUnrecorded is the zero value: the record predates the field and says
	// nothing about where its bytes came from. It is a distinct value from both
	// real routes and is never treated as either — a measurement that does not say
	// what it read cannot be shown to have read the same thing as one that does.
	RouteUnrecorded AcquisitionRoute = ""
	// RouteGoDev is the published source tarball from go.dev/dl, whose SHA-256 can
	// be matched against the release manifest's published checksum.
	RouteGoDev AcquisitionRoute = "godev"
	// RouteLocalToolchain is the installed toolchain's own source tree
	// ($GOROOT/src), digested in place with no network access. Its bytes are not
	// the published tarball's — the tarball is an archive, this is a directory —
	// so the two can never share an artefact identity.
	RouteLocalToolchain AcquisitionRoute = "local-toolchain"
)

// String renders the route, naming the zero value rather than printing an empty
// field a reader would take for an absence of route.
func (r AcquisitionRoute) String() string {
	if r == RouteUnrecorded {
		return "not recorded"
	}
	return string(r)
}

// AcquisitionRoutes is every route this type defines, published so consumers
// that must cover the dimension range over it rather than restating the list.
func AcquisitionRoutes() []AcquisitionRoute {
	return []AcquisitionRoute{RouteGoDev, RouteLocalToolchain, RouteUnrecorded}
}

// ArtefactIdentity is what names the bytes a measurement was taken over: the
// SHA-256 of the source tarball, or of the local source tree.
//
// It is deliberately NOT PublishedSHA256. That is the ANCHOR — the digest Go
// publishes — and it equals the artefact's own SHA-256 only when the checksum
// matched. Using it as identity would be wrong in exactly the case that matters
// most: a local-toolchain acquisition consults no published checksum at all, so
// every offline record would collapse onto one empty identity, and a mismatch
// record would be filed under the bytes it did NOT describe.
//
// Empty when no digest was computed, which is not a measurement of anything.
func ArtefactIdentity(f Facts) string { return f.Digests.SHA256 }
