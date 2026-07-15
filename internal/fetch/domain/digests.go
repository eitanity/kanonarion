package domain

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// ArtifactDigests holds the raw content digests of a downloaded artefact (a
// module zip, or the stdlib source tarball) computed over the exact bytes
// received at acquisition time. Unlike ModuleHash — the canonical h1 dirhash
// that anchors to go.sum and the checksum database — these are plain digests of
// the artefact bytes, carried into the SBOM as a component's <hashes>.
//
// Only the three currently-recommended SHA-2 algorithms are recorded; the
// superseded MD5 and SHA-1 are deliberately omitted. Values are lowercase hex
// with no algorithm prefix. A zero value means "no digests recorded" (a
// synthetic node, a local main component, or a record produced before digests
// were captured); IsZero distinguishes that from a real computation.
type ArtifactDigests struct {
	SHA256 string
	SHA384 string
	SHA512 string
}

// ComputeArtifactDigests computes the SHA-256, SHA-384 and SHA-512 digests of
// data. The three hashes are taken over the identical byte slice so a consumer
// can cross-check any one of them against the same artefact.
func ComputeArtifactDigests(data []byte) ArtifactDigests {
	sum256 := sha256.Sum256(data)
	sum384 := sha512.Sum384(data)
	sum512 := sha512.Sum512(data)
	return ArtifactDigests{
		SHA256: hex.EncodeToString(sum256[:]),
		SHA384: hex.EncodeToString(sum384[:]),
		SHA512: hex.EncodeToString(sum512[:]),
	}
}

// IsZero reports whether no digests were recorded, so serialisers can omit an
// empty block and the SBOM generator can skip emitting <hashes> for synthetic,
// local, or legacy nodes rather than fabricating or failing.
func (d ArtifactDigests) IsZero() bool {
	return d.SHA256 == "" && d.SHA384 == "" && d.SHA512 == ""
}
